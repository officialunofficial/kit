//! Partial-disclosure verification: prove and verify that a single path,
//! chunk, or byte range belongs to a commit id, with proof bytes on the
//! order of a few KiB regardless of repository size.
//!
//! ## Trust model
//!
//! A verified [`Disclosed`] proves that its `payload` bytes are exactly
//! the content the given `commit_id` commits to at `path` — nothing more.
//! It does **not** prove:
//!
//! * that the disclosed path is the *only* thing at that location (no
//!   sibling-completeness claim — see the closure profile,
//!   for that);
//! * anything about who the signer *is* — `signer`/`signature_valid`
//!   report whether the embedded Ed25519 signature verifies against the
//!   embedded public key; binding that key to an identity or trust level
//!   is application policy (trust roots), exactly as
//!   [`crate::sign::verify_commit`] already documents.
//!
//! Every function in this module verifies against an **object id**, never
//! a bare (pre-domain-wrap) inner root or an unauthenticated byte range —
//! see [`crate::merkle`]'s module docs for why that distinction matters.
//!
//! Wire format, verification algorithm, and bounds are pinned in
//! `docs/specs/SPEC-DISCLOSURE.md`; golden vectors live under
//! `rust/tests/golden/disclosure/`.
//!
//! ## Layering
//!
//! [`verify_object_id`], [`verify_path`] and [`verify_blob_slice`] are the small,
//! independently-useful primitives (each corresponds to one hop of the
//! authentication chain: commit → tree steps → leaf → chunk/slice).
//! [`verify_disclosure`] decodes a self-contained wire bundle (§ below)
//! and composes them into one call. [`build_disclosure_from`] is the
//! producer side, generic over any verifying [`crate::store::ObjectSource`]
//! (the on-disk store, an in-memory overlay, or a server-side index or
//! object CAS); [`build_disclosure`] is its thin wrapper over
//! [`crate::store::ObjectStore`]. The builder's source trait is distinct
//! from this module's [`ObjectSource`], the non-verifying
//! `fetch(&mut self)` trait the closure walker reads through. Full
//! disclosure — every reachable object against a commit id — is
//! [`verify_closure`], [`verify_closure_streaming`],
//! [`verify_closure_packs`], and [`verify_closure_manifest`], with
//! [`verify_closure_store`] and [`export_closure`] as native store-backed
//! operations.
//!
//! Everything here, the builder included, compiles with
//! `--no-default-features` and targets `wasm32-unknown-unknown`; no
//! separate feature gate is needed since `kit-core` itself is a `std`
//! crate (see the crate root docs).
//!
//! ## Wire bundle (`verify_disclosure` / `build_disclosure`)
//!
//! ```text
//! magic   = "KDPB"            (4 raw bytes)
//! version: u8 = 3
//! commit_id: [u8; 32]
//! commit_bytes: Vec<u8>        <= 4 MiB
//! steps: Vec<Step>             <= MAX_TREE_DEPTH (128), root first
//!   Step { name: Vec<u8> (1..=255), mode: u8, child_id: [u8; 32],
//!          inner_root: [u8; 32], position: u32, proof: Proof (max_items = 1) }
//! payload_kind: u8
//!   0 Object { bytes: Vec<u8> <= MAX_RAW_OBJECT_SIZE }
//!   1 Chunk  { total_size: u64, chunk_size: u32, index: u32,
//!              start: u64, end: u64,
//!              inner_root: [u8; 32], proof: Proof (max_items = 2),
//!              bytes: Vec<u8> }
//!   2 Range  { chunk: Option<ChunkHdr>, offset_in_blob: u64, len: u64,
//!              slice: Vec<u8> }
//!     ChunkHdr { total_size: u64, chunk_size: u32, index: u32,
//!                start: u64, end: u64,
//!                inner_root: [u8; 32], chunk_id: [u8; 32],
//!                proof: Proof (max_items = 2) }
//! ```
//!
//! All integers are big-endian, every length is an LEB128 varint, arrays
//! are raw — `commonware-codec` conventions (SPEC-CONVENTIONS §3;
//! `crate::transfer`'s packlist node is the existing precedent for this
//! house style). The whole bundle is capped at [`MAX_BUNDLE_BYTES`];
//! trailing bytes are rejected.
//!
//! `start` and `end` are the chunk's span in the file. The chunk's leaf is
//! built from them, so one multi-proof authenticates the span, the chunk id
//! and the manifest's `total_size`/`chunk_size`: an offset proof is the same
//! size at any position in the file.
//!
//! `ChunkHdr.chunk_id` is not literal to the original design
//! note, which omitted it: without an explicit chunk id, a verifier
//! reading a byte-range bundle would have no value to check the Bao slice
//! against before folding it into the enclosing `ChunkedBlob`'s multi-proof
//! (Bao's `SliceDecoder` always requires the expected root up front — it
//! cannot recover an unknown one from the slice, by construction). Adding
//! this field closes that gap; it is exactly the value the multi-proof of
//! [`verify_disclosure`] authenticates, so a forged `chunk_id` fails to fold to
//! the enclosing `ChunkedBlob`'s id.

use std::io::Read as _;

use bytes::{Buf as _, BufMut};
use commonware_codec::{Buf, Copying};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, ReadRangeExt, Write};

use crate::hash::{Hash, hash};
use crate::merkle::{self, MerkleError, ObjectKind, Proof};
use crate::object::{EntryMode, KitError, MAGIC, Object, ObjectType, TreeEntry};
use crate::ops::graph::{ChildKind, type_bit};
use crate::sign::{verify_commit, verify_remix};
use crate::store::MAX_TREE_DEPTH;

/// Hard cap on a whole encoded disclosure bundle, checked before any
/// decode work happens. A caller can cap decoded objects lower; this
/// 64 MiB ceiling is the bound this crate itself enforces.
pub const MAX_BUNDLE_BYTES: usize = 64 * 1024 * 1024;

/// Fixed 4-byte magic at the start of every disclosure bundle.
const BUNDLE_MAGIC: &[u8; 4] = b"KDPB";
/// Current (and only) bundle version byte. v1 and v2 are rejected with
/// [`VerifyError::UnsupportedBundleVersion`] (SPEC-DISCLOSURE v3).
const BUNDLE_VERSION: u8 = 3;
/// Cap on `commit_bytes` — comfortably above any real commit (~250 B) or
/// remix (larger, due to `sources`), far below `MAX_RAW_OBJECT_SIZE`.
const MAX_COMMIT_BYTES: usize = 4 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors verifying (or, natively, building) a disclosure.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// The encoded bundle exceeds [`MAX_BUNDLE_BYTES`].
    #[error("disclosure bundle exceeds the {MAX_BUNDLE_BYTES} byte cap")]
    BundleTooLarge,
    /// The bundle is shorter than the fixed magic+version header, or the
    /// magic bytes are not `"KDPB"`.
    #[error("disclosure bundle magic is not \"KDPB\"")]
    BadMagic,
    /// The bundle's version byte is not `3`. A version byte of `2` is
    /// this error with payload `2`.
    #[error("disclosure bundle version {0} is not supported (v3 only)")]
    UnsupportedBundleVersion(u8),
    /// A step's or chunk header's declared `inner_root` does not wrap to
    /// the expected object id (`Tree` domain for steps, `ChunkedBlob` domain
    /// for chunk headers). Checked before the field is used for anything.
    #[error("declared inner root does not wrap to the expected object id")]
    InnerRootMismatch {
        /// The parent `Tree` id (steps) or `ChunkedBlob` leaf id (chunk headers).
        expected: Hash,
        /// The prover-supplied inner root that failed the wrap check.
        inner_root: Hash,
    },
    /// The proof folds to a different root than the bundle declared,
    /// even though the declared root wraps to the expected id (or vice
    /// versa). Both must agree.
    #[error("proof fold does not equal the declared inner root")]
    InnerRootFoldMismatch,
    /// The codec body is malformed: truncated, an over-cap length, an
    /// invalid varint, or trailing bytes after the declared body.
    #[error("disclosure bundle body is malformed (bad codec payload or trailing bytes)")]
    Malformed,
    /// The bundle's embedded `commit_id` field does not match the id the
    /// caller asked to verify against.
    #[error("disclosure bundle's embedded commit_id does not match the requested commit id")]
    CommitIdMismatch,
    /// `BLAKE3(commit_bytes)` does not equal the commit id being verified.
    #[error("commit_bytes do not hash to the commit id being verified")]
    CommitBytesHashMismatch,
    /// `commit_bytes` decoded to an object type other than `Commit` or
    /// `Remix` — the only two kinds that carry a `tree_hash` a path can
    /// be walked from.
    #[error("commit_bytes decode to a {0:?}, which is not a Commit or Remix")]
    NotACommitOrRemix(ObjectType),
    /// More steps than [`crate::store::MAX_TREE_DEPTH`] were supplied.
    #[error("{0} steps exceeds MAX_TREE_DEPTH ({MAX_TREE_DEPTH})")]
    TooManySteps(usize),
    /// The entry name at the given step index fails SPEC-OBJECTS §4.1
    /// name validation ([`TreeEntry::validate_name`]).
    #[error("step {0}'s entry name fails SPEC-OBJECTS §4.1 validation")]
    InvalidEntryName(usize),
    /// A non-final step's mode is not [`EntryMode::Tree`] — every step
    /// but the last MUST descend into a directory.
    #[error("step {0} is not the final step but its mode is not Tree")]
    NonFinalStepNotTree(usize),
    /// A step's, or the payload's, merkle inclusion proof failed to
    /// verify — wraps every [`MerkleError`] variant (out-of-range
    /// position, unaligned proof, or a folded value that does not match
    /// the expected id).
    #[error("merkle proof verification failed: {0}")]
    Merkle(#[from] MerkleError),
    /// The bundle's `payload_kind` byte is not one of the three defined
    /// kinds (`0` Object, `1` Chunk, `2` Range).
    #[error("payload_kind byte {0:#04x} is not a recognized disclosure payload kind")]
    InvalidPayloadKind(u8),
    /// An `Object` payload's `BLAKE3`/merkle id does not equal the
    /// authenticated leaf id.
    #[error("disclosed Object payload's id does not equal the authenticated leaf id")]
    PayloadIdMismatch,
    /// The disclosed leaf has a type that the authenticated final step's
    /// mode does not allow (a `Tree` mode names a tree; every other mode
    /// names a blob or a chunked blob). `found` is the decoded type of an
    /// `Object` payload, or the type that a `Chunk` or `Range` payload
    /// requires of its leaf: a chunked blob, or a blob for a `Range` over a
    /// plain blob.
    #[error("disclosed leaf is a {found:?}, which entry mode {mode:?} does not allow")]
    PayloadTypeMismatch {
        /// The final step's mode (`Tree` for a root-tree disclosure).
        mode: EntryMode,
        /// The type of the leaf.
        found: ObjectType,
    },
    /// A chunk `index` is out of range for
    /// the `ChunkedBlob`'s proven `leaf_count`.
    #[error("chunk index {index} is out of range for a {leaf_count}-leaf ChunkedBlob proof")]
    ChunkIndexOutOfRange {
        /// The out-of-range chunk index.
        index: u32,
        /// The proof's claimed `leaf_count` (chunk count + 1, for the
        /// metadata leaf).
        leaf_count: u32,
    },
    /// A proof's implied chunk count (`leaf_count - 1`) exceeds
    /// [`crate::serialize::MAX_CHUNKS`].
    #[error("proof leaf_count implies more chunks than MAX_CHUNKS allows")]
    TooManyChunks,
    /// A `Range` payload's `len` is zero — there is nothing to disclose
    /// or verify.
    #[error("byte range length is zero")]
    ZeroLengthRange,
    /// A chunk of a fixed-size `ChunkedBlob` does not hold the span its
    /// layout requires (SPEC-OBJECTS §7): chunk `index` starts at `index *
    /// chunk_size` and ends `chunk_size` bytes later, or at `total_size`.
    #[error(
        "a fixed-size chunk has the wrong span: chunk {index} covers [{start}, {end}), which its layout does not allow"
    )]
    FixedChunkLength {
        /// The chunk's index within the manifest.
        index: u32,
        /// The span's start, as the chunk's leaf commits it.
        start: u64,
        /// The span's end, as the chunk's leaf commits it.
        end: u64,
    },
    /// A chunk's span `[start, end)` is empty or reaches past `total_size`.
    #[error("span outside the file: [{start}, {end}) in a file of {total_size} bytes")]
    SpanOutsideFile {
        /// The span's start.
        start: u64,
        /// The span's end.
        end: u64,
        /// The manifest's `total_size`.
        total_size: u64,
    },
    /// A chunk's span is longer than one Blob object can hold.
    #[error("span above the object limit: [{start}, {end}) is longer than a chunk blob can be")]
    SpanAboveObjectLimit {
        /// The span's start.
        start: u64,
        /// The span's end.
        end: u64,
    },
    /// `index == 0` and `start == 0` do not hold together.
    #[error("index 0 and start 0 disagree: chunk {index} starts at {start}")]
    FirstChunkStart {
        /// The chunk's index.
        index: u32,
        /// The span's start.
        start: u64,
    },
    /// The last index and `end == total_size` do not hold together.
    #[error("last index and end == total_size disagree: chunk {index} ends at {end}")]
    LastChunkEnd {
        /// The chunk's index.
        index: u32,
        /// The span's end.
        end: u64,
    },
    /// A disclosed chunk's Blob holds a different number of bytes than its
    /// span.
    #[error(
        "blob length differs from the span: chunk {index} holds {actual} bytes, span is {expected}"
    )]
    ChunkLengthDiffersFromSpan {
        /// The chunk's index.
        index: u32,
        /// The span's length, `end - start`.
        expected: u64,
        /// The length field of the chunk's Blob.
        actual: u64,
    },
    /// A disclosed chunk's bytes are not a well-formed Blob (SPEC-OBJECTS §3).
    #[error("chunk bytes are not a blob")]
    ChunkBytesNotBlob,
    /// A `Range` reaches past the committed span of its chunk.
    #[error("range past the committed span: {offset_in_blob} + {len} is above {span_len}")]
    RangePastSpan {
        /// The range's offset within the chunk.
        offset_in_blob: u64,
        /// The range's length.
        len: u64,
        /// The span's length, `end - start`.
        span_len: u64,
    },
    /// A Bao slice failed to verify against the expected root/offset/len.
    #[error("Bao slice verification failed: {0}")]
    Bao(String),
    /// A Bao slice decoded to fewer bytes than the claimed `len`.
    #[error("Bao slice yielded {got} bytes, expected {expected}")]
    ShortSlice {
        /// The requested length.
        expected: u64,
        /// The number of bytes the slice actually decoded to.
        got: usize,
    },
    /// An offset/length computation would overflow `u64`.
    #[error("offset/length computation overflowed u64")]
    OffsetOverflow,
    /// A byte range's canonical decode/serialize error.
    #[error(transparent)]
    Decode(#[from] KitError),
    /// [`Selector::Chunk`]/[`Selector::Range`] was used against a leaf
    /// whose object type does not support that selector (e.g. `Chunk` on
    /// a plain `Blob`, or either on a `Tree`).
    #[error("selector does not match the disclosed leaf's object type")]
    SelectorLeafMismatch,
    /// [`build_disclosure`]: the requested range crosses a `ChunkedBlob`
    /// chunk boundary — unsupported in this profile.
    #[error("byte range crosses a chunk boundary, which this profile does not support")]
    RangeCrossesChunkBoundary,
    /// [`build_disclosure`]: the requested range is out of bounds for the
    /// leaf's actual content length.
    #[error("byte range is out of bounds for the leaf's content length")]
    RangeOutOfBounds,
    /// [`build_disclosure`]: a path component was not found in its
    /// parent tree.
    #[error("path component {0} was not found in its parent tree")]
    PathNotFound(usize),
    /// [`build_disclosure`]: the path continues past a non-`Tree` entry,
    /// or the requested selector needs a leaf that isn't reached because
    /// an intermediate component isn't a directory.
    #[error("path continues past a non-Tree entry")]
    PathThroughNonTree,
    /// [`build_disclosure`]: the underlying object store returned an
    /// error.
    #[error(transparent)]
    Store(#[from] crate::store::StoreError),
    /// The supplied object set exceeds [`crate::pack::MAX_ENTRIES`].
    #[error("closure object set exceeds the pack MAX_ENTRIES cap")]
    TooManyClosureObjects,
    /// The closure root deserialized but is not a `Commit`, `Remix`, or `Tag`.
    #[error("closure root is a {0:?}, which is not a Commit, Remix, or Tag")]
    ClosureRootWrongType(ObjectType),
    /// A pack in the closure profile contained a delta or compressed entry.
    #[error(
        "closure pack {pack_index} entry {entry_index} is not a raw (0x00) entry (closure profile is raw-only)"
    )]
    ClosureProfileViolation {
        /// Index of the offending pack in the caller-supplied list.
        pack_index: usize,
        /// Index of the offending entry inside that pack.
        entry_index: usize,
    },
    /// The encoded closure manifest is shorter than the magic+version
    /// header, or the magic bytes are not `"KCLM"`.
    #[error("closure manifest magic is not \"KCLM\"")]
    ClosureManifestBadMagic,
    /// The manifest's version byte is not `1`.
    #[error("closure manifest version {0} is not supported (v1 only)")]
    ClosureManifestUnsupportedVersion(u8),
    /// The manifest body is malformed: truncated, an over-cap pack
    /// list, an unknown mode byte, or trailing bytes.
    #[error(
        "closure manifest body is malformed (bad codec payload, unknown mode, or trailing bytes)"
    )]
    ClosureManifestMalformed,
    /// The number of packs supplied does not match the manifest.
    #[error("closure manifest lists {expected} packs but {got} were supplied")]
    ClosurePackCountMismatch {
        /// Pack count recorded in the manifest.
        expected: usize,
        /// Number of pack buffers the caller handed the verifier.
        got: usize,
    },
    /// `pack_key(packs[index])` does not equal the manifest entry.
    #[error("pack {index} hash does not match the closure manifest")]
    ClosurePackKeyMismatch {
        /// Index of the mismatched pack.
        index: usize,
    },
    /// The manifest's `root` does not equal the caller-supplied trusted root.
    /// The manifest is a locator, never a trust anchor.
    #[error("closure manifest root does not match the caller's trusted root")]
    ClosureRootMismatch {
        /// Root the caller asked to verify against.
        expected: Hash,
        /// Root the manifest named.
        got: Hash,
    },
    /// A packfile framing/decode error while iterating a closure pack.
    #[error(transparent)]
    Pack(#[from] crate::pack::PackError),
}

impl From<CodecError> for VerifyError {
    fn from(_: CodecError) -> Self {
        // Mirrors `merkle::MerkleError`'s `From<CodecError>`: every codec
        // failure (truncation, an over-cap length, a bad varint, trailing
        // bytes) collapses to one "malformed" outcome — the caller never
        // needs to distinguish which codec primitive tripped, only that
        // decode failed rather than that verification failed.
        Self::Malformed
    }
}

mod closure;
pub use closure::{
    ClosureExport, ClosureManifest, ClosureReport, Known, MAX_CLOSURE_PACKS, MAX_MANIFEST_BYTES,
    ObjectSource, export_closure, verify_closure, verify_closure_manifest, verify_closure_packs,
    verify_closure_store, verify_closure_streaming,
};
mod push;
pub use push::{PushReport, verify_push};
/// Exact proof wire-size planning from canonical object metadata.
pub mod proof_size;
pub mod span;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// One authenticated hop of a path: the entry `name`/`mode` proven at
/// `position` under its parent (a commit's `tree_hash`, or the previous
/// step's `child_id`), via a single-leaf [`Proof`].
///
/// This is both the in-memory type [`verify_path`] takes and the wire
/// representation inside a disclosure bundle (§ module docs) — there is
/// no separate internal wire struct to keep in sync.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// The entry's name (1..=255 bytes; SPEC-OBJECTS §4.1 rules apply).
    pub name: Vec<u8>,
    /// The entry's mode.
    pub mode: EntryMode,
    /// The entry's child object id.
    pub child_id: Hash,
    /// Bare BMT root of the **parent** Tree this step's proof is verified
    /// against (the tree whose id is the commit's `tree_hash` for step 0,
    /// or the previous step's `child_id`). Wrap-checked against that id
    /// before use; never a second trust anchor.
    pub inner_root: Hash,
    /// The entry's BMT position (= index) within its parent `Tree`.
    pub position: u32,
    /// Single-leaf inclusion proof (`max_items = 1`) that `(name, mode,
    /// child_id)` is the entry at `position` in the parent tree.
    pub proof: Proof,
}

/// The result of walking and verifying a path from a commit's
/// `tree_hash` down to a leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathVerified {
    /// The commit's (or remix's) root tree id.
    pub tree_hash: Hash,
    /// The authenticated path, root first: each entry's `(name, mode)` —
    /// never a caller-claimed path string. Callers compare this against
    /// what they requested; this module never trusts a claimed path.
    pub path: Vec<(Vec<u8>, EntryMode)>,
    /// The id of the object at the end of the path (`tree_hash` itself
    /// when `path` is empty).
    pub leaf_id: Hash,
    /// The commit/remix's embedded Ed25519 public key.
    pub signer: [u8; 32],
    /// Whether the commit/remix's embedded signature verifies against
    /// `signer`. Does **not** say anything about who `signer` belongs to
    /// — that is application policy (see the module docs).
    pub signature_valid: bool,
}

/// A verified partial disclosure: `payload` is exactly the content
/// `commit_id` commits to at `path`, and nothing more. See the module
/// docs for the precise trust model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disclosed {
    /// The commit id the disclosure was verified against.
    pub commit_id: Hash,
    /// The commit's (or remix's) root tree id.
    pub tree_hash: Hash,
    /// The authenticated path, root first (see [`PathVerified::path`]).
    pub path: Vec<(Vec<u8>, EntryMode)>,
    /// The id of the disclosed leaf object.
    pub leaf_id: Hash,
    /// The disclosed content.
    pub payload: DisclosedPayload,
    /// The commit/remix's embedded Ed25519 public key.
    pub signer: [u8; 32],
    /// Whether the commit/remix's embedded signature verifies. See
    /// [`PathVerified::signature_valid`].
    pub signature_valid: bool,
    /// Authenticated bare BMT inner root of each step's parent Tree,
    /// root first. Empty when `steps` is empty (root-tree disclosure).
    /// Each value has been wrap-checked against the parent id and
    /// cross-checked against the proof fold.
    pub step_inner_roots: Vec<Hash>,
    /// Authenticated bare BMT inner root of the leaf `ChunkedBlob`, when
    /// the payload is `Chunk` or a `Range` over a chunk. `None` for an
    /// `Object` payload or a `Range` over a plain `Blob`.
    pub chunk_inner_root: Option<Hash>,
}

/// The disclosed content of a [`Disclosed`] result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisclosedPayload {
    /// The leaf's full canonical object bytes; `hash`/`id_from_object` of
    /// `bytes` equals `Disclosed::leaf_id`.
    Object {
        /// Canonical object bytes.
        bytes: Vec<u8>,
    },
    /// One whole chunk of a `ChunkedBlob` leaf, plus its authenticated
    /// manifest metadata.
    Chunk {
        /// The `ChunkedBlob`'s authenticated total content size.
        total_size: u64,
        /// The `ChunkedBlob`'s authenticated chunk-size marker (`0` =
        /// content-defined chunking).
        chunk_size: u32,
        /// The chunk's index within the manifest.
        index: u32,
        /// The offset of the chunk's first byte in the file, as the
        /// manifest commits it.
        start: u64,
        /// The offset one past the chunk's last byte in the file.
        end: u64,
        /// The chunk's canonical `Blob` bytes.
        bytes: Vec<u8>,
    },
    /// A byte range of a `Blob`, or of one chunk of a `ChunkedBlob`.
    Range {
        /// The id of the object the range was sliced from: the leaf
        /// itself when it is a plain `Blob`, or the containing chunk's
        /// id when the leaf is a `ChunkedBlob`.
        blob_id: Hash,
        /// `Some((index, total_size, chunk_size))` when the leaf is a
        /// `ChunkedBlob` (the authenticated manifest metadata for the
        /// containing chunk); `None` when the leaf is a plain `Blob`.
        chunk: Option<(u32, u64, u32)>,
        /// The range's offset within `blob_id`'s content (the chunk's
        /// content when `chunk` is `Some`, the blob's content otherwise).
        offset_in_blob: u64,
        /// The offset of the containing chunk's first byte in the file;
        /// `None` when the leaf is a plain `Blob`.
        start: Option<u64>,
        /// The offset one past the containing chunk's last byte in the file;
        /// `None` when the leaf is a plain `Blob`.
        end: Option<u64>,
        /// The range's offset within the *whole* disclosed file:
        /// `start + offset_in_blob` for a `ChunkedBlob`, `offset_in_blob`
        /// itself for a plain `Blob`. Always present: the chunk's leaf
        /// commits its span.
        absolute_offset: u64,
        /// The disclosed bytes.
        bytes: Vec<u8>,
    },
}

/// What [`build_disclosure`] discloses about the leaf its `path` reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selector {
    /// Disclose the leaf's full canonical object bytes.
    Object,
    /// Disclose one whole chunk of a `ChunkedBlob` leaf, by index.
    Chunk(u32),
    /// Disclose a byte range of a `Blob`/`ChunkedBlob` leaf's content.
    Range {
        /// Start offset within the leaf's content.
        offset: u64,
        /// Range length in bytes (MUST be non-zero).
        len: u64,
    },
}

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

/// Deserialize `bytes` and check that its content-address (BLAKE3 of the
/// bytes, or the merkle BMT root for a `Tree`/`ChunkedBlob`) equals
/// `expected`.
///
/// # Errors
///
/// [`VerifyError::Decode`] if `bytes` does not decode; otherwise
/// [`VerifyError::PayloadIdMismatch`] if the derived id disagrees with
/// `expected`.
/// Wrap-check-first: `domain_digest(TYPE_DOMAIN, inner_root) == expected_id`.
/// The declared field is never a second trust anchor.
fn check_inner_root_wrap(
    kind: ObjectKind,
    expected_id: &Hash,
    inner_root: &Hash,
) -> Result<(), VerifyError> {
    if merkle::wrap_id(kind, inner_root) == *expected_id {
        Ok(())
    } else {
        Err(VerifyError::InnerRootMismatch {
            expected: *expected_id,
            inner_root: *inner_root,
        })
    }
}

/// Proof fold equals the declared inner root, then wrap of the fold
/// equals `expected_id` (today's id check). Both must hold.
fn check_inner_root_fold(
    folded: Hash,
    declared: &Hash,
    expected_id: &Hash,
    kind: ObjectKind,
) -> Result<(), VerifyError> {
    if folded != *declared {
        return Err(VerifyError::InnerRootFoldMismatch);
    }
    if merkle::wrap_id(kind, &folded) == *expected_id {
        Ok(())
    } else {
        Err(VerifyError::Merkle(MerkleError::VerificationFailed))
    }
}

pub fn verify_object_id(bytes: &[u8], expected: &Hash) -> Result<Object, VerifyError> {
    let obj = crate::serialize::deserialize(bytes)?;
    let got = crate::object::id_from_object(&obj, bytes);
    if &got == expected {
        Ok(obj)
    } else {
        Err(VerifyError::PayloadIdMismatch)
    }
}

/// Verify a path of [`Step`]s from a commit/remix's `tree_hash` down to a
/// leaf id, checking each step's proof against the previous step's
/// `child_id` (the first against `tree_hash` itself).
///
/// `commit_bytes` MUST hash to `commit_id` and decode to a `Commit` or
/// `Remix` — every other object kind has no `tree_hash` to walk from.
/// Every non-final step MUST have `mode == Tree`. The returned `path` is
/// the authenticated `(name, mode)` sequence; callers compare it against
/// whatever path string they requested — this function never trusts one.
///
/// # Errors
///
/// See [`VerifyError`]'s variant docs for the specific failure reported.
pub fn verify_path(
    commit_id: &Hash,
    commit_bytes: &[u8],
    steps: &[Step],
) -> Result<PathVerified, VerifyError> {
    if hash(commit_bytes) != *commit_id {
        return Err(VerifyError::CommitBytesHashMismatch);
    }
    if steps.len() > MAX_TREE_DEPTH {
        return Err(VerifyError::TooManySteps(steps.len()));
    }
    let obj = crate::serialize::deserialize(commit_bytes)?;
    let (tree_hash, signer, signature_valid) = match &obj {
        Object::Commit(c) => (c.tree_hash, c.signer, verify_commit(c).is_ok()),
        Object::Remix(r) => (r.tree_hash, r.signer, verify_remix(r).is_ok()),
        other => return Err(VerifyError::NotACommitOrRemix(other.object_type())),
    };
    verify_path_with_context(
        steps,
        &CommitContext {
            tree_hash,
            signer,
            signature_valid,
        },
    )
}

/// Commit authentication shared by all bundles in one KDSP container.
#[derive(Clone, Copy)]
pub(crate) struct CommitContext {
    tree_hash: Hash,
    signer: [u8; 32],
    signature_valid: bool,
}

impl CommitContext {
    pub(crate) fn from_disclosed(d: &Disclosed) -> Self {
        Self {
            tree_hash: d.tree_hash,
            signer: d.signer,
            signature_valid: d.signature_valid,
        }
    }
}

/// Reuse a commit that the container has authenticated once, but still bind
/// each inner bundle's own commit bytes to the trusted id.
pub(crate) fn verify_path_reusing_context(
    commit_id: &Hash,
    commit_bytes: &[u8],
    steps: &[Step],
    context: &CommitContext,
) -> Result<PathVerified, VerifyError> {
    if hash(commit_bytes) != *commit_id {
        return Err(VerifyError::CommitBytesHashMismatch);
    }
    verify_path_with_context(steps, context)
}

fn verify_path_with_context(
    steps: &[Step],
    context: &CommitContext,
) -> Result<PathVerified, VerifyError> {
    if steps.len() > MAX_TREE_DEPTH {
        return Err(VerifyError::TooManySteps(steps.len()));
    }

    let mut expected_parent = context.tree_hash;
    let mut leaf_id = context.tree_hash;
    let mut path = Vec::with_capacity(steps.len());
    let last = steps.len().wrapping_sub(1);
    for (i, step) in steps.iter().enumerate() {
        if !TreeEntry::validate_name(&step.name) {
            return Err(VerifyError::InvalidEntryName(i));
        }
        if i != last && step.mode != EntryMode::Tree {
            return Err(VerifyError::NonFinalStepNotTree(i));
        }
        let entry = TreeEntry {
            name: step.name.clone(),
            mode: step.mode,
            object_hash: step.child_id,
        };
        check_inner_root_wrap(ObjectKind::Tree, &expected_parent, &step.inner_root)?;
        let folded = step
            .proof
            .reconstruct_element_root(&merkle::tree_entry_leaf(&entry), step.position)?;
        check_inner_root_fold(folded, &step.inner_root, &expected_parent, ObjectKind::Tree)?;
        path.push((step.name.clone(), step.mode));
        expected_parent = step.child_id;
        leaf_id = step.child_id;
    }

    Ok(PathVerified {
        tree_hash: context.tree_hash,
        path,
        leaf_id,
        signer: context.signer,
        signature_valid: context.signature_valid,
    })
}

/// The BMT position of chunk `index` in a manifest whose proof claims
/// `leaf_count` leaves (the metadata leaf, then one per chunk).
fn chunk_position(index: u32, leaf_count: u32) -> Result<u32, VerifyError> {
    let out_of_range = VerifyError::ChunkIndexOutOfRange { index, leaf_count };
    let chunk_count = leaf_count
        .checked_sub(1)
        .ok_or(VerifyError::ChunkIndexOutOfRange { index, leaf_count })?;
    if chunk_count > crate::serialize::MAX_CHUNKS {
        return Err(VerifyError::TooManyChunks);
    }
    index
        .checked_add(1)
        .filter(|&p| p < leaf_count)
        .ok_or(out_of_range)
}

/// The header fields and proof a chunked-leaf check starts from: what a
/// `Chunk` payload or a `ChunkHdr` declares.
struct ChunkClaim<'a> {
    total_size: u64,
    chunk_size: u32,
    index: u32,
    chunk: merkle::SpannedChunk,
    inner_root: &'a Hash,
    proof: &'a Proof,
}

/// The chunked-leaf checks of SPEC-DISCLOSURE §4 that every chunk payload
/// shares: the wrap check, step 1 (the multi-proof folds to the declared
/// inner root, which wraps to `chunked_id`), the header check on
/// `leaf_count - 1`, and steps 2 to 5 (the span).
fn verify_chunk_claim(chunked_id: &Hash, claim: &ChunkClaim<'_>) -> Result<(), VerifyError> {
    check_inner_root_wrap(ObjectKind::ChunkedBlob, chunked_id, claim.inner_root)?;
    let leaf_count = claim.proof.leaf_count;
    let position = chunk_position(claim.index, leaf_count)?;
    let meta_leaf = merkle::chunked_meta_leaf_raw(claim.total_size, claim.chunk_size);
    let chunk_leaf =
        merkle::chunked_chunk_leaf_raw(claim.chunk.start, claim.chunk.end, &claim.chunk.id);
    let folded = claim
        .proof
        .reconstruct_multi_root(&[(meta_leaf, 0u32), (chunk_leaf, position)])?;
    check_inner_root_fold(
        folded,
        claim.inner_root,
        chunked_id,
        ObjectKind::ChunkedBlob,
    )?;
    // The verifier never decodes the manifest, so it applies the header
    // check itself; `leaf_count` is trusted only once the fold has passed.
    crate::serialize::check_chunked_total_size(claim.total_size, claim.chunk_size, leaf_count - 1)?;
    check_chunk_span(claim, leaf_count)
}

/// Steps 2 to 5 of the chunked-leaf checks: the span lies in the file and
/// fits one Blob, the first and last chunks sit at the ends of the file, and
/// a fixed-size layout puts each chunk where its index says.
fn check_chunk_span(claim: &ChunkClaim<'_>, leaf_count: u32) -> Result<(), VerifyError> {
    let ChunkClaim {
        total_size,
        chunk_size,
        index,
        chunk: merkle::SpannedChunk { start, end, .. },
        ..
    } = *claim;
    if start >= end || end > total_size {
        return Err(VerifyError::SpanOutsideFile {
            start,
            end,
            total_size,
        });
    }
    if end - start > crate::serialize::MAX_CHUNK_LEN {
        return Err(VerifyError::SpanAboveObjectLimit { start, end });
    }
    if (index == 0) != (start == 0) {
        return Err(VerifyError::FirstChunkStart { index, start });
    }
    // `chunk_position` ruled out `index + 1 >= leaf_count`.
    let is_last = index + 2 == leaf_count;
    if is_last != (end == total_size) {
        return Err(VerifyError::LastChunkEnd { index, end });
    }
    if crate::chunker::Chunker::from_chunk_size(chunk_size).is_none() {
        let fixed_start = u64::from(index).checked_mul(u64::from(chunk_size));
        let fixed_end = start
            .checked_add(u64::from(chunk_size))
            .map(|end| end.min(total_size));
        if fixed_start != Some(start) || fixed_end != Some(end) {
            return Err(VerifyError::FixedChunkLength { index, start, end });
        }
    }
    Ok(())
}

/// Verify a Bao slice against `root`/`bao_offset`/`len`, returning the
/// decoded bytes. Used by [`verify_blob_slice`] (content offset + 10).
fn bao_verify_slice(
    root: &Hash,
    bao_offset: u64,
    len: u64,
    slice: &[u8],
) -> Result<Vec<u8>, VerifyError> {
    let h: bao::Hash = (*root).into();
    let mut decoder =
        bao::decode::SliceDecoder::new(std::io::Cursor::new(slice), &h, bao_offset, len);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|e| VerifyError::Bao(e.to_string()))?;
    if out.len() as u64 != len {
        return Err(VerifyError::ShortSlice {
            expected: len,
            got: out.len(),
        });
    }
    Ok(out)
}

/// Verify a Bao slice proving `len` content bytes at `content_offset`
/// belong to the object (`Blob`, or one `ChunkedBlob` chunk) whose
/// canonical-bytes BLAKE3 is `blob_id`. `slice` is expected in the format
/// `bao::encode::SliceExtractor` produces over the object's **canonical**
/// bytes (prologue ‖ `le32(len)` ‖ data) — so a Bao-authenticated content
/// offset `o` maps to Bao offset `o + 10`, and the returned root equals
/// the object's own id (SPEC-OBJECTS §3).
///
/// # Errors
///
/// [`VerifyError::ZeroLengthRange`] if `len == 0`;
/// [`VerifyError::OffsetOverflow`] if `content_offset + 10` overflows
/// `u64`; [`VerifyError::Bao`]/[`VerifyError::ShortSlice`] if the slice
/// does not verify or yields fewer bytes than `len`.
pub fn verify_blob_slice(
    blob_id: &Hash,
    content_offset: u64,
    len: u64,
    slice: &[u8],
) -> Result<Vec<u8>, VerifyError> {
    if len == 0 {
        return Err(VerifyError::ZeroLengthRange);
    }
    let bao_offset = content_offset
        .checked_add(10)
        .ok_or(VerifyError::OffsetOverflow)?;
    bao_verify_slice(blob_id, bao_offset, len, slice)
}

/// The content length a chunk's `bytes` declare, when they are exactly one
/// canonical Blob (SPEC-OBJECTS §3 and §11): the type, magic and schema of
/// the 10-byte prologue, a length field, and that many content bytes with
/// no byte after. `None` for anything else.
fn blob_content_len(bytes: &[u8]) -> Option<u64> {
    let (prologue, content) = bytes.split_at_checked(10)?;
    if prologue[0] != ObjectType::Blob as u8
        || prologue[1..5] != MAGIC
        || prologue[5] != ObjectType::Blob.schema_version()
    {
        return None;
    }
    let declared = u64::from(u32::from_le_bytes(prologue[6..10].try_into().ok()?));
    (declared == content.len() as u64).then_some(declared)
}

// ---------------------------------------------------------------------------
// Bundle: decode + verify
// ---------------------------------------------------------------------------

/// Wire representation of the `ChunkHdr` sub-message (Range payload,
/// chunked case). Kept private: callers see the authenticated
/// [`DisclosedPayload::Range`] fields, never this wire shape directly.
#[derive(Debug, Clone)]
struct ChunkHdr {
    total_size: u64,
    chunk_size: u32,
    index: u32,
    start: u64,
    end: u64,
    inner_root: Hash,
    chunk_id: Hash,
    proof: Proof,
}

impl Write for ChunkHdr {
    fn write(&self, writer: &mut impl BufMut) {
        self.total_size.write(writer);
        self.chunk_size.write(writer);
        self.index.write(writer);
        self.start.write(writer);
        self.end.write(writer);
        self.inner_root.write(writer);
        self.chunk_id.write(writer);
        self.proof.write(writer);
    }
}

impl EncodeSize for ChunkHdr {
    fn encode_size(&self) -> usize {
        self.total_size.encode_size()
            + self.chunk_size.encode_size()
            + self.index.encode_size()
            + self.start.encode_size()
            + self.end.encode_size()
            + self.inner_root.encode_size()
            + self.chunk_id.encode_size()
            + self.proof.encode_size()
    }
}

impl Read for ChunkHdr {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, (): &Self::Cfg) -> Result<Self, CodecError> {
        let total_size = u64::read(reader)?;
        let chunk_size = u32::read(reader)?;
        let index = u32::read(reader)?;
        let start = u64::read(reader)?;
        let end = u64::read(reader)?;
        let inner_root = Hash::read(reader)?;
        let chunk_id = Hash::read(reader)?;
        let proof = Proof::read_cfg(reader, &2usize)?;
        Ok(Self {
            total_size,
            chunk_size,
            index,
            start,
            end,
            inner_root,
            chunk_id,
            proof,
        })
    }
}

impl Write for Step {
    fn write(&self, writer: &mut impl BufMut) {
        self.name.as_slice().write(writer);
        (self.mode as u8).write(writer);
        self.child_id.write(writer);
        self.inner_root.write(writer);
        self.position.write(writer);
        self.proof.write(writer);
    }
}

impl EncodeSize for Step {
    fn encode_size(&self) -> usize {
        self.name.as_slice().encode_size()
            + 1
            + self.child_id.encode_size()
            + self.inner_root.encode_size()
            + self.position.encode_size()
            + self.proof.encode_size()
    }
}

impl Read for Step {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, (): &Self::Cfg) -> Result<Self, CodecError> {
        let name = Vec::<u8>::read_range(reader, 1..=255)?;
        let mode_byte = u8::read(reader)?;
        let mode = EntryMode::from_u8(mode_byte).map_err(|_| CodecError::InvalidEnum(mode_byte))?;
        let child_id = Hash::read(reader)?;
        let inner_root = Hash::read(reader)?;
        let position = u32::read(reader)?;
        let proof = Proof::read_cfg(reader, &1usize)?;
        Ok(Self {
            name,
            mode,
            child_id,
            inner_root,
            position,
            proof,
        })
    }
}

/// Wire payload variants (`payload_kind` byte). Kept private: the public
/// surface is [`DisclosedPayload`] (verified) and [`Selector`] (build
/// request); this is only the on-wire shape between them.
enum PayloadWire {
    Object {
        bytes: Vec<u8>,
    },
    Chunk {
        total_size: u64,
        chunk_size: u32,
        index: u32,
        start: u64,
        end: u64,
        inner_root: Hash,
        proof: Proof,
        bytes: Vec<u8>,
    },
    Range {
        chunk: Option<ChunkHdr>,
        offset_in_blob: u64,
        len: u64,
        slice: Vec<u8>,
    },
}

/// Decode a disclosure bundle's fixed header plus codec body. Returns the
/// bundle's own embedded `commit_id` (still to be checked against the
/// caller's expected id by [`verify_disclosure`]), `commit_bytes`,
/// `steps`, and the decoded payload.
fn decode_disclosure(bytes: &[u8]) -> Result<(Hash, Vec<u8>, Vec<Step>, PayloadWire), VerifyError> {
    if bytes.len() > MAX_BUNDLE_BYTES {
        return Err(VerifyError::BundleTooLarge);
    }
    if bytes.len() < 5 || bytes[..4] != *BUNDLE_MAGIC {
        return Err(VerifyError::BadMagic);
    }
    let version = bytes[4];
    if version != BUNDLE_VERSION {
        return Err(VerifyError::UnsupportedBundleVersion(version));
    }
    let mut r = Copying(&bytes[5..]);
    let commit_id = Hash::read(&mut r)?;
    let commit_bytes = Vec::<u8>::read_range(&mut r, ..=MAX_COMMIT_BYTES)?;
    let steps = Vec::<Step>::read_range(&mut r, ..=MAX_TREE_DEPTH)?;
    let payload_kind = u8::read(&mut r)?;
    let payload = match payload_kind {
        0 => {
            let bytes = Vec::<u8>::read_range(&mut r, ..=crate::store::MAX_RAW_OBJECT_SIZE)?;
            PayloadWire::Object { bytes }
        }
        1 => {
            let total_size = u64::read(&mut r)?;
            let chunk_size = u32::read(&mut r)?;
            let index = u32::read(&mut r)?;
            let start = u64::read(&mut r)?;
            let end = u64::read(&mut r)?;
            let inner_root = Hash::read(&mut r)?;
            let proof = Proof::read_cfg(&mut r, &2usize)?;
            let bytes = Vec::<u8>::read_range(&mut r, ..=crate::store::MAX_RAW_OBJECT_SIZE)?;
            PayloadWire::Chunk {
                total_size,
                chunk_size,
                index,
                start,
                end,
                inner_root,
                proof,
                bytes,
            }
        }
        2 => {
            let chunk = Option::<ChunkHdr>::read(&mut r)?;
            let offset_in_blob = u64::read(&mut r)?;
            let len = u64::read(&mut r)?;
            let slice = Vec::<u8>::read_range(&mut r, ..=MAX_BUNDLE_BYTES)?;
            PayloadWire::Range {
                chunk,
                offset_in_blob,
                len,
                slice,
            }
        }
        other => return Err(VerifyError::InvalidPayloadKind(other)),
    };
    if r.has_remaining() {
        return Err(VerifyError::Malformed);
    }
    Ok((commit_id, commit_bytes, steps, payload))
}

/// Encode a disclosure bundle. The inverse of [`decode_disclosure`].
fn encode_disclosure(
    commit_id: &Hash,
    commit_bytes: &[u8],
    steps: &[Step],
    payload: &PayloadWire,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(BUNDLE_MAGIC);
    out.push(BUNDLE_VERSION);
    commit_id.write(&mut out);
    commit_bytes.write(&mut out);
    steps.write(&mut out);
    match payload {
        PayloadWire::Object { bytes } => {
            out.push(0);
            bytes.as_slice().write(&mut out);
        }
        PayloadWire::Chunk {
            total_size,
            chunk_size,
            index,
            start,
            end,
            inner_root,
            proof,
            bytes,
        } => {
            out.push(1);
            total_size.write(&mut out);
            chunk_size.write(&mut out);
            index.write(&mut out);
            start.write(&mut out);
            end.write(&mut out);
            inner_root.write(&mut out);
            proof.write(&mut out);
            bytes.as_slice().write(&mut out);
        }
        PayloadWire::Range {
            chunk,
            offset_in_blob,
            len,
            slice,
        } => {
            out.push(2);
            chunk.write(&mut out);
            offset_in_blob.write(&mut out);
            len.write(&mut out);
            slice.as_slice().write(&mut out);
        }
    }
    out
}

/// The mode the authenticated path gives its leaf: the last step's, or
/// `Tree` for the root tree.
fn leaf_mode(path: &[(Vec<u8>, EntryMode)]) -> EntryMode {
    path.last().map_or(EntryMode::Tree, |(_, mode)| *mode)
}

/// Reject a leaf of type `found` under a final step of mode `leaf_mode` when
/// the mode does not name that type.
fn check_leaf_type(leaf_mode: EntryMode, found: ObjectType) -> Result<(), VerifyError> {
    if ChildKind::Entry(leaf_mode).mask() & type_bit(found) == 0 {
        return Err(VerifyError::PayloadTypeMismatch {
            mode: leaf_mode,
            found,
        });
    }
    Ok(())
}

fn compose_payload(
    leaf_id: Hash,
    leaf_mode: EntryMode,
    payload: PayloadWire,
) -> Result<DisclosedPayload, VerifyError> {
    match payload {
        PayloadWire::Object { bytes } => {
            let found = verify_object_id(&bytes, &leaf_id)?.object_type();
            check_leaf_type(leaf_mode, found)?;
            Ok(DisclosedPayload::Object { bytes })
        }
        PayloadWire::Chunk {
            total_size,
            chunk_size,
            index,
            start,
            end,
            inner_root,
            proof,
            bytes,
        } => {
            check_leaf_type(leaf_mode, ObjectType::ChunkedBlob)?;
            let claim = ChunkClaim {
                total_size,
                chunk_size,
                index,
                chunk: merkle::SpannedChunk {
                    id: hash(&bytes),
                    start,
                    end,
                },
                inner_root: &inner_root,
                proof: &proof,
            };
            verify_chunk_claim(&leaf_id, &claim)?;
            // Step 6: the bytes are one Blob, as long as the span.
            let content_len = blob_content_len(&bytes).ok_or(VerifyError::ChunkBytesNotBlob)?;
            if content_len != end - start {
                return Err(VerifyError::ChunkLengthDiffersFromSpan {
                    index,
                    expected: end - start,
                    actual: content_len,
                });
            }
            Ok(DisclosedPayload::Chunk {
                total_size,
                chunk_size,
                index,
                start,
                end,
                bytes,
            })
        }
        PayloadWire::Range {
            chunk: None,
            offset_in_blob,
            len,
            slice,
        } => {
            check_leaf_type(leaf_mode, ObjectType::Blob)?;
            let bytes = verify_blob_slice(&leaf_id, offset_in_blob, len, &slice)?;
            Ok(DisclosedPayload::Range {
                blob_id: leaf_id,
                chunk: None,
                offset_in_blob,
                start: None,
                end: None,
                absolute_offset: offset_in_blob,
                bytes,
            })
        }
        PayloadWire::Range {
            chunk: Some(hdr),
            offset_in_blob,
            len,
            slice,
        } => {
            check_leaf_type(leaf_mode, ObjectType::ChunkedBlob)?;
            compose_chunk_range(&leaf_id, &hdr, offset_in_blob, len, &slice)
        }
    }
}

/// Steps 4 to 8 of a chunk range disclosure: the chunk claim folds into the
/// leaf, the range lies inside the committed span, and the Bao slice proves
/// the bytes.
fn compose_chunk_range(
    leaf_id: &Hash,
    hdr: &ChunkHdr,
    offset_in_blob: u64,
    len: u64,
    slice: &[u8],
) -> Result<DisclosedPayload, VerifyError> {
    // SPEC-DISCLOSURE §4: `len == 0` is rejected before the wrap/fold
    // checks below, so it wins over e.g. InnerRootMismatch when a bundle is
    // malformed both ways.
    if len == 0 {
        return Err(VerifyError::ZeroLengthRange);
    }
    let claim = ChunkClaim {
        total_size: hdr.total_size,
        chunk_size: hdr.chunk_size,
        index: hdr.index,
        chunk: merkle::SpannedChunk {
            id: hdr.chunk_id,
            start: hdr.start,
            end: hdr.end,
        },
        inner_root: &hdr.inner_root,
        proof: &hdr.proof,
    };
    verify_chunk_claim(leaf_id, &claim)?;
    // Step 7: the range lies inside the committed span.
    let span_len = hdr.end - hdr.start;
    if offset_in_blob
        .checked_add(len)
        .is_none_or(|range_end| range_end > span_len)
    {
        return Err(VerifyError::RangePastSpan {
            offset_in_blob,
            len,
            span_len,
        });
    }
    let bytes = verify_blob_slice(&hdr.chunk_id, offset_in_blob, len, slice)?;
    // Step 8: the span puts the range in the file.
    let absolute_offset = hdr
        .start
        .checked_add(offset_in_blob)
        .ok_or(VerifyError::OffsetOverflow)?;
    Ok(DisclosedPayload::Range {
        blob_id: hdr.chunk_id,
        chunk: Some((hdr.index, hdr.total_size, hdr.chunk_size)),
        offset_in_blob,
        start: Some(hdr.start),
        end: Some(hdr.end),
        absolute_offset,
        bytes,
    })
}

/// Decode and fully verify a disclosure bundle against `commit_id`.
///
/// # Errors
///
/// See [`VerifyError`]'s variant docs. In particular: a bundle whose
/// embedded `commit_id` disagrees with the argument, whose `commit_bytes`
/// does not hash to it, or whose payload fails its merkle/Bao check, is
/// rejected with a specific typed error — never a bare "invalid".
pub fn verify_disclosure(commit_id: &Hash, bundle: &[u8]) -> Result<Disclosed, VerifyError> {
    let (wire_commit_id, commit_bytes, steps, payload) = decode_disclosure(bundle)?;
    if wire_commit_id != *commit_id {
        return Err(VerifyError::CommitIdMismatch);
    }
    let verified = verify_path(commit_id, &commit_bytes, &steps)?;
    let step_inner_roots: Vec<Hash> = steps.iter().map(|s| s.inner_root).collect();
    let chunk_inner_root = match &payload {
        PayloadWire::Chunk { inner_root, .. } => Some(*inner_root),
        PayloadWire::Range {
            chunk: Some(hdr), ..
        } => Some(hdr.inner_root),
        _ => None,
    };
    let payload = compose_payload(verified.leaf_id, leaf_mode(&verified.path), payload)?;
    Ok(Disclosed {
        commit_id: *commit_id,
        tree_hash: verified.tree_hash,
        path: verified.path,
        leaf_id: verified.leaf_id,
        payload,
        signer: verified.signer,
        signature_valid: verified.signature_valid,
        step_inner_roots,
        chunk_inner_root,
    })
}

/// KDSP-only verification path. The container authenticated `context`; the
/// inner bundle still has to carry commit bytes hashing to `commit_id`.
pub(crate) fn verify_disclosure_reusing_context(
    commit_id: &Hash,
    bundle: &[u8],
    context: &CommitContext,
) -> Result<Disclosed, VerifyError> {
    let (wire_commit_id, commit_bytes, steps, payload) = decode_disclosure(bundle)?;
    if wire_commit_id != *commit_id {
        return Err(VerifyError::CommitIdMismatch);
    }
    let verified = verify_path_reusing_context(commit_id, &commit_bytes, &steps, context)?;
    let step_inner_roots = steps.iter().map(|s| s.inner_root).collect();
    let chunk_inner_root = match &payload {
        PayloadWire::Chunk { inner_root, .. } => Some(*inner_root),
        PayloadWire::Range {
            chunk: Some(hdr), ..
        } => Some(hdr.inner_root),
        _ => None,
    };
    let payload = compose_payload(verified.leaf_id, leaf_mode(&verified.path), payload)?;
    Ok(Disclosed {
        commit_id: *commit_id,
        tree_hash: verified.tree_hash,
        path: verified.path,
        leaf_id: verified.leaf_id,
        payload,
        signer: verified.signer,
        signature_valid: verified.signature_valid,
        step_inner_roots,
        chunk_inner_root,
    })
}

// ---------------------------------------------------------------------------
// Builder (generic over `crate::store::ObjectSource`)
// ---------------------------------------------------------------------------

/// Build a Bao outboard encoding of `bytes` and extract a slice proving
/// `len` bytes at `bao_offset`.
fn extract_bao_slice(bytes: &[u8], bao_offset: u64, len: u64) -> Result<Vec<u8>, VerifyError> {
    let (outboard, _root) = bao::encode::outboard(bytes);
    let mut extractor = bao::encode::SliceExtractor::new_outboard(
        std::io::Cursor::new(bytes),
        std::io::Cursor::new(outboard),
        bao_offset,
        len,
    );
    let mut out = Vec::new();
    extractor
        .read_to_end(&mut out)
        .map_err(|e| VerifyError::Bao(e.to_string()))?;
    Ok(out)
}

/// Build a disclosure bundle proving `selector`'s content at `path` under
/// `commit_id`, reading only from `store`. `path` empty with
/// [`Selector::Object`] discloses the root tree.
///
/// A thin wrapper over [`build_disclosure_from`] for the on-disk
/// [`crate::store::ObjectStore`]; the bundle bytes are identical.
///
/// # Errors
///
/// [`VerifyError::Store`] for any missing/corrupt object; typed errors
/// (see [`VerifyError`]) for a path that does not resolve, a selector
/// that does not match the leaf's object type, an out-of-bounds range, or
/// a range that crosses a `ChunkedBlob` chunk boundary (unsupported in
/// this profile).
pub fn build_disclosure(
    store: &crate::store::ObjectStore,
    commit_id: &Hash,
    path: &[&[u8]],
    selector: Selector,
) -> Result<Vec<u8>, VerifyError> {
    build_disclosure_from(store, commit_id, path, selector)
}

/// Build a disclosure bundle proving `selector`'s content at `path` under
/// `commit_id`, reading only through `source`: any
/// [`crate::store::ObjectSource`] (the on-disk store, an
/// [`crate::store::EphemeralSink`], or a server-side repository index or
/// object CAS). Not to be confused with [`ObjectSource`], this module's
/// non-verifying closure-walker trait (`fetch(&mut self)`).
///
/// `source` MUST return verified bytes from `read`/`read_object` (the
/// [`crate::store::ObjectSource`] contract). The builder never calls
/// `read_unverified` and adds no verification of its own, so the bundle
/// bytes are identical to [`build_disclosure`]'s for the same objects.
/// [`crate::store::DisplaySource`] is therefore not a valid source: its
/// `read` skips verification.
///
/// A source that breaks the contract (returns bytes that do not hash to
/// the requested id) still cannot make the builder panic, and cannot make
/// it emit a bundle that verifies for content `commit_id` does not commit
/// to, because the bundle is self-authenticating against `commit_id`. The
/// build then either fails with a typed [`VerifyError`] or yields a bundle
/// that [`verify_disclosure`] rejects. It can still waste work: the
/// builder bounds nothing beyond what the objects themselves declare.
///
/// A source reports an absent object as
/// [`crate::store::StoreError::ObjectNotFound`], which surfaces as
/// [`VerifyError::Store`] exactly as on the store path.
///
/// # Errors
///
/// As [`build_disclosure`].
pub fn build_disclosure_from<S: crate::store::ObjectSource + ?Sized>(
    source: &S,
    commit_id: &Hash,
    path: &[&[u8]],
    selector: Selector,
) -> Result<Vec<u8>, VerifyError> {
    let (commit_bytes, steps, leaf_id) = build_prefix(source, commit_id, path)?;
    let payload = build_payload(source, &leaf_id, selector)?;
    Ok(encode_disclosure(
        commit_id,
        &commit_bytes,
        &steps,
        &payload,
    ))
}

fn build_prefix<S: crate::store::ObjectSource + ?Sized>(
    source: &S,
    commit_id: &Hash,
    path: &[&[u8]],
) -> Result<(Vec<u8>, Vec<Step>, Hash), VerifyError> {
    if path.len() > MAX_TREE_DEPTH {
        return Err(VerifyError::TooManySteps(path.len()));
    }
    let commit_bytes = source.read(commit_id)?;
    let commit_obj = crate::serialize::deserialize(&commit_bytes)?;
    let tree_hash = match &commit_obj {
        Object::Commit(c) => c.tree_hash,
        Object::Remix(r) => r.tree_hash,
        other => return Err(VerifyError::NotACommitOrRemix(other.object_type())),
    };

    let mut steps = Vec::with_capacity(path.len());
    let mut current_tree_id = tree_hash;
    let mut leaf_id = tree_hash;
    for (i, &name) in path.iter().enumerate() {
        let Object::Tree(tree) = source.read_object(&current_tree_id)? else {
            return Err(VerifyError::PathThroughNonTree);
        };
        let position =
            merkle::tree_entry_position(&tree, name).ok_or(VerifyError::PathNotFound(i))?;
        let entry = tree.entries[position as usize].clone();
        let proof = merkle::build_tree_entry_proof(&tree, position)?;
        steps.push(Step {
            name: name.to_vec(),
            mode: entry.mode,
            child_id: entry.object_hash,
            inner_root: merkle::tree_inner_root(&tree),
            position,
            proof,
        });
        leaf_id = entry.object_hash;
        let is_last = i + 1 == path.len();
        if entry.mode == EntryMode::Tree {
            current_tree_id = entry.object_hash;
        } else if !is_last {
            return Err(VerifyError::PathThroughNonTree);
        }
    }

    Ok((commit_bytes, steps, leaf_id))
}

fn build_payload<S: crate::store::ObjectSource + ?Sized>(
    source: &S,
    leaf_id: &Hash,
    selector: Selector,
) -> Result<PayloadWire, VerifyError> {
    match selector {
        Selector::Object => {
            let bytes = source.read(leaf_id)?;
            Ok(PayloadWire::Object { bytes })
        }
        Selector::Chunk(index) => {
            let Object::ChunkedBlob(cb) = source.read_object(leaf_id)? else {
                return Err(VerifyError::SelectorLeafMismatch);
            };
            let leaf_count = u32::try_from(cb.chunks().len())
                .ok()
                .and_then(|n| n.checked_add(1))
                .ok_or(VerifyError::TooManyChunks)?;
            let out_of_range = VerifyError::ChunkIndexOutOfRange { index, leaf_count };
            let (start, end) = cb.span(index).ok_or(out_of_range)?;
            let position = chunk_position(index, leaf_count)?;
            let chunk_id = cb.chunks()[index as usize];
            let proof = merkle::build_chunks_multi_proof(&cb, [0, position])?;
            let bytes = source.read(&chunk_id)?;
            // The source is untrusted: a chunk that is not one Blob as long
            // as its span would make a bundle that does not verify.
            let content_len = blob_content_len(&bytes).ok_or(VerifyError::ChunkBytesNotBlob)?;
            cb.check_chunk_length(index, content_len)?;
            Ok(PayloadWire::Chunk {
                total_size: cb.total_size(),
                chunk_size: cb.chunk_size(),
                index,
                start,
                end,
                inner_root: merkle::chunked_inner_root(&cb),
                proof,
                bytes,
            })
        }
        Selector::Range { offset, len } => {
            if len == 0 {
                return Err(VerifyError::ZeroLengthRange);
            }
            match source.read_object(leaf_id)? {
                Object::Blob(b) => {
                    let end = offset.checked_add(len).ok_or(VerifyError::OffsetOverflow)?;
                    if end > b.data.len() as u64 {
                        return Err(VerifyError::RangeOutOfBounds);
                    }
                    let canonical = source.read(leaf_id)?;
                    let bao_offset = offset.checked_add(10).ok_or(VerifyError::OffsetOverflow)?;
                    let slice = extract_bao_slice(&canonical, bao_offset, len)?;
                    Ok(PayloadWire::Range {
                        chunk: None,
                        offset_in_blob: offset,
                        len,
                        slice,
                    })
                }
                Object::ChunkedBlob(cb) => build_chunked_range_payload(source, &cb, offset, len),
                _ => Err(VerifyError::SelectorLeafMismatch),
            }
        }
    }
}

/// The `Range` payload for a byte range of a `ChunkedBlob`: the chunk that
/// holds `offset` is found by binary search over the manifest's ends, and
/// only that chunk is read.
fn build_chunked_range_payload<S: crate::store::ObjectSource + ?Sized>(
    source: &S,
    cb: &crate::object::ChunkedBlob,
    offset: u64,
    len: u64,
) -> Result<PayloadWire, VerifyError> {
    let index = cb.chunk_at(offset).ok_or(VerifyError::RangeOutOfBounds)?;
    let (start, end) = cb.span(index).ok_or(VerifyError::RangeOutOfBounds)?;
    let chunk_id = cb.chunks()[index as usize];
    // The source is untrusted for length: the bytes must be one Blob as long
    // as the span the manifest commits, or the bundle would not verify.
    let chunk_bytes = source.read(&chunk_id)?;
    let content_len = blob_content_len(&chunk_bytes).ok_or(VerifyError::ChunkBytesNotBlob)?;
    cb.check_chunk_length(index, content_len)?;

    // Every length and offset below is checked: `source` bytes and the
    // caller's `offset`/`len` are both untrusted here, and a panic (the
    // release profile has `overflow-checks = true`) is never acceptable.
    let offset_in_chunk = offset
        .checked_sub(start)
        .ok_or(VerifyError::OffsetOverflow)?;
    let range_end = offset_in_chunk
        .checked_add(len)
        .ok_or(VerifyError::OffsetOverflow)?;
    if range_end > end - start {
        return Err(VerifyError::RangeCrossesChunkBoundary);
    }

    let position = chunk_position(
        index,
        u32::try_from(cb.chunks().len()).map_err(|_| VerifyError::OffsetOverflow)? + 1,
    )?;
    let proof = merkle::build_chunks_multi_proof(cb, [0, position])?;
    let bao_offset = offset_in_chunk
        .checked_add(10)
        .ok_or(VerifyError::OffsetOverflow)?;
    let slice = extract_bao_slice(&chunk_bytes, bao_offset, len)?;

    Ok(PayloadWire::Range {
        chunk: Some(ChunkHdr {
            total_size: cb.total_size(),
            chunk_size: cb.chunk_size(),
            index,
            start,
            end,
            inner_root: merkle::chunked_inner_root(cb),
            chunk_id,
            proof,
        }),
        offset_in_blob: offset_in_chunk,
        len,
        slice,
    })
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers
mod tests {
    use super::*;
    use crate::hash::ZERO;
    use crate::layout::RepoLayout;
    use crate::object::{ChunkedBlob, Commit, Identity, Tree};
    use crate::sign::{KeyPair, sign_commit};
    use crate::store::{ObjectSink as _, ObjectStore};
    use crate::worktree::store_file_object;
    use std::collections::BTreeMap;

    /// A small deterministic repo: root tree with a shallow file, a
    /// 3-level-nested file, an executable file, and a chunked (> 1 MiB)
    /// file, committed under a fixed signer. Built fresh (native
    /// `ObjectStore`, no golden files) for this module's own unit tests;
    /// `tests/golden_disclosure.rs` carries the pinned wire-byte fixture.
    struct Fixture {
        _dir: tempfile::TempDir,
        store: ObjectStore,
        commit_id: Hash,
        chunked_bytes: Vec<u8>,
    }

    /// Write a commit over `tree_hash` under the fixed test signer.
    fn commit_for_tree(store: &ObjectStore, tree_hash: Hash) -> Hash {
        let kp = KeyPair::from_seed([0x07; 32]);
        let mut commit = Commit {
            tree_hash,
            parents: vec![],
            author: Identity::ed25519(kp.public.0),
            signer: kp.public.0,
            message: b"disclosure fixture".to_vec(),
            timestamp: 1_726_300_000,
            message_hash: ZERO,
            content_digest: ZERO,
            signature: [0u8; 64],
        };
        commit.signature = sign_commit(&commit, &kp).unwrap().0;
        let commit_bytes = crate::serialize::serialize(&Object::Commit(commit)).unwrap();
        store.write(&commit_bytes).unwrap()
    }

    /// A blob of `len` copies of `byte`, written to `store`, and its id.
    fn write_blob(store: &ObjectStore, byte: u8, len: usize) -> Hash {
        let bytes = crate::serialize::serialize(&Object::Blob(crate::object::Blob {
            data: vec![byte; len],
        }))
        .unwrap();
        store.write(&bytes).unwrap()
    }

    /// A range of a chunk that does not start the file may reach the end of
    /// that chunk and not one byte past it.
    #[test]
    fn range_disclosure_ends_at_the_end_of_its_chunk() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let store = ObjectStore::init(&RepoLayout::single(dir.path())).expect("store init");
        let chunks = (1..=3u8)
            .map(|b| (write_blob(&store, b, 1000), 1000))
            .collect();
        let manifest = Object::ChunkedBlob(crate::object::testing::sized(0, chunks).unwrap());
        let leaf = store
            .write(&crate::serialize::serialize(&manifest).unwrap())
            .unwrap();
        // Chunk 1 holds bytes 1000..2000.
        for (offset, len) in [(1500, 500), (1999, 1), (1000, 1000)] {
            assert!(
                build_payload(&store, &leaf, Selector::Range { offset, len }).is_ok(),
                "{offset}+{len}"
            );
        }
        for (offset, len) in [(1500, 501), (1500, 600), (1999, 2), (1000, 1001)] {
            assert!(
                matches!(
                    build_payload(&store, &leaf, Selector::Range { offset, len }),
                    Err(VerifyError::RangeCrossesChunkBoundary)
                ),
                "{offset}+{len}"
            );
        }
    }

    /// A byte-range disclosure reads only the chunk that holds the offset,
    /// so a file above the in-memory limit is disclosed without reading
    /// its other chunks. The second chunk here does not exist.
    #[test]
    fn range_disclosure_reads_only_the_chunk_that_holds_the_offset() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let store = ObjectStore::init(&RepoLayout::single(dir.path())).expect("store init");
        let first = write_blob(&store, b'a', 1000);
        let total = crate::worktree::MAX_FILE_BYTES + 1;
        let manifest = Object::ChunkedBlob(
            crate::object::ChunkedBlob::new(total, 0, [(first, 1000), ([2u8; 32], total)]).unwrap(),
        );
        let leaf = store
            .write(&crate::serialize::serialize(&manifest).unwrap())
            .unwrap();
        let selector = Selector::Range {
            offset: 999,
            len: 1,
        };
        assert!(matches!(
            build_payload(&store, &leaf, selector),
            Ok(PayloadWire::Range { len: 1, .. })
        ));
        // An offset in the missing chunk is a store error, not a panic.
        let selector = Selector::Range {
            offset: 1000,
            len: 1,
        };
        assert!(matches!(
            build_payload(&store, &leaf, selector),
            Err(VerifyError::Store(_))
        ));
        // Past the end of the file.
        let selector = Selector::Range {
            offset: total,
            len: 1,
        };
        assert!(matches!(
            build_payload(&store, &leaf, selector),
            Err(VerifyError::RangeOutOfBounds)
        ));
    }

    /// A byte-range disclosure from the last chunk of a manifest whose
    /// chunk blobs fill their spans exactly.
    #[test]
    fn range_disclosure_reads_the_chunk_holding_the_last_byte() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let store = ObjectStore::init(&RepoLayout::single(dir.path())).expect("store init");
        let chunk = write_blob(&store, b'a', 1000);
        let manifest =
            Object::ChunkedBlob(crate::object::testing::sized(0, vec![(chunk, 1000); 2]).unwrap());
        let leaf = store
            .write(&crate::serialize::serialize(&manifest).unwrap())
            .unwrap();
        let selector = Selector::Range {
            offset: 1999,
            len: 1,
        };
        assert!(matches!(
            build_payload(&store, &leaf, selector),
            Ok(PayloadWire::Range {
                len: 1,
                offset_in_blob: 999,
                ..
            })
        ));
    }

    /// A chunk blob whose length is not its span is refused by the builder,
    /// as the verifier would refuse the bundle, and a chunk that is not a
    /// Blob is refused too.
    #[test]
    fn range_disclosure_refuses_a_chunk_that_is_not_its_span() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let store = ObjectStore::init(&RepoLayout::single(dir.path())).expect("store init");
        let chunk = write_blob(&store, b'a', 1000);
        // Two 750-byte spans over 1000-byte blobs.
        let manifest =
            Object::ChunkedBlob(crate::object::testing::spread(1500, 0, vec![chunk; 2]).unwrap());
        let leaf = store
            .write(&crate::serialize::serialize(&manifest).unwrap())
            .unwrap();
        let selector = Selector::Range { offset: 0, len: 1 };
        assert!(matches!(
            build_payload(&store, &leaf, selector),
            Err(VerifyError::Decode(KitError::ChunkLengthMismatch {
                index: 0,
                expected: 750,
                actual: 1000,
            }))
        ));
        // A chunk id that names a manifest, not a Blob.
        let not_a_blob = store
            .write(&crate::serialize::serialize(&manifest).unwrap())
            .unwrap();
        let manifest = Object::ChunkedBlob(
            crate::object::ChunkedBlob::new(10, 0, [(not_a_blob, 10)]).unwrap(),
        );
        let leaf = store
            .write(&crate::serialize::serialize(&manifest).unwrap())
            .unwrap();
        assert!(matches!(
            build_payload(&store, &leaf, selector),
            Err(VerifyError::ChunkBytesNotBlob)
        ));
    }

    /// The chunk selector holds the same line: a chunk that is not as long as
    /// its span, or not a Blob, builds no bundle.
    #[test]
    fn chunk_disclosure_refuses_a_chunk_that_is_not_its_span() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let store = ObjectStore::init(&RepoLayout::single(dir.path())).expect("store init");
        let chunk = write_blob(&store, b'a', 1000);
        let manifest =
            Object::ChunkedBlob(crate::object::testing::spread(1500, 0, vec![chunk; 2]).unwrap());
        let leaf = store
            .write(&crate::serialize::serialize(&manifest).unwrap())
            .unwrap();
        assert!(matches!(
            build_payload(&store, &leaf, Selector::Chunk(1)),
            Err(VerifyError::Decode(KitError::ChunkLengthMismatch {
                index: 1,
                ..
            }))
        ));
        let not_a_blob = store
            .write(&crate::serialize::serialize(&manifest).unwrap())
            .unwrap();
        let manifest = Object::ChunkedBlob(
            crate::object::ChunkedBlob::new(10, 0, [(not_a_blob, 10)]).unwrap(),
        );
        let leaf = store
            .write(&crate::serialize::serialize(&manifest).unwrap())
            .unwrap();
        assert!(matches!(
            build_payload(&store, &leaf, Selector::Chunk(0)),
            Err(VerifyError::ChunkBytesNotBlob)
        ));
    }

    fn build_fixture() -> Fixture {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let store = ObjectStore::init(&RepoLayout::single(dir.path())).expect("store init");

        let shallow = store_file_object(&store, b"shallow file content").unwrap();
        let deep_file = store_file_object(&store, b"three levels deep").unwrap();
        let exec = store_file_object(&store, b"#!/bin/sh\necho hi\n").unwrap();

        // Deterministic pseudo-random 2 MiB stream so FastCDC yields
        // several chunks.
        let mut chunked_bytes = vec![0u8; 2 * 1024 * 1024];
        let mut x: u64 = 0x1234_5678_9abc_def0;
        for b in &mut chunked_bytes {
            x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            *b = (x >> 56) as u8;
        }
        let chunked_id = store_file_object(&store, &chunked_bytes).unwrap();

        let deep_tree = Tree {
            entries: vec![TreeEntry {
                name: b"deep.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: deep_file,
            }],
        };
        let deep_tree_id = store
            .write(&crate::serialize::serialize(&Object::Tree(deep_tree)).unwrap())
            .unwrap();

        let mid_tree = Tree {
            entries: vec![TreeEntry {
                name: b"deep".to_vec(),
                mode: EntryMode::Tree,
                object_hash: deep_tree_id,
            }],
        };
        let mid_tree_id = store
            .write(&crate::serialize::serialize(&Object::Tree(mid_tree)).unwrap())
            .unwrap();

        let root_tree = Tree {
            entries: vec![
                TreeEntry {
                    name: b"chunked.bin".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: chunked_id,
                },
                TreeEntry {
                    name: b"exec.sh".to_vec(),
                    mode: EntryMode::Executable,
                    object_hash: exec,
                },
                TreeEntry {
                    name: b"shallow.txt".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: shallow,
                },
                TreeEntry {
                    name: b"sub".to_vec(),
                    mode: EntryMode::Tree,
                    object_hash: mid_tree_id,
                },
            ],
        };
        let tree_hash = store
            .write(&crate::serialize::serialize(&Object::Tree(root_tree)).unwrap())
            .unwrap();

        let commit_id = commit_for_tree(&store, tree_hash);

        Fixture {
            _dir: dir,
            store,
            commit_id,
            chunked_bytes,
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)] // exercises every Selector against one fixture, kept together for auditability
    fn round_trips_every_selector() {
        let f = build_fixture();

        // Root tree, via Object.
        let bundle = build_disclosure(&f.store, &f.commit_id, &[], Selector::Object).unwrap();
        let d = verify_disclosure(&f.commit_id, &bundle).unwrap();
        assert!(d.path.is_empty());
        assert_eq!(d.leaf_id, d.tree_hash);
        assert!(d.signature_valid);

        // Shallow file, via Object.
        let bundle =
            build_disclosure(&f.store, &f.commit_id, &[b"shallow.txt"], Selector::Object).unwrap();
        let d = verify_disclosure(&f.commit_id, &bundle).unwrap();
        assert_eq!(d.path, vec![(b"shallow.txt".to_vec(), EntryMode::Blob)]);
        let DisclosedPayload::Object { bytes } = d.payload else {
            panic!("expected Object payload");
        };
        assert_eq!(
            bytes,
            crate::serialize::serialize(&Object::Blob(crate::object::Blob {
                data: b"shallow file content".to_vec()
            }))
            .unwrap()
        );

        // Nested (3-level) file.
        let bundle = build_disclosure(
            &f.store,
            &f.commit_id,
            &[b"sub", b"deep", b"deep.txt"],
            Selector::Object,
        )
        .unwrap();
        let d = verify_disclosure(&f.commit_id, &bundle).unwrap();
        assert_eq!(
            d.path,
            vec![
                (b"sub".to_vec(), EntryMode::Tree),
                (b"deep".to_vec(), EntryMode::Tree),
                (b"deep.txt".to_vec(), EntryMode::Blob),
            ]
        );

        // Executable-mode file.
        let bundle =
            build_disclosure(&f.store, &f.commit_id, &[b"exec.sh"], Selector::Object).unwrap();
        let d = verify_disclosure(&f.commit_id, &bundle).unwrap();
        assert_eq!(d.path, vec![(b"exec.sh".to_vec(), EntryMode::Executable)]);

        // One chunk of the chunked file.
        let bundle = build_disclosure(
            &f.store,
            &f.commit_id,
            &[b"chunked.bin"],
            Selector::Chunk(1),
        )
        .unwrap();
        let d = verify_disclosure(&f.commit_id, &bundle).unwrap();
        let DisclosedPayload::Chunk { index, .. } = d.payload else {
            panic!("expected Chunk payload");
        };
        assert_eq!(index, 1);

        // Range inside a chunk: the absolute offset is always proven, from
        // the chunk's committed start.
        let bundle = build_disclosure(
            &f.store,
            &f.commit_id,
            &[b"chunked.bin"],
            Selector::Range {
                offset: 200_000,
                len: 64,
            },
        )
        .unwrap();
        let d = verify_disclosure(&f.commit_id, &bundle).unwrap();
        let DisclosedPayload::Range {
            chunk,
            absolute_offset,
            offset_in_blob,
            start,
            end,
            bytes,
            ..
        } = d.payload
        else {
            panic!("expected Range payload");
        };
        let (index, _, _) = chunk.expect("a chunked leaf names its chunk");
        assert_ne!(index, 0);
        assert_eq!(absolute_offset, 200_000);
        assert_eq!(start.unwrap() + offset_in_blob, absolute_offset);
        assert!(end.unwrap() > absolute_offset);
        assert_eq!(bytes, f.chunked_bytes[200_000..200_064]);

        // Range covering a whole small blob.
        let bundle = build_disclosure(
            &f.store,
            &f.commit_id,
            &[b"shallow.txt"],
            Selector::Range {
                offset: 0,
                len: "shallow file content".len() as u64,
            },
        )
        .unwrap();
        let d = verify_disclosure(&f.commit_id, &bundle).unwrap();
        let DisclosedPayload::Range {
            bytes,
            chunk,
            start,
            absolute_offset,
            ..
        } = d.payload
        else {
            panic!("expected Range payload");
        };
        assert!(chunk.is_none());
        assert_eq!(start, None);
        assert_eq!(absolute_offset, 0);
        assert_eq!(bytes, b"shallow file content");
    }

    #[test]
    fn verify_object_id_rejects_mismatch() {
        let f = build_fixture();
        let bytes = f
            .store
            .read(&f.commit_id)
            .expect("commit_id was just written");
        assert!(matches!(
            verify_object_id(&bytes, &ZERO),
            Err(VerifyError::PayloadIdMismatch)
        ));
        verify_object_id(&bytes, &f.commit_id).expect("matches itself");
    }

    #[test]
    fn verify_path_rejects_wrong_commit_bytes_hash() {
        let f = build_fixture();
        let commit_bytes = f.store.read(&f.commit_id).unwrap();
        assert!(matches!(
            verify_path(&ZERO, &commit_bytes, &[]),
            Err(VerifyError::CommitBytesHashMismatch)
        ));
    }

    #[test]
    fn verify_path_rejects_non_final_non_tree_mode() {
        let f = build_fixture();
        let bundle =
            build_disclosure(&f.store, &f.commit_id, &[b"shallow.txt"], Selector::Object).unwrap();
        // A second, non-final step whose mode is Blob (not Tree) must be
        // rejected — the wire-level decode bound (steps <= 128) doesn't
        // catch this; only the semantic check does.
        let (_id, commit_bytes, mut steps, _payload) = decode_disclosure(&bundle).unwrap();
        assert_eq!(steps.len(), 1);
        let dup = steps[0].clone();
        steps.push(dup);
        assert!(matches!(
            verify_path(&f.commit_id, &commit_bytes, &steps),
            Err(VerifyError::NonFinalStepNotTree(0))
        ));
    }

    #[test]
    fn verify_path_rejects_too_many_steps() {
        let f = build_fixture();
        let bundle =
            build_disclosure(&f.store, &f.commit_id, &[b"shallow.txt"], Selector::Object).unwrap();
        let (_id, commit_bytes, steps, _payload) = decode_disclosure(&bundle).unwrap();
        let too_many: Vec<Step> =
            std::iter::repeat_n(steps[0].clone(), MAX_TREE_DEPTH + 1).collect();
        assert!(matches!(
            verify_path(&f.commit_id, &commit_bytes, &too_many),
            Err(VerifyError::TooManySteps(_))
        ));
    }

    #[test]
    fn verify_path_rejects_invalid_entry_name() {
        let f = build_fixture();
        let bundle =
            build_disclosure(&f.store, &f.commit_id, &[b"shallow.txt"], Selector::Object).unwrap();
        let (_id, commit_bytes, mut steps, _payload) = decode_disclosure(&bundle).unwrap();
        steps[0].name = b"trailing space ".to_vec();
        assert!(matches!(
            verify_path(&f.commit_id, &commit_bytes, &steps),
            Err(VerifyError::InvalidEntryName(0))
        ));
    }

    #[test]
    fn verify_path_rejects_swapped_step_proof() {
        let f = build_fixture();
        let bundle = build_disclosure(
            &f.store,
            &f.commit_id,
            &[b"sub", b"deep", b"deep.txt"],
            Selector::Object,
        )
        .unwrap();
        let (_id, commit_bytes, mut steps, _payload) = decode_disclosure(&bundle).unwrap();
        assert_eq!(steps.len(), 3);
        steps.swap(0, 1);
        assert!(matches!(
            verify_path(&f.commit_id, &commit_bytes, &steps),
            Err(VerifyError::InnerRootMismatch { .. } | VerifyError::Merkle(_))
        ));
    }

    #[test]
    fn verify_path_rejects_non_commit_non_remix() {
        let f = build_fixture();
        // A Tag targeting the commit: valid bytes, wrong object kind.
        let tag = crate::object::Tag {
            target: f.commit_id,
            target_type: ObjectType::Commit,
            name: b"v1".to_vec(),
            tagger: Identity::ed25519([9u8; 32]),
            signer: [9u8; 32],
            message: Vec::new(),
            timestamp: 0,
            signature: [0u8; 64],
        };
        let tag_bytes = crate::serialize::serialize(&Object::Tag(tag)).unwrap();
        let tag_id = crate::hash::hash(&tag_bytes);
        assert!(matches!(
            verify_path(&tag_id, &tag_bytes, &[]),
            Err(VerifyError::NotACommitOrRemix(ObjectType::Tag))
        ));
    }

    /// A `Chunk` payload whose header field is forged is refused, whichever
    /// field it is: the verifier computes the metadata leaf and the chunk leaf
    /// itself, so each field has to fold to the id.
    #[test]
    fn a_chunk_payload_with_a_forged_header_field_is_refused() {
        let f = build_fixture();
        let bundle = build_disclosure(
            &f.store,
            &f.commit_id,
            &[b"chunked.bin"],
            Selector::Chunk(1),
        )
        .unwrap();
        verify_disclosure(&f.commit_id, &bundle).expect("a built bundle verifies");
        let forged = |change: &dyn Fn(&mut u64, &mut u32, &mut u64, &mut u64, &mut u32)| {
            let (id, commit_bytes, steps, payload) = decode_disclosure(&bundle).unwrap();
            let PayloadWire::Chunk {
                mut total_size,
                mut chunk_size,
                mut index,
                mut start,
                mut end,
                inner_root,
                proof,
                bytes,
            } = payload
            else {
                panic!("expected Chunk payload");
            };
            change(
                &mut total_size,
                &mut chunk_size,
                &mut start,
                &mut end,
                &mut index,
            );
            let payload = PayloadWire::Chunk {
                total_size,
                chunk_size,
                index,
                start,
                end,
                inner_root,
                proof,
                bytes,
            };
            verify_disclosure(
                &f.commit_id,
                &encode_disclosure(&id, &commit_bytes, &steps, &payload),
            )
        };
        assert!(
            forged(&|total, _, _, _, _| *total += 1).is_err(),
            "total_size"
        );
        assert!(
            matches!(
                forged(&|_, chunk_size, _, _, _| *chunk_size += 1),
                Err(VerifyError::InnerRootFoldMismatch | VerifyError::Merkle(_))
            ),
            "chunk_size"
        );
        assert!(forged(&|_, _, start, _, _| *start += 1).is_err(), "start");
        assert!(forged(&|_, _, _, end, _| *end += 1).is_err(), "end");
        // The index one past the last valid position is out of range.
        let past = {
            let (_, _, _, payload) = decode_disclosure(&bundle).unwrap();
            let PayloadWire::Chunk { proof, .. } = payload else {
                panic!("expected Chunk payload");
            };
            proof.leaf_count
        };
        assert!(matches!(
            forged(&|_, _, _, _, index| *index = past),
            Err(VerifyError::ChunkIndexOutOfRange { .. })
        ));
    }

    #[test]
    fn verify_blob_slice_round_trip() {
        let content = b"the quick brown fox jumps over the lazy dog";
        let canonical = {
            let prologue = crate::serialize::blob_prologue(content.len()).unwrap();
            let mut v = prologue.to_vec();
            v.extend_from_slice(content);
            v
        };
        let blob_id = crate::hash::hash(&canonical);
        let (outboard, _root) = bao::encode::outboard(&canonical);

        let mut extractor = bao::encode::SliceExtractor::new_outboard(
            std::io::Cursor::new(&canonical),
            std::io::Cursor::new(&outboard),
            10, // content offset 0 -> bao offset 10
            content.len() as u64,
        );
        let mut slice = Vec::new();
        std::io::Read::read_to_end(&mut extractor, &mut slice).unwrap();

        let got = verify_blob_slice(&blob_id, 0, content.len() as u64, &slice).unwrap();
        assert_eq!(got, content);

        // Zero length is always rejected, regardless of slice bytes.
        assert!(matches!(
            verify_blob_slice(&blob_id, 0, 0, &slice),
            Err(VerifyError::ZeroLengthRange)
        ));
    }

    #[test]
    fn zero_length_range_rejected_end_to_end() {
        let f = build_fixture();
        assert!(matches!(
            build_disclosure(
                &f.store,
                &f.commit_id,
                &[b"shallow.txt"],
                Selector::Range { offset: 0, len: 0 }
            ),
            Err(VerifyError::ZeroLengthRange)
        ));
    }

    #[test]
    fn range_crossing_chunk_boundary_rejected() {
        let f = build_fixture();
        // The full 2 MiB span certainly crosses at least one chunk
        // boundary (chunks average well under 1 MiB).
        assert!(matches!(
            build_disclosure(
                &f.store,
                &f.commit_id,
                &[b"chunked.bin"],
                Selector::Range {
                    offset: 0,
                    len: f.chunked_bytes.len() as u64,
                }
            ),
            Err(VerifyError::RangeCrossesChunkBoundary)
        ));
    }

    /// The `Range` payload of the fixture's chunked file at `offset`.
    fn chunked_range_parts(
        f: &Fixture,
        offset: u64,
        len: u64,
    ) -> (Hash, Vec<u8>, Vec<Step>, ChunkHdr, u64, Vec<u8>) {
        let bundle = build_disclosure(
            &f.store,
            &f.commit_id,
            &[b"chunked.bin"],
            Selector::Range { offset, len },
        )
        .unwrap();
        let (commit_id, commit_bytes, steps, payload) = decode_disclosure(&bundle).unwrap();
        let PayloadWire::Range {
            chunk,
            offset_in_blob,
            slice,
            ..
        } = payload
        else {
            panic!("expected Range payload");
        };
        (
            commit_id,
            commit_bytes,
            steps,
            chunk.expect("chunked leaf"),
            offset_in_blob,
            slice,
        )
    }

    /// A range that reaches past the span its chunk's leaf commits is
    /// refused, before the slice is looked at.
    #[test]
    fn range_past_the_committed_span_is_rejected() {
        let f = build_fixture();
        let (commit_id, commit_bytes, steps, hdr, _, slice) = chunked_range_parts(&f, 700_000, 16);
        let span_len = hdr.end - hdr.start;
        for offset_in_blob in [span_len - 15, span_len, u64::MAX] {
            let tampered = encode_disclosure(
                &commit_id,
                &commit_bytes,
                &steps,
                &PayloadWire::Range {
                    chunk: Some(hdr.clone()),
                    offset_in_blob,
                    len: 16,
                    slice: slice.clone(),
                },
            );
            assert!(
                matches!(
                    verify_disclosure(&f.commit_id, &tampered),
                    Err(VerifyError::RangePastSpan { span_len: got, .. }) if got == span_len
                ),
                "offset_in_blob {offset_in_blob}"
            );
        }
        // The last whole range inside the span is not past it.
        let tampered = encode_disclosure(
            &commit_id,
            &commit_bytes,
            &steps,
            &PayloadWire::Range {
                chunk: Some(hdr.clone()),
                offset_in_blob: span_len - 16,
                len: 16,
                slice,
            },
        );
        assert!(!matches!(
            verify_disclosure(&f.commit_id, &tampered),
            Err(VerifyError::RangePastSpan { .. })
        ));
    }

    /// A `Range` whose chunk header moves the span is refused: the leaf
    /// commits both ends.
    #[test]
    fn range_with_a_moved_span_is_rejected() {
        let f = build_fixture();
        let (commit_id, commit_bytes, steps, hdr, offset_in_blob, slice) =
            chunked_range_parts(&f, 700_000, 16);
        for moved in [
            ChunkHdr {
                start: hdr.start - 1,
                ..hdr.clone()
            },
            ChunkHdr {
                end: hdr.end + 1,
                ..hdr.clone()
            },
        ] {
            let tampered = encode_disclosure(
                &commit_id,
                &commit_bytes,
                &steps,
                &PayloadWire::Range {
                    chunk: Some(moved),
                    offset_in_blob,
                    len: 16,
                    slice: slice.clone(),
                },
            );
            assert!(matches!(
                verify_disclosure(&f.commit_id, &tampered),
                Err(VerifyError::InnerRootFoldMismatch | VerifyError::Merkle(_))
            ));
        }
    }

    /// A manifest the span rules refuse, built past the checks a manifest
    /// value makes, and its `Chunk` claim for `index`, run through the
    /// chunked-leaf checks.
    fn claim_on_forged_manifest(
        total_size: u64,
        chunk_size: u32,
        ends: &[u64],
        index: u32,
    ) -> Result<(), VerifyError> {
        let chunks: Vec<Hash> = (0..ends.len())
            .map(|i| [u8::try_from(i).unwrap() + 1; 32])
            .collect();
        let cb = ChunkedBlob::new_unchecked(total_size, chunk_size, chunks.clone(), ends.to_vec());
        let id = merkle::compute_chunked_id(&cb);
        let proof = merkle::build_chunks_multi_proof(&cb, [0, index + 1]).unwrap();
        let (start, end) = cb.span(index).unwrap();
        let claim = ChunkClaim {
            total_size,
            chunk_size,
            index,
            chunk: merkle::SpannedChunk {
                id: chunks[index as usize],
                start,
                end,
            },
            inner_root: &merkle::chunked_inner_root(&cb),
            proof: &proof,
        };
        verify_chunk_claim(&id, &claim)
    }

    /// Each span rule of the chunked-leaf checks has its own error, so a
    /// reader can tell which rule a bundle broke.
    #[test]
    fn each_span_rule_has_its_own_error() {
        // Honest manifests verify, in both layouts.
        claim_on_forged_manifest(10, 0, &[3, 10], 0).unwrap();
        claim_on_forged_manifest(10, 0, &[3, 10], 1).unwrap();
        claim_on_forged_manifest(8, 4, &[4, 8], 1).unwrap();
        // The header fields are checked against the proof's leaf count.
        assert!(matches!(
            claim_on_forged_manifest(10, 0, &[3, 6], 0),
            Ok(()) | Err(VerifyError::Decode(KitError::ChunkedBlobTotalSizeInvalid))
        ));
        assert!(matches!(
            claim_on_forged_manifest(crate::serialize::MAX_CHUNKED_TOTAL_SIZE + 1, 0, &[1], 0),
            Err(VerifyError::Decode(KitError::ChunkedBlobTotalSizeInvalid))
        ));
        // A span that is empty, or past the end of the file.
        assert!(matches!(
            claim_on_forged_manifest(10, 0, &[5, 5, 10], 1),
            Err(VerifyError::SpanOutsideFile {
                start: 5,
                end: 5,
                total_size: 10
            })
        ));
        assert!(matches!(
            claim_on_forged_manifest(10, 0, &[5, 11], 1),
            Err(VerifyError::SpanOutsideFile {
                start: 5,
                end: 11,
                total_size: 10
            })
        ));
        // A span above one Blob object.
        let over = crate::serialize::MAX_CHUNK_LEN + 1;
        assert!(matches!(
            claim_on_forged_manifest(over, 0, &[over], 0),
            Err(VerifyError::SpanAboveObjectLimit { start: 0, end }) if end == over
        ));
        // Index 0 and start 0 go together.
        assert!(matches!(
            claim_on_forged_manifest(10, 0, &[0, 10], 1),
            Err(VerifyError::FirstChunkStart { index: 1, start: 0 })
        ));
        // The last index and `end == total_size` go together.
        assert!(matches!(
            claim_on_forged_manifest(10, 0, &[4, 8], 1),
            Err(VerifyError::LastChunkEnd { index: 1, end: 8 })
        ));
        assert!(matches!(
            claim_on_forged_manifest(10, 0, &[10, 10], 0),
            Err(VerifyError::LastChunkEnd { index: 0, end: 10 })
        ));
        // A fixed layout puts each chunk at `index * chunk_size`.
        assert!(matches!(
            claim_on_forged_manifest(8, 4, &[3, 8], 0),
            Err(VerifyError::FixedChunkLength {
                index: 0,
                start: 0,
                end: 3
            })
        ));
        assert!(matches!(
            claim_on_forged_manifest(8, 4, &[3, 8], 1),
            Err(VerifyError::FixedChunkLength {
                index: 1,
                start: 3,
                end: 8
            })
        ));
    }

    /// The position of chunk `index` is `index + 1` while it is inside the
    /// proof's leaves, and a proof past the chunk cap is refused.
    #[test]
    fn chunk_position_has_exact_bounds() {
        use crate::serialize::MAX_CHUNKS;
        assert_eq!(chunk_position(0, 2).unwrap(), 1);
        assert_eq!(chunk_position(1, 3).unwrap(), 2);
        // The last chunk of a manifest of `leaf_count - 1` chunks.
        assert!(matches!(
            chunk_position(2, 3),
            Err(VerifyError::ChunkIndexOutOfRange {
                index: 2,
                leaf_count: 3
            })
        ));
        assert!(matches!(
            chunk_position(0, 1),
            Err(VerifyError::ChunkIndexOutOfRange { .. })
        ));
        assert!(matches!(
            chunk_position(0, 0),
            Err(VerifyError::ChunkIndexOutOfRange { .. })
        ));
        // The most chunks a manifest can have, and one more.
        assert_eq!(
            chunk_position(MAX_CHUNKS - 1, MAX_CHUNKS + 1).unwrap(),
            MAX_CHUNKS
        );
        assert!(matches!(
            chunk_position(0, MAX_CHUNKS + 2),
            Err(VerifyError::TooManyChunks)
        ));
        assert!(matches!(
            chunk_position(u32::MAX, u32::MAX),
            Err(VerifyError::TooManyChunks)
        ));
    }

    /// A chunk's bytes are one Blob: each field of the 10-byte prologue
    /// matters alone, and so does a trailing byte.
    #[test]
    fn blob_content_len_checks_every_field_of_the_prologue() {
        let blob =
            crate::serialize::serialize(&Object::Blob(crate::object::Blob { data: vec![9; 20] }))
                .unwrap();
        assert_eq!(blob_content_len(&blob), Some(20));
        for at in [0usize, 1, 5] {
            let mut bad = blob.clone();
            bad[at] ^= 1;
            assert_eq!(blob_content_len(&bad), None, "byte {at}");
        }
        let mut long = blob.clone();
        long.push(0);
        assert_eq!(blob_content_len(&long), None);
        assert_eq!(blob_content_len(&blob[..blob.len() - 1]), None);
        assert_eq!(blob_content_len(&blob[..9]), None);
    }

    /// The span rules of a chunk, at their boundaries: a span may be as long
    /// as one Blob can be and no longer, wherever it sits in the file.
    #[test]
    fn chunk_span_rules_have_exact_bounds() {
        use crate::serialize::MAX_CHUNK_LEN;
        let root = [0u8; 32];
        let proof = Proof {
            leaf_count: 0,
            siblings: Vec::new(),
        };
        let check = |total_size: u64, index: u32, start: u64, end: u64, leaf_count: u32| {
            check_chunk_span(
                &ChunkClaim {
                    total_size,
                    chunk_size: 0,
                    index,
                    chunk: merkle::SpannedChunk {
                        id: [1u8; 32],
                        start,
                        end,
                    },
                    inner_root: &root,
                    proof: &proof,
                },
                leaf_count,
            )
        };
        // The only chunk of a file, as long as a chunk can be, and one byte more.
        assert!(check(MAX_CHUNK_LEN, 0, 0, MAX_CHUNK_LEN, 2).is_ok());
        assert!(matches!(
            check(MAX_CHUNK_LEN + 1, 0, 0, MAX_CHUNK_LEN + 1, 2),
            Err(VerifyError::SpanAboveObjectLimit { .. })
        ));
        // A short span far into a big file: start and end above the length
        // limit together do not matter, only the length does.
        let total = 3 * MAX_CHUNK_LEN;
        assert!(check(total, 1, MAX_CHUNK_LEN, MAX_CHUNK_LEN + 10, 4).is_ok());
        assert!(check(total, 3, 2 * MAX_CHUNK_LEN, total, 5).is_ok());
        // An empty span, and one that ends at the end of the file.
        assert!(matches!(
            check(100, 1, 50, 50, 4),
            Err(VerifyError::SpanOutsideFile { .. })
        ));
        assert!(check(100, 1, 50, 100, 3).is_ok());
        assert!(matches!(
            check(100, 1, 50, 101, 3),
            Err(VerifyError::SpanOutsideFile { .. })
        ));
    }

    /// The commit bytes of a bundle may be up to `MAX_COMMIT_BYTES` and no
    /// longer.
    #[test]
    fn commit_bytes_of_a_bundle_are_capped() {
        let id = [7u8; 32];
        let payload = PayloadWire::Object { bytes: Vec::new() };
        for len in [0usize, 1, 5000, MAX_COMMIT_BYTES] {
            let bundle = encode_disclosure(&id, &vec![1u8; len], &[], &payload);
            let (_, commit_bytes, ..) = decode_disclosure(&bundle).unwrap();
            assert_eq!(commit_bytes.len(), len);
        }
        let bundle = encode_disclosure(&id, &vec![1u8; MAX_COMMIT_BYTES + 1], &[], &payload);
        assert!(decode_disclosure(&bundle).is_err());
    }

    /// A chunk whose Blob holds a different number of bytes than its span
    /// is refused by the builder, and so is one that is not a Blob.
    #[test]
    fn chunk_bytes_must_be_one_blob_of_the_span() {
        let f = build_fixture();
        let chunk = write_blob(&f.store, b'a', 1000);
        // Two 750-byte spans over 1000-byte blobs.
        let manifest =
            Object::ChunkedBlob(crate::object::testing::spread(1500, 0, vec![chunk; 2]).unwrap());
        let manifest_id = f
            .store
            .write(&crate::serialize::serialize(&manifest).unwrap())
            .unwrap();
        let commit = commit_with_entry(&f, EntryMode::Blob, manifest_id);
        // The builder refuses it. The verifier's refusal of a forged bundle is
        // pinned by the vectors `neg_chunk_length_differs_from_span` and
        // `neg_chunk_bytes_not_blob`.
        assert!(matches!(
            build_disclosure(&f.store, &commit, &[b"x"], Selector::Chunk(0)),
            Err(VerifyError::Decode(KitError::ChunkLengthMismatch {
                index: 0,
                expected: 750,
                actual: 1000
            }))
        ));

        // A chunk id that names a commit, not a Blob: a commit's id is the hash
        // of its bytes, as a chunk's is.
        let other_id = f.commit_id;
        let other_len = f.store.read(&other_id).unwrap().len() as u64;
        let manifest = Object::ChunkedBlob(
            crate::object::ChunkedBlob::new(other_len, 0, [(other_id, other_len)]).unwrap(),
        );
        let manifest_id = f
            .store
            .write(&crate::serialize::serialize(&manifest).unwrap())
            .unwrap();
        let commit = commit_with_entry(&f, EntryMode::Blob, manifest_id);
        assert!(matches!(
            build_disclosure(&f.store, &commit, &[b"x"], Selector::Chunk(0)),
            Err(VerifyError::ChunkBytesNotBlob)
        ));

        // A chunk of the right length that is a Blob verifies, and discloses
        // its absolute span.
        let manifest =
            Object::ChunkedBlob(crate::object::testing::sized(0, vec![(chunk, 1000); 2]).unwrap());
        let manifest_id = f
            .store
            .write(&crate::serialize::serialize(&manifest).unwrap())
            .unwrap();
        let commit = commit_with_entry(&f, EntryMode::Blob, manifest_id);
        let bundle = build_disclosure(&f.store, &commit, &[b"x"], Selector::Chunk(1)).unwrap();
        let d = verify_disclosure(&commit, &bundle).unwrap();
        let DisclosedPayload::Chunk {
            start, end, index, ..
        } = d.payload
        else {
            panic!("expected Chunk payload");
        };
        assert_eq!((index, start, end), (1, 1000, 2000));
    }

    #[test]
    fn decode_rejects_bad_magic_version_and_trailing_bytes() {
        let f = build_fixture();
        let bundle =
            build_disclosure(&f.store, &f.commit_id, &[b"shallow.txt"], Selector::Object).unwrap();

        let mut bad_magic = bundle.clone();
        bad_magic[0] = b'X';
        assert!(matches!(
            verify_disclosure(&f.commit_id, &bad_magic),
            Err(VerifyError::BadMagic)
        ));

        let mut bad_version = bundle.clone();
        bad_version[4] = 1;
        assert!(matches!(
            verify_disclosure(&f.commit_id, &bad_version),
            Err(VerifyError::UnsupportedBundleVersion(1))
        ));

        let mut trailing = bundle.clone();
        trailing.push(0);
        assert!(matches!(
            verify_disclosure(&f.commit_id, &trailing),
            Err(VerifyError::Malformed)
        ));

        let oversize = vec![0u8; MAX_BUNDLE_BYTES + 1];
        assert!(matches!(
            verify_disclosure(&f.commit_id, &oversize),
            Err(VerifyError::BundleTooLarge)
        ));
    }

    #[test]
    fn decode_rejects_unknown_payload_kind() {
        let f = build_fixture();
        let bundle =
            build_disclosure(&f.store, &f.commit_id, &[b"shallow.txt"], Selector::Object).unwrap();
        let (commit_id, commit_bytes, steps, _payload) = decode_disclosure(&bundle).unwrap();

        // Recompute the prefix (magic + version + commit_id +
        // commit_bytes + steps) to find the payload_kind byte's offset
        // in the real bundle, rather than hand-computing it.
        let mut prefix = Vec::new();
        prefix.extend_from_slice(BUNDLE_MAGIC);
        prefix.push(BUNDLE_VERSION);
        commit_id.write(&mut prefix);
        commit_bytes.as_slice().write(&mut prefix);
        steps.as_slice().write(&mut prefix);
        let kind_offset = prefix.len();
        assert_eq!(bundle[kind_offset], 0, "Object payload_kind must be 0");

        let mut tampered = bundle.clone();
        tampered[kind_offset] = 0xFF;
        assert!(matches!(
            verify_disclosure(&f.commit_id, &tampered),
            Err(VerifyError::InvalidPayloadKind(0xFF))
        ));
    }

    #[test]
    fn payload_id_mismatch_is_rejected() {
        let f = build_fixture();
        let bundle =
            build_disclosure(&f.store, &f.commit_id, &[b"shallow.txt"], Selector::Object).unwrap();
        let (commit_id, commit_bytes, steps, payload) = decode_disclosure(&bundle).unwrap();
        let PayloadWire::Object { mut bytes } = payload else {
            panic!("expected Object payload");
        };
        *bytes.last_mut().unwrap() ^= 0xFF;
        let tampered = encode_disclosure(
            &commit_id,
            &commit_bytes,
            &steps,
            &PayloadWire::Object { bytes },
        );
        assert!(matches!(
            verify_disclosure(&f.commit_id, &tampered),
            Err(VerifyError::PayloadIdMismatch)
        ));
    }

    /// A signed commit over a tree of one entry `x` with `mode` naming
    /// `target`, written to `f`'s store.
    fn commit_with_entry(f: &Fixture, mode: EntryMode, target: Hash) -> Hash {
        let tree = Tree {
            entries: vec![TreeEntry {
                name: b"x".to_vec(),
                mode,
                object_hash: target,
            }],
        };
        let tree_hash = f
            .store
            .write(&crate::serialize::serialize(&Object::Tree(tree)).unwrap())
            .unwrap();
        let kp = KeyPair::from_seed([0x22; 32]);
        let mut commit = Commit {
            tree_hash,
            parents: vec![],
            author: Identity::ed25519(kp.public.0),
            signer: kp.public.0,
            message: b"hostile modes".to_vec(),
            timestamp: 1,
            message_hash: ZERO,
            content_digest: ZERO,
            signature: [0u8; 64],
        };
        commit.signature = sign_commit(&commit, &kp).unwrap().0;
        f.store
            .write(&crate::serialize::serialize(&Object::Commit(commit)).unwrap())
            .unwrap()
    }

    #[test]
    fn object_payload_must_match_the_final_step_mode() {
        let f = build_fixture();
        let tree_id = root_tree_id(&f.store, &f.commit_id);
        let blob_id = store_file_object(&f.store, b"a plain file").unwrap();

        // Blob, Executable and Symlink modes name a file, not a tree.
        for mode in [EntryMode::Blob, EntryMode::Executable, EntryMode::Symlink] {
            let commit = commit_with_entry(&f, mode, tree_id);
            let bundle = build_disclosure(&f.store, &commit, &[b"x"], Selector::Object).unwrap();
            assert!(
                matches!(
                    verify_disclosure(&commit, &bundle),
                    Err(VerifyError::PayloadTypeMismatch {
                        mode: m,
                        found: ObjectType::Tree
                    }) if m == mode
                ),
                "{mode:?}"
            );
        }

        // Tree mode names a tree, not a file.
        let commit = commit_with_entry(&f, EntryMode::Tree, blob_id);
        let bundle = build_disclosure(&f.store, &commit, &[b"x"], Selector::Object).unwrap();
        assert!(matches!(
            verify_disclosure(&commit, &bundle),
            Err(VerifyError::PayloadTypeMismatch {
                mode: EntryMode::Tree,
                found: ObjectType::Blob
            })
        ));
    }

    #[test]
    fn chunk_and_range_payloads_need_a_file_mode() {
        let f = build_fixture();
        let chunked = store_file_object(&f.store, &f.chunked_bytes).unwrap();
        let blob_id = store_file_object(&f.store, b"a plain file").unwrap();
        let range = |len| Selector::Range { offset: 0, len };
        for (target, selector, found) in [
            (chunked, Selector::Chunk(1), ObjectType::ChunkedBlob),
            (chunked, range(8), ObjectType::ChunkedBlob),
            (blob_id, range(4), ObjectType::Blob),
        ] {
            // A file mode accepts the same bundle.
            let ok = commit_with_entry(&f, EntryMode::Executable, target);
            let bundle = build_disclosure(&f.store, &ok, &[b"x"], selector).unwrap();
            verify_disclosure(&ok, &bundle).unwrap();

            let bad = commit_with_entry(&f, EntryMode::Tree, target);
            let bundle = build_disclosure(&f.store, &bad, &[b"x"], selector).unwrap();
            assert!(
                matches!(
                    verify_disclosure(&bad, &bundle),
                    Err(VerifyError::PayloadTypeMismatch {
                        mode: EntryMode::Tree,
                        found: f
                    }) if f == found
                ),
                "{found:?}"
            );
        }
    }

    #[test]
    fn object_payload_of_the_matching_type_is_accepted() {
        let f = build_fixture();
        let tree_id = root_tree_id(&f.store, &f.commit_id);
        let blob_id = store_file_object(&f.store, b"a plain file").unwrap();
        let chunked = store_file_object(&f.store, &f.chunked_bytes).unwrap();
        for (mode, target) in [
            (EntryMode::Tree, tree_id),
            (EntryMode::Blob, blob_id),
            (EntryMode::Symlink, blob_id),
            (EntryMode::Executable, chunked),
            (EntryMode::Blob, chunked),
        ] {
            let commit = commit_with_entry(&f, mode, target);
            let bundle = build_disclosure(&f.store, &commit, &[b"x"], Selector::Object).unwrap();
            verify_disclosure(&commit, &bundle).unwrap_or_else(|e| panic!("{mode:?}: {e}"));
        }
        // The root tree has no step: its mode is `Tree`.
        let bundle = build_disclosure(&f.store, &f.commit_id, &[], Selector::Object).unwrap();
        verify_disclosure(&f.commit_id, &bundle).unwrap();
    }

    #[test]
    fn commit_id_mismatch_is_rejected() {
        let f = build_fixture();
        let bundle =
            build_disclosure(&f.store, &f.commit_id, &[b"shallow.txt"], Selector::Object).unwrap();
        assert!(matches!(
            verify_disclosure(&ZERO, &bundle),
            Err(VerifyError::CommitIdMismatch)
        ));
    }

    #[test]
    fn inner_root_forged_is_rejected() {
        let f = build_fixture();
        let bundle =
            build_disclosure(&f.store, &f.commit_id, &[b"shallow.txt"], Selector::Object).unwrap();
        let (commit_id, commit_bytes, mut steps, payload) = decode_disclosure(&bundle).unwrap();
        steps[0].inner_root[0] ^= 0xFF;
        let tampered = encode_disclosure(&commit_id, &commit_bytes, &steps, &payload);
        assert!(matches!(
            verify_disclosure(&f.commit_id, &tampered),
            Err(VerifyError::InnerRootMismatch { .. })
        ));
    }

    #[test]
    fn inner_root_fold_mismatch_is_rejected() {
        let f = build_fixture();
        let nested = build_disclosure(
            &f.store,
            &f.commit_id,
            &[b"sub", b"deep", b"deep.txt"],
            Selector::Object,
        )
        .unwrap();
        let shallow =
            build_disclosure(&f.store, &f.commit_id, &[b"shallow.txt"], Selector::Object).unwrap();
        let (commit_id, commit_bytes, mut steps, payload) = decode_disclosure(&shallow).unwrap();
        let (_, _, nested_steps, _) = decode_disclosure(&nested).unwrap();
        // Keep the wrap-correct inner_root of the root tree, but swap in
        // a proof built against a different tree so the fold disagrees.
        steps[0].proof = nested_steps[1].proof.clone();
        steps[0].position = nested_steps[1].position;
        let tampered = encode_disclosure(&commit_id, &commit_bytes, &steps, &payload);
        assert!(matches!(
            verify_disclosure(&f.commit_id, &tampered),
            Err(VerifyError::InnerRootFoldMismatch)
        ));
    }

    // --- `build_disclosure_from` over a generic `store::ObjectSource` ---

    use crate::store::StoreError;

    /// A verifying in-memory [`crate::store::ObjectSource`]: every `read`
    /// re-derives the object id (the trait contract), so it stands in for
    /// a server-side per-repository index or global CAS.
    struct MapSource(BTreeMap<Hash, Vec<u8>>);

    impl MapSource {
        /// Every object currently in `store`.
        fn from_store(store: &ObjectStore) -> Self {
            let map = store
                .iter_object_hashes()
                .unwrap()
                .into_iter()
                .map(|h| (h, store.read(&h).unwrap()))
                .collect();
            Self(map)
        }
    }

    impl crate::store::ObjectSource for MapSource {
        fn read(&self, h: &Hash) -> crate::store::StoreResult<Vec<u8>> {
            let bytes = self
                .0
                .get(h)
                .ok_or_else(|| StoreError::ObjectNotFound(crate::hash::to_hex(h)))?;
            verify_object_id(bytes, h).map_err(|_| StoreError::HashMismatch {
                expected: crate::hash::to_hex(h),
                actual: String::from("<mismatch>"),
            })?;
            Ok(bytes.clone())
        }
    }

    /// A deliberately NON-verifying source (violates the
    /// `store::ObjectSource` contract): serves `lie`'s bytes for `target`.
    struct LyingSource<'a> {
        inner: &'a MapSource,
        target: Hash,
        lie: Vec<u8>,
    }

    impl crate::store::ObjectSource for LyingSource<'_> {
        fn read(&self, h: &Hash) -> crate::store::StoreResult<Vec<u8>> {
            if *h == self.target {
                return Ok(self.lie.clone());
            }
            crate::store::ObjectSource::read(self.inner, h)
        }
    }

    /// Another contract-violating source: `read_object(target)` decodes
    /// `object_lie`, while `read(target)` still returns the honest bytes,
    /// so the two methods disagree about the same id.
    struct SplitSource<'a> {
        inner: &'a MapSource,
        target: Hash,
        object_lie: Object,
    }

    impl crate::store::ObjectSource for SplitSource<'_> {
        fn read(&self, h: &Hash) -> crate::store::StoreResult<Vec<u8>> {
            crate::store::ObjectSource::read(self.inner, h)
        }

        fn read_object(&self, h: &Hash) -> crate::store::StoreResult<Object> {
            if *h == self.target {
                return Ok(self.object_lie.clone());
            }
            crate::store::ObjectSource::read_object(self.inner, h)
        }
    }

    /// Id of the entry `name` in the tree `tree_id`.
    fn entry_id(store: &ObjectStore, tree_id: &Hash, name: &[u8]) -> Hash {
        let Object::Tree(tree) = store.read_object(tree_id).unwrap() else {
            panic!("expected a tree");
        };
        tree.entries
            .iter()
            .find(|e| e.name == name)
            .unwrap()
            .object_hash
    }

    fn root_tree_id(store: &ObjectStore, commit_id: &Hash) -> Hash {
        let Object::Commit(c) = store.read_object(commit_id).unwrap() else {
            panic!("expected a commit");
        };
        c.tree_hash
    }

    /// A second commit (in the fixture store) whose root holds one plain,
    /// multi-Bao-block `Blob`, so small-blob ranges span block boundaries.
    fn medium_blob_commit(f: &Fixture) -> Hash {
        let data: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let blob = store_file_object(&f.store, &data).unwrap();
        assert!(matches!(
            f.store.read_object(&blob).unwrap(),
            Object::Blob(_)
        ));
        let tree = Tree {
            entries: vec![TreeEntry {
                name: b"medium.bin".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob,
            }],
        };
        let tree_hash = f
            .store
            .write(&crate::serialize::serialize(&Object::Tree(tree)).unwrap())
            .unwrap();
        let kp = KeyPair::from_seed([0x07; 32]);
        let mut commit = Commit {
            tree_hash,
            parents: vec![],
            author: Identity::ed25519(kp.public.0),
            signer: kp.public.0,
            message: b"medium blob".to_vec(),
            timestamp: 1_726_300_001,
            message_hash: ZERO,
            content_digest: ZERO,
            signature: [0u8; 64],
        };
        commit.signature = sign_commit(&commit, &kp).unwrap().0;
        f.store
            .write(&crate::serialize::serialize(&Object::Commit(commit)).unwrap())
            .unwrap()
    }

    type Case = (Hash, Vec<&'static [u8]>, Selector);

    /// Every selector kind the builder supports, as `(commit, path,
    /// selector)` cases over the fixture plus [`medium_blob_commit`].
    fn equivalence_cases(f: &Fixture, medium: Hash) -> Vec<Case> {
        let range = |offset, len| Selector::Range { offset, len };
        let c = f.commit_id;
        let mut cases: Vec<Case> = vec![
            (c, vec![], Selector::Object),
            (c, vec![b"shallow.txt"], Selector::Object),
            (c, vec![b"sub", b"deep", b"deep.txt"], Selector::Object),
            (c, vec![b"sub"], Selector::Object),
            (c, vec![b"exec.sh"], Selector::Object),
            (c, vec![b"chunked.bin"], Selector::Object),
            (c, vec![b"shallow.txt"], range(0, 20)),
            (c, vec![b"shallow.txt"], range(8, 4)),
            // Plain blob: first block, last partial block, a range across a
            // block boundary, and the whole content.
            (medium, vec![b"medium.bin"], range(0, 1024)),
            (medium, vec![b"medium.bin"], range(4096, 904)),
            (medium, vec![b"medium.bin"], range(1000, 100)),
            (medium, vec![b"medium.bin"], range(0, 5000)),
            // Chunked blob: a range inside chunk 0 and one past it.
            (c, vec![b"chunked.bin"], range(10, 64)),
            (c, vec![b"chunked.bin"], range(200_000, 64)),
        ];
        let chunked_id = entry_id(&f.store, &root_tree_id(&f.store, &c), b"chunked.bin");
        let Object::ChunkedBlob(cb) = f.store.read_object(&chunked_id).unwrap() else {
            panic!("expected a chunked blob");
        };
        assert!(cb.chunks().len() > 1, "fixture must yield several chunks");
        for i in 0..cb.chunks().len() {
            let index = u32::try_from(i).unwrap();
            cases.push((c, vec![b"chunked.bin"], Selector::Chunk(index)));
        }
        cases
    }

    fn assert_source_matches_store<S: crate::store::ObjectSource + ?Sized>(
        f: &Fixture,
        source: &S,
        medium: Hash,
    ) {
        for (commit, path, selector) in equivalence_cases(f, medium) {
            let expected = build_disclosure(&f.store, &commit, &path, selector).unwrap();
            let got = build_disclosure_from(source, &commit, &path, selector).unwrap();
            assert_eq!(
                got, expected,
                "bundle bytes differ for {path:?} / {selector:?}"
            );
            verify_disclosure(&commit, &got).unwrap();
        }
    }

    #[test]
    fn disclosure_from_map_source_equals_store_builder() {
        let f = build_fixture();
        let medium = medium_blob_commit(&f);
        let map = MapSource::from_store(&f.store);
        assert_source_matches_store(&f, &map, medium);
        // Also through a trait object (`?Sized`).
        let dyn_source: &dyn crate::store::ObjectSource = &map;
        assert_source_matches_store(&f, dyn_source, medium);
    }

    #[test]
    fn disclosure_from_ephemeral_sink_equals_store_builder() {
        let f = build_fixture();
        let medium = medium_blob_commit(&f);
        let sink = crate::store::EphemeralSink::new(&f.store);
        assert_source_matches_store(&f, &sink, medium);
    }

    #[test]
    fn disclosure_from_missing_object_is_store_error() {
        let f = build_fixture();
        let sub_id = entry_id(&f.store, &root_tree_id(&f.store, &f.commit_id), b"sub");
        let path: [&[u8]; 3] = [b"sub", b"deep", b"deep.txt"];

        let mut map = MapSource::from_store(&f.store);
        assert!(map.0.remove(&sub_id).is_some());
        let from_map =
            build_disclosure_from(&map, &f.commit_id, &path, Selector::Object).unwrap_err();

        f.store.remove_object(&sub_id).unwrap();
        let from_store =
            build_disclosure(&f.store, &f.commit_id, &path, Selector::Object).unwrap_err();

        let VerifyError::Store(StoreError::ObjectNotFound(map_hex)) = &from_map else {
            panic!("expected Store(ObjectNotFound), got {from_map:?}");
        };
        let VerifyError::Store(StoreError::ObjectNotFound(store_hex)) = &from_store else {
            panic!("expected Store(ObjectNotFound), got {from_store:?}");
        };
        assert_eq!(map_hex, store_hex);
        assert_eq!(map_hex, &crate::hash::to_hex(&sub_id));
        assert_eq!(from_map.to_string(), from_store.to_string());
    }

    #[test]
    fn disclosure_from_lying_leaf_fails_verification() {
        let f = build_fixture();
        let root = root_tree_id(&f.store, &f.commit_id);
        let shallow_id = entry_id(&f.store, &root, b"shallow.txt");
        let exec_id = entry_id(&f.store, &root, b"exec.sh");
        let map = MapSource::from_store(&f.store);
        let liar = LyingSource {
            inner: &map,
            target: shallow_id,
            // A different, well-formed blob.
            lie: f.store.read(&exec_id).unwrap(),
        };
        let bundle =
            build_disclosure_from(&liar, &f.commit_id, &[b"shallow.txt"], Selector::Object)
                .unwrap();
        assert!(matches!(
            verify_disclosure(&f.commit_id, &bundle),
            Err(VerifyError::PayloadIdMismatch)
        ));
    }

    #[test]
    fn disclosure_from_lying_tree_fails_at_that_path_step() {
        let f = build_fixture();
        let root = root_tree_id(&f.store, &f.commit_id);
        let sub_id = entry_id(&f.store, &root, b"sub");
        let deep_tree_id = entry_id(&f.store, &sub_id, b"deep");
        let shallow_id = entry_id(&f.store, &root, b"shallow.txt");
        // A well-formed forgery of `sub`: it still has the `deep` entry the
        // path needs, plus an extra one, so the builder walks straight
        // through it.
        let forged = Tree {
            entries: vec![
                TreeEntry {
                    name: b"aaa.txt".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: shallow_id,
                },
                TreeEntry {
                    name: b"deep".to_vec(),
                    mode: EntryMode::Tree,
                    object_hash: deep_tree_id,
                },
            ],
        };
        let map = MapSource::from_store(&f.store);
        let liar = LyingSource {
            inner: &map,
            target: sub_id,
            lie: crate::serialize::serialize(&Object::Tree(forged)).unwrap(),
        };
        let path: [&[u8]; 3] = [b"sub", b"deep", b"deep.txt"];
        let bundle = build_disclosure_from(&liar, &f.commit_id, &path, Selector::Object).unwrap();
        // Step 0 (root → sub) is honest; step 1 carries the forged tree's
        // inner root, which does not wrap to `sub`'s real id.
        let err = verify_disclosure(&f.commit_id, &bundle).unwrap_err();
        let VerifyError::InnerRootMismatch { expected, .. } = err else {
            panic!("expected InnerRootMismatch at the `sub` step, got {err:?}");
        };
        assert_eq!(expected, sub_id);
    }

    #[test]
    fn disclosure_from_short_chunk_is_error_not_panic() {
        let f = build_fixture();
        let root = root_tree_id(&f.store, &f.commit_id);
        let chunked_id = entry_id(&f.store, &root, b"chunked.bin");
        let Object::ChunkedBlob(cb) = f.store.read_object(&chunked_id).unwrap() else {
            panic!("expected a chunked blob");
        };
        let map = MapSource::from_store(&f.store);
        // Only the chunk holding the offset is read.
        let holder = cb.chunk_at(200_000).unwrap();
        for short_len in [0usize, 1, 9] {
            let liar = LyingSource {
                inner: &map,
                target: cb.chunks()[holder as usize],
                lie: vec![0u8; short_len],
            };
            let selector = Selector::Range {
                offset: 200_000,
                len: 64,
            };
            let err = build_disclosure_from(&liar, &f.commit_id, &[b"chunked.bin"], selector)
                .unwrap_err();
            assert!(
                matches!(err, VerifyError::ChunkBytesNotBlob),
                "{short_len}-byte chunk: got {err:?}"
            );
        }
    }

    #[test]
    fn disclosure_range_len_u64_max_is_error_not_panic() {
        let f = build_fixture();
        let map = MapSource::from_store(&f.store);
        let huge = |offset| Selector::Range {
            offset,
            len: u64::MAX,
        };
        for (path, offset) in [
            (b"chunked.bin".as_slice(), 10),
            (b"chunked.bin".as_slice(), 200_000),
            (b"shallow.txt".as_slice(), 1),
        ] {
            for result in [
                build_disclosure(&f.store, &f.commit_id, &[path], huge(offset)),
                build_disclosure_from(&map, &f.commit_id, &[path], huge(offset)),
            ] {
                let err = result.unwrap_err();
                assert!(
                    matches!(err, VerifyError::OffsetOverflow),
                    "{path:?} @ {offset}: got {err:?}"
                );
            }
        }
        // An offset at the very top of u64 is simply out of bounds.
        let top = Selector::Range {
            offset: u64::MAX,
            len: 1,
        };
        let err = build_disclosure(&f.store, &f.commit_id, &[b"chunked.bin"], top).unwrap_err();
        assert!(matches!(err, VerifyError::RangeOutOfBounds), "got {err:?}");
    }

    #[test]
    fn disclosure_from_split_blob_source_is_error_not_panic() {
        let f = build_fixture();
        let root = root_tree_id(&f.store, &f.commit_id);
        let shallow_id = entry_id(&f.store, &root, b"shallow.txt");
        let map = MapSource::from_store(&f.store);
        // `read_object` claims a 4 KiB blob; `read` returns the real
        // 20-byte one, so the range is past the canonical bytes.
        let liar = SplitSource {
            inner: &map,
            target: shallow_id,
            object_lie: Object::Blob(crate::object::Blob {
                data: vec![0u8; 4096],
            }),
        };
        let selector = Selector::Range {
            offset: 2048,
            len: 512,
        };
        // Either a typed error or a bundle the verifier rejects; never a
        // panic, never a verifying bundle.
        if let Ok(bundle) = build_disclosure_from(&liar, &f.commit_id, &[b"shallow.txt"], selector)
        {
            assert!(verify_disclosure(&f.commit_id, &bundle).is_err());
        }
    }

    /// A commit over one fixed-size chunked file of `chunks` chunks of
    /// `chunk_size` bytes (the last chunk is one byte shorter). Returns
    /// the store, commit id and the file bytes.
    fn fixed_layout_fixture(
        chunks: u32,
        chunk_size: u32,
    ) -> (tempfile::TempDir, ObjectStore, Hash, Vec<u8>) {
        let mut lens = vec![chunk_size as usize; chunks as usize];
        *lens.last_mut().unwrap() -= 1;
        let dir = tempfile::TempDir::new().expect("tempdir");
        let store = ObjectStore::init(&RepoLayout::single(dir.path())).expect("store init");
        let total: usize = lens.iter().sum();
        let mut data = vec![0u8; total];
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        for b in &mut data {
            x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            *b = (x >> 56) as u8;
        }
        let mut rest = data.as_slice();
        let entries: Vec<(Hash, u64)> = lens
            .iter()
            .map(|&n| {
                let (c, tail) = rest.split_at(n);
                rest = tail;
                let prologue = crate::serialize::blob_prologue(c.len()).unwrap();
                (store.put_parts(&[&prologue, c]).unwrap(), n as u64)
            })
            .collect();
        let manifest =
            Object::ChunkedBlob(crate::object::testing::sized(chunk_size, entries).unwrap());
        let file_id = store
            .write(&crate::serialize::serialize(&manifest).unwrap())
            .unwrap();
        let tree = Tree {
            entries: vec![TreeEntry {
                name: b"fixed.bin".to_vec(),
                mode: EntryMode::Blob,
                object_hash: file_id,
            }],
        };
        let tree_hash = store
            .write(&crate::serialize::serialize(&Object::Tree(tree)).unwrap())
            .unwrap();
        let commit_id = commit_for_tree(&store, tree_hash);
        (dir, store, commit_id, data)
    }

    /// A fixed-size layout proves the absolute offset of a range from the
    /// chunk's committed start, like a content-defined one.
    #[test]
    fn fixed_layout_range_proves_its_absolute_offset() {
        let (_d, store, commit_id, data) = fixed_layout_fixture(8, 1024);
        let offset: usize = 3 * 1024 + 5;
        let bundle = build_disclosure(
            &store,
            &commit_id,
            &[b"fixed.bin"],
            Selector::Range {
                offset: offset as u64,
                len: 4,
            },
        )
        .unwrap();
        let d = verify_disclosure(&commit_id, &bundle).unwrap();
        let DisclosedPayload::Range {
            chunk,
            offset_in_blob,
            start,
            end,
            absolute_offset,
            bytes,
            ..
        } = d.payload
        else {
            panic!("expected Range payload");
        };
        assert_eq!(chunk, Some((3, data.len() as u64, 1024)));
        assert_eq!(offset_in_blob, 5);
        assert_eq!((start, end), (Some(3 * 1024), Some(4 * 1024)));
        assert_eq!(absolute_offset, offset as u64);
        assert_eq!(bytes, data[offset..offset + 4]);
    }

    /// The last chunk of a fixed-size layout discloses as the short span
    /// the layout leaves for it.
    #[test]
    fn fixed_layout_last_chunk_discloses_its_short_span() {
        let (_d, store, commit_id, data) = fixed_layout_fixture(4, 100);
        let bundle =
            build_disclosure(&store, &commit_id, &[b"fixed.bin"], Selector::Chunk(3)).unwrap();
        let d = verify_disclosure(&commit_id, &bundle).unwrap();
        let DisclosedPayload::Chunk {
            start, end, bytes, ..
        } = d.payload
        else {
            panic!("expected Chunk payload");
        };
        assert_eq!((start, end), (300, data.len() as u64));
        assert_eq!(bytes.len(), 10 + 99);
    }
}

//! Transfer-layer helpers: delta-aware pack planning and the packlist
//! discovery wire format.
//!
//! These sit ABOVE the on-disk pack format (SPEC-PACKFILE / SPEC-DELTA)
//! and below the transport. The push path uses [`plan_pack_with`] to decide
//! which objects of a ref's closure to send, and how — raw, or as a delta
//! against a base the remote already holds. The plan is then serialised
//! with [`crate::pack::PackWriter`] into one or more packs — split when
//! the plan's payload exceeds a single pack's cap (the CLI's
//! `remote_dispatch::build_and_upload_packs` owns the splitting) — each
//! keyed by its own BLAKE3 digest.
//!
//! Because a delta-encoded pack is keyed by the pack digest (not by the
//! reconstructed object's hash), the fetch side can no longer find it by
//! walking object hashes. Each push records a [`PackListNode`] — this
//! module's small versioned wire format — holding the pack(s) it added plus
//! a `prev` pointer to the previous node, forming a per-branch chain. The
//! push side advertises the chain head through a `refs/kit/packmap/<branch>`
//! metadata ref whose value is the BLAKE3 of the head node (itself stored as
//! a pack object). The fetch side reads that ref, walks the chain, and
//! unpacks every pack oldest-first. Chaining keeps each push O(1) on the
//! wire rather than re-uploading the whole history's list.
//!
//! Content addressing is unchanged: delta is a transfer encoding only. The
//! reconstructed object's id (BLAKE3 of its canonical bytes, or the merkle
//! BMT root for a `Tree`/`ChunkedBlob` — see `crate::merkle`) is
//! re-verified by `PackReader` before storing.

pub mod packmap;
pub mod walk;

use std::collections::{HashMap, HashSet};

use crate::delta;
use crate::hash::{self, Hash};
use crate::list_decode::read_list;
use crate::object::{Object, ObjectType};
use crate::ops::graph::chunk_blob_len;
use crate::pack::delta_fits_reader;
use crate::store::{ObjectStore, StoreError};

use self::walk::{ChunkMemory, HeldCommits, MAX_CHUNK_MEMORY, MAX_HELD_SCAN, PushWalk};

/// Most objects a push walk holds: the commits the remote holds, the commits
/// it lacks, and the objects the walk keeps. A chunk of a large file counts
/// toward nothing.
pub const MAX_PUSH_WALK: usize = 10_000_000;

/// The limit [`plan_pack_with`] reports when a walk reaches
/// [`MAX_PUSH_WALK`].
pub const PUSH_WALK_LIMIT: &str = "10,000,000-object push walk";

/// The bounds of one push walk. The defaults are the production ones; a test
/// lowers them to cut a walk without building ten million objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalkLimits {
    /// Most held commits, new commits and kept objects together.
    pub objects: usize,
    /// Most trees the held filter reads from the remote head's snapshot.
    pub held_scan: usize,
    /// Most chunk ids remembered as already listed.
    pub chunk_memory: usize,
}

impl Default for WalkLimits {
    fn default() -> Self {
        Self {
            objects: MAX_PUSH_WALK,
            held_scan: MAX_HELD_SCAN,
            chunk_memory: MAX_CHUNK_MEMORY,
        }
    }
}

// ---------------------------------------------------------------------------
// PackList wire format
// ---------------------------------------------------------------------------

/// ASCII magic at the start of every packlist node ("kit pack list").
pub const PACKLIST_MAGIC: &[u8; 4] = b"KPKL";
/// Current packlist version. Readers reject anything else so a future
/// format change is a loud error, not a silent misparse.
pub const PACKLIST_VERSION: u8 = 1;
/// Hard cap on packs recorded in a single node — a normal push records
/// one; refuse to allocate unboundedly on a malformed blob.
pub const PACKLIST_MAX_ENTRIES: u32 = 1_000_000;

/// The fixed guard header preceding the codec body: `[4B magic][1B
/// version]`. The body (`prev` pointer + pack list) is encoded with
/// `commonware-codec` and is variable-length.
const PACKLIST_HEADER_LEN: usize = 4 + 1;

/// A single node in a branch's packlist chain.
///
/// The push path appends one node per push: `prev` points at the previous
/// node (the current packmap value before this push), and `packs` holds the
/// pack(s) this push added. The full ordered pack set for a branch is the
/// chain walked oldest-first — see `remote_dispatch::fetch_pack_chain`.
///
/// Chaining keeps each push O(1) on the wire (read a 32-byte pointer, write
/// a ~64-byte node) instead of re-uploading the whole history's list.
///
/// A node's `prev` is `None` (rather than linked to the prior head) when a
/// push re-baselines a deep chain or resets a broken one. A re-baseline
/// lists every pack of the chain it replaces, so only the old nodes become
/// unreachable. A reset lists only its own packs, so the packs the
/// superseded chain referenced become unreachable from the new head node
/// too. Neither is deleted here (this module only ever writes new nodes/packs, never
/// deletes), so they linger as orphaned storage on the remote until a
/// server-side sweep reclaims them. A stale
/// pack lingering harmlessly is safe; nothing on the fetch side ever
/// resolves it once no live chain points to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackListNode {
    /// Previous node's key, or `None` for the first node of a branch.
    pub prev: Option<Hash>,
    /// Pack keys this node lists, in apply order: the packs its push added,
    /// after every pack of the chain it replaced when it re-baselines one.
    pub packs: Vec<Hash>,
}

/// Errors decoding a [`PackListNode`] blob.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PackListError {
    #[error("packlist is shorter than the {PACKLIST_HEADER_LEN}-byte magic+version header")]
    TooShort,
    #[error("packlist magic is not \"KPKL\"")]
    InvalidMagic,
    #[error("packlist version {0} is not supported (v1 only)")]
    UnsupportedVersion(u8),
    #[error("packlist pack count exceeds the {PACKLIST_MAX_ENTRIES} cap")]
    TooManyEntries(u32),
    /// The codec body (prev pointer / pack list) is malformed, truncated,
    /// or has trailing bytes.
    #[error("packlist body is malformed (bad codec payload or trailing bytes)")]
    Malformed,
}

/// Serialise one packlist node: the `KPKL`/version guard header followed by
/// the `prev`/`packs` body encoded with `commonware-codec` (idiomatic
/// `Option` + `Vec`).
///
/// # Errors
///
/// [`PackListError::TooManyEntries`] if `packs` exceeds the cap.
pub fn encode_packlist(prev: Option<Hash>, packs: &[Hash]) -> Result<Vec<u8>, PackListError> {
    use commonware_codec::Write;
    let count = u32::try_from(packs.len()).map_err(|_| PackListError::TooManyEntries(u32::MAX))?;
    if count > PACKLIST_MAX_ENTRIES {
        return Err(PackListError::TooManyEntries(count));
    }
    let mut out = Vec::new();
    out.extend_from_slice(PACKLIST_MAGIC);
    out.push(PACKLIST_VERSION);
    // Body via commonware-codec: an `Option<Hash>` then a `Vec<Hash>`
    // (length-prefixed). `Vec<u8>` is a `bytes::BufMut`.
    prev.write(&mut out);
    packs.to_vec().write(&mut out);
    Ok(out)
}

/// Parse a packlist node blob.
///
/// # Errors
///
/// Returns the matching [`PackListError`] for a short buffer, wrong magic,
/// or unknown version (the explicit guard header), or
/// [`PackListError::Malformed`] / [`PackListError::TooManyEntries`] from
/// the `commonware-codec` body (over-cap pack list, truncation, or
/// trailing bytes).
pub fn decode_packlist(bytes: &[u8]) -> Result<PackListNode, PackListError> {
    use bytes::Buf as _;
    use commonware_codec::ReadExt;

    if bytes.len() < PACKLIST_HEADER_LEN {
        return Err(PackListError::TooShort);
    }
    if &bytes[..4] != PACKLIST_MAGIC.as_slice() {
        return Err(PackListError::InvalidMagic);
    }
    let version = bytes[4];
    if version != PACKLIST_VERSION {
        return Err(PackListError::UnsupportedVersion(version));
    }
    // Body: `Option<Hash>` then a length-capped list of hashes. `Copying`
    // reads the borrowed slice; `read_list` enforces the entry cap at decode
    // time and reserves only what the input can hold.
    let mut buf = commonware_codec::Copying(&bytes[PACKLIST_HEADER_LEN..]);
    let prev = <Option<Hash>>::read(&mut buf).map_err(|_| PackListError::Malformed)?;
    let packs = read_list::<Hash>(&mut buf, PACKLIST_MAX_ENTRIES as usize, hash::HASH_LEN, &())
        .map_err(|_| PackListError::Malformed)?;
    // Trailing bytes after the declared body are a malformed packlist.
    if buf.has_remaining() {
        return Err(PackListError::Malformed);
    }
    Ok(PackListNode { prev, packs })
}

// ---------------------------------------------------------------------------
// Delta base selection
// ---------------------------------------------------------------------------

/// Cap on tree-diff recursion depth when pairing chunked blobs across two
/// commits. Bounds the walk on adversarial / pathologically nested trees.
const MAX_TREE_DEPTH: usize = 64;

/// Choose, for each changed `FastCDC` chunk or small blob in `new_tip`, a
/// base object from `old_tip` to delta against.
///
/// (SPEC-DELTA §5 is informative — any base the size-gate later accepts is
/// fine.) Diff the two commits' trees by path; where the same path is a
/// [`crate::object::ChunkedBlob`] on both sides with a different manifest
/// hash, pair each changed new chunk against a base in the old manifest —
/// by same-index when the chunk counts match (an in-place edit didn't shift
/// boundaries) or by content similarity when they differ (an insert/delete
/// did, via `pair_chunks`). Identical chunks (present byte-for-byte in the
/// old manifest) are skipped — they dedup for free and never need a delta.
/// Where the same path is a plain [`crate::object::Blob`] on both sides
/// (a changed small file, under `CHUNK_THRESHOLD`), the old blob is paired
/// as the new blob's delta base directly — no similarity search, just
/// "same path, old version". A path whose kind changed between the
/// two blob/chunked-blob variants, or that has no old-side counterpart at
/// all (added path, or a rename), is left unpaired.
///
/// The returned map is `new_hash -> base_hash`. Every base is reachable
/// from `old_tip`, so a remote that already holds `old_tip` holds the
/// base. The caller still gates on whether the delta actually saves bytes
/// ([`plan_pack_with`]).
///
/// # Errors
///
/// Propagates [`StoreError`] other than `ObjectNotFound`, which is treated
/// as "no pairing available" (a partial local history is not fatal here —
/// the worst case is that we send the chunk raw).
pub fn select_chunk_delta_bases(
    store: &ObjectStore,
    new_tip: Hash,
    old_tip: Hash,
) -> Result<HashMap<Hash, Hash>, StoreError> {
    let mut out = HashMap::new();
    let (Some(new_tree), Some(old_tree)) = (tip_tree(store, new_tip)?, tip_tree(store, old_tip)?)
    else {
        return Ok(out);
    };
    pair_trees(store, new_tree, old_tree, 0, &mut out)?;
    Ok(out)
}

/// Resolve a commit/remix tip to its root tree hash; `None` for any other
/// object kind (a tip that is not a commit has no tree to diff).
fn tip_tree(store: &ObjectStore, tip: Hash) -> Result<Option<Hash>, StoreError> {
    match store.read_object(&tip) {
        Ok(Object::Commit(c)) => Ok(Some(c.tree_hash)),
        Ok(Object::Remix(r)) => Ok(Some(r.tree_hash)),
        // A non-commit tip, or one we don't have, simply has no tree to diff.
        Ok(_) | Err(StoreError::ObjectNotFound(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Merge-join two sorted trees by entry name, recursing into matching
/// subtrees and pairing chunks for matching chunked-blob entries.
fn pair_trees(
    store: &ObjectStore,
    new_tree: Hash,
    old_tree: Hash,
    depth: usize,
    out: &mut HashMap<Hash, Hash>,
) -> Result<(), StoreError> {
    if depth > MAX_TREE_DEPTH || new_tree == old_tree {
        return Ok(());
    }
    let (Some(Object::Tree(new_t)), Some(Object::Tree(old_t))) = (
        read_optional(store, new_tree)?,
        read_optional(store, old_tree)?,
    ) else {
        return Ok(());
    };

    // Both trees are lex-sorted by name (SPEC-OBJECTS §4); two-pointer
    // merge to find entries present under the same name on both sides.
    let (mut i, mut j) = (0usize, 0usize);
    while i < new_t.entries.len() && j < old_t.entries.len() {
        let ne = &new_t.entries[i];
        let oe = &old_t.entries[j];
        match ne.name.cmp(&oe.name) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                if ne.object_hash != oe.object_hash {
                    pair_entry(store, ne.object_hash, oe.object_hash, depth, out)?;
                }
                i += 1;
                j += 1;
            }
        }
    }
    Ok(())
}

/// Dispatch a changed same-named entry: recurse into subtrees, pair
/// chunked blobs, pair small blobs against their same-path prior version
/// (#646a), ignore everything else (in particular, a `Blob<->ChunkedBlob`
/// kind mismatch — a file crossing `CHUNK_THRESHOLD` between the two
/// commits — is deliberately left unpaired here).
fn pair_entry(
    store: &ObjectStore,
    new_hash: Hash,
    old_hash: Hash,
    depth: usize,
    out: &mut HashMap<Hash, Hash>,
) -> Result<(), StoreError> {
    match (store.read_object(&new_hash), store.read_object(&old_hash)) {
        (Ok(Object::Tree(_)), Ok(Object::Tree(_))) => {
            pair_trees(store, new_hash, old_hash, depth + 1, out)
        }
        (Ok(Object::ChunkedBlob(new_cb)), Ok(Object::ChunkedBlob(old_cb))) => pair_chunks(
            store,
            new_cb.chunks(),
            old_cb.chunks(),
            MAX_PAIRED_CHUNKS,
            out,
        ),
        // A changed same-path small blob: the old blob at this path is a
        // natural delta base for the new one. Never overwrite an
        // existing pairing for `new_hash`, mirroring `pair_chunks`'
        // determinism guarantee.
        (Ok(Object::Blob(_)), Ok(Object::Blob(_))) => {
            out.entry(new_hash).or_insert(old_hash);
            Ok(())
        }
        // A missing object or a kind mismatch (file became a chunked blob,
        // etc.) just yields no pairing for this entry.
        (Err(StoreError::ObjectNotFound(_)), _) | (_, Err(StoreError::ObjectNotFound(_))) => Ok(()),
        (Err(e), _) | (_, Err(e)) => Err(e),
        _ => Ok(()),
    }
}

/// Window size for content-similarity sketching. Matches the delta
/// encoder's match-block size, so a shared 16-byte run is a shared feature.
const FEATURE_WINDOW: usize = 16;
/// Number of min-hash "super-features" sampled per chunk. Small keeps the
/// index cheap; the delta size-gate in [`plan_pack_with`] is the final judge of a
/// pick, so a few features are enough signal to rank candidates.
const FEATURE_COUNT: usize = 4;
/// Most chunks of either manifest for which a shifted file is paired by
/// content. Pairing reads every chunk of both manifests and indexes four
/// features per old chunk, so its cost grows with the file. Above this (a
/// file of about 4 GiB) the changed chunks are sent raw.
const MAX_PAIRED_CHUNKS: usize = 65_536;

/// Pair each changed new chunk against a base chunk in the old manifest.
/// Skips chunks already present byte-identically in the old manifest (those
/// dedup for free) and never overwrites an existing pairing, so the result
/// is deterministic.
///
/// Two regimes:
///
/// * **Equal chunk counts** ⇒ `FastCDC` boundaries didn't shift (an in-place,
///   same-length edit), so same-index pairing lands the new chunk on its own
///   prior version. This is the common case and reads no chunk content.
/// * **Differing counts** ⇒ an insert/delete shifted indices, so position is
///   unreliable. We match by **content similarity**: index every old chunk's
///   min-hash super-features, then pick, for each changed new chunk, the old
///   chunk sharing the most features (deterministic tiebreak: lowest hash),
///   falling back to the clamped same-index chunk when there is no overlap.
///   This reads the changed file's chunk content (`O(file size)`), but only
///   when there actually was a shift — and it trades those local reads for a
///   much smaller upload than re-sending the shifted chunks raw. A manifest
///   of more than [`MAX_PAIRED_CHUNKS`] chunks is not paired: its changed
///   chunks are sent raw.
fn pair_chunks(
    store: &ObjectStore,
    new_chunks: &[Hash],
    old_chunks: &[Hash],
    max_chunks: usize,
    out: &mut HashMap<Hash, Hash>,
) -> Result<(), StoreError> {
    if old_chunks.is_empty() {
        return Ok(());
    }
    let old_set: HashSet<&Hash> = old_chunks.iter().collect();

    // Fast path: no boundary shift → same-index pairing, no content reads.
    if new_chunks.len() == old_chunks.len() {
        for (j, nj) in new_chunks.iter().enumerate() {
            if old_set.contains(nj) || out.contains_key(nj) {
                continue;
            }
            if old_chunks[j] != *nj {
                out.insert(*nj, old_chunks[j]);
            }
        }
        return Ok(());
    }

    // Shifted, in a file too large to read twice for a plan: no pairing.
    if new_chunks.len().max(old_chunks.len()) > max_chunks {
        return Ok(());
    }

    // Shifted: index old chunks by their super-features once. An unreadable
    // old chunk (absent / non-blob) contributes no features and can't be a
    // base — it is simply absent from the index.
    let mut feature_index: HashMap<u64, Vec<Hash>> = HashMap::new();
    for oc in old_chunks {
        if let Some(content) = chunk_bytes(store, oc)? {
            for f in chunk_features(&content) {
                feature_index.entry(f).or_default().push(*oc);
            }
        }
    }

    for nj in new_chunks {
        if old_set.contains(nj) || out.contains_key(nj) {
            continue;
        }
        // An unreadable new chunk has no content signal — skip pairing it
        // (it's sent raw) rather than guessing a base.
        let Some(content) = chunk_bytes(store, nj)? else {
            continue;
        };
        // Count shared features per candidate old chunk.
        let mut votes: HashMap<Hash, u32> = HashMap::new();
        for f in &chunk_features(&content) {
            if let Some(cands) = feature_index.get(f) {
                for cand in cands {
                    *votes.entry(*cand).or_default() += 1;
                }
            }
        }
        // Pair ONLY on genuine content overlap: most shared features wins,
        // ties → lowest hash (deterministic, order-independent). No overlap →
        // no base; the chunk is sent raw (a dissimilar base would be rejected
        // by the size-gate anyway). No position fallback after a shift.
        if let Some((base, _)) = votes
            .into_iter()
            .filter(|(cand, _)| cand != nj)
            .max_by(|x, y| x.1.cmp(&y.1).then_with(|| y.0.cmp(&x.0)))
        {
            out.insert(*nj, base);
        }
    }
    Ok(())
}

/// Read a chunk blob's CONTENT bytes (not its serialized object form).
///
/// Returns `None` when the object is absent or not a blob — there is no
/// content to compare, so the caller skips pairing that chunk rather than
/// inventing a base. A genuine read/IO error propagates, preserving the
/// [`select_chunk_delta_bases`] contract (only `ObjectNotFound` is swallowed).
fn chunk_bytes(store: &ObjectStore, h: &Hash) -> Result<Option<Vec<u8>>, StoreError> {
    match store.read_object(h) {
        Ok(Object::Blob(b)) => Ok(Some(b.data)),
        Ok(_) | Err(StoreError::ObjectNotFound(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Up to [`FEATURE_COUNT`] shift-resistant "super-features" for a chunk: the
/// smallest distinct `FEATURE_WINDOW`-byte FNV-1a window hashes. Two chunks
/// that share content share these min-hashes with high probability even when
/// the content is shifted, making them a cheap similarity key. Chunks shorter
/// than the window yield none (such a chunk has no similarity key, so it is
/// left unpaired and sent raw).
fn chunk_features(bytes: &[u8]) -> Vec<u64> {
    if bytes.len() < FEATURE_WINDOW {
        return Vec::new();
    }
    // Keep the K smallest DISTINCT window hashes, ascending.
    let mut best: Vec<u64> = Vec::with_capacity(FEATURE_COUNT + 1);
    for w in bytes.windows(FEATURE_WINDOW) {
        let h = fnv1a(w);
        if best.len() == FEATURE_COUNT && h >= best[FEATURE_COUNT - 1] {
            continue;
        }
        if let Err(pos) = best.binary_search(&h) {
            best.insert(pos, h);
            best.truncate(FEATURE_COUNT);
        }
    }
    best
}

/// FNV-1a 64-bit over a fixed window — this module's own min-hash feature
/// key; unrelated to (and independent of) `delta::block_hash`'s algorithm,
/// which only needs to agree with itself between the base-index build and
/// the scan, not with any hash used here.
fn fnv1a(block: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in block {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0001_0000_01b3);
    }
    h
}

/// Read an object, mapping a missing object to `None` so callers can treat
/// "absent" the same as "not the kind I wanted" without a hard error.
fn read_optional(store: &ObjectStore, h: Hash) -> Result<Option<Object>, StoreError> {
    match store.read_object(&h) {
        Ok(o) => Ok(Some(o)),
        Err(StoreError::ObjectNotFound(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------------------
// Pack planning
// ---------------------------------------------------------------------------

/// One delta entry in a [`PackPlan`]: a target object encoded against a
/// base the remote already holds.
#[derive(Debug, Clone)]
pub struct PlannedDelta {
    /// BLAKE3 of the reconstructed (canonical) object — its storage id.
    pub target: Hash,
    /// BLAKE3 of the base object the delta is applied against.
    pub base: Hash,
    /// SPEC-DELTA instruction stream.
    pub stream: Vec<u8>,
}

/// A deterministic plan for the pack(s) a push uploads for one ref —
/// serialised into a single pack when it fits under the payload cap, or
/// split across several when it doesn't.
///
/// Entries are pre-ordered for [`crate::pack::PackWriter`]: all `raw`
/// objects first (non-blobs before blobs, each group in BLAKE3 order),
/// then `deltas`, grouped by base in BLAKE3 order of the base, then of the
/// target. Delta bases are external — they live in `old_tip`'s
/// closure, which the remote already holds and earlier packs already
/// delivered, NEVER in an entry introduced earlier in this same plan —
/// so no in-pack base ordering is required (SPEC-PACKFILE §4), and a
/// left-to-right split of this sequence across multiple packs is always
/// safe.
#[derive(Debug, Clone, Default)]
pub struct PackPlan {
    /// Objects to send verbatim, already ordered non-blobs-then-blobs. A chunk
    /// repeated past the plan's chunk memory may appear twice; a pack reader
    /// accepts duplicate raw entries.
    pub raw: Vec<Hash>,
    /// Objects to send as a delta against an already-present base.
    pub deltas: Vec<PlannedDelta>,
    /// `true` when the pack needs no externally-resolved base — i.e. this is
    /// a full-closure push (no usable `old_tip`), so the pack reconstructs
    /// the ref's whole closure on its own. The push path normally **appends**
    /// this pack to the branch's packlist chain; it uses `self_contained`
    /// to decide whether a push may **reset** to a fresh chain when the
    /// prior chain is unreadable. A self-contained pack is the one kind
    /// that can safely escape a broken chain.
    pub self_contained: bool,
}

impl PackPlan {
    /// Total objects the plan transfers (raw + delta).
    #[must_use]
    pub fn object_count(&self) -> usize {
        self.raw.len() + self.deltas.len()
    }

    /// `true` when the plan carries nothing — the remote already holds the
    /// ref's whole closure.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.raw.is_empty() && self.deltas.is_empty()
    }
}

/// [`plan_pack_with`] with a sequential delta encoder, for tests.
#[cfg(test)]
pub(crate) fn plan_pack(
    store: &ObjectStore,
    new_tip: Hash,
    old_tip: Option<Hash>,
) -> Result<PackPlan, StoreError> {
    plan_pack_with(store, new_tip, old_tip, |store, candidates| {
        candidates
            .iter()
            .map(|&c| encode_delta_candidate(store, c))
            .collect()
    })
}

/// One delta-encoding candidate handed in a batch to [`plan_pack_with`]'s
/// `encode_deltas` callback: encode `target` against `base` if the
/// remote is already known to hold `base`.
#[derive(Debug, Clone, Copy)]
pub struct DeltaCandidate {
    /// BLAKE3 of the blob to encode.
    pub target: Hash,
    /// BLAKE3 of the base object to encode `target` against.
    pub base: Hash,
}

/// Encode one [`DeltaCandidate`] against `store`. Returns `None` when the
/// delta stream would not actually shrink the payload — [`plan_pack_with`] falls back to sending `target` raw in that case.
///
/// Reads both `target`'s and `base`'s bytes and runs [`delta::encode`]'s
/// block-hash-table build plus greedy scan — both CPU-bound and
/// independent of every other candidate, which is why this is exposed as
/// its own function: it's the unit [`plan_pack_with`] callers fan out per
/// candidate rather than per whole batch.
///
/// Multiple candidates commonly share the same `base` (e.g. several
/// chunks of one file all diffed against the same prior chunk) — each
/// call here re-reads it independently. [`encode_delta_candidate_with_base`]
/// is the same unit for a caller that has already deduplicated those
/// reads across a batch.
///
/// # Errors
///
/// Propagates [`StoreError`] from either read.
pub fn encode_delta_candidate(
    store: &ObjectStore,
    candidate: DeltaCandidate,
) -> Result<Option<PlannedDelta>, StoreError> {
    let target_bytes = store.read(&candidate.target)?;
    let base_bytes = store.read(&candidate.base)?;
    Ok(try_delta(
        candidate.target,
        candidate.base,
        &target_bytes,
        &base_bytes,
    ))
}

/// [`encode_delta_candidate`], but for a caller that has already read
/// `candidate.base`'s bytes — e.g. `kit-bin`'s rayon fan-out, which
/// reads each *distinct* base in `plan_pack_with`'s candidate batch once
/// up front (a `HashMap<Hash, Vec<u8>>` keyed by base hash) instead of
/// leaving `N` candidates sharing a base to each independently
/// `store.read` it — redundant I/O that a parallel fan-out turns into
/// concurrent redundant I/O and concurrent redundant in-memory copies of
/// the same bytes, not just serialized-and-short-lived like the
/// sequential default pays.
///
/// # Errors
///
/// Propagates [`StoreError`] from reading `target`'s bytes.
pub fn encode_delta_candidate_with_base(
    store: &ObjectStore,
    candidate: DeltaCandidate,
    base_bytes: &[u8],
) -> Result<Option<PlannedDelta>, StoreError> {
    let target_bytes = store.read(&candidate.target)?;
    Ok(try_delta(
        candidate.target,
        candidate.base,
        &target_bytes,
        base_bytes,
    ))
}

/// Plan the pack for pushing `new_tip` to a remote whose current tip is
/// `old_tip` (`None` for a first push or a remote we cannot diff against).
///
/// Plans from what changed: it walks the commits the remote lacks and keeps
/// the entries of each tree that differ from the trees of its parents (see
/// [`walk::PushWalk`]). An object the remote holds is not re-sent when a
/// parent has it at the same path or the remote head's snapshot holds it
/// (the identical-object dedup, preferred over delta). It then delta-encodes
/// changed chunks against same-path prior chunks where that actually saves
/// bytes, falling back to raw otherwise. A plan may send an object the remote
/// holds. It never omits one the remote lacks.
///
/// The caller supplies the `encode_deltas` batch callback that encodes the
/// delta candidates, for example with [`encode_delta_candidate`] in a
/// sequential loop.
///
/// `kit-core` has no thread-pool dependency of its own — it stays usable
/// from wasm targets, which have no OS threads — so the fan-out decision
/// lives with the caller instead of living in this function. `kit-bin`'s
/// native, rayon-backed push path passes a parallel `encode_deltas`
/// (mirroring the `prepare_raw_batch`/`prepare_delta_batch` compression
/// fan-out already in `remote_dispatch/mod.rs`, but for the diffing step
/// itself rather than the post-plan zstd pass).
///
/// `encode_deltas` receives every delta candidate for this plan in one
/// batch, in the order they were discovered (BLAKE3/send-set order), and
/// MUST return exactly one `Option<PlannedDelta>` per input candidate, in the same
/// order — a `None` for a given candidate falls back to sending that
/// blob raw, matching [`encode_delta_candidate`]'s own "smaller or raw"
/// rule. A chunk whose candidate returns `None` is still sent raw.
///
/// # Errors
///
/// Propagates [`StoreError`] from the local walk or from `encode_deltas`.
/// [`StoreError::ObjectNotFound`] names a new commit, or an object of one,
/// that this store lacks: a plan never omits what the remote lacks.
/// [`StoreError::OperationLimitExceeded`] names [`PUSH_WALK_LIMIT`] when the
/// held commits, the new commits and the kept objects together pass
/// [`MAX_PUSH_WALK`]. A chunk of a large file counts toward nothing.
///
/// Also returns [`StoreError::DeltaBatchLengthMismatch`] if `encode_deltas`
/// returns a `Vec` of a different length than the candidate slice it was given
/// — a contract violation by the caller, not a normal runtime condition, but
/// reported as a typed error rather than a panic since a push is a
/// network-facing operation where a clean error is a better failure mode than
/// crashing the process.
pub fn plan_pack_with(
    store: &ObjectStore,
    new_tip: Hash,
    old_tip: Option<Hash>,
    encode_deltas: impl FnOnce(
        &ObjectStore,
        &[DeltaCandidate],
    ) -> Result<Vec<Option<PlannedDelta>>, StoreError>,
) -> Result<PackPlan, StoreError> {
    plan_pack_capped(
        store,
        new_tip,
        old_tip,
        encode_deltas,
        WalkLimits::default(),
    )
}

/// [`plan_pack_with`] with caller-supplied bounds, so a test can cut the walk.
fn plan_pack_capped(
    store: &ObjectStore,
    new_tip: Hash,
    old_tip: Option<Hash>,
    encode_deltas: impl FnOnce(
        &ObjectStore,
        &[DeltaCandidate],
    ) -> Result<Vec<Option<PlannedDelta>>, StoreError>,
    limits: WalkLimits,
) -> Result<PackPlan, StoreError> {
    // What the remote holds is decided from its head alone. A head this store
    // lacks leaves nothing held, and the plan is the whole closure.
    let held = HeldCommits::collect(store, old_tip, limits.objects)?;
    let walk = PushWalk::run(store, new_tip, &held, &HashSet::new(), limits, None)?;
    let base_map = match held.tip() {
        Some(old) => select_chunk_delta_bases(store, new_tip, old)?,
        None => HashMap::new(),
    };

    // Objects the walk kept, in BLAKE3 order so the plan, and so the pack
    // bytes, are deterministic. Classify via the cheap 6-byte prologue check
    // (`object_type`) instead of a full read+verify of the object's bytes:
    // the plan only needs the type tag, not the content (INV-14). Bytes are
    // read lazily, only for the subset that are actually delta candidates,
    // by `encode_deltas` below.
    let mut non_blob_raw = Vec::new();
    let mut blobs = Vec::new();
    for h in walk.objects() {
        if store.object_type(h)? == ObjectType::Blob {
            blobs.push(*h);
        } else {
            non_blob_raw.push(*h);
        }
    }
    // Then the chunks of every kept manifest, which the walk never counted.
    // They follow the other blobs, in manifest order.
    let mut memory = ChunkMemory::new(limits.chunk_memory);
    // Each chunk is checked as a fetch checks it: a `Blob` whose length is its
    // span. A bad chunk fails the plan before anything is uploaded.
    walk.for_each_chunk(store, &mut memory, |_, manifest, index, chunk| {
        let len = chunk_blob_len(store, &chunk, index)?;
        manifest.check_chunk_length(index, len)?;
        blobs.push(chunk);
        Ok(())
    })?;

    // Only blobs (small files and `FastCDC` chunks) are delta candidates, and
    // only against a base the remote holds: the base sits in the remote
    // head's own tree, and this store must hold it too to encode.
    let mut candidates: Vec<DeltaCandidate> = Vec::new();
    let mut listed: HashSet<Hash> = HashSet::new();
    for h in &blobs {
        if let Some(&base) = base_map.get(h)
            && store.contains(&base)
            && listed.insert(*h)
        {
            candidates.push(DeltaCandidate { target: *h, base });
        }
    }

    let delta_results = encode_deltas(store, &candidates)?;
    if delta_results.len() != candidates.len() {
        return Err(StoreError::DeltaBatchLengthMismatch {
            expected: candidates.len(),
            actual: delta_results.len(),
        });
    }
    let mut encoded: HashMap<Hash, PlannedDelta> = candidates
        .iter()
        .zip(delta_results)
        .filter_map(|(candidate, planned)| Some((candidate.target, planned?)))
        .collect();

    // A blob goes out as its delta if one was encoded, else raw. A candidate
    // whose encode returned nothing is never dropped. A blob listed twice
    // (a repeat past the chunk memory) goes out as its delta once.
    let mut raw = non_blob_raw;
    let mut deltas = Vec::with_capacity(encoded.len());
    let mut sent_as_delta: HashSet<Hash> = HashSet::new();
    for h in blobs {
        if let Some(planned) = encoded.remove(&h) {
            sent_as_delta.insert(h);
            deltas.push(planned);
        } else if !sent_as_delta.contains(&h) {
            raw.push(h);
        }
    }

    // A reader holds a base from the first delta that names it to the last.
    // The deltas of one base sit next to each other, so a pack holds one base
    // at a time, whatever the number of bases. Hash order inside a base and
    // between bases keeps the plan, and so the pack bytes, deterministic.
    deltas.sort_unstable_by(|a, b| a.base.cmp(&b.base).then_with(|| a.target.cmp(&b.target)));

    Ok(PackPlan {
        raw,
        deltas,
        self_contained: held.tip().is_none(),
    })
}

/// Encode `target` against `base` and return the delta only if it is
/// strictly smaller on the wire than sending the target raw. The per-entry
/// frame (SPEC-PACKFILE §2) is identical for raw and delta, so only the
/// payloads differ: a delta payload is `base_hash (HASH_LEN) + stream`
/// (SPEC-PACKFILE §3.2) versus the raw object bytes. Compare those.
///
/// Takes `base_bytes` already read — both callers ([`encode_delta_candidate`]
/// and [`encode_delta_candidate_with_base`]) read `base` themselves,
/// from different sourcing strategies, so this pure comparison step
/// doesn't need to know which.
fn try_delta(
    target: Hash,
    base: Hash,
    target_bytes: &[u8],
    base_bytes: &[u8],
) -> Option<PlannedDelta> {
    try_delta_with(target, base, target_bytes, base_bytes, delta_fits_reader)
}

/// [`try_delta`] with the test of whether a reader takes the delta given.
fn try_delta_with(
    target: Hash,
    base: Hash,
    target_bytes: &[u8],
    base_bytes: &[u8],
    fits: impl FnOnce(&[u8]) -> bool,
) -> Option<PlannedDelta> {
    let Ok(stream) = delta::encode(base_bytes, target_bytes) else {
        // Over-u32 inputs can't happen here (object cap < 4 GiB), but treat
        // any encode failure as "send raw" rather than propagating.
        return None;
    };
    if hash::HASH_LEN + stream.len() < target_bytes.len() && fits(&stream) {
        Some(PlannedDelta {
            target,
            base,
            stream,
        })
    } else {
        None
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunker::{ChunkIterator, FastCdc};
    use crate::object::{Blob, Commit, EntryMode, Identity, Tree, TreeEntry};
    use crate::pack::{PackReader, PackWriter};
    use crate::serialize;
    use tempfile::TempDir;

    #[test]
    fn only_a_delta_a_reader_takes_alone_is_planned() {
        let base = vec![7_u8; 4096];
        let mut target = base.clone();
        target[100] = 8;
        // Within the default budget, the delta is taken.
        assert!(try_delta([2; 32], [1; 32], &target, &base).is_some());
        // A delta whose wire payload is as long as the object is not worth
        // sending: only a shorter one is. Look for an edit that fills it.
        let mut state = 0x2545_F491_4F6C_DD1D_u64;
        let mut noise = |len: usize| -> Vec<u8> {
            (0..len)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    state.to_le_bytes()[0]
                })
                .collect()
        };
        let small = noise(200);
        let mut equal = 0;
        for literal in 1..24_usize {
            for copy in 16..120_usize {
                let mut changed = noise(literal);
                changed.extend_from_slice(&small[..copy]);
                let stream = delta::encode(&small, &changed).unwrap();
                let wire = hash::HASH_LEN + stream.len();
                let planned = try_delta_with([2; 32], [1; 32], &changed, &small, |_| true);
                assert_eq!(planned.is_some(), wire < changed.len());
                equal += usize::from(wire == changed.len());
            }
        }
        assert!(equal > 0, "no edit filled the object exactly");
        // A delta that a reader cannot take alone is declined, so the object
        // goes raw.
        assert!(try_delta_with([2; 32], [1; 32], &target, &base, |_| false).is_none());
        assert!(try_delta_with([2; 32], [1; 32], &target, &base, |_| true).is_some());
    }

    pub(super) fn store() -> (TempDir, ObjectStore) {
        let d = TempDir::new().unwrap();
        let s = ObjectStore::init(&crate::layout::RepoLayout::single(d.path())).unwrap();
        (d, s)
    }

    pub(super) fn put(s: &ObjectStore, obj: &Object) -> Hash {
        s.write(&serialize::serialize(obj).unwrap()).unwrap()
    }

    /// Store `data` as `FastCDC` chunks + a `ChunkedBlob` manifest, mirroring
    /// the worktree large-file path. Returns the manifest hash.
    pub(super) fn put_chunked(s: &ObjectStore, data: &[u8]) -> Hash {
        let chunks: Vec<(Hash, u64)> = ChunkIterator::new(FastCdc::v1(), data)
            .take(data.len() + 1)
            .map(|b| {
                let id = put(
                    s,
                    &Object::Blob(Blob {
                        data: data[b.offset..b.offset + b.length].to_vec(),
                    }),
                );
                (id, b.length as u64)
            })
            .collect();
        put(
            s,
            &Object::ChunkedBlob(crate::object::testing::sized(0, chunks).unwrap()),
        )
    }

    pub(super) fn commit_with_file(
        s: &ObjectStore,
        file_hash: Hash,
        parents: Vec<Hash>,
        msg: &str,
    ) -> Hash {
        commit_with_named_file(s, b"big.bin", file_hash, parents, msg)
    }

    /// Like [`commit_with_file`], but with a caller-chosen tree entry name —
    /// needed to build trees with more than one entry, or to control whether
    /// two commits share a path.
    pub(super) fn commit_with_named_file(
        s: &ObjectStore,
        name: &[u8],
        file_hash: Hash,
        parents: Vec<Hash>,
        msg: &str,
    ) -> Hash {
        let tree = put(
            s,
            &Object::Tree(Tree {
                entries: vec![TreeEntry {
                    name: name.to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: file_hash,
                }],
            }),
        );
        put(
            s,
            &Object::Commit(Commit::new_unannotated(
                tree,
                parents,
                Identity::ed25519([7; 32]),
                [0; 32],
                msg.as_bytes().to_vec(),
                msg.len() as u64,
                [0; 64],
            )),
        )
    }

    /// A >1 MiB pseudo-random buffer (deterministic) that `FastCDC` splits
    /// into several chunks. Splitmix64 keeps it dependency-free and
    /// reproducible.
    pub(super) fn big_buffer() -> Vec<u8> {
        let mut data = vec![0u8; 2 * 1024 * 1024];
        let mut state: u64 = 0x1234_5678_9abc_def0;
        for chunk in data.chunks_mut(8) {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^= z >> 31;
            let bytes = z.to_le_bytes();
            let n = chunk.len();
            chunk.copy_from_slice(&bytes[..n]);
        }
        data
    }

    #[test]
    fn packlist_node_roundtrip_with_prev() {
        let prev = [0x11u8; 32];
        let packs = vec![[1u8; 32], [2u8; 32], [0xABu8; 32]];
        let bytes = encode_packlist(Some(prev), &packs).unwrap();
        assert_eq!(&bytes[..4], PACKLIST_MAGIC);
        assert_eq!(bytes[4], PACKLIST_VERSION);
        let node = decode_packlist(&bytes).unwrap();
        assert_eq!(node.prev, Some(prev));
        assert_eq!(node.packs, packs);
    }

    #[test]
    fn packlist_node_roundtrip_first_node() {
        // First node of a branch: no predecessor, one pack.
        let bytes = encode_packlist(None, &[[7u8; 32]]).unwrap();
        let node = decode_packlist(&bytes).unwrap();
        assert_eq!(node.prev, None);
        assert_eq!(node.packs, vec![[7u8; 32]]);
    }

    #[test]
    fn packlist_rejects_bad_magic_version_body_and_length() {
        let good = encode_packlist(Some([0x11u8; 32]), &[[9u8; 32]]).unwrap();

        // Magic and version are the explicit guard header (precise errors).
        let mut bad_magic = good.clone();
        bad_magic[0] = b'X';
        assert_eq!(
            decode_packlist(&bad_magic),
            Err(PackListError::InvalidMagic)
        );

        let mut bad_ver = good.clone();
        bad_ver[4] = 2;
        assert_eq!(
            decode_packlist(&bad_ver),
            Err(PackListError::UnsupportedVersion(2))
        );

        // Truncated codec body → Malformed.
        let mut short = good.clone();
        short.pop();
        assert_eq!(decode_packlist(&short), Err(PackListError::Malformed));

        // Trailing byte after the declared body → Malformed.
        let mut long = good;
        long.push(0);
        assert_eq!(decode_packlist(&long), Err(PackListError::Malformed));

        // Shorter than the magic+version guard header → TooShort.
        assert_eq!(decode_packlist(&[0u8; 3]), Err(PackListError::TooShort));
    }

    #[test]
    fn packlist_decode_rejects_over_cap_pack_list() {
        // A REAL over-cap body: `encode_packlist` refuses to build one,
        // so assemble the node by hand with the same codec — the guard
        // header followed by `Option<Hash>` + a `Vec<Hash>` holding
        // PACKLIST_MAX_ENTRIES + 1 entries (~32 MiB). The decode-side
        // RangeCfg must reject it as Malformed, not allocate it.
        use commonware_codec::Write as _;
        let over_cap = PACKLIST_MAX_ENTRIES as usize + 1;
        let mut node = Vec::with_capacity(PACKLIST_HEADER_LEN + 8 + 32 * over_cap);
        node.extend_from_slice(PACKLIST_MAGIC);
        node.push(PACKLIST_VERSION);
        let prev: Option<Hash> = None;
        prev.write(&mut node);
        vec![[1u8; 32]; over_cap].write(&mut node);
        assert_eq!(decode_packlist(&node), Err(PackListError::Malformed));

        // Sanity: the identical construction at exactly the cap is
        // accepted, so the failure above is the cap check itself, not
        // an artifact of the hand-rolled encoding.
        let mut at_cap = Vec::with_capacity(PACKLIST_HEADER_LEN + 8 + 32 * (over_cap - 1));
        at_cap.extend_from_slice(PACKLIST_MAGIC);
        at_cap.push(PACKLIST_VERSION);
        let prev: Option<Hash> = None;
        prev.write(&mut at_cap);
        vec![[1u8; 32]; over_cap - 1].write(&mut at_cap);
        let decoded = decode_packlist(&at_cap).expect("at-cap list must decode");
        assert_eq!(decoded.packs.len(), PACKLIST_MAX_ENTRIES as usize);
    }

    #[test]
    fn packlist_with_a_huge_count_and_short_input_is_malformed() {
        use commonware_codec::Encode as _;
        let mut node = Vec::new();
        node.extend_from_slice(PACKLIST_MAGIC);
        node.push(PACKLIST_VERSION);
        node.push(0); // no previous node
        node.extend_from_slice(&(PACKLIST_MAX_ENTRIES as usize).encode());
        node.extend_from_slice(&[1u8; 100]);
        assert_eq!(decode_packlist(&node), Err(PackListError::Malformed));
    }

    #[test]
    fn plan_first_push_is_self_contained_all_raw() {
        let (_d, s) = store();
        let file = put_chunked(&s, &big_buffer());
        let c1 = commit_with_file(&s, file, vec![], "v1");

        let plan = plan_pack(&s, c1, None).unwrap();
        assert!(plan.self_contained);
        assert!(plan.deltas.is_empty(), "no base on a first push");
        // commit + tree + manifest + every chunk must be present.
        let full = crate::ops::reachable_objects(&s, &c1).unwrap();
        assert_eq!(plan.object_count(), full.len());
    }

    // =================================================================
    // object_type() short-circuit for plan_pack's type check (INV-14)
    // — classification must use the cheap type-prologue check
    // rather than a full read+verify, while objects actually selected as
    // delta candidates still get a real, verified read.
    // =================================================================

    /// Flip the last byte so the object's on-disk content no longer matches
    /// its BLAKE3 hash, while its 10-byte prologue stays intact and
    /// `object_head()` still reads it correctly.
    fn corrupt_payload_byte(s: &ObjectStore, h: &Hash) {
        use std::fs::OpenOptions;
        use std::io::{Read, Seek, SeekFrom, Write};
        let path = s.path_for(h);
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        // The last byte is content, so the 10-byte prologue stays valid.
        f.seek(SeekFrom::End(-1)).unwrap();
        let mut byte = [0u8; 1];
        f.read_exact(&mut byte).unwrap();
        f.seek(SeekFrom::End(-1)).unwrap();
        f.write_all(&[byte[0] ^ 0xFF]).unwrap();
        f.sync_all().unwrap();
    }

    #[test]
    fn plan_pack_first_push_tolerates_corrupted_raw_blob_content() {
        // First push: every blob in the send-set is `raw` (no delta base
        // exists yet), so classification never needs to read a blob's
        // content — only its type. A blob whose payload has bit-rotted
        // must therefore still plan cleanly and land in `raw`; the actual
        // pack build is where its (now-failing) integrity check belongs.
        let (_d, s) = store();
        let file = put_chunked(&s, &big_buffer());
        let c1 = commit_with_file(&s, file, vec![], "v1");

        let full = crate::ops::reachable_objects(&s, &c1).unwrap();
        let blob_hash = *full
            .iter()
            .find(|h| s.object_type(h).unwrap() == ObjectType::Blob)
            .expect("chunked big_buffer must contain at least one blob chunk");
        corrupt_payload_byte(&s, &blob_hash);

        // Sanity: a full verified read of this object now fails.
        assert!(matches!(
            s.read(&blob_hash),
            Err(StoreError::HashMismatch { .. })
        ));

        let plan = plan_pack(&s, c1, None).unwrap();
        assert!(plan.raw.contains(&blob_hash));
        assert_eq!(plan.object_count(), full.len());
    }

    #[test]
    fn plan_pack_second_push_still_verifies_delta_candidate_bytes() {
        // A blob that IS a delta candidate (paired with a base the remote
        // holds) must still get a real, verified read — the short-circuit
        // only removes the *classification* read, not the read needed to
        // actually build a delta.
        let (_d, s) = store();
        let v1 = big_buffer();
        let file1 = put_chunked(&s, &v1);
        let c1 = commit_with_file(&s, file1, vec![], "v1");

        let mut v2 = v1.clone();
        for k in 0..16 {
            v2[900_000 + k] ^= 0xFF;
        }
        let file2 = put_chunked(&s, &v2);
        let c2 = commit_with_file(&s, file2, vec![c1], "v2");

        let bases = select_chunk_delta_bases(&s, c2, c1).unwrap();
        let target = *bases.keys().next().expect("expected a paired chunk");
        corrupt_payload_byte(&s, &target);

        let err = plan_pack(&s, c2, Some(c1)).unwrap_err();
        assert!(matches!(err, StoreError::HashMismatch { .. }));
    }

    #[test]
    fn plan_second_push_deltas_changed_chunk_and_skips_unchanged() {
        let (_d, s) = store();
        let v1 = big_buffer();
        let file1 = put_chunked(&s, &v1);
        let c1 = commit_with_file(&s, file1, vec![], "v1");

        // Edit a small in-place region (same length → stable boundaries).
        let mut v2 = v1.clone();
        for k in 0..16 {
            v2[900_000 + k] ^= 0xFF;
        }
        let file2 = put_chunked(&s, &v2);
        let c2 = commit_with_file(&s, file2, vec![c1], "v2");

        let plan = plan_pack(&s, c2, Some(c1)).unwrap();
        assert!(
            !plan.self_contained,
            "second push diffs against the prior tip"
        );

        // At least one changed chunk should delta-compress.
        assert!(
            !plan.deltas.is_empty(),
            "expected a delta for the edited chunk"
        );

        // The send-set must exclude every object the v1 closure already
        // holds (identical-chunk dedup), so it is far smaller than the full
        // v2 closure.
        let v2_full = crate::ops::reachable_objects(&s, &c2).unwrap();
        assert!(
            plan.object_count() < v2_full.len(),
            "unchanged chunks must not be re-sent"
        );

        // The pack must reconstruct, bit-for-bit, against a store seeded
        // with the v1 closure (what the remote/fetcher already holds).
        assert_pack_reconstructs(&s, &plan, c1, c2);
    }

    /// Build the planned pack, replay it into a fresh store pre-seeded with
    /// `old_tip`'s closure, and assert every `new_tip` object reconstructs
    /// with a matching hash.
    pub(super) fn assert_pack_reconstructs(
        src: &ObjectStore,
        plan: &PackPlan,
        old_tip: Hash,
        new_tip: Hash,
    ) {
        let mut w = PackWriter::new();
        for h in &plan.raw {
            let bytes = src.read(h).unwrap();
            w.push_raw(*h, &bytes).unwrap();
        }
        for d in &plan.deltas {
            w.push_delta(&d.base, &d.stream).unwrap();
        }
        let pack = w.finish().unwrap();

        // Seed the destination with what the remote already has.
        let (_d2, dst) = store();
        for h in crate::ops::reachable_objects(src, &old_tip).unwrap() {
            dst.write(&src.read(&h).unwrap()).unwrap();
        }

        PackReader::read(&pack, &dst).unwrap();

        for h in crate::ops::reachable_objects(src, &new_tip).unwrap() {
            // `dst.read` already re-verifies the object addresses to `h`
            // (merkle root for Tree/ChunkedBlob, BLAKE3 otherwise); assert
            // the dispatched id explicitly via `Object::id`.
            let got = dst.read(&h).unwrap();
            assert_eq!(
                crate::serialize::deserialize(&got).unwrap().id().unwrap(),
                h,
                "reconstructed object must address to its id"
            );
            assert_eq!(got, src.read(&h).unwrap());
        }
    }

    #[test]
    fn select_bases_pairs_only_changed_chunks() {
        let (_d, s) = store();
        let v1 = big_buffer();
        let file1 = put_chunked(&s, &v1);
        let c1 = commit_with_file(&s, file1, vec![], "v1");

        let mut v2 = v1.clone();
        v2[1_000_000] ^= 0xFF;
        let file2 = put_chunked(&s, &v2);
        let c2 = commit_with_file(&s, file2, vec![c1], "v2");

        let bases = select_chunk_delta_bases(&s, c2, c1).unwrap();
        assert!(!bases.is_empty());
        // Every paired target is a chunk that is new in v2, and every base
        // is a chunk that v1 held.
        let v1_set = crate::ops::reachable_objects(&s, &c1).unwrap();
        for (target, base) in &bases {
            assert!(!v1_set.contains(target), "target should be new");
            assert!(v1_set.contains(base), "base must be present at old tip");
        }
    }

    /// Deterministic, feature-rich chunk content (xorshift so 16-byte window
    /// hashes are well-distributed rather than colliding on flat data).
    pub(super) fn chunk_content(seed: u8, len: usize) -> Vec<u8> {
        let mut state = u64::from(seed).wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        let mut v = vec![0u8; len];
        for byte in &mut v {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = (state & 0xff) as u8;
        }
        v
    }

    pub(super) fn put_blob(s: &ObjectStore, content: Vec<u8>) -> Hash {
        put(s, &Object::Blob(Blob { data: content }))
    }

    /// Build a `ChunkedBlob` from explicit chunk contents (bypassing
    /// `FastCDC`) so a test can control chunk boundaries and shifts precisely.
    pub(super) fn put_chunked_from(s: &ObjectStore, chunks: &[Vec<u8>]) -> Hash {
        let entries: Vec<(Hash, u64)> = chunks
            .iter()
            .map(|c| (put_blob(s, c.clone()), c.len() as u64))
            .collect();
        put(
            s,
            &Object::ChunkedBlob(crate::object::testing::sized(0, entries).unwrap()),
        )
    }

    #[test]
    #[allow(clippy::many_single_char_names)] // a..e keep the chunk-shift table compact
    fn content_aware_pairing_picks_similar_base_after_a_shift() {
        let (_d, s) = store();
        let (a, b, c, d, e) = (
            chunk_content(1, 400),
            chunk_content(2, 400),
            chunk_content(3, 400),
            chunk_content(4, 400),
            chunk_content(5, 400),
        );
        let mut e_mod = e.clone();
        e_mod[200] ^= 0xFF; // a one-byte edit to E

        // Old file = [A,B,C,D,E]; new file = [B,C,D,E'] — A deleted (so every
        // surviving chunk's index shifts down by one) and E modified. Counts
        // differ, so the content-similarity path runs.
        let old_file = put_chunked_from(&s, &[a, b.clone(), c.clone(), d.clone(), e.clone()]);
        let new_file = put_chunked_from(&s, &[b, c, d.clone(), e_mod.clone()]);
        let c_old = commit_with_file(&s, old_file, vec![], "old");
        let c_new = commit_with_file(&s, new_file, vec![c_old], "new");

        let bases = select_chunk_delta_bases(&s, c_new, c_old).unwrap();

        let e_mod_id = put_blob(&s, e_mod);
        let e_id = put_blob(&s, e);
        let d_id = put_blob(&s, d);

        // E' is the only changed chunk. It sits at new index 3; the old chunk
        // at index 3 is D, so position-clamp pairing would mispair E'→D.
        // Content similarity must instead pair E'→E (its real prior version).
        assert_eq!(
            bases.get(&e_mod_id),
            Some(&e_id),
            "E' must delta against E (content match), not the wrong-index D"
        );
        assert_ne!(bases.get(&e_mod_id), Some(&d_id));
    }

    #[test]
    #[allow(clippy::many_single_char_names)] // a..d + z keep the chunk table compact
    fn shifted_pairing_skips_a_chunk_with_no_content_overlap() {
        // After a shift (differing counts), a brand-new chunk dissimilar to
        // every old chunk must NOT be paired — no position/clamp fallback.
        let (_d, s) = store();
        let (a, b, c, d) = (
            chunk_content(1, 400),
            chunk_content(2, 400),
            chunk_content(3, 400),
            chunk_content(4, 400),
        );
        let z = chunk_content(99, 400); // unrelated to a/b/c/d
        // old = [A,B,C,D]; new = [B,C,Z] — counts differ (content path), and Z
        // is new + dissimilar to every old chunk.
        let old_file = put_chunked_from(&s, &[a, b.clone(), c.clone(), d]);
        let new_file = put_chunked_from(&s, &[b, c, z.clone()]);
        let c_old = commit_with_file(&s, old_file, vec![], "old");
        let c_new = commit_with_file(&s, new_file, vec![c_old], "new");

        let bases = select_chunk_delta_bases(&s, c_new, c_old).unwrap();
        let z_id = put_blob(&s, z);
        assert!(
            !bases.contains_key(&z_id),
            "a dissimilar new chunk must be left unpaired (sent raw), not clamped to a base"
        );
    }

    #[test]
    fn a_shifted_file_in_a_subdirectory_is_paired_like_one_at_the_root() {
        let (_d, s) = store();
        let chunks: Vec<Vec<u8>> = (1..=5).map(|i| chunk_content(i, 400)).collect();
        let mut e_mod = chunks[4].clone();
        e_mod[200] ^= 0xFF;
        let old_file = put_chunked_from(&s, &chunks);
        let new_file = put_chunked_from(
            &s,
            &[
                chunks[1].clone(),
                chunks[2].clone(),
                chunks[3].clone(),
                e_mod.clone(),
            ],
        );
        let nested = |file: Hash, parents: Vec<Hash>, msg: &str| {
            let dir = put(
                &s,
                &Object::Tree(Tree {
                    entries: vec![TreeEntry {
                        name: b"big.bin".to_vec(),
                        mode: EntryMode::Blob,
                        object_hash: file,
                    }],
                }),
            );
            let root = put(
                &s,
                &Object::Tree(Tree {
                    entries: vec![TreeEntry {
                        name: b"dir".to_vec(),
                        mode: EntryMode::Tree,
                        object_hash: dir,
                    }],
                }),
            );
            put(
                &s,
                &Object::Commit(Commit::new_unannotated(
                    root,
                    parents,
                    Identity::ed25519([7; 32]),
                    [0; 32],
                    msg.as_bytes().to_vec(),
                    msg.len() as u64,
                    [0; 64],
                )),
            )
        };
        let c_old = nested(old_file, vec![], "old");
        let c_new = nested(new_file, vec![c_old], "new");
        let bases = select_chunk_delta_bases(&s, c_new, c_old).unwrap();
        assert_eq!(
            bases.get(&put_blob(&s, e_mod)),
            Some(&put_blob(&s, chunks[4].clone()))
        );
    }

    #[test]
    fn a_shifted_file_over_the_pairing_bound_sends_its_changed_chunks_raw() {
        // old = [A,B,C,D,E]; new = [B,C,D,E']: counts differ, and E' is E with
        // one byte changed. Within the bound E' pairs with E; one chunk over
        // the bound on either side, nothing pairs. The bound is inclusive.
        let (_d, s) = store();
        let chunks: Vec<Vec<u8>> = (1..=5).map(|i| chunk_content(i, 400)).collect();
        let mut e_mod = chunks[4].clone();
        e_mod[200] ^= 0xFF;
        let ids = |contents: &[Vec<u8>]| -> Vec<Hash> {
            contents.iter().map(|c| put_blob(&s, c.clone())).collect()
        };
        let old = ids(&chunks);
        let new = ids(&[
            chunks[1].clone(),
            chunks[2].clone(),
            chunks[3].clone(),
            e_mod,
        ]);
        let pair = |max| {
            let mut out = HashMap::new();
            pair_chunks(&s, &new, &old, max, &mut out).unwrap();
            out
        };
        assert_eq!(pair(5), HashMap::from([(new[3], old[4])]));
        assert!(pair(4).is_empty());
        // Equal counts need no content reads, so the bound does not apply.
        let mut out = HashMap::new();
        pair_chunks(&s, &new, &new, 0, &mut out).unwrap();
        assert!(out.is_empty());
        let mut same_count = old.clone();
        same_count[4] = new[3];
        pair_chunks(&s, &same_count, &old, 0, &mut out).unwrap();
        assert_eq!(out, HashMap::from([(new[3], old[4])]));
    }

    #[test]
    fn equal_count_edit_still_uses_fast_index_path() {
        // Same chunk count ⇒ no shift ⇒ same-index pairing (no content reads).
        let (_d, s) = store();
        let (a, b, c) = (
            chunk_content(10, 400),
            chunk_content(11, 400),
            chunk_content(12, 400),
        );
        let mut b_mod = b.clone();
        b_mod[50] ^= 0xFF;
        let old_file = put_chunked_from(&s, &[a.clone(), b.clone(), c.clone()]);
        let new_file = put_chunked_from(&s, &[a, b_mod.clone(), c]);
        let c_old = commit_with_file(&s, old_file, vec![], "old");
        let c_new = commit_with_file(&s, new_file, vec![c_old], "new");

        let bases = select_chunk_delta_bases(&s, c_new, c_old).unwrap();
        let b_mod_id = put_blob(&s, b_mod);
        let b_id = put_blob(&s, b);
        assert_eq!(
            bases.get(&b_mod_id),
            Some(&b_id),
            "in-place edit pairs by index"
        );
    }

    // =================================================================
    // #646a — small (non-chunked) blob delta pairing. `pair_entry` must
    // pair a changed `Blob<->Blob` same-path entry (previously a no-op),
    // using the old blob as the delta base for the new one, without
    // touching cross-path or `Blob<->ChunkedBlob` transitions.
    // =================================================================

    #[test]
    fn small_blob_edit_is_delta_paired_against_same_path_prior_version() {
        let (_d, s) = store();
        // Small, well under CHUNK_THRESHOLD: a single Blob object, not a
        // ChunkedBlob manifest. Large enough (many unchanged lines around a
        // single mid-file edit) that a delta's fixed per-instruction
        // overhead (SPEC-DELTA header + two COPYs + one INSERT + the
        // HASH_LEN base pointer) is comfortably smaller than the raw blob.
        let mut v1 = Vec::new();
        for i in 0..40 {
            v1.extend_from_slice(format!("unchanged line number {i:02}\n").as_bytes());
        }
        let mut v2 = v1.clone();
        // Replace exactly one line in the middle with a different one,
        // keeping everything before/after byte-identical to v1.
        let needle = b"unchanged line number 20\n".to_vec();
        let pos = v2
            .windows(needle.len())
            .position(|w| w == needle.as_slice())
            .unwrap();
        v2.splice(
            pos..pos + needle.len(),
            b"THIS LINE WAS EDITED\n".iter().copied(),
        );

        let blob1 = put_blob(&s, v1.clone());
        let blob2 = put_blob(&s, v2.clone());
        let c1 = commit_with_named_file(&s, b"small.txt", blob1, vec![], "v1");
        let c2 = commit_with_named_file(&s, b"small.txt", blob2, vec![c1], "v2");

        let bases = select_chunk_delta_bases(&s, c2, c1).unwrap();
        assert_eq!(
            bases.get(&blob2),
            Some(&blob1),
            "same-path small-blob edit must pair against the prior version"
        );

        // The pairing must actually be usable by plan_pack: it should
        // produce a delta for blob2, and that delta must be strictly
        // smaller on the wire than sending blob2 raw.
        let plan = plan_pack(&s, c2, Some(c1)).unwrap();
        let planned = plan
            .deltas
            .iter()
            .find(|d| d.target == blob2)
            .expect("expected a planned delta for the edited small blob");
        assert_eq!(planned.base, blob1);
        assert!(
            hash::HASH_LEN + planned.stream.len() < v2.len(),
            "delta payload must beat sending the new blob raw"
        );
        assert!(
            !plan.raw.contains(&blob2),
            "the edited blob should not also be sent raw"
        );

        assert_pack_reconstructs(&s, &plan, c1, c2);
    }

    /// The deltas of a plan are ordered by base and then target, so a reader
    /// holds one external base at a time and the plan is deterministic.
    #[test]
    fn the_deltas_of_a_plan_are_ordered_by_base_then_target() {
        let (_d, s) = store();
        let text = |file: usize, edit: bool| {
            let mut out = Vec::new();
            for i in 0..40 {
                if edit && i == 20 {
                    out.extend_from_slice(b"THIS LINE WAS EDITED\n");
                } else {
                    out.extend_from_slice(format!("file {file} line {i:02}\n").as_bytes());
                }
            }
            out
        };
        let commit_of = |edit: bool, parents: Vec<Hash>| {
            let entries = (0..8)
                .map(|file| TreeEntry {
                    name: format!("f{file}.txt").into_bytes(),
                    mode: EntryMode::Blob,
                    object_hash: put_blob(&s, text(file, edit)),
                })
                .collect();
            let tree = put(&s, &Object::Tree(Tree { entries }));
            put(
                &s,
                &Object::Commit(Commit::new_unannotated(
                    tree,
                    parents,
                    Identity::ed25519([7; 32]),
                    [0; 32],
                    b"m".to_vec(),
                    1,
                    [0; 64],
                )),
            )
        };
        let c1 = commit_of(false, vec![]);
        let c2 = commit_of(true, vec![c1]);
        let plan = plan_pack(&s, c2, Some(c1)).unwrap();
        assert!(plan.deltas.len() >= 2, "{}", plan.deltas.len());
        let keys: Vec<_> = plan.deltas.iter().map(|d| (d.base, d.target)).collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        assert_eq!(keys, sorted);
    }

    #[test]
    fn plan_pack_with_reports_a_typed_error_when_encode_deltas_miscounts() {
        // Same fixture as `small_blob_edit_is_delta_paired_against_same_path_prior_version`
        // — one delta candidate — but with a broken `encode_deltas` that
        // drops it instead of returning one result per candidate. Pins
        // `plan_pack_with`'s length-check contract: a caller bug here must
        // surface as `StoreError::DeltaBatchLengthMismatch`, not a panic.
        let (_d, s) = store();
        let mut v1 = Vec::new();
        for i in 0..40 {
            v1.extend_from_slice(format!("unchanged line number {i:02}\n").as_bytes());
        }
        let mut v2 = v1.clone();
        let needle = b"unchanged line number 20\n".to_vec();
        let pos = v2
            .windows(needle.len())
            .position(|w| w == needle.as_slice())
            .unwrap();
        v2.splice(
            pos..pos + needle.len(),
            b"THIS LINE WAS EDITED\n".iter().copied(),
        );
        let blob1 = put_blob(&s, v1);
        let blob2 = put_blob(&s, v2);
        let c1 = commit_with_named_file(&s, b"small.txt", blob1, vec![], "v1");
        let c2 = commit_with_named_file(&s, b"small.txt", blob2, vec![c1], "v2");

        let bases = select_chunk_delta_bases(&s, c2, c1).unwrap();
        assert_eq!(
            bases.get(&blob2),
            Some(&blob1),
            "sanity: expects a delta candidate"
        );

        let err = plan_pack_with(&s, c2, Some(c1), |_store, candidates| {
            assert_eq!(
                candidates.len(),
                1,
                "sanity: exactly one candidate expected"
            );
            Ok(Vec::new()) // drops the one candidate's result — the bug under test
        })
        .unwrap_err();
        assert!(
            matches!(
                err,
                StoreError::DeltaBatchLengthMismatch {
                    expected: 1,
                    actual: 0
                }
            ),
            "expected DeltaBatchLengthMismatch, got {err:?}"
        );
    }

    #[test]
    fn small_blob_pairing_is_strictly_same_path() {
        // Two unrelated paths, each holding a small blob, where the "new"
        // path's content is a near-duplicate of the "old" path's content.
        // Despite the content similarity, pairing is same-path only — a
        // blob at a path with no old-side counterpart must never be paired
        // against a differently-named entry's prior blob.
        let (_d, s) = store();
        let a_v1 = b"shared prefix content for path a\n".to_vec();
        let mut a_v2 = a_v1.clone();
        a_v2.push(b'!');

        let blob_a1 = put_blob(&s, a_v1.clone());
        let blob_a2 = put_blob(&s, a_v2);
        let c1 = commit_with_named_file(&s, b"a.txt", blob_a1, vec![], "v1");

        // c2 changes "a.txt" AND introduces a brand-new path "b.txt" whose
        // content is near-identical to a.txt's OLD content (but it is a
        // distinct path with no old-side entry at all).
        let blob_b = put_blob(&s, a_v1);
        let tree2 = put(
            &s,
            &Object::Tree(Tree {
                entries: vec![
                    TreeEntry {
                        name: b"a.txt".to_vec(),
                        mode: EntryMode::Blob,
                        object_hash: blob_a2,
                    },
                    TreeEntry {
                        name: b"b.txt".to_vec(),
                        mode: EntryMode::Blob,
                        object_hash: blob_b,
                    },
                ],
            }),
        );
        let c2 = put(
            &s,
            &Object::Commit(Commit::new_unannotated(
                tree2,
                vec![c1],
                Identity::ed25519([7; 32]),
                [0; 32],
                b"v2".to_vec(),
                2,
                [0; 64],
            )),
        );

        let bases = select_chunk_delta_bases(&s, c2, c1).unwrap();
        assert_eq!(
            bases.get(&blob_a2),
            Some(&blob_a1),
            "a.txt's edit still pairs against its own prior version"
        );
        assert!(
            !bases.contains_key(&blob_b),
            "b.txt has no old-side counterpart and must not be paired at all, \
             even against a content-similar blob from a different path"
        );
    }
}

#[cfg(test)]
mod wire_conformance {
    use super::*;

    /// Conformance pin: the exact on-wire bytes of a `PackListNode`. Locks
    /// the `commonware-codec` body encoding (`KPKL` + version guard, then a
    /// codec `Option<Hash>` and a length-prefixed `Vec<Hash>`) so a
    /// commonware version bump that silently changes the encoding is caught
    /// here rather than in the field. Regenerate deliberately only on an
    /// intentional format change (and bump `PACKLIST_VERSION`).
    #[test]
    fn packlist_wire_format_is_pinned() {
        let bytes = encode_packlist(Some([0x11u8; 32]), &[[0x22u8; 32], [0x33u8; 32]]).unwrap();
        let expected = "4b504b4c0101\
                        1111111111111111111111111111111111111111111111111111111111111111\
                        02\
                        2222222222222222222222222222222222222222222222222222222222222222\
                        3333333333333333333333333333333333333333333333333333333333333333";
        assert_eq!(
            hash::to_hex_bytes(&bytes),
            expected,
            "PackListNode wire format drifted (commonware-codec change?)"
        );
        let node = decode_packlist(&bytes).unwrap();
        assert_eq!(node.prev, Some([0x11u8; 32]));
        assert_eq!(node.packs, vec![[0x22u8; 32], [0x33u8; 32]]);
    }
}

#[cfg(test)]
mod push_walk_tests;

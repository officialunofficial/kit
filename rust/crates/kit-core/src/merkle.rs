//! Merkle (BMT) content-addressing for `ChunkedBlob` and `Tree`.
//!
//! A merkelized object's content-address **is** its Binary Merkle Tree
//! root: the object id is `wrap_id(kind, bmt_root(leaves))` where the BMT
//! is built over the object's child stream. This makes inclusion of any
//! chunk/entry provable, and makes a reconstructed object's read-time id
//! check a free completeness proof for its whole child set.
//!
//! ## Primitive: a BMT over `blake3`
//!
//! This module implements the construction of `commonware_storage::bmt`.
//! Tests compare the root and the proof bytes with that crate for trees of
//! one or more leaves.
//!
//! The module does not use the upstream crate, for two reasons:
//!
//! * A verifier here starts from an object id, not from a root. The id is
//!   `wrap_id(kind, root)`, and the hash cannot be inverted. The verifier
//!   must rebuild the root from the proof, then wrap it, then compare. The
//!   upstream `verify_*_inclusion` functions take the root as an argument.
//!   They rebuild the root, compare it, and return only `Ok(())` or an
//!   error. They do not return the rebuilt root.
//! * SPEC-MERKLE-OBJECTS §5.4 requires a builder to refuse every position of
//!   an empty tree. Upstream `range_proof` returns a default proof for the
//!   range `0..=0` on an empty tree.
//!
//! Native tests keep `commonware-storage` as a dev-dependency.
//! `tests::root_matches_commonware` compares roots for several leaf counts.
//! `tests::proofs_match_commonware` compares proof bytes. It also checks that
//! upstream accepts each proof that this module builds.
//!
//! The construction (matching commonware):
//! * leaf at index `i` is hashed with its position: `H(i_be32 ‖ leaf)`;
//! * each level pairs nodes `H(left ‖ right)`, duplicating the last node
//!   `H(left ‖ left)` when a level has an odd count;
//! * an empty tree is a single node `H("")`;
//! * the finalized root is `H(leaf_count_be32 ‖ tree_root)`, which binds
//!   the leaf count and defeats the odd-node-duplication malleability.
//!
//! Normative crypto: `docs/specs/SPEC-MERKLE-OBJECTS.md`.
//!
//! ## Identity formulas
//!
//! ```text
//! id            = wrap_id(kind, bmt_root(leaves))
//!               = domain_digest(TYPE_DOMAIN, bmt_root(leaves))
//!
//! ChunkedBlob   leaves = [meta_leaf] ++ chunks
//!   meta_leaf   = domain_digest("kit-cblob-meta-v1", total_size_le ‖ chunk_size_le)
//!   chunk i     -> BMT position i+1   (meta is position 0)
//!
//! Tree          leaves = entries (existing lex order)
//!   entry leaf  = domain_digest("kit-tree-entry-v1", name_len_le ‖ name ‖ mode ‖ object_hash)
//! ```
//!
//! The outer `wrap_id` wrap makes the id type-distinct: a bare BMT root
//! over identical leaf streams would collide across types (the prologue
//! type byte is not in the root), so an empty `Tree` and an empty
//! `ChunkedBlob`, or a 1-entry `Tree` and a 1-chunk `ChunkedBlob` with the
//! same child hash, would otherwise share an id.
//!
//! ## Inclusion proofs — stable, commonware-aligned
//!
//! Object identity (`compute_tree_id` / `compute_chunked_id`) and the
//! inclusion-proof construction below are both stable
//! (`docs/specs/SPEC-MERKLE-OBJECTS.md` §5). [`Proof`]'s bytes and sibling
//! selection are byte-identical to `commonware_storage::bmt::Proof` at the
//! pinned `2026.10.0` train: a commonware-based verifier can decode a
//! kit-produced proof with the upstream type and run its own
//! `verify_element_inclusion` / `verify_range_inclusion` /
//! `verify_multi_inclusion` against the **inner root** (see
//! [`chunked_inner_root`] / [`tree_inner_root`]), then apply [`wrap_id`] to
//! compare against the object id. `tests::proofs_match_commonware` pins
//! this claim; `rust/tests/golden/proofs/` carries fixed vectors.
//!
//! Verification in this crate is always stated against the **object id**
//! (`verify_tree_entry`, `verify_chunk`, and their range/multi
//! counterparts), never the bare inner root — passing a caller the inner
//! root invited skipping the type-domain wrap and accepting, say, a
//! `Tree` proof against a `ChunkedBlob` id (SPEC-DISCLOSURE). The
//! inner-root-comparing primitives (`Proof::verify_element_inclusion` and
//! friends) stay `pub(crate)`, kept only so the cross-check test can
//! compare directly against upstream's verifiers.

use std::collections::{BTreeMap, BTreeSet};

use bytes::{Buf as _, BufMut};
use commonware_codec::{Buf, Copying};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, ReadRangeExt, Write};

use crate::hash::{HASH_LEN, Hash, Hasher, domain_digest, hash};
use crate::object::{ChunkedBlob, Tree, TreeEntry};

/// Type domain for the outer identity wrap of a `ChunkedBlob`.
const CHUNKED_TYPE_DOMAIN: &[u8] = b"kit.chunked\x00";
/// Type domain for the outer identity wrap of a `Tree`.
const TREE_TYPE_DOMAIN: &[u8] = b"kit.tree\x00";
/// Leaf domain binding a `ChunkedBlob`'s `total_size`/`chunk_size`.
const CBLOB_META_DOMAIN: &[u8] = b"kit-cblob-meta-v1";
/// Leaf domain for a `Tree` entry's `(name, mode, object_hash)` triple.
const TREE_ENTRY_DOMAIN: &[u8] = b"kit-tree-entry-v1";

/// Upper bound on sibling levels in a [`Proof`]: `u32::BITS`, matching
/// `commonware_storage::bmt::MAX_LEVELS`. Because [`Proof::leaf_count`] is a
/// `u32`, a tree can have at most `u32::MAX` leaves, which requires at most
/// `u32::BITS` sibling hashes per proven item.
pub const MAX_LEVELS: usize = u32::BITS as usize;

/// The two object kinds addressed by a BMT root (`crate::merkle`), keying
/// [`wrap_id`]'s type-domain wrap. A versioned, supported accessor for the
/// outer identity wrap — the alternative (exposing the raw `TYPE_DOMAIN`
/// byte strings) would make them de facto ABI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    /// A [`Tree`]'s entry list.
    Tree,
    /// A [`ChunkedBlob`]'s `[meta, chunks…]` list.
    ChunkedBlob,
}

impl ObjectKind {
    fn type_domain(self) -> &'static [u8] {
        match self {
            Self::Tree => TREE_TYPE_DOMAIN,
            Self::ChunkedBlob => CHUNKED_TYPE_DOMAIN,
        }
    }
}

/// Apply the outer type-domain wrap to a bare BMT inner root, producing the
/// object id. The inverse does not exist — `wrap_id` is a one-way hash —
/// so a verifier holding `(inner_root, proof)` reconstructs the inner root
/// from the proof and wraps it with the *expected* kind to compare against
/// a claimed id, rather than trying to "unwrap" the id.
#[must_use]
pub fn wrap_id(kind: ObjectKind, inner_root: &Hash) -> Hash {
    domain_digest(kind.type_domain(), inner_root)
}

/// Errors building or verifying a merkle inclusion proof.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MerkleError {
    /// The requested leaf position is outside the object's leaf range.
    #[error("merkle position {0} is out of range")]
    PositionOutOfRange(u32),
    /// The same position was requested more than once in a multi-proof.
    #[error("merkle position {0} is duplicated")]
    DuplicatePosition(u32),
    /// A multi-proof position is lower than the position before it.
    /// Positions must be strictly ascending, in input order.
    #[error("merkle position {0} is not in ascending order")]
    UnsortedPosition(u32),
    /// No positions were given to prove/verify.
    #[error("no merkle positions given")]
    NoPositions,
    /// A range's `start` is greater than its `end`.
    #[error("merkle range start {start} is greater than end {end}")]
    InvalidRange {
        /// The range's start position.
        start: u32,
        /// The range's end position.
        end: u32,
    },
    /// The proof bytes were malformed (bad codec payload or trailing bytes).
    #[error("merkle proof is malformed")]
    MalformedProof,
    /// The proof's sibling count does not match what the position(s)
    /// require — too few, too many, or misordered.
    #[error("merkle proof is unaligned with the requested position(s)")]
    UnalignedProof,
    /// The proof did not verify against the given root/id.
    #[error("merkle proof verification failed")]
    VerificationFailed,
    /// A fold was given more than `u32::MAX` leaves.
    #[error("merkle tree has more than u32::MAX leaves")]
    TooManyLeaves,
    /// Raw chunk id bytes are not a whole number of 32-byte ids.
    #[error("chunk id bytes are not a whole number of 32-byte ids")]
    PartialChunkId,
}

impl From<CodecError> for MerkleError {
    fn from(_: CodecError) -> Self {
        Self::MalformedProof
    }
}

// ---------------------------------------------------------------------------
// BMT primitive (over `blake3`)
// ---------------------------------------------------------------------------

/// Leaf/index count as `u32`. Objects are decode-capped at 1,000,000
/// tree entries and 8,388,608 chunks (see `serialize.rs`), far below
/// `u32::MAX`, so this only panics on a programmer error that bypassed
/// those caps.
fn u32_of(n: usize) -> u32 {
    u32::try_from(n).expect("merkle leaf/index count fits u32 (objects are decode-capped)")
}

/// `BLAKE3(a ‖ b)`.
fn h2(a: &[u8], b: &[u8]) -> Hash {
    let mut h = Hasher::new();
    h.update(a).update(b);
    h.finalize()
}

/// Position-hash a leaf: `H(index_be32 ‖ leaf)` (matches commonware
/// `Builder::add`).
fn position_leaf(index: u32, leaf: &Hash) -> Hash {
    h2(&index.to_be_bytes(), leaf)
}

/// Returns the number of levels in a tree with `leaf_count` leaves
/// (level 0 = leaves, last level = the pre-finalize root). A tree with 1
/// leaf has 1 level, a tree with 2 leaves has 2 levels, etc. The count
/// equals `commonware_storage::bmt::levels_in_tree`.
fn levels_in_tree(leaf_count: u32) -> usize {
    (leaf_count.saturating_sub(1).bit_width() + 1) as usize
}

/// A built BMT: every level from the position-hashed leaves up to the
/// single pre-finalize root node. Test-only reference that the streaming
/// proof builder ([`stream_proof`]) and [`BmtFold`] are checked against;
/// production code holds no level.
#[cfg(test)]
struct BmtTree {
    /// The real leaf count (0 for an empty tree, even though `levels[0]`
    /// then holds a single placeholder node).
    leaf_count: u32,
    /// `true` when built from zero leaves — no position is ever provable.
    empty: bool,
    /// `levels[0]` = position-hashed leaves (or the single `H("")`
    /// placeholder); `levels[levels.len() - 1]` = the single pre-finalize
    /// tree root node.
    levels: Vec<Vec<Hash>>,
    /// The finalized root: `H(leaf_count_be32 ‖ levels.last()[0])`. Tests
    /// compare it with the fold and with commonware.
    root: Hash,
}

#[cfg(test)]
fn build_bmt(leaves: &[Hash]) -> BmtTree {
    let leaf_count = u32_of(leaves.len());
    let empty = leaves.is_empty();
    let position_hashed: Vec<Hash> = if empty {
        vec![hash(b"")]
    } else {
        leaves
            .iter()
            .enumerate()
            .map(|(i, l)| position_leaf(u32_of(i), l))
            .collect()
    };
    let mut levels = vec![position_hashed];
    while levels.last().expect("levels is never empty").len() > 1 {
        let cur = levels.last().expect("levels is never empty");
        let mut next = Vec::with_capacity(cur.len().div_ceil(2));
        for pair in cur.chunks(2) {
            let right = if pair.len() == 2 { &pair[1] } else { &pair[0] };
            next.push(h2(&pair[0], right));
        }
        levels.push(next);
    }
    BmtTree {
        leaf_count,
        empty,
        root: h2(
            &leaf_count.to_be_bytes(),
            &levels.last().expect("levels is never empty")[0],
        ),
        levels,
    }
}

/// The finalized BMT root, computed in one pass over the leaves.
///
/// It holds at most one node per level, so it needs O(log n) memory
/// where the level build holds every level. The root equals the level
/// build's root for every leaf count.
#[derive(Debug)]
struct BmtFold {
    /// Leaves pushed so far.
    count: u32,
    /// `pending[l]` is the left node of an unpaired pair at level `l`.
    /// A tree of at most `u32::MAX` leaves has at most `MAX_LEVELS + 1`
    /// levels.
    pending: [Option<Hash>; MAX_LEVELS + 1],
}

impl BmtFold {
    fn new() -> Self {
        Self {
            count: 0,
            pending: [None; MAX_LEVELS + 1],
        }
    }

    /// Append the next leaf. Each completed pair moves up a level at once.
    fn push(&mut self, leaf: &Hash) -> Result<(), MerkleError> {
        let mut node = position_leaf(self.count, leaf);
        self.count = self
            .count
            .checked_add(1)
            .ok_or(MerkleError::TooManyLeaves)?;
        let mut level = 0;
        while let Some(left) = self.pending[level].take() {
            node = h2(&left, &node);
            level += 1;
        }
        self.pending[level] = Some(node);
        Ok(())
    }

    /// Close every unpaired node from the bottom up, duplicating a level's
    /// last node when the level has an odd count, then bind the leaf
    /// count. Below the top level, the node carried up from level `l - 1`
    /// is the last node of level `l`.
    fn root(&self) -> Hash {
        if self.count == 0 {
            return h2(&0u32.to_be_bytes(), &hash(b""));
        }
        let top = levels_in_tree(self.count) - 1;
        let mut carry: Option<Hash> = None;
        for pending in &self.pending[..top] {
            carry = match (pending, carry) {
                (Some(left), Some(right)) => Some(h2(left, &right)),
                (Some(last), None) => Some(h2(last, last)),
                (None, Some(last)) => Some(h2(&last, &last)),
                (None, None) => None,
            };
        }
        let tree_root = carry
            .or(self.pending[top])
            .expect("a fold of at least one leaf has a node at its top level");
        h2(&self.count.to_be_bytes(), &tree_root)
    }
}

/// Computes a `ChunkedBlob` id from its header fields and its chunk ids,
/// one chunk id at a time.
///
/// The id equals [`compute_chunked_id`] of the same manifest. Memory is
/// O(log n) in the chunk count, so a caller can address a manifest
/// without decoding it whole: read `total_size` and `chunk_size` from the
/// header, then push the chunk ids in order, one at a time with
/// [`Self::push`] or as the raw id bytes of a manifest with
/// [`Self::push_ids`].
///
/// The fold applies none of the decode checks of SPEC-OBJECTS §7, and the
/// id does not bind `chunk_count` by itself. A caller that reads a raw
/// manifest checks the prologue, checks the header with
/// [`crate::serialize::check_chunked_header`], checks that the object is
/// exactly `22 + 32 * chunk_count` bytes long, and pushes exactly
/// `chunk_count` ids. Otherwise it addresses a manifest that no reader
/// decodes, or a different manifest.
#[derive(Debug)]
pub struct ChunkedIdFold {
    fold: BmtFold,
}

impl ChunkedIdFold {
    /// Start a fold for a manifest with these header fields. The metadata
    /// leaf takes position 0.
    #[must_use]
    pub fn new(total_size: u64, chunk_size: u32) -> Self {
        let mut fold = BmtFold::new();
        fold.pending[0] = Some(position_leaf(
            0,
            &chunked_meta_leaf_raw(total_size, chunk_size),
        ));
        fold.count = 1;
        Self { fold }
    }

    /// Append the next chunk id.
    ///
    /// # Errors
    /// [`MerkleError::TooManyLeaves`] once the fold holds `u32::MAX`
    /// leaves.
    pub fn push(&mut self, chunk: &Hash) -> Result<(), MerkleError> {
        self.fold.push(chunk)
    }

    /// Append the chunk ids in `ids`, a run of whole 32-byte ids as they
    /// sit in a manifest's encoding, in order. A caller can pass a
    /// manifest's id bytes in slices of any whole-id length.
    ///
    /// # Errors
    /// [`MerkleError::PartialChunkId`] if `ids` is not a whole number of
    /// ids, before any id is pushed, and [`MerkleError::TooManyLeaves`]
    /// once the fold holds `u32::MAX` leaves.
    pub fn push_ids(&mut self, ids: &[u8]) -> Result<(), MerkleError> {
        let (ids, rest) = ids.as_chunks::<HASH_LEN>();
        if !rest.is_empty() {
            return Err(MerkleError::PartialChunkId);
        }
        for id in ids {
            self.fold.push(id)?;
        }
        Ok(())
    }

    /// The bare (pre-wrap) BMT root, as [`chunked_inner_root`] returns it.
    #[must_use]
    pub fn inner_root(&self) -> Hash {
        self.fold.root()
    }

    /// The object id, as [`compute_chunked_id`] returns it.
    #[must_use]
    pub fn id(&self) -> Hash {
        wrap_id(ObjectKind::ChunkedBlob, &self.fold.root())
    }
}

/// Fold `leaves` into a finalized root. `leaves` comes from an object
/// whose decode caps its count far below `u32::MAX`.
fn fold_root(leaves: impl IntoIterator<Item = Hash>) -> Hash {
    let mut fold = BmtFold::new();
    for leaf in leaves {
        fold.push(&leaf)
            .expect("merkle leaf count fits u32 (objects are decode-capped)");
    }
    fold.root()
}

/// Returns the sorted, deduplicated `(level, index)` positions of siblings
/// required to prove inclusion of leaves at the given `positions`, which
/// must be strictly ascending and below `leaf_count`. The error names the
/// first position, in input order, that is out of range, repeats the one
/// before it, or precedes it. A
/// sibling is omitted when it would be the node's own duplicate (an odd
/// trailing node) or is already covered by another proven position —
/// verifiers reconstruct `H(computed, computed)` / skip re-deriving it
/// without consuming a proof entry. The selection equals the one in
/// `commonware_storage::bmt`.
fn siblings_required_for_multi_proof(
    leaf_count: u32,
    positions: impl IntoIterator<Item = u32>,
) -> Result<BTreeSet<(usize, usize)>, MerkleError> {
    let mut current = BTreeSet::new();
    let mut previous = None;
    for pos in positions {
        if pos >= leaf_count {
            return Err(MerkleError::PositionOutOfRange(pos));
        }
        match previous {
            Some(last) if pos == last => return Err(MerkleError::DuplicatePosition(pos)),
            Some(last) if pos < last => return Err(MerkleError::UnsortedPosition(pos)),
            _ => previous = Some(pos),
        }
        current.insert(pos as usize);
    }
    if current.is_empty() {
        return Err(MerkleError::NoPositions);
    }

    let mut sibling_positions = BTreeSet::new();
    let levels_count = levels_in_tree(leaf_count);
    let mut level_size = leaf_count as usize;
    for level in 0..levels_count.saturating_sub(1) {
        for &index in &current {
            let sibling_index = if index.is_multiple_of(2) {
                if index + 1 < level_size {
                    index + 1
                } else {
                    index
                }
            } else {
                index - 1
            };
            if sibling_index != index && !current.contains(&sibling_index) {
                sibling_positions.insert((level, sibling_index));
            }
        }
        current = current.iter().map(|idx| idx / 2).collect();
        level_size = level_size.div_ceil(2);
    }
    Ok(sibling_positions)
}

/// Returns the sorted, deduplicated `(level, index)` positions of siblings
/// required to prove inclusion of a contiguous range of leaves from
/// `start` to `end` (inclusive). The selection equals the one in
/// `commonware_storage::bmt`.
fn siblings_required_for_range_proof(
    leaf_count: u32,
    start: u32,
    end: u32,
) -> Result<BTreeSet<(usize, usize)>, MerkleError> {
    if leaf_count == 0 {
        return Err(MerkleError::NoPositions);
    }
    if start > end {
        return Err(MerkleError::InvalidRange { start, end });
    }
    if start >= leaf_count {
        return Err(MerkleError::PositionOutOfRange(start));
    }
    if end >= leaf_count {
        return Err(MerkleError::PositionOutOfRange(end));
    }

    let mut sibling_positions = BTreeSet::new();
    let levels_count = levels_in_tree(leaf_count);
    let mut level_start = start as usize;
    let mut level_end = end as usize;
    let mut level_size = leaf_count as usize;
    for level in 0..levels_count.saturating_sub(1) {
        if !level_start.is_multiple_of(2) {
            sibling_positions.insert((level, level_start - 1));
        }
        if level_end.is_multiple_of(2) {
            let right = level_end + 1;
            if right < level_size {
                sibling_positions.insert((level, right));
            }
        }
        level_start /= 2;
        level_end /= 2;
        level_size = level_size.div_ceil(2);
    }
    Ok(sibling_positions)
}

/// The sibling digests named by `required`, in the order the set defines
/// (level-major, then index ascending), from one pass over `leaves`.
///
/// `leaves` holds the raw leaves of a tree of `leaf_count` leaves, in
/// order. The pass pairs nodes as [`BmtFold`] does: a pair completes
/// upward at once and an odd trailing node pairs with itself. Memory is
/// one pending node and one node count per level plus the recorded
/// siblings, so a proof never holds a level.
///
/// `required` comes from [`siblings_required_for_multi_proof`] or
/// [`siblings_required_for_range_proof`] for the same `leaf_count`. Every
/// entry lies below the top level and below its level's node count, so the
/// pass produces each one.
fn stream_proof(
    leaf_count: u32,
    leaves: impl Iterator<Item = Hash>,
    required: &BTreeSet<(usize, usize)>,
) -> Vec<Hash> {
    let mut found: BTreeMap<(usize, usize), Hash> = BTreeMap::new();
    let mut pending = [None::<Hash>; MAX_LEVELS + 1];
    let mut produced = [0usize; MAX_LEVELS + 1];
    // A node made at `level` takes the next index there and is kept when
    // the proof needs it.
    let mut emit = |level: usize, node: &Hash| {
        let index = produced[level];
        produced[level] += 1;
        if required.contains(&(level, index)) {
            found.insert((level, index), *node);
        }
    };

    let mut count = 0u32;
    for leaf in leaves {
        let mut node = position_leaf(count, &leaf);
        count += 1;
        let mut level = 0;
        emit(level, &node);
        while let Some(left) = pending[level].take() {
            node = h2(&left, &node);
            level += 1;
            emit(level, &node);
        }
        pending[level] = Some(node);
    }
    debug_assert_eq!(
        count, leaf_count,
        "the leaf iterator matches the leaf count"
    );

    // Close the unpaired nodes bottom-up, as `BmtFold::root` does. The node
    // carried out of a level is the last node of the level above.
    let top = levels_in_tree(leaf_count) - 1;
    let mut carry: Option<Hash> = None;
    for (level, unpaired) in pending.iter().enumerate().take(top) {
        carry = match (*unpaired, carry) {
            (Some(left), Some(right)) => Some(h2(&left, &right)),
            (Some(last), None) | (None, Some(last)) => Some(h2(&last, &last)),
            (None, None) => None,
        };
        if let Some(node) = &carry {
            emit(level + 1, node);
        }
    }

    required
        .iter()
        .map(|key| {
            found
                .remove(key)
                .expect("the pass makes every sibling that the tree shape requires")
        })
        .collect()
}

/// A proof for the leaves at `positions`, built in one pass over `leaves`.
///
/// Positions must be strictly ascending: a repeated position is
/// [`MerkleError::DuplicatePosition`] and a lower one is
/// [`MerkleError::UnsortedPosition`]. `leaves` is not read when the
/// positions are refused.
fn multi_proof_streaming(
    leaf_count: u32,
    leaves: impl Iterator<Item = Hash>,
    positions: impl IntoIterator<Item = u32>,
) -> Result<Proof, MerkleError> {
    let mut positions = positions.into_iter().peekable();
    let first = *positions.peek().ok_or(MerkleError::NoPositions)?;
    if leaf_count == 0 {
        return Err(MerkleError::PositionOutOfRange(first));
    }
    let required = siblings_required_for_multi_proof(leaf_count, positions)?;
    Ok(Proof {
        leaf_count,
        siblings: stream_proof(leaf_count, leaves, &required),
    })
}

/// A range proof for the leaves `start..=end`, built in one pass over
/// `leaves`.
fn range_proof_streaming(
    leaf_count: u32,
    leaves: impl Iterator<Item = Hash>,
    start: u32,
    end: u32,
) -> Result<Proof, MerkleError> {
    // Intentional divergence from `commonware_storage::bmt`, whose
    // `range_proof(0, 0)` on an empty tree returns `Proof::default()`:
    // SPEC-MERKLE-OBJECTS §5.4 requires a builder to refuse every
    // position of the empty `Tree`, including the range `0..=0`.
    // `tests::proofs_match_commonware` only draws `n >= 1`, so the
    // cross-check never compares this case.
    if leaf_count == 0 {
        return Err(MerkleError::PositionOutOfRange(start));
    }
    let required = siblings_required_for_range_proof(leaf_count, start, end)?;
    Ok(Proof {
        leaf_count,
        siblings: stream_proof(leaf_count, leaves, &required),
    })
}

#[cfg(test)]
impl BmtTree {
    /// Generates a proof for the leaf at `position`. A single-element
    /// multi-proof.
    fn proof(&self, position: u32) -> Result<Proof, MerkleError> {
        self.multi_proof(core::iter::once(position))
    }

    /// Generates a range proof for the contiguous leaves `start..=end`.
    fn range_proof(&self, start: u32, end: u32) -> Result<Proof, MerkleError> {
        // Intentional divergence from `commonware_storage::bmt`, whose
        // `range_proof(0, 0)` on an empty tree returns `Proof::default()`:
        // SPEC-MERKLE-OBJECTS §5.4 requires a builder to refuse every
        // position of the empty `Tree`, including the range `0..=0`.
        // `tests::proofs_match_commonware` only draws `n >= 1`, so the
        // cross-check never compares this case.
        if self.empty {
            return Err(MerkleError::PositionOutOfRange(start));
        }
        if start > end {
            return Err(MerkleError::InvalidRange { start, end });
        }
        let leaf_count = self.leaf_count;
        if start >= leaf_count {
            return Err(MerkleError::PositionOutOfRange(start));
        }
        if end >= leaf_count {
            return Err(MerkleError::PositionOutOfRange(end));
        }
        let sibling_positions = siblings_required_for_range_proof(leaf_count, start, end)?;
        let siblings = sibling_positions
            .iter()
            .map(|&(level, index)| self.levels[level][index])
            .collect();
        Ok(Proof {
            leaf_count,
            siblings,
        })
    }

    /// Generates a proof for the non-contiguous leaves at `positions`.
    /// Positions must be strictly ascending: a repeated position is
    /// [`MerkleError::DuplicatePosition`] and a lower one is
    /// [`MerkleError::UnsortedPosition`].
    fn multi_proof(&self, positions: impl IntoIterator<Item = u32>) -> Result<Proof, MerkleError> {
        let mut positions = positions.into_iter().peekable();
        let first = *positions.peek().ok_or(MerkleError::NoPositions)?;
        if self.empty {
            return Err(MerkleError::PositionOutOfRange(first));
        }
        let leaf_count = self.leaf_count;
        let sibling_positions = siblings_required_for_multi_proof(leaf_count, positions)?;
        let siblings = sibling_positions
            .iter()
            .map(|&(level, index)| self.levels[level][index])
            .collect();
        Ok(Proof {
            leaf_count,
            siblings,
        })
    }
}

// ---------------------------------------------------------------------------
// Proof: wire format + verification
// ---------------------------------------------------------------------------

/// A BMT inclusion proof for one or more leaves: the tree's leaf count
/// plus the deduplicated sibling digests needed to reconstruct the root,
/// ordered level-major (bottom-up) then index-ascending.
///
/// Bytes are `u32 BE leaf_count ‖ LEB128-varint(n) ‖ n × 32-byte digest` —
/// byte-identical to `commonware_storage::bmt::Proof<D>` at the pinned
/// `2026.10.0` train (`tests::proofs_match_commonware` pins this; see also
/// `rust/tests/golden/proofs/`). A commonware-based verifier can decode
/// these bytes with the upstream type directly.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Proof {
    /// The number of leaves in the tree. Incorporated into the finalized
    /// root, so a mismatched `leaf_count` fails verification rather than
    /// being silently accepted (malleability guard).
    pub leaf_count: u32,
    /// The deduplicated sibling digests, level-major bottom-up then
    /// index-ascending, with self-duplicate and already-proven siblings
    /// omitted (see `docs/specs/SPEC-MERKLE-OBJECTS.md` §5.3).
    pub siblings: Vec<Hash>,
}

impl Write for Proof {
    fn write(&self, writer: &mut impl BufMut) {
        self.leaf_count.write(writer);
        self.siblings.write(writer);
    }
}

impl EncodeSize for Proof {
    fn encode_size(&self) -> usize {
        self.leaf_count.encode_size() + self.siblings.encode_size()
    }
}

impl Read for Proof {
    /// The maximum number of items being proven. The upper bound on
    /// sibling hashes is derived as `max_items * MAX_LEVELS`, bounding
    /// allocation before any hashing happens.
    type Cfg = usize;

    fn read_cfg(reader: &mut impl Buf, max_items: &Self::Cfg) -> Result<Self, CodecError> {
        let leaf_count = u32::read(reader)?;
        let max_siblings = max_items.saturating_mul(MAX_LEVELS);
        let siblings = Vec::<Hash>::read_range(reader, ..=max_siblings)?;
        Ok(Self {
            leaf_count,
            siblings,
        })
    }
}

impl Proof {
    /// Encode to the commonware-identical wire bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encode_size());
        self.write(&mut out);
        out
    }

    /// Decode from the commonware-identical wire bytes, bounding the
    /// sibling count to `max_items * MAX_LEVELS`. `max_items` should be the
    /// number of positions the caller is about to verify (1 for a
    /// single-leaf proof, the range length for a range proof, the position
    /// count for a multi-proof). Rejects trailing bytes.
    ///
    /// # Errors
    ///
    /// [`MerkleError::MalformedProof`] on a truncated buffer, an
    /// over-`max_items` sibling count, or trailing bytes.
    pub fn decode(bytes: &[u8], max_items: usize) -> Result<Self, MerkleError> {
        let mut buf = Copying(bytes);
        let proof = Self::read_cfg(&mut buf, &max_items)?;
        if buf.has_remaining() {
            return Err(MerkleError::MalformedProof);
        }
        Ok(proof)
    }

    /// Reconstructs the tree's inner (pre-wrap) root implied by this proof
    /// for `leaf` at `position`, without comparing it to anything. The
    /// shared building block for both the inner-root-comparing
    /// (commonware-parity) verifiers below and the public id-based
    /// verifiers. `pub(crate)` so `verify` can compare the fold to a
    /// bundle-declared inner root without a second pass.
    pub(crate) fn reconstruct_element_root(
        &self,
        leaf: &Hash,
        mut position: u32,
    ) -> Result<Hash, MerkleError> {
        if position >= self.leaf_count {
            return Err(MerkleError::PositionOutOfRange(position));
        }
        let mut computed = position_leaf(position, leaf);
        let mut level_size = self.leaf_count as usize;
        let mut sibling_iter = self.siblings.iter();

        while level_size > 1 {
            let is_last_odd = position.is_multiple_of(2) && position as usize + 1 >= level_size;
            let (left, right) = if is_last_odd {
                (computed, computed)
            } else if position.is_multiple_of(2) {
                let sib = *sibling_iter.next().ok_or(MerkleError::UnalignedProof)?;
                (computed, sib)
            } else {
                let sib = *sibling_iter.next().ok_or(MerkleError::UnalignedProof)?;
                (sib, computed)
            };
            computed = h2(&left, &right);
            position /= 2;
            level_size = level_size.div_ceil(2);
        }

        if sibling_iter.next().is_some() {
            return Err(MerkleError::UnalignedProof);
        }
        Ok(h2(&self.leaf_count.to_be_bytes(), &computed))
    }

    /// Reconstructs the tree's inner (pre-wrap) root implied by this proof
    /// for the non-contiguous `elements` (leaf, position pairs). Positions
    /// must be strictly ascending, in input order: a repeated position is
    /// [`MerkleError::DuplicatePosition`] and a lower one is
    /// [`MerkleError::UnsortedPosition`].
    pub(crate) fn reconstruct_multi_root(
        &self,
        elements: &[(Hash, u32)],
    ) -> Result<Hash, MerkleError> {
        // A proof over zero positions is rejected unconditionally, even
        // when `leaf_count == 0` and `siblings` is empty (upstream's
        // `Default` proof, which would otherwise trivially "reconstruct"
        // the empty tree's root). Accepting it here would let a caller
        // verify zero proven entries/chunks against any id whose inner
        // root happens to equal the empty tree's — most notably the
        // real `TREE_EMPTY_ID` — without ever having proven anything.
        // Builders already refuse to construct such a proof
        // (`BmtTree::multi_proof`'s `NoPositions` on an empty position
        // iterator); this is the matching verification-side rule (see
        // `tests::verify_rejects_empty_element_set` and
        // SPEC-MERKLE-OBJECTS §5.4).
        if elements.is_empty() {
            return Err(MerkleError::NoPositions);
        }
        // Check every position before any leaf is hashed. The error names
        // the first position, in input order, that is out of range,
        // repeats the one before it, or precedes it.
        let mut previous = None;
        for (_, position) in elements {
            if *position >= self.leaf_count {
                return Err(MerkleError::PositionOutOfRange(*position));
            }
            match previous {
                Some(last) if *position == last => {
                    return Err(MerkleError::DuplicatePosition(*position));
                }
                Some(last) if *position < last => {
                    return Err(MerkleError::UnsortedPosition(*position));
                }
                _ => previous = Some(*position),
            }
        }

        let hashed: Vec<(u32, Hash)> = elements
            .iter()
            .map(|(leaf, pos)| (*pos, position_leaf(*pos, leaf)))
            .collect();

        let levels = levels_in_tree(self.leaf_count);
        let mut level_size = self.leaf_count;
        let mut sibling_iter = self.siblings.iter();
        let mut current = hashed;

        for _ in 0..levels.saturating_sub(1) {
            let mut next_level: Vec<(u32, Hash)> = Vec::with_capacity(current.len().div_ceil(2));
            let mut idx = 0;
            while idx < current.len() {
                let (pos, digest) = current[idx];
                let parent_pos = pos / 2;
                let (left, right) = if pos.is_multiple_of(2) {
                    let left = digest;
                    let right = if idx + 1 < current.len() && current[idx + 1].0 == pos + 1 {
                        idx += 1;
                        current[idx].1
                    } else if pos + 1 >= level_size {
                        left
                    } else {
                        *sibling_iter.next().ok_or(MerkleError::UnalignedProof)?
                    };
                    (left, right)
                } else {
                    // The left child was missing from `current`, so it must
                    // be a sibling.
                    let right = digest;
                    let left = *sibling_iter.next().ok_or(MerkleError::UnalignedProof)?;
                    (left, right)
                };
                next_level.push((parent_pos, h2(&left, &right)));
                idx += 1;
            }
            current = next_level;
            level_size = level_size.div_ceil(2);
        }

        if sibling_iter.next().is_some() {
            return Err(MerkleError::UnalignedProof);
        }
        if current.len() != 1 {
            return Err(MerkleError::UnalignedProof);
        }
        Ok(h2(&self.leaf_count.to_be_bytes(), &current[0].1))
    }

    /// Reconstructs the inner root for a contiguous range of `leaves`
    /// starting at `position`. A convenience wrapper over
    /// [`Self::reconstruct_multi_root`].
    fn reconstruct_range_root(&self, position: u32, leaves: &[Hash]) -> Result<Hash, MerkleError> {
        if leaves.is_empty() && position != 0 {
            return Err(MerkleError::PositionOutOfRange(position));
        }
        if !leaves.is_empty() {
            let leaves_len = u32_of(leaves.len());
            let end = position
                .checked_add(leaves_len - 1)
                .ok_or(MerkleError::PositionOutOfRange(position))?;
            if end >= self.leaf_count {
                return Err(MerkleError::PositionOutOfRange(end));
            }
        }
        let elements: Vec<(Hash, u32)> = leaves
            .iter()
            .enumerate()
            .map(|(i, l)| (*l, position + u32_of(i)))
            .collect();
        self.reconstruct_multi_root(&elements)
    }

    /// Verify against the bare (pre-wrap) inner root — matches
    /// `commonware_storage::bmt::Proof::verify_element_inclusion` exactly.
    /// `cfg(test)`: kept only for the commonware cross-check test
    /// (`tests::proofs_match_commonware`) and `tests::verify_chunk_rejects_meta_leaf`,
    /// which need to show the *bare* BMT proof accepts a position/leaf the
    /// id-based verifier must still reject. Every real caller MUST use the
    /// id-based [`verify_tree_entry`] / [`verify_chunk`], which close the
    /// inner-root-vs-id confusion footgun (SPEC-DISCLOSURE) — so this
    /// is deliberately not reachable outside tests, not just `pub(crate)`.
    #[cfg(test)]
    pub(crate) fn verify_element_inclusion(
        &self,
        leaf: &Hash,
        position: u32,
        inner_root: &Hash,
    ) -> Result<(), MerkleError> {
        let got = self.reconstruct_element_root(leaf, position)?;
        if &got == inner_root {
            Ok(())
        } else {
            Err(MerkleError::VerificationFailed)
        }
    }

    /// Verify a multi-leaf proof against the bare inner root. `cfg(test)`
    /// for the same reason as [`Self::verify_element_inclusion`].
    #[cfg(test)]
    pub(crate) fn verify_multi_inclusion(
        &self,
        elements: &[(Hash, u32)],
        inner_root: &Hash,
    ) -> Result<(), MerkleError> {
        let got = self.reconstruct_multi_root(elements)?;
        if &got == inner_root {
            Ok(())
        } else {
            Err(MerkleError::VerificationFailed)
        }
    }

    /// Verify a range proof against the bare inner root. `cfg(test)` for
    /// the same reason as [`Self::verify_element_inclusion`].
    #[cfg(test)]
    pub(crate) fn verify_range_inclusion(
        &self,
        position: u32,
        leaves: &[Hash],
        inner_root: &Hash,
    ) -> Result<(), MerkleError> {
        let got = self.reconstruct_range_root(position, leaves)?;
        if &got == inner_root {
            Ok(())
        } else {
            Err(MerkleError::VerificationFailed)
        }
    }
}

// ---------------------------------------------------------------------------
// Leaf digests
// ---------------------------------------------------------------------------

/// The position-0 metadata leaf digest for a `ChunkedBlob`'s
/// `total_size`/`chunk_size`, without requiring a materialized
/// [`ChunkedBlob`] value. Shared by [`chunked_meta_leaf`] (which has one)
/// and [`verify_chunk_with_meta_leaf`] (which — by design — never does;
/// see that function's docs).
pub(crate) fn chunked_meta_leaf_raw(total_size: u64, chunk_size: u32) -> Hash {
    let mut body = [0u8; 12];
    body[..8].copy_from_slice(&total_size.to_le_bytes());
    body[8..].copy_from_slice(&chunk_size.to_le_bytes());
    domain_digest(CBLOB_META_DOMAIN, &body)
}

/// The position-0 metadata leaf for a `ChunkedBlob`, binding its
/// `total_size` and `chunk_size` (neither is derivable from the chunk
/// list, so without this they could be forged — a second-preimage hole).
fn chunked_meta_leaf(cb: &ChunkedBlob) -> Hash {
    chunked_meta_leaf_raw(cb.total_size, cb.chunk_size)
}

/// The leaf digest for one `Tree` entry. The `name_len` u32-LE prefix is
/// the anti-ambiguity guard so `("ab", m, h)` and `("a", m, "b"‖…)` cannot
/// alias. Feeding this triple (not the raw `object_hash`) means a Tree
/// inclusion proof attests the full `(name, mode, object_hash)`.
pub(crate) fn tree_entry_leaf(e: &TreeEntry) -> Hash {
    let mut body = Vec::with_capacity(4 + e.name.len() + 1 + HASH_LEN);
    body.extend_from_slice(&u32_of(e.name.len()).to_le_bytes());
    body.extend_from_slice(&e.name);
    body.push(e.mode as u8);
    body.extend_from_slice(&e.object_hash);
    domain_digest(TREE_ENTRY_DOMAIN, &body)
}

/// The raw leaves of a `ChunkedBlob`: the metadata leaf, then the chunks.
fn chunked_leaves(cb: &ChunkedBlob) -> impl Iterator<Item = Hash> + '_ {
    core::iter::once(chunked_meta_leaf(cb)).chain(cb.chunks.iter().copied())
}

/// The leaf count of a `ChunkedBlob`'s tree: the metadata leaf plus the chunks.
fn chunked_leaf_count(cb: &ChunkedBlob) -> u32 {
    u32_of(1 + cb.chunks.len())
}

/// The raw leaves of a `Tree`: one per entry.
fn tree_leaves(tree: &Tree) -> impl Iterator<Item = Hash> + '_ {
    tree.entries.iter().map(tree_entry_leaf)
}

// ---------------------------------------------------------------------------
// Inner roots + identity
// ---------------------------------------------------------------------------

/// Bare (pre-wrap) BMT root over a `ChunkedBlob`'s leaves (`[meta] ++
/// chunks`). A commonware-based verifier's `verify_*_inclusion` checks
/// against this; kit callers use the id-based [`verify_chunk`] instead.
///
/// # Panics
/// If `cb` has `u32::MAX` chunks or more. A decoded manifest has at most
/// [`crate::serialize::MAX_CHUNKS`].
#[must_use]
pub fn chunked_inner_root(cb: &ChunkedBlob) -> Hash {
    let mut fold = ChunkedIdFold::new(cb.total_size, cb.chunk_size);
    for chunk in &cb.chunks {
        fold.push(chunk)
            .expect("merkle leaf count fits u32 (objects are decode-capped)");
    }
    fold.inner_root()
}

/// Bare (pre-wrap) BMT root over a `Tree`'s entry leaves. A
/// commonware-based verifier's `verify_*_inclusion` checks against this;
/// kit callers use the id-based [`verify_tree_entry`] instead.
#[must_use]
pub fn tree_inner_root(tree: &Tree) -> Hash {
    fold_root(tree.entries.iter().map(tree_entry_leaf))
}

/// The content-address (object id) of a `ChunkedBlob`.
#[must_use]
pub fn compute_chunked_id(cb: &ChunkedBlob) -> Hash {
    wrap_id(ObjectKind::ChunkedBlob, &chunked_inner_root(cb))
}

/// The content-address (object id) of a `Tree`.
#[must_use]
pub fn compute_tree_id(tree: &Tree) -> Hash {
    wrap_id(ObjectKind::Tree, &tree_inner_root(tree))
}

/// The id of the empty `Tree` (`entries = []`) — a real, common object.
/// Pinned from a test run (see `empty_tree_id_matches_constant`); the
/// empty BMT root is `H(leaf_count ‖ H(""))`, NOT `H(0 ‖ 0)`.
pub const TREE_EMPTY_ID: Hash = [
    0xb2, 0x91, 0x17, 0xce, 0x9b, 0x3d, 0x66, 0xba, 0x98, 0xcd, 0x0a, 0x57, 0x14, 0x54, 0x00, 0xf0,
    0xbf, 0x6f, 0xff, 0x8b, 0x5c, 0x27, 0xc4, 0x55, 0x2d, 0x80, 0xa3, 0x84, 0x46, 0xf2, 0x7e, 0xf7,
];

// ---------------------------------------------------------------------------
// Position lookup
// ---------------------------------------------------------------------------

/// BMT position of `chunk_hash` within `cb`, or `None` if absent. The
/// returned position is the chunk index **+ 1** (the metadata leaf
/// occupies position 0).
#[must_use]
pub fn chunk_position(cb: &ChunkedBlob, chunk_hash: &Hash) -> Option<u32> {
    cb.chunks
        .iter()
        .position(|c| c == chunk_hash)
        .map(|i| u32_of(i + 1))
}

/// BMT position (= entry index) of the entry named `name` within `tree`,
/// or `None` if absent.
#[must_use]
pub fn tree_entry_position(tree: &Tree, name: &[u8]) -> Option<u32> {
    tree.entries.iter().position(|e| e.name == name).map(u32_of)
}

/// Wire size of a proof, calculated from tree shape without hashing leaves.
pub(crate) fn proof_encoded_size(
    leaf_count: u32,
    positions: impl IntoIterator<Item = u32>,
) -> Result<usize, MerkleError> {
    let siblings = siblings_required_for_multi_proof(leaf_count, positions)?.len();
    let mut count = siblings;
    let mut prefix = 1;
    while count >= 128 {
        prefix += 1;
        count >>= 7;
    }
    Ok(4 + prefix + siblings * 32)
}

// ---------------------------------------------------------------------------
// Proof construction
// ---------------------------------------------------------------------------

/// Build an inclusion proof that the chunk at `position` (= chunk index +
/// 1, per [`chunk_position`]) belongs to `cb`.
pub fn build_chunk_proof(cb: &ChunkedBlob, position: u32) -> Result<Proof, MerkleError> {
    multi_proof_streaming(
        chunked_leaf_count(cb),
        chunked_leaves(cb),
        core::iter::once(position),
    )
}

/// Build a range proof that the chunks at `start..=end` belong to `cb`.
pub fn build_chunks_range_proof(
    cb: &ChunkedBlob,
    start: u32,
    end: u32,
) -> Result<Proof, MerkleError> {
    range_proof_streaming(chunked_leaf_count(cb), chunked_leaves(cb), start, end)
}

/// Build a multi-leaf proof that the chunks at `positions` belong to `cb`.
/// The positions must be strictly ascending.
pub fn build_chunks_multi_proof(
    cb: &ChunkedBlob,
    positions: impl IntoIterator<Item = u32>,
) -> Result<Proof, MerkleError> {
    multi_proof_streaming(chunked_leaf_count(cb), chunked_leaves(cb), positions)
}

/// Build an inclusion proof that the entry at `position` (= entry index)
/// belongs to `tree`.
pub fn build_tree_entry_proof(tree: &Tree, position: u32) -> Result<Proof, MerkleError> {
    multi_proof_streaming(
        u32_of(tree.entries.len()),
        tree_leaves(tree),
        core::iter::once(position),
    )
}

/// Build a range proof that the entries at `start..=end` belong to `tree`.
pub fn build_tree_entries_range_proof(
    tree: &Tree,
    start: u32,
    end: u32,
) -> Result<Proof, MerkleError> {
    range_proof_streaming(u32_of(tree.entries.len()), tree_leaves(tree), start, end)
}

/// Build a multi-leaf proof that the entries at `positions` belong to
/// `tree`. The positions must be strictly ascending.
pub fn build_tree_entries_multi_proof(
    tree: &Tree,
    positions: impl IntoIterator<Item = u32>,
) -> Result<Proof, MerkleError> {
    multi_proof_streaming(u32_of(tree.entries.len()), tree_leaves(tree), positions)
}

// ---------------------------------------------------------------------------
// Proof verification — against the object id
// ---------------------------------------------------------------------------

/// Verify that `entry` at `position` belongs to the `Tree` whose id is
/// `tree_id`.
pub fn verify_tree_entry(
    tree_id: &Hash,
    entry: &TreeEntry,
    position: u32,
    proof: &Proof,
) -> Result<(), MerkleError> {
    let root = proof.reconstruct_element_root(&tree_entry_leaf(entry), position)?;
    check_wrapped(ObjectKind::Tree, &root, tree_id)
}

/// Verify that `entries` (in tree order, starting at `start`) belong to
/// the `Tree` whose id is `tree_id`.
pub fn verify_tree_entries_range(
    tree_id: &Hash,
    start: u32,
    entries: &[TreeEntry],
    proof: &Proof,
) -> Result<(), MerkleError> {
    let leaves: Vec<Hash> = entries.iter().map(tree_entry_leaf).collect();
    let root = proof.reconstruct_range_root(start, &leaves)?;
    check_wrapped(ObjectKind::Tree, &root, tree_id)
}

/// Verify that `entries` (each with its own position) belong to the `Tree`
/// whose id is `tree_id`. The positions must be strictly ascending.
pub fn verify_tree_entries_multi(
    tree_id: &Hash,
    entries: &[(TreeEntry, u32)],
    proof: &Proof,
) -> Result<(), MerkleError> {
    let elements: Vec<(Hash, u32)> = entries
        .iter()
        .map(|(e, pos)| (tree_entry_leaf(e), *pos))
        .collect();
    let root = proof.reconstruct_multi_root(&elements)?;
    check_wrapped(ObjectKind::Tree, &root, tree_id)
}

/// Verify that the chunk `chunk_hash` at `position` belongs to the
/// `ChunkedBlob` whose id is `chunked_id`. Rejects `position == 0`: that
/// position is the metadata leaf, not a chunk, so a valid BMT proof of it
/// must never be accepted as a chunk proof (see `verify_chunk_rejects_meta_leaf`).
pub fn verify_chunk(
    chunked_id: &Hash,
    chunk_hash: &Hash,
    position: u32,
    proof: &Proof,
) -> Result<(), MerkleError> {
    if position == 0 {
        return Err(MerkleError::PositionOutOfRange(0));
    }
    let root = proof.reconstruct_element_root(chunk_hash, position)?;
    check_wrapped(ObjectKind::ChunkedBlob, &root, chunked_id)
}

/// Verify that `chunk_hashes` (in chunk order, starting at `start`) belong
/// to the `ChunkedBlob` whose id is `chunked_id`. Rejects a range whose
/// `start` is 0 (the metadata leaf).
pub fn verify_chunks_range(
    chunked_id: &Hash,
    start: u32,
    chunk_hashes: &[Hash],
    proof: &Proof,
) -> Result<(), MerkleError> {
    if start == 0 {
        return Err(MerkleError::PositionOutOfRange(0));
    }
    let root = proof.reconstruct_range_root(start, chunk_hashes)?;
    check_wrapped(ObjectKind::ChunkedBlob, &root, chunked_id)
}

/// Verify that `chunks` (each with its own position) belong to the
/// `ChunkedBlob` whose id is `chunked_id`. The positions must be strictly
/// ascending. Rejects any position `== 0` (the metadata leaf).
pub fn verify_chunks_multi(
    chunked_id: &Hash,
    chunks: &[(Hash, u32)],
    proof: &Proof,
) -> Result<(), MerkleError> {
    if chunks.iter().any(|(_, pos)| *pos == 0) {
        return Err(MerkleError::PositionOutOfRange(0));
    }
    let elements: Vec<(Hash, u32)> = chunks.to_vec();
    let root = proof.reconstruct_multi_root(&elements)?;
    check_wrapped(ObjectKind::ChunkedBlob, &root, chunked_id)
}

/// Verify, in one multi-proof, that (a) a `ChunkedBlob`'s metadata leaf —
/// computed HERE from the caller's *claimed* `total_size`/`chunk_size`,
/// never accepted as an externally supplied leaf digest — and (b) the
/// chunk `chunk_hash` at `chunk_position` (= chunk index + 1) both belong
/// to the `ChunkedBlob` whose id is `chunked_id`.
///
/// This is the one sanctioned way a proof over position 0 is ever
/// accepted from outside this module: the verifier derives the meta leaf
/// itself from the very values it is simultaneously authenticating,
/// rather than trusting a caller-supplied leaf digest at that position.
/// [`verify_chunk`]'s "reject a caller-supplied position 0" rule is
/// unaffected — that guards a different, single-leaf proof shape; this
/// one always proves exactly `{0, chunk_position}` together. Used by
/// `crate::verify` (SPEC-DISCLOSURE) to
/// authenticate a disclosed chunk's `total_size`/`chunk_size`
/// announcement alongside its content id, in a single proof.
pub(crate) fn verify_chunk_with_meta_leaf(
    chunked_id: &Hash,
    total_size: u64,
    chunk_size: u32,
    chunk_hash: &Hash,
    chunk_position: u32,
    proof: &Proof,
) -> Result<(), MerkleError> {
    if chunk_position == 0 {
        return Err(MerkleError::PositionOutOfRange(0));
    }
    let meta_leaf = chunked_meta_leaf_raw(total_size, chunk_size);
    let elements = [(meta_leaf, 0u32), (*chunk_hash, chunk_position)];
    let root = proof.reconstruct_multi_root(&elements)?;
    check_wrapped(ObjectKind::ChunkedBlob, &root, chunked_id)
}

/// Wrap `root` with `kind`'s type domain and compare to `expected_id`.
fn check_wrapped(kind: ObjectKind, root: &Hash, expected_id: &Hash) -> Result<(), MerkleError> {
    if &wrap_id(kind, root) == expected_id {
        Ok(())
    } else {
        Err(MerkleError::VerificationFailed)
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::EntryMode;

    fn cb(total: u64, chunk_size: u32, chunks: &[u8]) -> ChunkedBlob {
        ChunkedBlob {
            total_size: total,
            chunk_size,
            chunks: chunks.iter().map(|b| [*b; 32]).collect(),
        }
    }

    fn entry(name: &[u8], mode: EntryMode, h: u8) -> TreeEntry {
        TreeEntry {
            name: name.to_vec(),
            mode,
            object_hash: [h; 32],
        }
    }

    fn tree(entries: Vec<TreeEntry>) -> Tree {
        Tree { entries }
    }

    #[test]
    fn id_changes_when_a_leaf_changes() {
        let a = cb(100, 0, &[1, 2, 3]);
        let b = cb(100, 0, &[1, 2, 4]);
        assert_ne!(compute_chunked_id(&a), compute_chunked_id(&b));
    }

    #[test]
    fn id_changes_when_leaf_count_changes() {
        let a = cb(100, 0, &[1, 2, 3]);
        let b = cb(100, 0, &[1, 2, 3, 3]); // duplicated last — must not collide
        assert_ne!(compute_chunked_id(&a), compute_chunked_id(&b));
    }

    #[test]
    fn chunked_id_changes_when_metadata_changes() {
        let a = cb(100, 0, &[1, 2, 3]);
        let b = cb(101, 0, &[1, 2, 3]);
        let c = cb(100, 64, &[1, 2, 3]);
        assert_ne!(compute_chunked_id(&a), compute_chunked_id(&b));
        assert_ne!(compute_chunked_id(&a), compute_chunked_id(&c));
    }

    #[test]
    fn tree_ordering_matters() {
        let a = tree(vec![
            entry(b"a", EntryMode::Blob, 1),
            entry(b"b", EntryMode::Blob, 2),
        ]);
        let b = tree(vec![
            entry(b"b", EntryMode::Blob, 2),
            entry(b"a", EntryMode::Blob, 1),
        ]);
        assert_ne!(compute_tree_id(&a), compute_tree_id(&b));
    }

    #[test]
    fn empty_tree_id_matches_constant() {
        let got = compute_tree_id(&tree(vec![]));
        assert_eq!(got, TREE_EMPTY_ID, "update TREE_EMPTY_ID to {got:02x?}");
    }

    #[test]
    fn type_binding_no_cross_collisions() {
        let empty_tree = compute_tree_id(&tree(vec![]));
        let empty_cblob = compute_chunked_id(&cb(0, 0, &[]));
        assert_ne!(empty_tree, empty_cblob);

        let t = tree(vec![entry(b"x", EntryMode::Blob, 9)]);
        let c = cb(10, 0, &[9]);
        assert_ne!(compute_tree_id(&t), compute_chunked_id(&c));
    }

    #[test]
    fn id_ne_flat_blake3_of_serialized_bytes() {
        let c = cb(100, 0, &[1, 2, 3]);
        let serialized =
            crate::serialize::serialize(&crate::object::Object::ChunkedBlob(c.clone())).unwrap();
        assert_ne!(compute_chunked_id(&c), crate::hash::hash(&serialized));
    }

    #[test]
    fn chunk_position_offsets_by_one() {
        let c = cb(100, 0, &[7, 8, 9]);
        assert_eq!(chunk_position(&c, &[7; 32]), Some(1));
        assert_eq!(chunk_position(&c, &[9; 32]), Some(3));
        assert_eq!(chunk_position(&c, &[0; 32]), None);
    }

    #[test]
    fn chunk_inclusion_proof_round_trips() {
        let c = cb(100, 0, &[10, 20, 30, 40]);
        let id = compute_chunked_id(&c);
        for (idx, byte) in [(0usize, 10u8), (2, 30), (3, 40)] {
            let pos = chunk_position(&c, &[byte; 32]).unwrap();
            assert_eq!(pos, u32_of(idx) + 1);
            let proof = build_chunk_proof(&c, pos).unwrap();
            verify_chunk(&id, &[byte; 32], pos, &proof).unwrap();
            assert!(verify_chunk(&id, &[0xFF; 32], pos, &proof).is_err());
        }
    }

    #[test]
    fn verify_chunk_rejects_meta_leaf() {
        let c = cb(100, 0, &[10, 20, 30]);
        let id = compute_chunked_id(&c);
        let meta_leaf = chunked_meta_leaf(&c);
        // Position 0 is a *valid* raw BMT proof of the meta leaf...
        let proof = build_chunk_proof(&c, 0).unwrap();
        proof
            .verify_element_inclusion(&meta_leaf, 0, &chunked_inner_root(&c))
            .expect("meta leaf is a valid BMT element at position 0");
        // ...but `verify_chunk` MUST reject it: position 0 is never a chunk.
        assert_eq!(
            verify_chunk(&id, &meta_leaf, 0, &proof),
            Err(MerkleError::PositionOutOfRange(0))
        );
    }

    #[test]
    fn verify_chunk_with_meta_leaf_round_trips_and_rejects_forgery() {
        let c = cb(100, 0, &[10, 20, 30]);
        let id = compute_chunked_id(&c);
        let pos = chunk_position(&c, &[20; 32]).unwrap(); // index 1 -> position 2
        let proof = build_chunks_multi_proof(&c, [0, pos]).unwrap();

        verify_chunk_with_meta_leaf(&id, 100, 0, &[20; 32], pos, &proof).unwrap();

        // Forged total_size must be rejected — the meta leaf the verifier
        // computes no longer folds to the real root.
        assert!(verify_chunk_with_meta_leaf(&id, 101, 0, &[20; 32], pos, &proof).is_err());
        // Forged chunk_size, likewise.
        assert!(verify_chunk_with_meta_leaf(&id, 100, 64, &[20; 32], pos, &proof).is_err());
        // Wrong chunk hash at the right position.
        assert!(verify_chunk_with_meta_leaf(&id, 100, 0, &[0xFF; 32], pos, &proof).is_err());
        // Position 0 is never accepted as `chunk_position`, even though
        // it is a structurally valid multi-proof position.
        assert_eq!(
            verify_chunk_with_meta_leaf(&id, 100, 0, &[10; 32], 0, &proof),
            Err(MerkleError::PositionOutOfRange(0))
        );
    }

    #[test]
    fn tree_inclusion_proof_round_trips() {
        let t = tree(vec![
            entry(b"a", EntryMode::Blob, 1),
            entry(b"b", EntryMode::Tree, 2),
            entry(b"c", EntryMode::Executable, 3),
        ]);
        let id = compute_tree_id(&t);
        let pos = tree_entry_position(&t, b"b").unwrap();
        assert_eq!(pos, 1);
        let proof = build_tree_entry_proof(&t, pos).unwrap();
        verify_tree_entry(&id, &t.entries[1], pos, &proof).unwrap();
        let wrong = entry(b"b", EntryMode::Blob, 2);
        assert!(verify_tree_entry(&id, &wrong, pos, &proof).is_err());
    }

    #[test]
    fn range_and_multi_proofs_round_trip() {
        let t = tree(
            (0..9)
                .map(|i| entry(&[b'a' + i], EntryMode::Blob, i))
                .collect(),
        );
        let id = compute_tree_id(&t);

        let range_proof = build_tree_entries_range_proof(&t, 2, 4).unwrap();
        verify_tree_entries_range(&id, 2, &t.entries[2..=4], &range_proof).unwrap();
        assert!(verify_tree_entries_range(&id, 2, &t.entries[2..4], &range_proof).is_err());

        let multi_proof = build_tree_entries_multi_proof(&t, [0, 4, 8]).unwrap();
        let elements = [
            (t.entries[0].clone(), 0),
            (t.entries[4].clone(), 4),
            (t.entries[8].clone(), 8),
        ];
        verify_tree_entries_multi(&id, &elements, &multi_proof).unwrap();
        let wrong_elements = [
            (t.entries[0].clone(), 0),
            (t.entries[4].clone(), 5), // wrong position
            (t.entries[8].clone(), 8),
        ];
        assert!(verify_tree_entries_multi(&id, &wrong_elements, &multi_proof).is_err());
    }

    #[test]
    fn multi_proofs_require_strictly_ascending_positions() {
        let t = tree(
            (0..9)
                .map(|i| entry(&[b'a' + i], EntryMode::Blob, i))
                .collect(),
        );
        let id = compute_tree_id(&t);
        let proof = build_tree_entries_multi_proof(&t, [0, 4, 8]).unwrap();
        let pair = |p: u32| (t.entries[p as usize].clone(), p);

        // The builder names the first position that is lower than its
        // predecessor, in input order.
        assert_eq!(
            build_tree_entries_multi_proof(&t, [8, 4, 0]),
            Err(MerkleError::UnsortedPosition(4))
        );
        assert_eq!(
            build_tree_entries_multi_proof(&t, [0, 8, 4]),
            Err(MerkleError::UnsortedPosition(4))
        );
        assert_eq!(
            build_tree_entries_multi_proof(&t, [0, 4, 4]),
            Err(MerkleError::DuplicatePosition(4))
        );
        assert_eq!(
            build_tree_entries_multi_proof(&t, [0, 4, 9]),
            Err(MerkleError::PositionOutOfRange(9))
        );
        // A duplicate that is not adjacent is still a descent.
        assert_eq!(
            build_tree_entries_multi_proof(&t, [0, 4, 8, 4]),
            Err(MerkleError::UnsortedPosition(4))
        );

        // The verifier rejects the same orders against a valid proof.
        verify_tree_entries_multi(&id, &[pair(0), pair(4), pair(8)], &proof).unwrap();
        assert_eq!(
            verify_tree_entries_multi(&id, &[pair(8), pair(4), pair(0)], &proof),
            Err(MerkleError::UnsortedPosition(4))
        );
        assert_eq!(
            verify_tree_entries_multi(&id, &[pair(0), pair(8), pair(4)], &proof),
            Err(MerkleError::UnsortedPosition(4))
        );
        assert_eq!(
            verify_tree_entries_multi(&id, &[pair(0), pair(4), pair(4)], &proof),
            Err(MerkleError::DuplicatePosition(4))
        );
        // Range errors and order errors are reported in input order.
        assert_eq!(
            verify_tree_entries_multi(&id, &[pair(4), pair(0), (t.entries[0].clone(), 9)], &proof),
            Err(MerkleError::UnsortedPosition(0))
        );
        assert_eq!(
            verify_tree_entries_multi(&id, &[pair(4), (t.entries[0].clone(), 9), pair(0)], &proof),
            Err(MerkleError::PositionOutOfRange(9))
        );

        let c = cb(100, 0, &[1, 2, 3, 4]);
        let chunked_id = compute_chunked_id(&c);
        let chunk_proof = build_chunks_multi_proof(&c, [1, 3]).unwrap();
        verify_chunks_multi(
            &chunked_id,
            &[(c.chunks[0], 1), (c.chunks[2], 3)],
            &chunk_proof,
        )
        .unwrap();
        assert_eq!(
            verify_chunks_multi(
                &chunked_id,
                &[(c.chunks[2], 3), (c.chunks[0], 1)],
                &chunk_proof
            ),
            Err(MerkleError::UnsortedPosition(1))
        );
        assert_eq!(
            build_chunks_multi_proof(&c, [3, 1]),
            Err(MerkleError::UnsortedPosition(1))
        );
        // The size calculator applies the same rule as the builder.
        assert_eq!(
            proof_encoded_size(9, [8, 4, 0]),
            Err(MerkleError::UnsortedPosition(4))
        );
    }

    #[test]
    fn chunk_range_and_multi_proofs_reject_position_zero() {
        let c = cb(100, 0, &[1, 2, 3]);
        let id = compute_chunked_id(&c);
        let proof = build_chunks_range_proof(&c, 0, 1).unwrap();
        assert_eq!(
            verify_chunks_range(&id, 0, &c.chunks[..2], &proof),
            Err(MerkleError::PositionOutOfRange(0))
        );
        let multi = build_chunks_multi_proof(&c, [0, 2]).unwrap();
        assert_eq!(
            verify_chunks_multi(&id, &[(c.chunks[0], 0), (c.chunks[1], 2)], &multi),
            Err(MerkleError::PositionOutOfRange(0))
        );
    }

    #[test]
    fn single_leaf_tree_proof_has_no_siblings() {
        // Odd trailing node at every level up to the root: the proof must
        // omit the self-duplicate sibling entirely (the old
        // format wrongly emitted it).
        let t = tree(vec![entry(b"only", EntryMode::Blob, 1)]);
        let id = compute_tree_id(&t);
        let proof = build_tree_entry_proof(&t, 0).unwrap();
        assert!(
            proof.siblings.is_empty(),
            "single-leaf tree proof must have zero siblings"
        );
        verify_tree_entry(&id, &t.entries[0], 0, &proof).unwrap();
    }

    #[test]
    fn verify_rejects_empty_element_set() {
        // A "proof" over zero positions must never verify — not even
        // against the real empty tree id with the trivial
        // `Proof::default()` (`leaf_count: 0, siblings: []`). Upstream's
        // own `verify_multi_inclusion` treats exactly this input as a
        // valid proof that a tree is empty; kit's id-based verifiers
        // reject it unconditionally instead, so a caller can never
        // "verify" zero proven entries/chunks against an id merely
        // because that id's inner root happens to fold the same way
        // (SPEC-MERKLE-OBJECTS §5.4).
        assert_eq!(
            verify_tree_entries_range(&TREE_EMPTY_ID, 0, &[], &Proof::default()),
            Err(MerkleError::NoPositions)
        );
        assert_eq!(
            verify_tree_entries_multi(&TREE_EMPTY_ID, &[], &Proof::default()),
            Err(MerkleError::NoPositions)
        );

        // The rule holds regardless of `leaf_count`: an empty
        // entries/positions slice is rejected even against a genuinely
        // non-empty tree with an otherwise-valid proof.
        let t = tree(vec![entry(b"a", EntryMode::Blob, 1)]);
        let id = compute_tree_id(&t);
        let real_proof = build_tree_entry_proof(&t, 0).unwrap();
        assert_eq!(
            verify_tree_entries_range(&id, 0, &[], &real_proof),
            Err(MerkleError::NoPositions)
        );
        assert_eq!(
            verify_tree_entries_multi(&id, &[], &real_proof),
            Err(MerkleError::NoPositions)
        );
    }

    #[test]
    fn empty_tree_builders_refuse_position_zero() {
        // SPEC-MERKLE-OBJECTS §5.4: position 0 of the empty `Tree`
        // (leaf_count 0), including the range `0..=0`, MUST be refused
        // rather than answered with the all-default proof.
        let empty = tree(vec![]);
        assert_eq!(
            build_tree_entries_range_proof(&empty, 0, 0),
            Err(MerkleError::PositionOutOfRange(0))
        );
        assert_eq!(
            build_tree_entry_proof(&empty, 0),
            Err(MerkleError::PositionOutOfRange(0))
        );
        assert_eq!(
            build_tree_entries_multi_proof(&empty, [0]),
            Err(MerkleError::PositionOutOfRange(0))
        );
    }

    #[test]
    fn out_of_range_position_rejected() {
        let c = cb(10, 0, &[1]);
        assert_eq!(
            build_chunk_proof(&c, 2),
            Err(MerkleError::PositionOutOfRange(2))
        );
    }

    #[test]
    fn proof_round_trips_through_encode_decode() {
        let t = tree(
            (0..7)
                .map(|i| entry(&[b'a' + i], EntryMode::Blob, i))
                .collect(),
        );
        let proof = build_tree_entry_proof(&t, 6).unwrap();
        let bytes = proof.encode();
        let decoded = Proof::decode(&bytes, 1).unwrap();
        assert_eq!(proof, decoded);

        // Trailing byte must be rejected.
        let mut truncated_extra = bytes.clone();
        truncated_extra.push(0);
        assert_eq!(
            Proof::decode(&truncated_extra, 1),
            Err(MerkleError::MalformedProof)
        );

        // A truncated buffer must be rejected.
        assert_eq!(
            Proof::decode(&bytes[..bytes.len() - 1], 1),
            Err(MerkleError::MalformedProof)
        );

        // An over-tight `max_items` bound must be rejected.
        assert_eq!(Proof::decode(&bytes, 0), Err(MerkleError::MalformedProof));
    }

    /// The fold and the level build give the same root for every leaf
    /// count to 1,024, and around every power of two to 2^14, where the
    /// odd-node duplication changes shape.
    #[test]
    fn fold_root_matches_level_build() {
        let max = (1usize << 14) + 1;
        let leaves: Vec<Hash> = (0..max).map(|i| hash(&(i as u64).to_le_bytes())).collect();
        let mut counts: Vec<usize> = (0..=1024).collect();
        for k in 11..=14 {
            counts.extend([(1 << k) - 1, 1 << k, (1 << k) + 1]);
        }
        for n in counts {
            assert_eq!(
                fold_root(leaves[..n].iter().copied()),
                build_bmt(&leaves[..n]).root,
                "fold diverged from the level build at n={n}"
            );
        }
    }

    /// Leaf counts that exercise the odd trailing node at every level:
    /// 1 to 70, every power of two to 2^10 and its neighbours, and a few
    /// sizes in between.
    fn stream_leaf_counts() -> Vec<usize> {
        let mut counts: Vec<usize> = (1..=70).collect();
        for k in 7..=10 {
            counts.extend([(1 << k) - 1, 1 << k, (1 << k) + 1]);
        }
        counts.extend([100, 333, 1000]);
        counts
    }

    /// Every single, range and multi proof of the streaming builder equals
    /// the level build's, byte for byte, for every leaf count shape and
    /// for every position that is a boundary of a pair at some level.
    #[test]
    fn streaming_proofs_equal_the_level_build_for_every_shape() {
        for n in stream_leaf_counts() {
            let leaves: Vec<Hash> = (0..n).map(|i| hash(&(i as u64).to_le_bytes())).collect();
            let reference = build_bmt(&leaves);
            let count = u32_of(n);
            let last = count - 1;
            let mut interesting: Vec<u32> = vec![0, last, last / 2];
            interesting.extend([1, 2, 3].into_iter().filter(|p| *p <= last));
            let mut k = 1;
            while k <= last {
                interesting.extend([k - 1, k, (k + 1).min(last)]);
                k <<= 1;
            }
            interesting.sort_unstable();
            interesting.dedup();
            for &p in &interesting {
                assert_eq!(
                    multi_proof_streaming(count, leaves.iter().copied(), [p]),
                    reference.proof(p),
                    "single proof at n={n}, p={p}"
                );
                for q in [p, p + (last - p) / 2, last] {
                    assert_eq!(
                        range_proof_streaming(count, leaves.iter().copied(), p, q),
                        reference.range_proof(p, q),
                        "range proof at n={n}, {p}..={q}"
                    );
                }
            }
            for window in interesting.windows(3) {
                assert_eq!(
                    multi_proof_streaming(count, leaves.iter().copied(), window.iter().copied()),
                    reference.multi_proof(window.iter().copied()),
                    "multi proof at n={n}, {window:?}"
                );
            }
            assert_eq!(
                multi_proof_streaming(count, leaves.iter().copied(), 0..count),
                reference.multi_proof(0..count),
                "multi proof of every leaf at n={n}"
            );
        }
    }

    /// The streaming builders refuse every position of an empty tree, the
    /// range `0..=0` included, as the level build does.
    #[test]
    fn streaming_proofs_refuse_every_position_of_an_empty_tree() {
        let reference = build_bmt(&[]);
        for positions in [vec![0u32], vec![3], vec![2, 1], vec![1, 1]] {
            assert_eq!(
                multi_proof_streaming(0, core::iter::empty(), positions.iter().copied()),
                reference.multi_proof(positions.iter().copied()),
                "multi {positions:?}"
            );
        }
        assert_eq!(
            multi_proof_streaming(0, core::iter::empty(), core::iter::empty()),
            Err(MerkleError::NoPositions)
        );
        for (start, end) in [(0u32, 0u32), (2, 1), (5, 9)] {
            assert_eq!(
                range_proof_streaming(0, core::iter::empty(), start, end),
                reference.range_proof(start, end),
                "range {start}..={end}"
            );
        }
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(600))]

        /// For random leaf counts and random positions, valid or not, the
        /// streaming proof and its error equal the level build's.
        #[test]
        fn streaming_proofs_equal_the_level_build(
            n in proptest::prop_oneof![
                3 => 1usize..=2000,
                2 => proptest::sample::select(stream_leaf_counts()),
            ],
            single in 0u32..2100,
            range in (0u32..2100, 0u32..2100),
            raw in proptest::collection::vec(0u32..2100, 0..=6),
            sorted in proptest::collection::btree_set(0u32..2000, 1..=40),
        ) {
            let leaves: Vec<Hash> = (0..n).map(|i| hash(&(i as u64).to_le_bytes())).collect();
            let reference = build_bmt(&leaves);
            let count = u32_of(n);
            proptest::prop_assert_eq!(
                multi_proof_streaming(count, leaves.iter().copied(), [single]),
                reference.proof(single)
            );
            proptest::prop_assert_eq!(
                range_proof_streaming(count, leaves.iter().copied(), range.0, range.1),
                reference.range_proof(range.0, range.1)
            );
            proptest::prop_assert_eq!(
                multi_proof_streaming(count, leaves.iter().copied(), raw.iter().copied()),
                reference.multi_proof(raw.iter().copied())
            );
            proptest::prop_assert_eq!(
                multi_proof_streaming(count, leaves.iter().copied(), sorted.iter().copied()),
                reference.multi_proof(sorted.iter().copied())
            );
        }
    }

    /// The public builders give the level build's proof for a manifest and
    /// for a tree.
    #[test]
    fn public_builders_equal_the_level_build() {
        for chunks in [0usize, 1, 2, 3, 6, 7, 8, 9, 31, 32, 33, 100] {
            let ids: Vec<u8> = (1..=u8::try_from(chunks).unwrap()).collect();
            let manifest = cb(chunks as u64 * 10, 0, &ids);
            let reference = build_bmt(&chunked_leaves(&manifest).collect::<Vec<_>>());
            let last = u32_of(chunks);
            for p in [0, last / 2, last] {
                assert_eq!(build_chunk_proof(&manifest, p), reference.proof(p));
                assert_eq!(
                    build_chunks_range_proof(&manifest, p, last),
                    reference.range_proof(p, last)
                );
                assert_eq!(
                    build_chunks_multi_proof(&manifest, [p, last + 1]),
                    reference.multi_proof([p, last + 1])
                );
            }
            assert_eq!(
                build_chunks_multi_proof(&manifest, 0..=last),
                reference.multi_proof(0..=last)
            );
        }
        for entries in [0usize, 1, 2, 3, 5, 8, 9, 40] {
            let names: Vec<TreeEntry> = (0..u8::try_from(entries).unwrap())
                .map(|i| entry(format!("e{i:03}").as_bytes(), EntryMode::Blob, i))
                .collect();
            let t = tree(names);
            let reference = build_bmt(&tree_leaves(&t).collect::<Vec<_>>());
            let count = u32_of(entries);
            for p in [0, count / 2, count.saturating_sub(1), count] {
                assert_eq!(build_tree_entry_proof(&t, p), reference.proof(p));
                assert_eq!(
                    build_tree_entries_range_proof(&t, p, count),
                    reference.range_proof(p, count)
                );
                assert_eq!(
                    build_tree_entries_multi_proof(&t, [p]),
                    reference.multi_proof([p])
                );
            }
        }
    }

    /// The id of a `FastCDC` manifest of `count` generated 16 KiB chunks.
    /// Chunk `i` is `i` as a little-endian u64, zero-padded to 32 bytes.
    fn generated_manifest(count: u32) -> ChunkedBlob {
        ChunkedBlob {
            total_size: u64::from(count) * 16 * 1024,
            chunk_size: 0,
            chunks: (0..count)
                .map(|i| {
                    let mut id = [0u8; 32];
                    id[..8].copy_from_slice(&u64::from(i).to_le_bytes());
                    id
                })
                .collect(),
        }
    }

    /// The level-build ids of `generated_manifest(1_000_001)` and
    /// `generated_manifest(MAX_CHUNKS)`.
    const ID_AT_1_000_001_CHUNKS: &str =
        "b0dca84f37350aeb6cfbf8f240f4c6a0d68b795d8412057bbc8fdfbbde0da767";
    const ID_AT_THE_CHUNK_CAP: &str =
        "2703e358293c235eb9103a36a25088cba7133be0cc4a957787632ecd8b77140e";

    /// A manifest just past the old 1,000,000-chunk cap keeps the id the
    /// level build gives it.
    #[test]
    fn chunked_id_at_1_000_001_chunks_is_pinned() {
        let manifest = generated_manifest(1_000_001);
        assert_eq!(
            crate::hash::to_hex(&compute_chunked_id(&manifest)),
            ID_AT_1_000_001_CHUNKS
        );
    }

    /// The level build gives the pinned ids, and the fold gives the same id
    /// at the 8,388,608-chunk cap. The unoptimized build takes over a
    /// minute and about 1 GiB, so it runs in the ignored lane.
    #[test]
    #[ignore = "slow: level-builds 8,388,608 chunks; runs in the ignored lane"]
    fn chunked_id_at_the_chunk_cap_is_pinned() {
        for (count, pinned) in [
            (1_000_001, ID_AT_1_000_001_CHUNKS),
            (crate::serialize::MAX_CHUNKS, ID_AT_THE_CHUNK_CAP),
        ] {
            let manifest = generated_manifest(count);
            let levels = wrap_id(
                ObjectKind::ChunkedBlob,
                &build_bmt(&chunked_leaves(&manifest).collect::<Vec<_>>()).root,
            );
            assert_eq!(
                crate::hash::to_hex(&levels),
                pinned,
                "level build at {count}"
            );
            assert_eq!(compute_chunked_id(&manifest), levels, "fold at {count}");
        }
    }

    /// `ChunkedIdFold` gives the stored id of a manifest, and its inner
    /// root is the one a commonware verifier checks against.
    #[test]
    fn chunked_id_fold_matches_compute_chunked_id() {
        for n in [0u8, 1, 2, 3, 7, 8, 9] {
            let manifest = cb(u64::from(n) * 5, 0, &(1..=n).collect::<Vec<_>>());
            let mut fold = ChunkedIdFold::new(manifest.total_size, manifest.chunk_size);
            for chunk in &manifest.chunks {
                fold.push(chunk).unwrap();
            }
            assert_eq!(fold.id(), compute_chunked_id(&manifest));
            assert_eq!(fold.inner_root(), chunked_inner_root(&manifest));
            assert_eq!(
                fold.inner_root(),
                build_bmt(&chunked_leaves(&manifest).collect::<Vec<_>>()).root
            );
        }
    }

    /// Folding a manifest's raw id bytes, in uneven slices, gives the
    /// decoded manifest's id, and a partial id is refused.
    #[test]
    fn push_ids_matches_the_decoded_manifest() {
        let manifest = generated_manifest(1000);
        let bytes =
            crate::serialize::serialize(&crate::object::Object::ChunkedBlob(manifest.clone()))
                .unwrap();
        // Prologue 6, total_size 8, chunk_size 4, chunk_count 4.
        let ids = &bytes[22..];
        let mut fold = ChunkedIdFold::new(manifest.total_size, manifest.chunk_size);
        for slice in [&ids[..32], &ids[32..32 * 7], &ids[32 * 7..]] {
            fold.push_ids(slice).unwrap();
        }
        assert_eq!(fold.id(), compute_chunked_id(&manifest));
        let mut partial = ChunkedIdFold::new(0, 0);
        assert_eq!(partial.push_ids(&[0; 33]), Err(MerkleError::PartialChunkId));
        assert_eq!(partial.id(), ChunkedIdFold::new(0, 0).id());
    }

    /// A fold refuses a leaf past `u32::MAX` instead of wrapping its
    /// position.
    #[test]
    fn fold_refuses_more_than_u32_max_leaves() {
        let mut fold = BmtFold::new();
        fold.count = u32::MAX;
        assert_eq!(fold.push(&[0; 32]), Err(MerkleError::TooManyLeaves));
    }

    /// Cross-verify the BMT root against `commonware_storage::bmt`
    /// (native-only dev-dep) for several leaf counts incl. odd ones.
    #[test]
    fn root_matches_commonware() {
        use commonware_cryptography::blake3::{Blake3, Digest};
        use commonware_storage::bmt::Builder;

        for n in [1usize, 2, 3, 4, 5, 7, 8, 9, 16, 33] {
            let leaves: Vec<Hash> = (0..n)
                .map(|i| hash(&[u8::try_from(i % 256).unwrap(); 4]))
                .collect();

            let mut builder = Builder::<Blake3>::new(n);
            for l in &leaves {
                builder.add(&Digest(*l));
            }
            let cw_root = builder.build().root().0;
            assert_eq!(
                build_bmt(&leaves).root,
                cw_root,
                "BMT root diverged at n={n}"
            );
            assert_eq!(
                fold_root(leaves.iter().copied()),
                cw_root,
                "fold root diverged at n={n}"
            );
        }
    }

    /// Strategy for `(leaf_count, single_pos, (range_start, range_end),
    /// multi_positions)`, weighted towards odd counts and powers-of-two ±1
    /// (where the odd-trailing-node dedup logic is most exercised) on top
    /// of a broad uniform range.
    fn tree_and_positions()
    -> impl proptest::strategy::Strategy<Value = (usize, u32, (u32, u32), Vec<u32>)> {
        use proptest::prelude::*;

        let boundary_counts: Vec<usize> = [1usize, 2, 4, 8, 16, 32, 64, 128, 256]
            .into_iter()
            .flat_map(|p| [p.saturating_sub(1).max(1), p, p + 1])
            .chain([
                3usize, 5, 7, 9, 15, 17, 31, 33, 63, 65, 127, 129, 255, 257, 300,
            ])
            .collect();

        prop_oneof![
            3 => 1usize..=300,
            2 => proptest::sample::select(boundary_counts),
        ]
        .prop_flat_map(|n| {
            let n_u32 =
                u32::try_from(n).expect("n is bounded well under u32::MAX by the strategy above");
            (
                Just(n),
                0..n_u32,
                (0..n_u32).prop_flat_map(move |s| (Just(s), s..n_u32)),
                proptest::collection::vec(0..n_u32, 1..=n.min(6)).prop_map(|mut v| {
                    v.sort_unstable();
                    v.dedup();
                    v
                }),
            )
        })
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(400))]

        /// Cross-verify [`Proof`] against `commonware_storage::bmt::Proof`
        /// (native-only dev-dep): for many randomised trees and randomised
        /// single/range/multi positions, kit's encoded bytes must equal
        /// upstream's, and each side's verifier must accept the other's
        /// bytes/positions against the (matching) inner root. A mutated
        /// proof must be rejected by both. Pins the
        /// "commonware-aligned bytes" claim beyond the root-only check
        /// above.
        #[test]
        fn proofs_match_commonware((n, pos, (start, end), positions) in tree_and_positions()) {
            use commonware_cryptography::blake3::{Blake3, Digest};
            use commonware_storage::bmt::Builder;

            let leaves: Vec<Hash> = (0..n).map(|i| hash(&(i as u64).to_le_bytes())).collect();

            let ours = build_bmt(&leaves);
            let mut cw_builder = Builder::<Blake3>::new(n);
            for l in &leaves {
                cw_builder.add(&Digest(*l));
            }
            let cw_tree = cw_builder.build();
            let cw_root = cw_tree.root();
            assert_eq!(ours.root, cw_root.0, "root mismatch at n={n}");

            // --- single position ---
            let our_proof = ours.proof(pos).unwrap();
            let cw_proof = cw_tree.proof(pos).unwrap();
            assert_eq!(
                our_proof.encode(),
                commonware_codec::Encode::encode(&cw_proof).to_vec(),
                "single-proof bytes diverged at n={n} pos={pos}"
            );
            cw_proof
                .verify_element_inclusion::<Blake3>(&Digest(leaves[pos as usize]), pos, &cw_root)
                .expect("upstream must accept its own proof");
            our_proof
                .verify_element_inclusion(&leaves[pos as usize], pos, &ours.root)
                .expect("ours must accept its own proof");
            // Cross-accept: decode the other side's bytes with our type.
            let cw_bytes = commonware_codec::Encode::encode(&cw_proof).to_vec();
            let our_decoded = Proof::decode(&cw_bytes, 1).unwrap();
            our_decoded
                .verify_element_inclusion(&leaves[pos as usize], pos, &ours.root)
                .expect("ours must accept upstream's proof bytes");
            // Cross-accept the other way: upstream decodes our bytes.
            let our_bytes = our_proof.encode();
            let mut our_bytes_buf = Copying(&our_bytes);
            let cw_decoded =
                <commonware_storage::bmt::Proof<Digest> as commonware_codec::Read>::read_cfg(
                    &mut our_bytes_buf,
                    &1usize,
                )
                .unwrap();
            cw_decoded
                .verify_element_inclusion::<Blake3>(&Digest(leaves[pos as usize]), pos, &cw_root)
                .expect("upstream must accept our proof bytes");

            // --- mutation must be rejected by both ---
            if !our_proof.siblings.is_empty() {
                let mut mutated = our_proof.clone();
                mutated.siblings[0][0] ^= 0x01;
                assert!(
                    mutated
                        .verify_element_inclusion(&leaves[pos as usize], pos, &ours.root)
                        .is_err()
                );

                let mut dropped = our_proof.clone();
                dropped.siblings.pop();
                assert!(
                    dropped
                        .verify_element_inclusion(&leaves[pos as usize], pos, &ours.root)
                        .is_err()
                );

                let mut extra = our_proof.clone();
                extra.siblings.push(hash(b"extra"));
                assert!(
                    extra
                        .verify_element_inclusion(&leaves[pos as usize], pos, &ours.root)
                        .is_err()
                );
            }
            let mut wrong_count = our_proof.clone();
            wrong_count.leaf_count = wrong_count.leaf_count.wrapping_add(1);
            assert!(
                wrong_count
                    .verify_element_inclusion(&leaves[pos as usize], pos, &ours.root)
                    .is_err()
            );

            if n >= 2 {
                // --- range ---
                let our_range = ours.range_proof(start, end).unwrap();
                let cw_range = cw_tree.range_proof(start, end).unwrap();
                assert_eq!(
                    our_range.encode(),
                    commonware_codec::Encode::encode(&cw_range).to_vec(),
                    "range-proof bytes diverged at n={n} start={start} end={end}"
                );
                let range_leaves: Vec<Hash> = leaves[start as usize..=end as usize].to_vec();
                let cw_range_leaves: Vec<Digest> =
                    range_leaves.iter().map(|h| Digest(*h)).collect();
                cw_range
                    .verify_range_inclusion::<Blake3>(start, &cw_range_leaves, &cw_root)
                    .expect("upstream must accept its own range proof");
                our_range
                    .verify_range_inclusion(start, &range_leaves, &ours.root)
                    .expect("ours must accept its own range proof");

                // --- multi ---
                if !positions.is_empty() {
                    let our_multi = ours.multi_proof(positions.iter().copied()).unwrap();
                    let cw_multi = cw_tree.multi_proof(positions.iter().copied()).unwrap();
                    assert_eq!(
                        our_multi.encode(),
                        commonware_codec::Encode::encode(&cw_multi).to_vec(),
                        "multi-proof bytes diverged at n={n} positions={positions:?}"
                    );
                    let elements: Vec<(Hash, u32)> =
                        positions.iter().map(|&p| (leaves[p as usize], p)).collect();
                    let cw_elements: Vec<(Digest, u32)> = positions
                        .iter()
                        .map(|&p| (Digest(leaves[p as usize]), p))
                        .collect();
                    cw_multi
                        .verify_multi_inclusion::<Blake3>(&cw_elements, &cw_root)
                        .expect("upstream must accept its own multi proof");
                    our_multi
                        .verify_multi_inclusion(&elements, &ours.root)
                        .expect("ours must accept its own multi proof");

                    // --- non-canonical order: both sides must reject ---
                    // The strategy draws ascending positions. Reversing them
                    // makes the first descent land on `positions[len - 2]`.
                    // Repeating the first one makes a duplicate.
                    let mut cases = vec![(
                        std::iter::repeat_n(positions[0], 2)
                            .chain(positions.iter().skip(1).copied())
                            .collect::<Vec<u32>>(),
                        MerkleError::DuplicatePosition as fn(u32) -> MerkleError,
                        positions[0],
                        format!("duplicate position: {}", positions[0]),
                    )];
                    if positions.len() >= 2 {
                        let first_descent = positions[positions.len() - 2];
                        cases.push((
                            positions.iter().rev().copied().collect(),
                            MerkleError::UnsortedPosition as fn(u32) -> MerkleError,
                            first_descent,
                            format!("unsorted position: {first_descent}"),
                        ));
                    }
                    for (bad, error, named, upstream_message) in cases {
                        assert_eq!(
                            ours.multi_proof(bad.iter().copied()),
                            Err(error(named)),
                            "builder must reject {bad:?} at n={n}"
                        );
                        assert_eq!(
                            cw_tree
                                .multi_proof(bad.iter().copied())
                                .unwrap_err()
                                .to_string(),
                            upstream_message
                        );
                        let bad_elements: Vec<(Hash, u32)> =
                            bad.iter().map(|&p| (leaves[p as usize], p)).collect();
                        let bad_cw_elements: Vec<(Digest, u32)> = bad
                            .iter()
                            .map(|&p| (Digest(leaves[p as usize]), p))
                            .collect();
                        assert_eq!(
                            our_multi.verify_multi_inclusion(&bad_elements, &ours.root),
                            Err(error(named)),
                            "verifier must reject {bad:?} at n={n}"
                        );
                        assert_eq!(
                            cw_multi
                                .verify_multi_inclusion::<Blake3>(&bad_cw_elements, &cw_root)
                                .unwrap_err()
                                .to_string(),
                            upstream_message
                        );
                    }
                }
            }
        }
    }
}

/// Kani proof harnesses (`cargo kani -p kit-core --no-default-features
/// -Z stubbing --harness merkle_`, see `delta.rs`), the model-checked counterpart of the `merkle_proof` fuzz
/// target.
///
/// BLAKE3 (`h2`, `domain_digest`, `hash`) is stubbed with a cheap
/// deterministic `toy` mixer: the index/level arithmetic, sibling
/// consumption and wire decoding are what is verified here; collision
/// resistance is BLAKE3's job and out of scope for a model checker.
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Loop-free deterministic mixer over the first 16 bytes of `a` and
    /// of `b` (zero-padded) and both lengths. Each output half depends on
    /// both inputs, so a change in either input's first 16 bytes
    /// propagates up the tree (a mixer that merely copied inputs into
    /// disjoint halves would drop leaf bytes one level up and make the
    /// tampered-leaf canary unfalsifiable). Loop-free so it does not
    /// interact with the global unwind bound.
    fn toy(a: &[u8], b: &[u8]) -> Hash {
        fn first16(x: &[u8]) -> u128 {
            let mut w = [0u8; 16];
            let n = x.len().min(16);
            w[..n].copy_from_slice(&x[..n]);
            u128::from_le_bytes(w)
        }
        let (ha, hb) = (first16(a), first16(b));
        let lo = ha ^ hb.rotate_left(8) ^ a.len() as u128;
        let hi = hb ^ ha.rotate_left(16) ^ ((b.len() as u128) << 64);
        let mut out = [0u8; HASH_LEN];
        out[..16].copy_from_slice(&lo.to_le_bytes());
        out[16..].copy_from_slice(&hi.to_le_bytes());
        out
    }
    fn toy_h2(a: &[u8], b: &[u8]) -> Hash {
        toy(a, b)
    }
    fn toy_domain_digest(domain: &[u8], body: &[u8]) -> Hash {
        toy(body, domain)
    }
    fn toy_hash(data: &[u8]) -> Hash {
        toy(data, &[])
    }

    /// SPEC-MERKLE-OBJECTS §5.3/§5.4: number of wire siblings a
    /// single-leaf proof of `position` in a `leaf_count`-leaf tree
    /// consumes (odd trailing nodes fold with themselves, no sibling).
    fn spec_sibling_count(leaf_count: u32, mut position: u32) -> usize {
        let mut level_size = u64::from(leaf_count);
        let mut need = 0;
        while level_size > 1 {
            if !(position % 2 == 0 && u64::from(position) + 1 >= level_size) {
                need += 1;
            }
            position /= 2;
            level_size = level_size.div_ceil(2);
        }
        need
    }

    fn short_at<const N: usize>() {
        let buf: [u8; N] = kani::any();
        let b: &[u8] = &buf;
        if let Ok(p) = Proof::decode(b, 1) {
            assert!(N == 5 && b[4] == 0 && p.siblings.is_empty());
            let lc: [u8; 4] = b[..4].try_into().expect("4 bytes");
            assert_eq!(p.leaf_count, u32::from_be_bytes(lc));
            kani::cover!(true, "ok_no_siblings");
        }
    }

    /// `Proof::decode(_, 1)` (the single-leaf bound the fuzz target and
    /// `verify_chunk` callers use) never panics on any input of 0..=4
    /// bytes (truncated before the sibling-count varint; each length
    /// concrete, every byte symbolic) and rejects all of them.
    #[kani::proof]
    #[kani::unwind(4)]
    fn merkle_proof_decode_no_panic() {
        short_at::<0>();
        short_at::<1>();
        short_at::<2>();
        short_at::<3>();
        short_at::<4>();
    }

    /// As above at 5 bytes (be32 leaf count + a symbolic varint): accepts
    /// exactly the §5.2 empty proof `be32(leaf_count) ‖ varint(0)`.
    #[kani::proof]
    // Varint <= 1 byte here; no sibling fits.
    #[kani::unwind(4)]
    fn merkle_proof_decode_empty_proof() {
        short_at::<5>();
    }

    /// At exactly 37 bytes with the sibling-count varint pinned to 1
    /// (be32 leaf count + `0x01` + one digest, the other 36 bytes
    /// symbolic): no panic, `Ok`, and the proof carries exactly the wire
    /// leaf count and digest (§5.2). (With the varint symbolic, the
    /// symbolic-size sibling `Vec` allocation ran out of memory.)
    #[kani::proof]
    // Largest loop: the 4-word digest comparison.
    #[kani::unwind(6)]
    fn merkle_proof_decode_one_sibling() {
        let mut buf: [u8; 37] = kani::any();
        buf[4] = 1;
        let p = Proof::decode(&buf, 1).expect("one-sibling proof decodes");
        assert_eq!(
            p.leaf_count,
            u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]])
        );
        assert_eq!(p.siblings.len(), 1);
        let d = &p.siblings[0];
        let w = |x: &[u8], i: usize| u64::from_le_bytes(x[i..i + 8].try_into().expect("8"));
        assert!((0..4).all(|k| w(d, 8 * k) == w(&buf[5..], 8 * k)));
    }

    /// One adversarial verification with `S` sibling digests and a
    /// symbolic `leaf_count <= max_leaves`.
    fn verify_with<const S: usize>(max_leaves: u32) -> bool {
        let proof = Proof {
            leaf_count: kani::any_where(|&n| n <= max_leaves),
            siblings: kani::any::<[Hash; S]>().to_vec(),
        };
        let position: u32 = kani::any();
        let leaf: Hash = kani::any();
        let id: Hash = kani::any();

        let folded = proof.reconstruct_element_root(&leaf, position);
        let shape_ok = position < proof.leaf_count
            && proof.siblings.len() == spec_sibling_count(proof.leaf_count, position);
        assert_eq!(folded.is_ok(), shape_ok);

        let chunk = verify_chunk(&id, &leaf, position, &proof);
        if position == 0 {
            assert_eq!(chunk, Err(MerkleError::PositionOutOfRange(0)));
        }
        if chunk.is_ok() {
            assert!(shape_ok);
        }
        let entry = TreeEntry {
            name: vec![b'a'],
            mode: crate::object::EntryMode::Blob,
            object_hash: leaf,
        };
        let _ = verify_tree_entry(&id, &entry, position, &proof);
        chunk.is_ok()
    }

    /// Adversarial single-leaf verification: any `leaf_count`, any
    /// `position`, no sibling digests, any claimed id. `verify_chunk` /
    /// `verify_tree_entry` never panic/overflow, and the fold succeeds
    /// iff `position < leaf_count` and the proof carries exactly the §5.3
    /// sibling count (§5.4 "consumed exactly once"). Chunk position 0 is
    /// always rejected (§5.5). One harness per sibling count: 0..=2 in
    /// one harness did not finish within 15 min.
    #[kani::proof]
    #[kani::stub(h2, toy_h2)]
    #[kani::stub(crate::hash::domain_digest, toy_domain_digest)]
    #[kani::stub(crate::hash::hash, toy_hash)]
    // <= 32 fold levels (any u32 leaf count).
    #[kani::unwind(34)]
    fn merkle_verify_s0() {
        verify_with::<0>(u32::MAX);
    }

    /// As above with one arbitrary sibling digest and `leaf_count <= 16`
    /// (<= 4 fold levels; any `u32` leaf count ran out of memory). Run
    /// with `-Z unstable-options --cbmc-args --unwindset memcmp.0:33`.
    #[kani::proof]
    #[kani::stub(h2, toy_h2)]
    #[kani::stub(crate::hash::domain_digest, toy_domain_digest)]
    #[kani::stub(crate::hash::hash, toy_hash)]
    #[kani::unwind(6)]
    fn merkle_verify_s1() {
        kani::cover!(verify_with::<1>(16), "accepts_one_sibling_proof");
    }

    /// As above with two arbitrary sibling digests and `leaf_count <= 16`.
    #[kani::proof]
    #[kani::stub(h2, toy_h2)]
    #[kani::stub(crate::hash::domain_digest, toy_domain_digest)]
    #[kani::stub(crate::hash::hash, toy_hash)]
    #[kani::unwind(6)]
    fn merkle_verify_s2() {
        kani::cover!(verify_with::<2>(16), "accepts_two_sibling_proof");
    }

    /// Independent single-leaf proof builder following
    /// SPEC-MERKLE-OBJECTS §1.1 (position-hashed leaves, odd trailing node paired
    /// with itself, `H(be32(leaf_count) ‖ top)` finalization) and §5.3
    /// (level-major siblings, self-duplicates omitted). Returns the
    /// finalized inner root and the sibling list. `leaves.len() <= 4`.
    fn spec_proof(leaves: &[Hash], pos: usize) -> (Hash, Vec<Hash>) {
        #[allow(clippy::cast_possible_truncation)]
        let mut level: Vec<Hash> = leaves
            .iter()
            .enumerate()
            .map(|(i, l)| toy_h2(&(i as u32).to_be_bytes(), l))
            .collect();
        let mut p = pos;
        let mut siblings = Vec::new();
        while level.len() > 1 {
            if p % 2 == 1 {
                siblings.push(level[p - 1]);
            } else if p + 1 < level.len() {
                siblings.push(level[p + 1]);
            }
            let mut next = Vec::new();
            let mut i = 0;
            while i < level.len() {
                let right = if i + 1 < level.len() {
                    level[i + 1]
                } else {
                    level[i]
                };
                next.push(toy_h2(&level[i], &right));
                i += 2;
            }
            level = next;
            p /= 2;
        }
        #[allow(clippy::cast_possible_truncation)]
        let root = toy_h2(&(leaves.len() as u32).to_be_bytes(), &level[0]);
        (root, siblings)
    }

    /// A `ChunkedBlob` with `N` symbolic chunks and symbolic sizes, its
    /// §3.1 leaf list `[meta, chunks…]`, and its id computed through the
    /// §2 domain wrap of the spec-built root.
    fn chunked_fixture<const N: usize>() -> (ChunkedBlob, Vec<Hash>) {
        let cb = ChunkedBlob {
            total_size: kani::any(),
            chunk_size: kani::any(),
            chunks: kani::any::<[Hash; N]>().to_vec(),
        };
        let mut leaves = vec![chunked_meta_leaf_raw(cb.total_size, cb.chunk_size)];
        leaves.extend_from_slice(&cb.chunks);
        (cb, leaves)
    }

    /// Spec-built proof for chunk `pos` (1-based, concrete) of an
    /// `N`-chunk symbolic blob is accepted.
    fn chunk_rt<const N: usize>(pos: u32) {
        let (cb, leaves) = chunked_fixture::<N>();
        let (root, siblings) = spec_proof(&leaves, pos as usize);
        let id = wrap_id(ObjectKind::ChunkedBlob, &root);
        #[allow(clippy::cast_possible_truncation)]
        let proof = Proof {
            leaf_count: leaves.len() as u32,
            siblings,
        };
        assert_eq!(
            proof.siblings.len(),
            spec_sibling_count(proof.leaf_count, pos)
        );
        assert_eq!(
            verify_chunk(&id, &cb.chunks[(pos - 1) as usize], pos, &proof),
            Ok(())
        );
    }

    /// Spec conformance (§1.1, §5.3–§5.5): for every `ChunkedBlob` of 1
    /// symbolic chunk (any sizes) and every chunk position, the proof an
    /// independent §5.3 builder produces for the independently built §1.1
    /// root (wrapped per §2) has the model sibling count and is accepted
    /// by `verify_chunk`. (`build_chunk_proof` goes through a `BTreeSet`
    /// and `compute_chunked_id` through `build_bmt`'s `Vec<Vec<Hash>>`
    /// levels; both ran out of memory even for one chunk, so the builder
    /// side is left to the unit tests and the `merkle_proof` fuzz target.)
    #[kani::proof]
    #[kani::stub(h2, toy_h2)]
    #[kani::stub(crate::hash::domain_digest, toy_domain_digest)]
    #[kani::stub(crate::hash::hash, toy_hash)]
    // <= 2 levels for <= 3 leaves; `spec_proof` pairs <= 3 nodes. Run
    // with `-Z unstable-options --cbmc-args --unwindset memcmp.0:33` for
    // the 32-byte digest comparisons.
    #[kani::unwind(5)]
    fn merkle_roundtrip_one_chunk() {
        chunk_rt::<1>(1);
    }

    /// As above for a 2-chunk blob (3 leaves, odd trailing node), both
    /// chunk positions, each concrete (a symbolic position, i.e. a
    /// symbolic index into the digest vectors, ran out of memory).
    #[kani::proof]
    #[kani::stub(h2, toy_h2)]
    #[kani::stub(crate::hash::domain_digest, toy_domain_digest)]
    #[kani::stub(crate::hash::hash, toy_hash)]
    // As above: `--cbmc-args --unwindset memcmp.0:33`.
    #[kani::unwind(5)]
    fn merkle_roundtrip_two_chunks() {
        chunk_rt::<2>(1);
        chunk_rt::<2>(2);
    }

    /// As above for a 3-chunk blob (4 leaves, a full 2-level tree), every
    /// chunk position, each concrete.
    #[kani::proof]
    #[kani::stub(h2, toy_h2)]
    #[kani::stub(crate::hash::domain_digest, toy_domain_digest)]
    #[kani::stub(crate::hash::hash, toy_hash)]
    // As above: `--cbmc-args --unwindset memcmp.0:33`.
    #[kani::unwind(5)]
    fn merkle_roundtrip_three_chunks() {
        chunk_rt::<3>(1);
        chunk_rt::<3>(2);
        chunk_rt::<3>(3);
    }

    /// SPEC-MERKLE-OBJECTS §5.4 builder rule: "A builder MUST refuse any
    /// position `>= leaf_count` ... A builder asked for position 0 of an
    /// empty `Tree`, including the range `0..=0`, MUST refuse rather than
    /// return the all-default proof." For the empty `Tree` every
    /// single-leaf, range and (one-position) multi-leaf request, over
    /// every `u32` position, is refused. The `cover` shows the range
    /// assertion is on a reachable path.
    #[kani::proof]
    #[kani::stub(h2, toy_h2)]
    #[kani::stub(crate::hash::domain_digest, toy_domain_digest)]
    #[kani::stub(crate::hash::hash, toy_hash)]
    #[kani::unwind(3)]
    fn merkle_builder_empty_tree_refuses() {
        let empty = Tree {
            entries: Vec::new(),
        };
        let (p, start, end): (u32, u32, u32) = (kani::any(), kani::any(), kani::any());
        assert!(build_tree_entry_proof(&empty, p).is_err());
        assert!(build_tree_entries_multi_proof(&empty, [p]).is_err());
        let range = build_tree_entries_range_proof(&empty, start, end);
        kani::cover!(range.is_err(), "range_refused");
        assert!(
            range.is_err(),
            "empty-Tree range proof must be refused (SPEC-MERKLE-OBJECTS §5.4)"
        );
    }

    /// Canary (§6 "leaf tampered"): the checker must find a forged chunk
    /// hash that the verifier rejects under a genuine 2-chunk proof, i.e.
    /// falsify "any leaf verifies under a genuine proof".
    #[kani::proof]
    #[kani::stub(h2, toy_h2)]
    #[kani::stub(crate::hash::domain_digest, toy_domain_digest)]
    #[kani::stub(crate::hash::hash, toy_hash)]
    // As above: `--cbmc-args --unwindset memcmp.0:33`.
    #[kani::unwind(6)]
    #[kani::should_panic]
    fn merkle_canary_tampered_leaf_verifies() {
        let (_cb, leaves) = chunked_fixture::<2>();
        let (root, siblings) = spec_proof(&leaves, 1);
        let id = wrap_id(ObjectKind::ChunkedBlob, &root);
        let proof = Proof {
            leaf_count: 3,
            siblings,
        };
        let forged: Hash = kani::any();
        assert!(verify_chunk(&id, &forged, 1, &proof).is_ok());
    }
}

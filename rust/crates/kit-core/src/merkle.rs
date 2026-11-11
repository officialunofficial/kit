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
//! For `ChunkedBlob`, this module implements the construction of
//! `commonware_storage::bmt`. Tests compare the root and the proof bytes
//! with that crate for trees of one or more leaves. A `Tree` uses the same
//! construction with a keyed parent that also commits to a separator name
//! (see "Keyed tree fold" below).
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
//!   parent      = H(left ‖ right ‖ u8(len(sep)) ‖ sep)   (keyed, see below)
//! ```
//!
//! The outer `wrap_id` wrap makes the id type-distinct. The BMT has no
//! leaf/node tag: a position-hashed leaf and a finalized root both hash a
//! `be32` integer and a digest, so an interior node of one BMT can equal
//! the bare root of another. The bound leaf count fixes the shape of the
//! tree a proof folds through, and the wrap keeps a verifier from
//! comparing a folded value with a bare root or another type's id.
//!
//! ## Keyed tree fold
//!
//! A two-child parent in a `Tree` BMT is `H(left ‖ right ‖ u8(len) ‖ sep)`,
//! where `sep` is the name of the first entry under `right`. A
//! [`TreeProof`] carries the separator of every parent on its path, and
//! [`verify_tree_entry`] checks the proven name against each one: below
//! the separator when the path goes left, at or above it when it goes
//! right. Two proofs of one name at different positions would need
//! contradictory checks at their lowest common ancestor, so a name has at
//! most one verifiable entry in a tree, even in a tree whose author broke
//! the sort order (SPEC-MERKLE-OBJECTS §5.8).
//!
//! ## Inclusion proofs
//!
//! Object identity (`compute_tree_id` / `compute_chunked_id`) and the
//! inclusion-proof construction below are both stable
//! (`docs/specs/SPEC-MERKLE-OBJECTS.md` §5). For `ChunkedBlob`,
//! [`Proof`]'s bytes and sibling selection are byte-identical to
//! `commonware_storage::bmt::Proof` at the pinned `2026.10.0` train: a
//! commonware-based verifier can decode a kit-produced chunk proof with
//! the upstream type and run its own `verify_element_inclusion` /
//! `verify_range_inclusion` / `verify_multi_inclusion` against the
//! **inner root** (see [`chunked_inner_root`]), then apply [`wrap_id`] to
//! compare against the object id. `tests::proofs_match_commonware` pins
//! this claim; `rust/tests/golden/proofs/` carries fixed vectors. A `Tree`
//! entry has only the keyed single-entry [`TreeProof`].
//!
//! Verification in this crate is always stated against the **object id**
//! (`verify_tree_entry`, `verify_chunk`, and the chunk range/multi
//! verifiers), never the bare inner root — passing a caller the inner
//! root invited skipping the type-domain wrap and accepting, say, a
//! `Tree` proof against a `ChunkedBlob` id (SPEC-DISCLOSURE). The
//! inner-root-comparing primitives (`Proof::verify_element_inclusion` and
//! friends) stay `pub(crate)`, kept only so the cross-check test can
//! compare directly against upstream's verifiers.

use std::collections::BTreeSet;

use bytes::{Buf as _, BufMut};
use commonware_codec::{Buf, Copying};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, ReadRangeExt, Write};

use crate::hash::{HASH_LEN, Hash, Hasher, domain_digest, hash};
use crate::object::{ChunkedBlob, Tree, TreeEntry};

/// Largest number of steps in a [`TreeProof`]: one per level of a tree
/// with up to `u32::MAX` leaves.
const MAX_TREE_PROOF_STEPS: usize = MAX_LEVELS;

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
    /// A tree proof separator is not a valid entry name.
    #[error("tree proof separator is not a valid entry name")]
    InvalidSeparator,
    /// The proven entry name is on the wrong side of a tree proof
    /// separator, so the entry is not where the proof places it.
    #[error("tree entry name is out of order with a tree proof separator")]
    SeparatorOrder,
}

impl From<CodecError> for MerkleError {
    fn from(_: CodecError) -> Self {
        Self::MalformedProof
    }
}

// ---------------------------------------------------------------------------
// BMT primitive (over `blake3`)
// ---------------------------------------------------------------------------

/// Leaf/index count as `u32`. Objects are decode-capped at 1M
/// entries/chunks (see `serialize.rs`), far below `u32::MAX`, so this
/// only panics on a programmer error that bypassed those caps.
fn u32_of(n: usize) -> u32 {
    u32::try_from(n).expect("merkle leaf/index count fits u32 (objects capped at 1M)")
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
/// single pre-finalize root node, plus the finalized root. Kept around so
/// one build serves many proofs cheaply — mirrors commonware's
/// `Builder`/`Tree` split.
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
    /// The finalized root: `H(leaf_count_be32 ‖ levels.last()[0])`.
    root: Hash,
}

fn build_bmt(leaves: &[Hash]) -> BmtTree {
    build_bmt_with(leaves, |_, _, left, right| h2(left, right))
}

/// The keyed parent of a `Tree` BMT: `H(left ‖ right ‖ u8(len) ‖ sep)`.
fn tree_parent(left: &Hash, right: &Hash, sep: &[u8]) -> Hash {
    let len = u8::try_from(sep.len()).expect("entry names are at most 255 bytes");
    let mut h = Hasher::new();
    h.update(left).update(right).update(&[len]).update(sep);
    h.finalize()
}

/// Index of the first leaf under the right child of the parent at index
/// `parent` whose children are at `level`.
fn first_leaf_of_right_child(level: usize, parent: usize) -> usize {
    (2 * parent + 1) << level
}

/// The keyed `Tree` BMT: every two-child parent commits to the name of
/// the first entry under its right child (SPEC-MERKLE-OBJECTS §3.2).
fn build_tree_bmt(tree: &Tree) -> BmtTree {
    let leaves = tree_leaves(tree);
    build_bmt_with(&leaves, |level, parent, left, right| {
        let sep = &tree.entries[first_leaf_of_right_child(level, parent)].name;
        tree_parent(left, right, sep)
    })
}

/// Build a BMT whose two-child parents are `combine(level, parent_index,
/// left, right)`, where `level` is the children's level. A level with an
/// odd node count duplicates its last node as `H(left ‖ left)`.
fn build_bmt_with(
    leaves: &[Hash],
    combine: impl Fn(usize, usize, &Hash, &Hash) -> Hash,
) -> BmtTree {
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
        let level = levels.len() - 1;
        let mut next = Vec::with_capacity(cur.len().div_ceil(2));
        for (parent, pair) in cur.chunks(2).enumerate() {
            next.push(match pair {
                [left, right] => combine(level, parent, left, right),
                [only] => h2(only, only),
                _ => unreachable!("chunks(2) yields one or two nodes"),
            });
        }
        levels.push(next);
    }
    let tree_root = levels.last().expect("levels is never empty")[0];
    let root = h2(&leaf_count.to_be_bytes(), &tree_root);
    BmtTree {
        leaf_count,
        empty,
        levels,
        root,
    }
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
// TreeProof: keyed tree entry proof
// ---------------------------------------------------------------------------

/// One level of a [`TreeProof`]: the sibling digest and the separator of
/// the parent the sibling shares with the proven node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeProofStep {
    /// The sibling node at this level.
    pub sibling: Hash,
    /// The name of the first entry under the parent's right child.
    pub separator: Vec<u8>,
}

/// A keyed inclusion proof for one `Tree` entry (SPEC-MERKLE-OBJECTS
/// §5.8): the tree's leaf count and one [`TreeProofStep`] per level at
/// which the proven node has a real sibling, bottom-up.
///
/// Bytes are `be32(leaf_count) ‖ varint(n) ‖ n × (sibling ‖ u8(len) ‖
/// separator)`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TreeProof {
    /// The number of entries in the tree.
    pub leaf_count: u32,
    /// The proof steps, bottom-up.
    pub steps: Vec<TreeProofStep>,
}

impl Write for TreeProofStep {
    fn write(&self, writer: &mut impl BufMut) {
        self.sibling.write(writer);
        let len = u8::try_from(self.separator.len()).expect("entry names are at most 255 bytes");
        len.write(writer);
        writer.put_slice(&self.separator);
    }
}

impl EncodeSize for TreeProofStep {
    fn encode_size(&self) -> usize {
        HASH_LEN + 1 + self.separator.len()
    }
}

impl Read for TreeProofStep {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, (): &Self::Cfg) -> Result<Self, CodecError> {
        let sibling = Hash::read(reader)?;
        let len = usize::from(u8::read(reader)?);
        if len == 0 {
            return Err(CodecError::Invalid("TreeProofStep", "empty separator"));
        }
        if reader.remaining() < len {
            return Err(CodecError::EndOfBuffer);
        }
        let mut separator = vec![0u8; len];
        reader.copy_to_slice(&mut separator);
        Ok(Self { sibling, separator })
    }
}

impl Write for TreeProof {
    fn write(&self, writer: &mut impl BufMut) {
        self.leaf_count.write(writer);
        self.steps.write(writer);
    }
}

impl EncodeSize for TreeProof {
    fn encode_size(&self) -> usize {
        self.leaf_count.encode_size() + self.steps.encode_size()
    }
}

impl Read for TreeProof {
    type Cfg = ();

    /// Bounds the step count to `MAX_TREE_PROOF_STEPS` before reading any
    /// step.
    fn read_cfg(reader: &mut impl Buf, (): &Self::Cfg) -> Result<Self, CodecError> {
        let leaf_count = u32::read(reader)?;
        let steps =
            Vec::<TreeProofStep>::read_cfg(reader, &((..=MAX_TREE_PROOF_STEPS).into(), ()))?;
        Ok(Self { leaf_count, steps })
    }
}

impl TreeProof {
    /// Encode to wire bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encode_size());
        self.write(&mut out);
        out
    }

    /// Decode from wire bytes. Rejects more than `MAX_LEVELS` steps, an
    /// empty separator and trailing bytes.
    ///
    /// # Errors
    ///
    /// [`MerkleError::MalformedProof`] on any of those, or on a truncated
    /// buffer.
    pub fn decode(bytes: &[u8]) -> Result<Self, MerkleError> {
        let mut buf = Copying(bytes);
        let proof = Self::read(&mut buf)?;
        if buf.has_remaining() {
            return Err(MerkleError::MalformedProof);
        }
        Ok(proof)
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

fn chunked_leaves(cb: &ChunkedBlob) -> Vec<Hash> {
    let mut leaves = Vec::with_capacity(1 + cb.chunks.len());
    leaves.push(chunked_meta_leaf(cb));
    leaves.extend_from_slice(&cb.chunks);
    leaves
}

fn tree_leaves(tree: &Tree) -> Vec<Hash> {
    tree.entries.iter().map(tree_entry_leaf).collect()
}

// ---------------------------------------------------------------------------
// Inner roots + identity
// ---------------------------------------------------------------------------

/// Bare (pre-wrap) BMT root over a `ChunkedBlob`'s leaves (`[meta] ++
/// chunks`). A commonware-based verifier's `verify_*_inclusion` checks
/// against this; kit callers use the id-based [`verify_chunk`] instead.
#[must_use]
pub fn chunked_inner_root(cb: &ChunkedBlob) -> Hash {
    build_bmt(&chunked_leaves(cb)).root
}

/// Bare (pre-wrap) keyed BMT root over a `Tree`'s entry leaves
/// (SPEC-MERKLE-OBJECTS §3.2). Kit callers verify entries with the
/// id-based [`verify_tree_entry`].
#[must_use]
pub fn tree_inner_root(tree: &Tree) -> Hash {
    build_tree_bmt(tree).root
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

/// Number of steps in the keyed proof of the entry at `position` in a
/// tree of `leaf_count` entries: one per level at which the entry's node
/// has a real sibling.
pub(crate) fn tree_proof_step_count(leaf_count: u32, position: u32) -> Result<usize, MerkleError> {
    Ok(siblings_required_for_multi_proof(leaf_count, [position])?.len())
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
    build_bmt(&chunked_leaves(cb)).proof(position)
}

/// Build a range proof that the chunks at `start..=end` belong to `cb`.
pub fn build_chunks_range_proof(
    cb: &ChunkedBlob,
    start: u32,
    end: u32,
) -> Result<Proof, MerkleError> {
    build_bmt(&chunked_leaves(cb)).range_proof(start, end)
}

/// Build a multi-leaf proof that the chunks at `positions` belong to `cb`.
/// The positions must be strictly ascending.
pub fn build_chunks_multi_proof(
    cb: &ChunkedBlob,
    positions: impl IntoIterator<Item = u32>,
) -> Result<Proof, MerkleError> {
    build_bmt(&chunked_leaves(cb)).multi_proof(positions)
}

/// Build a keyed proof that the entry at `position` (= entry index)
/// belongs to `tree` (SPEC-MERKLE-OBJECTS §5.8).
pub fn build_tree_entry_proof(tree: &Tree, position: u32) -> Result<TreeProof, MerkleError> {
    let leaf_count = u32_of(tree.entries.len());
    if position >= leaf_count {
        return Err(MerkleError::PositionOutOfRange(position));
    }
    let bmt = build_tree_bmt(tree);
    let mut steps = Vec::new();
    let mut index = position as usize;
    for (level, nodes) in bmt.levels.iter().enumerate() {
        if nodes.len() == 1 {
            break;
        }
        let sibling = index ^ 1;
        if sibling < nodes.len() {
            let sep = &tree.entries[first_leaf_of_right_child(level, index / 2)].name;
            steps.push(TreeProofStep {
                sibling: nodes[sibling],
                separator: sep.clone(),
            });
        }
        index /= 2;
    }
    Ok(TreeProof { leaf_count, steps })
}

// ---------------------------------------------------------------------------
// Proof verification — against the object id
// ---------------------------------------------------------------------------

/// Verify that `entry` at `position` belongs to the `Tree` whose id is
/// `tree_id` (SPEC-MERKLE-OBJECTS §5.8). Besides folding to the id, every
/// separator on the path must be a valid entry name, and the entry's name
/// must lie below each separator where the path goes left and at or above
/// it where the path goes right. So an accepted proof also shows that no
/// other position of `tree_id` has a verifiable entry with this name.
pub fn verify_tree_entry(
    tree_id: &Hash,
    entry: &TreeEntry,
    mut position: u32,
    proof: &TreeProof,
) -> Result<(), MerkleError> {
    if position >= proof.leaf_count {
        return Err(MerkleError::PositionOutOfRange(position));
    }
    let mut computed = position_leaf(position, &tree_entry_leaf(entry));
    let mut level_size = proof.leaf_count as usize;
    let mut steps = proof.steps.iter();
    while level_size > 1 {
        let goes_left = position.is_multiple_of(2);
        if goes_left && position as usize + 1 >= level_size {
            computed = h2(&computed, &computed);
        } else {
            let step = steps.next().ok_or(MerkleError::UnalignedProof)?;
            if !TreeEntry::validate_name(&step.separator) {
                return Err(MerkleError::InvalidSeparator);
            }
            let separator = step.separator.as_slice();
            computed = if goes_left {
                if entry.name.as_slice() >= separator {
                    return Err(MerkleError::SeparatorOrder);
                }
                tree_parent(&computed, &step.sibling, separator)
            } else {
                if entry.name.as_slice() < separator {
                    return Err(MerkleError::SeparatorOrder);
                }
                tree_parent(&step.sibling, &computed, separator)
            };
        }
        position /= 2;
        level_size = level_size.div_ceil(2);
    }
    if steps.next().is_some() {
        return Err(MerkleError::UnalignedProof);
    }
    let root = h2(&proof.leaf_count.to_be_bytes(), &computed);
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

    fn sorted_tree(n: usize) -> Tree {
        tree(
            (0..n)
                .map(|i| {
                    let name = format!("e{i:04}");
                    entry(
                        name.as_bytes(),
                        EntryMode::Blob,
                        u8::try_from(i % 256).unwrap(),
                    )
                })
                .collect(),
        )
    }

    #[test]
    fn every_entry_of_a_sorted_tree_verifies() {
        for n in [1usize, 2, 3, 4, 5, 7, 8, 9, 16, 17, 33] {
            let t = sorted_tree(n);
            let id = compute_tree_id(&t);
            for p in 0..u32_of(n) {
                let proof = build_tree_entry_proof(&t, p).unwrap();
                verify_tree_entry(&id, &t.entries[p as usize], p, &proof)
                    .unwrap_or_else(|e| panic!("n={n} p={p}: {e}"));
                let decoded = TreeProof::decode(&proof.encode()).unwrap();
                assert_eq!(decoded, proof);
            }
        }
    }

    #[test]
    fn keyed_fold_changes_ids_of_trees_with_two_or_more_entries() {
        // The keyed parent replaces every two-child parent, so only the
        // empty and one-entry trees keep the unkeyed id.
        for n in [0usize, 1] {
            let t = sorted_tree(n);
            assert_eq!(tree_inner_root(&t), build_bmt(&tree_leaves(&t)).root);
        }
        for n in [2usize, 3, 9] {
            let t = sorted_tree(n);
            assert_ne!(tree_inner_root(&t), build_bmt(&tree_leaves(&t)).root);
        }
    }

    #[test]
    fn a_repeated_name_has_at_most_one_verifiable_entry() {
        // A hostile author's tree: `lib.rs` twice, the second far from the
        // first, with the order broken in between.
        let t = tree(vec![
            entry(b"lib.rs", EntryMode::Blob, 1),
            entry(b"z", EntryMode::Blob, 2),
            entry(b"a", EntryMode::Blob, 3),
            entry(b"lib.rs", EntryMode::Blob, 4),
        ]);
        let id = compute_tree_id(&t);
        let verified: Vec<u32> = (0..4)
            .filter(|&p| t.entries[p as usize].name == b"lib.rs")
            .filter(|&p| {
                let proof = build_tree_entry_proof(&t, p).unwrap();
                verify_tree_entry(&id, &t.entries[p as usize], p, &proof).is_ok()
            })
            .collect();
        assert!(verified.len() <= 1, "verified positions {verified:?}");

        // Two adjacent copies: the left one fails its separator check.
        let t = tree(vec![
            entry(b"lib.rs", EntryMode::Blob, 1),
            entry(b"lib.rs", EntryMode::Blob, 2),
        ]);
        let id = compute_tree_id(&t);
        let left = build_tree_entry_proof(&t, 0).unwrap();
        assert_eq!(
            verify_tree_entry(&id, &t.entries[0], 0, &left),
            Err(MerkleError::SeparatorOrder)
        );
        let right = build_tree_entry_proof(&t, 1).unwrap();
        verify_tree_entry(&id, &t.entries[1], 1, &right).unwrap();
    }

    #[test]
    fn a_name_on_the_wrong_side_of_a_separator_is_rejected() {
        let t = sorted_tree(4);
        let id = compute_tree_id(&t);
        let proof = build_tree_entry_proof(&t, 1).unwrap();
        // Same leaf digest inputs except the name: a name above every
        // separator cannot sit at position 1.
        let mut moved = t.entries[1].clone();
        moved.name = b"zzz".to_vec();
        assert_eq!(
            verify_tree_entry(&id, &moved, 1, &proof),
            Err(MerkleError::SeparatorOrder)
        );
    }

    #[test]
    fn tree_proof_rejects_invalid_separators_and_bad_shapes() {
        let t = sorted_tree(4);
        let id = compute_tree_id(&t);
        let good = build_tree_entry_proof(&t, 0).unwrap();

        let mut bad = good.clone();
        bad.steps[0].separator = b"a/b".to_vec();
        assert_eq!(
            verify_tree_entry(&id, &t.entries[0], 0, &bad),
            Err(MerkleError::InvalidSeparator)
        );

        let mut short = good.clone();
        short.steps.pop();
        assert_eq!(
            verify_tree_entry(&id, &t.entries[0], 0, &short),
            Err(MerkleError::UnalignedProof)
        );

        let mut long = good.clone();
        long.steps.push(good.steps[0].clone());
        assert_eq!(
            verify_tree_entry(&id, &t.entries[0], 0, &long),
            Err(MerkleError::UnalignedProof)
        );

        assert_eq!(
            verify_tree_entry(&id, &t.entries[0], 4, &good),
            Err(MerkleError::PositionOutOfRange(4))
        );
    }

    #[test]
    fn tree_proof_decode_enforces_bounds() {
        let proof = build_tree_entry_proof(&sorted_tree(9), 4).unwrap();
        let bytes = proof.encode();

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            TreeProof::decode(&trailing),
            Err(MerkleError::MalformedProof)
        );
        assert_eq!(
            TreeProof::decode(&bytes[..bytes.len() - 1]),
            Err(MerkleError::MalformedProof)
        );

        // An empty separator: leaf count, one step, sibling, length 0.
        let mut empty_sep = 4u32.to_be_bytes().to_vec();
        empty_sep.push(1);
        empty_sep.extend_from_slice(&[0u8; 32]);
        empty_sep.push(0);
        assert_eq!(
            TreeProof::decode(&empty_sep),
            Err(MerkleError::MalformedProof)
        );

        // 33 steps: rejected from the count, before any step is read.
        let mut too_many = 4u32.to_be_bytes().to_vec();
        too_many.push(33);
        assert_eq!(
            TreeProof::decode(&too_many),
            Err(MerkleError::MalformedProof)
        );
    }

    proptest::proptest! {
        /// In any tree, canonical or not, built with names from a small
        /// alphabet so that names repeat, no name has two positions whose
        /// proofs verify.
        #[test]
        fn no_name_has_two_verifiable_entries(
            names in proptest::collection::vec(proptest::sample::select(vec!["a", "b", "c", "d"]), 1..24)
        ) {
            let t = tree(
                names
                    .iter()
                    .enumerate()
                    .map(|(i, n)| entry(n.as_bytes(), EntryMode::Blob, u8::try_from(i).unwrap()))
                    .collect(),
            );
            let id = compute_tree_id(&t);
            for name in ["a", "b", "c", "d"] {
                let verified = (0..u32_of(t.entries.len()))
                    .filter(|&p| t.entries[p as usize].name == name.as_bytes())
                    .filter(|&p| {
                        let proof = build_tree_entry_proof(&t, p).unwrap();
                        verify_tree_entry(&id, &t.entries[p as usize], p, &proof).is_ok()
                    })
                    .count();
                proptest::prop_assert!(verified <= 1, "{name} verified {verified} times in {names:?}");
            }
        }
    }

    #[test]
    fn range_and_multi_proofs_round_trip() {
        let c = cb(900, 0, &[1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let id = compute_chunked_id(&c);

        let range_proof = build_chunks_range_proof(&c, 2, 4).unwrap();
        verify_chunks_range(&id, 2, &c.chunks[1..=3], &range_proof).unwrap();
        assert!(verify_chunks_range(&id, 2, &c.chunks[1..3], &range_proof).is_err());

        let multi_proof = build_chunks_multi_proof(&c, [1, 4, 8]).unwrap();
        let elements = [(c.chunks[0], 1), (c.chunks[3], 4), (c.chunks[7], 8)];
        verify_chunks_multi(&id, &elements, &multi_proof).unwrap();
        let wrong_elements = [(c.chunks[0], 1), (c.chunks[3], 5), (c.chunks[7], 8)];
        assert!(verify_chunks_multi(&id, &wrong_elements, &multi_proof).is_err());
    }

    #[test]
    fn multi_proofs_require_strictly_ascending_positions() {
        // Nine chunks: BMT positions 1..=9 (position 0 is the metadata leaf).
        let nine = cb(900, 0, &[1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let id = compute_chunked_id(&nine);
        let proof = build_chunks_multi_proof(&nine, [1, 4, 8]).unwrap();
        let pair = |p: u32| (nine.chunks[p as usize - 1], p);

        // The builder names the first position that is lower than its
        // predecessor, in input order.
        assert_eq!(
            build_chunks_multi_proof(&nine, [8, 4, 1]),
            Err(MerkleError::UnsortedPosition(4))
        );
        assert_eq!(
            build_chunks_multi_proof(&nine, [1, 8, 4]),
            Err(MerkleError::UnsortedPosition(4))
        );
        assert_eq!(
            build_chunks_multi_proof(&nine, [1, 4, 4]),
            Err(MerkleError::DuplicatePosition(4))
        );
        assert_eq!(
            build_chunks_multi_proof(&nine, [1, 4, 10]),
            Err(MerkleError::PositionOutOfRange(10))
        );
        // A duplicate that is not adjacent is still a descent.
        assert_eq!(
            build_chunks_multi_proof(&nine, [1, 4, 8, 4]),
            Err(MerkleError::UnsortedPosition(4))
        );

        // The verifier rejects the same orders against a valid proof.
        verify_chunks_multi(&id, &[pair(1), pair(4), pair(8)], &proof).unwrap();
        assert_eq!(
            verify_chunks_multi(&id, &[pair(8), pair(4), pair(1)], &proof),
            Err(MerkleError::UnsortedPosition(4))
        );
        assert_eq!(
            verify_chunks_multi(&id, &[pair(1), pair(8), pair(4)], &proof),
            Err(MerkleError::UnsortedPosition(4))
        );
        assert_eq!(
            verify_chunks_multi(&id, &[pair(1), pair(4), pair(4)], &proof),
            Err(MerkleError::DuplicatePosition(4))
        );
        // Range errors and order errors are reported in input order.
        assert_eq!(
            verify_chunks_multi(&id, &[pair(4), pair(1), (nine.chunks[0], 10)], &proof),
            Err(MerkleError::UnsortedPosition(1))
        );
        assert_eq!(
            verify_chunks_multi(&id, &[pair(4), (nine.chunks[0], 10), pair(1)], &proof),
            Err(MerkleError::PositionOutOfRange(10))
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
            proof.steps.is_empty(),
            "single-leaf tree proof must have zero steps"
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
            verify_chunks_multi(&TREE_EMPTY_ID, &[], &Proof::default()),
            Err(MerkleError::NoPositions)
        );
        assert_eq!(
            verify_tree_entry(
                &TREE_EMPTY_ID,
                &entry(b"a", EntryMode::Blob, 1),
                0,
                &TreeProof::default()
            ),
            Err(MerkleError::PositionOutOfRange(0))
        );

        // The rule holds regardless of `leaf_count`: an empty positions
        // slice is rejected even against a genuinely non-empty chunked
        // blob with an otherwise-valid proof.
        let c = cb(100, 0, &[1]);
        let id = compute_chunked_id(&c);
        let real_proof = build_chunk_proof(&c, 1).unwrap();
        assert_eq!(
            verify_chunks_multi(&id, &[], &real_proof),
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
            build_tree_entry_proof(&empty, 0),
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
        let c = cb(700, 0, &[1, 2, 3, 4, 5, 6]);
        let proof = build_chunk_proof(&c, 6).unwrap();
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
            let ours = build_bmt(&leaves).root;
            assert_eq!(ours, cw_root, "BMT root diverged at n={n}");
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
        chunk.is_ok()
    }

    /// Adversarial single-leaf verification: any `leaf_count`, any
    /// `position`, no sibling digests, any claimed id. `verify_chunk`
    /// never panics or overflows, and the fold succeeds
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
    /// position `>= leaf_count`." For the empty `Tree` every entry proof
    /// request, over every `u32` position, is refused.
    #[kani::proof]
    #[kani::stub(h2, toy_h2)]
    #[kani::stub(crate::hash::domain_digest, toy_domain_digest)]
    #[kani::stub(crate::hash::hash, toy_hash)]
    #[kani::unwind(3)]
    fn merkle_builder_empty_tree_refuses() {
        let empty = Tree {
            entries: Vec::new(),
        };
        let p: u32 = kani::any();
        assert!(
            build_tree_entry_proof(&empty, p).is_err(),
            "empty-Tree entry proof must be refused (SPEC-MERKLE-OBJECTS §5.4)"
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

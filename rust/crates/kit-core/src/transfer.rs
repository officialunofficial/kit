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

mod delta_spool;
pub mod packmap;
pub mod walk;

pub use delta_spool::DeltaSpool;

use std::collections::{HashMap, HashSet};

use crate::delta;
use crate::hash::{self, Hash};
use crate::list_decode::read_list;
use crate::object::{Object, ObjectType};
use crate::pack::{self, delta_fits_reader};
use crate::store::{ObjectStore, StoreError};

use self::walk::{ChunkMemory, HeldCommits, MAX_CHUNK_MEMORY, MAX_HELD_SCAN, PushWalk};

/// Most objects a push walk holds: the held commits it visits, the commits
/// the remote lacks, and the objects the walk keeps. A chunk of a large file counts
/// toward nothing.
pub const MAX_PUSH_WALK: usize = 10_000_000;

/// The limit [`plan_pack_with`] reports when a walk reaches
/// [`MAX_PUSH_WALK`].
pub const PUSH_WALK_LIMIT: &str = "10,000,000-object push walk";

/// The bounds of one push walk. The defaults are the production ones; a test
/// lowers them to cut a walk without building ten million objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalkLimits {
    /// Most visited held commits, new commits and kept objects together.
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

/// The most bytes a packlist node can take: the header, a present `prev`,
/// the longest count prefix and [`PACKLIST_MAX_ENTRIES`] keys, about 32 MB.
/// A download of a node refuses anything longer, so a remote cannot make a
/// client hold a pack-sized "node".
pub const MAX_PACKLIST_NODE_BYTES: u64 = packlist_node_bound(PACKLIST_MAX_ENTRIES as u64);

/// The most bytes a packlist node that lists `packs` packs can take: the
/// header, a present `prev`, the longest count prefix and one key per pack.
/// A writer sizes a node it will write with this before it knows its `prev`.
#[must_use]
pub const fn packlist_node_bound(packs: u64) -> u64 {
    ((PACKLIST_HEADER_LEN + 1 + hash::HASH_LEN + 5) as u64)
        .saturating_add(packs.saturating_mul(hash::HASH_LEN as u64))
}

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
/// "same path, old version". Where a path was a plain blob and is now a
/// [`crate::object::ChunkedBlob`] (a file that grew past `CHUNK_THRESHOLD`),
/// the old blob is the base of every new chunk that shares content with it
/// (`pair_blob_to_chunks`), within a per-file budget. All content reads draw
/// on one push-wide budget (32,768 reads). A path that shrank
/// from a chunked blob to a plain one, or that has no old-side counterpart at
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
    Ok(select_delta_bases(store, new_tip, old_tip)?.chunks)
}

/// The delta bases [`select_delta_bases`] found.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DeltaBases {
    /// `new_hash -> base_hash` for the blobs: changed chunks and small files,
    /// as [`select_chunk_delta_bases`] returns them.
    pub chunks: HashMap<Hash, Hash>,
    /// `new_manifest -> old_manifest` for each path that is a
    /// [`crate::object::ChunkedBlob`] at both tips with a different manifest.
    pub manifests: HashMap<Hash, Hash>,
}

/// [`select_chunk_delta_bases`] together with the manifest of each changed
/// chunked file paired with the manifest it replaces. Every base, of either
/// kind, is an object of `old_tip`'s tree.
///
/// # Errors
///
/// As [`select_chunk_delta_bases`].
pub fn select_delta_bases(
    store: &ObjectStore,
    new_tip: Hash,
    old_tip: Hash,
) -> Result<DeltaBases, StoreError> {
    let mut reads_left = MAX_PUSH_SKETCH_READS;
    select_delta_bases_within(store, new_tip, old_tip, &mut reads_left)
}

/// [`select_delta_bases`] drawing its chunk reads from `reads_left`, which a
/// push shares between all its tips.
fn select_delta_bases_within(
    store: &ObjectStore,
    new_tip: Hash,
    old_tip: Hash,
    reads_left: &mut usize,
) -> Result<DeltaBases, StoreError> {
    let mut out = DeltaBases::default();
    let (Some(new_tree), Some(old_tree)) = (tip_tree(store, new_tip)?, tip_tree(store, old_tip)?)
    else {
        return Ok(out);
    };
    pair_trees(store, new_tree, old_tree, 0, reads_left, &mut out)?;
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
    reads_left: &mut usize,
    out: &mut DeltaBases,
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
                    pair_entry(
                        store,
                        ne.object_hash,
                        oe.object_hash,
                        depth,
                        reads_left,
                        out,
                    )?;
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
/// (#646a), pair the chunks of a file that grew past `CHUNK_THRESHOLD`
/// against its old inline blob, ignore everything else (a file that shrank
/// below the threshold keeps no base: one old chunk is at most a quarter of a
/// 1 MiB blob, so the saving does not repay reading the old chunks).
fn pair_entry(
    store: &ObjectStore,
    new_hash: Hash,
    old_hash: Hash,
    depth: usize,
    reads_left: &mut usize,
    out: &mut DeltaBases,
) -> Result<(), StoreError> {
    match (store.read_object(&new_hash), store.read_object(&old_hash)) {
        (Ok(Object::Tree(_)), Ok(Object::Tree(_))) => {
            pair_trees(store, new_hash, old_hash, depth + 1, reads_left, out)
        }
        (Ok(Object::ChunkedBlob(new_cb)), Ok(Object::ChunkedBlob(old_cb))) => {
            // The manifest the remote holds for this path is the base of the
            // one that replaces it; whether it is sent as a delta is the
            // planner's call.
            out.manifests.entry(new_hash).or_insert(old_hash);
            let spent = pair_chunks(
                store,
                new_cb.chunks(),
                old_cb.chunks(),
                *reads_left,
                &mut out.chunks,
            )?;
            *reads_left -= spent;
            Ok(())
        }
        // A changed same-path small blob: the old blob at this path is a
        // natural delta base for the new one. Never overwrite an
        // existing pairing for `new_hash`, mirroring `pair_chunks`'
        // determinism guarantee.
        (Ok(Object::Blob(_)), Ok(Object::Blob(_))) => {
            out.chunks.entry(new_hash).or_insert(old_hash);
            Ok(())
        }
        // A file that grew past `CHUNK_THRESHOLD`: its old inline blob is the
        // base of the new chunks that share content with it.
        (Ok(Object::ChunkedBlob(new_cb)), Ok(Object::Blob(old_blob))) => {
            let default = BlobBudget::default();
            let budget = BlobBudget {
                reads: default.reads.min(*reads_left),
                ..default
            };
            let spent = pair_blob_to_chunks(
                store,
                new_cb.chunks(),
                old_hash,
                &old_blob.data,
                budget,
                &mut out.chunks,
            )?;
            *reads_left -= spent;
            Ok(())
        }
        // A missing object or the other kind mismatch (a chunked file that
        // shrank to a blob) just yields no pairing for this entry.
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
/// Most chunk reads, old and new together, that pairing one unmatched run of
/// a shifted file may spend sketching content: about 256 MiB of chunk
/// content. Runs whose margins touch count as one run. A run that needs more
/// (a rewritten region, not an edit) is sent raw: a rewrite that large rarely
/// shares content, and finding out costs about as much CPU as the rest of the
/// push.
const MAX_RUN_READS: usize = 4_096;
/// Most chunk reads that pairing may spend sketching content over one push,
/// across every file and every tip: about 2 GiB of chunk content. What is
/// left when the budget runs out is sent raw.
const MAX_PUSH_SKETCH_READS: usize = 32_768;
/// Old chunks on each side of an unmatched run that may also serve as a base,
/// so a new chunk can still pair with a neighbour of the run it replaces.
const ANCHOR_MARGIN: usize = 2;

/// Bytes of the old inline blob sketched together: a chunk's features are
/// its smallest window hashes, so the blob is cut into slices small enough
/// that a window that is among a chunk's smallest is also among its slice's.
const BLOB_FEATURE_SLICE: usize = 4096;
/// What pairing one file that crossed `CHUNK_THRESHOLD` may spend.
#[derive(Clone, Copy)]
struct BlobBudget {
    /// Most new chunks read to look for a share of the old blob: 4,096
    /// chunks are about 256 MiB of content.
    reads: usize,
    /// Most new chunks paired with the one old blob. Each pair costs the
    /// encoder an index of the whole blob, and a blob under
    /// `CHUNK_THRESHOLD` cannot cover more than a few dozen chunks.
    pairs: usize,
    /// Most chunks in a row read without a share of the blob. The blob is at
    /// most `CHUNK_THRESHOLD`, about 16 chunks, so a file whose first 16
    /// chunks (about 1 MiB) share nothing with it is a new file, not the old
    /// one grown.
    misses: usize,
}

impl Default for BlobBudget {
    fn default() -> Self {
        Self {
            reads: 4_096,
            pairs: 256,
            misses: 16,
        }
    }
}

/// Pair the new chunks of a file that grew past `CHUNK_THRESHOLD` with the
/// inline blob it was at the old tip. A new chunk shares content with the
/// blob when one of its min-hash features is one of the blob's, sampled per
/// [`BLOB_FEATURE_SLICE`]; it then takes the blob as its base and the packed
/// cost gate decides whether the delta is sent. A chunk is read once, at most
/// `budget.reads` chunks per file, and at most `budget.pairs` are paired. It
/// stops at `budget.misses` chunks in a row that share nothing. What is left
/// is sent raw. A pairing already made for a chunk stands. Returns the chunk
/// reads it made.
fn pair_blob_to_chunks(
    store: &ObjectStore,
    new_chunks: &[Hash],
    old_blob: Hash,
    old_data: &[u8],
    budget: BlobBudget,
    out: &mut HashMap<Hash, Hash>,
) -> Result<usize, StoreError> {
    // A blob is one object up to the store's object cap, not only up to
    // `CHUNK_THRESHOLD` (another writer may have stored a larger one). Each
    // pair makes the encoder index the whole base, so a large one is left
    // alone, as is any base the decode budget would refuse anyway.
    if !u64::try_from(old_data.len()).is_ok_and(|len| len <= crate::worktree::CHUNK_THRESHOLD) {
        return Ok(0);
    }
    let features: HashSet<u64> = old_data
        .chunks(BLOB_FEATURE_SLICE)
        .flat_map(chunk_features)
        .collect();
    if features.is_empty() {
        return Ok(0);
    }
    let mut seen: HashSet<&Hash> = HashSet::new();
    let (mut reads, mut pairs, mut misses) = (0usize, 0usize, 0usize);
    for nj in new_chunks {
        if reads == budget.reads || pairs == budget.pairs || misses == budget.misses {
            break;
        }
        if *nj == old_blob || out.contains_key(nj) || !seen.insert(nj) {
            continue;
        }
        reads += 1;
        let Some(content) = chunk_bytes(store, nj)? else {
            continue;
        };
        if chunk_features(&content)
            .iter()
            .any(|f| features.contains(f))
        {
            out.insert(*nj, old_blob);
            pairs += 1;
            misses = 0;
        } else {
            misses += 1;
        }
    }
    Ok(reads)
}

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
///   unreliable. Chunk ids present exactly once in both manifests, in the
///   same order, anchor the two files to each other: everything between two
///   anchors is an unmatched run on each side. A changed new chunk is
///   matched by **content similarity** against the old chunks of its own run
///   (and [`ANCHOR_MARGIN`] neighbours) only: index their min-hash
///   super-features, then pick the old chunk sharing the most features
///   (deterministic tiebreak: lowest hash). No overlap means no base and the
///   chunk is sent raw, with no position fallback. Content is read only for
///   the unmatched runs, so a small edit to a large file costs in proportion
///   to the edit; a run that needs more than [`MAX_RUN_READS`] chunk reads,
///   or more than `max_reads` (what is left of the push's budget), is sent
///   raw. A chunk that moved far from where its old version sits and was
///   edited too is outside its run's window and goes raw. Returns the chunk
///   reads made.
fn pair_chunks(
    store: &ObjectStore,
    new_chunks: &[Hash],
    old_chunks: &[Hash],
    max_reads: usize,
    out: &mut HashMap<Hash, Hash>,
) -> Result<usize, StoreError> {
    if old_chunks.is_empty() {
        return Ok(0);
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
        return Ok(0);
    }

    // Each run reads its old chunks plus a margin on either side. Runs whose
    // windows touch are one run, so a chunk is read once however many runs
    // border it.
    let mut windows: Vec<(std::ops::Range<usize>, std::ops::Range<usize>)> = Vec::new();
    for (new_run, old_run) in unmatched_runs(new_chunks, old_chunks) {
        // A run with no new chunk to pair reads nothing.
        if new_chunks[new_run.clone()]
            .iter()
            .all(|nj| old_set.contains(nj))
        {
            continue;
        }
        let lo = old_run.start.saturating_sub(ANCHOR_MARGIN);
        let hi = (old_run.end + ANCHOR_MARGIN).min(old_chunks.len());
        match windows.last_mut() {
            Some((new_prev, old_prev)) if lo <= old_prev.end => {
                new_prev.end = new_run.end;
                old_prev.end = hi;
            }
            _ => windows.push((new_run, lo..hi)),
        }
    }

    let mut budget = max_reads;
    for (new_run, window) in windows {
        let changed = new_chunks[new_run.clone()]
            .iter()
            .filter(|nj| !old_set.contains(*nj))
            .count();
        let reads = changed + window.len();
        if reads > budget.min(MAX_RUN_READS) {
            continue;
        }
        budget -= reads;
        pair_run(
            store,
            &new_chunks[new_run],
            &old_chunks[window],
            &old_set,
            out,
        )?;
    }
    Ok(max_reads - budget)
}

/// Split two manifests, whose chunk counts differ, into the runs between
/// their anchors: chunk ids that occur exactly once in each manifest and
/// keep the same relative order in both (the longest such chain). Each item
/// is a run of new indices with the run of old indices between the same two
/// anchors; either side may be empty. Runs come back in file order.
fn unmatched_runs(
    new_chunks: &[Hash],
    old_chunks: &[Hash],
) -> Vec<(std::ops::Range<usize>, std::ops::Range<usize>)> {
    // Position of each id in the old manifest, or `None` once it repeats.
    let mut old_pos: HashMap<&Hash, Option<usize>> = HashMap::with_capacity(old_chunks.len());
    for (j, oc) in old_chunks.iter().enumerate() {
        old_pos
            .entry(oc)
            .and_modify(|p| *p = None)
            .or_insert(Some(j));
    }
    let mut new_count: HashMap<&Hash, u32> = HashMap::with_capacity(new_chunks.len());
    for nc in new_chunks {
        *new_count.entry(nc).or_default() += 1;
    }
    // (new index, old index) of every id unique on both sides, in new order.
    let candidates: Vec<(usize, usize)> = new_chunks
        .iter()
        .enumerate()
        .filter_map(|(i, nc)| match (old_pos.get(nc), new_count.get(nc)) {
            (Some(Some(j)), Some(1)) => Some((i, *j)),
            _ => None,
        })
        .collect();

    // Longest strictly increasing chain of old indices (patience sorting).
    let mut tails: Vec<usize> = Vec::new(); // index into `candidates`
    let mut prev: Vec<Option<usize>> = vec![None; candidates.len()];
    for (k, &(_, j)) in candidates.iter().enumerate() {
        let at = tails.partition_point(|&t| candidates[t].1 < j);
        prev[k] = at.checked_sub(1).map(|p| tails[p]);
        if at == tails.len() {
            tails.push(k);
        } else {
            tails[at] = k;
        }
    }
    let mut anchors: Vec<(usize, usize)> = Vec::with_capacity(tails.len());
    let mut cur = tails.last().copied();
    while let Some(k) = cur {
        anchors.push(candidates[k]);
        cur = prev[k];
    }
    anchors.reverse();

    // Runs sit between consecutive anchors, with sentinels at both ends.
    let mut runs = Vec::new();
    let (mut ni, mut oj) = (0usize, 0usize);
    for (ai, aj) in anchors
        .into_iter()
        .chain(std::iter::once((new_chunks.len(), old_chunks.len())))
    {
        if ni < ai || oj < aj {
            runs.push((ni..ai, oj..aj));
        }
        (ni, oj) = (ai + 1, aj + 1);
    }
    runs
}

/// Pair the changed chunks of one unmatched run against the old chunks
/// `candidates`, by shared min-hash super-features.
fn pair_run(
    store: &ObjectStore,
    new_run: &[Hash],
    candidates: &[Hash],
    old_set: &HashSet<&Hash>,
    out: &mut HashMap<Hash, Hash>,
) -> Result<(), StoreError> {
    // Index the candidates by their super-features once. An unreadable old
    // chunk (absent / non-blob) contributes no features and can't be a base —
    // it is simply absent from the index.
    let mut feature_index: HashMap<u64, Vec<Hash>> = HashMap::new();
    let mut seen: HashSet<&Hash> = HashSet::with_capacity(candidates.len());
    for oc in candidates {
        if !seen.insert(oc) {
            continue;
        }
        if let Some(content) = chunk_bytes(store, oc)? {
            for f in chunk_features(&content) {
                feature_index.entry(f).or_default().push(*oc);
            }
        }
    }

    for nj in new_run {
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

/// Whether a plan may send a replacement chunk manifest as a delta.
///
/// The manifest of a large file lists every chunk, so a rewrite that changes
/// one chunk still sends a manifest of the file's full length, at about 0.5 MB
/// per GiB of file. A delta against the manifest the remote holds for the path
/// is far smaller, and SPEC-PACKFILE §3.2 already allows it: a delta
/// reconstructs a full object whatever its type. A remote that admits only
/// full manifests must not be sent one, so the caller opts in per remote.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ManifestDeltas {
    /// Every manifest goes in full.
    #[default]
    Full,
    /// A replacement manifest goes as a delta against the manifest at the
    /// same path in the remote head when that is smaller as a framed entry,
    /// and in full otherwise.
    Held,
}

/// What one plan spends encoding manifests as deltas.
#[derive(Debug, Clone, Copy)]
struct ManifestBudget {
    /// Largest manifest, base or replacement, a plan encodes as a delta: each
    /// delta reads and indexes both. A manifest of 16 MiB lists about 32 GiB
    /// of file.
    each: u64,
    /// Most manifest bytes, bases and replacements together, one plan encodes
    /// as deltas; manifests past it go in full.
    plan: u64,
}

impl Default for ManifestBudget {
    fn default() -> Self {
        Self {
            each: 16 << 20,
            plan: 256 << 20,
        }
    }
}

/// One delta entry in a [`PackPlan`]: a target object encoded against a
/// base the remote already holds.
#[derive(Debug, Clone)]
pub struct PlannedDelta {
    /// BLAKE3 of the reconstructed (canonical) object — its storage id.
    pub target: Hash,
    /// BLAKE3 of the base object the delta is applied against.
    pub base: Hash,
    /// SPEC-DELTA instruction stream.
    pub stream: DeltaBytes,
}

/// The SPEC-DELTA stream of a [`PlannedDelta`]: held in memory, or a range
/// of a [`DeltaSpool`]'s file that is read back when its pack is built.
#[derive(Debug, Clone)]
pub enum DeltaBytes {
    /// The stream itself.
    Inline(Vec<u8>),
    /// `len` bytes at `offset` in a spool file.
    Spooled {
        file: std::sync::Arc<std::fs::File>,
        offset: u64,
        len: u64,
    },
}

impl DeltaBytes {
    /// Length of the stream in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::Inline(bytes) => bytes.len(),
            Self::Spooled { len, .. } => usize::try_from(*len).unwrap_or(usize::MAX),
        }
    }

    /// Whether the stream is empty. A valid stream never is.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The stream's bytes: borrowed when inline, read back when spooled.
    ///
    /// # Errors
    /// An I/O error reading a spooled stream back.
    pub fn bytes(&self) -> std::io::Result<std::borrow::Cow<'_, [u8]>> {
        match self {
            Self::Inline(bytes) => Ok(std::borrow::Cow::Borrowed(bytes)),
            Self::Spooled { .. } => self.clone().into_vec().map(std::borrow::Cow::Owned),
        }
    }

    /// The stream's bytes, owned.
    ///
    /// # Errors
    /// An I/O error reading a spooled stream back.
    pub fn into_vec(self) -> std::io::Result<Vec<u8>> {
        match self {
            Self::Inline(bytes) => Ok(bytes),
            Self::Spooled { file, offset, len } => {
                let len = usize::try_from(len)
                    .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
                let mut bytes = vec![0u8; len];
                crate::pack::read_spooled(&file, offset, &mut bytes)?;
                Ok(bytes)
            }
        }
    }
}

impl From<Vec<u8>> for DeltaBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self::Inline(bytes)
    }
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
/// visited held commits, the new commits and the kept objects together pass
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
    plan_pack_tips(store, &[new_tip], old_tip, encode_deltas)
}

/// [`plan_pack_with`] for several tips at once, such as the tags of one push
/// that share a remote head: the union of their closures less what `old_tip`
/// holds, each object once.
///
/// An annotated tag among `new_tips` is peeled ([`PushWalk::run_tips`]): the
/// plan sends the tag objects and what their target's history sends, and its
/// delta bases pair the target's tree with the remote head's.
///
/// # Errors
///
/// As [`plan_pack_with`].
pub fn plan_pack_tips(
    store: &ObjectStore,
    new_tips: &[Hash],
    old_tip: Option<Hash>,
    encode_deltas: impl FnOnce(
        &ObjectStore,
        &[DeltaCandidate],
    ) -> Result<Vec<Option<PlannedDelta>>, StoreError>,
) -> Result<PackPlan, StoreError> {
    plan_tips_capped(
        store,
        new_tips,
        old_tip,
        encode_deltas,
        WalkLimits::default(),
    )
}

/// [`plan_pack_tips`] that may also send replacement manifests as deltas, as
/// `manifests` allows. `encode_deltas` is handed the manifest candidates after
/// the blob ones, in the same batch; a manifest delta it returns is kept only
/// when its framed entry is smaller than the manifest's own.
///
/// # Errors
///
/// As [`plan_pack_tips`].
pub fn plan_pack_tips_with_manifests(
    store: &ObjectStore,
    new_tips: &[Hash],
    old_tip: Option<Hash>,
    manifests: ManifestDeltas,
    encode_deltas: impl FnOnce(
        &ObjectStore,
        &[DeltaCandidate],
    ) -> Result<Vec<Option<PlannedDelta>>, StoreError>,
) -> Result<PackPlan, StoreError> {
    let limits = WalkLimits::default();
    let held = HeldCommits::for_tips(store, new_tips, old_tip, limits.objects)?;
    plan_with_held_manifests(
        store,
        new_tips,
        &held,
        manifests,
        ManifestBudget::default(),
        encode_deltas,
        limits,
    )
}

/// [`plan_pack_with`] with caller-supplied bounds, so a test can cut the walk.
#[cfg(test)]
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
    plan_tips_capped(store, &[new_tip], old_tip, encode_deltas, limits)
}

/// The most annotated tags a push peels from one tip, as a revision peels
/// them. The push walk takes a deeper tag as a closure.
pub const MAX_PEELED_TAGS: usize = 16;

/// The object a tip's tree comes from: the tip with its annotated tags
/// peeled, at most [`MAX_PEELED_TAGS`] deep. A tag whose target this store
/// lacks peels to that target.
///
/// # Errors
/// A store read that fails other than for a missing object.
pub fn peeled_tip(store: &ObjectStore, tip: Hash) -> Result<Hash, StoreError> {
    let mut id = tip;
    for _ in 0..MAX_PEELED_TAGS {
        match store.object_type(&id) {
            Ok(ObjectType::Tag) => {}
            Ok(_) | Err(StoreError::ObjectNotFound(_)) => break,
            Err(e) => return Err(e),
        }
        let Object::Tag(tag) = store.read_object(&id)? else {
            break;
        };
        id = tag.target;
    }
    Ok(id)
}

/// [`plan_pack_tips`] with caller-supplied bounds, so a test can cut the walk.
fn plan_tips_capped(
    store: &ObjectStore,
    new_tips: &[Hash],
    old_tip: Option<Hash>,
    encode_deltas: impl FnOnce(
        &ObjectStore,
        &[DeltaCandidate],
    ) -> Result<Vec<Option<PlannedDelta>>, StoreError>,
    limits: WalkLimits,
) -> Result<PackPlan, StoreError> {
    let held = HeldCommits::for_tips(store, new_tips, old_tip, limits.objects)?;
    plan_with_held(store, new_tips, &held, encode_deltas, limits)
}

fn plan_with_held(
    store: &ObjectStore,
    new_tips: &[Hash],
    held: &HeldCommits,
    encode_deltas: impl FnOnce(
        &ObjectStore,
        &[DeltaCandidate],
    ) -> Result<Vec<Option<PlannedDelta>>, StoreError>,
    limits: WalkLimits,
) -> Result<PackPlan, StoreError> {
    plan_with_held_manifests(
        store,
        new_tips,
        held,
        ManifestDeltas::Full,
        ManifestBudget::default(),
        encode_deltas,
        limits,
    )
}

fn plan_with_held_manifests(
    store: &ObjectStore,
    new_tips: &[Hash],
    held: &HeldCommits,
    manifests: ManifestDeltas,
    manifest_budget: ManifestBudget,
    encode_deltas: impl FnOnce(
        &ObjectStore,
        &[DeltaCandidate],
    ) -> Result<Vec<Option<PlannedDelta>>, StoreError>,
    limits: WalkLimits,
) -> Result<PackPlan, StoreError> {
    let walk = PushWalk::run_tips(store, new_tips, held, limits, None)?;
    let mut base_map = HashMap::new();
    let mut manifest_bases = HashMap::new();
    if let Some(old) = held.tip() {
        let mut reads_left = MAX_PUSH_SKETCH_READS;
        for &tip in new_tips {
            // A tip the head holds sends no blob, so it needs no delta base.
            let peeled = peeled_tip(store, tip)?;
            if held.contains(&peeled) {
                continue;
            }
            let bases = select_delta_bases_within(store, peeled, old, &mut reads_left)?;
            for (target, base) in bases.chunks {
                base_map.entry(target).or_insert(base);
            }
            if manifests == ManifestDeltas::Held {
                for (target, base) in bases.manifests {
                    manifest_bases.entry(target).or_insert(base);
                }
            }
        }
    }

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
    // The walk checks each chunk as a fetch checks it, except that it takes
    // the length a replaced manifest states for the same chunk. A bad chunk
    // fails the plan before anything is uploaded.
    walk.for_each_chunk(store, &mut memory, |_, _, _, chunk| {
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

    // A replacement manifest is a candidate too, after the blobs, when the
    // caller allows it: against the manifest at its path in the remote head,
    // which this store must hold, and only while the work stays within the
    // per-manifest and per-plan bounds.
    let mut manifest_left = manifest_budget.plan;
    for h in &non_blob_raw {
        let Some(&base) = manifest_bases.get(h) else {
            continue;
        };
        if !store.contains(&base) {
            continue;
        }
        let (target_len, base_len) = (store.object_size(h)?, store.object_size(&base)?);
        let work = target_len.saturating_add(base_len);
        if target_len > manifest_budget.each
            || base_len > manifest_budget.each
            || work > manifest_left
        {
            continue;
        }
        manifest_left -= work;
        candidates.push(DeltaCandidate { target: *h, base });
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
    let mut raw = Vec::with_capacity(non_blob_raw.len());
    let mut deltas = Vec::with_capacity(encoded.len());
    for h in non_blob_raw {
        // A manifest goes as its delta only when that is smaller on the wire
        // as the entry a pack writer frames, which compresses a manifest and
        // a delta stream alike: a stream shorter than the manifest can still
        // lose to the manifest's own compressed entry.
        match encoded.remove(&h) {
            Some(planned) if manifest_delta_wins(store, &planned)? => deltas.push(planned),
            _ => raw.push(h),
        }
    }
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

/// Whether `planned`, a delta of a manifest, takes fewer bytes in a pack than
/// the manifest in full, each as the framed entry a pack writer emits.
fn manifest_delta_wins(store: &ObjectStore, planned: &PlannedDelta) -> Result<bool, StoreError> {
    let stream = planned.stream.bytes().map_err(StoreError::Io)?;
    let full = store.read(&planned.target)?;
    Ok(pack::delta_entry_len(&stream) < pack::raw_entry_len(&full))
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
            stream: DeltaBytes::Inline(stream),
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

    /// The bound is the node with a prior pointer, one key per pack and four
    /// spare bytes beyond a one-byte count prefix: never shorter than the
    /// node itself.
    #[test]
    fn the_packlist_node_bound_covers_every_node_it_sizes() {
        for packs in [0_usize, 1, 2, 127, 128, 1_000, 16_383, 16_384] {
            let keys = vec![[7u8; 32]; packs];
            let node = encode_packlist(Some([1u8; 32]), &keys).unwrap().len() as u64;
            let prefix = if packs < 128 {
                1
            } else if packs < 16_384 {
                2
            } else {
                3
            };
            assert_eq!(packlist_node_bound(packs as u64), node + 5 - prefix);
            assert!(encode_packlist(None, &keys).unwrap().len() as u64 <= node);
        }
        assert_eq!(
            MAX_PACKLIST_NODE_BYTES,
            packlist_node_bound(u64::from(PACKLIST_MAX_ENTRIES))
        );
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

    /// The largest node `encode_packlist` makes, with a `prev`, fits the
    /// download bound exactly.
    #[test]
    fn the_largest_node_fits_the_node_download_bound() {
        let packs = vec![[1u8; 32]; PACKLIST_MAX_ENTRIES as usize];
        let node = encode_packlist(Some([2u8; 32]), &packs).unwrap();
        assert!(node.len() as u64 <= MAX_PACKLIST_NODE_BYTES);
        assert!(MAX_PACKLIST_NODE_BYTES - (node.len() as u64) < 8);
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
            w.push_delta(&d.base, &d.stream.bytes().unwrap()).unwrap();
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
    fn a_shifted_file_over_the_read_budget_sends_its_changed_chunks_raw() {
        // old = [A,B,C,D,E]; new = [B,C,D,E']: counts differ, and E' is E with
        // one byte changed. The one unmatched run is E' against E and the two
        // old chunks before it: four chunk reads. With that many reads E'
        // pairs with E; one fewer, nothing pairs. The budget is inclusive.
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
        assert_eq!(pair(4), HashMap::from([(new[3], old[4])]));
        assert!(pair(3).is_empty());
        // Equal counts need no content reads, so the budget does not apply.
        let mut out = HashMap::new();
        pair_chunks(&s, &new, &new, 0, &mut out).unwrap();
        assert!(out.is_empty());
        let mut same_count = old.clone();
        same_count[4] = new[3];
        pair_chunks(&s, &same_count, &old, 0, &mut out).unwrap();
        assert_eq!(out, HashMap::from([(new[3], old[4])]));
    }

    /// `n` distinct chunks of `len` bytes, seeded from `base`.
    fn distinct_chunks(base: u8, n: usize, len: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| chunk_content(base.wrapping_add(u8::try_from(i).unwrap()), len))
            .collect()
    }

    /// `chunk` with one byte flipped near the middle: similar, not identical.
    fn tweaked(chunk: &[u8]) -> Vec<u8> {
        let mut c = chunk.to_vec();
        c[chunk.len() / 2] ^= 0xFF;
        c
    }

    /// Bytes the pairing `bases` would put on the wire for the new chunks it
    /// names: each target as its delta when that is smaller, else raw.
    fn pairing_cost(s: &ObjectStore, bases: &HashMap<Hash, Hash>) -> usize {
        bases
            .iter()
            .map(|(&target, &base)| {
                let raw = s.read(&target).unwrap().len();
                encode_delta_candidate(s, DeltaCandidate { target, base })
                    .unwrap()
                    .map_or(raw, |d| d.stream.bytes().unwrap().len())
            })
            .sum()
    }

    /// Wire bytes of every new chunk `bases` leaves out: sent raw.
    fn unpaired_cost(
        s: &ObjectStore,
        new: &[Hash],
        old: &[Hash],
        bases: &HashMap<Hash, Hash>,
    ) -> usize {
        let old: HashSet<&Hash> = old.iter().collect();
        let mut seen = HashSet::new();
        new.iter()
            .filter(|h| !old.contains(h) && !bases.contains_key(*h) && seen.insert(**h))
            .map(|h| s.read(h).unwrap().len())
            .sum()
    }

    /// Pair `new` against `old` with the anchored algorithm and with the
    /// whole-manifest sketch it replaced, and require the anchored result to
    /// send no more bytes. Returns the anchored pairing.
    fn assert_anchored_pairing_is_no_worse(
        s: &ObjectStore,
        new: &[Vec<u8>],
        old: &[Vec<u8>],
    ) -> HashMap<Hash, Hash> {
        let new: Vec<Hash> = new.iter().map(|c| put_blob(s, c.clone())).collect();
        let old: Vec<Hash> = old.iter().map(|c| put_blob(s, c.clone())).collect();
        let mut anchored = HashMap::new();
        pair_chunks(s, &new, &old, MAX_PUSH_SKETCH_READS, &mut anchored).unwrap();
        let mut full = HashMap::new();
        let old_set: HashSet<&Hash> = old.iter().collect();
        pair_run(s, &new, &old, &old_set, &mut full).unwrap();
        let cost = |b: &HashMap<Hash, Hash>| pairing_cost(s, b) + unpaired_cost(s, &new, &old, b);
        assert!(
            cost(&anchored) <= cost(&full),
            "anchored pairing sends {} bytes, whole-manifest sketch {}",
            cost(&anchored),
            cost(&full)
        );
        anchored
    }

    #[test]
    fn an_edit_in_the_middle_pairs_inside_its_run_and_reads_only_that_run() {
        let (_d, s) = store();
        let old = distinct_chunks(1, 40, 2_000);
        // C20 is replaced by two chunks that each keep half of it, so the
        // count differs and the manifests are shifted.
        let mut new = old.clone();
        let (lo, hi) = old[20].split_at(1_000);
        new.splice(20..21, [tweaked(lo), tweaked(hi)]);
        let bases = assert_anchored_pairing_is_no_worse(&s, &new, &old);
        assert_eq!(bases.len(), 2, "both halves pair");
        let c20 = put_blob(&s, old[20].clone());
        assert!(bases.values().all(|b| *b == c20));

        // Two new chunks and the old run plus its margin: 2 + 5 reads. A
        // whole-manifest sketch would need 80.
        let new_ids: Vec<Hash> = new.iter().map(|c| put_blob(&s, c.clone())).collect();
        let old_ids: Vec<Hash> = old.iter().map(|c| put_blob(&s, c.clone())).collect();
        let mut tight = HashMap::new();
        let spent = pair_chunks(&s, &new_ids, &old_ids, 7, &mut tight).unwrap();
        assert_eq!(tight, bases);
        assert_eq!(spent, 7);
        let mut starved = HashMap::new();
        let spent = pair_chunks(&s, &new_ids, &old_ids, 6, &mut starved).unwrap();
        assert!(starved.is_empty());
        assert_eq!(spent, 0);
    }

    /// Pair `new` against `old` with a read budget of `max_reads`.
    fn pair_with_budget(
        s: &ObjectStore,
        new: &[Vec<u8>],
        old: &[Vec<u8>],
        max_reads: usize,
    ) -> HashMap<Hash, Hash> {
        let ids = |chunks: &[Vec<u8>]| -> Vec<Hash> {
            chunks.iter().map(|c| put_blob(s, c.clone())).collect()
        };
        let mut out = HashMap::new();
        pair_chunks(s, &ids(new), &ids(old), max_reads, &mut out).unwrap();
        out
    }

    #[test]
    fn runs_whose_windows_overlap_read_each_old_chunk_once() {
        let (_d, s) = store();
        let old = distinct_chunks(1, 40, 2_000);
        // C10 and C12 are each followed by a fresh chunk and edited: two runs
        // two chunks apart, so their margins share old chunks 10 and 11.
        let mut new = old.clone();
        new.splice(12..13, [tweaked(&old[12]), chunk_content(150, 2_000)]);
        new.splice(10..11, [tweaked(&old[10]), chunk_content(151, 2_000)]);
        let bases = assert_anchored_pairing_is_no_worse(&s, &new, &old);
        assert_eq!(bases.len(), 2);
        // One window of old chunks 8..15 (7) and four changed chunks: 11
        // reads. Charged per run it would be 14.
        assert_eq!(pair_with_budget(&s, &new, &old, 11), bases);
        assert!(pair_with_budget(&s, &new, &old, 10).is_empty());
    }

    #[test]
    fn runs_far_apart_are_read_separately_and_share_one_budget() {
        let (_d, s) = store();
        let old = distinct_chunks(1, 40, 2_000);
        // Each of C5 and C30 is edited and followed by a fresh chunk. Each
        // run reads 2 new chunks and 5 old ones.
        let mut new = old.clone();
        new.splice(30..31, [tweaked(&old[30]), chunk_content(150, 2_000)]);
        new.splice(5..6, [tweaked(&old[5]), chunk_content(151, 2_000)]);
        let both = pair_with_budget(&s, &new, &old, 14);
        assert_eq!(both.len(), 2);
        // Merged into one window the two would read 34 chunks; and the first
        // run's reads come out of the budget the second draws on.
        let first_only = pair_with_budget(&s, &new, &old, 13);
        assert_eq!(first_only.len(), 1);
        let c5 = put_blob(&s, old[5].clone());
        assert_eq!(first_only.values().next(), Some(&c5));
        assert!(pair_with_budget(&s, &new, &old, 6).is_empty());
    }

    #[test]
    fn an_edit_at_the_start_pairs_inside_its_run() {
        let (_d, s) = store();
        let old = distinct_chunks(1, 30, 2_000);
        let mut new = old.clone();
        let (lo, hi) = old[0].split_at(900);
        new.splice(0..1, [tweaked(lo), tweaked(hi)]);
        let bases = assert_anchored_pairing_is_no_worse(&s, &new, &old);
        assert_eq!(bases.len(), 2);
        // Two new chunks and old chunks 0..3: five reads, not the file's 62.
        assert_eq!(pair_with_budget(&s, &new, &old, 5), bases);
        assert!(pair_with_budget(&s, &new, &old, 4).is_empty());
    }

    #[test]
    fn an_edit_at_the_end_pairs_inside_its_run() {
        let (_d, s) = store();
        let old = distinct_chunks(1, 30, 2_000);
        let mut new = old.clone();
        let (lo, hi) = old[29].split_at(900);
        new.splice(29..30, [tweaked(lo), tweaked(hi)]);
        let bases = assert_anchored_pairing_is_no_worse(&s, &new, &old);
        assert_eq!(bases.len(), 2);
        // Two new chunks and old chunks 27..30: five reads.
        assert_eq!(pair_with_budget(&s, &new, &old, 5), bases);
        assert!(pair_with_budget(&s, &new, &old, 4).is_empty());
    }

    #[test]
    fn an_insertion_that_shifts_every_later_chunk_sends_only_the_new_chunk() {
        let (_d, s) = store();
        let old = distinct_chunks(1, 30, 2_000);
        let fresh = chunk_content(200, 2_000);
        let mut new = old.clone();
        new.insert(12, fresh.clone());
        let bases = assert_anchored_pairing_is_no_worse(&s, &new, &old);
        // Nothing resembles the inserted chunk, so it goes raw and every
        // other chunk dedups.
        assert!(bases.is_empty());
    }

    #[test]
    fn an_insertion_resembling_a_neighbour_pairs_with_it() {
        let (_d, s) = store();
        let old = distinct_chunks(1, 30, 2_000);
        let mut new = old.clone();
        // A new chunk between C11 and C12 that is a copy of C11 with an edit:
        // the old run is empty, so the margin is what supplies the base.
        new.insert(12, tweaked(&old[11]));
        let bases = assert_anchored_pairing_is_no_worse(&s, &new, &old);
        assert_eq!(
            bases.get(&put_blob(&s, tweaked(&old[11]))),
            Some(&put_blob(&s, old[11].clone()))
        );
    }

    #[test]
    fn a_file_with_no_shared_chunks_pairs_like_the_whole_manifest_sketch() {
        let (_d, s) = store();
        let old = distinct_chunks(1, 20, 2_000);
        // Every chunk changed a little, and the count differs.
        let new: Vec<Vec<u8>> = old.iter().take(18).map(|c| tweaked(c)).collect();
        let bases = assert_anchored_pairing_is_no_worse(&s, &new, &old);
        assert_eq!(bases.len(), 18);
        // Wholly unrelated content pairs with nothing.
        let unrelated = distinct_chunks(100, 25, 2_000);
        let bases = assert_anchored_pairing_is_no_worse(&s, &unrelated, &old);
        assert!(bases.is_empty());
    }

    #[test]
    fn repeated_and_reordered_chunks_pair_without_a_wrong_base() {
        let (_d, s) = store();
        let c = distinct_chunks(1, 6, 2_000);
        // A repeated id is never an anchor; swapped neighbours keep only one
        // of the two as an anchor. The result must still be a valid pairing:
        // every base is a chunk of the old manifest and no target is a base.
        let old = vec![
            c[0].clone(),
            c[1].clone(),
            c[1].clone(),
            c[2].clone(),
            c[3].clone(),
            c[4].clone(),
        ];
        let new = vec![
            c[0].clone(),
            c[3].clone(),
            c[2].clone(),
            tweaked(&c[1]),
            c[4].clone(),
            c[5].clone(),
            c[5].clone(),
        ];
        let bases = assert_anchored_pairing_is_no_worse(&s, &new, &old);
        let old_ids: HashSet<Hash> = old.iter().map(|x| put_blob(&s, x.clone())).collect();
        assert!(bases.values().all(|b| old_ids.contains(b)));
        assert!(bases.keys().all(|t| !old_ids.contains(t)));
    }

    #[test]
    fn a_manifest_of_one_repeated_chunk_has_no_anchors_and_stays_bounded() {
        let (_d, s) = store();
        let a = put_blob(&s, chunk_content(1, 2_000));
        let b = put_blob(&s, tweaked(&chunk_content(1, 2_000)));
        let old = vec![a; 500];
        let new = vec![b; 700];
        let mut out = HashMap::new();
        // One run of 700 new and 500 old chunks: over a budget of 1,000.
        pair_chunks(&s, &new, &old, 1_000, &mut out).unwrap();
        assert!(out.is_empty());
        pair_chunks(&s, &new, &old, 1_200, &mut out).unwrap();
        assert_eq!(out, HashMap::from([(b, a)]));
    }

    #[test]
    fn a_run_over_the_per_run_bound_is_sent_raw_whatever_the_budget_left() {
        let (_d, s) = store();
        let a = put_blob(&s, chunk_content(1, 2_000));
        let b = put_blob(&s, tweaked(&chunk_content(1, 2_000)));
        // One run of 1,000 new and the rest of MAX_RUN_READS old chunks (the
        // counts differ, so the run is read): exactly the bound, so it pairs;
        // one more new chunk and it is sent raw.
        let old = vec![a; MAX_RUN_READS - 1_000];
        let mut out = HashMap::new();
        let spent = pair_chunks(&s, &vec![b; 1_000], &old, usize::MAX, &mut out).unwrap();
        assert_eq!(out, HashMap::from([(b, a)]));
        assert_eq!(spent, MAX_RUN_READS);
        let mut out = HashMap::new();
        let spent = pair_chunks(&s, &vec![b; 1_001], &old, usize::MAX, &mut out).unwrap();
        assert!(out.is_empty());
        assert_eq!(spent, 0);
    }

    #[test]
    fn unmatched_runs_lie_between_the_longest_ordered_chain_of_shared_ids() {
        let h = |n: u8| [n; 32];
        // old: 1 2 3 4 5; new: 1 9 3 2 4 5 — 2 and 3 cross, so one of them
        // anchors with 1, 4 and 5.
        let old = [h(1), h(2), h(3), h(4), h(5)];
        let new = [h(1), h(9), h(3), h(2), h(4), h(5)];
        let runs = unmatched_runs(&new, &old);
        // The longest chain is 1, 2, 4, 5 (old positions 0, 1, 3, 4): the
        // run 9, 3 sits against nothing, and old 3 against nothing.
        assert_eq!(runs, vec![(1..3, 1..1), (4..4, 2..3)]);
        // Identical manifests have no runs; disjoint ones are one run.
        assert!(unmatched_runs(&old, &old).is_empty());
        assert_eq!(unmatched_runs(&[h(7), h(8)], &old), vec![(0..2, 0..5)]);
    }

    #[test]
    fn a_re_push_after_an_edit_round_trips_for_every_edit_position() {
        let v1 = big_buffer()[..1 << 20].to_vec();
        let edit_len = 20_000;
        let cases: Vec<(&str, Vec<u8>)> = {
            let patch: Vec<u8> = chunk_content(77, edit_len);
            let mut start = v1.clone();
            start.splice(0..edit_len, patch.clone());
            let mut end = v1.clone();
            let at = end.len() - edit_len;
            end.splice(at.., patch.clone());
            let mut middle = v1.clone();
            let mid = middle.len() / 2;
            middle.splice(mid..mid + edit_len, patch.clone());
            let mut insert = v1.clone();
            let mid = insert.len() / 2;
            insert.splice(mid..mid, patch.clone());
            let mut delete = v1.clone();
            delete.drain(mid..mid + edit_len);
            let unrelated = chunk_content(78, v1.len());
            vec![
                ("start", start),
                ("end", end),
                ("middle", middle),
                ("insert", insert),
                ("delete", delete),
                ("unrelated", unrelated),
            ]
        };
        for (name, v2) in cases {
            let (_d, s) = store();
            let file1 = put_chunked(&s, &v1);
            let c1 = commit_with_file(&s, file1, vec![], "v1");
            let file2 = put_chunked(&s, &v2);
            let c2 = commit_with_file(&s, file2, vec![c1], name);
            let plan = plan_pack(&s, c2, Some(c1)).unwrap();
            assert_pack_reconstructs(&s, &plan, c1, c2);
            if name == "insert" || name == "delete" {
                // The chunk at the edit is cut in two, so the counts differ
                // and its halves delta against it.
                assert!(!plan.deltas.is_empty(), "{name}: expected a delta");
            }
            // Never more than sending every new chunk raw.
            let mut w = PackWriter::new();
            for h in &plan.raw {
                w.push_raw(*h, &s.read(h).unwrap()).unwrap();
            }
            for d in &plan.deltas {
                w.push_delta(&d.base, &d.stream.bytes().unwrap()).unwrap();
            }
            let sent = w.finish().unwrap().len();
            assert!(
                sent <= v2.len() + 4_096,
                "{name}: pack of {sent} bytes for a {} byte file",
                v2.len()
            );
        }
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

    // =================================================================
    // A path that was an inline blob and is now a chunked file (it grew
    // past CHUNK_THRESHOLD): the old blob is the base of the new chunks
    // that share content with it.
    // =================================================================

    /// An old inline blob of `len` bytes and the commit that holds it.
    fn inline_old_tip(s: &ObjectStore, seed: u8, len: usize) -> (Vec<u8>, Hash, Hash) {
        let content = chunk_content(seed, len);
        let blob = put_blob(s, content.clone());
        let tip = commit_with_named_file(s, b"doc.bin", blob, vec![], "old");
        (content, blob, tip)
    }

    /// A commit that holds `chunks` as the chunked file at the old tip's path.
    fn chunked_new_tip(s: &ObjectStore, chunks: &[Vec<u8>], old_tip: Hash) -> Hash {
        let file = put_chunked_from(s, chunks);
        commit_with_named_file(s, b"doc.bin", file, vec![old_tip], "new")
    }

    #[test]
    fn inline_blob_that_became_chunked_is_the_base_of_its_shared_chunks() {
        let (_d, s) = store();
        let (old, old_blob, c_old) = inline_old_tip(&s, 1, 600_000);
        // The file grew: its first 200 kB and the rest survive, an unrelated
        // block sits between them and a tail was appended.
        let kept_head = old[..200_000].to_vec();
        let unrelated = chunk_content(2, 100_000);
        let mut kept_tail = old[200_000..].to_vec();
        kept_tail.extend_from_slice(&chunk_content(3, 50_000));
        let c_new = chunked_new_tip(
            &s,
            &[kept_head.clone(), unrelated.clone(), kept_tail.clone()],
            c_old,
        );

        let bases = select_chunk_delta_bases(&s, c_new, c_old).unwrap();
        assert_eq!(bases.get(&put_blob(&s, kept_head.clone())), Some(&old_blob));
        assert_eq!(bases.get(&put_blob(&s, kept_tail.clone())), Some(&old_blob));
        assert!(
            !bases.contains_key(&put_blob(&s, unrelated.clone())),
            "a chunk with nothing in common with the blob has no base"
        );
        // The remote holds every base: each is an object of the old tip.
        let held = crate::ops::reachable_objects(&s, &c_old).unwrap();
        assert!(bases.values().all(|base| held.contains(base)));

        // The plan sends the shared chunks as deltas, far under their raw
        // size, and the pack rebuilds every object under its id.
        let plan = plan_pack(&s, c_new, Some(c_old)).unwrap();
        for chunk in [&kept_head, &kept_tail] {
            let id = put_blob(&s, chunk.clone());
            let delta = plan.deltas.iter().find(|d| d.target == id).unwrap();
            assert_eq!(delta.base, old_blob);
            // The head is all copies; the tail adds 50 kB of new bytes.
            assert!(hash::HASH_LEN + delta.stream.len() < chunk.len() - 140_000);
            assert!(!plan.raw.contains(&id));
        }
        assert!(plan.raw.contains(&put_blob(&s, unrelated)));
        assert_pack_reconstructs(&s, &plan, c_old, c_new);
    }

    #[test]
    fn a_chunked_file_that_shrank_to_an_inline_blob_keeps_no_base() {
        let (_d, s) = store();
        let old = chunk_content(1, 400_000);
        let old_file = put_chunked_from(&s, &[old[..200_000].to_vec(), old[200_000..].to_vec()]);
        let c_old = commit_with_named_file(&s, b"doc.bin", old_file, vec![], "old");
        let new_blob = put_blob(&s, old[..300_000].to_vec());
        let c_new = commit_with_named_file(&s, b"doc.bin", new_blob, vec![c_old], "new");

        assert!(
            select_chunk_delta_bases(&s, c_new, c_old)
                .unwrap()
                .is_empty()
        );
        let plan = plan_pack(&s, c_new, Some(c_old)).unwrap();
        assert!(plan.deltas.is_empty());
        assert_pack_reconstructs(&s, &plan, c_old, c_new);
    }

    #[test]
    fn a_missing_inline_base_leaves_the_chunks_raw() {
        let (_d, s) = store();
        let old = chunk_content(1, 300_000);
        // The old tip names a blob this store does not hold: nothing to read,
        // so no pairing, and the push plans every chunk raw rather than fail.
        let absent = Object::Blob(Blob { data: old.clone() }).id().unwrap();
        let c_old = commit_with_named_file(&s, b"doc.bin", absent, vec![], "old");
        let c_new = chunked_new_tip(
            &s,
            &[old[..150_000].to_vec(), old[150_000..].to_vec()],
            c_old,
        );
        assert!(
            select_chunk_delta_bases(&s, c_new, c_old)
                .unwrap()
                .is_empty()
        );
        let plan = plan_pack(&s, c_new, Some(c_old)).unwrap();
        assert!(plan.deltas.is_empty());
    }

    #[test]
    fn a_declined_inline_base_delta_sends_the_chunk_raw() {
        let (_d, s) = store();
        let (old, _, c_old) = inline_old_tip(&s, 1, 300_000);
        let head = old[..150_000].to_vec();
        let c_new = chunked_new_tip(&s, &[head.clone(), old[150_000..].to_vec()], c_old);
        // An encoder that finds no delta worth sending (the packed-cost
        // gate's answer for a chunk whose delta loses) leaves it raw.
        let plan = plan_pack_with(&s, c_new, Some(c_old), |_, candidates| {
            assert!(!candidates.is_empty());
            Ok(vec![None; candidates.len()])
        })
        .unwrap();
        assert!(plan.deltas.is_empty());
        assert!(plan.raw.contains(&put_blob(&s, head)));
        assert_pack_reconstructs(&s, &plan, c_old, c_new);
    }

    #[test]
    fn an_inline_blob_over_the_threshold_is_not_a_base() {
        let (_d, s) = store();
        let big = usize::try_from(crate::worktree::CHUNK_THRESHOLD).unwrap() + 1;
        let old = chunk_content(1, big);
        let chunks = vec![old[..40_000].to_vec()];
        let (_, out) = pair_blob_within(&s, &old, &chunks, BlobBudget::default());
        assert!(out.is_empty());
        // At the threshold it is still a base.
        let old = chunk_content(1, big - 1);
        let (old_blob, out) = pair_blob_within(&s, &old, &chunks, BlobBudget::default());
        assert_eq!(out.get(&put_blob(&s, chunks[0].clone())), Some(&old_blob));
    }

    #[test]
    fn an_inline_blob_is_never_its_own_chunk_base() {
        let (_d, s) = store();
        let old = chunk_content(1, 40_000);
        // A new chunk that is byte-identical to the old blob has its id.
        let (_, out) =
            pair_blob_within(&s, &old, std::slice::from_ref(&old), BlobBudget::default());
        assert!(out.is_empty());
    }

    #[test]
    fn an_earlier_pairing_for_a_chunk_stands() {
        let (_d, s) = store();
        let old = chunk_content(1, 100_000);
        let old_blob = put_blob(&s, old.clone());
        let chunk = put_blob(&s, old[..40_000].to_vec());
        let other = [9u8; 32];
        let mut out = HashMap::from([(chunk, other)]);
        pair_blob_to_chunks(
            &s,
            &[chunk],
            old_blob,
            &old,
            BlobBudget::default(),
            &mut out,
        )
        .unwrap();
        assert_eq!(out.get(&chunk), Some(&other));
    }

    /// `pair_blob_to_chunks` on the `chunks` of a file whose old tip held
    /// `old` as one blob, within `budget`.
    fn pair_blob_within(
        s: &ObjectStore,
        old: &[u8],
        chunks: &[Vec<u8>],
        budget: BlobBudget,
    ) -> (Hash, HashMap<Hash, Hash>) {
        let old_blob = put_blob(s, old.to_vec());
        let ids: Vec<Hash> = chunks.iter().map(|c| put_blob(s, c.clone())).collect();
        let mut out = HashMap::new();
        pair_blob_to_chunks(s, &ids, old_blob, old, budget, &mut out).unwrap();
        (old_blob, out)
    }

    /// `n` distinct chunks, each a slice of `old` with one byte changed, so
    /// every one shares features with it.
    fn variants_of(old: &[u8], n: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| {
                let mut chunk = old[20_000..60_000].to_vec();
                chunk[i] ^= 0xFF;
                chunk
            })
            .collect()
    }

    #[test]
    fn inline_base_pairing_stops_at_its_pair_cap() {
        let (_d, s) = store();
        let old = chunk_content(1, 100_000);
        let chunks = variants_of(&old, 6);
        let budget = BlobBudget {
            reads: 100,
            pairs: 4,
            ..BlobBudget::default()
        };
        let (old_blob, out) = pair_blob_within(&s, &old, &chunks, budget);
        assert_eq!(out.len(), 4);
        assert!(out.values().all(|base| *base == old_blob));
        // The first chunks in file order are the ones paired.
        for chunk in &chunks[..4] {
            assert!(out.contains_key(&put_blob(&s, chunk.clone())));
        }
    }

    #[test]
    fn inline_base_sketching_stops_at_its_read_budget() {
        let (_d, s) = store();
        let old = chunk_content(1, 100_000);
        // The budget goes on chunks with nothing in common with the blob; a
        // chunk past it is not read, even though it shares content.
        let mut chunks: Vec<Vec<u8>> = (0..3).map(|i| chunk_content(10 + i, 4_096)).collect();
        chunks.push(old[..40_000].to_vec());
        let budget = BlobBudget {
            reads: 3,
            pairs: 100,
            ..BlobBudget::default()
        };
        let (_, out) = pair_blob_within(&s, &old, &chunks, budget);
        assert!(out.is_empty());
        // One more read and the same chunk pairs.
        let budget = BlobBudget {
            reads: 4,
            pairs: 100,
            ..BlobBudget::default()
        };
        let (old_blob, out) = pair_blob_within(&s, &old, &chunks, budget);
        assert_eq!(out.get(&put_blob(&s, chunks[3].clone())), Some(&old_blob));
    }

    #[test]
    fn inline_base_sketching_stops_after_chunks_in_a_row_that_share_nothing() {
        let (_d, s) = store();
        let old = chunk_content(1, 100_000);
        let unrelated = |i: u8| chunk_content(10 + i, 4_096);
        let shares = old[..40_000].to_vec();
        let ids = |chunks: &[Vec<u8>]| -> Vec<Hash> {
            chunks.iter().map(|c| put_blob(&s, c.clone())).collect()
        };
        let old_blob = put_blob(&s, old.clone());
        let pair = |chunks: &[Vec<u8>], misses: usize| {
            let budget = BlobBudget {
                misses,
                ..BlobBudget::default()
            };
            let mut out = HashMap::new();
            let reads =
                pair_blob_to_chunks(&s, &ids(chunks), old_blob, &old, budget, &mut out).unwrap();
            (reads, out)
        };
        let late = vec![unrelated(0), unrelated(1), unrelated(2), shares.clone()];
        let (reads, out) = pair(&late, 3);
        assert!(out.is_empty());
        assert_eq!(reads, 3);
        let (reads, out) = pair(&late, 4);
        assert_eq!(out.get(&put_blob(&s, shares.clone())), Some(&old_blob));
        assert_eq!(reads, 4);

        // A share starts the count again: two misses, a share, two more
        // misses and a second share all fit within three in a row.
        let second = old[50_000..90_000].to_vec();
        let spaced = vec![
            unrelated(0),
            unrelated(1),
            shares.clone(),
            unrelated(2),
            unrelated(3),
            second.clone(),
        ];
        let (reads, out) = pair(&spaced, 3);
        assert_eq!(out.len(), 2);
        assert_eq!(out.get(&put_blob(&s, second)), Some(&old_blob));
        assert_eq!(reads, 6);
    }

    #[test]
    fn the_read_budget_of_a_push_is_shared_by_its_files() {
        let (_d, s) = store();
        // Two chunked files, each with one chunk replaced by two halves that
        // each keep half of it: one run of 2 new and 5 old chunk reads per
        // file.
        let file = |base: u8| -> (Hash, Hash) {
            let old = distinct_chunks(base, 40, 2_000);
            let mut new = old.clone();
            let (lo, hi) = old[20].split_at(1_000);
            new.splice(20..21, [tweaked(lo), tweaked(hi)]);
            (put_chunked_from(&s, &old), put_chunked_from(&s, &new))
        };
        let ((a_old, a_new), (b_old, b_new)) = (file(1), file(60));
        // A file that was one inline blob and grew: two new chunks share
        // content with it, one read each.
        let blob = chunk_content(150, 100_000);
        let c_old = put_blob(&s, blob.clone());
        let c_new = put_chunked_from(
            &s,
            &[blob[..40_000].to_vec(), blob[50_000..90_000].to_vec()],
        );
        let old_tip = commit_with_files(
            &s,
            &[(b"a.bin", a_old), (b"b.bin", b_old), (b"c.bin", c_old)],
            vec![],
            "o",
        );
        let new_tip = commit_with_files(
            &s,
            &[(b"a.bin", a_new), (b"b.bin", b_new), (b"c.bin", c_new)],
            vec![old_tip],
            "n",
        );
        let paired = |reads: usize| {
            let mut left = reads;
            let bases = select_delta_bases_within(&s, new_tip, old_tip, &mut left).unwrap();
            (bases.chunks.len(), reads - left)
        };
        // A file whose run does not fit what is left goes raw, and a later
        // file still draws on the rest.
        assert_eq!(paired(6), (2, 2), "only the blob file fits");
        assert_eq!(paired(13), (4, 9), "a, then c; b did not fit");
        assert_eq!(paired(14), (4, 14), "a and b took it all");
        assert_eq!(paired(15), (5, 15), "c has one read");
        assert_eq!(paired(16), (6, 16));
    }

    // =================================================================
    // A replacement chunk manifest goes as a delta against the manifest the
    // remote holds at the same path, when the caller allows it and the
    // framed delta entry is smaller than the manifest's own.
    // =================================================================

    fn encode_sequentially(
        s: &ObjectStore,
        candidates: &[DeltaCandidate],
    ) -> Result<Vec<Option<PlannedDelta>>, StoreError> {
        candidates
            .iter()
            .map(|&c| encode_delta_candidate(s, c))
            .collect()
    }

    /// `n` distinct 64-byte chunks.
    fn many_chunks(n: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| {
                let mut chunk = chunk_content(3, 64);
                chunk[..8].copy_from_slice(&(i as u64).to_le_bytes());
                chunk
            })
            .collect()
    }

    /// An old file of `many_chunks(n)`, and the new one with chunk `at`
    /// replaced; each at a commit, with their manifests.
    struct ManifestPair {
        old_tip: Hash,
        new_tip: Hash,
        old_manifest: Hash,
        new_manifest: Hash,
    }

    fn manifest_pair(s: &ObjectStore, n: usize, at: usize) -> ManifestPair {
        let old_chunks = many_chunks(n);
        let mut new_chunks = old_chunks.clone();
        new_chunks[at] = chunk_content(9, 64);
        let old_manifest = put_chunked_from(s, &old_chunks);
        let new_manifest = put_chunked_from(s, &new_chunks);
        let old_tip = commit_with_file(s, old_manifest, vec![], "old");
        let new_tip = commit_with_file(s, new_manifest, vec![old_tip], "new");
        ManifestPair {
            old_tip,
            new_tip,
            old_manifest,
            new_manifest,
        }
    }

    fn plan_manifests(
        s: &ObjectStore,
        pair: &ManifestPair,
        manifests: ManifestDeltas,
        budget: ManifestBudget,
    ) -> PackPlan {
        let limits = WalkLimits::default();
        let held =
            HeldCommits::for_tips(s, &[pair.new_tip], Some(pair.old_tip), limits.objects).unwrap();
        plan_with_held_manifests(
            s,
            &[pair.new_tip],
            &held,
            manifests,
            budget,
            encode_sequentially,
            limits,
        )
        .unwrap()
    }

    #[test]
    fn a_replacement_manifest_goes_as_a_delta_against_the_held_one() {
        let (_d, s) = store();
        let pair = manifest_pair(&s, 300, 150);
        let plan = plan_manifests(&s, &pair, ManifestDeltas::Held, ManifestBudget::default());

        let delta = plan
            .deltas
            .iter()
            .find(|d| d.target == pair.new_manifest)
            .expect("the manifest is sent as a delta");
        assert_eq!(delta.base, pair.old_manifest);
        assert!(!plan.raw.contains(&pair.new_manifest));
        // The framed delta entry is a small fraction of the manifest's.
        let full = s.read(&pair.new_manifest).unwrap();
        let stream = delta.stream.bytes().unwrap();
        assert!(pack::delta_entry_len(&stream) * 10 < pack::raw_entry_len(&full));
        // Every object of the new tip reconstructs under its id, the manifest
        // from the one the remote held.
        assert_pack_reconstructs(&s, &plan, pair.old_tip, pair.new_tip);
    }

    #[test]
    fn full_manifests_are_the_default() {
        let (_d, s) = store();
        let pair = manifest_pair(&s, 300, 150);
        let plan = plan_manifests(&s, &pair, ManifestDeltas::Full, ManifestBudget::default());
        assert!(plan.raw.contains(&pair.new_manifest));
        assert!(plan.deltas.iter().all(|d| d.target != pair.new_manifest));
        let plan =
            plan_pack_with(&s, pair.new_tip, Some(pair.old_tip), encode_sequentially).unwrap();
        assert!(plan.raw.contains(&pair.new_manifest));
        assert_pack_reconstructs(&s, &plan, pair.old_tip, pair.new_tip);
        // The opt-in entry point sends one delta where the default sends none.
        let plan = plan_pack_tips_with_manifests(
            &s,
            &[pair.new_tip],
            Some(pair.old_tip),
            ManifestDeltas::Held,
            encode_sequentially,
        )
        .unwrap();
        assert!(plan.deltas.iter().any(|d| d.target == pair.new_manifest));
    }

    #[test]
    fn a_manifest_with_no_held_base_goes_in_full() {
        let (_d, s) = store();
        // The old tip names a manifest this store does not hold.
        let elsewhere = store();
        let absent = put_chunked_from(&elsewhere.1, &many_chunks(300));
        let c_old = commit_with_file(&s, absent, vec![], "old");
        let new_manifest = put_chunked_from(&s, &many_chunks(301));
        let c_new = commit_with_file(&s, new_manifest, vec![c_old], "new");
        let pair = ManifestPair {
            old_tip: c_old,
            new_tip: c_new,
            old_manifest: absent,
            new_manifest,
        };
        let plan = plan_manifests(&s, &pair, ManifestDeltas::Held, ManifestBudget::default());
        assert!(plan.raw.contains(&new_manifest));
        assert!(plan.deltas.iter().all(|d| d.target != new_manifest));
    }

    #[test]
    fn a_manifest_that_shares_nothing_goes_in_full() {
        let (_d, s) = store();
        let old: Vec<Vec<u8>> = (0..300)
            .map(|i| {
                chunk_content(1, 64 + i % 7)
                    .into_iter()
                    .chain([u8::try_from(i % 256).unwrap()])
                    .collect()
            })
            .collect();
        let new: Vec<Vec<u8>> = (0..300)
            .map(|i| {
                chunk_content(2, 70 + i % 5)
                    .into_iter()
                    .chain([u8::try_from(i % 256).unwrap()])
                    .collect()
            })
            .collect();
        let old_manifest = put_chunked_from(&s, &old);
        let new_manifest = put_chunked_from(&s, &new);
        let old_tip = commit_with_file(&s, old_manifest, vec![], "old");
        let new_tip = commit_with_file(&s, new_manifest, vec![old_tip], "new");
        let pair = ManifestPair {
            old_tip,
            new_tip,
            old_manifest,
            new_manifest,
        };
        let plan = plan_manifests(&s, &pair, ManifestDeltas::Held, ManifestBudget::default());
        assert!(plan.raw.contains(&new_manifest));
        assert!(plan.deltas.iter().all(|d| d.target != new_manifest));
    }

    #[test]
    fn a_delta_manifest_must_beat_the_framed_full_entry() {
        let (_d, s) = store();
        // A manifest of one chunk repeated compresses to a few hundred bytes,
        // so a stream far shorter than its canonical length still loses.
        let chunk = chunk_content(4, 64);
        let manifest = put_chunked_from(&s, &vec![chunk; 2_000]);
        let canonical = s.read(&manifest).unwrap();
        assert!(canonical.len() > 50_000);
        let planned = |stream: Vec<u8>| PlannedDelta {
            target: manifest,
            base: [7; 32],
            stream: DeltaBytes::Inline(stream),
        };
        let long = planned(chunk_content(5, 10_000));
        assert!(hash::HASH_LEN + long.stream.len() < canonical.len());
        assert!(!manifest_delta_wins(&s, &long).unwrap());
        let short = planned(chunk_content(5, 100));
        assert!(manifest_delta_wins(&s, &short).unwrap());
    }

    #[test]
    fn a_delta_manifest_that_only_ties_the_framed_full_entry_goes_in_full() {
        let (_d, s) = store();
        let manifest = put_chunked_from(&s, &many_chunks(300));
        let framed = pack::raw_entry_len(&s.read(&manifest).unwrap());
        // An incompressible stream's entry is the frame, the base id and the
        // stream itself.
        let entry = |stream_len: u64| {
            let stream = chunk_content(5, usize::try_from(stream_len).unwrap());
            let entry = pack::delta_entry_len(&stream);
            (
                PlannedDelta {
                    target: manifest,
                    base: [7; 32],
                    stream: DeltaBytes::Inline(stream),
                },
                entry,
            )
        };
        let overhead = 5 + hash::HASH_LEN as u64;
        let (tie, tie_len) = entry(framed - overhead);
        assert_eq!(tie_len, framed);
        assert!(!manifest_delta_wins(&s, &tie).unwrap());
        let (under, under_len) = entry(framed - overhead - 1);
        assert_eq!(under_len, framed - 1);
        assert!(manifest_delta_wins(&s, &under).unwrap());
    }

    #[test]
    fn a_cap_under_either_manifest_leaves_it_in_full() {
        let (_d, s) = store();
        // Two files of different lengths, so one manifest is longer.
        let longer = |n: usize| {
            let mut chunks = many_chunks(n);
            chunks.push(chunk_content(9, 64));
            chunks
        };
        for (old_chunks, new_chunks) in [
            (many_chunks(300), longer(300)),
            (longer(300), many_chunks(300)),
        ] {
            let old_manifest = put_chunked_from(&s, &old_chunks);
            let new_manifest = put_chunked_from(&s, &new_chunks);
            let old_tip = commit_with_file(&s, old_manifest, vec![], "old");
            let new_tip = commit_with_file(&s, new_manifest, vec![old_tip], "new");
            let pair = ManifestPair {
                old_tip,
                new_tip,
                old_manifest,
                new_manifest,
            };
            let (old_len, new_len) = (
                s.object_size(&old_manifest).unwrap(),
                s.object_size(&new_manifest).unwrap(),
            );
            assert_ne!(old_len, new_len);
            // A cap that only the shorter one fits: the longer is in the way.
            let under = ManifestBudget {
                each: old_len.min(new_len),
                plan: u64::MAX,
            };
            let plan = plan_manifests(&s, &pair, ManifestDeltas::Held, under);
            assert!(plan.raw.contains(&new_manifest));
            let fits = ManifestBudget {
                each: old_len.max(new_len),
                plan: u64::MAX,
            };
            let plan = plan_manifests(&s, &pair, ManifestDeltas::Held, fits);
            assert!(plan.deltas.iter().any(|d| d.target == new_manifest));
        }
    }

    #[test]
    fn a_manifest_whose_delta_loses_the_framed_comparison_goes_in_full() {
        let (_d, s) = store();
        // The new file is one chunk repeated, a manifest that compresses to
        // a few hundred bytes. The old one shares only its first twenty
        // entries, so the delta is nearly all literal: shorter than the
        // canonical manifest, but longer than its compressed entry.
        let repeated = chunk_content(4, 64);
        let mut old_chunks = vec![repeated.clone(); 20];
        old_chunks.extend(many_chunks(380));
        let new_chunks = vec![repeated; 400];
        let old_manifest = put_chunked_from(&s, &old_chunks);
        let new_manifest = put_chunked_from(&s, &new_chunks);
        let old_tip = commit_with_file(&s, old_manifest, vec![], "old");
        let new_tip = commit_with_file(&s, new_manifest, vec![old_tip], "new");
        let pair = ManifestPair {
            old_tip,
            new_tip,
            old_manifest,
            new_manifest,
        };
        let old_bytes = s.read(&old_manifest).unwrap();
        let new_bytes = s.read(&new_manifest).unwrap();
        let stream = delta::encode(&old_bytes, &new_bytes).unwrap();
        assert!(hash::HASH_LEN + stream.len() < new_bytes.len());
        assert!(pack::delta_entry_len(&stream) >= pack::raw_entry_len(&new_bytes));

        let plan = plan_manifests(&s, &pair, ManifestDeltas::Held, ManifestBudget::default());
        assert!(plan.raw.contains(&new_manifest));
        assert!(plan.deltas.iter().all(|d| d.target != new_manifest));
    }

    #[test]
    fn a_manifest_over_the_per_manifest_cap_goes_in_full() {
        let (_d, s) = store();
        let pair = manifest_pair(&s, 300, 150);
        let size = s.object_size(&pair.new_manifest).unwrap();
        let over = ManifestBudget {
            each: size - 1,
            plan: u64::MAX,
        };
        let plan = plan_manifests(&s, &pair, ManifestDeltas::Held, over);
        assert!(plan.raw.contains(&pair.new_manifest));
        // The base counts too: a cap under its length leaves it in full.
        let base_size = s.object_size(&pair.old_manifest).unwrap();
        let small_base = ManifestBudget {
            each: base_size - 1,
            plan: u64::MAX,
        };
        let plan = plan_manifests(&s, &pair, ManifestDeltas::Held, small_base);
        assert!(plan.raw.contains(&pair.new_manifest));
        // At the cap it is a delta.
        let at = ManifestBudget {
            each: size.max(base_size),
            plan: u64::MAX,
        };
        let plan = plan_manifests(&s, &pair, ManifestDeltas::Held, at);
        assert!(plan.deltas.iter().any(|d| d.target == pair.new_manifest));
    }

    /// A commit holding each `(name, object)`, names in tree order.
    fn commit_with_files(
        s: &ObjectStore,
        files: &[(&[u8], Hash)],
        parents: Vec<Hash>,
        msg: &str,
    ) -> Hash {
        let tree = put(
            s,
            &Object::Tree(Tree {
                entries: files
                    .iter()
                    .map(|(name, object_hash)| TreeEntry {
                        name: name.to_vec(),
                        mode: EntryMode::Blob,
                        object_hash: *object_hash,
                    })
                    .collect(),
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

    #[test]
    fn manifest_deltas_stop_at_the_per_plan_cap() {
        let (_d, s) = store();
        let chunks = many_chunks(300);
        let (mut a_new, mut b_new) = (chunks.clone(), many_chunks(310));
        a_new[10] = chunk_content(9, 64);
        b_new[20] = chunk_content(8, 64);
        let (a_old, b_old) = (
            put_chunked_from(&s, &chunks),
            put_chunked_from(&s, &many_chunks(310)),
        );
        let (a_new, b_new) = (put_chunked_from(&s, &a_new), put_chunked_from(&s, &b_new));
        let old_tip = commit_with_files(&s, &[(b"a.bin", a_old), (b"b.bin", b_old)], vec![], "old");
        let new_tip = commit_with_files(
            &s,
            &[(b"a.bin", a_new), (b"b.bin", b_new)],
            vec![old_tip],
            "new",
        );
        let pair = ManifestPair {
            old_tip,
            new_tip,
            old_manifest: a_old,
            new_manifest: a_new,
        };
        let work =
            |old: Hash, new: Hash| s.object_size(&old).unwrap() + s.object_size(&new).unwrap();
        let (a_work, b_work) = (work(a_old, a_new), work(b_old, b_new));
        let sent = |plan: &PackPlan| {
            [a_new, b_new]
                .iter()
                .filter(|m| plan.deltas.iter().any(|d| d.target == **m))
                .count()
        };
        let both = ManifestBudget {
            each: u64::MAX,
            plan: a_work + b_work,
        };
        let plan = plan_manifests(&s, &pair, ManifestDeltas::Held, both);
        assert_eq!(sent(&plan), 2);
        let one_short = ManifestBudget {
            each: u64::MAX,
            plan: a_work + b_work - 1,
        };
        let plan = plan_manifests(&s, &pair, ManifestDeltas::Held, one_short);
        assert_eq!(sent(&plan), 1, "the rest goes in full");
        assert_pack_reconstructs(&s, &plan, old_tip, new_tip);
        let none = ManifestBudget {
            each: u64::MAX,
            plan: a_work.min(b_work) - 1,
        };
        assert_eq!(
            sent(&plan_manifests(&s, &pair, ManifestDeltas::Held, none)),
            0
        );
    }

    #[test]
    fn select_delta_bases_pairs_the_manifest_of_a_changed_chunked_path() {
        let (_d, s) = store();
        let pair = manifest_pair(&s, 30, 5);
        let bases = select_delta_bases(&s, pair.new_tip, pair.old_tip).unwrap();
        assert_eq!(
            bases.manifests,
            HashMap::from([(pair.new_manifest, pair.old_manifest)])
        );
        assert_eq!(
            bases.chunks,
            select_chunk_delta_bases(&s, pair.new_tip, pair.old_tip).unwrap()
        );
        // A path that was an inline blob has no manifest to pair.
        let (_old, _blob, c_old) = inline_old_tip(&s, 1, 300_000);
        let c_new = chunked_new_tip(&s, &many_chunks(10), c_old);
        assert!(
            select_delta_bases(&s, c_new, c_old)
                .unwrap()
                .manifests
                .is_empty()
        );
    }

    /// Split probing plans several ranges of one chain. Through one delta
    /// spool, a `(target, base)` pair the probes share is encoded once, and
    /// every plan gets the same stream, read back from the spool's file.
    #[test]
    fn probes_that_share_a_delta_encode_it_once_through_a_delta_spool() {
        let (d, s) = store();
        let mut v1 = Vec::new();
        for i in 0..40 {
            v1.extend_from_slice(format!("unchanged line number {i:02}\n").as_bytes());
        }
        let mut v2 = v1.clone();
        v2.extend_from_slice(b"one more line\n");
        let blob1 = put_blob(&s, v1);
        let blob2 = put_blob(&s, v2);
        let c1 = commit_with_named_file(&s, b"small.txt", blob1, vec![], "v1");
        let c2 = commit_with_named_file(&s, b"small.txt", blob2, vec![c1], "v2");
        let c3 = commit_with_named_file(&s, b"small.txt", blob2, vec![c2], "v3");

        let inline = plan_pack(&s, c2, Some(c1)).unwrap();
        let mut spool = DeltaSpool::create(&d.path().join("tmp")).unwrap();
        let mut encoded = Vec::new();
        let mut probe = |tip| {
            plan_pack_with(&s, tip, Some(c1), |store, candidates| {
                spool.encode(store, candidates, |store, fresh| {
                    encoded.extend(fresh.iter().map(|c| (c.target, c.base)));
                    fresh
                        .iter()
                        .map(|&c| encode_delta_candidate(store, c))
                        .collect()
                })
            })
            .unwrap()
        };
        let probes = [probe(c2), probe(c3), probe(c2)];
        assert_eq!(encoded, vec![(blob2, blob1)], "one encode for three probes");
        for plan in probes {
            assert_eq!(plan.deltas.len(), 1);
            assert!(matches!(plan.deltas[0].stream, DeltaBytes::Spooled { .. }));
            assert_eq!(
                plan.deltas[0].stream.bytes().unwrap(),
                inline.deltas[0].stream.bytes().unwrap()
            );
            assert_eq!(plan.raw.contains(&blob2), inline.raw.contains(&blob2));
        }
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

//! GC retention roots — the complete set of object hashes that
//! `kit gc` must treat as live, plus the live-object closure
//! over them.
//!
//! Pruning is only safe if the root set is **complete**: anything gc can
//! reach from a root is kept; everything else is reclaimable. Missing a
//! root means deleting a live object, so this collector is deliberately
//! exhaustive and **fails closed** — if any source can't be read, the
//! whole collection errors and the caller must abort rather than prune
//! against an under-counted root set.
//!
//! Roots, by source:
//! - **HEAD** (incl. detached) and every `refs/heads`, `refs/tags`, and
//!   `refs/remotes/<remote>` ref.
//! - **Stash** entries — each stashed commit and its recorded parent.
//! - **In-progress operations** — merge (`MERGE_HEAD`), cherry-pick
//!   (`CHERRY_PICK_HEAD`), rebase (`onto` + every `todo`/`done` commit),
//!   the `ORIG_HEAD` saved by those ops and by `reset`, and the conflict
//!   sidecar's base/ours/theirs blob hashes.
//! - **Attestations** — every `attestations/<commit>/` directory pins
//!   its commit so an attested commit is never orphaned.
//! - **Recovery log** — every commit recorded as superseded by a
//!   history-rewriting op (see [`super::recovery`]); retained so it stays
//!   recoverable until `recovery::expire` drops it past the window.
//!
//! RECOVERY: commits superseded by `commit --amend`, `reset`, or
//! `rebase` are unrecoverable from the opaque-digest history journal, so
//! [`super::recovery`] logs them (the commands record the old tip before
//! moving the ref) and they are roots here.

use std::collections::{BTreeSet, VecDeque};
use std::fs;
use std::io;
use std::path::Path;

use crate::bounded_read;
use crate::hash::{self, Hash};
use crate::index;
use crate::layout::RepoLayout;
use crate::object::{Object, ObjectType};
use crate::store::{ObjectStore, StoreError};

use super::conflict_state;
use super::graph::{ClosureMode, MAX_REACHABLE, children};
use super::rebase;
use super::recovery;
use super::stash;
use crate::layout::ATTESTATIONS_DIR_NAME;
use crate::refs::{self, HEADS_DIR, REMOTES_DIR, TAGS_DIR};

/// Longest ref or root file that gc reads: one hex hash plus whitespace.
const HASH_FILE_MAX_BYTES: u64 = 128;

use crate::refs::MAX_REF_WALK_DEPTH;

/// Errors from collecting the retention root set. Every underlying
/// source error is wrapped so the collector can fail closed.
///
/// `#[non_exhaustive]`: new root sources (like the staging index, added
/// in 0.2.0) come with new variants; downstream matches must keep a
/// wildcard arm so those additions stay minor-version changes.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GcRootsError {
    #[error("refs: {0}")]
    Refs(#[from] refs::RefError),
    #[error("stash: {0}")]
    Stash(#[from] stash::StashError),
    #[error("conflict state: {0}")]
    ConflictState(#[from] conflict_state::ConflictStateError),
    #[error("rebase state: {0}")]
    Rebase(#[from] rebase::RebaseError),
    #[error("recovery log: {0}")]
    Recovery(#[from] recovery::RecoveryError),
    #[error("staging index: {0}")]
    Index(#[from] index::IndexError),
    #[error("object store: {0}")]
    Store(#[from] StoreError),
    #[error("malformed object id on disk: {0}")]
    BadHash(#[from] hash::FromHexError),
    #[error("io: {0}")]
    Io(#[from] io::Error),
    /// The mark reached [`super::graph::MAX_REACHABLE`] commits, trees,
    /// manifests and other objects before completing. Chunks of a chunked
    /// file are not counted. The live set is incomplete, so a caller must
    /// abort rather than treat beyond-cap objects as prunable.
    #[error(
        "object graph exceeds the reachability cap of {} objects (chunks are not counted); refusing to compute a partial keep-set",
        MAX_REACHABLE
    )]
    Truncated,
    /// The distinct chunk ids that manifests list passed [`MAX_LIVE_CHUNKS`].
    /// The list of ids must fit in memory, so gc refuses instead of marking
    /// part of it.
    #[error(
        "{count} distinct chunk ids exceed the live chunk cap of {cap}; refusing to compute a partial keep-set"
    )]
    TooManyChunks {
        /// Distinct chunk ids when the cap was found exceeded.
        count: usize,
        /// The cap that applied.
        cap: usize,
    },
    /// A manifest lists an object that is neither a blob nor a delta. A chunk
    /// is a leaf, so gc cannot tell what that object reaches and refuses.
    #[error(
        "chunk {} of manifest {} is not a blob or delta (fail closed)",
        hash::to_hex(.chunk),
        hash::to_hex(.manifest)
    )]
    ChunkNotBlob {
        /// A manifest that lists the chunk. All zeros if none lists it any
        /// more, which only a change to the store during the mark causes.
        manifest: Hash,
        /// The listed object.
        chunk: Hash,
    },
    /// A ref directory nested deeper than [`MAX_REF_WALK_DEPTH`], which is
    /// deeper than any ref name of the bounded length. Gc cannot tell what
    /// it holds, so it refuses instead of skipping it.
    #[error("ref tree too deep at {0} (fail closed)")]
    RefTooDeep(String),
    /// `.kit` or `.kit/objects` is a symlink. A deletion-capable gc
    /// refuses, since pruning would follow the link and unlink files
    /// outside the repo.
    #[error("refusing to gc: {0} is a symlink (objects may live outside the repo)")]
    SymlinkedStore(String),
    /// The linked-worktree registry could not be enumerated. Root
    /// collection must union EVERY tree's per-tree state;
    /// a partial view would let a sibling's staged work be pruned.
    #[error("worktree registry: {0}")]
    Worktrees(#[from] crate::layout::DiscoverError),
}

/// Collect the complete set of GC retention roots for the repo at
/// the repository described by `layout`. The returned hashes are roots,
/// not the closure — feed them to `reachable_closure` (or use
/// [`live_objects`]) to get the full keep-set.
///
/// The all-zero hash is filtered out (an unset ref / `ORIG_HEAD`).
///
/// # Errors
///
/// [`GcRootsError`] if any source (refs, stash, op state, attestation
/// dir) cannot be read — the caller must then abort, never prune.
pub fn collect_roots(layout: &RepoLayout) -> Result<BTreeSet<Hash>, GcRootsError> {
    let mut roots: BTreeSet<Hash> = BTreeSet::new();
    let add = |h: Hash, set: &mut BTreeSet<Hash>| {
        if h != hash::ZERO {
            set.insert(h);
        }
    };

    // Branches, tags, and remote-tracking refs. We deliberately do NOT
    // use `refs::list_refs`/`list_tags`/`list_remote_refs` here: those
    // are lenient (they yield `hash: None` for malformed content, skip
    // unreadable files, and silently stop at a depth cap), which would
    // let a corrupt ref drop out of the root set while collection still
    // "succeeds" — exactly the fail-open hole gc cannot tolerate. The
    // strict walk below errors on any unreadable / undecodable / too-deep
    // ref instead.
    for ns in [HEADS_DIR, TAGS_DIR, REMOTES_DIR] {
        walk_ref_roots_strict(&layout.common_dir().join(ns), ns, 0, &mut roots)?;
    }

    // Per-tree sources, unioned over EVERY worktree of the repository
    // the main tree plus each registered state dir —
    // including prunable-but-unpruned ones, whose staged work stays
    // pinned until `worktree prune` explicitly reaps it. Fail closed:
    // a registry error or an unreadable sibling state aborts
    // collection entirely.
    for tree in crate::layout::all_state_layouts(layout)? {
        collect_tree_roots(&tree, &add, &mut roots)?;
    }

    // Attested commits — pinned so an attestation never dangles.
    for h in attested_commits(layout.common_dir())? {
        add(h, &mut roots);
    }

    // A crash may leave a history intent before its target ref is published.
    // Retain both sides even on builds without the history-mmr feature.
    for h in refs::pending_history_roots(layout)? {
        add(h, &mut roots);
    }

    // Recovery log — commits superseded by amend/reset/rebase, retained
    // so they stay recoverable. Clock-free here: `recovery::expire` (a
    // gc maintenance step) drops entries past the retention window so
    // they stop pinning objects.
    for h in recovery::roots(layout)? {
        add(h, &mut roots);
    }

    Ok(roots)
}

/// One worktree's per-tree retention roots: HEAD, staging index,
/// `ORIG_HEAD`, in-progress merge/cherry-pick/revert/rebase state,
/// conflict sidecars, and the tree-local stash.
fn collect_tree_roots(
    tree: &crate::layout::RepoLayout,
    add: &impl Fn(Hash, &mut BTreeSet<Hash>),
    roots: &mut BTreeSet<Hash>,
) -> Result<(), GcRootsError> {
    // HEAD (covers a detached HEAD not present under refs/heads).
    if let Some(h) = refs::resolve_head(tree)? {
        add(h, roots);
    }

    // Stash: each stashed commit and the HEAD it was based on.
    for entry in stash::list(tree)?.entries {
        add(entry.commit_hash, roots);
        add(entry.parent_hash, roots);
    }

    // Staging index — blobs recorded by `kit add` but not yet
    // committed. They are reachable from no ref, so without this root
    // staged work would be pruned once it ages past the grace window
    // (or immediately under `--grace-secs 0`). `read_index` is strict
    // (errors on corrupt/oversized index), so a damaged index aborts
    // gc instead of silently dropping roots.
    for entry in index::read_index(tree)?.entries {
        add(entry.object_hash, roots);
    }

    // An unfinished pull keeps its immutable baseline even if the index changes.
    if let Some(state) = super::pull_state::PullState::read(tree)? {
        add(state.target, roots);
        add(state.before_tree, roots);
    }

    // ORIG_HEAD (written by reset and by the in-progress ops below).
    if let Some(h) = read_optional_hash(&tree.orig_head_file())? {
        add(h, roots);
    }

    // In-progress merge / cherry-pick / revert.
    if let Some(m) = conflict_state::read_merge_state(tree)? {
        add(m.merge_head, roots);
        add(m.orig_head, roots);
    }
    if let Some(c) = conflict_state::read_cherry_pick_state(tree)? {
        add(c.cherry_pick_head, roots);
        add(c.orig_head, roots);
    }
    if let Some(r) = conflict_state::read_revert_state(tree)? {
        add(r.revert_head, roots);
        add(r.orig_head, roots);
    }

    // In-progress rebase: target + every commit still to replay or
    // already replayed onto the new base.
    if rebase::is_rebase_in_progress(tree) {
        let st = rebase::read_state(tree)?;
        add(st.orig_head, roots);
        add(st.onto, roots);
        for h in st.todo.into_iter().chain(st.done) {
            add(h, roots);
        }
    }

    // Conflict sidecar: base/ours/theirs blobs needed to resolve an
    // in-progress conflict. Merge/cherry-pick write `kit-conflicts`
    // in the state dir; rebase writes its sidecar inside
    // `rebase-apply/`. Both are empty/absent when no conflict is
    // recorded.
    for dir in [tree.worktree_state_dir().to_path_buf(), tree.rebase_dir()] {
        for c in conflict_state::read_conflicts(&dir)? {
            for h in [c.base_hash, c.ours_hash, c.theirs_hash]
                .into_iter()
                .flatten()
            {
                add(h, roots);
            }
        }
    }
    Ok(())
}

/// Most distinct chunk ids [`live_objects`] holds: 134,217,728, which is 4 GiB
/// of ids. Past it the mark fails with [`GcRootsError::TooManyChunks`]. The
/// chunk id buffer is checked at a compaction, so before the error it can hold
/// about twice that.
pub const MAX_LIVE_CHUNKS: usize = 134_217_728;

/// The chunk id buffer compacts only when its capacity would grow past this
/// many ids (or twice its length after the last compaction, if larger).
const CHUNK_COMPACT_FLOOR: usize = 1_048_576;

/// The three bounds of a mark. Tests inject small ones.
#[derive(Debug, Clone, Copy)]
struct MarkLimits {
    /// Most non-chunk objects.
    cap: usize,
    /// Most distinct chunk ids.
    chunk_cap: usize,
    /// See [`CHUNK_COMPACT_FLOOR`].
    compact_floor: usize,
}

impl MarkLimits {
    const DEFAULT: Self = Self {
        cap: MAX_REACHABLE,
        chunk_cap: MAX_LIVE_CHUNKS,
        compact_floor: CHUNK_COMPACT_FLOOR,
    };
}

/// The objects `kit gc` keeps, in two parts so that a chunk costs one hash in
/// a sorted vector instead of one node in a tree.
///
/// - `objects`: commits, trees, tags, remixes, manifests, and blobs reached
///   other than as a chunk. The mark caps it at [`MAX_REACHABLE`].
/// - `chunks`: the ids that manifests list, sorted, without duplicates, and
///   disjoint from `objects`. Each is a blob or a delta.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LiveSet {
    objects: BTreeSet<Hash>,
    chunks: Vec<Hash>,
}

/// Iterator over a [`LiveSet`]: the objects, then the chunks.
pub type LiveIter<'a> =
    std::iter::Chain<std::collections::btree_set::Iter<'a, Hash>, std::slice::Iter<'a, Hash>>;

impl LiveSet {
    /// True when `h` is live, as an object or as a chunk.
    #[must_use]
    pub fn contains(&self, h: &Hash) -> bool {
        self.objects.contains(h) || self.contains_chunk(h)
    }

    /// True when `h` is a live chunk and no other kind of live object.
    fn contains_chunk(&self, h: &Hash) -> bool {
        // `chunks` is sorted when the mark returns it and is never appended
        // to after that.
        self.chunks.binary_search(h).is_ok()
    }

    /// Live objects and chunks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.objects.len() + self.chunks.len()
    }

    /// True when nothing is live.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty() && self.chunks.is_empty()
    }

    /// Live chunks, counted in [`len`](Self::len) too.
    #[must_use]
    pub fn chunks_len(&self) -> usize {
        self.chunks.len()
    }

    /// Every live id: the objects in order, then the chunks in order.
    pub fn iter(&self) -> LiveIter<'_> {
        self.objects.iter().chain(self.chunks.iter())
    }
}

impl<'a> IntoIterator for &'a LiveSet {
    type Item = &'a Hash;
    type IntoIter = LiveIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// The chunk ids that manifests list, kept sorted and deduplicated often
/// enough that memory stays near twice the number of distinct ids.
struct ChunkIds {
    ids: Vec<Hash>,
    /// Length after the last compaction.
    settled: usize,
    floor: usize,
    cap: usize,
}

impl ChunkIds {
    fn new(floor: usize, cap: usize) -> Self {
        Self {
            ids: Vec::new(),
            settled: 0,
            floor,
            cap,
        }
    }

    /// Capacity above which the buffer compacts before it grows.
    fn threshold(&self) -> usize {
        self.settled.saturating_mul(2).max(self.floor)
    }

    /// Append `new`. Capacity doubles while it stays within the threshold.
    /// A growth past it compacts first, and the buffer then holds at most
    /// the threshold, or what `new` needs if that is more.
    fn extend(&mut self, new: &[Hash]) -> Result<(), GcRootsError> {
        let mut need = self.ids.len().saturating_add(new.len());
        if need > self.ids.capacity() {
            let mut target = self.ids.capacity().saturating_mul(2).max(need);
            if target > self.threshold() {
                self.compact()?;
                need = self.ids.len().saturating_add(new.len());
                target = need.max(self.threshold());
            }
            self.ids.reserve_exact(target - self.ids.len());
        }
        self.ids.extend_from_slice(new);
        Ok(())
    }

    /// Sort and deduplicate, then refuse a buffer past the chunk cap.
    fn compact(&mut self) -> Result<(), GcRootsError> {
        self.ids.sort_unstable();
        self.ids.dedup();
        self.settled = self.ids.len();
        if self.ids.len() > self.cap {
            return Err(GcRootsError::TooManyChunks {
                count: self.ids.len(),
                cap: self.cap,
            });
        }
        Ok(())
    }
}

/// Mark every object `kit gc` keeps live: the closure over `roots` in
/// [`ClosureMode::History`], with the chunks of each manifest held apart.
///
/// The walk is breadth-first over `objects`. A manifest queues nothing: its
/// chunk ids go to a buffer, which is later checked once per distinct id for
/// being a blob or a delta, as the old walk's leaf test did. An id that
/// manifests list and another path also reaches stays an object, and so does
/// a manifest reached as a file when another manifest lists it.
///
/// This function reads nothing for deletion and deletes nothing. A caller must
/// run it to the end, every type read included, before it lists or deletes
/// any object.
fn mark_live(
    store: &ObjectStore,
    roots: &BTreeSet<Hash>,
    limits: MarkLimits,
) -> Result<LiveSet, GcRootsError> {
    let mut objects: BTreeSet<Hash> = BTreeSet::new();
    let mut queue: VecDeque<Hash> = roots.iter().copied().collect();
    let mut ids = ChunkIds::new(limits.compact_floor, limits.chunk_cap);
    while let Some(h) = queue.pop_front() {
        if objects.contains(&h) {
            continue;
        }
        if objects.len() >= limits.cap {
            return Err(GcRootsError::Truncated);
        }
        objects.insert(h);
        // A blob or delta is a leaf. Its type is all gc needs, so its
        // content is not read or verified (see [`live_objects`]).
        if matches!(store.object_type(&h)?, ObjectType::Blob | ObjectType::Delta) {
            continue;
        }
        let object = store.read_object(&h)?;
        let edges = children(&object, ClosureMode::History);
        if matches!(object, Object::ChunkedBlob(_)) {
            drop(object);
            ids.extend(&edges)?;
        } else {
            queue.extend(edges);
        }
    }
    drop(queue);

    ids.compact()?;
    let mut chunks = ids.ids;
    chunks.retain(|c| !objects.contains(c));
    for chunk in &chunks {
        if !matches!(
            store.object_type(chunk)?,
            ObjectType::Blob | ObjectType::Delta
        ) {
            return Err(GcRootsError::ChunkNotBlob {
                manifest: manifest_listing(store, &objects, chunk)?,
                chunk: *chunk,
            });
        }
    }
    Ok(LiveSet { objects, chunks })
}

/// A live manifest that lists `chunk`, for an error message. Runs only after
/// the mark found a bad chunk, so its cost is the cost of a failed run.
fn manifest_listing(
    store: &ObjectStore,
    objects: &BTreeSet<Hash>,
    chunk: &Hash,
) -> Result<Hash, GcRootsError> {
    for h in objects {
        if store.object_type(h)? != ObjectType::ChunkedBlob {
            continue;
        }
        if let Object::ChunkedBlob(manifest) = store.read_object(h)?
            && manifest.chunks.contains(chunk)
        {
            return Ok(*h);
        }
    }
    Ok(hash::ZERO)
}

/// The full live-object keep-set for `kit gc`: the closure over every
/// retention root from [`collect_roots`], with chunks held apart (see
/// [`LiveSet`]).
///
/// The closure follows commits, trees, tags and parents like
/// [`super::graph::reachable_closure`]. The chunks of a manifest count toward
/// no cap but [`MAX_LIVE_CHUNKS`], and each must be a blob or a delta.
///
/// Does not verify leaf (blob/delta) content integrity as part of the
/// walk — see [`super::graph::reachable_closure`]'s "Content integrity
/// of leaves" doc section. `gc` is therefore no longer an incidental
/// corruption-detection pass over blob content the way it was before the
/// object-type short-circuit; it still fails closed on a *missing* object, just not on a
/// present-but-corrupted one.
///
/// # Errors
///
/// [`GcRootsError`] if roots cannot be collected, a [`StoreError`] (e.g. a
/// root, referenced object or chunk missing) during the walk,
/// [`GcRootsError::Truncated`] past [`MAX_REACHABLE`] objects,
/// [`GcRootsError::TooManyChunks`] past [`MAX_LIVE_CHUNKS`] distinct chunks,
/// or [`GcRootsError::ChunkNotBlob`] for a chunk of another kind.
pub fn live_objects(store: &ObjectStore, layout: &RepoLayout) -> Result<LiveSet, GcRootsError> {
    live_objects_with(store, layout, MarkLimits::DEFAULT)
}

fn live_objects_with(
    store: &ObjectStore,
    layout: &RepoLayout,
    limits: MarkLimits,
) -> Result<LiveSet, GcRootsError> {
    mark_live(store, &collect_roots(layout)?, limits)
}

/// Outcome of a [`run_gc`] sweep.
#[derive(Debug, Default, Clone, Copy)]
pub struct GcReport {
    /// Objects examined in the store.
    pub scanned: usize,
    /// Objects retained because they are reachable from a root. Chunks count.
    pub live: usize,
    /// The part of `live` that is chunks of a chunked file.
    pub live_chunks: usize,
    /// Unreachable objects retained anyway — within the grace window, or
    /// whose age could not be determined (kept fail-safe).
    pub kept_recent: usize,
    /// Unreachable objects pruned (or that *would* be pruned in a dry run).
    pub pruned: usize,
    /// Temp files of dead writers removed (or that *would* be removed in a dry
    /// run): files in the object directories that no object name matches.
    pub temp_files_pruned: usize,
    /// Bytes reclaimed by the pruned objects and temp files.
    pub bytes_reclaimed: u64,
    /// True if this was a dry run (nothing deleted).
    pub dry_run: bool,
}

/// Mark-and-sweep prune: keep every object reachable from the retention
/// roots ([`live_objects`]) plus every unreachable object younger than
/// `grace_secs` (relative to `now_secs`); delete the rest. With
/// `dry_run`, computes the report without deleting anything.
///
/// **Fail closed / fail safe.** If the live set can't be computed (a
/// missing/corrupt root, a malformed ref, a bad chunk, or a cap), this
/// returns an error and deletes nothing: the whole mark, every type read
/// included, ends before the sweep lists or deletes any object. An object
/// whose age can't be read is kept, never pruned. The caller MUST hold the
/// repo lock so the live set can't shift mid-sweep (see
/// [`super::recovery`]); `gc` runs `recovery::expire` then this, all under
/// that lock.
///
/// The sweep lists one `objects/<2 hex>/` directory at a time, so it never
/// holds the id of every loose object.
///
/// # Errors
/// [`GcRootsError`] from [`live_objects`], store enumeration, or a delete.
/// An error from the sweep itself leaves the objects of earlier directories
/// pruned, which is safe because only unreachable objects are.
pub fn run_gc(
    store: &ObjectStore,
    layout: &RepoLayout,
    now_secs: u64,
    grace_secs: u64,
    dry_run: bool,
) -> Result<GcReport, GcRootsError> {
    run_gc_with_hook(
        store,
        layout,
        now_secs,
        grace_secs,
        dry_run,
        MarkLimits::DEFAULT,
        |_| {},
    )
}

/// [`run_gc`] with injected mark limits and a `before_prune` call for every
/// candidate of the sweep: each unreachable object old enough to prune, in a
/// dry run as well as in a real run.
fn run_gc_with_hook(
    store: &ObjectStore,
    layout: &RepoLayout,
    now_secs: u64,
    grace_secs: u64,
    dry_run: bool,
    limits: MarkLimits,
    mut before_prune: impl FnMut(&Hash),
) -> Result<GcReport, GcRootsError> {
    // Refuse to delete through a symlinked store: if `.kit` or
    // `.kit/objects` is a symlink, `remove_object` would unlink the
    // link target's files — potentially outside the repo. (Dry runs are
    // safe but we reject uniformly so a preview matches the real run.)
    reject_symlink(layout.common_dir())?;
    reject_symlink(store.objects_root())?;

    // Compute the keep-set FIRST, to the end; if this fails we list and
    // delete nothing.
    let live = live_objects_with(store, layout, limits)?;

    let mut report = GcReport {
        dry_run,
        ..GcReport::default()
    };
    for shard in 0..=u8::MAX {
        for h in store.list_shard(shard)? {
            report.scanned += 1;
            if live.contains(&h) {
                report.live += 1;
                report.live_chunks += usize::from(live.contains_chunk(&h));
                continue;
            }
            // Unreachable. Keep it if it is within the grace window, or if
            // its age cannot be determined (fail safe — never delete when
            // uncertain).
            let Ok(meta) = store.object_metadata(&h) else {
                report.kept_recent += 1;
                continue;
            };
            let age_known_old = crate::store::old_enough(&meta, now_secs, grace_secs);
            if !age_known_old {
                report.kept_recent += 1;
                continue;
            }
            before_prune(&h);
            let mut len = meta.len();
            if !dry_run {
                let Some(reclaimed) = store.prune_if_old(&h, now_secs, grace_secs)? else {
                    report.kept_recent += 1;
                    continue;
                };
                len = reclaimed;
            }
            report.pruned += 1;
            report.bytes_reclaimed += len;
        }
        sweep_temp_files(store, shard, now_secs, grace_secs, dry_run, &mut report)?;
    }
    Ok(report)
}

/// Delete the temp files in shard `shard` that a dead writer left and that are
/// older than the grace window. A file goes through the same final check as an
/// object, under the exclusive lock of `format`, so a fetch that is writing is
/// never touched. A file whose age cannot be read is kept.
fn sweep_temp_files(
    store: &ObjectStore,
    shard: u8,
    now_secs: u64,
    grace_secs: u64,
    dry_run: bool,
    report: &mut GcReport,
) -> Result<(), GcRootsError> {
    for path in store.list_shard_temp_files(shard)? {
        let Ok(meta) = fs::metadata(&path) else {
            continue;
        };
        if !crate::store::old_enough(&meta, now_secs, grace_secs) {
            continue;
        }
        let mut len = meta.len();
        if !dry_run {
            let Some(freed) = store.prune_temp_file_if_old(&path, now_secs, grace_secs)? else {
                continue;
            };
            len = freed;
        }
        report.temp_files_pruned += 1;
        report.bytes_reclaimed += len;
    }
    Ok(())
}

/// Strict, fail-closed walk of a ref namespace directory (e.g.
/// `refs/heads`), inserting every ref's target hash into `roots`.
///
/// Unlike `refs::list_refs`, this errors instead of skipping on:
/// unreadable files ([`io::Error`]), undecodable content
/// ([`hash::FromHexError`]), and excessive nesting
/// ([`GcRootsError::RefTooDeep`]). Dot-files are skipped (lock/temp
/// cruft), and an absent namespace dir yields no roots. The all-zero
/// hash (an unset ref) is excluded.
fn walk_ref_roots_strict(
    dir: &Path,
    rel: &str,
    depth: usize,
    roots: &mut BTreeSet<Hash>,
) -> Result<(), GcRootsError> {
    if depth > MAX_REF_WALK_DEPTH {
        return Err(GcRootsError::RefTooDeep(rel.to_owned()));
    }
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    // Subdirectories wait until this directory handle closes, so a deep
    // tree holds one open handle at a time.
    let mut subdirs = Vec::new();
    for entry in rd {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            subdirs.push((entry.path(), format!("{rel}/{name}")));
            continue;
        }
        if !ft.is_file() || name.starts_with('.') {
            // Skip non-files and lock/temp cruft (e.g. `*.lock`, dotfiles).
            continue;
        }
        // Strict: read + decode, erroring (fail closed) on any failure.
        let raw = bounded_read::read_capped_string(&entry.path(), HASH_FILE_MAX_BYTES)?;
        let h = hash::from_hex(raw.trim())?;
        if h != hash::ZERO {
            roots.insert(h);
        }
    }
    for (path, child_rel) in subdirs {
        walk_ref_roots_strict(&path, &child_rel, depth + 1, roots)?;
    }
    Ok(())
}

/// Commit hashes that have at least one attestation envelope, taken from
/// the `attestations/<commit-hex>/` directory names. Non-hex directory
/// names are ignored (defensive); a missing dir yields an empty set.
fn attested_commits(common_dir: &Path) -> Result<Vec<Hash>, io::Error> {
    let dir = common_dir.join(ATTESTATIONS_DIR_NAME);
    let mut out = Vec::new();
    let rd = match fs::read_dir(&dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e),
    };
    for entry in rd {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        if let Some(name) = entry.file_name().to_str()
            && let Ok(h) = hash::from_hex(name)
        {
            out.push(h);
        }
    }
    Ok(out)
}

/// Read a single 64-hex object id from `path`, trimming trailing
/// whitespace. `Ok(None)` if the file is absent.
fn read_optional_hash(path: &Path) -> Result<Option<Hash>, GcRootsError> {
    let raw = match bounded_read::read_capped_string(path, HASH_FILE_MAX_BYTES) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    Ok(Some(hash::from_hex(trimmed)?))
}

// =====================================================================
// Tests
// =====================================================================

/// Error if `path` is a symlink — a deletion-capable gc must not follow
/// it (the target may be outside the repo). Absent path is fine.
fn reject_symlink(path: &Path) -> Result<(), GcRootsError> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => {
            Err(GcRootsError::SymlinkedStore(path.display().to_string()))
        }
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod mark_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::EntryMode;
    use crate::object::{Blob, Commit, Identity, Object, Tree, TreeEntry};
    use crate::serialize;
    use std::fs;
    use tempfile::TempDir;

    /// A repo with an initialized `.kit` dir + object store.
    fn repo() -> (TempDir, ObjectStore) {
        let d = TempDir::new().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(d.path())).unwrap();
        refs::init(&RepoLayout::single(d.path())).unwrap();
        (d, store)
    }

    fn layout(d: &TempDir) -> RepoLayout {
        RepoLayout::single(d.path())
    }

    /// Write a loose ref file (e.g. `refs/heads/main`) — the on-disk
    /// form `list_refs`/`list_tags` read.
    fn write_ref(md: &RepoLayout, rel: &str, h: &Hash) {
        let path = md.common_dir().join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, format!("{}\n", hash::to_hex(h))).unwrap();
    }

    fn write_blob(s: &ObjectStore, data: &[u8]) -> Hash {
        s.write(
            &serialize::serialize(&Object::Blob(Blob {
                data: data.to_vec(),
            }))
            .unwrap(),
        )
        .unwrap()
    }

    /// Commit a single-file tree; returns `(commit, blob)` hashes.
    fn commit_one(s: &ObjectStore, name: &[u8], data: &[u8], parents: Vec<Hash>) -> (Hash, Hash) {
        let blob = write_blob(s, data);
        let tree = s
            .write(
                &serialize::serialize(&Object::Tree(Tree {
                    entries: vec![TreeEntry {
                        name: name.to_vec(),
                        mode: EntryMode::Blob,
                        object_hash: blob,
                    }],
                }))
                .unwrap(),
            )
            .unwrap();
        let commit = s
            .write(
                &serialize::serialize(&Object::Commit(Commit {
                    tree_hash: tree,
                    parents,
                    author: Identity::opaque(b"t".to_vec()),
                    signer: [0u8; 32],
                    message: name.to_vec(),
                    // Per-commit divergence so distinct fixtures don't dedup.
                    timestamp: name.len() as u64,
                    message_hash: [0u8; 32],
                    content_digest: [0u8; 32],
                    signature: [0u8; 64],
                }))
                .unwrap(),
            )
            .unwrap();
        (commit, blob)
    }

    #[test]
    fn linked_worktree_pull_keeps_its_baseline_and_target() {
        let (d, store) = repo();
        let main = layout(&d);
        let linked = tempfile::tempdir().unwrap();
        let state_dir = main.worktree_state_dir_for("linked");
        fs::create_dir_all(&state_dir).unwrap();
        fs::write(state_dir.join("commondir"), b"../..\n").unwrap();
        fs::write(
            state_dir.join("kitdir"),
            format!("{}\n", linked.path().join(".kit").display()),
        )
        .unwrap();
        crate::layout::write_pointer_file(linked.path(), &state_dir).unwrap();
        let linked_layout = crate::layout::discover(linked.path()).unwrap();
        refs::write_head_branch(&linked_layout, "unborn").unwrap();
        let (before_commit, before_blob) = commit_one(&store, b"before", b"before", vec![]);
        let Object::Commit(before) = store.read_object(&before_commit).unwrap() else {
            panic!("commit");
        };
        let (target, target_blob) = commit_one(&store, b"target", b"target", vec![]);
        let state = super::super::pull_state::PullState {
            target,
            before_tree: before.tree_hash,
        };
        fs::write(linked_layout.pull_head_file(), state.encode()).unwrap();
        run_gc(&store, &main, u64::MAX, 0, false).unwrap();
        for hash in [target, target_blob, before.tree_hash, before_blob] {
            assert!(store.contains(&hash), "linked pull root must survive");
        }
        assert!(!store.contains(&before_commit));
        let orphan = write_blob(&store, b"cannot prune through corrupt state");
        fs::write(linked_layout.pull_head_file(), b"invalid").unwrap();
        assert!(run_gc(&store, &main, u64::MAX, 0, false).is_err());
        assert!(store.contains(&orphan));
    }

    #[test]
    fn unfinished_pull_roots_and_malformed_state_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        let _store = ObjectStore::init(&layout).unwrap();
        refs::init(&layout).unwrap();
        let state = super::super::pull_state::PullState {
            target: hash::hash(b"pull-target"),
            before_tree: hash::hash(b"pull-before-tree"),
        };
        fs::write(layout.pull_head_file(), state.encode()).unwrap();
        let roots = collect_roots(&layout).unwrap();
        assert!(roots.contains(&state.target));
        assert!(roots.contains(&state.before_tree));
        fs::write(layout.pull_head_file(), b"invalid").unwrap();
        assert!(collect_roots(&layout).is_err());
    }

    #[test]
    fn collect_roots_includes_branches_and_tags() {
        let (d, s) = repo();
        let md = layout(&d);
        let (c1, _) = commit_one(&s, b"a", b"a", vec![]);
        let (c2, _) = commit_one(&s, b"b", b"b", vec![]);
        write_ref(&md, "refs/heads/main", &c1);
        write_ref(&md, "refs/tags/v1", &c2);

        let roots = collect_roots(&md).unwrap();
        assert!(roots.contains(&c1), "branch tip must be a root");
        assert!(roots.contains(&c2), "tag target must be a root");
    }

    #[test]
    fn collect_roots_includes_orig_head_and_attested_commit() {
        let (d, s) = repo();
        let md = layout(&d);
        let (orig, _) = commit_one(&s, b"o", b"o", vec![]);
        let (att, _) = commit_one(&s, b"x", b"x", vec![]);
        fs::write(md.orig_head_file(), format!("{}\n", hash::to_hex(&orig))).unwrap();
        fs::create_dir_all(md.attestations_dir().join(hash::to_hex(&att))).unwrap();

        let roots = collect_roots(&md).unwrap();
        assert!(roots.contains(&orig), "ORIG_HEAD must be a root");
        assert!(roots.contains(&att), "attested commit must be a root");
    }

    #[test]
    fn live_objects_keeps_only_reachable_closure() {
        let (d, s) = repo();
        let md = layout(&d);
        let (kept, kept_blob) = commit_one(&s, b"keep", b"keep", vec![]);
        // An unreferenced commit + blob: reachable from no root.
        let (orphan, orphan_blob) = commit_one(&s, b"orphan", b"orphan", vec![]);
        write_ref(&md, "refs/heads/main", &kept);

        let live = live_objects(&s, &md).unwrap();
        assert!(
            live.contains(&kept) && live.contains(&kept_blob),
            "kept closure live"
        );
        assert!(
            !live.contains(&orphan) && !live.contains(&orphan_blob),
            "unreferenced objects must not be live"
        );
    }

    #[test]
    fn live_objects_aborts_truncated_when_closure_exceeds_cap() {
        // gc's fail-closed contract: beyond the reachability cap the
        // "unreachable" verdict is unsound, so live_objects (and
        // therefore run_gc) must abort rather than prune against a
        // partial closure. Each commit_one call adds 3 objects
        // (commit + tree + blob); two commits give 6 reachable objects,
        // comfortably over an injected cap of 2.
        let (d, s) = repo();
        let md = layout(&d);
        let (c1, _) = commit_one(&s, b"a", b"a", vec![]);
        let (c2, _) = commit_one(&s, b"b", b"b", vec![c1]);
        write_ref(&md, "refs/heads/main", &c2);

        let small = MarkLimits {
            cap: 2,
            ..MarkLimits::DEFAULT
        };
        let err = live_objects_with(&s, &md, small).unwrap_err();
        assert!(matches!(err, GcRootsError::Truncated));

        // Sanity: the same closure with a generous cap succeeds and
        // contains every object from both commits.
        let live = live_objects_with(&s, &md, MarkLimits::DEFAULT).unwrap();
        assert!(live.contains(&c1) && live.contains(&c2));
    }

    #[test]
    fn reachable_closure_is_union_of_single_root_closures() {
        let (_d, s) = repo();
        let (c1, b1) = commit_one(&s, b"a", b"a", vec![]);
        let (c2, b2) = commit_one(&s, b"b", b"b", vec![]);
        let multi = super::super::graph::reachable_closure(&s, [&c1, &c2]).unwrap();
        let single1 = super::super::graph::reachable_objects(&s, &c1).unwrap();
        let single2 = super::super::graph::reachable_objects(&s, &c2).unwrap();
        let union: BTreeSet<Hash> = single1.union(&single2).copied().collect();
        assert_eq!(multi, union);
        assert!([c1, b1, c2, b2].iter().all(|h| multi.contains(h)));
    }

    #[test]
    fn strict_walk_picks_up_nested_remote_ref() {
        let (d, s) = repo();
        let md = layout(&d);
        let (c, _) = commit_one(&s, b"r", b"r", vec![]);
        write_ref(&md, "refs/remotes/origin/main", &c);
        assert!(
            collect_roots(&md).unwrap().contains(&c),
            "nested remote-tracking ref must be a root"
        );
    }

    /// A ref stored before names had a segment bound can nest as deep as
    /// the length bound allows. The strict walk still reads it, so its
    /// closure is live and gc keeps it.
    #[test]
    fn gc_keeps_what_a_legacy_deep_ref_reaches() {
        let (d, s) = repo();
        let md = layout(&d);
        let (kept, kept_blob) = commit_one(&s, b"deep", b"deep", vec![]);
        let (orphan, orphan_blob) = commit_one(&s, b"orphan", b"orphan", vec![]);
        let name = vec!["a"; crate::refs::MAX_REF_NAME_BYTES / 2].join("/");
        write_ref(&md, &format!("refs/heads/{name}"), &kept);

        assert!(collect_roots(&md).unwrap().contains(&kept));
        run_gc(&s, &md, u64::MAX, 0, false).unwrap();
        assert!(s.contains(&kept) && s.contains(&kept_blob));
        assert!(!s.contains(&orphan) && !s.contains(&orphan_blob));
    }

    /// Past every name the length bound allows, gc cannot tell what the
    /// ref reaches. It refuses and deletes nothing.
    #[test]
    fn gc_refuses_and_deletes_nothing_for_a_ref_nested_beyond_any_name() {
        let (d, s) = repo();
        let md = layout(&d);
        let (kept, _) = commit_one(&s, b"deep", b"deep", vec![]);
        let (orphan, _) = commit_one(&s, b"orphan", b"orphan", vec![]);
        let name = vec!["a"; MAX_REF_WALK_DEPTH + 3].join("/");
        write_ref(&md, &format!("refs/heads/{name}"), &kept);

        assert!(matches!(
            collect_roots(&md),
            Err(GcRootsError::RefTooDeep(_))
        ));
        assert!(matches!(
            run_gc(&s, &md, u64::MAX, 0, false),
            Err(GcRootsError::RefTooDeep(_))
        ));
        assert!(s.contains(&kept) && s.contains(&orphan));
    }

    #[test]
    fn run_gc_prunes_orphans_but_never_a_live_object() {
        let (d, s) = repo();
        let md = layout(&d);
        // Live: a branch commit + its tree + blob.
        let (kept, kept_blob) = commit_one(&s, b"keep", b"keep", vec![]);
        write_ref(&md, "refs/heads/main", &kept);
        let live = live_objects(&s, &md).unwrap();
        // Orphans: unreferenced commit + its tree + blob.
        let (orphan, orphan_blob) = commit_one(&s, b"orphan", b"orphan", vec![]);

        // grace=0 → all unreachable objects are old enough to prune.
        let report = run_gc(&s, &md, u64::MAX, 0, false).unwrap();

        // The safety invariant: every live object still present.
        for h in &live {
            assert!(s.contains(h), "gc must never delete a live object");
        }
        // Orphan closure gone.
        assert!(
            !s.contains(&orphan) && !s.contains(&orphan_blob),
            "orphans pruned"
        );
        assert_eq!(report.live, live.len());
        assert!(
            report.pruned >= 2,
            "orphan commit + blob pruned: {report:?}"
        );
        // Sanity: kept objects accounted as live.
        assert!(s.contains(&kept) && s.contains(&kept_blob));
    }

    #[test]
    fn run_gc_keeps_staged_but_uncommitted_blobs() {
        let (d, s) = repo();
        let md = layout(&d);
        // A committed branch so the repo has a normal ref-side root.
        let (kept, _) = commit_one(&s, b"k", b"k", vec![]);
        write_ref(&md, "refs/heads/main", &kept);
        // Stage a blob no commit references — what `kit add` leaves
        // behind: the object in the store + an index entry.
        let staged = write_blob(&s, b"staged-only");
        let idx = index::Index::from_entries(vec![index::IndexEntry {
            path: "staged.txt".into(),
            status: index::EntryStatus::Blob,
            object_hash: staged,
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
        }]);
        index::write_index(&md, &idx).unwrap();

        assert!(
            collect_roots(&md).unwrap().contains(&staged),
            "staged blob must be a retention root"
        );
        // grace=0 → anything unrooted is pruned immediately.
        run_gc(&s, &md, u64::MAX, 0, false).unwrap();
        assert!(
            s.contains(&staged),
            "gc must never delete staged-but-uncommitted content"
        );
    }

    #[test]
    fn run_gc_grace_window_keeps_recent_orphans() {
        let (d, s) = repo();
        let md = layout(&d);
        let (kept, _) = commit_one(&s, b"k", b"k", vec![]);
        write_ref(&md, "refs/heads/main", &kept);
        let (orphan, _) = commit_one(&s, b"o", b"o", vec![]);

        // Huge grace window with now=0 → nothing is "old", so the orphan
        // is kept despite being unreachable.
        let report = run_gc(&s, &md, 0, u64::MAX, false).unwrap();
        assert!(s.contains(&orphan), "recent orphan kept by grace window");
        assert_eq!(report.pruned, 0);
        assert!(report.kept_recent >= 1, "{report:?}");
    }

    #[cfg(unix)]
    #[test]
    fn run_gc_refuses_symlinked_objects_dir() {
        use std::os::unix::fs::symlink;
        let (d, s) = repo();
        let md = layout(&d);
        let (kept, _) = commit_one(&s, b"k", b"k", vec![]);
        write_ref(&md, "refs/heads/main", &kept);

        // Replace `.kit/objects` with a symlink to an external dir. A
        // deletion-capable gc must refuse rather than prune through it.
        let external = d.path().join("external-objects");
        let real_objects = md.objects_dir();
        fs::create_dir_all(&external).unwrap();
        // Move existing shards out so the symlink target holds them.
        for entry in fs::read_dir(&real_objects).unwrap() {
            let entry = entry.unwrap();
            fs::rename(entry.path(), external.join(entry.file_name())).unwrap();
        }
        fs::remove_dir_all(&real_objects).unwrap();
        symlink(&external, &real_objects).unwrap();

        let err = run_gc(&s, &md, u64::MAX, 0, false).unwrap_err();
        assert!(
            matches!(err, GcRootsError::SymlinkedStore(_)),
            "gc must refuse a symlinked objects dir, got {err:?}"
        );
    }

    #[test]
    fn run_gc_dry_run_deletes_nothing() {
        let (d, s) = repo();
        let md = layout(&d);
        let (kept, _) = commit_one(&s, b"k", b"k", vec![]);
        write_ref(&md, "refs/heads/main", &kept);
        let (orphan, _) = commit_one(&s, b"o", b"o", vec![]);

        let report = run_gc(&s, &md, u64::MAX, 0, true).unwrap();
        assert!(report.dry_run && report.pruned >= 1, "{report:?}");
        assert!(s.contains(&orphan), "dry run must not delete the orphan");
    }

    #[test]
    fn run_gc_keeps_recovery_logged_orphan() {
        let (d, s) = repo();
        let md = layout(&d);
        let (kept, _) = commit_one(&s, b"k", b"k", vec![]);
        write_ref(&md, "refs/heads/main", &kept);
        // An orphan that is recorded in the recovery log must survive gc.
        let (superseded, superseded_blob) = commit_one(&s, b"old", b"old", vec![]);
        super::super::recovery::record(
            &md,
            &super::super::recovery::RecoveryEntry {
                timestamp: 1,
                op: "amend".into(),
                superseded,
                branch: "main".into(),
            },
        )
        .unwrap();

        run_gc(&s, &md, u64::MAX, 0, false).unwrap();
        assert!(
            s.contains(&superseded) && s.contains(&superseded_blob),
            "a recovery-logged commit must not be pruned"
        );
    }

    #[test]
    fn collect_roots_includes_recovery_log_entries() {
        let (d, s) = repo();
        let md = layout(&d);
        let (superseded, _) = commit_one(&s, b"old", b"old", vec![]);
        super::super::recovery::record(
            &md,
            &super::super::recovery::RecoveryEntry {
                timestamp: 1,
                op: "amend".into(),
                superseded,
                branch: "main".into(),
            },
        )
        .unwrap();
        assert!(
            collect_roots(&md).unwrap().contains(&superseded),
            "a superseded commit in the recovery log must be a root"
        );
    }

    #[test]
    fn corrupt_or_truncated_staging_aborts_gc_before_sweep() {
        let (d, s) = repo();
        let md = layout(&d);
        let staged = write_blob(&s, b"only staged copy");
        for bytes in [
            Vec::new(),
            b"KIDX\x03\0\0\0\0".to_vec(),
            b"KIDX\x04\0\0\0\0".to_vec(),
        ] {
            fs::write(md.index_file(), &bytes).unwrap();
            assert!(run_gc(&s, &md, u64::MAX, 0, false).is_err());
            assert!(s.contains(&staged));
        }
    }

    #[test]
    fn collect_roots_fails_closed_on_malformed_ref() {
        let (d, _s) = repo();
        let md = layout(&d);
        // A corrupt ref file (not 64-hex) must error, never be silently
        // dropped — else gc could prune the object it should pin.
        let bad = md.heads_dir().join("corrupt");
        fs::create_dir_all(bad.parent().unwrap()).unwrap();
        fs::write(&bad, b"not-a-valid-object-id\n").unwrap();
        assert!(
            matches!(collect_roots(&md), Err(GcRootsError::BadHash(_))),
            "malformed ref must fail closed"
        );
    }

    #[test]
    fn collect_roots_fails_closed_on_oversized_ref_file() {
        let (d, _s) = repo();
        let md = layout(&d);
        // A valid hash padded past the cap must error, not be read whole.
        let big = md.heads_dir().join("big");
        fs::create_dir_all(big.parent().unwrap()).unwrap();
        let mut bytes = format!("{}\n", hash::to_hex(&[7u8; 32])).into_bytes();
        bytes.resize(usize::try_from(HASH_FILE_MAX_BYTES).unwrap() + 1, b' ');
        fs::write(&big, bytes).unwrap();
        assert!(
            matches!(collect_roots(&md), Err(GcRootsError::Io(_))),
            "oversized ref must fail closed"
        );
    }

    #[test]
    fn strict_walk_skips_lock_and_dotfile_cruft() {
        let (d, s) = repo();
        let md = layout(&d);
        let (c, _) = commit_one(&s, b"m", b"m", vec![]);
        write_ref(&md, "refs/heads/main", &c);
        // Atomic-write temp files are dotfiles; a stale one must not
        // break collection.
        fs::write(md.heads_dir().join(".main.tmp.123.4"), b"garbage").unwrap();
        let roots = collect_roots(&md).unwrap();
        assert!(roots.contains(&c), "real ref still collected past cruft");
    }
}

#[cfg(test)]
mod sweep_interleaving_tests {
    use super::*;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[test]
    fn refresh_between_candidate_check_and_unlink_is_kept() {
        let td = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(td.path());
        let store = ObjectStore::init(&layout).unwrap();
        crate::refs::init(&layout).unwrap();
        let bytes = b"old orphan reused by concurrent import";
        let h = store.write(bytes).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        std::fs::File::open(store.path_for(&h))
            .unwrap()
            .set_modified(UNIX_EPOCH + Duration::from_secs(now - 100))
            .unwrap();
        let report = run_gc_with_hook(
            &store,
            &layout,
            now,
            10,
            false,
            MarkLimits::DEFAULT,
            |candidate| {
                assert_eq!(candidate, &h);
                let mut writer = store.bulk_writer();
                writer.write(bytes).unwrap();
                writer.commit().unwrap();
            },
        )
        .unwrap();
        assert!(
            store.contains(&h),
            "refreshed object was pruned: {report:?}"
        );
        assert_eq!(report.pruned, 0);
        assert_eq!(report.kept_recent, 1);
    }
}

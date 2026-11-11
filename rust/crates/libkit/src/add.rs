//! Stage files into the index.
//!
//! [`stage`] is the work of `add`. It stages named paths, the whole tree (`.`
//! or `all`), only the files the index tracks (`update`), or single hunks of
//! named files (`patch`). [`stage_tracked`] is the tracked-only restage on its
//! own, for a caller that holds the worktree lock already, such as a commit of
//! all tracked changes.
//!
//! Every object reaches the store before the index that names it. A failure
//! before the write leaves the index as it was. A name that the ignore files
//! match needs `force`, unless the index tracks it. A named path never leads
//! out of the repository, and never goes through a symlink.
//!
//! The tree walk only reads metadata. The hash of the content runs after the
//! walk, in parallel when the batch is large enough to pay for the threads.
//! The index changes in the order of the walk, whichever way the hash ran.

use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use kit_core::KitError;
use kit_core::hash::{Hash, ZERO};
use kit_core::ignore::{self, IgnoreError, IgnoreList};
use kit_core::index::{self, EntryStatus, Index, IndexEntry, IndexError};
use kit_core::layout::RepoLayout;
use kit_core::object::{Blob, Object};
use kit_core::observer::Observer;
pub use kit_core::ops::PatchHunk;
use kit_core::ops::{apply_hunks_subset, enumerate_hunks};
use kit_core::serialize;
use kit_core::store::{EphemeralSink, ObjectSink, ObjectStore, StoreError};
use kit_core::worktree::{self, WorktreeError};
use kit_sync::fanout;
use kit_sync::worktree::{index_tracks_path_or_descendant, read_or_seed_index_from_head};

use crate::lock;
use crate::repo::StoreConfig;

/// Errors from [`stage`] and [`stage_tracked`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The object store cannot be opened.
    #[error("not a kit repo: {0}")]
    NotARepository(StoreError),
    /// The worktree lock cannot be taken.
    #[error(transparent)]
    Lock(#[from] lock::Error),
    /// `patch` is on with `all` or `update`.
    #[error("-p/--patch cannot be combined with -A/--all or -u/--update")]
    PatchWithBulk,
    /// `patch` is on and no path is named.
    #[error("-p/--patch requires one or more file paths")]
    PatchNeedsPaths,
    /// `dry_run` is on with `patch` or `update`.
    #[error("-n/--dry-run cannot be combined with -p/--patch or -u/--update")]
    DryRunWithMode,
    /// `all` and `update` are both on.
    #[error("cannot combine -A/--all with -u/--update")]
    AllWithUpdate,
    /// `all` or `update` is on and a path is named.
    #[error("-A/--all and -u/--update take no path arguments")]
    BulkTakesNoPaths,
    /// No mode is on and no path is named.
    #[error("no paths given (use `.`, -A, -u, or one or more paths)")]
    NoPaths,
    /// The index cannot be read or seeded.
    #[error("{0}")]
    ReadIndex(String),
    /// The ignore files cannot be read.
    #[error("read ignore file: {0}")]
    IgnoreFile(IgnoreError),
    /// A tracked file cannot be staged again. The text names the failed step.
    #[error("{0}")]
    Refresh(String),
    /// A path is not a valid path of the index.
    #[error("invalid path: {0}")]
    InvalidPath(String),
    /// The directory above a named path cannot be resolved.
    #[error("path {}: {source}", path.display())]
    ResolveParent {
        /// The directory.
        path: PathBuf,
        /// Why it cannot be resolved.
        source: io::Error,
    },
    /// The root of the repository cannot be resolved.
    #[error("repo root: {0}")]
    RepoRoot(io::Error),
    /// A named path leads out of the repository.
    #[error("path is outside repository: {0}")]
    Outside(String),
    /// A named path goes through a symlink.
    #[error("path traverses a symbolic link ({}): refusing to stage beyond it", .0.display())]
    ThroughSymlink(PathBuf),
    /// A path cannot be inspected.
    #[error("metadata {}: {source}", path.display())]
    Metadata {
        /// The path.
        path: PathBuf,
        /// Why the inspection failed.
        source: io::Error,
    },
    /// A named path is ignored, and `force` is off.
    #[error("path '{0}' is ignored; use -f to add it anyway")]
    Ignored(String),
    /// A symlink cannot be read.
    #[error("read link {}: {source}", path.display())]
    ReadLink {
        /// The symlink.
        path: PathBuf,
        /// Why the read failed.
        source: io::Error,
    },
    /// The target of a symlink is not UTF-8.
    #[error("symlink target is not valid UTF-8")]
    SymlinkTargetNotUtf8,
    /// The target of a symlink is absolute or leaves the repository.
    #[error("invalid symlink target: {0}")]
    InvalidSymlinkTarget(String),
    /// An object cannot be encoded.
    #[error("serialize: {0}")]
    Serialize(KitError),
    /// An object cannot be stored.
    #[error("store: {0}")]
    Store(StoreError),
    /// A file cannot be stored.
    #[error("store: {0}")]
    StoreFile(WorktreeError),
    /// A path is not a regular file or a symlink.
    #[error("not a regular file: {}", .0.display())]
    NotRegular(PathBuf),
    /// The content of a file cannot be hashed and stored.
    #[error("{}: {source}", path.display())]
    Hash {
        /// The file.
        path: PathBuf,
        /// Why it failed.
        source: WorktreeError,
    },
    /// A directory cannot be listed.
    #[error("read dir {}: {source}", path.display())]
    ReadDir {
        /// The directory.
        path: PathBuf,
        /// Why the listing failed.
        source: io::Error,
    },
    /// A staged blob cannot be compared with the new one.
    #[error("compare staged {path}: {source}")]
    CompareStaged {
        /// The path.
        path: String,
        /// Why the comparison failed.
        source: StoreError,
    },
    /// The index cannot be written.
    #[error("write index: {0}")]
    WriteIndex(IndexError),
    /// `patch` names a path that is not a regular file.
    #[error("-p/--patch supports regular files only: {0}")]
    PatchRegularOnly(String),
    /// The staged blob of a file cannot be read.
    #[error("read staged blob: {0}")]
    ReadStagedBlob(WorktreeError),
    /// A file cannot be read.
    #[error("read {}: {source}", path.display())]
    ReadFile {
        /// The file.
        path: PathBuf,
        /// Why the read failed.
        source: WorktreeError,
    },
    /// The chooser of hunks cannot read its input.
    #[error("read input: {0}")]
    ReadInput(io::Error),
}

/// What [`stage`] does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // independent switches of the command
pub struct Request<'a> {
    /// Stage every change in the tree, and record deletions of tracked files.
    /// This takes no paths.
    pub all: bool,
    /// Stage again only the files that the index tracks. This takes no paths.
    pub update: bool,
    /// Choose single hunks of the named files, with the chooser. This needs
    /// paths, and it takes neither `all` nor `update`.
    pub patch: bool,
    /// Stage a named path that the ignore files match.
    pub force: bool,
    /// Report what the call would stage and change nothing: no object, no
    /// index. This takes neither `patch` nor `update`.
    pub dry_run: bool,
    /// The named paths. `.` stands for the whole tree.
    pub paths: &'a [String],
}

/// What a [`HunkChooser`] decides for one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Choice {
    /// The indices of the hunks to stage.
    pub selected: Vec<usize>,
    /// Stop after this file. The other named files stay as they are.
    pub quit: bool,
}

/// Chooses the hunks to stage.
pub trait HunkChooser {
    /// Choose from the `hunks` of the file at `path`.
    ///
    /// # Errors
    /// The error of the input that the chooser reads from.
    fn choose(&mut self, path: &str, hunks: &[PatchHunk]) -> io::Result<Choice>;
}

/// What [`stage`] reports to its [`Observer`] while it chooses hunks.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// A file is binary, so it has no hunks to choose from.
    BinarySkipped {
        /// The path.
        path: String,
    },
    /// A file has no change against the index.
    NoChanges {
        /// The path.
        path: String,
    },
    /// The chosen hunks of a file are staged.
    HunksStaged {
        /// The path.
        path: String,
        /// How many hunks the chooser took.
        selected: usize,
        /// How many hunks the file has.
        total: usize,
    },
    /// A dry run finds a file that the call would stage or update.
    WouldAdd {
        /// The path.
        path: String,
    },
    /// A dry run finds a tracked file that the call would record as deleted.
    WouldRemove {
        /// The path.
        path: String,
    },
}

/// Stage files as `request` says.
///
/// `cwd` is the root of the tree for every mode except `patch`, which uses
/// the root of `layout`. The operation takes the worktree lock after it opens
/// the store, and it holds the lock until the index is written.
///
/// # Errors
/// [`Error`], with one variant for each refused or failed step. A refusal
/// before the index write leaves the index as it was. With `patch`, a failure
/// in the middle leaves the index as it was too, because the index is written
/// once at the end.
#[allow(clippy::too_many_arguments)] // the inputs of one command
pub fn stage(
    layout: &RepoLayout,
    store_config: &StoreConfig<'_>,
    cwd: &Path,
    request: &Request<'_>,
    chooser: &mut dyn HunkChooser,
    lock_observer: &dyn Observer<lock::Event>,
    observer: &dyn Observer<Event>,
) -> Result<(), Error> {
    let store = store_config.open(layout).map_err(Error::NotARepository)?;
    let _lock = lock::acquire_worktree(layout, lock_observer)?;

    if request.dry_run && (request.patch || request.update) {
        return Err(Error::DryRunWithMode);
    }
    if request.patch {
        if request.all || request.update {
            return Err(Error::PatchWithBulk);
        }
        if request.paths.is_empty() {
            return Err(Error::PatchNeedsPaths);
        }
        return patch(layout, &store, request, chooser, observer);
    }

    if request.all && request.update {
        return Err(Error::AllWithUpdate);
    }
    if (request.all || request.update) && !request.paths.is_empty() {
        return Err(Error::BulkTakesNoPaths);
    }
    if request.update {
        return stage_tracked(layout, &store);
    }

    let mut idx = read_or_seed_index_from_head(layout, &store).map_err(Error::ReadIndex)?;
    let previous = idx.clone();

    // One durability batch for the whole call. A staged object costs no full
    // flush until the commit below, which runs before the index write.
    let batch = store.batch();
    // A dry run hashes into memory, so the store gets no object.
    let ephemeral = EphemeralSink::new(&store);
    let sink: &(dyn ObjectSink + Sync) = if request.dry_run { &ephemeral } else { &batch };

    if request.all {
        add_whole_tree(cwd, sink, &mut idx)?;
    } else if request.paths.is_empty() {
        return Err(Error::NoPaths);
    } else {
        // An ignored path that is named is refused. The ignore files load once
        // for all the paths.
        let ignores = ignore::load(cwd).map_err(Error::IgnoreFile)?;
        for target in request.paths {
            if target == "." {
                add_whole_tree(cwd, sink, &mut idx)?;
            } else {
                // The walk of the whole tree cannot leave the repository. A
                // named path can, through a symlink above it.
                let p = Path::new(target);
                let abs = if p.is_absolute() {
                    p.to_path_buf()
                } else {
                    cwd.join(p)
                };
                ensure_within_repo(cwd, &abs)?;
                add_one(cwd, p, sink, &mut idx, &ignores, request.force)?;
            }
        }
    }

    if request.dry_run {
        report_changes(&previous, &idx, observer);
        return Ok(());
    }

    // The objects become durable before the index that names them.
    batch.commit().map_err(Error::Store)?;
    retain_content_identities(&store, &previous, &mut idx)?;
    index::write_index(layout, &idx).map_err(Error::WriteIndex)
}

/// Report to `observer` each entry of `next` that a real run would add, update
/// or record as deleted. The report is in path order, whatever the order of the
/// walk was.
fn report_changes(previous: &Index, next: &Index, observer: &dyn Observer<Event>) {
    let old: HashMap<_, _> = previous
        .entries
        .iter()
        .map(|e| (e.path.as_str(), e))
        .collect();
    let mut changes: Vec<Event> = Vec::new();
    for entry in &next.entries {
        let before = old
            .get(entry.path.as_str())
            .filter(|b| b.status != EntryStatus::Removed);
        let path = entry.path.clone();
        if entry.status == EntryStatus::Removed {
            if before.is_some() {
                changes.push(Event::WouldRemove { path });
            }
        } else if before
            .is_none_or(|b| b.status != entry.status || b.object_hash != entry.object_hash)
        {
            changes.push(Event::WouldAdd { path });
        }
    }
    changes.sort_by(|a, b| event_path(a).cmp(event_path(b)));
    for change in &changes {
        observer.event(change);
    }
}

fn event_path(event: &Event) -> &str {
    match event {
        Event::WouldAdd { path } | Event::WouldRemove { path } => path,
        _ => "",
    }
}

/// Stage again the entries that the index tracks. Update the entries of
/// modified files and record the deletions. Add no untracked path.
///
/// The caller holds the worktree lock.
///
/// # Errors
/// [`Error::Refresh`], with the text of the failed step.
pub fn stage_tracked(layout: &RepoLayout, store: &ObjectStore) -> Result<(), Error> {
    let root = layout.worktree_root();
    let mut idx = read_or_seed_index_from_head(layout, store).map_err(Error::Refresh)?;
    let previous = idx.clone();

    // The objects of the restage share one durability batch. It commits
    // before the index write that names them.
    let batch = store.batch();

    for entry in &mut idx.entries {
        if entry.status == EntryStatus::Removed {
            continue;
        }
        if !index::validate_index_path(&entry.path) {
            return Err(Error::Refresh(format!(
                "invalid index path: {}",
                entry.path
            )));
        }

        let abs = root.join(&entry.path);
        let meta = match abs.symlink_metadata() {
            Ok(meta) => meta,
            Err(e) if is_gone(&e) => {
                entry.status = EntryStatus::Removed;
                entry.object_hash = ZERO;
                continue;
            }
            Err(e) => {
                return Err(Error::Refresh(format!("metadata {}: {e}", abs.display())));
            }
        };

        // A file whose time, size and mode class match the entry keeps the
        // entry. No read, no hash, no store.
        if worktree::stat_matches(entry, &meta) {
            continue;
        }

        // A regular file goes through the same path as `build_tree` and
        // `hash_file`, so a large file becomes a chunked blob, and the hashes
        // of commit, status and rm agree. A symlink is one blob of its target.
        let (status, h, stat) = if meta.file_type().is_file() {
            let (h, opened_meta) = worktree::hash_file_with_metadata(&batch, &abs)
                .map_err(|e| Error::Refresh(format!("read/store {}: {e}", abs.display())))?;
            let stat = worktree::stat_cache_fields(&opened_meta);
            (file_status_from_meta(&opened_meta, entry.status), h, stat)
        } else if meta.file_type().is_symlink() {
            let target = std::fs::read_link(&abs)
                .map_err(|e| Error::Refresh(format!("read link {}: {e}", abs.display())))?;
            let target_str = target
                .to_str()
                .ok_or_else(|| Error::Refresh("symlink target is not valid UTF-8".to_owned()))?;
            if !worktree::validate_symlink_target(target_str) {
                return Err(Error::Refresh(format!(
                    "invalid symlink target: {target_str}"
                )));
            }
            let blob = Object::Blob(Blob {
                data: target_str.as_bytes().to_vec(),
            });
            let ser = serialize::serialize(&blob)
                .map_err(|e| Error::Refresh(format!("serialize: {e}")))?;
            let h = batch
                .put(&ser)
                .map_err(|e| Error::Refresh(format!("store: {e}")))?;
            // A symlink never matches the stat cache.
            (EntryStatus::Symlink, h, (0, 0, 0, 0))
        } else {
            entry.status = EntryStatus::Removed;
            entry.object_hash = ZERO;
            continue;
        };

        entry.status = status;
        entry.object_hash = h;
        entry.mtime_ns = stat.0;
        entry.size = stat.1;
        entry.ino = stat.2;
        entry.ctime_ns = stat.3;
    }

    // The objects first, then the index that names them.
    batch
        .commit()
        .map_err(|e| Error::Refresh(format!("store: {e}")))?;
    retain_content_identities(store, &previous, &mut idx)
        .map_err(|e| Error::Refresh(e.to_string()))?;
    index::write_index(layout, &idx).map_err(|e| Error::Refresh(format!("write index: {e}")))
}

fn is_gone(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    )
}

#[cfg(unix)]
fn file_status_from_meta(meta: &std::fs::Metadata, _previous: EntryStatus) -> EntryStatus {
    use std::os::unix::fs::PermissionsExt;

    if meta.permissions().mode() & 0o111 != 0 {
        EntryStatus::Executable
    } else {
        EntryStatus::Blob
    }
}

#[cfg(not(unix))]
fn file_status_from_meta(_meta: &std::fs::Metadata, previous: EntryStatus) -> EntryStatus {
    if previous == EntryStatus::Executable {
        EntryStatus::Executable
    } else {
        EntryStatus::Blob
    }
}

/// Keep the staged form of a blob when the new content is the same. The batch
/// is durable by now, so the comparison reads the bytes that were hashed, and
/// never a second read of the tree.
fn retain_content_identities(
    store: &ObjectStore,
    previous: &Index,
    next: &mut Index,
) -> Result<(), Error> {
    let old: HashMap<_, _> = previous
        .entries
        .iter()
        .map(|e| (e.path.as_str(), e))
        .collect();
    for entry in &mut next.entries {
        if entry.status == EntryStatus::Removed {
            continue;
        }
        if let Some(before) = old.get(entry.path.as_str())
            && before.status != EntryStatus::Removed
            // The target of a symlink needs a single blob. A regular file
            // with the same bytes may be chunked, so the new target stays when
            // a regular file becomes a symlink.
            && (entry.status != EntryStatus::Symlink || before.status == EntryStatus::Symlink)
            && worktree::content_eq(store, &before.object_hash, &entry.object_hash).map_err(
                |source| Error::CompareStaged {
                    path: entry.path.clone(),
                    source,
                },
            )?
        {
            entry.object_hash = before.object_hash;
        }
    }
    Ok(())
}

/// Stage every file under `root` that the ignore files do not match, then
/// record the deletion of each tracked path that is gone.
fn add_whole_tree(
    root: &Path,
    sink: &(dyn ObjectSink + Sync),
    idx: &mut Index,
) -> Result<(), Error> {
    let ignores = ignore::load(root).map_err(Error::IgnoreFile)?;
    let mut seen = HashSet::new();
    let mut pending = Vec::new();
    add_tree(
        root,
        root,
        false,
        sink,
        idx,
        &ignores,
        &mut seen,
        &mut pending,
    )?;

    // The walk only inspects metadata, which is cheap. The open, the read and
    // the hash are the cost, and they run here.
    let hashed = hash_pending_batch(&pending, sink);

    // One failure ends the call, and the caller writes nothing on an error.
    // The first failure in walk order is the one to report, the file that a
    // sequential run would have stopped on. The entries staged before it are
    // lost with `idx`.
    for (p, outcome) in pending.into_iter().zip(hashed) {
        match outcome {
            HashOutcome::Done(hashed_file) => {
                stage_hashed(idx, p.rel_str.clone(), hashed_file);
                seen.insert(p.rel_str);
            }
            HashOutcome::Failed(e) => return Err(e),
            // The file ran after an earlier failure. The failure comes in the
            // walk before this file or after it, and the loop reaches it.
            HashOutcome::Skipped => {}
        }
    }

    mark_missing_paths_removed(root, idx, &seen);
    Ok(())
}

/// The files per thread below which the hash of a batch runs in sequence.
///
/// The benchmark `add_hash_fanout` measured a 4-core host. The dispatch of the
/// thread pool costs 25 to 100 percent for 1 to 16 files, ties at 32 files and
/// wins clearly from 64 files. 32 files on 4 threads is 8 files per thread,
/// the safe side of that crossover. The threshold scales with the real pool,
/// so a host with another core count keeps the same ratio, and the ratio is
/// assumed to hold.
const HASH_FANOUT_FILES_PER_THREAD: usize = 8;

fn hash_fanout_threshold() -> usize {
    fanout::threshold(HASH_FANOUT_FILES_PER_THREAD)
}

/// Hash one pending file. Skip it once an earlier failure set `aborted`. The
/// sequential and the parallel run share this, so their stop rule is the same.
fn hash_one(
    sink: &(dyn ObjectSink + Sync),
    aborted: &AtomicBool,
    p: &PendingHash,
    chunk_fanout: bool,
) -> HashOutcome {
    if aborted.load(Ordering::Relaxed) {
        return HashOutcome::Skipped;
    }
    match hash_pending(sink, p, chunk_fanout) {
        Ok(v) => HashOutcome::Done(v),
        Err(e) => {
            aborted.store(true, Ordering::Relaxed);
            HashOutcome::Failed(e)
        }
    }
}

/// Hash every pending file, in sequence below [`hash_fanout_threshold`] and on
/// the global thread pool from there. The result has the order of `pending`.
/// Both runs stop starting new hashes after the first failure.
///
/// The parallel run turns the chunk fan-out of a single file off. Every file
/// has a busy worker already, and a nested fan-out into the same pool was not
/// measured to help. The sequential run has no outer parallelism, so a single
/// huge file keeps the chunk fan-out.
fn hash_pending_batch(pending: &[PendingHash], sink: &(dyn ObjectSink + Sync)) -> Vec<HashOutcome> {
    let aborted = AtomicBool::new(false);
    fanout::map_seq_or_par(pending, hash_fanout_threshold(), |p, is_par| {
        hash_one(sink, &aborted, p, !is_par)
    })
}

/// The result of the hash of one pending file.
enum HashOutcome {
    Done(HashedFile),
    Failed(Error),
    /// Another file failed first, so this one never ran.
    Skipped,
}

/// A regular file that [`route_path`] chose to stage, with its hash still to
/// do.
struct PendingHash {
    abs: PathBuf,
    rel_str: String,
    previous_status: EntryStatus,
}

/// What [`route_path`] decided for one path.
enum Routed {
    /// The path is staged already, or needs nothing.
    Done(String),
    /// The file needs its hash.
    NeedsHash(PendingHash),
}

/// Check `abs` and `rel`, apply the ignore and the stat cache, and stage a
/// symlink at once, because that needs no read of the content. A regular file
/// comes back as a [`PendingHash`], so a caller with many files can hash them
/// in parallel.
fn route_path(
    root: &Path,
    rel: &Path,
    sink: &dyn ObjectSink,
    idx: &mut Index,
    ignores: &IgnoreList,
    force: bool,
) -> Result<Routed, Error> {
    let abs = if rel.is_absolute() {
        rel.to_path_buf()
    } else {
        root.join(rel)
    };
    let meta = abs.symlink_metadata().map_err(|source| Error::Metadata {
        path: abs.clone(),
        source,
    })?;
    let rel_str = abs
        .strip_prefix(root)
        .unwrap_or(rel)
        .to_string_lossy()
        .replace('\\', "/");
    if !index::validate_index_path(&rel_str) {
        return Err(Error::InvalidPath(rel_str));
    }
    // One lookup serves every check below.
    let existing_pos = idx.find_entry(&rel_str);
    let previous_status = existing_pos.map_or(EntryStatus::Blob, |i| idx.entries[i].status);
    // A path that is named and ignored needs `force`. A path that is tracked
    // is never ignored.
    let already_tracked = previous_status != EntryStatus::Removed && existing_pos.is_some();
    if !force && !already_tracked && ignores.is_ignored_with_ancestors(&rel_str, meta.is_dir()) {
        return Err(Error::Ignored(rel_str));
    }
    // A tracked file whose time, size and mode class match is staged to the
    // byte. No read, no hash, no store.
    if let Some(existing) = existing_pos
        && worktree::stat_matches(&idx.entries[existing], &meta)
    {
        return Ok(Routed::Done(rel_str));
    }
    if meta.file_type().is_file() {
        Ok(Routed::NeedsHash(PendingHash {
            abs,
            rel_str,
            previous_status,
        }))
    } else if meta.file_type().is_symlink() {
        let target = std::fs::read_link(&abs).map_err(|source| Error::ReadLink {
            path: abs.clone(),
            source,
        })?;
        let Some(target_str) = target.to_str().map(str::to_owned) else {
            return Err(Error::SymlinkTargetNotUtf8);
        };
        if !worktree::validate_symlink_target(&target_str) {
            return Err(Error::InvalidSymlinkTarget(target_str));
        }
        let blob = Object::Blob(Blob {
            data: target_str.into_bytes(),
        });
        let ser = serialize::serialize(&blob).map_err(Error::Serialize)?;
        let h = sink.put(&ser).map_err(Error::Store)?;
        let entry = IndexEntry {
            path: rel_str.clone(),
            // A symlink never matches the stat cache.
            status: EntryStatus::Symlink,
            object_hash: h,
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
        };
        idx.remove_directory_conflicts(&entry.path);
        idx.upsert_entry(entry);
        Ok(Routed::Done(rel_str))
    } else {
        Err(Error::NotRegular(abs))
    }
}

/// The staging fields of a hashed file: the status, the content hash and the
/// stat cache `(mtime_ns, size, ino, ctime_ns)`.
type HashedFile = (EntryStatus, Hash, (u64, u64, u64, u64));

/// The chunks per thread below which the chunk batch of a large file hashes
/// in sequence. It has the shape of [`HASH_FANOUT_FILES_PER_THREAD`], with its
/// own value, because a chunk costs one hash of up to the maximum chunk size
/// and a temporary file write.
///
/// The benchmark `chunk_hash_fanout` measured a 4-core host. 8 chunks tie, 16
/// chunks win by 15 percent, and a batch of 64 chunks wins by 16 percent. 32
/// chunks win the most, by 31 percent. 4 chunks per thread puts the crossover
/// at 16 chunks on 4 threads, the first size with a clean win. From end to
/// end, the files of 8, 32 and 128 MiB ran 1.7 to 2.2 times as fast.
const CHUNK_FANOUT_CHUNKS_PER_THREAD: usize = 4;

fn chunk_fanout_threshold() -> usize {
    fanout::threshold(CHUNK_FANOUT_CHUNKS_PER_THREAD)
}

/// Hash and store the content of one pending file. The function reads no index
/// and reports nothing, so a batch can call it from many threads. The
/// `WriteBatch` behind `sink` holds a lock for its dedup check only, and its
/// file writes run outside the lock.
///
/// A file above `CHUNK_THRESHOLD` hashes and stores its chunks in batches. With
/// `chunk_fanout`, a batch large enough to pay for the dispatch runs on the
/// thread pool.
fn hash_pending(
    sink: &(dyn ObjectSink + Sync),
    p: &PendingHash,
    chunk_fanout: bool,
) -> Result<HashedFile, Error> {
    let result = if chunk_fanout {
        worktree::hash_file_with_metadata_with(sink, &p.abs, |sink, batch| {
            fanout::try_map_seq_or_par(batch, chunk_fanout_threshold(), |chunk| {
                worktree::store_chunk_blob(sink, chunk)
            })
        })
    } else {
        // Every file has a busy worker. Borrow each chunk from the reader,
        // and allocate no batches in sequence.
        worktree::hash_file_with_metadata(sink, &p.abs)
    };
    let (h, opened_meta) = result.map_err(|source| Error::Hash {
        path: p.abs.clone(),
        source,
    })?;
    let stat = worktree::stat_cache_fields(&opened_meta);
    let status = file_status_from_meta(&opened_meta, p.previous_status);
    Ok((status, h, stat))
}

/// Make the entry of a hashed file and apply it to the index.
fn stage_hashed(idx: &mut Index, rel_str: String, hashed: HashedFile) {
    let (status, h, stat) = hashed;
    let entry = IndexEntry {
        path: rel_str,
        status,
        object_hash: h,
        mtime_ns: stat.0,
        size: stat.1,
        ino: stat.2,
        ctime_ns: stat.3,
    };
    idx.remove_directory_conflicts(&entry.path);
    idx.upsert_entry(entry);
}

fn add_one(
    root: &Path,
    rel: &Path,
    sink: &(dyn ObjectSink + Sync),
    idx: &mut Index,
    ignores: &IgnoreList,
    force: bool,
) -> Result<String, Error> {
    match route_path(root, rel, sink, idx, ignores, force)? {
        Routed::Done(rel_str) => Ok(rel_str),
        Routed::NeedsHash(p) => {
            // A single path is never one of many workers, so the chunk
            // fan-out is the only parallelism a large file can have.
            let hashed = hash_pending(sink, &p, true)?;
            stage_hashed(idx, p.rel_str.clone(), hashed);
            Ok(p.rel_str)
        }
    }
}

/// Walk `dir` and send each file and symlink through [`route_path`]. A symlink
/// and a stat cache hit are staged on the visit. A regular file that needs its
/// hash goes into `pending`.
#[allow(clippy::too_many_arguments)] // the state of one walk
fn add_tree(
    root: &Path,
    dir: &Path,
    parent_ignored: bool,
    sink: &dyn ObjectSink,
    idx: &mut Index,
    ignores: &IgnoreList,
    seen: &mut HashSet<String>,
    pending: &mut Vec<PendingHash>,
) -> Result<(), Error> {
    let rd = std::fs::read_dir(dir).map_err(|source| Error::ReadDir {
        path: dir.to_path_buf(),
        source,
    })?;
    for ent in rd.flatten() {
        let p = ent.path();
        let meta = p.symlink_metadata().map_err(|source| Error::Metadata {
            path: p.clone(),
            source,
        })?;
        let is_dir = meta.file_type().is_dir();
        // The patterns match the path from the root, so a pattern with a
        // leading slash or a middle slash works. The name alone is not enough.
        let rel_path = p
            .strip_prefix(root)
            .unwrap_or(&p)
            .to_string_lossy()
            .replace('\\', "/");
        // An ignore rule hides untracked content only. A tracked file stays
        // in view, and so does a directory that holds tracked content, so
        // `add .` and `add -A` refresh the tracked changes. The bit of an
        // ignored ancestor goes down, so the untracked and ignored children of
        // a tracked directory stay out.
        let entry_ignored = parent_ignored || ignores.is_ignored(&rel_path, is_dir);
        if entry_ignored && !index_tracks_path_or_descendant(idx, &rel_path) {
            continue;
        }
        if meta.file_type().is_dir() {
            add_tree(root, &p, entry_ignored, sink, idx, ignores, seen, pending)?;
        } else if meta.file_type().is_file() || meta.file_type().is_symlink() {
            // The decision to include is made, so `force` skips the second
            // look at the ignore rules in `route_path`.
            match route_path(root, &p, sink, idx, ignores, true)? {
                Routed::Done(rel) => {
                    seen.insert(rel);
                }
                Routed::NeedsHash(pend) => pending.push(pend),
            }
        }
    }
    Ok(())
}

fn mark_missing_paths_removed(root: &Path, idx: &mut Index, seen: &HashSet<String>) {
    for entry in &mut idx.entries {
        if entry.status != EntryStatus::Removed
            && !seen.contains(&entry.path)
            && matches!(root.join(&entry.path).symlink_metadata(), Err(e) if is_gone(&e))
        {
            entry.status = EntryStatus::Removed;
            entry.object_hash = ZERO;
        }
    }
}

/// Choose hunks across the named files. The index is seeded from `HEAD`, so a
/// committed file has a base. It is written once, and only when a hunk was
/// staged, so a choice of nothing leaves the index as it was.
fn patch(
    layout: &RepoLayout,
    store: &ObjectStore,
    request: &Request<'_>,
    chooser: &mut dyn HunkChooser,
    observer: &dyn Observer<Event>,
) -> Result<(), Error> {
    let root = layout.worktree_root();
    let mut idx = read_or_seed_index_from_head(layout, store).map_err(Error::ReadIndex)?;
    let ignores = ignore::load(root).map_err(Error::IgnoreFile)?;
    let mut any_staged = false;
    for target in request.paths {
        let outcome = patch_one_file(
            root,
            Path::new(target),
            store,
            &mut idx,
            &ignores,
            request.force,
            chooser,
            observer,
        )?;
        any_staged |= outcome.staged;
        if outcome.quit {
            break;
        }
    }
    if any_staged {
        index::write_index(layout, &idx).map_err(Error::WriteIndex)?;
    }
    Ok(())
}

/// What the choice of hunks did for one file.
struct PatchOutcome {
    /// A hunk was staged, so the index needs a write.
    staged: bool,
    /// The chooser asked to stop.
    quit: bool,
}

#[allow(clippy::too_many_arguments)] // the state of one file
fn patch_one_file(
    root: &Path,
    rel: &Path,
    store: &ObjectStore,
    idx: &mut Index,
    ignores: &IgnoreList,
    force: bool,
    chooser: &mut dyn HunkChooser,
    observer: &dyn Observer<Event>,
) -> Result<PatchOutcome, Error> {
    let abs = if rel.is_absolute() {
        rel.to_path_buf()
    } else {
        root.join(rel)
    };
    let meta = abs.symlink_metadata().map_err(|source| Error::Metadata {
        path: abs.clone(),
        source,
    })?;
    let rel_str = abs
        .strip_prefix(root)
        .unwrap_or(rel)
        .to_string_lossy()
        .replace('\\', "/");
    if !index::validate_index_path(&rel_str) {
        return Err(Error::InvalidPath(rel_str));
    }
    // A path behind a symlink could name a file outside the repository, and
    // the read would follow the link.
    ensure_within_repo(root, &abs)?;
    // Hunks exist for a regular file. A directory, a symlink and a special
    // file are refused.
    if !meta.file_type().is_file() {
        return Err(Error::PatchRegularOnly(rel_str));
    }
    // A named and ignored path needs `force`, as for a plain staging. A
    // tracked path is never ignored.
    let already_tracked = idx
        .find_entry(&rel_str)
        .is_some_and(|i| idx.entries[i].status != EntryStatus::Removed);
    if !force && !already_tracked && ignores.is_ignored_with_ancestors(&rel_str, false) {
        return Err(Error::Ignored(rel_str));
    }

    // The base is the staged blob, or the blob that HEAD seeded. A new file
    // has an empty base. The other side is the content in the tree.
    let base = match idx.find_entry(&rel_str) {
        Some(i) if idx.entries[i].status != EntryStatus::Removed => {
            worktree::read_blob(store, &idx.entries[i].object_hash)
                .map_err(Error::ReadStagedBlob)?
        }
        _ => Vec::new(),
    };
    let previous_status = idx
        .find_entry(&rel_str)
        .map_or(EntryStatus::Blob, |i| idx.entries[i].status);
    let (opened_meta, work_bytes) =
        worktree::read_regular_file_bounded(&abs).map_err(|source| Error::ReadFile {
            path: abs.clone(),
            source,
        })?;

    let hunks = match enumerate_hunks(&base, &work_bytes) {
        None => {
            observer.event(&Event::BinarySkipped { path: rel_str });
            return Ok(PatchOutcome {
                staged: false,
                quit: false,
            });
        }
        Some(h) if h.is_empty() => {
            observer.event(&Event::NoChanges { path: rel_str });
            return Ok(PatchOutcome {
                staged: false,
                quit: false,
            });
        }
        Some(h) => h,
    };

    let Choice { selected, quit } = chooser.choose(&rel_str, &hunks).map_err(Error::ReadInput)?;
    if selected.is_empty() {
        return Ok(PatchOutcome {
            staged: false,
            quit,
        });
    }

    let new_bytes = apply_hunks_subset(&base, &hunks, &selected);
    let h = worktree::store_file_object(store, &new_bytes).map_err(Error::StoreFile)?;
    let status = file_status_from_meta(&opened_meta, previous_status);
    let entry = IndexEntry {
        path: rel_str.clone(),
        status,
        object_hash: h,
        mtime_ns: 0,
        size: 0,
        ino: 0,
        ctime_ns: 0,
    };
    idx.remove_directory_conflicts(&entry.path);
    idx.upsert_entry(entry);
    observer.event(&Event::HunksStaged {
        path: rel_str,
        selected: selected.len(),
        total: hunks.len(),
    });
    Ok(PatchOutcome { staged: true, quit })
}

/// Refuse a named path that leaves the repository through a symlink above it.
/// There are two refusals, as git has them for a path "beyond a symbolic
/// link".
///
/// 1. The path leaves the repository. Its resolved parent is not below the
///    resolved root. This covers `..` and a symlink that points out.
/// 2. A component above the last one is a symlink, even one that points back
///    into the repository. The index would hold a path that the tree can never
///    give back, because the tree sees `link_in` as a symlink and not as a
///    directory. A symlink as the last component is fine. It is staged as a
///    symlink.
///
/// The walk of the whole tree does not descend into a symlinked directory, so
/// it needs no such check.
fn ensure_within_repo(root: &Path, abs: &Path) -> Result<(), Error> {
    use std::path::Component;

    let parent = abs
        .parent()
        .ok_or_else(|| Error::InvalidPath(abs.display().to_string()))?;
    let real_parent = parent
        .canonicalize()
        .map_err(|source| Error::ResolveParent {
            path: parent.to_path_buf(),
            source,
        })?;
    let real_root = root.canonicalize().map_err(Error::RepoRoot)?;
    if real_parent != real_root && !real_parent.starts_with(&real_root) {
        return Err(Error::Outside(abs.display().to_string()));
    }

    // Look for a symlink between the root and the last component. A path
    // that is not below the root in text was refused above.
    if let Ok(rel) = abs.strip_prefix(root) {
        let comps: Vec<Component<'_>> = rel.components().collect();
        let parent_count = comps.len().saturating_sub(1);
        let mut cur = root.to_path_buf();
        for comp in &comps[..parent_count] {
            if let Component::Normal(name) = comp {
                cur.push(name);
                if matches!(cur.symlink_metadata(), Ok(m) if m.file_type().is_symlink()) {
                    return Err(Error::ThroughSymlink(cur));
                }
            }
        }
    }
    Ok(())
}

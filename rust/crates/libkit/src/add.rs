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
use std::ffi::OsString;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use kit_core::KitError;
use kit_core::hash::{self, Hash, ZERO};
use kit_core::ignore::{self, IgnoreError, IgnoreList};
use kit_core::index::{self, EntryStatus, Index, IndexEntry, IndexError};
use kit_core::layout::RepoLayout;
use kit_core::object::{Blob, Object};
use kit_core::observer::Observer;
pub use kit_core::ops::PatchHunk;
use kit_core::ops::restore::is_restore_temp_name;
use kit_core::ops::{BINARY_SNIFF_LEN, apply_hunks_subset, enumerate_hunks, is_binary};
use kit_core::serialize;
use kit_core::store::{HashOnlySink, ObjectSink, ObjectStore, StoreError};
use kit_core::worktree::{self, LoadedBlob, WorktreeError};
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
    Store(#[source] StoreError),
    /// A file cannot be stored.
    #[error("store: {0}")]
    StoreFile(#[source] WorktreeError),
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
    WriteIndex(#[source] IndexError),
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
    /// Input bytes hashed so far, excluding object headers and manifests.
    /// Concurrent observers can receive samples out of order.
    HashProgress { bytes: u64 },
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
    stage_with_limit(
        layout,
        store_config,
        cwd,
        request,
        chooser,
        lock_observer,
        observer,
        index::MAX_INDEX_BYTES,
    )
}

#[allow(clippy::too_many_arguments)]
fn stage_with_limit(
    layout: &RepoLayout,
    store_config: &StoreConfig<'_>,
    cwd: &Path,
    request: &Request<'_>,
    chooser: &mut dyn HunkChooser,
    lock_observer: &dyn Observer<lock::Event>,
    observer: &dyn Observer<Event>,
    limit: u64,
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
        return patch(layout, &store, request, chooser, observer, limit);
    }

    if request.all && request.update {
        return Err(Error::AllWithUpdate);
    }
    if (request.all || request.update) && !request.paths.is_empty() {
        return Err(Error::BulkTakesNoPaths);
    }
    if request.update {
        return stage_tracked_observed(layout, &store, observer);
    }

    let mut idx = read_or_seed_index_from_head(layout, &store).map_err(Error::ReadIndex)?;
    let previous = idx.clone();

    // One durability batch for the whole call. A staged object costs no full
    // flush until the commit below, which runs before the index write.
    let batch = store.batch();
    // A dry run only hashes, so the store gets no object and the run keeps
    // none in memory.
    let hash_only = HashOnlySink::new();
    let sink: &(dyn ObjectSink + Sync) = if request.dry_run { &hash_only } else { &batch };

    let pending = prepare(cwd, request, &mut idx, limit)?;
    let progress_sink = HashProgressSink::new(sink, observer)?;
    observer.event(&Event::HashProgress { bytes: 0 });
    let hashed = hash_pending_batch(&pending, &progress_sink);
    observer.event(&Event::HashProgress {
        bytes: progress_sink.bytes.load(Ordering::Relaxed),
    });
    for (p, outcome) in pending.into_iter().zip(hashed) {
        match outcome {
            HashOutcome::Done(file) => stage_hashed(&mut idx, p.rel_str, file),
            HashOutcome::Failed(e) => return Err(e),
            HashOutcome::Skipped => {}
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
    stage_tracked_observed(layout, store, &crate::NoopObserver)
}

fn stage_tracked_observed(
    layout: &RepoLayout,
    store: &ObjectStore,
    observer: &dyn Observer<Event>,
) -> Result<(), Error> {
    let root = layout.worktree_root();
    let mut idx = read_or_seed_index_from_head(layout, store).map_err(Error::Refresh)?;
    check_size(&idx, index::MAX_INDEX_BYTES)?;
    let previous = idx.clone();

    // The objects of the restage share one durability batch. It commits
    // before the index write that names them.
    let batch = store.batch();
    let progress_sink = HashProgressSink::new(&batch, observer)?;
    observer.event(&Event::HashProgress { bytes: 0 });

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

        if is_restore_temp_alias(root, &entry.path, &meta)
            .map_err(|e| Error::Refresh(format!("metadata {}: {e}", abs.display())))?
        {
            entry.status = EntryStatus::Removed;
            entry.object_hash = ZERO;
            continue;
        }

        // A file whose time, size and mode class match the entry keeps the
        // entry. No read, no hash, no store.
        if worktree::stat_matches(entry, &meta) {
            continue;
        }

        // A regular file goes through the same path as `build_tree` and
        // `hash_file`, so a large file becomes a chunked blob, and the hashes
        // of commit, status and rm agree. A symlink is one blob of its target.
        let (status, h, stat) = if meta.file_type().is_file() {
            let (h, opened_meta) = worktree::hash_file_with_metadata(&progress_sink, &abs)
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
            let h = progress_sink
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

    observer.event(&Event::HashProgress {
        bytes: progress_sink.bytes.load(Ordering::Relaxed),
    });
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

/// Resolve the complete request using metadata and link targets only. The
/// projected entries include tombstones and directory conflict removals.
fn prepare(
    root: &Path,
    request: &Request<'_>,
    idx: &mut Index,
    limit: u64,
) -> Result<Vec<PendingHash>, Error> {
    let ignores = ignore::load(root).map_err(Error::IgnoreFile)?;
    let mut pending = Vec::new();
    if !request.all && request.paths.is_empty() {
        return Err(Error::NoPaths);
    }
    let targets = if request.all {
        vec![".".to_owned()]
    } else {
        request.paths.to_vec()
    };
    for target in &targets {
        let p = Path::new(target);
        let abs = if p.is_absolute() {
            p.to_path_buf()
        } else {
            root.join(p)
        };
        if request.patch {
            let meta = abs.symlink_metadata().map_err(|source| Error::Metadata {
                path: abs.clone(),
                source,
            })?;
            if !meta.is_file() {
                return Err(Error::PatchRegularOnly(target.clone()));
            }
        }
        if target == "." {
            let mut seen = HashSet::new();
            add_tree(root, root, false, idx, &ignores, &mut seen, &mut pending)?;
            mark_missing_paths_removed(root, idx, &seen);
        } else {
            ensure_within_repo(root, &abs)?;
            if let Routed::NeedsHash(p) = route_path(root, p, None, idx, &ignores, request.force)? {
                stage_hashed(
                    idx,
                    p.rel_str.clone(),
                    (p.previous_status, ZERO, (0, 0, 0, 0)),
                );
                pending.push(p);
            }
        }
    }
    let mut seen = HashSet::new();
    pending.retain(|p| seen.insert(p.rel_str.clone()));
    check_size(idx, limit)?;
    Ok(pending)
}

fn check_size(idx: &Index, limit: u64) -> Result<(), Error> {
    // SPEC-INDEX: magic, version, count, checksum; status, hash, four stat fields, path length.
    let header = 4 + 1 + 4 + hash::HASH_LEN as u64;
    let fixed_entry = 1 + hash::HASH_LEN as u64 + 4 * 8 + 2;
    let bytes = header
        + idx
            .entries
            .iter()
            .map(|e| fixed_entry + e.path.len() as u64)
            .sum::<u64>();
    if bytes > limit {
        // Keep the write refusal and its exit code without changing the public error API.
        return Err(Error::WriteIndex(IndexError::Io(io::Error::other(
            format!(
                "index limit {limit} bytes exceeded: {} files (including deletions) require {bytes} bytes",
                idx.entries.len()
            ),
        ))));
    }
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

/// Counts only blob payloads after the sink accepted them. The byte counter
/// and emission deadline are atomic; the hot path takes no progress lock.
struct HashProgressSink<'a> {
    blob_header_len: u64,
    inner: &'a (dyn ObjectSink + Sync),
    observer: Option<&'a (dyn Observer<Event> + Sync)>,
    bytes: std::sync::atomic::AtomicU64,
    next: std::sync::atomic::AtomicU64,
    started: std::time::Instant,
}

impl<'a> HashProgressSink<'a> {
    fn new(
        inner: &'a (dyn ObjectSink + Sync),
        observer: &'a dyn Observer<Event>,
    ) -> Result<Self, Error> {
        Ok(Self {
            blob_header_len: serialize::blob_prologue(0).map_err(Error::Serialize)?.len() as u64,
            inner,
            observer: observer.concurrent(),
            bytes: std::sync::atomic::AtomicU64::new(0),
            next: std::sync::atomic::AtomicU64::new(100),
            started: std::time::Instant::now(),
        })
    }

    fn note(&self, parts: &[&[u8]]) {
        if parts.first().and_then(|p| p.first()).copied()
            != Some(kit_core::object::ObjectType::Blob as u8)
        {
            return;
        }
        let bytes = parts
            .iter()
            .map(|p| p.len() as u64)
            .sum::<u64>()
            .saturating_sub(self.blob_header_len);
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
        let now = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let next = self.next.load(Ordering::Relaxed);
        if now >= next
            && self
                .next
                .compare_exchange(
                    next,
                    now.saturating_add(100),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
            && let Some(observer) = self.observer
        {
            observer.event(&Event::HashProgress {
                bytes: self.bytes.load(Ordering::Relaxed),
            });
        }
    }
}

impl ObjectSink for HashProgressSink<'_> {
    fn put(&self, bytes: &[u8]) -> kit_core::store::StoreResult<Hash> {
        let hash = self.inner.put(bytes)?;
        self.note(&[bytes]);
        Ok(hash)
    }
    fn put_parts(&self, parts: &[&[u8]]) -> kit_core::store::StoreResult<Hash> {
        let hash = self.inner.put_parts(parts)?;
        self.note(parts);
        Ok(hash)
    }
    fn put_chunk_parts(
        &self,
        parts: &[&[u8]],
        origin: kit_core::store::ChunkOrigin<'_>,
    ) -> kit_core::store::StoreResult<Hash> {
        let hash = self.inner.put_chunk_parts(parts, origin)?;
        self.note(parts);
        Ok(hash)
    }
    fn has(&self, hash: &Hash) -> bool {
        self.inner.has(hash)
    }
    fn checkpoint(&self) -> kit_core::store::StoreResult<()> {
        self.inner.checkpoint()
    }
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
    symlink_target: Option<String>,
}

/// What [`route_path`] decided for one path.
enum Routed {
    /// The path is staged already, or needs nothing.
    Done(String),
    /// The file needs its hash.
    NeedsHash(PendingHash),
}

/// Check `abs` and `rel`, apply the ignore and the stat cache, and stage a
/// symlink target without storing it. A file or link
/// comes back as a [`PendingHash`], so a caller with many files can hash them
/// in parallel.
fn route_path(
    root: &Path,
    rel: &Path,
    walked_meta: Option<std::fs::Metadata>,
    idx: &mut Index,
    ignores: &IgnoreList,
    force: bool,
) -> Result<Routed, Error> {
    let abs = if rel.is_absolute() {
        rel.to_path_buf()
    } else {
        root.join(rel)
    };
    let named = walked_meta.is_none();
    let meta = match walked_meta {
        Some(meta) if rel.is_absolute() => meta,
        _ => abs.symlink_metadata().map_err(|source| Error::Metadata {
            path: abs.clone(),
            source,
        })?,
    };
    let rel_str = path_text(abs.strip_prefix(root).unwrap_or(rel))?;
    validate_staging_path(root, idx, &rel_str, named.then_some(&meta))?;
    // One lookup serves every check below.
    let existing_pos = idx.find_entry(&rel_str);
    let previous_status = existing_pos.map_or(EntryStatus::Blob, |i| idx.entries[i].status);
    // A path that is named and ignored needs `force`. A path that is tracked
    // is never ignored.
    let already_tracked = previous_status != EntryStatus::Removed && existing_pos.is_some();
    if !force && !already_tracked && is_ignored_untracked(ignores, &abs, &rel_str, meta.is_dir())? {
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
            symlink_target: None,
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
        Ok(Routed::NeedsHash(PendingHash {
            abs,
            rel_str,
            previous_status: EntryStatus::Symlink,
            symlink_target: Some(target_str),
        }))
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
    if let Some(target) = &p.symlink_target {
        let blob = Object::Blob(Blob {
            data: target.as_bytes().to_vec(),
        });
        let ser = serialize::serialize(&blob).map_err(Error::Serialize)?;
        let h = sink.put(&ser).map_err(Error::Store)?;
        return Ok((EntryStatus::Symlink, h, (0, 0, 0, 0)));
    }
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

// Keep native filename characters inside each component. Only native
// separators become index separators; lossy conversion would alias files.
fn path_text(path: &Path) -> Result<String, Error> {
    let components = path
        .components()
        .map(|component| component.as_os_str().to_str())
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| Error::InvalidPath(path.display().to_string()))?;
    Ok(components.join("/"))
}

fn validate_staging_path(
    root: &Path,
    idx: &Index,
    path: &str,
    named: Option<&std::fs::Metadata>,
) -> Result<(), Error> {
    let name = path.rsplit('/').next().unwrap_or(path);
    if !index::validate_index_path(path)
        || (is_restore_temp_name(name) && idx.find_entry(path).is_none())
    {
        return Err(Error::InvalidPath(path.to_owned()));
    }
    if let Some(meta) = named
        && is_restore_temp_alias(root, path, meta).map_err(|source| Error::Metadata {
            path: root.join(path),
            source,
        })?
    {
        return Err(Error::InvalidPath(path.to_owned()));
    }
    Ok(())
}

/// Check the on-disk spelling of a named path that can alias a temporary
/// name. Compare the entries on disk so the filesystem decides which
/// non-ASCII names alias, and keep ordinary files with similar names.
fn is_restore_temp_alias(root: &Path, path: &str, meta: &std::fs::Metadata) -> io::Result<bool> {
    let name = path.rsplit('/').next().unwrap_or(path);
    if meta.is_dir() || !could_alias_restore_temp_name(name) {
        return Ok(false);
    }
    let abs = root.join(path);
    let parent = abs.parent().unwrap_or(root);
    let names = match std::fs::read_dir(parent) {
        Ok(names) => names,
        // An explicit add can read a file in a searchable directory.
        // Without a listing there is no evidence that its name is an alias.
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => return Ok(false),
        Err(e) => return Err(e),
    };
    let mut aliases_temporary = false;
    for entry in names {
        let entry = entry?;
        let file_name = entry.file_name();
        if file_name == name {
            return if is_restore_temp_name(name) {
                match has_exact_parent_spelling(root, path) {
                    Err(e) if e.kind() == io::ErrorKind::PermissionDenied => Ok(false),
                    exact => exact.map(|exact| !exact),
                }
            } else {
                Ok(false)
            };
        }
        if file_name.to_str().is_some_and(is_restore_temp_name)
            && same_restore_entry(meta, &abs, &entry.path())?
        {
            aliases_temporary = true;
        }
    }
    Ok(aliases_temporary)
}

/// Check whether a name could have the generated spelling after case and
/// Unicode normalization. Use the filesystem to confirm any candidate.
fn could_alias_restore_temp_name(name: &str) -> bool {
    if name.is_ascii() {
        return name.starts_with('.') && is_restore_temp_name(&name.to_ascii_lowercase());
    }
    if !name.bytes().any(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let folded = name.to_uppercase().to_lowercase();
    let ascii: String = folded.chars().filter(char::is_ascii).collect();
    is_restore_temp_name(&ascii)
}

/// A historical temporary-looking name is tracked only at its exact path.
fn has_exact_parent_spelling(root: &Path, path: &str) -> io::Result<bool> {
    let Some((parents, _)) = path.rsplit_once('/') else {
        return Ok(true);
    };
    let mut parent = root.to_path_buf();
    for component in parents.split('/') {
        let mut found = false;
        for entry in std::fs::read_dir(&parent)? {
            let entry = entry?;
            if entry.file_name() == component {
                found = entry.file_type()?.is_dir();
                break;
            }
        }
        if !found {
            return Ok(false);
        }
        parent.push(component);
    }
    Ok(true)
}

#[cfg(unix)]
fn same_restore_entry(meta: &std::fs::Metadata, _: &Path, actual: &Path) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt as _;

    // A hard-linked inode can have a separate, ordinary name.
    if meta.nlink() > 1 {
        return Ok(false);
    }
    let actual = actual.symlink_metadata()?;
    Ok(meta.dev() == actual.dev() && meta.ino() == actual.ino())
}

#[cfg(not(unix))]
fn same_restore_entry(_: &std::fs::Metadata, requested: &Path, actual: &Path) -> io::Result<bool> {
    Ok(requested.canonicalize()? == actual.canonicalize()?)
}

fn is_ignored_untracked(
    ignores: &IgnoreList,
    path: &Path,
    relative: &str,
    is_dir: bool,
) -> Result<bool, Error> {
    let scoped = ignores
        .load_directory(path.parent().unwrap_or(path))
        .map_err(Error::IgnoreFile)?;
    Ok(scoped.is_ignored_with_ancestors(relative, is_dir))
}

/// Walk `dir` using metadata and link targets. Record a placeholder for each
/// pending hash so the index has the exact paths before any object is stored.
#[allow(clippy::too_many_arguments)] // the state of one walk
fn add_tree(
    root: &Path,
    dir: &Path,
    parent_ignored: bool,
    idx: &mut Index,
    ignores: &IgnoreList,
    seen: &mut HashSet<String>,
    pending: &mut Vec<PendingHash>,
) -> Result<(), Error> {
    let local;
    let ignores = if dir != root && !parent_ignored {
        local = ignores.load_directory(dir).map_err(Error::IgnoreFile)?;
        &local
    } else {
        ignores
    };
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
        let native_relative = p.strip_prefix(root).unwrap_or(&p);
        // Lossy text is only for ignore decisions. Unrepresentable names can
        // never be tracked; route_path rejects them if a file is included.
        let rel_path = native_relative
            .components()
            .map(|component| component.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        if !is_dir
            && native_relative
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .is_some_and(is_restore_temp_name)
            && idx.find_entry(&rel_path).is_none()
        {
            continue;
        }
        // An ignore rule hides untracked content only. A tracked file stays
        // in view, and so does a directory that holds tracked content, so
        // `add .` and `add -A` refresh the tracked changes. The bit of an
        // ignored ancestor goes down, so the untracked and ignored children of
        // a tracked directory stay out.
        let entry_ignored = parent_ignored || ignores.is_ignored(&rel_path, is_dir);
        if entry_ignored
            && (native_relative.to_str().is_none()
                || !index_tracks_path_or_descendant(idx, &rel_path))
        {
            continue;
        }
        if meta.file_type().is_dir() {
            add_tree(root, &p, entry_ignored, idx, ignores, seen, pending)?;
        } else if meta.file_type().is_file() || meta.file_type().is_symlink() {
            // The decision to include is made, so `force` skips the second
            // look at the ignore rules in `route_path`.
            match route_path(root, &p, Some(meta), idx, ignores, true)? {
                Routed::Done(rel) => {
                    seen.insert(rel);
                }
                Routed::NeedsHash(pend) => {
                    stage_hashed(
                        idx,
                        pend.rel_str.clone(),
                        (pend.previous_status, ZERO, (0, 0, 0, 0)),
                    );
                    seen.insert(pend.rel_str.clone());
                    pending.push(pend);
                }
            }
        }
    }
    Ok(())
}

fn mark_missing_paths_removed(root: &Path, idx: &mut Index, seen: &HashSet<String>) {
    let mut directory_names = HashMap::new();
    for entry in &mut idx.entries {
        if entry.status != EntryStatus::Removed
            && !seen.contains(&entry.path)
            && match root.join(&entry.path).symlink_metadata() {
                Ok(_) => has_exact_spelling(root, &entry.path, &mut directory_names) == Some(false),
                Err(error) => is_gone(&error),
            }
        {
            entry.status = EntryStatus::Removed;
            entry.object_hash = ZERO;
        }
    }
}

/// A case-insensitive lookup can succeed even after the name disappeared.
fn has_exact_spelling(
    root: &Path,
    path: &str,
    directory_names: &mut HashMap<PathBuf, Option<HashSet<OsString>>>,
) -> Option<bool> {
    let mut parent = root.to_path_buf();
    for component in path.split('/') {
        let names = directory_names
            .entry(parent.clone())
            .or_insert_with_key(|dir| {
                std::fs::read_dir(dir)
                    .ok()?
                    .map(|entry| entry.map(|entry| entry.file_name()))
                    .collect::<io::Result<_>>()
                    .ok()
            })
            .as_ref()?;
        if !names.contains(std::ffi::OsStr::new(component)) {
            return Some(false);
        }
        parent.push(component);
    }
    Some(true)
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
    limit: u64,
) -> Result<(), Error> {
    let root = layout.worktree_root();
    let mut idx = read_or_seed_index_from_head(layout, store).map_err(Error::ReadIndex)?;
    prepare(root, request, &mut idx.clone(), limit)?;
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
    let rel_str = path_text(abs.strip_prefix(root).unwrap_or(rel))?;
    // A path behind a symlink could name a file outside the repository, and
    // the read would follow the link.
    ensure_within_repo(root, &abs)?;
    validate_staging_path(root, idx, &rel_str, Some(&meta))?;
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
    if !force && !already_tracked && is_ignored_untracked(ignores, &abs, &rel_str, false)? {
        return Err(Error::Ignored(rel_str));
    }

    // The base is the staged blob, or the blob that HEAD seeded. A new file
    // has an empty base. The other side is the content in the tree.
    let staged = match idx.find_entry(&rel_str) {
        Some(i) if idx.entries[i].status != EntryStatus::Removed => {
            LoadedBlob::load(store, &idx.entries[i].object_hash).map_err(Error::ReadStagedBlob)?
        }
        _ => LoadedBlob::empty(),
    };
    let previous_status = idx
        .find_entry(&rel_str)
        .map_or(EntryStatus::Blob, |i| idx.entries[i].status);

    // A binary side has no hunks. Both sides are tested on a bounded prefix
    // before either is read whole, so a large binary file is skipped without
    // a full read. A text side above the in-memory limit is refused below.
    if patch_sides_are_binary(store, &staged, &abs)? {
        observer.event(&Event::BinarySkipped { path: rel_str });
        return Ok(PatchOutcome {
            staged: false,
            quit: false,
        });
    }
    let base = staged.into_content(store).map_err(Error::ReadStagedBlob)?;
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

/// Whether the staged blob or the file at `abs` is binary. The test reads a
/// bounded prefix of each side.
fn patch_sides_are_binary(
    store: &ObjectStore,
    staged: &LoadedBlob,
    abs: &Path,
) -> Result<bool, Error> {
    let staged_prefix = staged
        .prefix(store, BINARY_SNIFF_LEN)
        .map_err(Error::ReadStagedBlob)?;
    let work_prefix =
        read_file_prefix(abs, BINARY_SNIFF_LEN).map_err(|source| Error::ReadFile {
            path: abs.to_path_buf(),
            source: WorktreeError::Io(source),
        })?;
    Ok(is_binary(&staged_prefix) || is_binary(&work_prefix))
}

/// Up to `max_len` leading bytes of the regular file at `path`. The final
/// component is not followed if it is a symlink.
fn read_file_prefix(path: &Path, max_len: usize) -> io::Result<Vec<u8>> {
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt as _;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?
    };
    #[cfg(not(unix))]
    let file = {
        if !path.symlink_metadata()?.file_type().is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path is not a regular file",
            ));
        }
        std::fs::File::open(path)?
    };
    let mut prefix = Vec::new();
    file.take(max_len as u64).read_to_end(&mut prefix)?;
    Ok(prefix)
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn bulk_add_keeps_an_unseen_tracked_file_with_its_exact_name() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("present"), b"data").unwrap();
        let mut index = Index::new();
        let original = [3; 32];
        for path in ["present", "gone"] {
            stage_hashed(
                &mut index,
                path.to_owned(),
                (EntryStatus::Blob, original, (0, 0, 0, 0)),
            );
        }

        mark_missing_paths_removed(dir.path(), &mut index, &HashSet::new());

        assert_eq!(index.entries[0].status, EntryStatus::Blob);
        assert_eq!(index.entries[0].object_hash, original);
        assert_eq!(index.entries[1].status, EntryStatus::Removed);
        assert_eq!(index.entries[1].object_hash, ZERO);
    }

    #[test]
    fn bulk_add_checks_exact_spelling_of_each_path_component() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("Folder")).unwrap();
        std::fs::write(dir.path().join("Folder/foo"), b"data").unwrap();
        let mut names = HashMap::new();

        assert_eq!(
            has_exact_spelling(dir.path(), "Folder/foo", &mut names),
            Some(true)
        );
        for path in ["Folder/Foo", "folder/foo"] {
            assert_eq!(
                has_exact_spelling(dir.path(), path, &mut names),
                Some(false)
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn native_path_text_preserves_boundaries_and_refuses_lossy_names() {
        use std::os::unix::ffi::OsStringExt;
        assert_eq!(path_text(Path::new(r"a\b/file")).unwrap(), r"a\b/file");
        let invalid = std::ffi::OsString::from_vec(vec![0xff]);
        assert!(matches!(
            path_text(Path::new(&invalid)),
            Err(Error::InvalidPath(_))
        ));
    }

    struct NoChooser;
    impl HunkChooser for NoChooser {
        fn choose(&mut self, _: &str, _: &[PatchHunk]) -> io::Result<Choice> {
            panic!("must refuse before reading content")
        }
    }
    fn snapshot(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(root).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                out.extend(snapshot(&p));
            } else {
                out.push((p.clone(), std::fs::read(p).unwrap()));
            }
        }
        out.sort();
        out
    }
    #[test]
    fn oversized_request_leaves_no_objects_temps_or_partial_index() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let layout = RepoLayout::single(root);
        ObjectStore::init(&layout).unwrap();
        kit_core::refs::init(&layout).unwrap();
        kit_core::refs::write_head_branch(&layout, "main").unwrap();
        std::fs::write(root.join("first"), "first content").unwrap();
        std::fs::write(root.join("second"), "second content").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("first", root.join("link")).unwrap();
        // Warm the persistent lock file before taking the snapshot.
        drop(lock::acquire_worktree(&layout, &crate::NoopObserver).unwrap());
        let before = snapshot(&root.join(".kit"));
        let paths = ["first".to_owned(), "second".to_owned()];
        for (targets, count) in [
            (&paths[..], 2),
            (&[".".to_owned()][..], if cfg!(unix) { 3 } else { 2 }),
        ] {
            for (dry_run, patch) in [(false, false), (true, false), (false, true)] {
                if patch && targets[0] == "." {
                    continue;
                }
                let request = Request {
                    all: false,
                    update: false,
                    patch,
                    force: false,
                    dry_run,
                    paths: targets,
                };
                let err = stage_with_limit(
                    &layout,
                    &StoreConfig {
                        environment: &crate::Environment::new(root),
                        observer: &crate::NoopObserver,
                    },
                    root,
                    &request,
                    &mut NoChooser,
                    &crate::NoopObserver,
                    &crate::NoopObserver,
                    100,
                )
                .unwrap_err();
                assert!(matches!(err, Error::WriteIndex(_)));
                let message = err.to_string();
                assert!(message.contains("100 bytes"), "{message}");
                assert!(message.contains(&format!("{count} files")), "{message}");
                assert_eq!(snapshot(&root.join(".kit")), before);
            }
        }
    }

    #[test]
    fn routing_an_absolute_walk_path_reuses_its_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let path = root.join("file");
        std::fs::write(&path, "content").unwrap();
        let metadata = path.symlink_metadata().unwrap();
        std::fs::remove_file(&path).unwrap();

        let routed = route_path(
            root,
            &path,
            Some(metadata),
            &mut Index::new(),
            &IgnoreList::new(),
            true,
        )
        .unwrap();

        // The walker already observed this path. The hash step opens it later.
        assert!(matches!(routed, Routed::NeedsHash(pending) if pending.abs == path));
    }

    #[test]
    fn routing_a_relative_path_reads_metadata_at_the_resolved_path() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let observed = root.join("observed");
        std::fs::write(&observed, "content").unwrap();
        let metadata = observed.symlink_metadata().unwrap();
        let relative = Path::new("missing");

        let routed = route_path(
            root,
            relative,
            Some(metadata),
            &mut Index::new(),
            &IgnoreList::new(),
            true,
        );

        assert!(matches!(
            routed,
            Err(Error::Metadata { path, source })
                if path == root.join(relative) && source.kind() == io::ErrorKind::NotFound
        ));
    }

    #[cfg(unix)]
    #[test]
    fn dot_add_refuses_a_file_replaced_by_a_symlink_before_hashing() {
        use std::os::unix::fs::symlink;

        struct ReplaceBeforeHash(PathBuf);
        impl Observer<Event> for ReplaceBeforeHash {
            fn event(&self, event: &Event) {
                if matches!(event, Event::HashProgress { bytes: 0 }) && !self.0.is_symlink() {
                    std::fs::remove_file(&self.0).unwrap();
                    symlink("target", &self.0).unwrap();
                }
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let layout = RepoLayout::single(root);
        ObjectStore::init(&layout).unwrap();
        kit_core::refs::init(&layout).unwrap();
        kit_core::refs::write_head_branch(&layout, "main").unwrap();
        std::fs::write(root.join(".kitignore"), "target\n").unwrap();
        std::fs::write(root.join("target"), "ignored").unwrap();
        std::fs::write(root.join("file"), "regular").unwrap();
        drop(lock::acquire_worktree(&layout, &crate::NoopObserver).unwrap());
        let before = snapshot(&root.join(".kit"));

        let err = stage(
            &layout,
            &StoreConfig {
                environment: &crate::Environment::new(root),
                observer: &crate::NoopObserver,
            },
            root,
            &Request {
                all: false,
                update: false,
                patch: false,
                force: false,
                dry_run: false,
                paths: &[".".to_owned()],
            },
            &mut NoChooser,
            &crate::NoopObserver,
            &ReplaceBeforeHash(root.join("file")),
        )
        .unwrap_err();

        assert!(matches!(err, Error::Hash { path, .. } if path == root.join("file")));
        assert_eq!(snapshot(&root.join(".kit")), before);
    }

    #[test]
    fn repeated_paths_only_hash_once() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("file"), "content").unwrap();
        let mut idx = Index::new();
        let paths = ["file".to_owned(), ".".to_owned(), "file".to_owned()];
        let request = Request {
            all: false,
            update: false,
            patch: false,
            force: false,
            dry_run: false,
            paths: &paths,
        };
        let pending = prepare(dir.path(), &request, &mut idx, 1000).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(idx.entries.len(), 1);
        assert_eq!(idx.serialize().len(), 41 + 67 + 4);
    }
}

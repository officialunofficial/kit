//! Move or rename tracked paths, and stage the change.
//!
//! [`mv`] takes `<source>... <dest>`. A source is a tracked file or a
//! directory with tracked files. The operation renames one source to the
//! destination, or moves every source into the destination when that is an
//! existing directory. It moves the file in the tree, stages the source path
//! as removed, and stages the destination with the blob and mode of the
//! source. The content does not change, so the blob keeps its object id.
//!
//! The operation checks every move before it changes anything. A bad source
//! in a batch leaves the tree and the index as they were. A destination never
//! leaves the repository, and it never goes through a symlink. A file does not
//! replace an existing path without `force`, and nothing replaces a directory.
//! A directory moves in one rename, so the untracked files in it move with it.
//! A failure in the middle of the batch keeps the index in step with the moves
//! that are done.

use std::io;
use std::path::{Path, PathBuf};

use kit_core::hash::{Hash, ZERO};
use kit_core::index::{self, EntryStatus, IndexEntry};
use kit_core::layout::RepoLayout;
use kit_core::observer::Observer;
use kit_core::store::{ObjectStore, StoreError};
use kit_sync::worktree::read_or_seed_index_from_head;

use crate::{lock, pathspec};

/// What is wrong with a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SourceFault {
    /// The path is not in the tree.
    Missing,
    /// A tracked file is now a directory.
    NowDirectory,
    /// The path goes through a symlink.
    SymlinkAncestor,
    /// A tracked directory is not a directory in the tree.
    NotDirectory,
    /// A tracked file below a directory is not in the tree.
    MissingFromTree,
}

impl SourceFault {
    fn suffix(self) -> &'static str {
        match self {
            Self::Missing => "",
            Self::NowDirectory => " (tracked as a file but is now a directory)",
            Self::SymlinkAncestor => " (path traverses a symlink)",
            Self::NotDirectory => " (not a directory, or a symlink standing in for one)",
            Self::MissingFromTree => " (tracked file missing from the worktree)",
        }
    }
}

/// Errors from [`mv`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The object store cannot be opened.
    #[error("not a kit repo: {0}")]
    NotARepository(StoreError),
    /// The worktree lock cannot be taken.
    #[error(transparent)]
    Lock(#[from] lock::Error),
    /// The index cannot be read.
    #[error("{0}")]
    ReadIndex(String),
    /// The root of the repository cannot be resolved.
    #[error("repo root: {0}")]
    RepoRoot(io::Error),
    /// A path argument is not valid.
    #[error(transparent)]
    Path(#[from] pathspec::Error),
    /// Several sources need a destination that is a directory.
    #[error("destination directory does not exist: {0}")]
    DestinationNotDirectory(String),
    /// A source has no tracked file.
    #[error("not under version control: {0}")]
    NotTracked(String),
    /// A source and its destination are the same path.
    #[error("source and destination are the same: {0}")]
    SameSourceAndDestination(String),
    /// A source cannot move.
    #[error("bad source: {path}{}", fault.suffix())]
    BadSource {
        /// The path, as the caller wrote it or as the index has it.
        path: String,
        /// What is wrong with it.
        fault: SourceFault,
    },
    /// A directory cannot move into itself.
    #[error("cannot move '{0}' into itself")]
    MoveIntoItself(String),
    /// The destination leaves the repository.
    #[error("destination escapes the repository: {0}")]
    DestinationEscapes(String),
    /// The destination goes through a symlink.
    #[error("destination path traverses a symlink: {0}")]
    DestinationSymlink(String),
    /// A file cannot replace a directory.
    #[error("destination is a directory: {0} (mv cannot replace a directory with a file)")]
    DestinationIsDirectory(String),
    /// The destination exists, and `force` is off.
    #[error("destination exists (use -f to overwrite): {0}")]
    DestinationExists(String),
    /// A directory cannot replace an existing path.
    #[error(
        "destination already exists: {0} (refusing to overwrite it — -f does not clobber a directory)"
    )]
    DirectoryDestinationExists(String),
    /// A file cannot replace a path that has tracked files below it.
    #[error("destination has tracked descendants (e.g. '{0}'); a file cannot replace it")]
    DestinationHasDescendants(String),
    /// The destination is below a tracked file.
    #[error("destination nests under tracked file '{0}'; move or remove it first")]
    DestinationUnderFile(String),
    /// A directory destination collides with a tracked path.
    #[error("destination conflicts with a tracked path: {0}")]
    DestinationConflict(String),
    /// Two sources are the same path.
    #[error("duplicate source: {0}")]
    DuplicateSource(String),
    /// A source is inside another source.
    #[error("overlapping sources: '{inner}' is inside '{outer}'")]
    OverlappingSources {
        /// The outer source.
        outer: String,
        /// The source inside it.
        inner: String,
    },
    /// Two sources land on the same path.
    #[error("multiple sources map to the same destination: {0}")]
    SameDestination(String),
    /// A destination is inside another destination.
    #[error("conflicting destinations: '{outer}' and '{inner}' (one is inside the other)")]
    NestedDestinations {
        /// The outer destination.
        outer: String,
        /// The destination inside it.
        inner: String,
    },
    /// Two directories land on the same root.
    #[error("multiple directory sources map to the same destination: {0}")]
    SameDirectoryDestination(String),
    /// A directory above the destination cannot be created.
    #[error("create {}: {source}", path.display())]
    CreateDirectory {
        /// The directory.
        path: PathBuf,
        /// Why it cannot be created.
        source: io::Error,
    },
    /// A rename failed.
    #[error("move {from} -> {to}: {source}")]
    Rename {
        /// The source path.
        from: String,
        /// The destination path.
        to: String,
        /// Why the rename failed.
        source: io::Error,
    },
    /// The index cannot be written.
    #[error("write index: {0}")]
    WriteIndex(index::IndexError),
}

/// A validated single-file move.
struct PlannedMove {
    /// The slot of the source entry. The execution only flips statuses and
    /// appends, so the slot stays valid.
    src_idx: usize,
    src_rel: String,
    src_abs: PathBuf,
    target_rel: String,
    target_abs: PathBuf,
    status: EntryStatus,
    hash: Hash,
}

/// A tracked file that a directory move carries. The blob and the mode move
/// with it.
struct DirFileMove {
    src_rel: String,
    target_rel: String,
    status: EntryStatus,
    hash: Hash,
}

/// A validated directory move. One rename moves the directory, so untracked
/// files travel with it. Each tracked file below it is staged again.
struct PlannedDirMove {
    src_dir_rel: String,
    src_dir_abs: PathBuf,
    dest_dir_rel: String,
    dest_dir_abs: PathBuf,
    files: Vec<DirFileMove>,
}

enum Planned {
    File(PlannedMove),
    Dir(PlannedDirMove),
}

impl Planned {
    /// Every path that this move stages, for the collision check.
    fn target_paths(&self) -> Vec<&str> {
        match self {
            Self::File(m) => vec![m.target_rel.as_str()],
            Self::Dir(m) => m.files.iter().map(|f| f.target_rel.as_str()).collect(),
        }
    }

    /// The root that a directory move lands on. `target_paths` lists the
    /// files only, so two directories on one root need this.
    fn dest_dir_root(&self) -> Option<&str> {
        match self {
            Self::Dir(m) => Some(m.dest_dir_rel.as_str()),
            Self::File(_) => None,
        }
    }

    fn source_rel(&self) -> &str {
        match self {
            Self::File(m) => &m.src_rel,
            Self::Dir(m) => &m.src_dir_rel,
        }
    }
}

/// Move `sources` to `dest`, and stage the change.
///
/// `cwd` is the root of the tree. The paths resolve against it. The operation
/// holds the worktree lock from the read of the index to the write.
///
/// # Errors
/// [`Error`], with one variant for each refused or failed step. No refusal
/// changes the tree or the index. [`Error::CreateDirectory`] and
/// [`Error::Rename`] stop the batch after the moves that are done, and the
/// index records those.
pub fn mv(
    layout: &RepoLayout,
    cwd: &Path,
    sources: &[String],
    dest: &str,
    force: bool,
    observer: &dyn Observer<lock::Event>,
) -> Result<(), Error> {
    let store = ObjectStore::open(layout).map_err(Error::NotARepository)?;
    let _lock = lock::acquire_worktree(layout, observer)?;
    // Seed from HEAD when the index is absent or empty, so a source that
    // HEAD tracks counts as tracked.
    let mut idx = read_or_seed_index_from_head(layout, &store).map_err(Error::ReadIndex)?;
    let root_canon = cwd.canonicalize().map_err(Error::RepoRoot)?;

    let dest_rel = pathspec::index_path_for_arg(cwd, Path::new(dest))?;
    let dest_abs = cwd.join(&dest_rel);
    // Several sources need an existing directory. One source moves into the
    // destination when that is a directory, and is renamed otherwise.
    if sources.len() > 1 && !dest_abs.is_dir() {
        return Err(Error::DestinationNotDirectory(dest.to_owned()));
    }
    let into_dir = sources.len() > 1 || dest_abs.is_dir();

    // A source that is a tracked entry is a file move. A source that is the
    // prefix of tracked entries is a directory move.
    let mut plan: Vec<Planned> = Vec::new();
    for source in sources {
        let src_rel = pathspec::index_path_for_arg(cwd, Path::new(source))?;
        let file_slot = idx
            .entries
            .iter()
            .position(|e| e.path == src_rel && e.status != EntryStatus::Removed);
        let dir_prefix = format!("{src_rel}/");
        let is_dir = idx
            .entries
            .iter()
            .any(|e| e.status != EntryStatus::Removed && e.path.starts_with(&dir_prefix));
        let planned = if let Some(src_idx) = file_slot {
            plan_move(
                cwd,
                &root_canon,
                &idx,
                src_idx,
                source,
                &dest_rel,
                into_dir,
                force,
            )
            .map(Planned::File)
        } else if is_dir {
            plan_dir_move(
                cwd,
                &root_canon,
                &idx,
                source,
                &src_rel,
                &dest_rel,
                into_dir,
            )
            .map(Planned::Dir)
        } else {
            Err(Error::NotTracked(source.clone()))
        };
        plan.push(planned?);
    }
    check_batch(&plan)?;

    // On a failure in the middle of the batch, write the index for the moves
    // that are done, so it stays in step with the tree.
    for (done, p) in plan.iter().enumerate() {
        let moved = match p {
            Planned::File(m) => execute_move(m, force),
            Planned::Dir(m) => execute_dir_move(m),
        };
        if let Err(e) = moved {
            if done > 0 {
                let _ = index::write_index(layout, &idx);
            }
            return Err(e);
        }
        match p {
            Planned::File(m) => apply_to_index(&mut idx, m),
            Planned::Dir(m) => apply_dir_to_index(&mut idx, m),
        }
    }
    index::write_index(layout, &idx).map_err(Error::WriteIndex)
}

/// Refuse a batch whose moves collide. Two sources must not overlap, and no
/// two destinations may be the same path or nest.
fn check_batch(plan: &[Planned]) -> Result<(), Error> {
    // Moving one source would invalidate the other, and a part of the batch
    // would be left on disk.
    for (i, a) in plan.iter().enumerate() {
        for (j, b) in plan.iter().enumerate() {
            if i == j {
                continue;
            }
            let (a, b) = (a.source_rel(), b.source_rel());
            if a == b {
                return Err(Error::DuplicateSource(a.to_owned()));
            }
            if b.starts_with(&format!("{a}/")) {
                return Err(Error::OverlappingSources {
                    outer: a.to_owned(),
                    inner: b.to_owned(),
                });
            }
        }
    }
    // The same path, or a path below another one, gives a clash between a
    // file and a directory on disk and in the index.
    let all_targets: Vec<&str> = plan.iter().flat_map(Planned::target_paths).collect();
    for (i, a) in all_targets.iter().enumerate() {
        for (j, b) in all_targets.iter().enumerate() {
            if i == j {
                continue;
            }
            if a == b {
                return Err(Error::SameDestination((*a).to_owned()));
            }
            if b.starts_with(&format!("{a}/")) {
                return Err(Error::NestedDestinations {
                    outer: (*a).to_owned(),
                    inner: (*b).to_owned(),
                });
            }
        }
    }
    // The file paths of two directories on one root do not clash, so the
    // check above misses them. The second rename would then fail in the
    // middle of the batch.
    let roots: Vec<&str> = plan.iter().filter_map(Planned::dest_dir_root).collect();
    for (i, a) in roots.iter().enumerate() {
        for b in &roots[i + 1..] {
            if a == b || b.starts_with(&format!("{a}/")) || a.starts_with(&format!("{b}/")) {
                return Err(Error::SameDirectoryDestination((*a).to_owned()));
            }
        }
    }
    Ok(())
}

/// Check one file source and plan its move. The function changes nothing.
#[allow(clippy::too_many_arguments)] // the inputs of one check
#[allow(clippy::too_many_lines)] // a flat sequence of independent guards
fn plan_move(
    cwd: &Path,
    root_canon: &Path,
    idx: &index::Index,
    src_idx: usize,
    source: &str,
    dest_rel: &str,
    into_dir: bool,
    force: bool,
) -> Result<PlannedMove, Error> {
    let src_rel = idx.entries[src_idx].path.clone();
    let status = idx.entries[src_idx].status;
    let hash = idx.entries[src_idx].object_hash;

    let target_rel = if into_dir {
        let base = src_rel.rsplit('/').next().unwrap_or(&src_rel);
        format!("{dest_rel}/{base}")
    } else {
        dest_rel.to_owned()
    };
    if target_rel == src_rel {
        return Err(Error::SameSourceAndDestination(source.to_owned()));
    }

    let src_abs = cwd.join(&src_rel);
    let target_abs = cwd.join(&target_rel);
    let bad = |fault| Error::BadSource {
        path: source.to_owned(),
        fault,
    };

    if !path_present(&src_abs) {
        return Err(bad(SourceFault::Missing));
    }
    // A tracked file that is now a directory would move as a directory, and
    // the index would stage the old blob at the destination.
    if std::fs::symlink_metadata(&src_abs).is_ok_and(|m| m.is_dir()) {
        return Err(bad(SourceFault::NowDirectory));
    }
    // A symlink above the source could lead out of the repository.
    if has_symlinked_ancestor(cwd, &src_rel) {
        return Err(bad(SourceFault::SymlinkAncestor));
    }
    // Writes stay inside the repository.
    if !target_within_repo(root_canon, &target_abs) {
        return Err(Error::DestinationEscapes(target_rel));
    }
    // A link that stays inside the repository is refused too. The rename
    // follows the link, and the index names the path as written.
    if has_symlinked_ancestor(cwd, &target_rel) {
        return Err(Error::DestinationSymlink(target_rel));
    }
    // A dangling symlink counts as present. A case-only rename on a
    // case-insensitive file system is a plain rename, because the destination
    // is the source. A symlink that points at the source is not.
    if path_present(&target_abs)
        && !is_case_only_rename(&src_rel, &target_rel, &src_abs, &target_abs)
    {
        // Even `force` does not replace a directory. It would delete the
        // tracked and untracked files in it, and the index would hold a clash.
        if std::fs::symlink_metadata(&target_abs).is_ok_and(|m| m.is_dir()) {
            return Err(Error::DestinationIsDirectory(target_rel));
        }
        if !force {
            return Err(Error::DestinationExists(target_rel));
        }
    }
    // A tracked file below the destination, such as `dst/child` when `dst`
    // is gone from the tree, would sit beside a file at `dst`.
    if let Some(desc) = idx
        .entries
        .iter()
        .find(|e| e.status != EntryStatus::Removed && e.path.starts_with(&format!("{target_rel}/")))
    {
        return Err(Error::DestinationHasDescendants(desc.path.clone()));
    }
    // A tracked file at an ancestor of the destination gives the same clash.
    // The checks on disk miss it when the ancestor is gone from the tree.
    if let Some(anc) = idx.entries.iter().find(|e| {
        e.status != EntryStatus::Removed && target_rel.starts_with(&format!("{}/", e.path))
    }) {
        return Err(Error::DestinationUnderFile(anc.path.clone()));
    }

    Ok(PlannedMove {
        src_idx,
        src_rel,
        src_abs,
        target_rel,
        target_abs,
        status,
        hash,
    })
}

/// Move the file of one planned move. Create the directories above the
/// destination. Under `force`, remove an existing destination first.
fn execute_move(m: &PlannedMove, force: bool) -> Result<(), Error> {
    create_parent(&m.target_abs)?;
    // The destination of a case-only rename is the source. Removing it would
    // delete the source, and the rename would fail with both gone.
    if force
        && path_present(&m.target_abs)
        && !is_case_only_rename(&m.src_rel, &m.target_rel, &m.src_abs, &m.target_abs)
    {
        let _ = remove_path(&m.target_abs);
    }
    std::fs::rename(&m.src_abs, &m.target_abs).map_err(|source| Error::Rename {
        from: m.src_rel.clone(),
        to: m.target_rel.clone(),
        source,
    })
}

fn create_parent(path: &Path) -> Result<(), Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| Error::CreateDirectory {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    Ok(())
}

/// Record a file move in the index. The source is removed. The destination
/// gets the blob and the mode of the source.
fn apply_to_index(idx: &mut index::Index, m: &PlannedMove) {
    idx.entries[m.src_idx].status = EntryStatus::Removed;
    idx.entries[m.src_idx].object_hash = ZERO;
    stage_destination(idx, &m.target_rel, m.status, m.hash);
}

fn stage_destination(idx: &mut index::Index, path: &str, status: EntryStatus, hash: Hash) {
    match idx.find_entry(path) {
        Some(j) => {
            idx.entries[j].status = status;
            idx.entries[j].object_hash = hash;
        }
        None => idx.upsert_entry(IndexEntry {
            path: path.to_owned(),
            status,
            object_hash: hash,
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
        }),
    }
}

/// Check one directory source and plan its move. The function changes
/// nothing.
#[allow(clippy::too_many_lines)] // a flat sequence of independent guards
fn plan_dir_move(
    cwd: &Path,
    root_canon: &Path,
    idx: &index::Index,
    source: &str,
    src_rel: &str,
    dest_rel: &str,
    into_dir: bool,
) -> Result<PlannedDirMove, Error> {
    let src_dir_abs = cwd.join(src_rel);
    let bad = |path: &str, fault| Error::BadSource {
        path: path.to_owned(),
        fault,
    };
    // `is_dir` follows symlinks. A tracked directory that is now a link to a
    // directory would move as a link, and its files would be staged under a
    // path that leaves the repository. The type on disk must be a directory.
    if !std::fs::symlink_metadata(&src_dir_abs).is_ok_and(|m| m.is_dir()) {
        return Err(bad(source, SourceFault::NotDirectory));
    }
    // The check above covers the last component only.
    if has_symlinked_ancestor(cwd, src_rel) {
        return Err(bad(source, SourceFault::SymlinkAncestor));
    }

    // A plain rename to `dest_rel`, or a move into it as `dest_rel/<name>`
    // when it is a directory or when there are several sources.
    let dest_dir_rel = if into_dir {
        let base = src_rel.rsplit('/').next().unwrap_or(src_rel);
        format!("{dest_rel}/{base}")
    } else {
        dest_rel.to_owned()
    };
    if dest_dir_rel == src_rel {
        return Err(Error::SameSourceAndDestination(source.to_owned()));
    }
    if dest_dir_rel.starts_with(&format!("{src_rel}/")) {
        return Err(Error::MoveIntoItself(source.to_owned()));
    }

    let dest_dir_abs = cwd.join(&dest_dir_rel);
    if !target_within_repo(root_canon, &dest_dir_abs) {
        return Err(Error::DestinationEscapes(dest_dir_rel));
    }
    // A link inside the repository is refused too, as for a file.
    if has_symlinked_ancestor(cwd, &dest_dir_rel) {
        return Err(Error::DestinationSymlink(dest_dir_rel));
    }
    // A directory move never overwrites, not even with `force`. The delete
    // would take the tracked files and the untracked files in it.
    if path_present(&dest_dir_abs) {
        return Err(Error::DirectoryDestinationExists(dest_dir_rel));
    }
    // A tracked path can collide with the destination though the tree has
    // none. The index would then hold `<dest>` and `<dest>/<child>`.
    let dest_prefix = format!("{dest_dir_rel}/");
    if idx.entries.iter().any(|e| {
        e.status != EntryStatus::Removed
            && (e.path == dest_dir_rel
                || e.path.starts_with(&dest_prefix)
                || dest_dir_rel.starts_with(&format!("{}/", e.path)))
    }) {
        return Err(Error::DestinationConflict(dest_dir_rel));
    }

    let prefix = format!("{src_rel}/");
    let mut files = Vec::new();
    for e in &idx.entries {
        if e.status == EntryStatus::Removed || !e.path.starts_with(&prefix) {
            continue;
        }
        // A tracked file that is gone from the tree would be staged at the
        // destination again, and the move would bring back a deleted file.
        let Ok(meta) = std::fs::symlink_metadata(cwd.join(&e.path)) else {
            return Err(bad(&e.path, SourceFault::MissingFromTree));
        };
        // A file that is now a directory would stage the old blob.
        if meta.is_dir() {
            return Err(bad(&e.path, SourceFault::NowDirectory));
        }
        // The rename would carry a symlink inside the directory along.
        if has_symlinked_ancestor(cwd, &e.path) {
            return Err(bad(&e.path, SourceFault::SymlinkAncestor));
        }
        files.push(DirFileMove {
            src_rel: e.path.clone(),
            target_rel: format!("{dest_dir_rel}/{}", &e.path[prefix.len()..]),
            status: e.status,
            hash: e.object_hash,
        });
    }
    if files.is_empty() {
        return Err(Error::NotTracked(source.to_owned()));
    }

    Ok(PlannedDirMove {
        src_dir_rel: src_rel.to_owned(),
        src_dir_abs,
        dest_dir_rel,
        dest_dir_abs,
        files,
    })
}

/// Rename the directory of one planned move. The plan found the destination
/// absent, so the rename removes nothing.
fn execute_dir_move(m: &PlannedDirMove) -> Result<(), Error> {
    create_parent(&m.dest_dir_abs)?;
    std::fs::rename(&m.src_dir_abs, &m.dest_dir_abs).map_err(|source| Error::Rename {
        from: m.src_dir_rel.clone(),
        to: m.dest_dir_rel.clone(),
        source,
    })
}

/// Record a directory move in the index. The execution only flips statuses
/// and appends, so the slots of the file moves in the same batch stay valid.
fn apply_dir_to_index(idx: &mut index::Index, m: &PlannedDirMove) {
    for f in &m.files {
        if let Some(i) = idx
            .find_entry(&f.src_rel)
            .filter(|&i| idx.entries[i].status != EntryStatus::Removed)
        {
            idx.entries[i].status = EntryStatus::Removed;
            idx.entries[i].object_hash = ZERO;
        }
        stage_destination(idx, &f.target_rel, f.status, f.hash);
    }
}

/// True for a dangling symlink too, unlike [`Path::exists`].
fn path_present(p: &Path) -> bool {
    p.symlink_metadata().is_ok()
}

/// Do `a` and `b` resolve to the same file system object? A path that does
/// not resolve counts as different.
fn same_file(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(ca), Ok(cb)) => ca == cb,
        _ => false,
    }
}

/// Is the move a case-only rename (`Foo` to `foo`) on a case-insensitive file
/// system? The destination then resolves to the source. The paths differ in
/// text, and the destination is not a symlink. A symlink that points at the
/// source is a separate name, and the caller needs `force` to replace it.
fn is_case_only_rename(src_rel: &str, target_rel: &str, src_abs: &Path, target_abs: &Path) -> bool {
    src_rel != target_rel
        && same_file(src_abs, target_abs)
        && std::fs::symlink_metadata(target_abs).is_ok_and(|m| !m.file_type().is_symlink())
}

/// Does a component above the last one of `rel` (under `root`) go through a
/// symlink? `symlink_metadata` does not follow the last component only. A
/// link above it could lead out of the repository. The last component is not
/// checked, because a move may carry a tracked symlink.
fn has_symlinked_ancestor(root: &Path, rel: &str) -> bool {
    let comps: Vec<&str> = rel.split('/').filter(|c| !c.is_empty()).collect();
    let mut p = root.to_path_buf();
    for comp in comps.iter().take(comps.len().saturating_sub(1)) {
        p.push(comp);
        if std::fs::symlink_metadata(&p).is_ok_and(|m| m.file_type().is_symlink()) {
            return true;
        }
    }
    false
}

/// Remove a file, a symlink or a directory at `p`.
fn remove_path(p: &Path) -> io::Result<()> {
    match p.symlink_metadata() {
        Ok(meta) if meta.is_dir() => std::fs::remove_dir_all(p),
        _ => std::fs::remove_file(p),
    }
}

/// Does `target_abs` stay in the repository once symlinks resolve? The check
/// resolves the nearest ancestor that exists, because the leaf may not exist
/// yet. A link above the destination that leads out fails the check.
fn target_within_repo(root_canon: &Path, target_abs: &Path) -> bool {
    let mut ancestor = target_abs.parent();
    while let Some(a) = ancestor {
        match a.canonicalize() {
            Ok(real) => return real.starts_with(root_canon),
            Err(_) => ancestor = a.parent(),
        }
    }
    false
}

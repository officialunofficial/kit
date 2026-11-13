//! The resolvable-conflict workflow shared by `merge`, `rebase`,
//! `cherry-pick` and `revert`.
//!
//! [`materialize`] writes the conflict material of a paused operation into
//! the index and the files. A text conflict gets markers. A binary,
//! delete/modify or special conflict keeps one side whole. [`first_unresolved_marker`]
//! and [`ensure_staged`] decide whether a resolution is complete.
//! [`ensure_abort_safe`] and [`reset_paths`] undo the material of a paused
//! operation without loss of user work.
//!
//! A caller runs `kit_sync::worktree::ensure_restore_safe` over the conflict
//! tree before [`materialize`], so dirty tracked files and untracked
//! collisions are never overwritten. This module prints nothing. [`materialize`]
//! reports each path to an [`Observer`].

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use kit_core::bounded_read;
use kit_core::hash::{self, Hash};
use kit_core::index::{self, EntryStatus, Index, IndexEntry, IndexError};
use kit_core::layout::RepoLayout;
use kit_core::object::{EntryMode, Object};
use kit_core::observer::Observer;
use kit_core::ops::conflict_state::ConflictRecord;
use kit_core::ops::diff::{DiffKind, diff_trees};
use kit_core::ops::merge::{Conflict, ConflictKind};
use kit_core::store::{EphemeralSink, HashOnlySink, ObjectStore, StoreError};
use kit_core::worktree::{self, WorktreeError};
use kit_sync::worktree::{
    current_head_tree, read_or_seed_index_from_head, restore_worktree_and_index,
};

/// How a conflicting path is presented to the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConflictClass {
    /// Text modify/modify or add/add. The file holds markers for both sides.
    TextMarkers,
    /// A binary blob on either side. The file keeps one side whole, because
    /// markers would corrupt it.
    Binary,
    /// One side deleted the path. The file keeps the side that survives.
    DeleteModify,
    /// A symlink, an executable or a file-versus-directory conflict. The
    /// file keeps one side whole with its exact mode.
    Special,
}

/// What [`materialize`] reports to its [`Observer`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// The material of one conflicting path is now in the files and the
    /// index.
    Materialized {
        /// The repository-relative path.
        path: String,
        /// How the path is presented.
        class: ConflictClass,
    },
}

/// Errors from the conflict workflow.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A conflict side is not a blob.
    #[error("conflict side is not a blob")]
    SideNotBlob,
    /// A conflict blob cannot be read.
    #[error("read conflict blob: {0}")]
    ReadBlob(StoreError),
    /// A restore primitive of the worktree failed. The text is final.
    #[error("{0}")]
    Worktree(String),
    /// The index cannot be read.
    #[error("read index: {0}")]
    ReadIndex(IndexError),
    /// The index cannot be written.
    #[error("write index: {0}")]
    WriteIndex(IndexError),
    /// The tree to go back to cannot be read.
    #[error("read target tree: {0}")]
    ReadTargetTree(IndexError),
    /// A directory cannot be created.
    #[error("create dir {}: {source}", path.display())]
    CreateDir {
        /// The directory.
        path: PathBuf,
        /// Why it failed.
        source: io::Error,
    },
    /// A file cannot be written.
    #[error("write {}: {source}", path.display())]
    WriteFile {
        /// The file.
        path: PathBuf,
        /// Why it failed.
        source: io::Error,
    },
    /// A file cannot be read.
    #[error("read {}: {source}", path.display())]
    ReadFile {
        /// The file.
        path: PathBuf,
        /// Why it failed.
        source: io::Error,
    },
    /// A file cannot be removed.
    #[error("remove {}: {source}", path.display())]
    Remove {
        /// The file.
        path: PathBuf,
        /// Why it failed.
        source: io::Error,
    },
    /// A file cannot be examined.
    #[error("stat {}: {source}", path.display())]
    Stat {
        /// The file.
        path: PathBuf,
        /// Why it failed.
        source: io::Error,
    },
    /// The executable bit cannot be set.
    #[error("chmod {}: {source}", path.display())]
    SetExecutable {
        /// The file.
        path: PathBuf,
        /// Why it failed.
        source: io::Error,
    },
    /// A symlink in the files cannot be read.
    #[error("read link {}: {source}", path.display())]
    ReadLink {
        /// The symlink.
        path: PathBuf,
        /// Why it failed.
        source: io::Error,
    },
    /// A symlink cannot be created.
    #[error("create symlink {}: {source}", path.display())]
    CreateSymlink {
        /// The symlink.
        path: PathBuf,
        /// Why it failed.
        source: io::Error,
    },
    /// The target of a conflict symlink is not text.
    #[error("symlink target for {} is not UTF-8", .0.display())]
    SymlinkTargetNotText(PathBuf),
    /// The target of a symlink in the files is not text.
    #[error("symlink target not UTF-8: {}", .0.display())]
    LinkTargetNotText(PathBuf),
    /// The target of a conflict symlink would leave the tree.
    #[error("refusing to materialise unsafe symlink target {target:?} for {}", path.display())]
    UnsafeSymlinkTarget {
        /// The target text.
        target: String,
        /// The symlink.
        path: PathBuf,
    },
    /// A symlink target cannot be stored.
    #[error("store symlink: {0}")]
    StoreSymlink(WorktreeError),
    /// A file cannot be stored.
    #[error("store: {0}")]
    StoreFile(WorktreeError),
    /// The changes between two trees cannot be computed to find the deleted
    /// paths.
    #[error("diff for staged deletions: {0}")]
    DiffForRemovals(StoreError),
    /// A safety check could not finish.
    #[error("{stage}: {source}")]
    Check {
        /// What the check looked at.
        stage: &'static str,
        /// Why it failed.
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// An abort would overwrite staged changes.
    #[error("abort would overwrite staged changes; commit, stash, or reset '{0}' first")]
    AbortOverwritesStaged(String),
    /// An abort would overwrite changes in the files.
    #[error("abort would overwrite local changes; commit, stash, or reset '{0}' first")]
    AbortOverwritesLocal(String),
    /// An abort would overwrite an untracked path.
    #[error("abort would overwrite untracked path '{0}'; move or remove it first")]
    AbortOverwritesUntracked(String),
    /// An abort would replace a directory with a file.
    #[error("abort would replace directory '{0}' with a file; move or remove it first")]
    AbortReplacesDirectory(String),
    /// An abort would restore a path below a file.
    #[error("abort would restore '{path}' but '{ancestor}' is a file; move or remove it first")]
    AbortBelowFile {
        /// The path to restore.
        path: String,
        /// The ancestor that is a file now.
        ancestor: String,
    },
    /// An abort would discard an untracked directory.
    #[error("abort would discard the untracked directory '{0}'; move or remove it first")]
    AbortDiscardsDirectory(String),
    /// A resolution is in the files but not in the index.
    #[error(
        "'{0}' is resolved in the worktree but not staged; run `kit add {0}` (or `kit rm {0}`) then `--continue`"
    )]
    NotStaged(String),
}

/// Wrap the failure of a safety check.
fn check<E>(stage: &'static str) -> impl FnOnce(E) -> Error
where
    E: std::error::Error + Send + Sync + 'static,
{
    move |source| Error::Check {
        stage,
        source: Box::new(source),
    }
}

/// The lines of a marker block. The scanner and the writer share them.
const MARK_OURS: &str = "<<<<<<< ours";
const MARK_SEP: &str = "=======";
const MARK_THEIRS: &str = ">>>>>>> theirs";

/// A blob is text when it has no NUL byte and is valid UTF-8.
fn is_text(data: &[u8]) -> bool {
    !data.contains(&0) && core::str::from_utf8(data).is_ok()
}

fn read_blob(store: &ObjectStore, h: Hash) -> Result<Vec<u8>, Error> {
    match store.read_object(&h) {
        Ok(Object::Blob(b)) => Ok(b.data),
        Ok(_) => Err(Error::SideNotBlob),
        Err(e) => Err(Error::ReadBlob(e)),
    }
}

fn is_blob(store: &ObjectStore, h: Hash) -> bool {
    matches!(store.read_object(&h), Ok(Object::Blob(_)))
}

/// A side is fit for markers when it is absent or a blob. A side that is a
/// tree is a file-versus-directory conflict.
fn side_is_blob_or_absent(store: &ObjectStore, side: Option<Hash>) -> bool {
    side.is_none_or(|h| is_blob(store, h))
}

/// Markers cannot show a symlink or an executable, and the exact mode must
/// survive.
fn side_is_special_mode(mode: Option<EntryMode>) -> bool {
    matches!(mode, Some(EntryMode::Symlink | EntryMode::Executable))
}

fn classify(store: &ObjectStore, c: &Conflict) -> Result<ConflictClass, Error> {
    match c.kind {
        ConflictKind::DeleteModify => Ok(ConflictClass::DeleteModify),
        ConflictKind::ModifyModify | ConflictKind::AddAdd => {
            if !side_is_blob_or_absent(store, c.ours_hash)
                || !side_is_blob_or_absent(store, c.theirs_hash)
                || side_is_special_mode(c.ours_mode)
                || side_is_special_mode(c.theirs_mode)
            {
                return Ok(ConflictClass::Special);
            }
            let ours_text = match c.ours_hash {
                Some(h) => is_text(&read_blob(store, h)?),
                None => true,
            };
            let theirs_text = match c.theirs_hash {
                Some(h) => is_text(&read_blob(store, h)?),
                None => true,
            };
            if ours_text && theirs_text {
                Ok(ConflictClass::TextMarkers)
            } else {
                Ok(ConflictClass::Binary)
            }
        }
    }
}

/// Write the material of every conflict into the files and the index. Return
/// one record for each path, for the sidecar file.
///
/// `merged_tree` is the merge result of the operation. It holds "ours" at
/// every conflicting path and the clean change everywhere else. The function
/// applies it to the index and the files first. Without that step the clean
/// changes would never reach the index, and the build of the final tree
/// from the index would drop them. Then it overlays the conflicting paths:
///
/// - A text conflict gets `<<<<<<< ours`, `=======` and `>>>>>>> theirs`
///   markers.
/// - Any other conflict keeps one side whole in the files, with its mode.
///
/// The index entry of each path becomes the ours side, or a removal when
/// ours deleted the path. A later `kit add` then updates it as usual. The
/// executable bit and a symlink survive, because the committed tree takes its
/// mode from the index.
///
/// # Errors
/// [`Error`] when the store, the index or the files fail.
pub fn materialize(
    layout: &RepoLayout,
    store: &ObjectStore,
    merged_tree: Hash,
    conflicts: &[Conflict],
    observer: &dyn Observer<Event>,
) -> Result<Vec<ConflictRecord>, Error> {
    restore_worktree_and_index(layout, store, merged_tree).map_err(Error::Worktree)?;
    let mut idx = index::read_index(layout).map_err(Error::ReadIndex)?;
    let mut records = Vec::with_capacity(conflicts.len());

    for c in conflicts {
        let class = classify(store, c)?;
        let abs = layout.worktree_root().join(&c.path);
        match class {
            ConflictClass::TextMarkers => {
                let ours = c
                    .ours_hash
                    .map_or_else(|| Ok(Vec::new()), |h| read_blob(store, h))?;
                let theirs = c
                    .theirs_hash
                    .map_or_else(|| Ok(Vec::new()), |h| read_blob(store, h))?;
                write_text_markers(&abs, &ours, &theirs)?;
            }
            ConflictClass::Binary | ConflictClass::DeleteModify | ConflictClass::Special => {
                materialize_side(store, &abs, c)?;
            }
        }
        stage_ours(&mut idx, store, c);
        observer.event(&Event::Materialized {
            path: c.path.clone(),
            class,
        });
        records.push(ConflictRecord::from(c));
    }

    index::write_index(layout, &idx).map_err(Error::WriteIndex)?;
    Ok(records)
}

/// The index status that keeps a tree mode. A tree has no single-file
/// representation, and the caller stages blob sides only.
fn status_for_mode(mode: EntryMode) -> EntryStatus {
    match mode {
        EntryMode::Executable => EntryStatus::Executable,
        EntryMode::Symlink => EntryStatus::Symlink,
        EntryMode::Blob | EntryMode::Tree => EntryStatus::Blob,
    }
}

/// Stage the ours side of a conflict. A removal stands for a path that ours
/// deleted. A tree side stays for the user to resolve.
fn stage_ours(idx: &mut Index, store: &ObjectStore, c: &Conflict) {
    let entry = match c.ours_hash {
        Some(h) if is_blob(store, h) => IndexEntry {
            path: c.path.clone(),
            status: c.ours_mode.map_or(EntryStatus::Blob, status_for_mode),
            object_hash: h,
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
        },
        Some(_) => return,
        None => IndexEntry {
            path: c.path.clone(),
            status: EntryStatus::Removed,
            object_hash: hash::ZERO,
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
        },
    };
    idx.upsert_entry(entry);
}

fn write_text_markers(abs: &Path, ours: &[u8], theirs: &[u8]) -> Result<(), Error> {
    let mut buf = Vec::new();
    buf.extend_from_slice(MARK_OURS.as_bytes());
    buf.push(b'\n');
    buf.extend_from_slice(ours);
    if !ours.is_empty() && ours.last() != Some(&b'\n') {
        buf.push(b'\n');
    }
    buf.extend_from_slice(MARK_SEP.as_bytes());
    buf.push(b'\n');
    buf.extend_from_slice(theirs);
    if !theirs.is_empty() && theirs.last() != Some(&b'\n') {
        buf.push(b'\n');
    }
    buf.extend_from_slice(MARK_THEIRS.as_bytes());
    buf.push(b'\n');
    write_bytes(abs, &buf)
}

/// Put the surviving side of a non-text conflict in the files, with its mode.
///
/// The ours side wins, so the file and the staged entry agree. When ours is
/// absent or a tree, theirs is the fallback. When neither side is a blob, the
/// files stay as they are.
fn materialize_side(store: &ObjectStore, abs: &Path, c: &Conflict) -> Result<(), Error> {
    let pick = [(c.ours_hash, c.ours_mode), (c.theirs_hash, c.theirs_mode)]
        .into_iter()
        .find_map(|(h, m)| match h {
            Some(h) if is_blob(store, h) => Some((h, m)),
            _ => None,
        });
    let Some((h, mode)) = pick else {
        return Ok(());
    };
    // In a file-versus-directory conflict the merged tree already wrote the
    // directory side at this path. A blob cannot replace a directory, and a
    // failed write here would leave the operation without state to abort.
    // The directory stays. The user resolves the path by hand.
    if fs::symlink_metadata(abs).is_ok_and(|m| m.is_dir()) {
        return Ok(());
    }
    match mode {
        Some(EntryMode::Symlink) => write_symlink(store, abs, h),
        Some(EntryMode::Executable) => write_blob(store, abs, h, true),
        _ => write_blob(store, abs, h, false),
    }
}

fn write_blob(store: &ObjectStore, abs: &Path, h: Hash, executable: bool) -> Result<(), Error> {
    let data = read_blob(store, h)?;
    // A file or symlink of another shape must not shadow the new file.
    let _ = fs::remove_file(abs);
    write_bytes(abs, &data)?;
    if executable {
        set_executable(abs)?;
    }
    Ok(())
}

/// Write a symlink blob, whose payload is the target. The target must stay
/// inside the tree, so a conflict cannot plant a link that escapes it.
fn write_symlink(store: &ObjectStore, abs: &Path, h: Hash) -> Result<(), Error> {
    let data = read_blob(store, h)?;
    let target =
        core::str::from_utf8(&data).map_err(|_| Error::SymlinkTargetNotText(abs.to_path_buf()))?;
    if !worktree::validate_symlink_target(target) {
        return Err(Error::UnsafeSymlinkTarget {
            target: target.to_owned(),
            path: abs.to_path_buf(),
        });
    }
    if let Some(parent) = abs.parent() {
        fs::create_dir_all(parent).map_err(|source| Error::CreateDir {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let _ = fs::remove_file(abs);
    create_symlink(target, abs).map_err(|source| Error::CreateSymlink {
        path: abs.to_path_buf(),
        source,
    })
}

#[cfg(unix)]
fn set_executable(abs: &Path) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;
    let mut perm = fs::metadata(abs)
        .map_err(|source| Error::Stat {
            path: abs.to_path_buf(),
            source,
        })?
        .permissions();
    perm.set_mode(0o755);
    fs::set_permissions(abs, perm).map_err(|source| Error::SetExecutable {
        path: abs.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn set_executable(_abs: &Path) -> Result<(), Error> {
    Ok(())
}

#[cfg(unix)]
fn create_symlink(target: &str, link: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn create_symlink(target: &str, link: &Path) -> io::Result<()> {
    std::os::windows::fs::symlink_file(target, link)
}

#[cfg(not(any(unix, windows)))]
fn create_symlink(_target: &str, _link: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "symlink creation is not supported on this target",
    ))
}

fn write_bytes(abs: &Path, data: &[u8]) -> Result<(), Error> {
    if let Some(parent) = abs.parent() {
        fs::create_dir_all(parent).map_err(|source| Error::CreateDir {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    fs::write(abs, data).map_err(|source| Error::WriteFile {
        path: abs.to_path_buf(),
        source,
    })
}

/// Refuse an abort before it changes anything, when going back to
/// `target_tree` would overwrite user work that is not conflict material.
///
/// An abort first resets the conflict paths and then restores `target_tree`
/// with the usual guards. The reset destroys the resolution of the user, so
/// it must not run when the restore is going to be refused. This check looks
/// at the paths that are not discardable. The conflict paths hold markers and
/// partial edits, so they are expected to be dirty.
///
/// A path is discardable when it is a recorded conflict path. A clean hunk of
/// the operation is discardable too, while its index entry and its file
/// still match `op_result_tree`. A clean hunk that the user edited is user
/// work. Without `op_result_tree` only the conflict paths are discardable.
///
/// # Errors
/// An `Abort*` variant that names the blocking path. [`Error::Check`] or
/// [`Error::Worktree`] when the check cannot finish.
#[allow(clippy::too_many_lines)] // independent checks that all run before any change
pub fn ensure_abort_safe(
    layout: &RepoLayout,
    store: &ObjectStore,
    records: &[ConflictRecord],
    target_tree: Hash,
    op_result_tree: Option<Hash>,
) -> Result<(), Error> {
    let root = layout.worktree_root();
    let current_tree = current_head_tree(layout, store).map_err(Error::Worktree)?;
    let idx = read_or_seed_index_from_head(layout, store).map_err(Error::Worktree)?;
    // The snapshot trees of a check live in memory only.
    let snapshot = EphemeralSink::new(store);
    let index_tree = worktree::build_tree_from_index_with(store, &snapshot, &idx, false)
        .map_err(check("check index state"))?;
    // The index is the tracked set. A tracked file that an ignore rule
    // matches must stay in the snapshot, or it reads as a deletion.
    let worktree_tree = worktree::build_tree_filtered_observed_with_source(
        &snapshot,
        &snapshot,
        root,
        Some(&idx),
        &mut Vec::new(),
    )
    .map_err(check("check worktree"))?;

    let conflict_paths: HashSet<String> = records.iter().map(|r| r.path.clone()).collect();
    let mut discardable = conflict_paths.clone();
    if let Some(result_tree) = op_result_tree {
        let authored = diff_trees(&snapshot, current_tree, Some(result_tree))
            .map_err(check("check operation changes"))?;
        // The paths that the user changed after the operation paused.
        let mut modified: HashSet<String> = HashSet::new();
        for tree in [index_tree, worktree_tree] {
            for e in diff_trees(&snapshot, Some(result_tree), Some(tree))
                .map_err(check("check operation changes"))?
                .entries
            {
                modified.insert(e.path);
            }
        }
        for e in authored.entries {
            if conflict_paths.contains(&e.path) || !modified.contains(&e.path) {
                discardable.insert(e.path);
            }
        }
    }
    let is_discardable = |p: &str| discardable.contains(p);

    let staged = diff_trees(&snapshot, current_tree, Some(index_tree))
        .map_err(check("check staged changes"))?;
    if let Some(entry) = staged.entries.iter().find(|e| !is_discardable(&e.path)) {
        return Err(Error::AbortOverwritesStaged(entry.path.clone()));
    }

    let unstaged = diff_trees(&snapshot, Some(index_tree), Some(worktree_tree))
        .map_err(check("check worktree"))?;
    if let Some(entry) = unstaged
        .entries
        .iter()
        .find(|e| e.kind != DiffKind::Added && !is_discardable(&e.path))
    {
        return Err(Error::AbortOverwritesLocal(entry.path.clone()));
    }

    let restore = diff_trees(&snapshot, Some(index_tree), Some(target_tree))
        .map_err(check("check restore target"))?;

    // An untracked path that the restore would write.
    let target_writes: Vec<&str> = restore
        .entries
        .iter()
        .filter(|e| e.kind != DiffKind::Removed && !is_discardable(&e.path))
        .map(|e| e.path.as_str())
        .collect();
    if !target_writes.is_empty() {
        for entry in &unstaged.entries {
            if entry.kind == DiffKind::Added
                && !is_discardable(&entry.path)
                && target_writes.contains(&entry.path.as_str())
            {
                return Err(Error::AbortOverwritesUntracked(entry.path.clone()));
            }
        }
    }

    // The restore writes a file at every path that it adds or changes, also
    // at a discardable path. Refuse when that path is a directory now, or
    // when an ancestor is a file now. The restore would stop half way, and
    // the removal of the directory would destroy untracked content.
    for entry in &restore.entries {
        if entry.kind == DiffKind::Removed {
            continue;
        }
        if fs::symlink_metadata(root.join(&entry.path)).is_ok_and(|m| m.is_dir()) {
            return Err(Error::AbortReplacesDirectory(entry.path.clone()));
        }
        if let Some(ancestor) = ancestor_that_is_file(root, &entry.path) {
            return Err(Error::AbortBelowFile {
                path: entry.path.clone(),
                ancestor,
            });
        }
    }
    Ok(())
}

/// The first proper ancestor of `path` that is not a directory in the files.
fn ancestor_that_is_file(root: &Path, path: &str) -> Option<String> {
    let mut prefix = String::new();
    for comp in path.split('/') {
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(comp);
        if prefix == path {
            return None;
        }
        if fs::symlink_metadata(root.join(&prefix)).is_ok_and(|m| !m.is_dir()) {
            return Some(prefix);
        }
    }
    None
}

/// Reset every path that the operation wrote to its content in
/// `target_tree`. Write the target file, or remove the file when the target
/// has no such path, and align the index entry.
///
/// The paths are the recorded conflict paths and the clean hunks of
/// `op_result_tree`. After the reset the files and the index agree with
/// `target_tree` on those paths. The restore that follows then sees no
/// change that the operation itself made, and it still protects unrelated
/// work.
///
/// The function checks every path before it changes one, so a refusal leaves
/// the tree as it was.
///
/// # Errors
/// An `Abort*` variant when a path cannot be reset without loss.
/// [`Error`] when the store or the files fail.
#[allow(clippy::too_many_lines)] // the checks and the changes stay together
pub fn reset_paths(
    layout: &RepoLayout,
    store: &ObjectStore,
    records: &[ConflictRecord],
    target_tree: Hash,
    op_result_tree: Option<Hash>,
) -> Result<(), Error> {
    let root = layout.worktree_root();

    let target_idx = index::from_tree(store, target_tree).map_err(Error::ReadTargetTree)?;
    let target_map: HashMap<&str, &IndexEntry> = target_idx
        .entries
        .iter()
        .map(|e| (e.path.as_str(), e))
        .collect();

    let mut paths: BTreeSet<String> = records.iter().map(|r| r.path.clone()).collect();
    if let Some(result_tree) = op_result_tree {
        let snapshot = EphemeralSink::new(store);
        let authored = diff_trees(&snapshot, Some(target_tree), Some(result_tree))
            .map_err(check("check operation changes"))?;
        for e in authored.entries {
            paths.insert(e.path);
        }
    }

    // Check first. The caller may have vetted another tree than the one that
    // the reset goes back to, so a path can still fail in the loop below.
    // Every failure of the loop is covered here: a write over a directory, a
    // write below a file, and the removal of a path that the user replaced
    // with a directory that holds files.
    for path in &paths {
        let abs = root.join(path);
        if target_map.contains_key(path.as_str()) {
            if fs::symlink_metadata(&abs).is_ok_and(|m| m.is_dir()) {
                return Err(Error::AbortReplacesDirectory(path.clone()));
            }
            if let Some(ancestor) = ancestor_that_is_file(root, path) {
                return Err(Error::AbortBelowFile {
                    path: path.clone(),
                    ancestor,
                });
            }
            continue;
        }
        if is_directory_in(&target_map, path) {
            continue;
        }
        if fs::symlink_metadata(&abs).is_ok_and(|m| m.is_dir())
            && fs::read_dir(&abs).is_ok_and(|mut it| it.next().is_some())
        {
            return Err(Error::AbortDiscardsDirectory(path.clone()));
        }
    }

    let mut idx = read_or_seed_index_from_head(layout, store).map_err(Error::Worktree)?;

    for path in &paths {
        let abs = root.join(path);
        if let Some(target_entry) = target_map.get(path.as_str()) {
            match target_entry.status {
                EntryStatus::Symlink => write_symlink(store, &abs, target_entry.object_hash)?,
                EntryStatus::Executable => write_blob(store, &abs, target_entry.object_hash, true)?,
                _ => write_blob(store, &abs, target_entry.object_hash, false)?,
            }
            idx.upsert_entry((*target_entry).clone());
            continue;
        }
        // The path is no file in the target. A file-versus-directory conflict
        // records the path of a directory that the target holds. That
        // directory is in the files already, and the restore that follows
        // aligns it. Only a stale index entry at the path itself goes.
        if is_directory_in(&target_map, path) {
            idx.remove_path(path);
            continue;
        }
        // The operation added the path. Remove it. A directory that the user
        // put there goes only when it is empty, so untracked files stay.
        if fs::symlink_metadata(&abs).is_ok_and(|m| m.is_dir()) {
            if let Err(e) = fs::remove_dir(&abs)
                && e.kind() != io::ErrorKind::NotFound
            {
                return Err(Error::AbortDiscardsDirectory(path.clone()));
            }
        } else if let Err(source) = fs::remove_file(&abs)
            && source.kind() != io::ErrorKind::NotFound
        {
            return Err(Error::Remove { path: abs, source });
        }
        idx.remove_path(path);
    }
    index::write_index(layout, &idx).map_err(Error::WriteIndex)
}

/// Whether the target tree holds a directory at `path`.
fn is_directory_in(target_map: &HashMap<&str, &IndexEntry>, path: &str) -> bool {
    let dir_prefix = format!("{path}/");
    target_map
        .keys()
        .any(|k| k.starts_with(dir_prefix.as_str()))
}

/// Stage the deletions of `result_tree` against `base_tree`.
///
/// A tree cannot hold a deletion, so staging a result tree drops them. This
/// function adds a removal entry to the index for every path of `base_tree`
/// that `result_tree` lacks. An operation that stages its result without a
/// commit calls it. Otherwise a result that only deletes files would leave an
/// empty index, and the next commit would find nothing staged.
///
/// # Errors
/// [`Error::DiffForRemovals`], [`Error::ReadIndex`] or [`Error::WriteIndex`].
pub fn stage_removals(
    layout: &RepoLayout,
    store: &ObjectStore,
    base_tree: Option<Hash>,
    result_tree: Hash,
) -> Result<(), Error> {
    let removed: Vec<String> = diff_trees(store, base_tree, Some(result_tree))
        .map_err(Error::DiffForRemovals)?
        .entries
        .into_iter()
        .filter(|e| e.kind == DiffKind::Removed)
        .map(|e| e.path)
        .collect();
    if removed.is_empty() {
        return Ok(());
    }
    let mut idx = index::read_index(layout).map_err(Error::ReadIndex)?;
    for path in removed {
        match idx.find_entry(&path) {
            Some(j) => {
                idx.entries[j].status = EntryStatus::Removed;
                idx.entries[j].object_hash = hash::ZERO;
            }
            None => idx.upsert_entry(IndexEntry {
                path,
                status: EntryStatus::Removed,
                object_hash: hash::ZERO,
                mtime_ns: 0,
                size: 0,
                ino: 0,
                ctime_ns: 0,
            }),
        }
    }
    index::write_index(layout, &idx).map_err(Error::WriteIndex)
}

/// Whether `meta` has an executable bit. Kit records no executable on other
/// platforms.
#[cfg(unix)]
fn is_executable(meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o111 != 0
}
#[cfg(not(unix))]
fn is_executable(_meta: &fs::Metadata) -> bool {
    false
}

/// The status and hash that `kit add` would stage for the file at `abs`.
/// Return `None` for a missing path or a directory, which have no single-file
/// entry.
fn worktree_object(store: &ObjectStore, abs: &Path) -> Result<Option<(EntryStatus, Hash)>, Error> {
    let meta = match abs.symlink_metadata() {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(Error::Stat {
                path: abs.to_path_buf(),
                source,
            });
        }
    };
    let ft = meta.file_type();
    if ft.is_symlink() {
        let target = fs::read_link(abs).map_err(|source| Error::ReadLink {
            path: abs.to_path_buf(),
            source,
        })?;
        let target_str = target
            .to_str()
            .ok_or_else(|| Error::LinkTargetNotText(abs.to_path_buf()))?;
        let h = worktree::store_file_object(store, target_str.as_bytes())
            .map_err(Error::StoreSymlink)?;
        return Ok(Some((EntryStatus::Symlink, h)));
    }
    if ft.is_file() {
        // The hash streams a large file one chunk at a time. A dry sink
        // keeps no object, because the caller compares the id only.
        let (h, opened) =
            worktree::hash_file_with_metadata(&HashOnlySink::new(), abs).map_err(|e| match e {
                WorktreeError::Io(_) | WorktreeError::FileTooLarge { .. } => Error::ReadFile {
                    path: abs.to_path_buf(),
                    source: io::Error::other(e),
                },
                other => Error::StoreFile(other),
            })?;
        let status = if is_executable(&opened) {
            EntryStatus::Executable
        } else {
            EntryStatus::Blob
        };
        return Ok(Some((status, h)));
    }
    Ok(None)
}

/// Refuse to continue when a resolution is in the files but not in the
/// index. The final tree comes from the index, so an unstaged resolution
/// would be lost, and the restore of the files would overwrite it.
///
/// The check compares the status and the hash of the file with the staged
/// entry. It catches an edited regular or executable file, and a path that
/// was deleted or replaced without `kit rm` or `kit add`. A conflict that the
/// user left as it was still matches the staged ours side, with its mode.
///
/// # Errors
/// [`Error::NotStaged`] for the first path that is not staged.
pub fn ensure_staged(
    layout: &RepoLayout,
    store: &ObjectStore,
    records: &[ConflictRecord],
) -> Result<(), Error> {
    let idx = index::read_index(layout).map_err(Error::ReadIndex)?;
    for r in records {
        let wt = worktree_object(store, &layout.worktree_root().join(&r.path))?;
        // A removal entry means that ours deleted the path.
        let staged = idx
            .entries
            .iter()
            .find(|e| e.path == r.path)
            .filter(|e| e.status != EntryStatus::Removed);
        let resolved = match (&wt, staged) {
            (None, None) => true,
            (Some((ws, wh)), Some(e)) => *ws == e.status && *wh == e.object_hash,
            (Some(_), None) | (None, Some(_)) => false,
        };
        if !resolved {
            return Err(Error::NotStaged(r.path.clone()));
        }
    }
    Ok(())
}

/// The size above which the scan for markers skips a file.
///
/// A conflict writes markers only when both sides are single blobs, and a
/// chunked side is never text-merged. A file above the limit is not scanned.
/// The limit does not follow the size that kit hashes, so a larger hash limit
/// never grows the scan.
const MARKER_SCAN_LIMIT: u64 = 1024 * 1024 * 1024;

/// The first recorded path whose file still holds a complete marker block.
///
/// Only text conflicts hold markers. A directory holds none, so a
/// file-versus-directory conflict never blocks a continue. A missing file is
/// skipped.
///
/// # Errors
/// [`Error::ReadFile`] when a file cannot be read.
pub fn first_unresolved_marker(
    root: &Path,
    records: &[ConflictRecord],
) -> Result<Option<String>, Error> {
    for r in records {
        let abs = root.join(&r.path);
        let meta = fs::symlink_metadata(&abs);
        if meta.as_ref().is_ok_and(fs::Metadata::is_dir) {
            continue;
        }
        // A file above the scan limit is skipped without a read.
        if meta.is_ok_and(|m| m.len() > MARKER_SCAN_LIMIT) {
            continue;
        }
        let data = match bounded_read::read_capped(&abs, MARKER_SCAN_LIMIT) {
            Ok(d) => d,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            // The file grew past the limit after the size check.
            Err(e) if e.kind() == io::ErrorKind::InvalidData => continue,
            Err(source) => return Err(Error::ReadFile { path: abs, source }),
        };
        if file_has_markers(&data) {
            return Ok(Some(r.path.clone()));
        }
    }
    Ok(None)
}

fn file_has_markers(data: &[u8]) -> bool {
    let Ok(text) = core::str::from_utf8(data) else {
        return false;
    };
    let mut saw_ours = false;
    let mut saw_sep = false;
    let mut saw_theirs = false;
    for line in text.lines() {
        if line == MARK_OURS {
            saw_ours = true;
        } else if line == MARK_SEP {
            saw_sep = true;
        } else if line == MARK_THEIRS {
            saw_theirs = true;
        }
    }
    saw_ours && saw_sep && saw_theirs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_complete_marker_set() {
        let data = b"<<<<<<< ours\nfoo\n=======\nbar\n>>>>>>> theirs\n";
        assert!(file_has_markers(data));
    }

    #[test]
    fn ignores_partial_markers() {
        let data = b"<<<<<<< ours\nfoo\n";
        assert!(!file_has_markers(data));
    }

    #[test]
    fn clean_file_has_no_markers() {
        let data = b"just some resolved content\n";
        assert!(!file_has_markers(data));
    }

    #[test]
    fn text_detection() {
        assert!(is_text(b"hello world\n"));
        assert!(!is_text(b"\x00\x01\x02binary"));
        assert!(!is_text(&[0xff, 0xfe, 0xfd]));
    }
}

//! Apply parsed patches to the worktree, the index or both (SPEC-PATCH §4).
//!
//! [`apply`] builds an image of every path the patches name, applies each
//! file patch to the image in order, and writes only when all of them
//! apply. A patch that does not apply changes nothing.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use kit_core::hash::ZERO;
use kit_core::index::{self, EntryStatus, IndexEntry};
use kit_core::layout::RepoLayout;
use kit_core::observer::Observer;
use kit_core::ops::patch::{self, ApplyError, FilePatch, Mode};
use kit_core::store::ObjectStore;
use kit_core::worktree::{self, WorktreeError};
use kit_sync::worktree::read_or_seed_index_from_head;

use crate::lock;

/// Where the patches apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// The worktree files.
    Worktree,
    /// The index entries (`--cached`).
    Index,
    /// Both, which must agree on every path the patches name (`--index`).
    Both,
}

/// Errors from [`apply`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A file patch does not apply to its file.
    #[error("{path}: {reason}")]
    DoesNotApply {
        /// The path the file patch names.
        path: String,
        /// Why.
        reason: ApplyError,
    },
    /// `--index`: the worktree file differs from its index entry.
    #[error("{0}: the worktree file does not match the index")]
    Mismatch(String),
    /// The path is a symlink, a directory or below a symlink.
    #[error("{0}: not a regular file inside the worktree")]
    NotRegular(String),
    /// The worktree lock could not be taken.
    #[error(transparent)]
    Lock(#[from] lock::Error),
    /// The index could not be read or written.
    #[error("index: {0}")]
    Index(String),
    /// A file or a stored object could not be read or written.
    #[error("{path}: {source}")]
    Io {
        /// The path.
        path: PathBuf,
        /// The cause.
        source: io::Error,
    },
    /// The content of an index entry could not be read, or a new one could
    /// not be stored.
    #[error("{path}: {source}")]
    Object {
        /// The repository path.
        path: String,
        /// The cause.
        source: WorktreeError,
    },
}

impl Error {
    /// Whether the patch did not apply to the files as they are, rather than
    /// failing for another reason.
    #[must_use]
    pub fn is_conflict(&self) -> bool {
        matches!(
            self,
            Self::DoesNotApply { .. } | Self::Mismatch(_) | Self::NotRegular(_)
        )
    }
}

/// The content and mode of a path, or `None` when it does not exist.
type Entry = Option<(Vec<u8>, Mode)>;

/// Apply `patches` in order to `target`. With `check`, write nothing.
///
/// # Errors
/// [`Error`]. Every error leaves the files and the index as they were,
/// except an I/O failure in the middle of the writes.
pub fn apply(
    layout: &RepoLayout,
    store: &ObjectStore,
    patches: &[FilePatch],
    target: Target,
    check: bool,
    observer: &dyn Observer<lock::Event>,
) -> Result<(), Error> {
    let _lock = lock::acquire_worktree(layout, observer)?;
    let root = layout.worktree_root();
    let mut idx = match target {
        Target::Worktree => None,
        Target::Index | Target::Both => {
            Some(read_or_seed_index_from_head(layout, store).map_err(Error::Index)?)
        }
    };
    let mut before: BTreeMap<String, Entry> = BTreeMap::new();
    let mut image: BTreeMap<String, Entry> = BTreeMap::new();
    let mut load = |path: &str, image: &mut BTreeMap<String, Entry>| -> Result<Entry, Error> {
        if let Some(e) = image.get(path) {
            return Ok(e.clone());
        }
        let entry = match target {
            Target::Worktree => from_worktree(root, path)?,
            Target::Index => from_index(store, idx.as_ref(), path)?,
            Target::Both => {
                let w = from_worktree(root, path)?;
                if w != from_index(store, idx.as_ref(), path)? {
                    return Err(Error::Mismatch(path.to_owned()));
                }
                w
            }
        };
        before.insert(path.to_owned(), entry.clone());
        image.insert(path.to_owned(), entry.clone());
        Ok(entry)
    };
    for fp in patches {
        let shown = fp.new.as_deref().or(fp.old.as_deref()).unwrap_or_default();
        let fail = |reason| Error::DoesNotApply {
            path: shown.to_owned(),
            reason,
        };
        let old = match &fp.old {
            Some(o) => load(o, &mut image)?,
            None => None,
        };
        if let Some(new) = &fp.new
            && fp.old.as_ref() != Some(new)
            && load(new, &mut image)?.is_some()
        {
            return Err(fail(ApplyError::Exists));
        }
        let result = patch::apply(old.as_ref().map(|(c, _)| c.as_slice()), fp).map_err(fail)?;
        if let Some(o) = &fp.old {
            image.insert(o.clone(), None);
        }
        if let (Some(new), Some(content)) = (&fp.new, result) {
            let mode = fp
                .new_mode
                .or(old.as_ref().map(|(_, m)| *m))
                .unwrap_or(Mode::Regular);
            image.insert(new.clone(), Some((content, mode)));
        }
    }
    if check {
        return Ok(());
    }
    let changed: Vec<(&String, &Entry)> = image
        .iter()
        .filter(|(p, e)| before.get(*p) != Some(*e))
        .collect();
    if matches!(target, Target::Worktree | Target::Both) {
        // Deletions first, so a file may take the place of a removed one.
        for (path, _) in changed.iter().filter(|(_, e)| e.is_none()) {
            remove_file(root, path)?;
        }
        for (path, entry) in &changed {
            if let Some((content, mode)) = entry {
                write_file(root, path, content, *mode)?;
            }
        }
    }
    if let Some(idx) = idx.as_mut() {
        for (path, entry) in &changed {
            stage(store, idx, path, entry.as_ref())?;
        }
        index::write_index(layout, idx).map_err(|e| Error::Index(e.to_string()))?;
    }
    Ok(())
}

fn from_worktree(root: &Path, path: &str) -> Result<Entry, Error> {
    let abs = match worktree::path_for_write(root, path) {
        Ok(Some(abs)) => abs,
        Ok(None) => return Err(Error::NotRegular(path.to_owned())),
        Err(source) => {
            return Err(Error::Io {
                path: root.join(path),
                source,
            });
        }
    };
    match fs::symlink_metadata(&abs) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(Error::Io { path: abs, source }),
        Ok(meta) if !meta.is_file() => return Err(Error::NotRegular(path.to_owned())),
        Ok(_) => {}
    }
    let (meta, data) =
        worktree::read_regular_file_bounded(&abs).map_err(|source| Error::Object {
            path: path.to_owned(),
            source,
        })?;
    Ok(Some((data, mode_of(&meta))))
}

#[cfg(unix)]
fn mode_of(meta: &fs::Metadata) -> Mode {
    use std::os::unix::fs::PermissionsExt;
    if meta.permissions().mode() & 0o111 != 0 {
        Mode::Executable
    } else {
        Mode::Regular
    }
}

#[cfg(not(unix))]
fn mode_of(_meta: &fs::Metadata) -> Mode {
    Mode::Regular
}

fn from_index(store: &ObjectStore, idx: Option<&index::Index>, path: &str) -> Result<Entry, Error> {
    let Some(entry) = idx.and_then(|i| i.find_entry(path).map(|n| &i.entries[n])) else {
        return Ok(None);
    };
    let mode = match entry.status {
        EntryStatus::Removed => return Ok(None),
        EntryStatus::Blob => Mode::Regular,
        EntryStatus::Executable => Mode::Executable,
        EntryStatus::Symlink | EntryStatus::Tree => {
            return Err(Error::NotRegular(path.to_owned()));
        }
    };
    let data = worktree::read_blob(store, &entry.object_hash).map_err(|source| Error::Object {
        path: path.to_owned(),
        source,
    })?;
    Ok(Some((data, mode)))
}

fn remove_file(root: &Path, path: &str) -> Result<(), Error> {
    let io_err = |source| Error::Io {
        path: root.join(path),
        source,
    };
    let Some(abs) = worktree::path_under_real_dirs(root, path).map_err(io_err)? else {
        return Err(Error::NotRegular(path.to_owned()));
    };
    match fs::remove_file(&abs) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(source) => return Err(Error::Io { path: abs, source }),
    }
    // Remove the directories the file leaves empty, as git does.
    let mut dir = abs.parent();
    while let Some(d) = dir {
        if d == root || fs::remove_dir(d).is_err() {
            break;
        }
        dir = d.parent();
    }
    Ok(())
}

fn write_file(root: &Path, path: &str, content: &[u8], mode: Mode) -> Result<(), Error> {
    let abs = match worktree::path_for_write(root, path) {
        Ok(Some(abs)) => abs,
        Ok(None) => return Err(Error::NotRegular(path.to_owned())),
        Err(source) => {
            return Err(Error::Io {
                path: root.join(path),
                source,
            });
        }
    };
    let io_err = |p: &Path| {
        let p = p.to_path_buf();
        move |source| Error::Io { path: p, source }
    };
    if let Some(parent) = abs.parent() {
        fs::create_dir_all(parent).map_err(io_err(parent))?;
    }
    fs::write(&abs, content).map_err(io_err(&abs))?;
    set_mode(&abs, mode).map_err(io_err(&abs))
}

#[cfg(unix)]
fn set_mode(abs: &Path, mode: Mode) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perm = fs::metadata(abs)?.permissions();
    let bits = perm.mode();
    perm.set_mode(match mode {
        Mode::Executable => bits | ((bits & 0o444) >> 2),
        Mode::Regular => bits & !0o111,
    });
    fs::set_permissions(abs, perm)
}

#[cfg(not(unix))]
fn set_mode(_abs: &Path, _mode: Mode) -> io::Result<()> {
    Ok(())
}

fn stage(
    store: &ObjectStore,
    idx: &mut index::Index,
    path: &str,
    entry: Option<&(Vec<u8>, Mode)>,
) -> Result<(), Error> {
    let Some((content, mode)) = entry else {
        if let Some(n) = idx.find_entry(path) {
            idx.entries[n].status = EntryStatus::Removed;
            idx.entries[n].object_hash = ZERO;
        }
        return Ok(());
    };
    let hash = worktree::store_file_object(store, content).map_err(|source| Error::Object {
        path: path.to_owned(),
        source,
    })?;
    let status = match mode {
        Mode::Regular => EntryStatus::Blob,
        Mode::Executable => EntryStatus::Executable,
    };
    idx.remove_path(path);
    idx.upsert_entry(IndexEntry {
        path: path.to_owned(),
        status,
        object_hash: hash,
        mtime_ns: 0,
        size: 0,
        ino: 0,
        ctime_ns: 0,
    });
    Ok(())
}

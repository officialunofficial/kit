//! Cloning: create a repository whose config names a remote, then pull.

use std::io::Write as _;
use std::path::Path;

use kit_core::layout::{DiscoverError, RepoLayout};
use kit_core::refs::{self, RefError};
use kit_core::store::{ObjectStore, StoreError};

use crate::SyncOptions;
use crate::error::SyncError;
use crate::observer::{Observer, SyncEvent};
use crate::pull::{PullReport, pull};
use crate::source::RemoteSource;

pub use kit_core::{DEFAULT_BRANCH, DEFAULT_REMOTE_NAME};

/// The remote a clone records in the new repository's config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloneRemote {
    /// The remote's name. [`DEFAULT_REMOTE_NAME`] selects the flat
    /// `remote_endpoint` / `remote_type` keys; any other name becomes a
    /// `remote.<name>.url` / `.type` entry. The caller validates the name and
    /// the URL (no control characters, a legal ref name).
    pub name: String,
    pub url: String,
    /// The transport kind (`file`, `http`, `s3`, `ssh`, ...), empty if unknown.
    pub kind: String,
}

/// Why preparing the clone destination failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CloneInitError {
    #[error("create {path}: {source}")]
    CreateDir {
        path: String,
        source: std::io::Error,
    },
    #[error("worktree discovery: {0}")]
    Discover(#[from] DiscoverError),
    /// `dir` holds a repository that is not an unfinished clone of the same
    /// remote.
    #[error("already a kit repository")]
    AlreadyInitialized,
    /// The remote name, URL or kind cannot be written to the config safely.
    #[error("invalid remote: {0}")]
    InvalidRemote(String),
    #[error("init: {0}")]
    Store(StoreError),
    #[error("refs init: {0}")]
    Refs(RefError),
    #[error("write config: I/O: {0}")]
    WriteConfig(std::io::Error),
}

/// Create `dir`, initialise an empty repository in it and write its config
/// with `remote` recorded. Nothing is fetched. A failure leaves whatever was
/// created so far in place, exactly like a failed `git clone`.
///
/// When `dir` holds an unfinished clone of the same remote (only a
/// repository directory with what a clone writes before it makes a branch
/// or lands `HEAD`, this remote's config byte for byte, its tracking refs
/// and fetched tags), its layout is returned with its objects and its
/// record of applied packs kept, so the pull that follows resumes that clone
/// without downloading those packs again. Everything else an earlier run
/// published or recorded is dropped: its remote-tracking refs, tags, records of
/// verified tips, its fetch checkpoints and cursor records, and the history of
/// a branch it made and undid. A clone builds its trust from nothing, so the
/// resumed pull checks every closure and history in full, locally, and
/// republishes each branch it lists. When they
/// cannot be dropped, the directory is refused as
/// [`CloneInitError::AlreadyInitialized`], as is a clone another process is
/// still running into `dir`.
pub fn init_clone_dir(dir: &Path, remote: &CloneRemote) -> Result<RepoLayout, CloneInitError> {
    validate_remote(remote)?;
    if unfinished_clone(dir, remote).is_some() {
        return restart(dir, remote).ok_or(CloneInitError::AlreadyInitialized);
    }
    std::fs::create_dir_all(dir).map_err(|source| CloneInitError::CreateDir {
        path: dir.display().to_string(),
        source,
    })?;
    let layout = kit_core::layout::discover(dir)?;
    match ObjectStore::init(&layout) {
        Ok(_) => {}
        Err(StoreError::AlreadyInitialized) => return Err(CloneInitError::AlreadyInitialized),
        Err(e) => return Err(CloneInitError::Store(e)),
    }
    refs::init(&layout).map_err(CloneInitError::Refs)?;
    write_config(&layout, remote).map_err(CloneInitError::WriteConfig)?;
    Ok(layout)
}

/// What a clone writes before it makes a branch or lands `HEAD`,
/// lock files (`*.lock`) aside, and [`BRANCH_HISTORY_DIR`].
const UNFINISHED_CLONE_ENTRIES: [&str; 9] = [
    "HEAD",
    "applied-packs",
    "attestations",
    "config",
    "format",
    BRANCH_HISTORY_DIR,
    "objects",
    "refs",
    "tmp",
];

/// The branch history a build with history records writes beside a branch.
/// A clone interrupted once it made its branch undoes the branch but leaves
/// this; a restart drops it.
const BRANCH_HISTORY_DIR: &str = "history-v1";

/// The layout of `dir` when it holds a clone of `remote` that stopped before
/// it made a branch or landed `HEAD`, or undid both: `dir` holds only the repository
/// directory, which holds only what such a clone writes
/// ([`UNFINISHED_CLONE_ENTRIES`] and lock files), with the config a clone of `remote`
/// writes, byte for byte, the `HEAD` a new repository starts with, no branch,
/// fetched tags and remote-tracking refs of `remote` alone (a clone publishes each
/// branch's tracking ref as soon as that branch is in, before the next one
/// downloads).
///
/// Pulling into it is the same pull a fresh clone runs, and that pull is
/// safe to resume: a pack applied before the stop is not fetched again, and
/// the closure and history of each tip are checked before any ref is
/// published. A different remote, URL or name, or anything made or written
/// in the worktree, rules the directory out, so a resume never mixes two
/// remotes or overwrites work.
fn unfinished_clone(dir: &Path, remote: &CloneRemote) -> Option<RepoLayout> {
    let mut entries = std::fs::read_dir(dir).ok()?;
    let only = entries.next()?.ok()?;
    if entries.next().is_some()
        || only.file_name() != kit_core::store::KIT_DIR
        || !only.file_type().ok()?.is_dir()
    {
        return None;
    }
    let kit = only.path();
    for entry in std::fs::read_dir(&kit).ok()? {
        let entry = entry.ok()?;
        let name = entry.file_name();
        let lock = Path::new(&name)
            .extension()
            .is_some_and(|ext| ext == "lock")
            && entry.file_type().ok()?.is_file();
        if !lock && !UNFINISHED_CLONE_ENTRIES.iter().any(|known| name == *known) {
            return None;
        }
    }
    if std::fs::read(kit.join("HEAD")).ok()? != b"ref: refs/heads/main\n" {
        return None;
    }
    let layout = kit_core::layout::discover(dir).ok()?;
    if std::fs::read(layout.config_file()).ok()? != render_config(remote).as_bytes() {
        return None;
    }
    let unpublished = refs::resolve_head(&layout).ok()?.is_none()
        && only_clone_refs(&kit.join("refs"), &remote.name)?;
    unpublished.then_some(layout)
}

/// Whether everything under `refs` is a directory or a regular file, with
/// every file a remote-tracking ref of `remote` or a fetched tag. A link,
/// or a file anywhere else, is something a clone did not write.
fn only_clone_refs(refs: &Path, remote: &str) -> Option<bool> {
    let tracking = refs.join("remotes").join(remote);
    let tags = refs.join("tags");
    let mut dirs = vec![refs.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).ok()? {
            let entry = entry.ok()?;
            let kind = entry.file_type().ok()?;
            if kind.is_dir() {
                dirs.push(entry.path());
            } else if !kind.is_file()
                || !(entry.path().starts_with(&tracking) || entry.path().starts_with(&tags))
            {
                return Some(false);
            }
        }
    }
    Some(true)
}

/// Drop what an earlier run of a clone of `remote` into `dir` published or
/// recorded, its objects and its record of applied packs aside (see
/// [`init_clone_dir`]), and return its layout. `None` when another process
/// is still writing it, when it no longer is an unfinished clone, or when
/// something cannot be dropped.
fn restart(dir: &Path, remote: &CloneRemote) -> Option<RepoLayout> {
    // A clone still running here holds the store's shared lock while it
    // fetches (see `ObjectStore::prune_guard`). Taking the exclusive one
    // proves none is, keeps one from starting meanwhile, and the directory
    // is checked again under it.
    let format = std::fs::File::open(dir.join(kit_core::store::KIT_DIR).join("format")).ok()?;
    format.try_lock().ok()?;
    let layout = unfinished_clone(dir, remote)?;
    let tracking = dir
        .join(kit_core::store::KIT_DIR)
        .join("refs")
        .join("remotes")
        .join(&remote.name);
    crate::anchor::remove_dir_if_present(&tracking).ok()?;
    crate::anchor::remove_dir_if_present(&dir.join(kit_core::store::KIT_DIR).join("refs/tags"))
        .ok()?;
    crate::anchor::remove_dir_if_present(
        &dir.join(kit_core::store::KIT_DIR).join(BRANCH_HISTORY_DIR),
    )
    .ok()?;
    crate::anchor::forget_all(&layout).ok()?;
    crate::checkpoint::forget_all(&layout).ok()?;
    crate::cursor::forget_all(&layout).ok()?;
    Some(layout)
}

/// Refuse values that would corrupt or inject into the config file, before
/// anything is created. The config is `key = value` lines written raw, so a
/// control character in any value would add lines of the caller's choosing.
fn validate_remote(remote: &CloneRemote) -> Result<(), CloneInitError> {
    let invalid = |what: &str| Err(CloneInitError::InvalidRemote(what.to_owned()));
    for (what, value) in [
        ("name", &remote.name),
        ("url", &remote.url),
        ("kind", &remote.kind),
    ] {
        if value.chars().any(char::is_control) {
            return invalid(&format!("{what} contains control characters"));
        }
    }
    if remote.name != DEFAULT_REMOTE_NAME
        && (!refs::validate_ref_name(&remote.name) || remote.name.contains('.'))
    {
        return invalid("name must be `default` or a dot-free ref-safe name");
    }
    Ok(())
}

/// Render the repository config a clone writes.
fn render_config(remote: &CloneRemote) -> String {
    use std::fmt::Write as _;
    let (url_key, kind_key) = if remote.name == DEFAULT_REMOTE_NAME {
        ("remote_endpoint".to_owned(), "remote_type".to_owned())
    } else {
        (
            format!("remote.{}.url", remote.name),
            format!("remote.{}.type", remote.name),
        )
    };
    let mut out = format!("default_branch = {DEFAULT_BRANCH}\n");
    if !remote.url.is_empty() {
        let _ = writeln!(out, "{url_key} = {}", remote.url);
    }
    if !remote.kind.is_empty() {
        let _ = writeln!(out, "{kind_key} = {}", remote.kind);
    }
    out
}

/// Atomic replace: write a sibling temp file then rename over the target, so
/// a crash mid-write can never leave a truncated config.
fn write_config(layout: &RepoLayout, remote: &CloneRemote) -> std::io::Result<()> {
    let path = layout.config_file();
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let mut tmp = tempfile::Builder::new()
        .prefix(".config.")
        .tempfile_in(parent)?;
    tmp.write_all(render_config(remote).as_bytes())?;
    tmp.flush()?;
    tmp.persist(&path).map_err(|e| e.error)?;
    Ok(())
}

/// What a clone did.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CloneReport {
    pub layout_root: std::path::PathBuf,
    pub pull: PullReport,
}

/// Why a clone failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CloneError {
    #[error(transparent)]
    Init(#[from] CloneInitError),
    #[error(transparent)]
    Sync(#[from] SyncError),
}

/// Initialise `dir` and pull the remote into it: [`init_clone_dir`] followed
/// by [`pull`], with the new remote's name as the tracking namespace.
pub fn clone(
    dir: &Path,
    source: &dyn RemoteSource,
    remote: &CloneRemote,
    options: &SyncOptions,
    observer: &dyn Observer<SyncEvent>,
) -> Result<CloneReport, CloneError> {
    let layout = init_clone_dir(dir, remote)?;
    let mut options = options.clone();
    options.remote_url.clone_from(&remote.url);
    let report = pull(dir, source, &remote.name, &options, observer)?;
    Ok(CloneReport {
        layout_root: layout.worktree_root().to_path_buf(),
        pull: report,
    })
}

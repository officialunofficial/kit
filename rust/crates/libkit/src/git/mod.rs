//! The git bridge: export to a git mirror, import of a git upstream, audit of
//! the bridge state and patch series for `git am`.
//!
//! The bridge keeps one state directory for each remote name under the git
//! state directory of the repository. The state directory holds a bare staging
//! repository, the map of git ids to kit hashes, the recorded refs and the
//! bindings that tie the directory to one direction and one remote. Each
//! operation that writes the state takes the `git-<name>.lock` lock for its
//! whole run.
//!
//! - [`export`] translates branches and tags into the staging repository,
//!   mints one attestation for each exported head and pushes the result to the
//!   mirror with a lease on each ref.
//! - [`import`] translates a git upstream into signed kit objects under a
//!   dedicated import key. [`import::fetch`] refreshes the tracking refs, and
//!   with its `pull` flag it fast-forwards the current branch.
//! - [`verify`] checks the state directory against the object store.
//! - [`state`] lists the state directories.
//! - [`patch`] turns native commits into patches that `git am` applies.
//!
//! A function in this module never prints. Notices go to an [`Observer`] as
//! [`Event`] values.
//!
//! [`Observer`]: kit_core::observer::Observer

pub mod export;
pub mod import;
pub mod patch;
pub mod state;
pub mod verify;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use kit_core::layout::{self, DiscoverError, RepoLayout};
use kit_core::repo_lock::LockError;
use kit_core::store::{ObjectStore, StoreError};

use crate::lock;

/// How a failed step counts for the caller. A command maps each class to an
/// exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Class {
    /// The arguments, or the recorded bindings, contradict the request.
    Usage,
    /// The data on disk, or the data in the request, is malformed.
    Data,
    /// An input is missing.
    NoInput,
    /// A required program or remote cannot be reached.
    Unavailable,
    /// A file or directory cannot be created.
    CannotCreate,
    /// The configuration is wrong.
    Config,
    /// Another process holds a lock. A retry can work.
    TempFail,
    /// Anything else.
    General,
}

/// Errors from a git bridge operation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A step failed. `context` names the step. It can be empty.
    #[error("{}", step_text(.context, .message))]
    Step {
        /// The class of the failure.
        class: Class,
        /// What the operation was doing.
        context: String,
        /// Why it failed.
        message: String,
    },
    /// The `git` program cannot run.
    #[error("{0}")]
    GitUnavailable(String),
    /// The object store of a repository cannot be opened for an export or an
    /// import.
    #[error("open repository: {0}")]
    OpenRepository(StoreError),
    /// The location of a git remote is empty.
    #[error("empty git URL or path")]
    EmptyUrl,
    /// The location of a git remote has the shape of an option.
    #[error("{0:?} is not a valid git URL or path")]
    InvalidUrl(String),
    /// A worktree discovery failed.
    #[error("worktree discovery: {0}")]
    Discover(DiscoverError),
    /// The directory is not a kit repository.
    #[error("not a kit repository")]
    NotARepository,
    /// Another bridge operation holds the state directory.
    #[error("bridge state '{name}' is busy (another kit git operation?): {source}")]
    StateBusy {
        /// The remote name of the state directory.
        name: String,
        /// Why the lock failed.
        source: LockError,
    },
    /// The worktree lock is held, so the branch cannot move.
    #[error("worktree is busy (another kit command?)")]
    WorktreeBusy(lock::Error),
    /// The destination of an export is the recorded source of an import.
    #[error(
        "{dest} is a recorded git-import source (state '{state}'); export toward an imported-from upstream would replace its history with a disconnected re-translation. Passthrough export through that state (`--passthrough --remote-name {state}`) is the supported path (SPEC-GIT-BRIDGE §14.2)"
    )]
    ImportSource {
        /// The destination.
        dest: String,
        /// The state that imported from it.
        state: String,
    },
    /// A passthrough export needs the import state of its remote name.
    #[error(
        "--passthrough requires import state for '{remote}' — run `kit git import <url>` first (SPEC-GIT-BRIDGE §14.1)"
    )]
    PassthroughNeedsImport {
        /// The remote name.
        remote: String,
    },
    /// The state has trees with normalized modes, so a fork cannot reproduce
    /// their ids.
    #[error(
        "state '{remote}' contains historic-mode-normalized trees; fork mode cannot reproduce their original sha1s (SPEC-GIT-IMPORT §3.3). Re-import under a new --remote-name to get fork-strict refusals"
    )]
    PassthroughNormalized {
        /// The remote name.
        remote: String,
    },
    /// The state directory is bound to another direction.
    #[error(
        "state dir is bound to direction '{direction}'; 'export' is not allowed here (one direction per state dir — use a different --remote-name)"
    )]
    DirectionBound {
        /// The recorded direction.
        direction: &'static str,
    },
    /// The state directory is bound to another remote.
    #[error("state '{name}' is bound to {recorded}; use a different --remote-name for {target}")]
    StateBound {
        /// The remote name of the state directory.
        name: String,
        /// The remote that the state is bound to.
        recorded: String,
        /// The remote of the request.
        target: String,
    },
    /// The upstream is imported under another state already.
    #[error(
        "{url} is already imported as state '{other}'; use `--remote-name {other}` instead of creating a duplicate import (SPEC-GIT-IMPORT §6.1)"
    )]
    DuplicateImport {
        /// The upstream of the request.
        url: String,
        /// The state that holds it.
        other: String,
    },
    /// A `--ref` name is not a full branch or tag name.
    #[error("--ref {0}: expected refs/heads/... or refs/tags/...")]
    BadRefName(String),
    /// A `--ref` name does not exist.
    #[error("--ref {0}: not found")]
    RefNotFound(String),
    /// The repository has no branch and no tag to export.
    #[error("nothing to export: no branches or tags")]
    NothingToExport,
    /// The export skipped every ref.
    #[error("every requested ref was skipped ({} refusals)", .skipped.len())]
    AllRefsSkipped {
        /// Each skipped ref with the reason.
        skipped: Vec<Skipped>,
    },
    /// A fork export would move a tag that the mirror has already.
    #[error(
        "{name} already exists on {dest} at a different object; fork-mode export never moves an existing tag"
    )]
    TagExists {
        /// The tag.
        name: String,
        /// The destination.
        dest: String,
    },
    /// A fork export would not fast-forward a ref of the mirror.
    #[error(
        "{name} on {dest} has commits this repo has not integrated; run `kit git fetch` and `kit merge {remote}/{branch}` first (fork-mode export refuses non-fast-forward pushes)"
    )]
    NotFastForward {
        /// The ref of the mirror.
        name: String,
        /// The destination.
        dest: String,
        /// The remote name of the state directory.
        remote: String,
        /// The branch name that the advice names.
        branch: String,
    },
    /// A pull would not fast-forward the current branch.
    #[error(
        "pull would not fast-forward branch '{branch}'; integrate with `kit merge {remote}/{branch}` (or `kit rebase {remote}/{branch}`)"
    )]
    PullNotFastForward {
        /// The current branch.
        branch: String,
        /// The remote name.
        remote: String,
    },
    /// The upstream is already imported under another key.
    #[error(
        "this upstream is already imported here under key {key}…; pull from the designated importer over kit transport, or install that key (SPEC-GIT-IMPORT §4/§6.1)"
    )]
    OtherImporter {
        /// The first 16 hex digits of the other key.
        key: String,
    },
    /// The signer for the attestations of an export cannot be built.
    #[error("{0}")]
    Signer(SignerError),
    /// The directory of the fresh clone exists and is not empty.
    #[error("destination '{0}' already exists")]
    DestinationExists(String),
    /// The remote name has no import state.
    #[error("no import state for '{0}' — run `kit git import <url>` first")]
    NoImportState(String),
    /// The range of a patch series names an object that is not a commit.
    #[error("{0}: not a commit")]
    RangeNotACommit(String),
    /// A patch series changes binary content.
    #[error(
        "{path}: binary change in commit {commit} — format-patch emits text patches only; use `kit git export` for binary content"
    )]
    BinaryChange {
        /// The path.
        path: String,
        /// The first 12 hex digits of the commit.
        commit: String,
    },
    /// The history of a patch series has a cycle.
    #[error("commit graph cycle (corrupt store?)")]
    CommitCycle,
}

/// A reason a signer cannot be built. The caller of an export gives it.
pub type SignerError = Box<dyn std::error::Error + Send + Sync>;

/// A ref that an operation skipped, with the reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// The ref name.
    pub ref_name: String,
    /// Why the ref was skipped.
    pub reason: String,
}

/// What an operation reports to its [`Observer`](kit_core::observer::Observer).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// A ref was skipped. The operation went on with the other refs.
    RefSkipped {
        /// The ref name.
        ref_name: String,
        /// Why it was skipped.
        reason: String,
    },
    /// An import signs with an existing key.
    SigningKey {
        /// The first 16 hex digits of the public key.
        key_prefix: String,
        /// The key file.
        path: PathBuf,
    },
    /// An import made a new import key.
    KeyGenerated {
        /// The key file.
        path: PathBuf,
    },
    /// An earlier import did not finish. The import rebuilds the map.
    ImportInterrupted,
    /// The map of the state is missing or damaged. The import rebuilds it.
    MapRebuilt,
    /// The upstream replaced the history of a branch.
    UpstreamForcePushed {
        /// The upstream ref.
        ref_name: String,
    },
    /// A tag moved locally, so the import kept it.
    TagKeptLocal {
        /// The tag name.
        tag: String,
    },
    /// The upstream deleted a branch, so the tracking ref went too.
    TrackingRefRemoved {
        /// The upstream ref.
        ref_name: String,
        /// The remote name.
        remote: String,
        /// The branch name.
        branch: String,
    },
    /// An event of a repository lock.
    Lock(lock::Event),
}

/// Escape `text` for a JSON string in a predicate.
pub(crate) fn json_escape(text: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(text.len() + 2);
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

fn step_text(context: &str, message: &str) -> String {
    if context.is_empty() {
        message.to_owned()
    } else {
        format!("{context}: {message}")
    }
}

/// Build a [`Error::Step`] from a failure.
pub(crate) fn step(
    class: Class,
    context: impl Into<String>,
    cause: impl std::fmt::Display,
) -> Error {
    Error::Step {
        class,
        context: context.into(),
        message: cause.to_string(),
    }
}

/// Build a [`Error::Step`] with no context.
pub(crate) fn plain(class: Class, cause: impl std::fmt::Display) -> Error {
    step(class, "", cause)
}

/// Forwards the events of a lock helper to an observer of bridge events.
pub(crate) struct LockEvents<'a>(pub(crate) &'a dyn kit_core::observer::Observer<Event>);

impl kit_core::observer::Observer<lock::Event> for LockEvents<'_> {
    fn event(&self, event: &lock::Event) {
        self.0.event(&Event::Lock(event.clone()));
    }
}

/// Take the lock of one bridge state directory.
pub(crate) fn lock_state(
    layout: &RepoLayout,
    remote_name: &str,
) -> Result<kit_core::repo_lock::RepoLock, Error> {
    kit_core::repo_lock::acquire_default(layout.common_dir(), &format!("git-{remote_name}.lock"))
        .map_err(|source| Error::StateBusy {
            name: remote_name.to_owned(),
            source,
        })
}

/// Refuse a location that cannot be a git remote.
///
/// An option-shaped location must never reach the argument list of `git`. An
/// empty one would make `git` work on the current directory.
///
/// # Errors
/// [`Error::EmptyUrl`] for an empty location. [`Error::InvalidUrl`] for a
/// location that starts with `-`.
pub fn validate_url(url: &str) -> Result<(), Error> {
    if url.trim().is_empty() {
        return Err(Error::EmptyUrl);
    }
    if url.starts_with('-') {
        return Err(Error::InvalidUrl(url.to_owned()));
    }
    Ok(())
}

/// Check that `git` runs.
pub(crate) fn git_version() -> Result<(), Error> {
    let mut command = Command::new("git");
    kit_git_bridge::gitsrc::apply_hygiene(&mut command);
    match command
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(Error::GitUnavailable(format!(
            "`git --version` exited with {status}"
        ))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(Error::GitUnavailable(
            "`git` not found on PATH; kit git export shells out to it".to_owned(),
        )),
        Err(e) => Err(Error::GitUnavailable(format!("spawn git: {e}"))),
    }
}

/// Run `git` in `dir` and return its standard output.
pub(crate) fn git_in(dir: &Path, args: &[&str]) -> Result<String, String> {
    let out = kit_git_bridge::gitsrc::git_command(dir)
        .args(args)
        .output()
        .map_err(|e| format!("spawn git: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(format!(
            "git {} failed: {}",
            args.first().copied().unwrap_or(""),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Discover the layout at `cwd` and open its object store.
pub(crate) fn open_repo(cwd: &Path) -> Result<(RepoLayout, ObjectStore), Error> {
    let layout = layout::discover(cwd).map_err(Error::Discover)?;
    if !layout.common_dir().is_dir() {
        return Err(Error::NotARepository);
    }
    let store = ObjectStore::open(&layout).map_err(|e| step(Class::NoInput, "open store", e))?;
    Ok((layout, store))
}

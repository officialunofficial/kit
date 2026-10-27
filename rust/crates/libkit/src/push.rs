//! Push planning: which branch goes to which remote, and the upstream that a
//! first push records.
//!
//! The transfer itself is the job of `kit-sync`. This module decides what to
//! send and where. [`plan`] resolves the current branch to a remote and a
//! remote branch. [`plan_all`] resolves the remote of a mirror push. Both read
//! the tips that they report, and neither contacts the remote.
//!
//! The lease of a push is the policy for the compare-and-swap on the remote
//! ref. [`lease`] turns the two force switches into a [`PushLease`].

use kit_core::hash::Hash;
use kit_core::layout::RepoLayout;
use kit_core::observer::Observer;
use kit_core::ops::merge::is_ancestor;
use kit_core::refs::{self, Head, RefError};
use kit_core::store::{ObjectStore, StoreError};
pub use kit_sync::PushLease;

use crate::Environment;
use crate::config::{
    self, ConfigError, ConfigEvent, DEFAULT_REMOTE_NAME, LayeredConfig, ResolvedRemote, Upstream,
};

/// Errors from push planning.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Both force switches are set.
    #[error("--force and --force-with-lease are mutually exclusive")]
    ConflictingForce,
    /// `HEAD` is detached, so no branch can go.
    #[error("cannot push a detached HEAD; check out a branch first")]
    DetachedHead,
    /// `HEAD` cannot be read.
    #[error("read HEAD: {0}")]
    ReadHead(RefError),
    /// The branch has no upstream and the config has no default remote.
    #[error(
        "no upstream configured for branch '{0}' and no default remote; run `kit push <remote>` to push it (the upstream will be remembered)"
    )]
    NoUpstream(String),
    /// The named remote is not configured.
    #[error("unknown remote '{0}' — add it with `kit remote add {0} <url>`")]
    UnknownRemote(String),
    /// A mirror push finds no remote.
    #[error("no remote configured — use `kit remote add <url>`")]
    NoRemote,
    /// The ancestry of two commits cannot be found.
    #[error("ancestry: {0}")]
    Ancestry(StoreError),
    /// The upstream cannot be written to the config.
    #[error("write: {0}")]
    RecordUpstream(ConfigError),
}

/// What a push of the current branch would do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// The local branch.
    pub branch: String,
    /// The remote that receives it.
    pub remote: ResolvedRemote,
    /// The branch name on the remote.
    pub remote_branch: String,
    /// The tip of the local branch, when it has one.
    pub local_tip: Option<Hash>,
    /// The tip that the remote-tracking ref holds. It is the last tip that
    /// this repository saw on the remote, and the lease of the push.
    pub tracked: Option<Hash>,
}

impl Plan {
    /// True when the remote-tracking ref holds the local tip already, and the
    /// push does not force. A forced push always runs.
    #[must_use]
    pub fn is_up_to_date(&self, force: bool) -> bool {
        !force && self.local_tip.is_some() && self.local_tip == self.tracked
    }
}

/// The lease for the two force switches.
///
/// # Errors
/// [`Error::ConflictingForce`] when both are set.
pub fn lease(force: bool, force_with_lease: bool) -> Result<PushLease, Error> {
    match (force, force_with_lease) {
        (true, true) => Err(Error::ConflictingForce),
        (true, false) => Ok(PushLease::Force),
        (false, true) => Ok(PushLease::WithLease),
        (false, false) => Ok(PushLease::FastForward),
    }
}

/// Plan the push of the current branch.
///
/// A named `remote` receives the branch under its own name. With no `remote`,
/// the upstream of the branch decides, as [`config::resolve_upstream`] reads
/// it.
///
/// # Errors
/// [`Error::DetachedHead`] or [`Error::ReadHead`] when `HEAD` names no
/// branch. [`Error::NoUpstream`] when no remote is known for the branch.
/// [`Error::UnknownRemote`] when the remote is not configured.
pub fn plan(layout: &RepoLayout, cfg: &LayeredConfig, remote: Option<&str>) -> Result<Plan, Error> {
    let branch = match refs::read_head(layout) {
        Ok(Head::Branch(branch)) => branch,
        Ok(Head::Detached(_)) => return Err(Error::DetachedHead),
        Err(e) => return Err(Error::ReadHead(e)),
    };
    let (remote_name, remote_branch) = match remote {
        Some(name) => (name.to_owned(), branch.clone()),
        None => match config::resolve_upstream(cfg, &branch) {
            Some(Upstream { remote, branch }) => (remote, branch),
            None => return Err(Error::NoUpstream(branch)),
        },
    };
    let resolved =
        config::resolve_remote(cfg, &remote_name).ok_or(Error::UnknownRemote(remote_name))?;
    let local_tip = refs::read_ref(layout, &branch).ok().flatten();
    let tracked = refs::read_remote_ref(layout, &resolved.name, &remote_branch)
        .ok()
        .flatten();
    Ok(Plan {
        branch,
        remote: resolved,
        remote_branch,
        local_tip,
        tracked,
    })
}

/// Resolve the remote of a mirror push. With no `remote`, the default remote
/// receives it.
///
/// # Errors
/// [`Error::NoRemote`] when the remote is not configured.
pub fn plan_all(cfg: &LayeredConfig, remote: Option<&str>) -> Result<ResolvedRemote, Error> {
    config::resolve_remote(cfg, remote.unwrap_or(DEFAULT_REMOTE_NAME)).ok_or(Error::NoRemote)
}

/// True when moving a ref from `old` to `new` is a fast-forward. A ref that
/// did not exist and a ref that does not change both count.
///
/// # Errors
/// [`Error::Ancestry`] when the store cannot be opened or walked.
pub fn is_fast_forward(layout: &RepoLayout, old: Option<Hash>, new: Hash) -> Result<bool, Error> {
    match old {
        None => Ok(true),
        Some(old) if old == new => Ok(true),
        Some(old) => {
            let store = ObjectStore::open(layout).map_err(Error::Ancestry)?;
            is_ancestor(&store, old, new).map_err(Error::Ancestry)
        }
    }
}

/// Record `branch.<branch>.{remote,merge}` after a successful push, so a bare
/// push finds the upstream next time.
///
/// With `replace` unset, the call keeps an upstream that is set already, so
/// only the first push records one. With `replace` set, it points the
/// upstream at `upstream`. The call reads the repo layer of the config again
/// and changes that layer only, so a user-scoped value never reaches
/// `.kit/config`, and a change made during a long push is kept.
///
/// # Errors
/// [`Error::RecordUpstream`] when the config cannot be read or written. The
/// push has succeeded by then, so a caller can report the failure and go on.
pub fn record_upstream(
    layout: &RepoLayout,
    cfg: &LayeredConfig,
    environment: &Environment,
    observer: &dyn Observer<ConfigEvent>,
    branch: &str,
    upstream: Upstream,
    replace: bool,
) -> Result<(), Error> {
    if !replace
        && cfg
            .merged
            .branch_upstreams
            .get(branch)
            .is_some_and(|set| !set.remote.is_empty())
    {
        return Ok(());
    }
    let mut repo = config::read_layered(layout, environment, observer)
        .map_err(Error::RecordUpstream)?
        .repo;
    repo.branch_upstreams.insert(branch.to_owned(), upstream);
    config::write(layout, &repo).map_err(Error::RecordUpstream)
}

//! The transfer of history to and from a remote.
//!
//! `kit-sync` runs the engine: the pack building, the pack map, the checks of
//! signatures and the moves of refs. This module is the layer that a program
//! calls. It turns the failures of the engine into one [`Error`], it names
//! the failures of a Connect client that mean "stopped by the user", and it
//! takes every setting as an argument. It never reads the config or the
//! process state.
//!
//! The `*_with_source` operations take a [`RemoteSource`] and an observer. The
//! other operations take a [`Transport`] and report nothing. Both kinds run
//! the same engine.

pub mod envelope;
mod error;
mod open;
mod trust;

use std::path::Path;

use kit_core::hash::Hash;
use kit_core::observer::{NoopObserver, Observer};
use kit_core::pack;
use kit_core::protocol::Transport;
use kit_core::refs::RefWriteCondition;
use kit_core::store::{ObjectStore, SyncPolicy};
use kit_sync::{
    PushLease, PushOptions, PushTarget, RemoteSource, SourceError, SyncError, SyncEvent,
    SyncOptions, TransportSource,
};
use kit_transport_connect::PENDING_INTERRUPTED_MESSAGE;

pub use error::{Error, PublishedPrefix};
pub use kit_sync::push::{PushControl, RetryReason, StepAuthority};
pub use open::{Remote, Scheme, is_connect_url, open, scheme, validate_connect_repository};
pub use trust::check_endpoint;

/// The chain depth at which a push re-baselines the pack chain of the branch
/// into one node that lists every pack of the chain. A push appends one node
/// otherwise. A push and a fresh clone read every node, so their cost grows
/// with the depth. Zero turns the re-baseline off.
pub const DEFAULT_REBASELINE_DEPTH: usize = 64;

/// What a successful push published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pushed {
    /// Branches pushed.
    pub refs: usize,
    /// Advances published in total. A push makes one advance for each branch
    /// unless it was split.
    pub steps: usize,
}

/// The settings of a push that do not come from the repository.
#[derive(Clone, Copy)]
pub struct PushSettings<'a> {
    /// The durability schedule of the object store.
    pub sync_policy: SyncPolicy,
    /// The chain depth at which the push re-baselines the pack chain. Zero
    /// turns the re-baseline off.
    pub rebaseline_threshold: usize,
    /// The check that the stored grants cover every advance of a split push.
    pub authority: Option<&'a dyn StepAuthority>,
}

impl std::fmt::Debug for PushSettings<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PushSettings")
            .field("sync_policy", &self.sync_policy)
            .field("rebaseline_threshold", &self.rebaseline_threshold)
            .field("authority", &self.authority.map(|_| "<hook>"))
            .finish()
    }
}

impl Default for PushSettings<'_> {
    fn default() -> Self {
        Self {
            sync_policy: SyncPolicy::Batch,
            rebaseline_threshold: DEFAULT_REBASELINE_DEPTH,
            authority: None,
        }
    }
}

impl<'a> PushSettings<'a> {
    fn options(&self, observer: &'a dyn Observer<SyncEvent>) -> PushOptions<'a> {
        let mut options = PushOptions::default();
        options.sync_policy = self.sync_policy;
        options.rebaseline_threshold = self.rebaseline_threshold;
        options.control.authority = self.authority;
        options.control.observer = observer;
        options
    }
}

/// Recognise the two interruption messages of the Connect client on a call
/// about a repository. Every other failure falls through to the default
/// classification.
fn classify_repository_error(error: &SourceError) -> Option<SyncError> {
    if let SourceError::RemoteError(message) = error {
        if message.starts_with("upload interrupted; ") {
            return Some(SyncError::UploadInterrupted(message.clone()));
        }
        if message == PENDING_INTERRUPTED_MESSAGE {
            return Some(SyncError::Interrupted);
        }
    }
    None
}

/// The view of `transport` that the sync engine uses. It classifies the two
/// interruption messages of the Connect client.
#[must_use]
pub fn source(transport: &dyn Transport) -> TransportSource<'_> {
    TransportSource::new(transport).with_error_classifier(&classify_repository_error)
}

/// Push every branch to the remote, with the tracking refs of `remote` as the
/// lease. `force` turns every write into an unconditional write. Each pushed
/// branch moves its tracking ref to the pushed tip, and a split branch moves
/// it after every published advance.
///
/// # Errors
/// The push fails. [`Error::into_published_prefix`] reports the advances that
/// a split push published before it failed.
pub fn push_all_with_source(
    cwd: &Path,
    source: &dyn RemoteSource,
    remote: &str,
    force: bool,
    settings: &PushSettings<'_>,
    observer: &dyn Observer<SyncEvent>,
) -> Result<Pushed, Error> {
    let mut options = settings.options(observer);
    options.remote_name = remote;
    options.target = PushTarget::All { force };
    let report = kit_sync::push(cwd, source, &options)?;
    Ok(Pushed {
        refs: report.refs,
        steps: report.steps,
    })
}

/// Push the local branch `branch` to `remote_branch` on the remote. On
/// success the tracking ref `refs/remotes/<remote>/<remote_branch>` follows
/// every published advance. Returns the pushed tip and the number of
/// advances. It is more than one when the push was split along the first-parent
/// history.
///
/// # Errors
/// As [`push_all_with_source`].
#[allow(clippy::too_many_arguments)] // one value for each part of the branch mapping and the lease
pub fn push_branch_tracked_with_source(
    cwd: &Path,
    source: &dyn RemoteSource,
    remote: &str,
    branch: &str,
    remote_branch: &str,
    lease: PushLease,
    settings: &PushSettings<'_>,
    observer: &dyn Observer<SyncEvent>,
) -> Result<(Hash, usize), Error> {
    let mut options = settings.options(observer);
    options.remote_name = remote;
    options.target = PushTarget::Branch {
        local: branch.into(),
        remote: remote_branch.into(),
        lease,
    };
    let report = kit_sync::push(cwd, source, &options)?;
    Ok((report.tip.ok_or(Error::NotCommit)?, report.steps))
}

/// Fetch the refs of `remote`, then fast-forward the current branch from its
/// tracking ref. Returns the number of branches fetched.
///
/// `require_signed` checks the signature of every new commit, remix and tag,
/// and fails closed. Only an explicit opt-out of the caller turns it off.
///
/// # Errors
/// The fetch or the fast-forward fails.
pub fn pull_with_source(
    cwd: &Path,
    source: &dyn RemoteSource,
    remote: &str,
    target_branch: Option<&str>,
    require_signed: bool,
    sync_policy: SyncPolicy,
    observer: &dyn Observer<SyncEvent>,
) -> Result<usize, Error> {
    let options = sync_options(target_branch, require_signed, sync_policy);
    let report = kit_sync::pull(cwd, source, remote, &options, observer)?;
    Ok(report.fetch.branches_fetched)
}

/// [`pull_with_source`] without the move of `HEAD`. It downloads every object
/// that each remote ref reaches, and writes the ref to
/// `refs/remotes/<remote>/<branch>`. Returns the number of branches fetched.
///
/// With `prune`, the fetch then deletes the tracking refs whose branch the
/// remote no longer has.
///
/// # Errors
/// The fetch fails.
pub fn fetch_with_source(
    cwd: &Path,
    source: &dyn RemoteSource,
    remote: &str,
    require_signed: bool,
    prune: bool,
    sync_policy: SyncPolicy,
    observer: &dyn Observer<SyncEvent>,
) -> Result<usize, Error> {
    let options = sync_options(None, require_signed, sync_policy).with_prune(prune);
    let report = kit_sync::fetch(cwd, source, remote, &options, observer)?;
    Ok(report.branches_fetched)
}

fn sync_options(
    target_branch: Option<&str>,
    require_signed: bool,
    sync_policy: SyncPolicy,
) -> SyncOptions {
    SyncOptions::default()
        .with_verify_signatures(require_signed)
        .with_target_branch(target_branch.map(str::to_owned))
        .with_sync_policy(sync_policy)
}

/// Push every branch over `transport`. Returns the number of branches pushed.
/// It reports no progress and uses the default settings.
///
/// # Errors
/// As [`push_all_with_source`].
pub fn push_all(cwd: &Path, transport: &dyn Transport) -> Result<usize, Error> {
    push_all_with(cwd, transport, None, false, None).map(|pushed| pushed.refs)
}

/// [`push_all`] with a remote name for the tracking refs, a force switch and
/// the check of the stored grants. `None` for the remote names the remote
/// `default`.
///
/// # Errors
/// As [`push_all_with_source`].
pub fn push_all_with(
    cwd: &Path,
    transport: &dyn Transport,
    remote: Option<&str>,
    force: bool,
    authority: Option<&dyn StepAuthority>,
) -> Result<Pushed, Error> {
    push_all_with_source(
        cwd,
        &source(transport),
        remote.unwrap_or(kit_sync::DEFAULT_REMOTE_NAME),
        force,
        &PushSettings {
            authority,
            ..PushSettings::default()
        },
        &NoopObserver,
    )
}

/// Upload a branch over `transport` and move the branch ref on the remote. It
/// does not move a tracking ref.
///
/// # Errors
/// The push fails.
pub fn push_branch(
    transport: &dyn Transport,
    store: &ObjectStore,
    branch: &str,
    tip: Hash,
    condition: RefWriteCondition,
) -> Result<(), Error> {
    push_branch_with_depth(
        transport,
        store,
        branch,
        tip,
        condition,
        DEFAULT_REBASELINE_DEPTH,
    )
}

/// [`push_branch`] with a chain depth in place of the default.
///
/// # Errors
/// As [`push_branch`].
pub fn push_branch_with_depth(
    transport: &dyn Transport,
    store: &ObjectStore,
    branch: &str,
    tip: Hash,
    condition: RefWriteCondition,
    rebaseline_threshold: usize,
) -> Result<(), Error> {
    push_branch_with_limits(
        transport,
        store,
        branch,
        tip,
        condition,
        rebaseline_threshold,
        pack::MAX_TOTAL_PAYLOAD,
    )
}

/// [`push_branch_with_depth`] with a bound on the payload of one pack in place
/// of the bound of the format.
///
/// # Errors
/// As [`push_branch`].
pub fn push_branch_with_limits(
    transport: &dyn Transport,
    store: &ObjectStore,
    branch: &str,
    tip: Hash,
    condition: RefWriteCondition,
    rebaseline_threshold: usize,
    pack_payload_cap: u64,
) -> Result<(), Error> {
    push_branch_steps(
        transport,
        store,
        branch,
        tip,
        condition,
        rebaseline_threshold,
        pack_payload_cap,
        &PushControl::default(),
        &mut |_| Ok(()),
    )
    .map(drop)
}

/// [`push_branch_with_limits`] that splits a push too large for one advance
/// along the first-parent history of the branch. It reports each published
/// advance to `on_step` with the commit that the remote branch now holds.
/// Returns the number of advances.
///
/// The split applies when the transport uploads with tickets and the estimate
/// of the packs of the push exceeds the data-pack budget of one advance. The
/// first advance uses `condition`. Every later advance is a `Match` on the
/// commit of the advance before it, so a long split never overwrites a
/// concurrent push. Each advance uploads its own packs just before it lands.
///
/// A failure after the first advance is [`Error::SplitInterrupted`]. It names
/// the published prefix, and a new push resumes from it.
///
/// # Errors
/// As [`push_branch`], the refusals of the split, and whatever `on_step`
/// returns.
#[allow(clippy::too_many_arguments)] // one value for each bound and hook of the split
pub fn push_branch_steps(
    transport: &dyn Transport,
    store: &ObjectStore,
    branch: &str,
    tip: Hash,
    condition: RefWriteCondition,
    rebaseline_threshold: usize,
    pack_payload_cap: u64,
    control: &PushControl<'_>,
    on_step: &mut dyn FnMut(Hash) -> Result<(), kit_sync::PushError>,
) -> Result<usize, Error> {
    kit_sync::push::push_branch_steps(
        &source(transport),
        store,
        branch,
        tip,
        condition,
        rebaseline_threshold,
        pack_payload_cap,
        control,
        on_step,
    )
    .map_err(Into::into)
}

/// Plan the advances of a split push without uploading anything. Returns the
/// commits where each advance ends.
///
/// # Errors
/// The split is refused. A step needs more packs than the server permits, or
/// the split passes a bound, or the stored grants do not cover every advance.
#[allow(clippy::too_many_arguments)] // one value for each input of the plan
pub fn plan_push_steps(
    store: &ObjectStore,
    tip: Hash,
    remote_tip: Option<Hash>,
    limits: kit_core::protocol::UploadLimits,
    pack_payload_cap: u64,
    control: &PushControl<'_>,
    condition: RefWriteCondition,
    branch: &str,
) -> Result<Vec<Hash>, Error> {
    kit_sync::push::plan_push_steps(
        store,
        tip,
        remote_tip,
        limits,
        pack_payload_cap,
        control,
        condition,
        branch,
    )
    .map_err(Into::into)
}

/// [`pull_with_source`] over `transport` with the default settings. It checks
/// signatures and reports no progress.
///
/// # Errors
/// As [`pull_with_source`].
pub fn pull_all(
    cwd: &Path,
    transport: &dyn Transport,
    remote: &str,
    target_branch: Option<&str>,
) -> Result<usize, Error> {
    pull_all_with(cwd, transport, remote, target_branch, true)
}

/// [`pull_all`] with a switch for the check of signatures.
///
/// # Errors
/// As [`pull_with_source`].
pub fn pull_all_with(
    cwd: &Path,
    transport: &dyn Transport,
    remote: &str,
    target_branch: Option<&str>,
    require_signed: bool,
) -> Result<usize, Error> {
    pull_with_source(
        cwd,
        &source(transport),
        remote,
        target_branch,
        require_signed,
        SyncPolicy::Batch,
        &NoopObserver,
    )
}

/// [`fetch_with_source`] over `transport` with the default settings. It checks
/// signatures and reports no progress.
///
/// # Errors
/// As [`fetch_with_source`].
pub fn fetch_all(cwd: &Path, transport: &dyn Transport, remote: &str) -> Result<usize, Error> {
    fetch_with_source(
        cwd,
        &source(transport),
        remote,
        true,
        false,
        SyncPolicy::Batch,
        &NoopObserver,
    )
}

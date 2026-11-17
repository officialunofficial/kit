//! Native clone, fetch, pull and push for `.kit` repositories.
//!
//! `kit-sync` is the filesystem layer behind the `kit` command line's
//! `clone`, `fetch`, `pull` and `push`, as a library. Every call returns a typed
//! report or a typed error and prints nothing: warnings and progress go to a
//! [`Observer`] as typed [`SyncEvent`]s, and cancellation is polled through it.
//!
//! * No kit config, credentials or environment variables are read by the
//!   library itself. The caller passes the [`RemoteSource`] (already
//!   authenticated; for the transport backend the credentials live in the
//!   [`Transport`](kit_core::protocol::Transport) it was built with) and the
//!   [`SyncOptions`].
//! * A fetch holds no repository lock while it downloads and applies packs. It
//!   keeps gc from deleting its objects with a
//!   [`PruneGuard`](kit_core::store::PruneGuard), and takes the worktree lock
//!   only to publish its refs.
//! * Signature verification of every commit, remix and tag a fetch
//!   introduces is on by default and fails closed. Turning it off is an
//!   explicit option.
//! * [`pull`] refuses anything that is not a fast-forward.
//!
//! The fetch engine reads through the [`RemoteSource`] trait. The always-on
//! backend, [`TransportSource`], wraps kit-core's synchronous `Transport`, so
//! every transport scheme keeps working. With the `client` feature,
//! `ClientSource` accesses `kit+https` and `kit+http` remotes through
//! `kit_client::Client` with an injected signer; with `connect-native`,
//! `NativeHttp` is a small native HTTP channel (gzip only, adding no zstd) for it.

#![deny(unsafe_code)]
#![deny(clippy::print_stdout, clippy::print_stderr)]

mod anchor;
mod applied_packs;
mod checkpoint;
#[cfg(feature = "client")]
mod client_source;
mod clone;
mod closure;
#[doc(hidden)]
pub mod cursor;
mod error;
#[doc(hidden)]
pub mod fanout;
mod fetch;
mod fetch_attestations;
mod lock;
#[cfg(feature = "connect-native")]
mod native;
mod observer;
pub mod packmap;
mod pull;
pub mod push;
pub use push::{PushError, PushLease, PushOptions, PushReport, PushTarget, push};
mod apply;
#[doc(hidden)]
pub mod restore_fanout;
mod source;
mod source_error;
mod tags;
mod verify;
pub mod worktree;

pub use applied_packs::AppliedPacks;
#[cfg(feature = "client")]
pub use client_source::{
    ClientSession, ClientSource, Executor, FuturesExecutor, NoWriteRecovery, UploadEvent,
    WriteRecovery,
};
pub use clone::{
    CloneError, CloneInitError, CloneRemote, CloneReport, DEFAULT_BRANCH, DEFAULT_REMOTE_NAME,
    clone, init_clone_dir,
};
pub use error::SyncError;
pub use fetch::FetchReport;
#[cfg(feature = "connect-native")]
pub use native::{
    DEFAULT_METADATA_TIMEOUT, DEFAULT_TRANSFER_TIMEOUT, NativeClock, NativeHttp, NativeHttpError,
    default_tls_config,
};
pub use observer::{NoopObserver, Observer, SyncEvent};
pub use pull::{PullOutcome, PullReport, fetch, pull, verify_pull_tip};
pub use source::{ErrorClassifier, RemoteSource, TransportSource};
pub use source_error::{FailureClass, RemoteDetail, RemoteFailure, SourceError};
pub use tags::{TAG_SELF_HEALS_PER_FETCH, TagRejectReason, TagRejection, TagWarning};

use kit_core::store::SyncPolicy;

/// Options shared by [`fetch`], [`pull`] and [`clone`]. Start from
/// [`SyncOptions::default`] and set the fields you need.
#[derive(Debug, Clone)]
#[non_exhaustive]
#[allow(clippy::struct_excessive_bools)] // Independent fetch policy switches.
pub struct SyncOptions {
    /// Verify the Ed25519 signature of every commit, remix and tag the call
    /// introduces. `true` by default; failing closed on an unsigned or invalid
    /// object is the point of the check.
    pub verify_signatures: bool,
    /// The branch to land on (clone `-b`, pull). It must exist on the remote;
    /// there is no silent fallback. `None` selects by HEAD.
    pub target_branch: Option<String>,
    /// Object-store durability schedule.
    pub sync_policy: SyncPolicy,
    /// After a complete fetch, delete the remote-tracking refs whose branch
    /// is gone from the remote. Only [`fetch`] acts on it.
    pub prune: bool,
    /// The total time one clone, fetch or pull may spend blocked waiting for
    /// the worktree lock, summed over every wait of the call. `None` waits for
    /// as long as it takes at each publish of a fetch, and a pull's final
    /// update of the branch, HEAD and worktree keeps its usual 5 second wait.
    /// With `Some`, every wait of the call draws from the one limit, the
    /// pull's final update included, and that update has no separate 5 second
    /// wait. Only the time spent waiting counts: the work between two waits
    /// (a download, an apply) is not charged, and a lock that changes hands
    /// does not restart the count. `Some(Duration::MAX)` waits with no bound,
    /// as `None` does at a publish. When the limit is reached, the call fails
    /// with [`SyncError::RepoLock`] (`LockError::Busy`) and publishes nothing
    /// more. What it applied stays in the store, and the next call resumes
    /// from it.
    pub lock_wait: Option<std::time::Duration>,
    /// Fetch the remote's tags after its branches (SPEC-TRANSPORT §1.4).
    /// `true` by default; `false` skips the tag phase (`--no-tags`). A tag
    /// publishes only once its closure and signatures are checked, and a
    /// local tag is never moved: a remote tag of the same name with another
    /// value is refused.
    pub tags: bool,
    /// Fetch portable attestations after code publication. Enabled by default.
    pub attestations: bool,
    /// Clear the remote attestation checkpoint and retry dropped envelopes.
    pub refetch_attestations: bool,
    /// Exact configured remote URL, used only to key disposable records.
    pub remote_url: String,
    /// Maximum decoded attestation bytes per fetch, capped at 512 MiB.
    pub attestation_decode_bytes: u64,
}

impl SyncOptions {
    /// Set [`tags`](Self::tags).
    #[must_use]
    pub fn with_tags(mut self, tags: bool) -> Self {
        self.tags = tags;
        self
    }

    /// Set [`prune`](Self::prune).
    #[must_use]
    pub fn with_prune(mut self, prune: bool) -> Self {
        self.prune = prune;
        self
    }

    /// Set [`verify_signatures`](Self::verify_signatures).
    #[must_use]
    pub fn with_verify_signatures(mut self, verify: bool) -> Self {
        self.verify_signatures = verify;
        self
    }

    /// Set [`target_branch`](Self::target_branch).
    #[must_use]
    pub fn with_target_branch(mut self, branch: Option<String>) -> Self {
        self.target_branch = branch;
        self
    }

    /// Set [`lock_wait`](Self::lock_wait).
    #[must_use]
    pub fn with_lock_wait(mut self, wait: Option<std::time::Duration>) -> Self {
        self.lock_wait = wait;
        self
    }

    /// Set [`sync_policy`](Self::sync_policy).
    #[must_use]
    pub fn with_sync_policy(mut self, policy: SyncPolicy) -> Self {
        self.sync_policy = policy;
        self
    }
}

impl Default for SyncOptions {
    fn default() -> Self {
        Self {
            verify_signatures: true,
            target_branch: None,
            sync_policy: SyncPolicy::Batch,
            prune: false,
            lock_wait: None,
            tags: true,
            attestations: true,
            refetch_attestations: false,
            remote_url: String::new(),
            attestation_decode_bytes: kit_attest::pack::MAX_FETCH_DECODED_BYTES,
        }
    }
}

#[doc(hidden)]
pub mod attestation_records;

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn each_setter_changes_only_its_own_field() {
        let fields = |o: &SyncOptions| {
            (
                o.prune,
                o.verify_signatures,
                o.target_branch.clone(),
                o.lock_wait,
                o.sync_policy,
                o.tags,
            )
        };
        let default = fields(&SyncOptions::default());
        let set = Duration::from_secs(3);
        assert_eq!(
            fields(&SyncOptions::default().with_prune(true)),
            (
                true,
                default.1,
                default.2.clone(),
                default.3,
                default.4,
                default.5
            )
        );
        assert_eq!(
            fields(&SyncOptions::default().with_verify_signatures(false)),
            (
                default.0,
                false,
                default.2.clone(),
                default.3,
                default.4,
                default.5
            )
        );
        assert_eq!(
            fields(&SyncOptions::default().with_tags(false)),
            (
                default.0,
                default.1,
                default.2.clone(),
                default.3,
                default.4,
                false
            )
        );
        assert_eq!(
            fields(&SyncOptions::default().with_target_branch(Some("topic".to_owned()))),
            (
                default.0,
                default.1,
                Some("topic".to_owned()),
                default.3,
                default.4,
                default.5
            )
        );
        assert_eq!(
            fields(&SyncOptions::default().with_lock_wait(Some(set))),
            (
                default.0,
                default.1,
                default.2.clone(),
                Some(set),
                default.4,
                default.5
            )
        );
        assert_eq!(
            fields(&SyncOptions::default().with_sync_policy(SyncPolicy::PerObject)),
            (
                default.0,
                default.1,
                default.2,
                default.3,
                SyncPolicy::PerObject,
                default.5
            )
        );
    }

    #[test]
    fn defaults_verify_signatures_and_batch_writes() {
        let options = SyncOptions::default();
        assert!(options.verify_signatures);
        assert!(!options.prune);
        assert_eq!(options.target_branch, None);
        assert_eq!(options.lock_wait, None);
        assert_eq!(options.sync_policy, SyncPolicy::Batch);
        assert!(options.tags);
    }
}

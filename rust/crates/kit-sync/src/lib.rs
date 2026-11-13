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

mod applied_packs;
mod checkpoint;
#[cfg(feature = "client")]
mod client_source;
mod clone;
#[doc(hidden)]
pub mod cursor;
mod error;
#[doc(hidden)]
pub mod fanout;
mod fetch;
mod lock;
#[cfg(feature = "connect-native")]
mod native;
mod observer;
pub mod packmap;
mod pull;
pub mod push;
pub use push::{PushError, PushLease, PushOptions, PushReport, PushTarget, push};
#[doc(hidden)]
pub mod restore_fanout;
mod source;
mod source_error;
mod stage;
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
pub use lock::{SERVE_LOCK, WORKTREE_LOCK, warn_if_served};
#[cfg(feature = "connect-native")]
pub use native::{
    DEFAULT_METADATA_TIMEOUT, DEFAULT_TRANSFER_TIMEOUT, NativeClock, NativeHttp, NativeHttpError,
    default_tls_config,
};
pub use observer::{NoopObserver, Observer, SyncEvent};
pub use pull::{PullOutcome, PullReport, fetch, pull};
pub use source::{ErrorClassifier, RemoteSource, TransportSource};
pub use source_error::{FailureClass, RemoteDetail, RemoteFailure, SourceError};

use kit_core::store::SyncPolicy;

/// Options shared by [`fetch`], [`pull`] and [`clone`]. Start from
/// [`SyncOptions::default`] and set the fields you need.
#[derive(Debug, Clone)]
#[non_exhaustive]
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
}

impl SyncOptions {
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
        }
    }
}

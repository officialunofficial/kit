//! The per-worktree lock a fetch publishes under, and the served-repository
//! probe that accompanies it.

use std::time::Duration;

use kit_core::layout::RepoLayout;
use kit_core::repo_lock::{self, LockError, RepoLock};

use crate::error::SyncError;
use crate::observer::{Observer, SyncEvent};

pub use kit_core::repo_lock::{SERVE_LOCK, WORKTREE_LOCK};

/// Tell `observer` when at least one server process is currently alive
/// against `layout`'s common dir. Detection, not coordination: a probe
/// failure is swallowed.
pub fn warn_if_served(layout: &RepoLayout, observer: &dyn Observer<SyncEvent>) {
    if let Ok(false) = repo_lock::probe_exclusive(layout.common_dir(), SERVE_LOCK) {
        observer.event(&SyncEvent::RepositoryServed {
            worktree_root: layout.worktree_root().to_path_buf(),
        });
    }
}

/// Take the worktree lock with the default timeout, then run the
/// served-repository probe. Every site that takes [`WORKTREE_LOCK`] directly
/// must go through here so the probe cannot be forgotten.
pub(crate) fn acquire_worktree_lock(
    layout: &RepoLayout,
    observer: &dyn Observer<SyncEvent>,
) -> Result<RepoLock, SyncError> {
    let lock = repo_lock::acquire_default(layout.worktree_state_dir(), WORKTREE_LOCK)?;
    warn_if_served(layout, observer);
    Ok(lock)
}

/// How long a fetch sleeps between attempts to take a held lock.
const PUBLISH_LOCK_POLL: Duration = Duration::from_millis(100);

/// Take the worktree lock for a fetch's publish step, however long another
/// process holds it, then run the served-repository probe. A fetch has
/// already downloaded and applied its packs by then, so giving up would throw
/// that work away. The wait sends [`SyncEvent::WaitingForRepoLock`] once and
/// returns [`SyncError::Interrupted`] when the observer cancels. It polls with
/// non-blocking attempts, so an abandoned wait leaves no thread behind.
pub(crate) fn wait_for_worktree_lock(
    layout: &RepoLayout,
    observer: &dyn Observer<SyncEvent>,
) -> Result<RepoLock, SyncError> {
    let mut announced = false;
    loop {
        match repo_lock::acquire(layout.worktree_state_dir(), WORKTREE_LOCK, Duration::ZERO) {
            Ok(lock) => {
                warn_if_served(layout, observer);
                return Ok(lock);
            }
            Err(LockError::Busy(_)) => {}
            Err(e) => return Err(e.into()),
        }
        if observer.cancelled() {
            return Err(SyncError::Interrupted);
        }
        if !announced {
            announced = true;
            observer.event(&SyncEvent::WaitingForRepoLock);
        }
        std::thread::sleep(PUBLISH_LOCK_POLL);
    }
}

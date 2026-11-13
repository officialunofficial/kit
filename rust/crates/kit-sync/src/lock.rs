//! The per-worktree lock a fetch publishes under, and the served-repository
//! probe that accompanies it.

use std::cell::Cell;
use std::time::{Duration, Instant};

use kit_core::layout::RepoLayout;
use kit_core::repo_lock::{self, LockError, RepoLock};

use crate::error::SyncError;
use crate::observer::{Observer, SyncEvent};

use kit_core::repo_lock::WORKTREE_LOCK;

/// Tell `observer` when at least one server process is currently alive
/// against `layout`'s common dir. Detection, not coordination: a probe
/// failure is swallowed.
fn warn_if_served(layout: &RepoLayout, observer: &dyn Observer<SyncEvent>) {
    if repo_lock::is_served(layout.common_dir()) {
        observer.event(&SyncEvent::RepositoryServed {
            worktree_root: layout.worktree_root().to_path_buf(),
        });
    }
}

/// The one deadline of a clone, fetch or pull for the waits on the worktree
/// lock. It starts at the first failed attempt to take the lock and is not
/// restarted by a later wait or by a change of holder.
pub(crate) struct LockWait {
    limit: Option<Duration>,
    deadline: Cell<Option<Instant>>,
}

impl LockWait {
    /// A wait that gives up `limit` after its first failed attempt, or never
    /// when `limit` is `None`.
    pub(crate) fn new(limit: Option<Duration>) -> Self {
        Self {
            limit,
            deadline: Cell::new(None),
        }
    }

    /// Note a failed attempt, which starts the clock the first time, and
    /// return how long is left, or `None` when there is no limit.
    fn remaining(&self) -> Option<Duration> {
        let limit = self.limit?;
        let deadline = self.deadline.get().unwrap_or_else(|| {
            let deadline = Instant::now() + limit;
            self.deadline.set(Some(deadline));
            deadline
        });
        Some(deadline.saturating_duration_since(Instant::now()))
    }
}

/// Take the worktree lock, then run the served-repository probe. Without a
/// deadline it waits the default timeout. With one it waits as
/// [`wait_for_worktree_lock`] does. Every site that takes [`WORKTREE_LOCK`]
/// directly must go through here so the probe cannot be forgotten.
pub(crate) fn acquire_worktree_lock(
    layout: &RepoLayout,
    observer: &dyn Observer<SyncEvent>,
    wait: &LockWait,
) -> Result<RepoLock, SyncError> {
    if wait.limit.is_some() {
        return wait_for_worktree_lock(layout, observer, wait);
    }
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
///
/// When `wait` has a deadline and it passes, the wait returns
/// [`SyncError::RepoLock`] with [`LockError::Busy`].
pub(crate) fn wait_for_worktree_lock(
    layout: &RepoLayout,
    observer: &dyn Observer<SyncEvent>,
    wait: &LockWait,
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
        let remaining = wait.remaining();
        if observer.cancelled() {
            return Err(SyncError::Interrupted);
        }
        if remaining.is_some_and(|left| left.is_zero()) {
            return Err(LockError::Busy(WORKTREE_LOCK.to_owned()).into());
        }
        if !announced {
            announced = true;
            observer.event(&SyncEvent::WaitingForRepoLock);
        }
        std::thread::sleep(remaining.map_or(PUBLISH_LOCK_POLL, |left| left.min(PUBLISH_LOCK_POLL)));
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::error::SyncError;

    /// An observer that, each time the wait checks for an interrupt, lets the
    /// holder of the lock change: it drops the lock and takes it again, as
    /// another process would between two attempts.
    struct ChangesHands<'a> {
        layout: &'a RepoLayout,
        held: RefCell<Option<RepoLock>>,
        rounds: RefCell<u32>,
        release_after: Option<u32>,
    }

    impl Observer<SyncEvent> for ChangesHands<'_> {
        fn event(&self, _event: &SyncEvent) {}
        fn cancelled(&self) -> bool {
            *self.rounds.borrow_mut() += 1;
            let release = self.release_after == Some(*self.rounds.borrow());
            self.held.borrow_mut().take();
            if !release {
                *self.held.borrow_mut() = Some(
                    repo_lock::acquire_default(self.layout.worktree_state_dir(), WORKTREE_LOCK)
                        .unwrap(),
                );
            }
            false
        }
    }

    fn layout() -> (tempfile::TempDir, RepoLayout) {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        std::fs::create_dir_all(layout.worktree_state_dir()).unwrap();
        (dir, layout)
    }

    fn observer(layout: &RepoLayout, release_after: Option<u32>) -> ChangesHands<'_> {
        ChangesHands {
            layout,
            held: RefCell::new(Some(
                repo_lock::acquire_default(layout.worktree_state_dir(), WORKTREE_LOCK).unwrap(),
            )),
            rounds: RefCell::new(0),
            release_after,
        }
    }

    #[test]
    fn a_lock_that_changes_hands_between_attempts_still_ends_at_the_one_deadline() {
        let (_dir, layout) = layout();
        let observer = observer(&layout, None);
        let wait = LockWait::new(Some(Duration::from_millis(300)));
        let started = Instant::now();
        let error = wait_for_worktree_lock(&layout, &observer, &wait).unwrap_err();
        assert!(matches!(error, SyncError::RepoLock(LockError::Busy(_))));
        assert!(started.elapsed() >= Duration::from_millis(300));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(*observer.rounds.borrow() >= 2, "the holder changed hands");
    }

    #[test]
    fn a_later_wait_of_the_same_call_gets_no_fresh_budget() {
        let (_dir, layout) = layout();
        let observer = observer(&layout, None);
        let wait = LockWait::new(Some(Duration::from_millis(200)));
        wait_for_worktree_lock(&layout, &observer, &wait).unwrap_err();
        let started = Instant::now();
        let error = wait_for_worktree_lock(&layout, &observer, &wait).unwrap_err();
        assert!(matches!(error, SyncError::RepoLock(LockError::Busy(_))));
        assert!(started.elapsed() < Duration::from_millis(100));
    }

    #[test]
    fn a_lock_freed_before_the_deadline_is_taken() {
        let (_dir, layout) = layout();
        let observer = observer(&layout, Some(2));
        let wait = LockWait::new(Some(Duration::from_secs(30)));
        let lock = wait_for_worktree_lock(&layout, &observer, &wait).unwrap();
        drop(lock);
    }

    #[test]
    fn no_limit_waits_until_the_lock_is_free() {
        let (_dir, layout) = layout();
        let observer = observer(&layout, Some(4));
        let wait = LockWait::new(None);
        let lock = wait_for_worktree_lock(&layout, &observer, &wait).unwrap();
        assert!(*observer.rounds.borrow() >= 4);
        drop(lock);
    }
}

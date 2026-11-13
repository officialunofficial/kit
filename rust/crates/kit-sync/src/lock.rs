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

/// The limit of a clone, fetch or pull on the time it spends blocked waiting
/// for the worktree lock, summed over every wait of the call. Work between two
/// waits (a download, an apply) is not charged, and a lock that changes hands
/// does not restart the count.
pub(crate) struct LockWait {
    limit: Option<Duration>,
    waited: Cell<Duration>,
}

impl LockWait {
    /// A wait that gives up once the waits of the call add up to `limit`, or
    /// never when `limit` is `None`.
    pub(crate) fn new(limit: Option<Duration>) -> Self {
        Self {
            limit,
            waited: Cell::new(Duration::ZERO),
        }
    }

    /// How much of the limit is left, or `None` when there is no limit.
    /// `in_progress` is the time of the wait that is still running.
    fn remaining(&self, in_progress: Duration) -> Option<Duration> {
        let limit = self.limit?;
        Some(limit.saturating_sub(self.waited.get().saturating_add(in_progress)))
    }

    /// Add the time of a wait that has ended.
    fn charge(&self, wait: Duration) {
        self.waited.set(self.waited.get().saturating_add(wait));
    }
}

/// Take the worktree lock, then run the served-repository probe. Without a
/// limit it waits the default timeout. With one it waits as
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
/// When `wait` has a limit and the time spent waiting, over this wait and the
/// earlier ones of the call, reaches it, the wait returns
/// [`SyncError::RepoLock`] with [`LockError::Busy`].
pub(crate) fn wait_for_worktree_lock(
    layout: &RepoLayout,
    observer: &dyn Observer<SyncEvent>,
    wait: &LockWait,
) -> Result<RepoLock, SyncError> {
    let mut announced = false;
    // The wait starts at the first failed attempt, so an attempt that succeeds
    // at once charges nothing.
    let mut blocked_since: Option<Instant> = None;
    let result = loop {
        match repo_lock::acquire(layout.worktree_state_dir(), WORKTREE_LOCK, Duration::ZERO) {
            Ok(lock) => {
                warn_if_served(layout, observer);
                break Ok(lock);
            }
            Err(LockError::Busy(_)) => {}
            Err(e) => break Err(e.into()),
        }
        let in_progress = blocked_since.get_or_insert_with(Instant::now).elapsed();
        let remaining = wait.remaining(in_progress);
        if observer.cancelled() {
            break Err(SyncError::Interrupted);
        }
        if remaining.is_some_and(|left| left.is_zero()) {
            break Err(LockError::Busy(WORKTREE_LOCK.to_owned()).into());
        }
        if !announced {
            announced = true;
            observer.event(&SyncEvent::WaitingForRepoLock);
        }
        std::thread::sleep(remaining.map_or(PUBLISH_LOCK_POLL, |left| left.min(PUBLISH_LOCK_POLL)));
    };
    if let Some(since) = blocked_since {
        wait.charge(since.elapsed());
    }
    result
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
    fn a_lock_that_changes_hands_between_attempts_still_ends_at_the_limit() {
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
    fn a_later_wait_of_the_same_call_gets_no_fresh_limit() {
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
    fn a_lock_freed_before_the_limit_is_taken() {
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

    /// A call waits twice for the lock, for example once for each branch it
    /// publishes. The first wait is short. The work between the two waits (a
    /// download) takes longer than the limit. The second wait then finds the
    /// lock held for a moment. Neither wait is near the limit, so the call
    /// goes on.
    #[test]
    fn work_between_two_waits_is_not_charged_to_the_lock_wait() {
        let (_dir, layout) = layout();
        let wait = LockWait::new(Some(Duration::from_millis(300)));
        {
            let first = observer(&layout, Some(1));
            let started = Instant::now();
            let lock = wait_for_worktree_lock(&layout, &first, &wait).unwrap();
            assert!(started.elapsed() < Duration::from_millis(250));
            drop(lock);
        }
        // The download of the next branch.
        std::thread::sleep(Duration::from_millis(400));
        let second = observer(&layout, Some(1));
        let started = Instant::now();
        let result = wait_for_worktree_lock(&layout, &second, &wait);
        assert!(
            result.is_ok(),
            "the lock was free after {:?} of waiting, with a limit of 300 ms: {:?}",
            started.elapsed(),
            result.err()
        );
    }

    /// The longest wait a caller can ask for is a wait, not a panic.
    #[test]
    fn the_longest_lock_wait_does_not_panic() {
        let (_dir, layout) = layout();
        let observer = observer(&layout, Some(2));
        let wait = LockWait::new(Some(Duration::MAX));
        let lock = wait_for_worktree_lock(&layout, &observer, &wait).unwrap();
        drop(lock);
    }

    #[test]
    fn a_lock_that_stays_held_fails_a_short_limit_quickly() {
        let (_dir, layout) = layout();
        let held = repo_lock::acquire_default(layout.worktree_state_dir(), WORKTREE_LOCK).unwrap();
        let wait = LockWait::new(Some(Duration::from_millis(200)));
        let started = Instant::now();
        let error = wait_for_worktree_lock(&layout, &NoCancel, &wait).unwrap_err();
        assert!(matches!(error, SyncError::RepoLock(LockError::Busy(_))));
        assert!(started.elapsed() >= Duration::from_millis(200));
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(held);
    }

    /// The first wait takes the lock after about half the limit, and the lock
    /// is then taken again by another holder. The second wait gets only what
    /// is left of the limit.
    #[test]
    fn waits_that_lose_and_retake_the_lock_sum_to_the_limit() {
        let (_dir, layout) = layout();
        let wait = LockWait::new(Some(Duration::from_millis(1000)));
        let first = observer(&layout, Some(5));
        let lock = wait_for_worktree_lock(&layout, &first, &wait).unwrap();
        drop(lock);
        let second = observer(&layout, None);
        let started = Instant::now();
        let error = wait_for_worktree_lock(&layout, &second, &wait).unwrap_err();
        assert!(matches!(error, SyncError::RepoLock(LockError::Busy(_))));
        assert!(
            started.elapsed() < Duration::from_millis(900),
            "the second wait got a fresh limit: {:?}",
            started.elapsed()
        );
    }

    /// A pull's final update takes the lock through `acquire_worktree_lock`.
    /// With a limit, it draws from the waiting time the earlier waits left,
    /// and has no wait of its own: it fails once the summed waiting passes
    /// the limit, long before the default 5 seconds.
    #[test]
    fn the_final_update_of_a_pull_draws_from_the_same_limit() {
        let (_dir, layout) = layout();
        let wait = LockWait::new(Some(Duration::from_millis(1000)));
        let earlier = observer(&layout, Some(5));
        let lock = wait_for_worktree_lock(&layout, &earlier, &wait).unwrap();
        drop(lock);
        let held = repo_lock::acquire_default(layout.worktree_state_dir(), WORKTREE_LOCK).unwrap();
        let started = Instant::now();
        let error = acquire_worktree_lock(&layout, &NoCancel, &wait).unwrap_err();
        assert!(matches!(error, SyncError::RepoLock(LockError::Busy(_))));
        assert!(
            started.elapsed() < Duration::from_millis(900),
            "the final update waited {:?}",
            started.elapsed()
        );
        drop(held);
    }

    struct NoCancel;

    impl Observer<SyncEvent> for NoCancel {
        fn event(&self, _event: &SyncEvent) {}
    }
}

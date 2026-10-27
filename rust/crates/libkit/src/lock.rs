//! The repository locks.
//!
//! The library takes a lock only when a caller asks for it. The caller picks
//! the scope: it holds the returned guard for as long as the operation must
//! exclude other writers, then drops the guard. An operation that must exclude
//! other writers for its whole run, such as [`crate::branch::delete`], takes
//! the lock itself, and its documentation says so. No other library operation
//! takes a lock behind the caller's back.
//!
//! Each tree has a worktree lock for its index and files. The common
//! directory has a registry lock for the set of linked trees. A process that
//! takes more than one lock follows the order in [`WORKTREES_REGISTRY_LOCK`].

use std::path::PathBuf;

use kit_core::layout::RepoLayout;
use kit_core::observer::Observer;
use kit_core::repo_lock;

pub use kit_core::repo_lock::{
    LockError, RepoLock, SERVE_LOCK, WORKTREE_LOCK, WORKTREES_REGISTRY_LOCK,
};

/// What a lock helper reports to its [`Observer`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// A live `kit serve` process holds the repository. Local changes to the
    /// tree and `gc` are not coordinated with it.
    RepositoryServed {
        /// The worktree root of the repository.
        worktree_root: PathBuf,
    },
}

/// Errors from taking a repository lock.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The worktree lock could not be taken in time.
    #[error("repo lock: {0}")]
    Worktree(LockError),
    /// The registry lock could not be taken in time.
    #[error("worktree registry lock: {0}")]
    Registry(LockError),
}

/// Tell `observer` when a live `kit serve` process holds `layout`.
///
/// This is detection, not coordination. A probe failure is not an error,
/// because the check is a diagnostic and never a reason to fail the caller.
/// A caller that takes [`WORKTREE_LOCK`] or [`WORKTREES_REGISTRY_LOCK`]
/// directly calls this function right after it takes the lock. The two
/// `acquire_*` functions do that already.
pub fn warn_if_served(layout: &RepoLayout, observer: &dyn Observer<Event>) {
    if let Ok(false) = repo_lock::probe_exclusive(layout.common_dir(), SERVE_LOCK) {
        observer.event(&Event::RepositoryServed {
            worktree_root: layout.worktree_root().to_path_buf(),
        });
    }
}

/// Take the worktree lock of the tree at `layout`, then run
/// [`warn_if_served`].
///
/// Hold the guard across the whole read-modify-write on the index and the
/// files, so a second writer waits and then times out instead of racing.
///
/// # Errors
/// [`Error::Worktree`] when another process holds the lock past the default
/// timeout, or when the lock file cannot be opened.
pub fn acquire_worktree(
    layout: &RepoLayout,
    observer: &dyn Observer<Event>,
) -> Result<RepoLock, Error> {
    let lock = repo_lock::acquire_default(layout.worktree_state_dir(), WORKTREE_LOCK)
        .map_err(Error::Worktree)?;
    warn_if_served(layout, observer);
    Ok(lock)
}

/// Take the registry lock in the common directory, then run
/// [`warn_if_served`].
///
/// # Errors
/// [`Error::Registry`] when another process holds the lock past the default
/// timeout, or when the lock file cannot be opened.
pub fn acquire_registry(
    layout: &RepoLayout,
    observer: &dyn Observer<Event>,
) -> Result<RepoLock, Error> {
    let lock = repo_lock::acquire_default(layout.common_dir(), WORKTREES_REGISTRY_LOCK)
        .map_err(Error::Registry)?;
    warn_if_served(layout, observer);
    Ok(lock)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::time::Duration;

    use super::*;

    #[derive(Default)]
    struct Recorder(RefCell<Vec<Event>>);

    impl Observer<Event> for Recorder {
        fn event(&self, event: &Event) {
            self.0.borrow_mut().push(event.clone());
        }
    }

    fn layout() -> (tempfile::TempDir, RepoLayout) {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        std::fs::create_dir_all(layout.common_dir()).unwrap();
        (dir, layout)
    }

    #[test]
    fn the_worktree_guard_excludes_a_second_taker_until_it_drops() {
        let (_dir, layout) = layout();
        let guard = acquire_worktree(&layout, &kit_core::observer::NoopObserver).unwrap();
        let contended = repo_lock::acquire(
            layout.worktree_state_dir(),
            WORKTREE_LOCK,
            Duration::from_millis(100),
        );
        assert!(matches!(contended, Err(LockError::Busy(_))));
        drop(guard);
        let _again = acquire_worktree(&layout, &kit_core::observer::NoopObserver).unwrap();
    }

    #[test]
    fn the_registry_lock_is_separate_from_the_worktree_lock() {
        let (_dir, layout) = layout();
        let _worktree = acquire_worktree(&layout, &kit_core::observer::NoopObserver).unwrap();
        let _registry = acquire_registry(&layout, &kit_core::observer::NoopObserver).unwrap();
    }

    #[test]
    fn a_busy_lock_names_its_scope_in_the_error() {
        let (_dir, layout) = layout();
        let _held =
            repo_lock::acquire_default(layout.common_dir(), WORKTREES_REGISTRY_LOCK).unwrap();
        let err = repo_lock::acquire(
            layout.common_dir(),
            WORKTREES_REGISTRY_LOCK,
            Duration::from_millis(50),
        )
        .map_err(Error::Registry)
        .unwrap_err();
        assert!(err.to_string().starts_with("worktree registry lock: "));
    }

    #[test]
    fn a_live_server_is_reported_and_an_idle_repository_is_not() {
        let (_dir, layout) = layout();
        let recorder = Recorder::default();
        warn_if_served(&layout, &recorder);
        assert!(recorder.0.borrow().is_empty());

        let _serving =
            repo_lock::acquire_shared(layout.common_dir(), SERVE_LOCK, Duration::from_millis(200))
                .unwrap();
        let guard = acquire_worktree(&layout, &recorder).unwrap();
        assert_eq!(
            *recorder.0.borrow(),
            vec![Event::RepositoryServed {
                worktree_root: layout.worktree_root().to_path_buf()
            }]
        );
        drop(guard);
    }
}

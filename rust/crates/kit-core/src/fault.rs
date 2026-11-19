//! Injected write failures, for tests of how a full disk ends a transfer, and a
//! hook on the store's dirent flushes, for tests of what is durable before a
//! ref names it.
//!
//! Built with the `fault-injection` feature,
//! which only test builds turn on. A failure applies to every thread of the
//! process until its guard drops, so a test that injects one runs alone.

use std::io;
use std::sync::atomic::{AtomicU8, Ordering};

/// Where a write fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Site {
    /// A positioned write to a spool file: every write a fetch makes to its
    /// spool.
    Spool = 1,
    /// A write to an object file of the store.
    Store = 2,
}

static FAILING: AtomicU8 = AtomicU8::new(0);

/// Every write at `site` fails as a full disk until the guard drops.
#[must_use = "the failure ends when the guard drops"]
pub fn fail_writes(site: Site) -> Guard {
    FAILING.fetch_or(site as u8, Ordering::SeqCst);
    Guard(site)
}

/// Ends an injected failure when dropped.
#[derive(Debug)]
pub struct Guard(Site);

impl Drop for Guard {
    fn drop(&mut self) {
        FAILING.fetch_and(!(self.0 as u8), Ordering::SeqCst);
    }
}

/// The injected failure of a write at `site`, if any.
pub(crate) fn check(site: Site) -> io::Result<()> {
    if FAILING.load(Ordering::SeqCst) & site as u8 == 0 {
        Ok(())
    } else {
        Err(io::Error::from(io::ErrorKind::StorageFull))
    }
}

/// A step that makes the store's directory entries durable, as
/// [`on_sync`] reports it once the step has completed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncStep {
    /// The dirents of one shard directory were barriered.
    DirBarrier(std::path::PathBuf),
    /// The terminal device flush that makes the barriers durable, anchored
    /// at the store's `objects/` directory.
    DeviceFlush(std::path::PathBuf),
}

type SyncHook = Box<dyn Fn(&SyncStep) + Send + Sync>;

static SYNC_HOOK: std::sync::Mutex<Option<SyncHook>> = std::sync::Mutex::new(None);

/// Call `hook` after every dirent barrier and device flush of every store in
/// the process, until the guard drops. A test that sets one runs alone.
#[must_use = "the hook ends when the guard drops"]
pub fn on_sync(hook: impl Fn(&SyncStep) + Send + Sync + 'static) -> SyncHookGuard {
    *SYNC_HOOK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Box::new(hook));
    SyncHookGuard(())
}

/// Ends a hook set by [`on_sync`] when dropped.
#[derive(Debug)]
pub struct SyncHookGuard(());

impl Drop for SyncHookGuard {
    fn drop(&mut self) {
        *SYNC_HOOK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }
}

/// Report a completed step to the hook, if one is set.
pub(crate) fn sync_step(step: impl FnOnce() -> SyncStep) {
    let hook = SYNC_HOOK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(hook) = hook.as_ref() {
        hook(&step());
    }
}

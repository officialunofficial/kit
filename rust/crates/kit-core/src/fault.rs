//! Injected write failures, for tests of how a full disk ends a transfer, a
//! hook on the device operations of the store and of every durable write, for
//! tests of what is durable before a ref names it, and a count of full
//! flushes.
//!
//! Built with the `fault-injection` feature,
//! which only test builds turn on. A failure applies to every thread of the
//! process until its guard drops, so a test that injects one runs alone.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

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

/// A device operation, as [`on_sync`] reports it once the operation has
/// completed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncStep {
    /// The dirents of one shard directory were barriered.
    DirBarrier(std::path::PathBuf),
    /// The terminal device flush that makes the barriers durable, anchored
    /// at the store's `objects/` directory.
    DeviceFlush(std::path::PathBuf),
    /// A file or a directory was written out: its data was handed to the
    /// drive, with no flush of the drive's cache. Every command reports this,
    /// not only the object batches.
    Writeout(std::path::PathBuf),
    /// A file or a directory was flushed with a full flush. The step of the
    /// flush that [`flushes`] counts; every command reports it.
    Flush(std::path::PathBuf),
}

type SyncHook = Box<dyn Fn(&SyncStep) + Send + Sync>;

static SYNC_HOOK: std::sync::Mutex<Option<SyncHook>> = std::sync::Mutex::new(None);

/// Call `hook` after every dirent barrier and device flush of every store in
/// the process, until the guard drops. A test keeps only the steps under its
/// own objects directory. One hook is set at a time, so tests that set one
/// run one per process, as nextest runs them, or not concurrently. The hook
/// must not flush a store: it runs under the hook's lock.
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

thread_local! {
    static FLUSHES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// How many full flushes the calling thread has made, counting every file and
/// directory that [`crate::durable::flush_file`] flushed. A test takes the count
/// before and after a call and compares them. Another thread's flush is not
/// counted, so tests run in parallel do not disturb each other.
#[must_use]
pub fn flushes() -> u64 {
    FLUSHES.with(std::cell::Cell::get)
}

pub(crate) fn count_flush() {
    FLUSHES.with(|count| count.set(count.get() + 1));
}

/// The device operations under one directory, counted by [`count_flushes`].
#[derive(Debug)]
pub struct Counter {
    flushes: Arc<AtomicUsize>,
    writeouts: Arc<AtomicUsize>,
    _hook: SyncHookGuard,
}

impl Counter {
    /// The full flushes of files and directories under the directory since the
    /// counter was made.
    #[must_use]
    pub fn flushes(&self) -> usize {
        self.flushes.load(Ordering::SeqCst)
    }

    /// The writeouts under the directory since the counter was made.
    #[must_use]
    pub fn writeouts(&self) -> usize {
        self.writeouts.load(Ordering::SeqCst)
    }
}

/// Count the [`SyncStep::Flush`] and [`SyncStep::Writeout`] steps whose path
/// lies under `under`, of every thread, until the counter drops. It sets the
/// [`on_sync`] hook, so a test that uses it runs one per process, as nextest
/// runs them.
#[must_use = "the count ends when the counter drops"]
pub fn count_flushes(under: &std::path::Path) -> Counter {
    let flushes = Arc::new(AtomicUsize::new(0));
    let writeouts = Arc::new(AtomicUsize::new(0));
    let hook = {
        let (flushes, writeouts) = (Arc::clone(&flushes), Arc::clone(&writeouts));
        let under = under.to_path_buf();
        on_sync(move |step| match step {
            SyncStep::Flush(path) if path.starts_with(&under) => {
                flushes.fetch_add(1, Ordering::SeqCst);
            }
            SyncStep::Writeout(path) if path.starts_with(&under) => {
                writeouts.fetch_add(1, Ordering::SeqCst);
            }
            _ => {}
        })
    };
    Counter {
        flushes,
        writeouts,
        _hook: hook,
    }
}

static LOOSE: std::sync::Mutex<Vec<std::path::PathBuf>> = std::sync::Mutex::new(Vec::new());

/// Keep the store of `layout` loose: the one-way local-pack activation that a
/// write or fetch attempts leaves its format marker as it is. For tests that
/// unlink or inspect individual objects, which a pack does not hold as files.
/// Applies to this repository only, for the rest of
/// the process, so tests run in parallel are not affected. Call it before the
/// first write or fetch; a store that exists already is made loose at once.
///
/// # Panics
/// If the loose marker cannot be written.
pub fn keep_loose(layout: &crate::layout::RepoLayout) {
    let marker = layout.format_file();
    LOOSE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(marker.clone());
    // A store that `init` already made starts packed: make it loose.
    if marker.exists() {
        std::fs::write(&marker, b"bmt-v2\n").expect("write the loose marker");
    }
}

/// Whether [`keep_loose`] named the format marker at `path`.
pub(crate) fn keeps_loose(path: &std::path::Path) -> bool {
    LOOSE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .any(|kept| kept == path)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::{SyncStep, on_sync};
    use crate::layout::RepoLayout;
    use crate::store::ObjectStore;

    #[test]
    fn the_hook_sees_each_dirent_flush_until_its_guard_drops() {
        let dir = tempfile::tempdir().unwrap();
        let store = ObjectStore::init_loose(&RepoLayout::single(dir.path())).unwrap();
        let root = store.objects_root().to_path_buf();
        let seen: Arc<Mutex<Vec<SyncStep>>> = Arc::default();
        {
            let seen = Arc::clone(&seen);
            let root = root.clone();
            let _hook = on_sync(move |step| {
                let ours = match step {
                    SyncStep::DirBarrier(dir) => dir.starts_with(&root),
                    SyncStep::DeviceFlush(at) => *at == root,
                    SyncStep::Writeout(_) | SyncStep::Flush(_) => false,
                };
                if ours {
                    seen.lock().unwrap().push(step.clone());
                }
            });
            store.sync_shards([0x01]).unwrap();
        }
        store.sync_shards([0x02]).unwrap();

        assert_eq!(
            *seen.lock().unwrap(),
            [
                SyncStep::DirBarrier(root.join("01")),
                SyncStep::DeviceFlush(root.clone()),
            ]
        );
    }

    #[test]
    fn keep_loose_keeps_that_store_loose_only() {
        let dir = tempfile::tempdir().unwrap();
        let kept = RepoLayout::single(dir.path().join("kept"));
        let other = RepoLayout::single(dir.path().join("other"));
        super::keep_loose(&kept);
        let kept_store = ObjectStore::init(&kept).unwrap();
        let other_store = ObjectStore::init(&other).unwrap();

        kept_store.try_activate_local_packs().unwrap();
        kept_store.write(b"kept").unwrap();
        other_store.try_activate_local_packs().unwrap();
        assert!(!kept_store.local_packs_enabled().unwrap());
        assert!(other_store.local_packs_enabled().unwrap());
    }
}

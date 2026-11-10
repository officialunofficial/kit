//! Atomic write helper shared by `refs`, `index`, and friends.
//!
//! The same `temp + fsync + rename + parent-dir-fsync` pattern lives in
//! `store::write_atomic`; we keep this copy `pub(crate)` instead of
//! reaching into `store` so the two subsystems can be developed
//! independently and so future changes to one don't ripple into the
//! other. The behaviour is identical.
//!
//! Deliberately NOT batched: refs, the index, and recovery-log entries
//! are the durable *pointers* the batched object store orders itself
//! against (`crate::batch` module docs). Each one must hit stable
//! storage in its own right before its caller returns. Do not
//! "optimise" these writes onto the batch path.
//!
//! The one documented exception is `refs::RemoteRefBatch`:
//! `refs/remotes/*` entries are not pointers anything orders against —
//! they are a locally-cached, trivially recomputable-from-a-re-fetch
//! view of another repository's branches — so a multi-ref fan-out (one
//! `push`/`fetch` updating N tracking refs) is allowed to defer the
//! parent-directory fsync ([`sync_dir`]) across the whole batch instead
//! of paying it per ref. `refs/heads/*` (branch heads) and everything
//! else in this module keep the unbatched per-write contract described
//! above.

use std::fs;
#[cfg(unix)]
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};

use tempfile::NamedTempFile;

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// The prefix of a temp file name: `.kit.tmp.<pid>.<seq>`. `tempfile` adds a
/// random suffix and creates the file with `O_EXCL`, so a link at that name is
/// never followed. The name does not contain the destination name: a ref
/// segment can be as long as the file system allows, and a temp name that
/// held it would be too long. The leading dot keeps the temp file out of any
/// ref listing, because a ref segment never starts with a dot.
fn temp_prefix() -> String {
    let pid = process::id();
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    format!(".kit.tmp.{pid}.{seq}")
}

/// Atomically write `bytes` to `final_path`, fsyncing the file CONTENTS
/// before the rename but deferring the directory fsync to the caller.
/// This is the durable-before-visible primitive for [`store::BulkWriter`]:
/// the object's bytes are on stable storage before the rename publishes
/// it, so a concurrent process that dedups against the now-visible object
/// can never reference non-durable content. The rename itself becomes
/// durable when the caller fsyncs the shard dir at commit.
///
/// [`store::BulkWriter`]: crate::store::BulkWriter
pub(crate) fn write_content_synced(final_path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = final_path
        .parent()
        .expect("atomic::write_content_synced: path has parent");
    let tmp_name = temp_prefix();
    let mut tmp = NamedTempFile::with_prefix_in(tmp_name, parent)?;
    tmp.as_file_mut().write_all(bytes)?;
    tmp.as_file_mut().sync_all()?;
    tmp.persist(final_path).map_err(|e| e.error)?;
    Ok(())
}

/// Fsync a directory (making completed renames durable).
pub(crate) fn sync_dir(dir: &Path) -> io::Result<()> {
    sync_parent_dir(dir)
}

pub(crate) fn write_atomic(final_path: &Path, bytes: &[u8], make_parents: bool) -> io::Result<()> {
    let parent = final_path
        .parent()
        .expect("atomic::write_atomic: path has parent");
    if make_parents {
        fs::create_dir_all(parent)?;
    }
    let tmp_name = temp_prefix();

    let mut tmp = NamedTempFile::with_prefix_in(tmp_name, parent)?;
    tmp.as_file_mut().write_all(bytes)?;
    tmp.as_file_mut().sync_all()?;
    tmp.persist(final_path).map_err(|e| e.error)?;

    sync_parent_dir(parent)?;
    Ok(())
}

/// Create-new (`O_EXCL`) variant for the `.missing` CAS condition: the
/// caller wants the write to fail with `AlreadyExists` if `final_path`
/// already has anything there.
///
/// Returns `Ok(true)` on success, `Ok(false)` if the path already
/// existed, or an `Err` for any other I/O failure.
pub(crate) fn write_create_new(
    final_path: &Path,
    bytes: &[u8],
    make_parents: bool,
) -> io::Result<bool> {
    let parent = final_path
        .parent()
        .expect("atomic::write_create_new: path has parent");
    if make_parents {
        fs::create_dir_all(parent)?;
    }

    // Write into a sibling temp file first, fsync it, then atomically
    // rename into place with replace-existing semantics disabled. This
    // combines `O_EXCL` exclusivity on the destination with atomicity on
    // the payload: a crash mid-write leaves only the temp file behind,
    // never a half-written `final_path` that later readers would see as
    // a corrupt ref. Writing straight into `final_path` with `O_EXCL`
    // (the previous approach) poisons the slot on partial-write failure.
    let tmp_name = temp_prefix();

    let mut tmp = NamedTempFile::with_prefix_in(tmp_name, parent)?;
    tmp.as_file_mut().write_all(bytes)?;
    tmp.as_file_mut().sync_all()?;

    // `persist_noclobber` uses `renameat2(RENAME_NOREPLACE)` on Linux
    // and `link(2) + unlink(2)` on other Unix; on Windows it uses
    // `MoveFileExW` without `MOVEFILE_REPLACE_EXISTING`. It returns
    // `io::ErrorKind::AlreadyExists` if the destination exists.
    match tmp.persist_noclobber(final_path) {
        Ok(_file) => {
            sync_parent_dir(parent)?;
            Ok(true)
        }
        Err(e) if e.error.kind() == io::ErrorKind::AlreadyExists => {
            // `persist_noclobber` on failure returns the `NamedTempFile`
            // back to us via `e.file`, which `Drop` will unlink. Nothing
            // leaks.
            Ok(false)
        }
        Err(e) => Err(e.error),
    }
}

#[cfg(unix)]
pub(crate) fn sync_parent_dir(parent: &Path) -> io::Result<()> {
    #[cfg(test)]
    testing::record_dir_sync_call();
    match File::open(parent) {
        Ok(dir) => dir.sync_all(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn sync_parent_dir(_parent: &Path) -> io::Result<()> {
    #[cfg(test)]
    testing::record_dir_sync_call();
    Ok(())
}

/// Test-only directory-fsync call counter.
///
/// [`sync_parent_dir`] is the single choke point every parent-directory
/// fsync in this crate goes through — `write_atomic`, `write_create_new`,
/// [`sync_dir`], and [`crate::store`]'s syncers all bottom out here. A
/// per-thread counter (rather than a process-global one) lets tests run
/// under the default parallel test harness without a lock: `cargo test`
/// gives each `#[test]` its own OS thread, so one test's count can never
/// be perturbed by another running concurrently.
#[cfg(test)]
pub(crate) mod testing {
    use std::cell::Cell;

    thread_local! {
        static DIR_SYNC_CALLS: Cell<u64> = const { Cell::new(0) };
    }

    pub(crate) fn record_dir_sync_call() {
        DIR_SYNC_CALLS.with(|c| c.set(c.get() + 1));
    }

    /// Zero this thread's counter. Call at the start of a test that
    /// asserts a call count, so any directory syncs performed by earlier
    /// setup (`fresh_repo`, etc.) on the same thread aren't counted.
    pub(crate) fn reset_dir_sync_calls() {
        DIR_SYNC_CALLS.with(|c| c.set(0));
    }

    /// This thread's directory-fsync count since the last
    /// [`reset_dir_sync_calls`].
    #[must_use]
    pub(crate) fn dir_sync_calls() -> u64 {
        DIR_SYNC_CALLS.with(Cell::get)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temp_prefixes_are_short_hidden_and_unique() {
        let (a, b) = (temp_prefix(), temp_prefix());
        assert_ne!(a, b);
        for name in [&a, &b] {
            let rest = name.strip_prefix(".kit.tmp.").expect("fixed hidden prefix");
            let (pid, seq) = rest.split_once('.').expect("pid and sequence");
            assert_eq!(pid, process::id().to_string());
            assert!(seq.bytes().all(|c| c.is_ascii_digit()) && !seq.is_empty());
        }
    }
}

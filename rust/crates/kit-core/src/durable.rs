//! Durable writes: the pointer and cache-record helpers every crate shares,
//! the full flush they all go through, and the group API that lets later
//! writes share flushes.
//!
//! # Words
//!
//! - **Writeout**: hand a file's or a directory's dirty data to the drive.
//!   It does not empty the drive's volatile cache. Apple: `fsync(2)`. Linux:
//!   `fdatasync` or `fsync`. Windows: `FlushFileBuffers`. On Linux and
//!   Windows a writeout is already durable.
//! - **Flush**: one `fcntl(F_FULLFSYNC)` (Apple) that empties the drive's
//!   cache and so makes every earlier writeout on that device durable.
//!   [`flush_file`] is the one place a full flush of a file or a directory is
//!   made, so a test can count what a command flushes.
//! - **Pointer**: a small file whose name is the state: a ref, `HEAD`, the
//!   index, a marker, the config, the recovery log. Its bytes are durable
//!   before its rename, and its rename is durable before the writer returns.
//!   Refs, the index and recovery-log entries are the pointers the object
//!   store orders itself against (`crate::batch`), so each one is durable in
//!   its own right.
//! - **Cache record**: a file whose loss or tear only costs work, and whose
//!   reader validates it. It gets no writeout and no flush.
//!
//! # One-shot writes
//!
//! [`write_pointer`], [`write_pointer_from`] and [`write_pointer_new`] write a
//! pointer: temp file, writeout and full flush of its bytes, rename, then a
//! full flush of its directory. [`write_cache`] writes a cache record: temp
//! file and rename.
//!
//! # Groups
//!
//! A [`Group`] makes several writes share flushes: [`Group::stage`] writes a
//! temp file and writes it out, [`Group::flush`] is one ordering point and
//! returns a [`Flushed`] token, [`Group::publish`] renames a staged file into
//! place, and [`Group::finish`] makes the last renames durable. A rename is
//! refused unless its token comes from a flush that came after the staged
//! file's writeout and after every earlier rename of the group. A failed
//! writeout or flush poisons the group, and nothing is retried: a retried
//! `fsync` can report success for pages the kernel already dropped.
//!
//! Every device operation goes through the store's `Syncer`, so a test
//! double sees them, and with the `fault-injection` feature the
//! `Writeout` and `Flush` steps of `fault::SyncStep` report each one.
//!
//! The one documented exception to "a pointer is durable on its own" is
//! `refs::RemoteRefBatch`: `refs/remotes/*` entries are not pointers anything
//! orders against, since they are a locally cached view of another
//! repository's branches that a re-fetch recomputes. A multi-ref fan-out may
//! defer the parent-directory flush ([`flush_dir`]) across the whole batch.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tempfile::{NamedTempFile, TempPath};

use crate::batch::{RealSyncer, Syncer};

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

pub(crate) fn temp_file_in(parent: &Path) -> io::Result<NamedTempFile> {
    NamedTempFile::with_prefix_in(temp_prefix(), parent)
}

/// Who may read a file the pointer writers make.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Access {
    /// Mode 0600, the mode of `tempfile`.
    Private,
    /// The mode `File::create` gives: 0666 less the umask, for a file that
    /// users sharing a directory read.
    Shared,
}

fn temp_file_with(parent: &Path, access: Access) -> io::Result<NamedTempFile> {
    #[cfg(unix)]
    if access == Access::Shared {
        use std::os::unix::fs::PermissionsExt as _;
        return tempfile::Builder::new()
            .prefix(&temp_prefix())
            .permissions(fs::Permissions::from_mode(0o666))
            .tempfile_in(parent);
    }
    let _ = access;
    temp_file_in(parent)
}

/// Whether a write makes the missing directories above its destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Parents {
    /// The directory exists; a missing one is an error.
    Existing,
    /// Make the directory and its parents first. The new directories are not
    /// flushed.
    Create,
}

fn parent_of(dest: &Path) -> io::Result<&Path> {
    dest.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "destination path has no parent",
            )
        })
}

fn prepare_parent(dest: &Path, parents: Parents) -> io::Result<&Path> {
    let parent = parent_of(dest)?;
    if parents == Parents::Create {
        fs::create_dir_all(parent)?;
    }
    Ok(parent)
}

/// Copy exactly `len` bytes of `source` to `file`, [`crate::pack::SPOOL_BUFFER`]
/// bytes at a time, so a file of any size is written with one buffer.
fn copy_exact(file: &mut File, source: &mut dyn Read, len: u64) -> io::Result<()> {
    let mut buf = vec![
        0u8;
        usize::try_from(len).map_or(crate::pack::SPOOL_BUFFER, |n| {
            n.min(crate::pack::SPOOL_BUFFER)
        })
    ];
    let mut left = len;
    while left > 0 {
        let n = usize::try_from(left).map_or(buf.len(), |left| left.min(buf.len()));
        source.read_exact(&mut buf[..n])?;
        file.write_all(&buf[..n])?;
        left -= n as u64;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The full flush
// ---------------------------------------------------------------------------

/// Flush `file` and the device cache behind it. `path` names the file, for
/// the test hooks only.
///
/// With the `fault-injection` feature, `fault::flushes` counts the flushes of
/// a thread, `fault::SyncStep::Flush` reports each one, and a process
/// whose environment sets `KIT_FLUSH_LOG` to a path appends one line to that
/// file for each full flush of any thread, so a test that runs the binary
/// counts the lines. Without the feature this is `sync_all` and the
/// environment is not read. A per-file writeout that a later full flush covers
/// (`fsync(2)` on Apple, `fdatasync` on Linux) is not a full flush and is not
/// counted.
///
/// # Errors
/// The flush failed.
#[doc(hidden)]
#[cfg_attr(not(feature = "fault-injection"), allow(unused_variables))]
pub fn flush_file(file: &File, path: &Path) -> io::Result<()> {
    #[cfg(feature = "fault-injection")]
    {
        crate::fault::count_flush();
        if let Some(log) = std::env::var_os("KIT_FLUSH_LOG") {
            append_flush_line(Path::new(&log));
        }
    }
    file.sync_all()?;
    #[cfg(feature = "fault-injection")]
    crate::fault::sync_step(|| crate::fault::SyncStep::Flush(path.to_path_buf()));
    Ok(())
}

/// Append the line of one flush to the log at `path`; a log that cannot be
/// written is skipped, since it only serves tests.
#[cfg(feature = "fault-injection")]
fn append_flush_line(path: &Path) {
    if let Ok(mut log) = fs::OpenOptions::new().append(true).create(true).open(path) {
        // One write, so processes that share the log do not interleave lines.
        let _ = log.write_all(b"full\n");
    }
}

/// Report one writeout to the test hook. A writeout is a device operation
/// that a later flush covers, so it is not counted as a flush.
#[cfg_attr(not(feature = "fault-injection"), allow(unused_variables))]
pub(crate) fn note_writeout(path: &Path) {
    #[cfg(feature = "fault-injection")]
    crate::fault::sync_step(|| crate::fault::SyncStep::Writeout(path.to_path_buf()));
}

/// Flush a directory, making the renames, links and removals already done in
/// it durable. A missing `dir` counts as success; on Windows, which has no
/// directory flush, this does nothing.
///
/// # Errors
/// The directory could not be opened or flushed.
#[doc(hidden)]
#[cfg(unix)]
pub fn flush_dir(dir: &Path) -> io::Result<()> {
    #[cfg(test)]
    testing::record_dir_sync_call();
    match File::open(dir) {
        Ok(handle) => flush_file(&handle, dir),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Flush a directory. Windows has no directory flush, so this does nothing.
///
/// # Errors
/// Never.
#[doc(hidden)]
#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
pub fn flush_dir(_dir: &Path) -> io::Result<()> {
    #[cfg(test)]
    testing::record_dir_sync_call();
    Ok(())
}

// ---------------------------------------------------------------------------
// One-shot writes
// ---------------------------------------------------------------------------

/// Write a pointer: a temp file beside `dest`, its bytes flushed, a rename
/// over `dest`, then a flush of the directory. Apple makes 2 full flushes;
/// Linux does `fsync(temp)` and `fsync(dir)`.
///
/// # Errors
/// `dest` has no parent directory, or a step failed.
#[doc(hidden)]
pub fn write_pointer(dest: &Path, bytes: &[u8], parents: Parents) -> io::Result<()> {
    pointer_via(&RealSyncer, dest, parents, |file| file.write_all(bytes))
}

/// [`write_pointer`] of a file that users sharing its directory read: it gets
/// the mode `File::create` gives, 0666 less the umask, where [`write_pointer`]
/// makes it private to its owner.
///
/// # Errors
/// As [`write_pointer`].
#[doc(hidden)]
pub fn write_pointer_shared(dest: &Path, bytes: &[u8], parents: Parents) -> io::Result<()> {
    pointer_with(&RealSyncer, dest, parents, Access::Shared, |file| {
        file.write_all(bytes)
    })
}

/// [`write_pointer`] of exactly `len` bytes read from `source`, so a pointer of
/// any size is written with one buffer. A failure to read `source` is the
/// error of `read_exact` on it.
///
/// # Errors
/// As [`write_pointer`], or `source` ended before `len` bytes.
#[doc(hidden)]
pub fn write_pointer_from(
    dest: &Path,
    source: &mut dyn Read,
    len: u64,
    parents: Parents,
) -> io::Result<()> {
    pointer_via(&RealSyncer, dest, parents, |file| {
        copy_exact(file, source, len)
    })
}

/// [`write_pointer_from`] with the mode of [`write_pointer_shared`].
///
/// # Errors
/// As [`write_pointer_from`].
#[doc(hidden)]
pub fn write_pointer_from_shared(
    dest: &Path,
    source: &mut dyn Read,
    len: u64,
    parents: Parents,
) -> io::Result<()> {
    pointer_with(&RealSyncer, dest, parents, Access::Shared, |file| {
        copy_exact(file, source, len)
    })
}

/// A pointer written through `syncer`: the schedule of [`write_pointer`] with
/// the device calls of the store's own seam, so a test sees them.
pub(crate) fn pointer_via(
    syncer: &dyn Syncer,
    dest: &Path,
    parents: Parents,
    fill: impl FnOnce(&mut File) -> io::Result<()>,
) -> io::Result<()> {
    pointer_with(syncer, dest, parents, Access::Private, fill)
}

fn pointer_with(
    syncer: &dyn Syncer,
    dest: &Path,
    parents: Parents,
    access: Access,
    fill: impl FnOnce(&mut File) -> io::Result<()>,
) -> io::Result<()> {
    let parent = prepare_parent(dest, parents)?;
    let mut tmp = temp_file_with(parent, access)?;
    fill(tmp.as_file_mut())?;
    syncer.full(tmp.as_file(), tmp.path())?;
    // A cross-platform atomic replace: rename(2) on Unix, `MoveFileExW` with
    // `MOVEFILE_REPLACE_EXISTING` on Windows.
    syncer.rename(tmp.into_temp_path(), dest)?;
    syncer.dir_sync(parent)
}

/// [`write_pointer`] that fails with `Ok(false)` when `dest` exists, for the
/// `.missing` compare-and-swap of a ref: the caller wants no write at all if
/// `dest` already has anything.
///
/// The bytes go to a sibling temp file first and are renamed into place with
/// replace-existing disabled, so a crash mid-write leaves only the temp file,
/// never a half-written `dest` that a later reader would see as a corrupt ref.
/// (Writing straight into `dest` with `O_EXCL` poisons the slot on a partial
/// write.) The rename is `renameat2(RENAME_NOREPLACE)` on Linux, `link(2)` and
/// `unlink(2)` on other Unix, and `MoveFileExW` without
/// `MOVEFILE_REPLACE_EXISTING` on Windows.
///
/// # Errors
/// As [`write_pointer`]. An existing `dest` is `Ok(false)`, not an error.
#[doc(hidden)]
pub fn write_pointer_new(dest: &Path, bytes: &[u8], parents: Parents) -> io::Result<bool> {
    pointer_new_with(dest, bytes, parents, Access::Private)
}

/// [`write_pointer_new`] with the mode of [`write_pointer_shared`].
///
/// # Errors
/// As [`write_pointer_new`].
#[doc(hidden)]
pub fn write_pointer_new_shared(dest: &Path, bytes: &[u8], parents: Parents) -> io::Result<bool> {
    pointer_new_with(dest, bytes, parents, Access::Shared)
}

fn pointer_new_with(
    dest: &Path,
    bytes: &[u8],
    parents: Parents,
    access: Access,
) -> io::Result<bool> {
    let parent = prepare_parent(dest, parents)?;
    let mut tmp = temp_file_with(parent, access)?;
    tmp.as_file_mut().write_all(bytes)?;
    flush_file(tmp.as_file(), tmp.path())?;
    // A failed rename returns the temp file, which drops and unlinks it:
    // nothing leaks.
    if RealSyncer.rename_new(tmp.into_temp_path(), dest)? {
        flush_dir(parent)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Write a cache record: a temp file beside `dest` and a rename, with no
/// writeout and no flush. A power loss can leave the old bytes, no file, or a
/// shorter file, so the reader of a cache record must accept a missing, stale
/// or torn one: a lost record costs the next command more work and nothing
/// else. A pointer that something else orders against uses [`write_pointer`].
///
/// # Errors
/// As [`write_pointer`].
#[doc(hidden)]
pub fn write_cache(dest: &Path, bytes: &[u8], parents: Parents) -> io::Result<()> {
    let parent = prepare_parent(dest, parents)?;
    let mut tmp = temp_file_in(parent)?;
    tmp.as_file_mut().write_all(bytes)?;
    tmp.persist(dest).map_err(|e| e.error)?;
    Ok(())
}

/// Write `bytes` to `dest` with the content flushed before the rename but the
/// directory flush left to the caller: the durable-before-visible primitive of
/// [`crate::store::BulkWriter`]. The object's bytes are on stable storage
/// before the rename publishes it, so a concurrent process that dedups
/// against the now-visible object can never reference non-durable content.
/// The rename itself becomes durable when the caller flushes the shard
/// directory at commit.
///
/// [`crate::store::BulkWriter`]: crate::store::BulkWriter
pub(crate) fn write_content_synced(dest: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = parent_of(dest)?;
    let mut tmp = temp_file_in(parent)?;
    tmp.as_file_mut().write_all(bytes)?;
    flush_file(tmp.as_file(), tmp.path())?;
    tmp.persist(dest).map_err(|e| e.error)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

static GROUP_IDS: AtomicU64 = AtomicU64::new(1);

/// A temp file written out and not yet visible. Dropping it unlinks the temp
/// file.
#[derive(Debug)]
#[must_use = "a staged file is invisible until it is published"]
pub struct Staged {
    group: u64,
    /// The group's clock when the file was written out.
    at: u64,
    temp: TempPath,
    dest: PathBuf,
}

/// Proof that a flush completed after every write the group had made up to a
/// point. [`Group::publish`] needs one.
#[derive(Debug)]
#[must_use = "a token is the proof that a publish needs"]
pub struct Flushed {
    group: u64,
    /// The group's clock when the flush ran.
    upto: u64,
}

/// Writes that share flushes. Not `Sync`: one per command thread. See the
/// [module docs](self).
#[derive(Debug)]
pub struct Group {
    id: u64,
    syncer: Arc<dyn Syncer>,
    /// Counts the group's writeouts and renames.
    clock: u64,
    /// The clock at the group's latest rename, zero before any.
    last_rename: u64,
    /// The devices written to since the last flush, each with the directories
    /// written in on it: the flush is anchored at the first one still there.
    pending: BTreeMap<u64, Vec<PathBuf>>,
    failed: bool,
}

impl Default for Group {
    fn default() -> Self {
        Self::new()
    }
}

impl Group {
    /// A group on the real device calls.
    #[must_use]
    pub fn new() -> Self {
        Self::with_syncer(Arc::new(RealSyncer))
    }

    pub(crate) fn with_syncer(syncer: Arc<dyn Syncer>) -> Self {
        Self {
            id: GROUP_IDS.fetch_add(1, Ordering::Relaxed),
            syncer,
            clock: 0,
            last_rename: 0,
            pending: BTreeMap::new(),
            failed: false,
        }
    }

    fn live(&self) -> io::Result<()> {
        if self.failed {
            Err(io::Error::other(
                "an earlier writeout or flush failed; the group writes no more",
            ))
        } else {
            Ok(())
        }
    }

    /// Poison the group when a writeout or flush fails.
    fn guard<T>(&mut self, result: io::Result<T>) -> io::Result<T> {
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    /// Record a writeout of an item in the directory `anchor`, which also
    /// anchors the flush of its device. A directory that is gone has no device,
    /// and there is nothing left to flush for it.
    fn wrote(&mut self, anchor: &Path) {
        self.clock += 1;
        if let Some(device) = self.syncer.device_of(anchor) {
            let anchors = self.pending.entry(device).or_default();
            if !anchors.iter().any(|known| known == anchor) {
                anchors.push(anchor.to_path_buf());
            }
        }
    }

    /// Write `bytes` to a temp file beside `dest` and write it out. The file
    /// is invisible until [`Group::publish`].
    ///
    /// # Errors
    /// `dest` has no parent, a step failed, or the group is poisoned. A failed
    /// writeout poisons the group.
    pub fn stage(&mut self, dest: &Path, bytes: &[u8], parents: Parents) -> io::Result<Staged> {
        self.stage_with(dest, parents, |file| file.write_all(bytes))
    }

    /// [`Group::stage`] of exactly `len` bytes read from `source`.
    ///
    /// # Errors
    /// As [`Group::stage`], or `source` ended before `len` bytes.
    pub fn stage_from(
        &mut self,
        dest: &Path,
        source: &mut dyn Read,
        len: u64,
        parents: Parents,
    ) -> io::Result<Staged> {
        self.stage_with(dest, parents, |file| copy_exact(file, source, len))
    }

    fn stage_with(
        &mut self,
        dest: &Path,
        parents: Parents,
        fill: impl FnOnce(&mut File) -> io::Result<()>,
    ) -> io::Result<Staged> {
        self.live()?;
        let parent = prepare_parent(dest, parents)?;
        let mut tmp = temp_file_in(parent)?;
        fill(tmp.as_file_mut())?;
        let written = self.syncer.writeout(tmp.as_file(), tmp.path());
        self.guard(written)?;
        self.wrote(parent);
        Ok(Staged {
            group: self.id,
            at: self.clock,
            temp: tmp.into_temp_path(),
            dest: dest.to_path_buf(),
        })
    }

    /// Write out a file that other code wrote: an appended log, a reused
    /// object, a dedup shard.
    ///
    /// # Errors
    /// The file could not be opened or written out, or the group is poisoned.
    /// A failed writeout poisons the group.
    pub fn note_file(&mut self, path: &Path) -> io::Result<()> {
        self.live()?;
        let mut options = fs::OpenOptions::new();
        if cfg!(unix) {
            options.read(true);
        } else {
            // `FlushFileBuffers` needs a write handle.
            options.write(true);
        }
        let file = options.open(path)?;
        let written = self.syncer.writeout(&file, path);
        self.guard(written)?;
        // A bare file name lives in the current directory.
        let dir = match path.parent() {
            Some(parent) if parent.as_os_str().is_empty() => Path::new("."),
            Some(parent) => parent,
            None => path,
        };
        self.wrote(dir);
        Ok(())
    }

    /// Write out the entries of a directory: made by renames, links or
    /// removals. A missing `dir` counts as written out.
    ///
    /// # Errors
    /// The directory could not be written out, or the group is poisoned. A
    /// failed writeout poisons the group.
    pub fn note_dir(&mut self, dir: &Path) -> io::Result<()> {
        self.live()?;
        let written = self.syncer.dir_writeout(dir);
        self.guard(written)?;
        self.wrote(dir);
        Ok(())
    }

    /// An ordering point: one full flush for each device written to since the
    /// last one, and none where every writeout is already durable. The token
    /// covers every write and rename the group has made so far.
    ///
    /// # Errors
    /// A flush failed, every directory the group wrote in on a device is gone
    /// or moved, or the group is poisoned. A failed flush poisons the group.
    pub fn flush(&mut self) -> io::Result<Flushed> {
        self.live()?;
        let anchors = std::mem::take(&mut self.pending);
        if self.syncer.writeouts_need_flush() {
            for (device, dirs) in &anchors {
                // A flush on any directory of the device covers every writeout
                // on it. A directory that is gone or moved since its write is
                // no anchor, since the open of a gone one would fail quietly:
                // use one that is still on the device before and after, and
                // when there is none the writeouts could not be flushed, which
                // fails the group.
                let mut flushed = false;
                for dir in dirs {
                    if self.syncer.device_of(dir) != Some(*device) {
                        continue;
                    }
                    let result = self.syncer.flush(dir);
                    self.guard(result)?;
                    if self.syncer.device_of(dir) == Some(*device) {
                        flushed = true;
                        break;
                    }
                }
                if !flushed {
                    let result = Err(io::Error::other(
                        "a directory the group wrote in is gone: its writeouts cannot be flushed",
                    ));
                    return self.guard(result);
                }
            }
        }
        Ok(Flushed {
            group: self.id,
            upto: self.clock,
        })
    }

    /// Rename a staged file into place, replacing what is there, then write
    /// out its directory.
    ///
    /// # Errors
    /// `after` is not a token of this group from a flush that came after the
    /// file's writeout and after every earlier rename of the group; the
    /// rename failed; or the group is poisoned. The staged file is dropped,
    /// and its temp file unlinked, on any error.
    pub fn publish(&mut self, staged: Staged, after: &Flushed) -> io::Result<()> {
        self.live()?;
        self.covered(&staged, after)?;
        let parent = parent_of(&staged.dest)?.to_path_buf();
        self.clock += 1;
        self.last_rename = self.clock;
        self.syncer.rename(staged.temp, &staged.dest)?;
        self.note_dir(&parent)
    }

    /// [`Group::publish`] that leaves an existing `dest` alone: `Ok(false)`
    /// drops the staged file and renames nothing.
    ///
    /// # Errors
    /// As [`Group::publish`].
    pub fn publish_new(&mut self, staged: Staged, after: &Flushed) -> io::Result<bool> {
        self.live()?;
        self.covered(&staged, after)?;
        let parent = parent_of(&staged.dest)?.to_path_buf();
        if !self.syncer.rename_new(staged.temp, &staged.dest)? {
            return Ok(false);
        }
        self.clock += 1;
        self.last_rename = self.clock;
        self.note_dir(&parent)?;
        Ok(true)
    }

    /// Whether `after` shows a flush of this group that came after `staged`'s
    /// writeout and after the group's latest rename, so that what the rename
    /// depends on is durable.
    fn covered(&self, staged: &Staged, after: &Flushed) -> io::Result<()> {
        if staged.group != self.id || after.group != self.id {
            return Err(io::Error::other(
                "the file or the token is of another group",
            ));
        }
        if after.upto < staged.at || after.upto < self.last_rename {
            return Err(io::Error::other(
                "no flush since the file's writeout and the group's last rename",
            ));
        }
        Ok(())
    }

    /// The last flush: make everything written since the previous one durable.
    ///
    /// # Errors
    /// As [`Group::flush`].
    pub fn finish(mut self) -> io::Result<()> {
        self.flush().map(drop)
    }
}

/// Test-only directory-flush call counter.
///
/// [`flush_dir`] is the single choke point every directory flush in this
/// crate goes through, whether the call is a one-shot write, a ref write, or
/// one of [`crate::store`]'s syncers. A per-thread counter (rather than a
/// process-global one) lets tests run under the default parallel test
/// harness without a lock: `cargo test` gives each `#[test]` its own OS
/// thread, so one test's count can never be perturbed by another running
/// concurrently.
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
    /// asserts a call count, so any directory flushes performed by earlier
    /// setup (`fresh_repo`, etc.) on the same thread aren't counted.
    pub(crate) fn reset_dir_sync_calls() {
        DIR_SYNC_CALLS.with(|c| c.set(0));
    }

    /// This thread's directory-flush count since the last
    /// [`reset_dir_sync_calls`].
    #[must_use]
    pub(crate) fn dir_sync_calls() -> u64 {
        DIR_SYNC_CALLS.with(Cell::get)
    }
}

#[cfg(test)]
mod tests;

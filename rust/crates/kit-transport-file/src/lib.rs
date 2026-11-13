#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]
#![doc = include_str!("../README.md")]
//!
//! Local-filesystem [`Transport`] implementation.
//!
//! This is a real local/served transport, not a test-only fixture: it is
//! the backend for `kit+file://` remotes and for repositories served via
//! `kit serve`. It also doubles as the in-tree test transport.
//!
//! Stores pack files under `<root>/packs/<64-hex>` and ref files under
//! `<root>/refs/...`.
//!
//! ## On-disk layout
//!
//! ```text
//! <root>/
//!   packs/<64-hex>          — raw pack bytes, written atomically
//!   refs/heads/main         — 65-byte wire (64-hex + '\n')
//!   refs/tags/v1.0          — nested dirs created on demand
//! ```
//!
//! ## CAS atomicity guarantees
//!
//! | Variant   | Mechanism                                              | Race behaviour |
//! |-----------|--------------------------------------------------------|----------------|
//! | `Any`     | `write_atomic`: tmp file → `fsync` → `rename` → parent | Last writer wins. Concurrent writers never expose a half-written file because `rename(2)` is atomic on POSIX. |
//! | `Missing` | `write_create_new`: same tmp+fsync, then a hard-link    | Only the first writer succeeds. If two concurrent callers both see "absent" before writing, only one `link(2)` wins; the other gets `AlreadyExists` → `RefConflict`. |
//! | `Match(H)`| OS file-locks + in-process locks around read-then-`write_atomic` | Atomic across processes on the same on-disk root. The exclusive lock of the ref's stripe, `<root>/.kit/refs/refs-<hh>.lock`, serialises every CAS critical section on that ref; the in-process stripe mutex keeps multi-threaded callers from racing each other before they hit the file lock. |
//!
//! Cross-process atomicity for `Match` is achieved via
//! [`std::fs::File::lock`] (stable as of Rust 1.89) on two files under
//! `<root>/.kit/refs/`. A ref write holds the repo lock `.lock` shared and
//! the exclusive lock of the ref's stripe. The stripe is the first byte of
//! the BLAKE3 digest of the ref name, so `<hh>` is one of 256 lowercase hex
//! values and every process on the root maps a ref to the same file. The
//! locks are held for the duration of the read-compare-write sequence and
//! released on `Drop` (including on panic). The in-process locks are a
//! fast-path optimisation and serialise lock acquisition fairly within one
//! process.
//!
//! Writes to refs in different stripes run in parallel. A write to one
//! ref, or to two refs in one stripe, waits for the earlier one.
//!
//! Every ref write takes these locks, whatever its condition.
//! [`FileTransport::with_ref_lock_for`] hands them to callers that check
//! and write one ref as a step, through [`LockedRef`].
//! [`FileTransport::with_ref_lock`] takes the repo lock exclusive instead,
//! which excludes every ref write, and hands it to callers that read,
//! decide and write several files as one step, through [`LockedRefs`].

#![forbid(unsafe_code)]

use std::fs;
use std::io::{self, ErrorKind, Read, Seek, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, PoisonError, RwLock};

/// Open the pack at `path` for reading, never through a link, and check
/// on the open handle that it is a regular file.
///
/// # Errors
/// The open fails, which includes a link at `path`. A file that is not
/// regular has kind `InvalidInput`.
fn open_pack_file(path: &Path) -> io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_OPEN_REPARSE_POINT: open a link itself, not its target.
        options.custom_flags(0x0020_0000);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "pack is not a regular file",
        ));
    }
    Ok(file)
}

/// Open the lock file at `path` for reading and writing, creating it when it
/// is missing and never through a link. A link at `path` fails the open, so a
/// planted link cannot make a lock create or write a file elsewhere.
///
/// # Errors
/// The open fails, which includes a link at `path`.
fn open_lock_file(path: &Path) -> io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_OPEN_REPARSE_POINT: open a link itself, not its target.
        options.custom_flags(0x0020_0000);
    }
    options.open(path)
}

use kit_core::bounded_read;
use kit_core::hash::Hash;
use kit_core::protocol::{
    AdvanceOutcome, PACK_BODY_LIMIT, PACK_BODY_LIMIT_USIZE, PackKey, RefWriteCondition, RepoCursor,
    Transport, TransportError, TransportResult,
};
use kit_core::refs::{
    REF_FILE_MAX_BYTES, Ref, decode_ref_wire, encode_ref_wire, validate_ref_name,
    validate_ref_name_grammar, validate_ref_prefix,
};

// We need write_atomic and write_create_new from kit_core's private `atomic`
// module. Since they are `pub(crate)`, we re-implement them locally here.
// The logic is identical to `kit_core::atomic`.

use std::process;
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// The next temp-file path beside `dest`: `.kit.tmp.<pid>.<seq>` in `dest`'s
/// directory. The name does not hold `dest`'s name, so it stays short when
/// `dest` has a long name. The sequence comes from one process-wide counter,
/// so two writers in one process never pick the same name, and writers in
/// different processes differ by pid.
///
/// # Errors
/// `InvalidInput` if `dest` has no parent directory or no file name.
fn temp_path(dest: &Path) -> io::Result<PathBuf> {
    let parent = dest
        .parent()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "destination path has no parent"))?;
    if dest.file_name().is_none() {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "destination has no file name",
        ));
    }
    let pid = process::id();
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    Ok(parent.join(format!(".kit.tmp.{pid}.{seq}")))
}

/// Create a new, empty temp file beside `dest`, named `.kit.tmp.<pid>.<seq>`.
/// The file is created with `create_new`, which never follows a link and
/// never truncates: a name that is taken, by a file or a link, is skipped and
/// the next one is tried. Every temp file this crate writes is created here.
/// A streaming writer that publishes into the same layout (a blob store
/// writing `packs/`) creates its temp files here too, so it can never
/// collide with this crate's own writes. The caller removes the file when it
/// fails to publish it.
///
/// # Errors
/// `InvalidInput` if `dest` has no parent directory or no file name. Any
/// other error is the one from creating the file.
pub fn create_temp(dest: &Path) -> io::Result<(PathBuf, fs::File)> {
    loop {
        let path = temp_path(dest)?;
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => return Ok((path, file)),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
}

/// Write `bytes` to a new temp file beside `dest` and fsync it. A failure
/// removes the temp file and returns the original error.
fn write_temp(dest: &Path, bytes: &[u8]) -> io::Result<PathBuf> {
    use std::io::Write;
    let (path, mut file) = create_temp(dest)?;
    if let Err(e) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&path);
        return Err(e);
    }
    Ok(path)
}

/// Atomically write `bytes` to `dest` using a temp-file + fsync +
/// rename + parent-dir-fsync sequence. Creates parent dirs when
/// `make_parents` is `true`. Mirrors `kit_core::atomic::write_atomic`.
fn write_atomic(dest: &Path, bytes: &[u8], make_parents: bool) -> io::Result<()> {
    let parent = dest
        .parent()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "destination path has no parent"))?;
    if make_parents {
        create_dir_all_durably(parent)?;
    }

    let tmp_path = write_temp(dest, bytes)?;

    if let Err(e) = fs::rename(&tmp_path, dest) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    // Make the rename's dirent durable. Propagated (not best-effort
    // discarded): on power loss a swallowed parent-dir fsync could lose a
    // committed ref/pack write. Matches `kit_core::atomic::write_atomic`,
    // which propagates its `sync_parent_dir(parent)?` the same way.
    sync_parent(parent)?;
    Ok(())
}

/// Exclusive-create variant: writes `bytes` to `dest` only if `dest`
/// does not already exist. Returns `Ok(true)` on success, `Ok(false)`
/// if the destination was already present. Mirrors
/// `kit_core::atomic::write_create_new`.
fn write_create_new(dest: &Path, bytes: &[u8], make_parents: bool) -> io::Result<bool> {
    let parent = dest
        .parent()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "destination path has no parent"))?;
    if make_parents {
        create_dir_all_durably(parent)?;
    }

    let tmp_path = write_temp(dest, bytes)?;

    // Hard-link tmp → dest (atomic, fails with AlreadyExists if dest exists).
    match fs::hard_link(&tmp_path, dest) {
        Ok(()) => {
            let _ = fs::remove_file(&tmp_path);
            // Make the hard-link's dirent durable. Propagated (not
            // best-effort discarded): on power loss a swallowed
            // parent-dir fsync could lose a committed ref write. Matches
            // `kit_core::atomic::write_create_new`.
            sync_parent(parent)?;
            Ok(true)
        }
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&tmp_path);
            Ok(false)
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp_path);
            Err(e)
        }
    }
}

/// Fsync a directory, making completed renames/hard-links durable.
///
/// The result is propagated by callers (not discarded) so a power loss
/// cannot silently lose a committed ref/pack write. A `NotFound` is
/// tolerated as success — the directory only vanishes if a concurrent
/// actor removed it, in which case there is nothing left to make
/// durable. Mirrors `kit_core::atomic::sync_parent_dir`.
///
/// Unix-only: opening a directory with a plain [`fs::File::open`] (no
/// `FILE_FLAG_BACKUP_SEMANTICS`) fails on Windows with `ERROR_ACCESS_DENIED`
/// (os error 5) — this crate's `write_atomic`/`write_create_new` were
/// silently failing every ref/pack write on Windows through this path
/// before the platform split below was added (caught by the `windows-smoke`
/// CI job; `kit_core::atomic::sync_parent_dir`, which this mirrors, already
/// had this split). Directory-fsync is a POSIX durability idiom with no
/// direct Windows equivalent reachable from safe `std::fs`, so the
/// non-Unix arm is a deliberate no-op, not a partial implementation.
#[cfg(unix)]
fn sync_parent(dir: &Path) -> io::Result<()> {
    match fs::File::open(dir) {
        Ok(d) => d.sync_all(),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn sync_parent(_dir: &Path) -> io::Result<()> {
    Ok(())
}

/// Fsync directory `dir`, making the renames, links and removals already
/// done in it durable: what every write of this crate does after its
/// rename. A missing `dir` counts as success; on non-Unix targets this is a
/// no-op (see `sync_parent`). For writers that publish into the same
/// layout with their own temp file (see [`create_temp`]).
///
/// # Errors
/// The directory could not be opened or synced.
pub fn sync_dir(dir: &Path) -> io::Result<()> {
    sync_parent(dir)
}

/// [`fs::create_dir_all`], then fsync the parent of every directory it
/// created, top-most first, so a file later published in `dir` does not
/// vanish with its directory on power loss. A no-op when `dir` exists.
///
/// # Errors
/// A directory could not be created or a parent could not be synced.
pub fn create_dir_all_durably(dir: &Path) -> io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    let missing: Vec<&Path> = dir
        .ancestors()
        .take_while(|d| !d.as_os_str().is_empty() && !d.exists())
        .collect();
    fs::create_dir_all(dir)?;
    for created in missing.iter().rev() {
        if let Some(parent) = created.parent().filter(|p| !p.as_os_str().is_empty()) {
            sync_parent(parent)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Cross-process ref lock
// ---------------------------------------------------------------------------

/// Number of per-ref lock files under `<root>/.kit/refs/`. A ref maps to
/// one of them by the first byte of the BLAKE3 digest of its full name, so
/// every process on a root agrees on the mapping and the number of lock
/// files stays fixed however many refs the root holds.
const REF_LOCK_STRIPES: usize = 256;

/// Bytes of a stripe version: the count of writes to refs in the stripe,
/// little-endian, at the start of the stripe's lock file (SPEC-REFS
/// §5.1.2). An empty lock file counts zero.
const STRIPE_VERSION_LEN: usize = 8;

/// The file under `<root>/.kit/refs/` that holds the root's random id.
const REPO_ID_FILE: &str = ".repo-id";

/// Bytes of the root's random id.
const REPO_ID_LEN: usize = 16;

/// Domain separator of the file transport's repository cursor digest.
const REPO_CURSOR_DOMAIN: &[u8] = b"kit.file-repo-cursor\0";

/// How old the modification time of every ref directory must be before
/// the file transport offers a cursor. A file system stamps times at a
/// coarse granularity (a clock tick on Linux, up to 2 s on FAT), so two
/// writes close together can leave one time. A time older than this window
/// changes on any later write.
const RACY_WINDOW: std::time::Duration = std::time::Duration::from_secs(2);

/// The most ref directories a cursor covers. A root with more offers none.
const MAX_CURSOR_DIRS: usize = 1 << 16;

/// The stripe version at the start of `file`. Zero for an empty file; any
/// length but zero and [`STRIPE_VERSION_LEN`] is `InvalidData`.
fn read_stripe_version(mut file: &fs::File) -> io::Result<u64> {
    let mut buf = [0u8; STRIPE_VERSION_LEN + 1];
    file.seek(io::SeekFrom::Start(0))?;
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    match filled {
        0 => Ok(0),
        STRIPE_VERSION_LEN => {
            let mut le = [0u8; STRIPE_VERSION_LEN];
            le.copy_from_slice(&buf[..STRIPE_VERSION_LEN]);
            Ok(u64::from_le_bytes(le))
        }
        _ => Err(io::Error::new(
            ErrorKind::InvalidData,
            "stripe lock file holds no version",
        )),
    }
}

/// Add one to the stripe version in `file`.
fn bump_version_in(mut file: &fs::File) -> io::Result<()> {
    let next = read_stripe_version(file)?.wrapping_add(1);
    file.seek(io::SeekFrom::Start(0))?;
    file.write_all(&next.to_le_bytes())
}

/// The kernel's boot id, which changes on every boot. `None` where the
/// system offers none.
fn boot_id() -> Option<Vec<u8>> {
    const BOOT_ID_MAX: u64 = 64;
    if !cfg!(target_os = "linux") {
        return None;
    }
    bounded_read::read_capped(Path::new("/proc/sys/kernel/random/boot_id"), BOOT_ID_MAX)
        .ok()
        .filter(|id| !id.is_empty())
}

/// The lock stripe of the ref `name`: the first byte of the BLAKE3 digest
/// of its UTF-8 bytes.
fn ref_stripe(name: &str) -> usize {
    usize::from(kit_core::hash::hash(name.as_bytes())[0])
}

/// The lock file of stripe `stripe` under `<root>/.kit/refs/`:
/// `refs-<hh>.lock`, `<hh>` the stripe as two lowercase hex digits.
fn stripe_lock_file(stripe: usize) -> String {
    format!("refs-{stripe:02x}.lock")
}

/// RAII guard around an OS-level file lock under `<root>/.kit/refs/`. The
/// repo lock `.lock` is held exclusive by a step that reads and writes
/// several files as one ([`FileTransport::with_ref_lock`]) and shared by a
/// single-ref write ([`FileTransport::with_ref_lock_for`]). A stripe lock
/// `refs-<hh>.lock` is held exclusive by a single-ref write, so writes to
/// refs in different stripes run in parallel and writes to one ref never
/// do. The order is the repo lock first, then the stripe lock.
///
/// On `Drop` (including on panic-unwind) the kernel releases the lock
/// when the underlying `File` handle is closed; we also call
/// [`std::fs::File::unlock`] explicitly to surface any I/O error in
/// debug builds via the panic path (it is otherwise silently
/// discarded — best-effort).
///
/// We deliberately do **not** lock the ref file itself. Refs are
/// written via tmp + atomic `rename`, which produces a brand-new inode
/// each time; a lock taken on the previous inode would migrate to an
/// abandoned file and stop providing mutual exclusion.
///
/// Locks block until they can be taken; ref updates are user-driven and
/// waiting is the desired behaviour.
#[must_use = "lock is released on drop; bind to a named guard"]
struct RefLock {
    file: fs::File,
}

/// How a [`RefLock`] is held.
#[derive(Clone, Copy)]
enum LockMode {
    Shared,
    Exclusive,
}

impl RefLock {
    /// Acquire the exclusive repo lock on `<root>/.kit/refs/.lock`,
    /// creating the lock file (and its parent directories) on first
    /// use. Blocks until the lock can be taken.
    fn acquire(root: &Path) -> io::Result<Self> {
        Self::open(root, ".lock", LockMode::Exclusive)
    }

    /// Acquire the repo lock shared. It conflicts only with an exclusive
    /// holder.
    fn acquire_shared(root: &Path) -> io::Result<Self> {
        Self::open(root, ".lock", LockMode::Shared)
    }

    /// Acquire the exclusive lock of one stripe.
    fn acquire_stripe(root: &Path, stripe: usize) -> io::Result<Self> {
        Self::open(root, &stripe_lock_file(stripe), LockMode::Exclusive)
    }

    fn open(root: &Path, file_name: &str, mode: LockMode) -> io::Result<Self> {
        let lock_dir = kit_core::layout::RepoLayout::single(root).refs_dir();
        fs::create_dir_all(&lock_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Best-effort: tighten parent dir permissions to 0700 on
            // creation. Ignore errors on filesystems that do not
            // support POSIX permissions (e.g. FAT-on-removable-media).
            let _ = fs::set_permissions(&lock_dir, fs::Permissions::from_mode(0o700));
        }

        let lock_path = lock_dir.join(file_name);
        let file = open_lock_file(&lock_path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600));
        }

        // Blocking lock. Stable since Rust 1.89.
        match mode {
            LockMode::Shared => file.lock_shared()?,
            LockMode::Exclusive => file.lock()?,
        }
        Ok(Self { file })
    }
}

impl Drop for RefLock {
    fn drop(&mut self) {
        // Best-effort explicit unlock. The kernel also releases when
        // the file handle is closed, which covers the panic-unwind
        // path.
        let _ = self.file.unlock();
    }
}

// ---------------------------------------------------------------------------
// FileTransport
// ---------------------------------------------------------------------------

/// Local-filesystem transport. Every instance holds a root `PathBuf`
/// and the in-process mirrors of the ref locks. Cross-process atomicity
/// is supplied separately by `RefLock`: a ref write holds the repo lock
/// `<root>/.kit/refs/.lock` shared and the exclusive lock of the ref's
/// stripe, and a multi-file step holds the repo lock exclusive.
///
/// The in-process locks are unit-typed (zero overhead when uncontended);
/// pack I/O does **not** acquire them.
#[derive(Debug)]
pub struct FileTransport {
    root: PathBuf,
    /// Mirrors the repo lock within a single process: read for a
    /// single-ref write, write for a multi-file step.
    repo_gate: RwLock<()>,
    /// Mirrors the stripe locks within a single process.
    stripe_gates: Box<[Mutex<()>]>,
}

/// Canonicalize `path`, or — if it does not exist yet — canonicalize its
/// closest existing ancestor and re-attach the not-yet-created trailing
/// components. This resolves any symlinked parent already on disk while
/// still yielding the full intended path (comparing only the ancestor
/// would wrongly reject legitimate writes when the root itself does not
/// exist yet). Returns `None` only if nothing along the ancestor chain
/// can be canonicalized.
fn canonicalize_with_missing_tail(path: &Path) -> Option<PathBuf> {
    if let Ok(c) = fs::canonicalize(path) {
        return Some(c);
    }
    let mut ancestor = path.parent();
    while let Some(p) = ancestor {
        if let Ok(c) = fs::canonicalize(p) {
            return Some(match path.strip_prefix(p) {
                Ok(rel) => c.join(rel),
                Err(_) => c,
            });
        }
        ancestor = p.parent();
    }
    None
}

impl FileTransport {
    /// Create a `FileTransport` rooted at `root`. The root directory does
    /// not need to exist yet: sub-directories (`packs/`, `refs/`) and the
    /// root itself are created on demand by the write paths. The
    /// path-escape guard canonicalises the root lazily at use time, so a
    /// root that does not exist at construction (or one that lives under a
    /// symlinked parent, e.g. macOS `/tmp` -> `/private/tmp`) does not
    /// spuriously trip the guard.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            repo_gate: RwLock::new(()),
            stripe_gates: (0..REF_LOCK_STRIPES).map(|_| Mutex::new(())).collect(),
        }
    }

    /// Resolve the comparison base for the path-escape guard: the
    /// canonical form of `root` if it (or its closest existing ancestor)
    /// exists on disk, else the literal `root`.
    ///
    /// Computed lazily on every guard check rather than cached at
    /// construction. Caching the construction-time value silently disables
    /// the guard whenever the root does not exist yet (it would store the
    /// non-canonical literal path) or lives under a symlinked parent: a
    /// legitimate ref then canonicalises to the resolved `/private/...`
    /// form which does not start with the stored `/tmp/...` prefix, so the
    /// guard rejects valid writes. Re-deriving here keeps the base
    /// canonical once the directory exists.
    fn canonical_root(&self) -> PathBuf {
        canonicalize_with_missing_tail(&self.root).unwrap_or_else(|| self.root.clone())
    }

    /// [`RefFileError::MetaElsewhere`] if the root carries
    /// [`SERVER_META_MARKER`]. A marker that cannot be checked is refused
    /// too (fail closed).
    fn refuse_if_meta_elsewhere(&self) -> Result<(), RefFileError> {
        let marker = self.root.join(SERVER_META_MARKER);
        match fs::symlink_metadata(&marker) {
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Ok(_) => Err(RefFileError::MetaElsewhere(marker)),
            Err(e) => Err(RefFileError::Io(e)),
        }
    }

    fn pack_path(&self, key: &PackKey) -> PathBuf {
        self.root.join("packs").join(key.to_hex())
    }

    fn ref_path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    /// Path-escape guard: verify that `path` (whether it already exists
    /// or not) resolves under the (lazily canonicalised) transport root.
    /// Returns `Ok(())` on success, or a `RemoteError` if the operation
    /// would escape the transport tree via a pre-existing symlink.
    ///
    /// - If `path` exists, `canonicalize(path)` is compared against the
    ///   canonical root. A canonicalize failure here (e.g. `EACCES`/`ELOOP`
    ///   on a component) is a hard error — fail closed rather than fall
    ///   back to a lenient check on a path-traversal boundary.
    /// - If `path` does not exist yet, [`canonicalize_with_missing_tail`]
    ///   canonicalises its closest existing ancestor (following any
    ///   symlinked parent already on disk) and re-attaches the missing
    ///   tail; that result must sit under the canonical root.
    fn check_ref_path(&self, path: &Path) -> TransportResult<()> {
        let canonical_root = self.canonical_root();
        let resolved = if path.exists() {
            fs::canonicalize(path).map_err(|e| {
                TransportError::RemoteError(format!("canonicalize ref path failed: {e}"))
            })?
        } else {
            canonicalize_with_missing_tail(path).unwrap_or_else(|| path.to_path_buf())
        };

        if resolved.starts_with(&canonical_root) {
            Ok(())
        } else {
            Err(TransportError::RemoteError(format!(
                "path escape: {} resolves outside transport root",
                path.display()
            )))
        }
    }

    /// The transport root: `packs/`, `refs/` and `.kit/` live under it.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Run `f` holding the exclusive ref lock: this transport's in-process
    /// write gate, then the OS exclusive lock on `<root>/.kit/refs/.lock`
    /// (created on first use). It excludes every ref write on the root,
    /// including [`Transport::update_ref`] and [`Self::with_ref_lock_for`],
    /// so what `f` reads, decides and writes through [`LockedRefs`] is one
    /// step that no other writer on the same root, in this process or
    /// another, can interleave with. Blocks until the lock is free. `f` is
    /// synchronous, so nothing holds the lock across an `.await`.
    ///
    /// Use [`Self::with_ref_lock_for`] when the step touches one ref. This
    /// method makes every other writer wait.
    ///
    /// A panic in `f` releases both locks. The in-process gate guards no
    /// data (the state is the files, and every write is one atomic rename),
    /// so a panic never poisons the transport: the next caller recovers it.
    ///
    /// # Errors
    /// [`RefFileError::Io`] if the lock file cannot be created or locked;
    /// `f` did not run.
    pub fn with_ref_lock<T>(
        &self,
        f: impl FnOnce(&LockedRefs<'_>) -> T,
    ) -> Result<T, RefFileError> {
        let _process_guard = self
            .repo_gate
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        let _xproc_guard = RefLock::acquire(&self.root).map_err(RefFileError::Io)?;
        Ok(f(&LockedRefs { tx: self }))
    }

    /// Run `f` holding the lock of the ref `name` only: the repo lock
    /// shared and the exclusive lock of the ref's stripe, each after its
    /// in-process mirror. What `f` reads and writes through [`LockedRef`]
    /// is one step that no other write to `name`, in this process or
    /// another, can interleave with. Writes to refs in other stripes run
    /// in parallel with it; a write to another ref in the same stripe
    /// waits. A step under [`Self::with_ref_lock`] excludes it.
    ///
    /// A panic in `f` releases the locks and never poisons the transport.
    ///
    /// # Errors
    /// [`RefFileError::InvalidName`] for a name that is not a valid ref
    /// name. [`RefFileError::Io`] if a lock file cannot be created or
    /// locked; `f` did not run.
    pub fn with_ref_lock_for<T>(
        &self,
        name: &str,
        f: impl FnOnce(&LockedRef<'_>) -> T,
    ) -> Result<T, RefFileError> {
        if !validate_ref_name(name) {
            return Err(RefFileError::InvalidName(name.to_owned()));
        }
        let stripe = ref_stripe(name);
        let _repo_guard = self
            .repo_gate
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        let _stripe_guard = self.stripe_gates[stripe]
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let _repo_lock = RefLock::acquire_shared(&self.root).map_err(RefFileError::Io)?;
        let stripe_lock = RefLock::acquire_stripe(&self.root, stripe).map_err(RefFileError::Io)?;
        Ok(f(&LockedRef {
            tx: self,
            name,
            stripe: &stripe_lock.file,
        }))
    }

    /// Run `f` holding the locks of two refs: the repo lock shared and the
    /// exclusive lock of each ref's stripe, taken in ascending stripe
    /// order and once for two refs in one stripe, each after its
    /// in-process mirror. No write to either ref, in this process or
    /// another, interleaves with `f`.
    fn with_two_ref_locks<T>(
        &self,
        first: &str,
        second: &str,
        step: impl FnOnce() -> T,
    ) -> io::Result<T> {
        let (lo, hi) = {
            let (one, two) = (ref_stripe(first), ref_stripe(second));
            (one.min(two), one.max(two))
        };
        let stripes: &[usize] = if lo == hi { &[lo][..] } else { &[lo, hi][..] };
        let _repo_guard = self
            .repo_gate
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        let _stripe_guards: Vec<_> = stripes
            .iter()
            .map(|&s| {
                self.stripe_gates[s]
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
            })
            .collect();
        let _repo_lock = RefLock::acquire_shared(&self.root)?;
        let _stripe_locks = stripes
            .iter()
            .map(|&s| RefLock::acquire_stripe(&self.root, s))
            .collect::<io::Result<Vec<_>>>()?;
        Ok(step())
    }

    /// The two-ref advance of [`Transport::advance_refs`].
    ///
    /// When both ref files exist, it holds the two refs' locks
    /// ([`Self::with_two_ref_locks`]). A write then replaces an existing
    /// file, so no write to another ref can clash with it. When either
    /// file is missing, the advance creates a ref, and a ref created under
    /// another stripe could clash with it (`refs/heads/a` and
    /// `refs/heads/a/b`). It then holds the repo lock exclusive, which
    /// excludes every other ref write on the root, so the clash check
    /// before the first write decides the outcome.
    #[allow(clippy::too_many_arguments)]
    fn advance_two_refs(
        &self,
        head: &str,
        head_condition: RefWriteCondition,
        head_value: &Hash,
        packmap: &str,
        packmap_condition: RefWriteCondition,
        packmap_value: &Hash,
    ) -> Result<AdvanceOutcome, RefFileError> {
        for name in [head, packmap] {
            if !validate_ref_name(name) {
                return Err(RefFileError::InvalidName(name.to_owned()));
            }
        }
        // One name, or one name below the other, can never both be refs.
        if head == packmap || names_nest(head, packmap) {
            return Err(RefFileError::InvalidName(packmap.to_owned()));
        }
        self.refuse_if_meta_elsewhere()?;
        for name in [head, packmap] {
            self.guard_ref_path(&self.ref_path(name))?;
        }
        let step = TwoRefStep {
            head,
            head_condition,
            head_value,
            packmap,
            packmap_condition,
            packmap_value,
        };
        let under_stripes = self
            .with_two_ref_locks(head, packmap, || {
                let both_exist = [head, packmap].iter().all(|n| {
                    fs::symlink_metadata(self.ref_path(n)).is_ok_and(|m| m.file_type().is_file())
                });
                both_exist.then(|| self.advance_held(&step))
            })
            .map_err(RefFileError::Io)?;
        match under_stripes {
            Some(outcome) => outcome,
            None => self.with_ref_lock(|_| self.advance_held(&step))?,
        }
    }

    /// The checks and writes of a two-ref advance, under its locks: both
    /// conditions first (the packmap's reported first), then the packmap,
    /// then the head. A failed head write puts the packmap's previous
    /// bytes back, so a failed advance changes nothing. A crash between
    /// the writes leaves the new packmap with the old head.
    fn advance_held(&self, step: &TwoRefStep<'_>) -> Result<AdvanceOutcome, RefFileError> {
        let head_path = self.ref_path(step.head);
        let packmap_path = self.ref_path(step.packmap);
        for (name, path) in [(step.packmap, &packmap_path), (step.head, &head_path)] {
            if self.ref_clash(path) {
                return Err(RefFileError::InvalidName(name.to_owned()));
            }
        }
        if !condition_holds(&packmap_path, step.packmap_condition).map_err(RefFileError::Io)? {
            return Ok(AdvanceOutcome::PackmapConflict);
        }
        if !condition_holds(&head_path, step.head_condition).map_err(RefFileError::Io)? {
            return Ok(AdvanceOutcome::HeadConflict);
        }
        let previous = read_previous(&packmap_path).map_err(RefFileError::Io)?;
        match self.write_ref_file(step.packmap, step.packmap_condition, step.packmap_value) {
            Ok(()) => {}
            Err(RefFileError::Conflict) => return Ok(AdvanceOutcome::PackmapConflict),
            Err(e) => return Err(e),
        }
        #[cfg(test)]
        if let Some(fault) = advance_fault::take() {
            match fault {
                advance_fault::Fault::CrashAfterPackmap => {
                    return Err(RefFileError::Io(io::Error::other("injected crash")));
                }
                advance_fault::Fault::FailHead => {
                    self.restore(step.packmap, &packmap_path, previous.as_deref());
                    return Err(RefFileError::Io(io::Error::other("injected head failure")));
                }
            }
        }
        match self.write_ref_file(step.head, step.head_condition, step.head_value) {
            Ok(()) => Ok(AdvanceOutcome::Committed),
            Err(e) => {
                self.restore(step.packmap, &packmap_path, previous.as_deref());
                match e {
                    RefFileError::Conflict => Ok(AdvanceOutcome::HeadConflict),
                    e => Err(e),
                }
            }
        }
    }

    /// Put back a ref file's previous bytes, or remove it if it had none;
    /// best-effort. The caller holds the ref's lock, and the exclusive
    /// repo lock when the file was absent. It changes the ref file again,
    /// so it counts one more write on the ref's stripe (SPEC-REFS §5.1.2).
    fn restore(&self, name: &str, path: &Path, previous: Option<&[u8]>) {
        match previous {
            Some(bytes) => {
                let _ = write_atomic(path, bytes, false);
            }
            None => {
                if remove_durably(path).unwrap_or(false) {
                    self.prune_empty_parents(path, name);
                }
            }
        }
        let _ = self.bump_stripe_version(name);
    }

    /// The ref's id, strictly: like [`Transport::read_ref`], but a ref file
    /// that does not hold a ref wire is [`RefFileError::Corrupt`] rather
    /// than absent. A directory where the ref file would be is no ref, and
    /// no ref lies below a ref file.
    ///
    /// # Errors
    /// [`RefFileError::InvalidName`], [`RefFileError::Escape`] for the
    /// path-escape guard, [`RefFileError::Corrupt`], or I/O.
    pub fn read_ref_strict(&self, name: &str) -> Result<Option<Hash>, RefFileError> {
        if !validate_ref_name(name) {
            return Err(RefFileError::InvalidName(name.to_owned()));
        }
        let path = self.ref_path(name);
        if path.is_dir() {
            return Ok(None);
        }
        if path.exists() {
            self.guard_ref_path(&path)?;
        }
        match bounded_read::read_capped(&path, REF_FILE_MAX_BYTES) {
            Ok(bytes) => decode_ref_wire(&bytes)
                .map(Some)
                .ok_or_else(|| RefFileError::Corrupt(name.to_owned())),
            Err(e) if no_ref_file(&e) => Ok(None),
            Err(e) if e.kind() == ErrorKind::InvalidData => {
                Err(RefFileError::Corrupt(name.to_owned()))
            }
            Err(e) => Err(RefFileError::Io(e)),
        }
    }

    /// Every ref file under `prefix` (a directory, e.g. `refs/`), with its
    /// full name and its id, or `None` for a file whose name is a valid
    /// ref name (by the grammar: a name over
    /// [`kit_core::refs::MAX_REF_NAME_BYTES`] is listed, for the caller to
    /// skip loudly) but that does not hold a ref wire, which
    /// [`Transport::list_refs`] skips silently: the caller decides whether
    /// to skip it loudly or fail. Symlinks, temp and lock files are
    /// skipped, as there. Sorted by name.
    ///
    /// # Errors
    /// [`RefFileError::InvalidName`] for an invalid prefix, or I/O.
    pub fn list_ref_files(
        &self,
        prefix: &str,
    ) -> Result<Vec<(String, Option<Hash>)>, RefFileError> {
        let trimmed = prefix.trim_end_matches('/');
        if !validate_ref_name(trimmed) {
            return Err(RefFileError::InvalidName(prefix.to_owned()));
        }
        let mut out = Vec::new();
        let mut dirs = vec![self.root.join(trimmed)];
        while let Some(dir) = dirs.pop() {
            let entries = match fs::read_dir(&dir) {
                Ok(entries) => entries,
                Err(e) if no_ref_file(&e) => continue,
                Err(e) => return Err(RefFileError::Io(e)),
            };
            for entry in entries {
                let entry = entry.map_err(RefFileError::Io)?;
                let path = entry.path();
                let file_type = entry.file_type().map_err(RefFileError::Io)?;
                if file_type.is_dir() {
                    dirs.push(path);
                    continue;
                }
                let Ok(rel) = path.strip_prefix(&self.root) else {
                    continue;
                };
                let name = rel.to_string_lossy().replace('\\', "/");
                // The grammar without the length bound: a ref file named
                // before SPEC-REFS §3 bounded names is reported, so the
                // caller can skip it loudly.
                if !file_type.is_file() || !validate_ref_name_grammar(&name) {
                    continue; // a symlink, a temp or lock file, or no ref name
                }
                match bounded_read::read_capped(&path, REF_FILE_MAX_BYTES) {
                    Ok(bytes) => out.push((name, decode_ref_wire(&bytes))),
                    // An oversized file is malformed content, like a bad hash.
                    Err(e) if e.kind() == ErrorKind::InvalidData => out.push((name, None)),
                    Err(e) => return Err(RefFileError::Io(e)),
                }
            }
        }
        out.sort();
        Ok(out)
    }

    /// The path of a server-owned file: `rel` must be a plain relative path
    /// (normal components only) under [`SERVER_DIR`], and must not resolve
    /// outside `<root>/.kit/server` through a symlink. The only files
    /// [`LockedRefs::write_file`] and [`LockedRefs::remove_file`] touch.
    ///
    /// # Errors
    /// [`RefFileError::Escape`] for any other path.
    pub fn server_path(&self, rel: &Path) -> Result<PathBuf, RefFileError> {
        let plain = rel.components().all(|c| matches!(c, Component::Normal(_)));
        let inside = rel
            .strip_prefix(SERVER_DIR)
            .is_ok_and(|r| r.components().next().is_some());
        if !plain || !inside {
            return Err(RefFileError::Escape(format!(
                "path escape: {} is not a path under {SERVER_DIR}",
                rel.display()
            )));
        }
        let path = self.root.join(rel);
        let base = self.canonical_root().join(SERVER_DIR);
        let resolved = if path.exists() {
            fs::canonicalize(&path).map_err(RefFileError::Io)?
        } else {
            canonicalize_with_missing_tail(&path).unwrap_or_else(|| path.clone())
        };
        if resolved.starts_with(&base) {
            Ok(path)
        } else {
            Err(RefFileError::Escape(format!(
                "path escape: {} resolves outside {SERVER_DIR}",
                path.display()
            )))
        }
    }

    /// [`Self::check_ref_path`] as a [`RefFileError`].
    fn guard_ref_path(&self, path: &Path) -> Result<(), RefFileError> {
        self.check_ref_path(path).map_err(|e| match e {
            TransportError::RemoteError(msg) => RefFileError::Escape(msg),
            other => RefFileError::Escape(other.to_string()),
        })
    }

    /// Whether writing a ref file at `dest` clashes with another ref: a
    /// directory is where the file would go, or a file is where one of its
    /// directories would go.
    fn ref_clash(&self, dest: &Path) -> bool {
        dest.is_dir()
            || dest
                .ancestors()
                .skip(1)
                .take_while(|d| *d != self.root)
                .any(Path::is_file)
    }

    /// The CAS write of one ref file. The caller holds the ref's lock: the
    /// exclusive repo lock, or the shared repo lock and the ref's stripe.
    ///
    /// Two writers under different stripe locks can race to create a ref
    /// and a ref below it (`refs/heads/a` and `refs/heads/a/b`). One wins.
    /// The other fails, and a failure that leaves a clash on disk is
    /// [`RefFileError::InvalidName`], as the check before the write reports
    /// it, never a bare I/O error or a false conflict.
    /// The CAS write of one ref file, then one more count on its stripe
    /// version (SPEC-REFS §5.1.2) whenever the write may have changed the
    /// file. The caller holds the ref's stripe lock or the repo lock
    /// exclusive.
    fn write_ref_file(
        &self,
        name: &str,
        condition: RefWriteCondition,
        hash: &Hash,
    ) -> Result<(), RefFileError> {
        self.write_ref_file_in(name, condition, hash, None)
    }

    /// [`Self::write_ref_file`], counting through `stripe`, the open lock
    /// file of the ref's stripe, when the caller holds it.
    fn write_ref_file_in(
        &self,
        name: &str,
        condition: RefWriteCondition,
        hash: &Hash,
        stripe: Option<&fs::File>,
    ) -> Result<(), RefFileError> {
        let written = self.write_ref_file_uncounted(name, condition, hash);
        #[cfg(test)]
        tests::BETWEEN_WRITE_AND_COUNT.with(|hook| {
            if let Some(f) = hook.borrow_mut().as_mut() {
                f();
            }
        });
        if matches!(written, Ok(()) | Err(RefFileError::Io(_))) {
            match stripe {
                Some(file) => bump_version_in(file),
                None => self.bump_stripe_version(name),
            }
            .map_err(RefFileError::Io)?;
        }
        written
    }

    /// Count one more write to the stripe of `name`, after the write's
    /// rename. Only a holder of that stripe's lock, or of the repo lock
    /// exclusive, calls this, so the read and the write of the count are
    /// one step.
    fn bump_stripe_version(&self, name: &str) -> io::Result<()> {
        let path = self.lock_dir().join(stripe_lock_file(ref_stripe(name)));
        let file = open_lock_file(&path)?;
        bump_version_in(&file)
    }

    /// `<root>/.kit/refs/`, which holds the lock files.
    fn lock_dir(&self) -> PathBuf {
        kit_core::layout::RepoLayout::single(&self.root).refs_dir()
    }

    /// The repository cursor (SPEC-TRANSPORT §1.2): the BLAKE3 digest of
    /// [`REPO_CURSOR_DOMAIN`], the root's random id, the kernel's boot id
    /// and the 256 stripe versions, then the times of every directory under
    /// `<root>/refs` ([`Self::stamp_ref_dirs`]). Each stripe version is read
    /// under that stripe's lock held shared, after the repo lock held
    /// shared, so no write is half counted. The directories are read under
    /// the same shared repo lock, which excludes a writer that holds it
    /// exclusive and keeps no count. No ref file is read.
    ///
    /// The directory times cover writers that keep no count. While any of
    /// them is less than [`RACY_WINDOW`] old, the transport offers no
    /// cursor, so a client fetches in full. The times are read first, so
    /// such a read reads no count and takes no stripe lock.
    ///
    /// A count is written without fsync. A process crash keeps it, because
    /// the page cache survives the process. An operating system crash can
    /// lose it, and then the boot id changes, so no cursor read before the
    /// crash equals one read after it. Where the boot id cannot be read, the
    /// transport offers no cursor.
    ///
    /// # Errors
    /// [`RefFileError::Corrupt`] for a lock file or id file that holds
    /// neither nothing nor a valid value, or I/O.
    fn repo_cursor_digest(&self) -> Result<Option<Hash>, RefFileError> {
        self.repo_cursor_digest_at(std::time::SystemTime::now())
    }

    /// [`Self::repo_cursor_digest`] read at `now`.
    fn repo_cursor_digest_at(
        &self,
        now: std::time::SystemTime,
    ) -> Result<Option<Hash>, RefFileError> {
        let Some(boot) = boot_id() else {
            return Ok(None);
        };
        let id = self.repo_id()?;
        let mut input = Vec::with_capacity(
            REPO_CURSOR_DOMAIN.len()
                + id.len()
                + boot.len()
                + REF_LOCK_STRIPES * STRIPE_VERSION_LEN,
        );
        input.extend_from_slice(REPO_CURSOR_DOMAIN);
        input.extend_from_slice(&id);
        input.extend_from_slice(&boot);
        let _repo_guard = self
            .repo_gate
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        let _repo_lock = RefLock::acquire_shared(&self.root).map_err(RefFileError::Io)?;
        // The times come first: a fresh one withholds the cursor whatever
        // the counts hold, so such a read takes no stripe lock and never
        // waits behind a write. They are digested after the counts, as
        // before, and both parts are read under one hold of the repo lock.
        let mut stamps = Vec::new();
        if !self.stamp_ref_dirs(now, &mut stamps)? {
            return Ok(None);
        }
        for stripe in 0..REF_LOCK_STRIPES {
            let _stripe_guard = self.stripe_gates[stripe]
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let lock = RefLock::open(&self.root, &stripe_lock_file(stripe), LockMode::Shared)
                .map_err(RefFileError::Io)?;
            let version = read_stripe_version(&lock.file).map_err(|e| {
                if e.kind() == ErrorKind::InvalidData {
                    RefFileError::Corrupt(stripe_lock_file(stripe))
                } else {
                    RefFileError::Io(e)
                }
            })?;
            input.extend_from_slice(&version.to_le_bytes());
        }
        input.extend_from_slice(&stamps);
        Ok(Some(kit_core::hash::hash(&input)))
    }

    /// Append to `out` the path, inode number, modification time and change
    /// time of every directory under `<root>/refs`, sorted by path, or a
    /// marker when there is none. A rename or unlink in a directory changes
    /// its times, so a writer that keeps no stripe count still changes them.
    /// No directory entry is read beyond its type, and no ref file is read.
    ///
    /// `false` when no cursor can be trusted: a directory was modified less
    /// than [`RACY_WINDOW`] before `now` or after it, one vanished during
    /// the walk (a write is in progress), `<root>/refs` is not a directory,
    /// or there are more than [`MAX_CURSOR_DIRS`].
    #[cfg(unix)]
    fn stamp_ref_dirs(
        &self,
        now: std::time::SystemTime,
        out: &mut Vec<u8>,
    ) -> Result<bool, RefFileError> {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::MetadataExt;
        let top = self.root.join("refs");
        match fs::symlink_metadata(&top) {
            Err(e) if e.kind() == ErrorKind::NotFound => {
                out.push(0);
                return Ok(true);
            }
            Err(e) => return Err(RefFileError::Io(e)),
            Ok(meta) if !meta.is_dir() => return Ok(false),
            Ok(_) => {}
        }
        let Some(trusted_before) = now.checked_sub(RACY_WINDOW) else {
            return Ok(false);
        };
        let mut stamps: Vec<(Vec<u8>, [i64; 5])> = Vec::new();
        let mut pending = vec![(Vec::new(), top)];
        while let Some((rel, dir)) = pending.pop() {
            if stamps.len() == MAX_CURSOR_DIRS {
                return Ok(false);
            }
            let meta = match fs::symlink_metadata(&dir) {
                Ok(meta) => meta,
                Err(e) if e.kind() == ErrorKind::NotFound => return Ok(false),
                Err(e) => return Err(RefFileError::Io(e)),
            };
            if !meta.is_dir() || meta.modified().map_err(RefFileError::Io)? >= trusted_before {
                return Ok(false);
            }
            let entries = match fs::read_dir(&dir) {
                Ok(entries) => entries,
                Err(e) if e.kind() == ErrorKind::NotFound => return Ok(false),
                Err(e) => return Err(RefFileError::Io(e)),
            };
            for entry in entries {
                let entry = entry.map_err(RefFileError::Io)?;
                if entry.file_type().map_err(RefFileError::Io)?.is_dir() {
                    let mut sub = rel.clone();
                    sub.push(b'/');
                    sub.extend_from_slice(entry.file_name().as_bytes());
                    pending.push((sub, entry.path()));
                }
            }
            // The inode number fits in an i64 bit for bit; only equality
            // matters.
            #[allow(clippy::cast_possible_wrap)]
            let ino = meta.ino() as i64;
            stamps.push((
                rel,
                [
                    ino,
                    meta.mtime(),
                    meta.mtime_nsec(),
                    meta.ctime(),
                    meta.ctime_nsec(),
                ],
            ));
        }
        stamps.sort();
        out.push(1);
        for (rel, fields) in &stamps {
            out.extend_from_slice(&(rel.len() as u64).to_le_bytes());
            out.extend_from_slice(rel);
            for field in fields {
                out.extend_from_slice(&field.to_le_bytes());
            }
        }
        Ok(true)
    }

    /// No directory times to cover where the platform offers none, so no
    /// cursor.
    #[cfg(not(unix))]
    fn stamp_ref_dirs(
        &self,
        _now: std::time::SystemTime,
        _out: &mut Vec<u8>,
    ) -> Result<bool, RefFileError> {
        Ok(false)
    }

    /// The root's random id, created by the first caller that needs it.
    /// A root that is deleted and created again gets a new one.
    fn repo_id(&self) -> Result<[u8; REPO_ID_LEN], RefFileError> {
        let path = self.lock_dir().join(REPO_ID_FILE);
        let mut fresh = [0u8; REPO_ID_LEN];
        getrandom::fill(&mut fresh)
            .map_err(|e| RefFileError::Io(io::Error::other(e.to_string())))?;
        // Exactly one creator wins the exclusive create; every caller then
        // reads the winner's id.
        write_create_new(&path, &fresh, true).map_err(RefFileError::Io)?;
        let bytes =
            bounded_read::read_capped(&path, REPO_ID_LEN as u64).map_err(RefFileError::Io)?;
        bytes
            .try_into()
            .map_err(|_| RefFileError::Corrupt(REPO_ID_FILE.to_owned()))
    }

    fn write_ref_file_uncounted(
        &self,
        name: &str,
        condition: RefWriteCondition,
        hash: &Hash,
    ) -> Result<(), RefFileError> {
        if !validate_ref_name(name) {
            return Err(RefFileError::InvalidName(name.to_owned()));
        }
        self.refuse_if_meta_elsewhere()?;
        let dest = self.ref_path(name);
        self.guard_ref_path(&dest)?;
        if self.ref_clash(&dest) {
            return Err(RefFileError::InvalidName(name.to_owned()));
        }
        let wire = encode_ref_wire(hash);
        let clashed = |e: io::Error| {
            if self.ref_clash(&dest) {
                RefFileError::InvalidName(name.to_owned())
            } else {
                RefFileError::Io(e)
            }
        };

        match condition {
            // Unconditional atomic overwrite.
            RefWriteCondition::Any => write_atomic(&dest, &wire, true).map_err(clashed),

            RefWriteCondition::Missing => {
                // Exclusive create: succeeds only when the file is absent.
                match write_create_new(&dest, &wire, true) {
                    Ok(true) => Ok(()),
                    Ok(false) if dest.is_dir() => Err(RefFileError::InvalidName(name.to_owned())),
                    Ok(false) => Err(RefFileError::Conflict),
                    Err(e) => Err(clashed(e)),
                }
            }

            RefWriteCondition::Match(expected) => {
                match read_ref_raw(&dest).map_err(RefFileError::Io)? {
                    Some(c) if c == expected => {}
                    _ => return Err(RefFileError::Conflict),
                }
                write_atomic(&dest, &wire, true).map_err(clashed)
            }
        }
    }

    /// Remove the directories between `path` and `<root>/<first component
    /// of name>` that are empty, innermost first; best-effort.
    fn prune_empty_parents(&self, path: &Path, name: &str) {
        let stop = self.root.join(name.split('/').next().unwrap_or(name));
        for dir in path.ancestors().skip(1) {
            if dir == stop || !dir.starts_with(&stop) || fs::remove_dir(dir).is_err() {
                break;
            }
            if let Some(parent) = dir.parent() {
                let _ = sync_parent(parent);
            }
        }
    }
}

/// The directory, under a [`FileTransport`] root, of files a server keeps
/// next to the refs ([`LockedRefs::write_file`]).
pub const SERVER_DIR: &str = ".kit/server";

/// The marker, under a [`FileTransport`] root, that a SQLite-metadata
/// server deployment writes: the root's refs live in that server's
/// `SQLite` database, not in ref files. Every ref write through this
/// transport refuses a marked root ([`RefFileError::MetaElsewhere`]), so a
/// local push or `kit serve` cannot keep a second, diverging copy of the
/// refs. Reads still work.
pub const SERVER_META_MARKER: &str = ".kit/server-meta";

/// Why a strict ref-file operation ([`LockedRefs`],
/// [`FileTransport::read_ref_strict`], [`FileTransport::list_ref_files`],
/// [`FileTransport::server_path`]) failed. It converts into the
/// [`TransportError`] the [`Transport`] verbs return.
#[derive(Debug)]
#[non_exhaustive]
pub enum RefFileError {
    /// Not a valid ref name, or the ref clashes with another: a directory
    /// is where its file would go, or a file where its directory would.
    InvalidName(String),
    /// A path the operation may not touch: outside [`SERVER_DIR`], or
    /// resolving outside the root through a symlink.
    Escape(String),
    /// The CAS condition did not hold.
    Conflict,
    /// A ref file exists but does not hold a ref wire.
    Corrupt(String),
    /// I/O failed.
    Io(io::Error),
    /// The root carries [`SERVER_META_MARKER`]: its refs live in a
    /// server `SQLite` database, so no ref file may be written. The
    /// marker's path.
    MetaElsewhere(PathBuf),
}

impl std::fmt::Display for RefFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MetaElsewhere(marker) => write!(
                f,
                "refusing to write ref files: this root's refs live in a server SQLite \
                 database (marker {}); push to that server instead",
                marker.display()
            ),
            Self::InvalidName(name) => write!(f, "invalid or clashing ref name: {name}"),
            Self::Escape(msg) => f.write_str(msg),
            Self::Conflict => f.write_str("ref CAS precondition failed"),
            Self::Corrupt(name) => write!(f, "ref file {name} does not hold a ref id"),
            Self::Io(e) => write!(f, "ref file I/O error: {e}"),
        }
    }
}

impl std::error::Error for RefFileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<RefFileError> for TransportError {
    fn from(e: RefFileError) -> Self {
        match e {
            RefFileError::InvalidName(name) => Self::InvalidRef(name),
            RefFileError::Conflict => Self::RefConflict,
            other => Self::RemoteError(other.to_string()),
        }
    }
}

/// The ref files (and the server files under [`SERVER_DIR`]) of a
/// [`FileTransport`] root while [`FileTransport::with_ref_lock`] holds the
/// ref lock. Writes are the transport's CAS and atomic writes, without
/// taking the lock again.
#[derive(Debug)]
pub struct LockedRefs<'a> {
    tx: &'a FileTransport,
}

impl LockedRefs<'_> {
    /// The ref's id: [`FileTransport::read_ref_strict`].
    ///
    /// # Errors
    /// As [`FileTransport::read_ref_strict`].
    pub fn read_ref(&self, name: &str) -> Result<Option<Hash>, RefFileError> {
        self.tx.read_ref_strict(name)
    }

    /// The CAS write of [`Transport::update_ref`], under the lock already
    /// held. A ref that clashes with another (a directory where its file
    /// would go, or a file where its directory would) is
    /// [`RefFileError::InvalidName`].
    ///
    /// # Errors
    /// [`RefFileError::InvalidName`], [`RefFileError::Escape`],
    /// [`RefFileError::Conflict`], or I/O.
    pub fn update_ref(
        &self,
        name: &str,
        condition: RefWriteCondition,
        hash: &Hash,
    ) -> Result<(), RefFileError> {
        self.tx.write_ref_file(name, condition, hash)
    }

    /// Remove the ref file, fsync its directory, then remove the
    /// directories it left empty below the name's first component (so
    /// `refs/` stays); `false` if there was no ref file.
    ///
    /// # Errors
    /// [`RefFileError::InvalidName`], [`RefFileError::Escape`], or I/O.
    pub fn delete_ref(&self, name: &str) -> Result<bool, RefFileError> {
        if !validate_ref_name(name) {
            return Err(RefFileError::InvalidName(name.to_owned()));
        }
        self.tx.refuse_if_meta_elsewhere()?;
        let path = self.tx.ref_path(name);
        self.tx.guard_ref_path(&path)?;
        if path.is_dir() {
            return Ok(false);
        }
        let removed = remove_durably(&path);
        // Count the stripe whenever the file may be gone (SPEC-REFS §5.1.2).
        if !matches!(removed, Ok(false)) {
            self.tx
                .bump_stripe_version(name)
                .map_err(RefFileError::Io)?;
        }
        let removed = removed.map_err(RefFileError::Io)?;
        if removed {
            self.tx.prune_empty_parents(&path, name);
        }
        Ok(removed)
    }

    /// Atomically replace the server file at `rel` (see
    /// [`FileTransport::server_path`]) with `bytes`, creating its
    /// directories: the same temp file, fsync, rename and directory fsync
    /// as a ref write.
    ///
    /// # Errors
    /// [`RefFileError::Escape`] for a path outside [`SERVER_DIR`], or I/O.
    pub fn write_file(&self, rel: &Path, bytes: &[u8]) -> Result<(), RefFileError> {
        self.tx.refuse_if_meta_elsewhere()?;
        let path = self.tx.server_path(rel)?;
        write_atomic(&path, bytes, true).map_err(RefFileError::Io)
    }

    /// Remove the server file at `rel` (see [`FileTransport::server_path`]),
    /// then fsync its directory; `false` if it was absent.
    ///
    /// # Errors
    /// [`RefFileError::Escape`] for a path outside [`SERVER_DIR`], or I/O.
    pub fn remove_file(&self, rel: &Path) -> Result<bool, RefFileError> {
        self.tx.refuse_if_meta_elsewhere()?;
        let path = self.tx.server_path(rel)?;
        remove_durably(&path).map_err(RefFileError::Io)
    }
}

/// One ref of a [`FileTransport`] root while
/// [`FileTransport::with_ref_lock_for`] holds that ref's lock. It reads and
/// writes only that ref, so a step under it cannot disturb a write to
/// another ref that runs in parallel.
#[derive(Debug)]
pub struct LockedRef<'a> {
    tx: &'a FileTransport,
    name: &'a str,
    /// The stripe's lock file, held exclusive, which also holds the
    /// stripe version.
    stripe: &'a fs::File,
}

impl LockedRef<'_> {
    /// The ref's id: [`FileTransport::read_ref_strict`].
    ///
    /// # Errors
    /// As [`FileTransport::read_ref_strict`].
    pub fn read(&self) -> Result<Option<Hash>, RefFileError> {
        self.tx.read_ref_strict(self.name)
    }

    /// The CAS write of [`Transport::update_ref`], under the lock already
    /// held.
    ///
    /// # Errors
    /// [`RefFileError::InvalidName`], [`RefFileError::Escape`],
    /// [`RefFileError::Conflict`], or I/O.
    pub fn update(&self, condition: RefWriteCondition, hash: &Hash) -> Result<(), RefFileError> {
        self.tx
            .write_ref_file_in(self.name, condition, hash, Some(self.stripe))
    }
}

/// The arguments of one two-ref advance.
struct TwoRefStep<'a> {
    head: &'a str,
    head_condition: RefWriteCondition,
    head_value: &'a Hash,
    packmap: &'a str,
    packmap_condition: RefWriteCondition,
    packmap_value: &'a Hash,
}

/// Whether one ref name lies below the other (`refs/heads/a` and
/// `refs/heads/a/b`): their files can never both exist.
fn names_nest(a: &str, b: &str) -> bool {
    let below = |x: &str, y: &str| x.strip_prefix(y).is_some_and(|rest| rest.starts_with('/'));
    below(a, b) || below(b, a)
}

/// Whether the write condition holds on the ref file at `path`, as
/// [`FileTransport::write_ref_file`] decides it: `Missing` needs no file
/// at all, `Match` needs the file to hold that id.
fn condition_holds(path: &Path, condition: RefWriteCondition) -> io::Result<bool> {
    match condition {
        RefWriteCondition::Any => Ok(true),
        RefWriteCondition::Missing => match fs::symlink_metadata(path) {
            Ok(_) => Ok(false),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(true),
            Err(e) => Err(e),
        },
        RefWriteCondition::Match(expected) => Ok(read_ref_raw(path)? == Some(expected)),
    }
}

/// The bytes of the ref file at `path`, bounded like every ref read, or
/// `None` when there is no file.
fn read_previous(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match bounded_read::read_capped(path, REF_FILE_MAX_BYTES) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod push_tests;

/// Fault injection for the two-ref advance, in tests only.
#[cfg(test)]
mod advance_fault {
    use std::cell::Cell;

    #[derive(Clone, Copy)]
    pub(super) enum Fault {
        /// Stop after the packmap write, as a crashed process would.
        CrashAfterPackmap,
        /// Fail the head write.
        FailHead,
    }

    thread_local! {
        static NEXT: Cell<Option<Fault>> = const { Cell::new(None) };
    }

    pub(super) fn set(fault: Fault) {
        NEXT.with(|n| n.set(Some(fault)));
    }

    pub(super) fn take() -> Option<Fault> {
        NEXT.with(Cell::take)
    }
}

/// Remove `path`, then fsync its directory; `false` if it was absent.
fn remove_durably(path: &Path) -> io::Result<bool> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    }
    if let Some(parent) = path.parent() {
        sync_parent(parent)?;
    }
    Ok(true)
}

impl Transport for FileTransport {
    // ------------------------------------------------------------------
    // Pack verbs
    // ------------------------------------------------------------------

    fn upload_pack(&self, bytes: &[u8], key: &PackKey) -> TransportResult<()> {
        let dest = self.pack_path(key);
        write_atomic(&dest, bytes, true)
            .map_err(|e| TransportError::RemoteError(format!("upload_pack I/O error: {e}")))
    }

    fn download_pack(&self, key: &PackKey) -> TransportResult<Vec<u8>> {
        let path = self.pack_path(key);
        let io_err = |e: io::Error| match e.kind() {
            ErrorKind::NotFound => TransportError::PackNotFound,
            _ => TransportError::RemoteError(format!("download_pack I/O error: {e}")),
        };
        // The open refuses a link, and the checks read the open handle, so
        // a swap of the path after the open changes nothing.
        let file = open_pack_file(&path).map_err(|e| {
            if e.kind() == ErrorKind::InvalidInput {
                TransportError::RemoteError("download_pack: pack is not a regular file".into())
            } else {
                io_err(e)
            }
        })?;
        let len = file.metadata().map_err(io_err)?.len();
        if len > PACK_BODY_LIMIT {
            return Err(TransportError::PayloadTooLarge(
                usize::try_from(len).unwrap_or(usize::MAX),
            ));
        }
        bounded_read::read_capped_from(file, PACK_BODY_LIMIT).map_err(|e| {
            if e.kind() == ErrorKind::InvalidData {
                TransportError::PayloadTooLarge(PACK_BODY_LIMIT_USIZE.saturating_add(1))
            } else {
                io_err(e)
            }
        })
    }

    fn pack_exists(&self, key: &PackKey) -> TransportResult<bool> {
        Ok(self.pack_path(key).exists())
    }

    // ------------------------------------------------------------------
    // Ref verbs
    // ------------------------------------------------------------------

    fn update_ref(
        &self,
        name: &str,
        condition: RefWriteCondition,
        hash: &Hash,
    ) -> TransportResult<()> {
        if !validate_ref_name(name) {
            return Err(TransportError::InvalidRef(name.to_owned()));
        }
        // Every condition participates: an unconditional write must not
        // interleave between a Match read and its publication.
        Ok(self.with_ref_lock_for(name, |lock| lock.update(condition, hash))??)
    }

    /// Both refs' conditions are checked under both refs' locks before
    /// either is written, then the packmap is written, then the head. A
    /// failed advance changes nothing, and no other writer interleaves.
    ///
    /// Lock-free readers are not excluded: between the two renames they
    /// see the new packmap with the old head, and a crash there leaves
    /// that state on disk. That state is consistent only when the new
    /// packmap also reconstructs the old head's closure: an append and a
    /// re-baseline always do, a reset does only for a fast-forward. So
    /// [`Transport::supports_atomic_advance`] stays `false`, and the
    /// transport offers [`Transport::supports_serialized_advance`]
    /// instead: a client asks it for a reset only of a push that is
    /// a verified fast-forward of the head it conditions on.
    fn advance_refs(
        &self,
        head_ref: &str,
        head_condition: RefWriteCondition,
        head_value: &Hash,
        packmap_ref: &str,
        packmap_condition: RefWriteCondition,
        packmap_value: &Hash,
    ) -> TransportResult<AdvanceOutcome> {
        Ok(self.advance_two_refs(
            head_ref,
            head_condition,
            head_value,
            packmap_ref,
            packmap_condition,
            packmap_value,
        )?)
    }

    /// [`Self::advance_refs`] holds both refs' locks across its checks and
    /// writes, so no other writer interleaves and a conflict changes
    /// nothing. Readers still see its two renames one at a time.
    fn supports_serialized_advance(&self) -> bool {
        true
    }

    fn repo_cursor(&self) -> TransportResult<Option<RepoCursor>> {
        match self.repo_cursor_digest()? {
            Some(digest) => RepoCursor::new(&digest).map(Some),
            None => Ok(None),
        }
    }

    fn read_ref(&self, name: &str) -> TransportResult<Option<Hash>> {
        if !validate_ref_name(name) {
            return Err(TransportError::InvalidRef(name.to_owned()));
        }
        let path = self.ref_path(name);
        // Path-escape guard: if the file already exists, it must
        // canonicalise under the transport root. If it does not exist
        // the read will return `None` via `read_ref_raw` unchanged.
        if path.exists() {
            self.check_ref_path(&path)?;
        }
        read_ref_raw(&path)
            .map_err(|e| TransportError::RemoteError(format!("read_ref I/O error: {e}")))
    }

    fn list_refs(&self, prefix: &str) -> TransportResult<Vec<Ref>> {
        if !validate_ref_prefix(prefix) {
            return Err(TransportError::InvalidRef(prefix.to_owned()));
        }

        let prefix_trimmed = prefix.trim_end_matches('/');
        let dir = if prefix_trimmed.is_empty() {
            self.root.clone()
        } else {
            self.root.join(prefix_trimmed)
        };

        let mut out = Vec::new();
        collect_refs(&dir, &dir, &mut out)?;
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read and decode the hash from a ref file. Returns `None` if no ref
/// file is there ([`no_ref_file`]); propagates other I/O errors.
fn read_ref_raw(path: &Path) -> io::Result<Option<Hash>> {
    ref_from_read(bounded_read::read_capped(path, REF_FILE_MAX_BYTES))
}

/// The ref a capped read of a ref file yields.
fn ref_from_read(read: io::Result<Vec<u8>>) -> io::Result<Option<Hash>> {
    match read {
        Ok(bytes) => Ok(decode_ref_wire(&bytes)),
        Err(e) if no_ref_file(&e) => Ok(None),
        // An oversized file is malformed content, like a bad hash.
        Err(e) if e.kind() == ErrorKind::InvalidData => Ok(None),
        Err(e) => Err(e),
    }
}

/// Whether a failed open or read of a ref path means no ref file is there:
/// the path is missing, a component above it is a ref file (`Not a
/// directory`), or it is a directory of other refs (`Is a directory`).
/// Every other failure is a real I/O error.
fn no_ref_file(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        ErrorKind::NotFound | ErrorKind::NotADirectory | ErrorKind::IsADirectory
    )
}

/// Recursively walk `dir`, collecting all ref files whose full logical
/// name starts with `prefix`. Entries are pushed to `out` with the
/// prefix stripped.
///
/// `root_dir` is the directory corresponding to `prefix_trimmed` (the
/// first call uses `prefix_trimmed`'s directory). `current_dir` is the
/// directory currently being iterated. We track the relative path from
/// `root_dir` to each file to build the suffix name.
fn collect_refs(root_dir: &Path, current_dir: &Path, out: &mut Vec<Ref>) -> TransportResult<()> {
    let entries = match fs::read_dir(current_dir) {
        Ok(e) => e,
        Err(e) if no_ref_file(&e) => return Ok(()),
        Err(e) => {
            return Err(TransportError::RemoteError(format!(
                "list_refs I/O error: {e}"
            )));
        }
    };

    for entry in entries {
        let entry = entry
            .map_err(|e| TransportError::RemoteError(format!("list_refs dir entry error: {e}")))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|e| TransportError::RemoteError(format!("list_refs file_type error: {e}")))?;

        if file_type.is_dir() {
            collect_refs(root_dir, &path, out)?;
        } else if file_type.is_file() {
            // Build the name relative to root_dir.
            let rel = path
                .strip_prefix(root_dir)
                .expect("path is under root_dir")
                .to_string_lossy()
                .replace('\\', "/"); // normalise Windows separators

            // Only include entries that are valid ref name segments.
            if !validate_ref_name(&rel) {
                continue;
            }

            if let Ok(bytes) = bounded_read::read_capped(&path, REF_FILE_MAX_BYTES)
                && let Some(hash) = decode_ref_wire(&bytes)
            {
                out.push(Ref {
                    name: rel,
                    hash: Some(hash),
                });
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use kit_core::hash::hash as blake3_hash;
    use kit_core::protocol::RefWriteCondition;
    use tempfile::TempDir;

    fn tmp() -> TempDir {
        tempfile::tempdir().expect("create tempdir")
    }

    fn pack_key_for(data: &[u8]) -> PackKey {
        PackKey::from(blake3_hash(data))
    }

    // ------------------------------------------------------------------
    // Pack verb tests (6 tests)
    // ------------------------------------------------------------------

    #[test]
    fn upload_and_download_pack() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let data = b"hello packfile content";
        let key = pack_key_for(data);
        t.upload_pack(data, &key).unwrap();
        let got = t.download_pack(&key).unwrap();
        assert_eq!(got, data);
    }

    #[test]
    fn download_missing_pack_returns_not_found() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let key = pack_key_for(b"nonexistent pack");
        let err = t.download_pack(&key).unwrap_err();
        assert!(matches!(err, TransportError::PackNotFound));
    }

    #[test]
    fn upload_pack_creates_packs_directory() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        assert!(!dir.path().join("packs").exists());
        let data = b"first pack";
        let key = pack_key_for(data);
        t.upload_pack(data, &key).unwrap();
        assert!(dir.path().join("packs").is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn download_pack_refuses_a_symlink() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let data = b"real pack";
        let key = pack_key_for(data);
        t.upload_pack(data, &key).unwrap();
        let outside = dir.path().join("outside");
        fs::write(&outside, b"secret").unwrap();
        let link = t.pack_path(&key);
        fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        assert!(matches!(
            t.download_pack(&key),
            Err(TransportError::RemoteError(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_pack_file_is_opened_without_following_a_link() {
        let dir = tmp();
        let target = dir.path().join("target");
        fs::write(&target, b"secret").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        // The open itself refuses the link, so no check can race it.
        assert!(open_pack_file(&link).is_err());
        assert!(open_pack_file(&target).is_ok());
        assert!(
            open_pack_file(dir.path()).is_err(),
            "a directory is no pack"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_lock_file_is_opened_without_following_a_link() {
        let dir = tmp();
        let target = dir.path().join("target");
        fs::write(&target, b"secret").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(open_lock_file(&link).is_err());
        let dangling = dir.path().join("dangling");
        std::os::unix::fs::symlink(dir.path().join("created"), &dangling).unwrap();
        assert!(open_lock_file(&dangling).is_err());
        assert!(!dir.path().join("created").exists());
        assert!(open_lock_file(&dir.path().join("fresh")).is_ok());
        assert!(open_lock_file(&target).is_ok());
        assert_eq!(fs::read(&target).unwrap(), b"secret");
    }

    /// A link planted at a lock path makes the operation fail and leaves the
    /// link's target as it was.
    #[cfg(unix)]
    #[test]
    fn a_link_planted_at_a_lock_path_fails_the_write_and_leaves_its_target() {
        let name = "refs/heads/main";
        let cases: [(&str, String); 2] = [
            ("repo lock", ".lock".to_owned()),
            ("stripe lock", stripe_lock_file(ref_stripe(name))),
        ];
        for (what, lock_name) in cases {
            let dir = tmp();
            let tx = FileTransport::new(dir.path());
            let lock_dir = tx.lock_dir();
            fs::create_dir_all(&lock_dir).unwrap();
            let target = dir.path().join("target");
            fs::write(&target, b"secret").unwrap();
            std::os::unix::fs::symlink(&target, lock_dir.join(&lock_name)).unwrap();

            let err = tx
                .update_ref(name, RefWriteCondition::Missing, &value(0, 0))
                .unwrap_err();
            assert!(
                !matches!(err, TransportError::RefConflict),
                "{what}: {err:?}"
            );
            assert_eq!(fs::read(&target).unwrap(), b"secret", "{what}");
            assert!(tx.read_ref(name).unwrap().is_none(), "{what}");
        }
    }

    /// The count of a stripe is written through the same open: a link at the
    /// stripe's lock path fails it and the target stays as it was.
    #[cfg(unix)]
    #[test]
    fn a_link_planted_at_a_stripe_lock_path_fails_its_count() {
        let dir = tmp();
        let tx = FileTransport::new(dir.path());
        let name = "refs/heads/main";
        let lock_dir = tx.lock_dir();
        fs::create_dir_all(&lock_dir).unwrap();
        let target = dir.path().join("target");
        fs::write(&target, b"secret").unwrap();
        std::os::unix::fs::symlink(&target, lock_dir.join(stripe_lock_file(ref_stripe(name))))
            .unwrap();
        assert!(tx.bump_stripe_version(name).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"secret");
    }

    #[test]
    fn download_pack_refuses_a_pack_over_the_body_limit() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let key = PackKey::new([0x55u8; 32]);
        t.upload_pack(b"seed", &key).unwrap();
        // A sparse file, so the test writes no data.
        let f = fs::OpenOptions::new()
            .write(true)
            .open(t.pack_path(&key))
            .unwrap();
        f.set_len(PACK_BODY_LIMIT + 1).unwrap();
        assert!(matches!(
            t.download_pack(&key),
            Err(TransportError::PayloadTooLarge(_))
        ));
    }

    #[test]
    fn pack_exists_before_and_after_upload() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let data = b"exists test";
        let key = pack_key_for(data);
        assert!(!t.pack_exists(&key).unwrap());
        t.upload_pack(data, &key).unwrap();
        assert!(t.pack_exists(&key).unwrap());
    }

    #[test]
    fn upload_pack_overwrites_idempotently() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let key = PackKey::new([0x77u8; 32]);
        t.upload_pack(b"first", &key).unwrap();
        t.upload_pack(b"second", &key).unwrap();
        assert_eq!(t.download_pack(&key).unwrap(), b"second");
    }

    #[test]
    fn pack_filename_is_64_hex_chars() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let data = b"hex filename test";
        let key = pack_key_for(data);
        t.upload_pack(data, &key).unwrap();
        let expected_name = key.to_hex();
        assert!(dir.path().join("packs").join(&expected_name).exists());
        assert_eq!(expected_name.len(), 64);
    }

    // ------------------------------------------------------------------
    // Ref verb tests (10 tests)
    // ------------------------------------------------------------------

    #[test]
    fn write_and_read_ref() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let h = blake3_hash(b"commit-data");
        t.write_ref("refs/heads/main", &h).unwrap();
        let read = t.read_ref("refs/heads/main").unwrap();
        assert_eq!(read, Some(h));
    }

    #[test]
    fn write_ref_creates_parent_dirs() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let h = blake3_hash(b"deep-ref");
        t.write_ref("refs/heads/feature/deep/branch", &h).unwrap();
        // Intermediate dirs were created.
        assert!(dir.path().join("refs/heads/feature/deep").is_dir());
        assert_eq!(
            t.read_ref("refs/heads/feature/deep/branch").unwrap(),
            Some(h)
        );
    }

    #[test]
    fn write_ref_accepts_a_name_of_250_bytes() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let name = format!("refs/heads/{}", "n".repeat(250));
        let h = blake3_hash(b"long-name");
        t.write_ref(&name, &h).unwrap();
        assert_eq!(t.read_ref(&name).unwrap(), Some(h));
    }

    /// Plant links to `target` at the next 64 temp names beside `dest`,
    /// counted from a name taken now. Returns the links.
    #[cfg(unix)]
    fn plant_links_ahead(dest: &Path, target: &Path) -> Vec<PathBuf> {
        let next = temp_path(dest).unwrap();
        let name = next.file_name().unwrap().to_string_lossy().into_owned();
        let (stem, seq) = name.rsplit_once('.').unwrap();
        let seq: u64 = seq.parse().unwrap();
        (seq + 1..seq + 65)
            .map(|n| {
                let link = next.with_file_name(format!("{stem}.{n}"));
                std::os::unix::fs::symlink(target, &link).unwrap();
                link
            })
            .collect()
    }

    /// A link planted at the temp names a write is about to use is neither
    /// followed nor truncated: the target keeps its bytes, the link stays
    /// and the write lands under a name that is free. The links are planted
    /// from a fresh name right before each write.
    #[cfg(unix)]
    #[test]
    fn writes_never_follow_a_link_at_a_temp_name() {
        let dir = tmp();
        let outside = tmp();
        let target = outside.path().join("target");
        fs::write(&target, b"old").unwrap();
        let heads = dir.path().join("refs/heads");
        fs::create_dir_all(&heads).unwrap();
        let t = FileTransport::new(dir.path());
        let h = blake3_hash(b"after-link");

        let mut planted = plant_links_ahead(&heads.join("main"), &target);
        t.write_ref("refs/heads/main", &h).unwrap();
        planted.extend(plant_links_ahead(&heads.join("fresh"), &target));
        assert!(write_create_new(&heads.join("fresh"), b"x", false).unwrap());

        assert_eq!(fs::read(&target).unwrap(), b"old");
        for link in &planted {
            assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
        }
        assert_eq!(t.read_ref("refs/heads/main").unwrap(), Some(h));
        assert_eq!(fs::read(heads.join("fresh")).unwrap(), b"x");
        let leftovers = fs::read_dir(&heads)
            .unwrap()
            .map(|e| e.unwrap())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .filter(|e| !e.file_type().unwrap().is_symlink())
            .count();
        assert_eq!(leftovers, 0);
    }

    #[test]
    fn read_missing_ref_returns_none() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        assert_eq!(t.read_ref("refs/heads/nonexistent").unwrap(), None);
    }

    #[test]
    fn write_ref_overwrites_previous() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let h1 = blake3_hash(b"commit-v1");
        let h2 = blake3_hash(b"commit-v2");
        t.write_ref("refs/heads/main", &h1).unwrap();
        t.write_ref("refs/heads/main", &h2).unwrap();
        assert_eq!(t.read_ref("refs/heads/main").unwrap(), Some(h2));
    }

    #[test]
    fn update_ref_match_success_writes_new_hash() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let h_old = blake3_hash(b"cas-old");
        let h_new = blake3_hash(b"cas-new");
        t.write_ref("refs/heads/main", &h_old).unwrap();
        t.update_ref("refs/heads/main", RefWriteCondition::Match(h_old), &h_new)
            .unwrap();
        assert_eq!(t.read_ref("refs/heads/main").unwrap(), Some(h_new));
    }

    #[test]
    fn update_ref_match_stale_returns_conflict() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let h_current = blake3_hash(b"current");
        let h_stale = blake3_hash(b"stale");
        let h_next = blake3_hash(b"next");
        t.write_ref("refs/heads/main", &h_current).unwrap();
        let err = t
            .update_ref(
                "refs/heads/main",
                RefWriteCondition::Match(h_stale),
                &h_next,
            )
            .unwrap_err();
        assert!(matches!(err, TransportError::RefConflict));
        // Ref unchanged.
        assert_eq!(t.read_ref("refs/heads/main").unwrap(), Some(h_current));
    }

    #[test]
    fn update_ref_missing_creates_when_absent() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let h = blake3_hash(b"initial");
        t.update_ref("refs/heads/main", RefWriteCondition::Missing, &h)
            .unwrap();
        assert_eq!(t.read_ref("refs/heads/main").unwrap(), Some(h));
    }

    #[test]
    fn update_ref_missing_fails_when_present() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let h = blake3_hash(b"initial");
        t.update_ref("refs/heads/main", RefWriteCondition::Missing, &h)
            .unwrap();
        let err = t
            .update_ref("refs/heads/main", RefWriteCondition::Missing, &h)
            .unwrap_err();
        assert!(matches!(err, TransportError::RefConflict));
    }

    #[test]
    fn update_ref_invalid_name_returns_error() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let h = blake3_hash(b"h");
        let err = t.update_ref("", RefWriteCondition::Any, &h).unwrap_err();
        assert!(matches!(err, TransportError::InvalidRef(_)));
    }

    #[test]
    fn read_ref_invalid_name_returns_error() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let err = t.read_ref("/bad").unwrap_err();
        assert!(matches!(err, TransportError::InvalidRef(_)));
    }

    /// A ref file `a` is no directory, so no ref `a/b` lies below it: the
    /// read reports `a/b` absent rather than `Not a directory`.
    #[test]
    fn read_ref_below_a_ref_file_is_absent() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        t.write_ref("refs/heads/a", &blake3_hash(b"a")).unwrap();
        assert_eq!(t.read_ref("refs/heads/a/b").unwrap(), None);
        assert_eq!(t.read_ref("refs/heads/a/b/c").unwrap(), None);
        assert_eq!(t.read_ref_strict("refs/heads/a/b").unwrap(), None);
        t.with_ref_lock(|refs| assert_eq!(refs.read_ref("refs/heads/a/b").unwrap(), None))
            .unwrap();
        assert_eq!(t.read_ref("refs/heads/a").unwrap(), Some(blake3_hash(b"a")));
    }

    /// The directory that holds ref `a/b` is no ref file: the read of `a`
    /// reports it absent rather than `Is a directory`.
    #[test]
    fn read_ref_of_a_directory_of_refs_is_absent() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        t.write_ref("refs/heads/a/b", &blake3_hash(b"b")).unwrap();
        assert_eq!(t.read_ref("refs/heads/a").unwrap(), None);
        assert_eq!(t.read_ref_strict("refs/heads/a").unwrap(), None);
        assert_eq!(
            t.read_ref("refs/heads/a/b").unwrap(),
            Some(blake3_hash(b"b"))
        );
    }

    /// A prefix that names a ref file lists nothing: no ref lies below a
    /// file, and a ref named exactly the prefix is not listed (SPEC-REFS
    /// §4).
    #[test]
    fn list_refs_below_a_ref_file_is_empty() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        t.write_ref("refs/heads/a", &blake3_hash(b"a")).unwrap();
        assert!(t.list_refs("refs/heads/a").unwrap().is_empty());
        assert!(t.list_refs("refs/heads/a/b/").unwrap().is_empty());
        assert!(t.list_ref_files("refs/heads/a").unwrap().is_empty());
        assert_eq!(t.list_refs("refs/heads").unwrap().len(), 1);
    }

    /// Only a missing file, a ref file above the name and a directory at
    /// the name read as absent. Any other read failure, here an injected
    /// permission error, stays an error.
    #[test]
    fn ref_read_failure_other_than_absence_is_an_error() {
        for kind in [
            ErrorKind::NotFound,
            ErrorKind::NotADirectory,
            ErrorKind::IsADirectory,
        ] {
            assert_eq!(ref_from_read(Err(kind.into())).unwrap(), None, "{kind:?}");
        }
        for kind in [
            ErrorKind::PermissionDenied,
            ErrorKind::InvalidInput,
            ErrorKind::Other,
        ] {
            let err = ref_from_read(Err(kind.into())).unwrap_err();
            assert_eq!(err.kind(), kind);
        }
        let h = blake3_hash(b"h");
        assert_eq!(
            ref_from_read(Ok(encode_ref_wire(&h).to_vec())).unwrap(),
            Some(h)
        );
        assert_eq!(ref_from_read(Ok(b"junk".to_vec())).unwrap(), None);
    }

    /// A read that fails for another reason than absence surfaces through
    /// every reader: a ref path that is a symlink loop.
    #[cfg(unix)]
    #[test]
    fn read_ref_of_a_symlink_loop_is_an_error() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let heads = dir.path().join("refs/heads");
        fs::create_dir_all(&heads).unwrap();
        std::os::unix::fs::symlink("loop", heads.join("loop")).unwrap();
        assert!(matches!(
            t.read_ref("refs/heads/loop"),
            Err(TransportError::RemoteError(_))
        ));
        assert!(matches!(
            t.read_ref_strict("refs/heads/loop"),
            Err(RefFileError::Io(_))
        ));
        assert!(matches!(
            t.list_refs("refs/heads/loop"),
            Err(TransportError::RemoteError(_))
        ));
        assert!(matches!(
            t.list_ref_files("refs/heads/loop"),
            Err(RefFileError::Io(_))
        ));
    }

    // ------------------------------------------------------------------
    // list_refs tests (8 tests)
    // ------------------------------------------------------------------

    #[test]
    fn list_refs_returns_suffix_only() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        t.write_ref("refs/heads/main", &blake3_hash(b"c1")).unwrap();
        t.write_ref("refs/heads/develop", &blake3_hash(b"c2"))
            .unwrap();
        t.write_ref("refs/tags/v1.0", &blake3_hash(b"c3")).unwrap();

        let heads = t.list_refs("refs/heads").unwrap();
        assert_eq!(heads.len(), 2);
        let names: Vec<&str> = heads.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["develop", "main"]);
    }

    #[test]
    fn list_refs_all_with_empty_prefix() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        t.write_ref("refs/heads/main", &blake3_hash(b"m")).unwrap();
        t.write_ref("refs/tags/v1", &blake3_hash(b"t")).unwrap();
        let all = t.list_refs("").unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn list_refs_returns_empty_when_dir_missing() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let refs = t.list_refs("refs/heads").unwrap();
        assert!(refs.is_empty());
    }

    #[test]
    fn list_refs_sorted_alphabetically() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let h = blake3_hash(b"h");
        t.write_ref("refs/heads/zebra", &h).unwrap();
        t.write_ref("refs/heads/alpha", &h).unwrap();
        t.write_ref("refs/heads/middle", &h).unwrap();
        let refs = t.list_refs("refs/heads").unwrap();
        assert_eq!(refs.len(), 3);
        assert_eq!(refs[0].name, "alpha");
        assert_eq!(refs[1].name, "middle");
        assert_eq!(refs[2].name, "zebra");
    }

    #[test]
    fn list_refs_invalid_prefix_returns_error() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let err = t.list_refs("/").unwrap_err();
        assert!(matches!(err, TransportError::InvalidRef(_)));
    }

    #[test]
    fn list_refs_with_trailing_slash_prefix() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        t.write_ref("refs/heads/main", &blake3_hash(b"m")).unwrap();
        let refs = t.list_refs("refs/heads/").unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].name, "main");
    }

    #[test]
    fn list_refs_does_not_include_pack_dir() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        // Upload a pack (creates packs/ directory).
        let data = b"some pack";
        let key = pack_key_for(data);
        t.upload_pack(data, &key).unwrap();
        // list_refs("") should not return the pack hex file as a ref.
        t.write_ref("refs/heads/main", &blake3_hash(b"m")).unwrap();
        let all = t.list_refs("").unwrap();
        // Should only include refs/heads/main, not the pack key.
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].name, "refs/heads/main");
    }

    #[test]
    fn list_refs_no_tmp_files_leaked() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        t.write_ref("refs/heads/main", &blake3_hash(b"m")).unwrap();
        // Overwrite a few times.
        for i in 0..5u8 {
            t.write_ref("refs/heads/main", &blake3_hash(&[i])).unwrap();
        }
        // No .tmp. files should remain.
        let count = fs::read_dir(dir.path().join("refs/heads"))
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .count();
        assert_eq!(count, 0);
    }

    // ------------------------------------------------------------------
    // Full-interface integration test
    // ------------------------------------------------------------------

    // ------------------------------------------------------------------
    // Concurrent write test (write_ref Any never exposes truncated file)
    // ------------------------------------------------------------------

    #[test]
    fn concurrent_any_writes_never_expose_empty_file() {
        use std::sync::Arc;
        use std::thread;

        let dir = tmp();
        let t = Arc::new(FileTransport::new(dir.path()));

        let h_old = blake3_hash(b"concurrent-old");
        let h_new = blake3_hash(b"concurrent-new");
        t.write_ref("refs/heads/main", &h_old).unwrap();

        let t2 = Arc::clone(&t);
        let writer = thread::spawn(move || {
            for _ in 0..50 {
                let _ = t2.write_ref("refs/heads/main", &h_new);
            }
        });

        // Meanwhile, read and assert the ref is always one of the two valid hashes.
        for _ in 0..50 {
            if let Ok(Some(v)) = t.read_ref("refs/heads/main") {
                assert!(v == h_old || v == h_new, "unexpected hash value");
            }
        }

        writer.join().expect("writer thread panicked");

        // Final state must be one of the two valid hashes.
        let final_h = t.read_ref("refs/heads/main").unwrap();
        assert!(
            final_h == Some(h_old) || final_h == Some(h_new),
            "unexpected final state"
        );
    }

    // ------------------------------------------------------------------
    // Missing-race: two threads competing for Missing → only one wins
    // ------------------------------------------------------------------

    #[test]
    fn concurrent_missing_only_one_writer_wins() {
        use std::sync::Arc;
        use std::thread;

        let dir = tmp();
        let t = Arc::new(FileTransport::new(dir.path()));
        let h = blake3_hash(b"race-missing");

        let results: Vec<_> = (0..4)
            .map(|_| {
                let t2 = Arc::clone(&t);
                let h2 = h;
                thread::spawn(move || {
                    t2.update_ref("refs/heads/race", RefWriteCondition::Missing, &h2)
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|jh| jh.join().expect("thread panicked"))
            .collect();

        let successes = results.iter().filter(|r| r.is_ok()).count();
        let conflicts = results
            .iter()
            .filter(|r| matches!(r, Err(TransportError::RefConflict)))
            .count();
        assert_eq!(successes, 1, "exactly one Missing writer should succeed");
        assert_eq!(conflicts, 3, "the other three should get RefConflict");
    }

    // ------------------------------------------------------------------
    // E7: path-escape guard — symlink inside refs/ cannot escape root
    // ------------------------------------------------------------------

    /// A pre-existing symlink in `<root>/refs/...` that points outside
    /// `<root>/` MUST NOT allow read/write to escape the transport root.
    /// The transport must refuse the operation with a `RemoteError`
    /// mentioning the path-escape guard.
    #[cfg(unix)]
    #[test]
    fn read_ref_rejects_symlink_escaping_root() {
        use std::os::unix::fs::symlink;

        let dir = tmp();
        let outside = tmp();
        let outside_file = outside.path().join("secret");
        fs::write(&outside_file, b"outside content").unwrap();

        // Create refs/heads/, then a symlink evil -> outside_file.
        let refs_heads = dir.path().join("refs").join("heads");
        fs::create_dir_all(&refs_heads).unwrap();
        symlink(&outside_file, refs_heads.join("evil")).unwrap();

        let t = FileTransport::new(dir.path());
        let err = t
            .read_ref("refs/heads/evil")
            .expect_err("read_ref on path-escape symlink must return an error");
        match err {
            TransportError::RemoteError(msg) => {
                assert!(
                    msg.to_lowercase().contains("escape"),
                    "error should mention path escape: {msg}"
                );
            }
            other => panic!("expected RemoteError with path-escape, got {other:?}"),
        }
    }

    /// Regression: a root that lives under a symlinked parent and does
    /// NOT exist at construction time must NOT spuriously trip the
    /// path-escape guard. Previously `new()` cached
    /// `canonicalize(root).unwrap_or(root)`; when `root` was absent it
    /// stored the non-canonical literal path, so a later legitimate ref
    /// that canonicalised to the resolved `/private/...` form failed the
    /// `starts_with` prefix check and a valid write was rejected with a
    /// spurious "path escape" error. The guard now canonicalises the root
    /// lazily, so this round-trips cleanly.
    #[cfg(unix)]
    #[test]
    fn legit_write_under_symlinked_root_not_yet_existing_is_allowed() {
        use std::os::unix::fs::symlink;

        // `real` is the actual backing directory; `link` is a symlink that
        // points at it. We root the transport at `<link>/repo`, which does
        // NOT exist yet at construction time. Writing a ref under it must
        // succeed even though `<link>/repo` canonicalises to
        // `<real>/repo`.
        let real = tmp();
        let link_parent = tmp();
        let link = link_parent.path().join("link");
        symlink(real.path(), &link).unwrap();

        let root = link.join("repo");
        assert!(!root.exists(), "root must be absent at construction");

        let t = FileTransport::new(&root);
        let h = blake3_hash(b"legit-under-symlink");

        // This must NOT be rejected by the path-escape guard.
        t.write_ref("refs/heads/main", &h)
            .expect("legitimate write under a symlinked, not-yet-existing root must succeed");
        assert_eq!(t.read_ref("refs/heads/main").unwrap(), Some(h));

        // And the bytes really landed under the real backing directory.
        assert!(real.path().join("repo/refs/heads/main").exists());
    }

    // ------------------------------------------------------------------
    // Cross-process CAS race (file-lock guarantee)
    // ------------------------------------------------------------------

    /// Single-process round-trip: `Match` CAS succeeds for the right
    /// hash and fails (with the ref unchanged) for the wrong hash —
    /// exercised after the file-lock wiring is in place to confirm
    /// existing behaviour is preserved.
    #[test]
    fn match_cas_single_process_roundtrip_with_file_lock() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let h0 = blake3_hash(b"genesis");
        let h1 = blake3_hash(b"first");
        let h2 = blake3_hash(b"second");

        t.write_ref("refs/heads/main", &h0).unwrap();

        // Wrong expected hash: ref unchanged, RefConflict.
        let err = t
            .update_ref("refs/heads/main", RefWriteCondition::Match(h1), &h2)
            .unwrap_err();
        assert!(matches!(err, TransportError::RefConflict));
        assert_eq!(t.read_ref("refs/heads/main").unwrap(), Some(h0));

        // Right expected hash: ref advances.
        t.update_ref("refs/heads/main", RefWriteCondition::Match(h0), &h1)
            .unwrap();
        assert_eq!(t.read_ref("refs/heads/main").unwrap(), Some(h1));

        // Lock sentinel file must exist after a Match CAS.
        assert!(
            dir.path().join(".kit").join("refs").join(".lock").exists(),
            "RefLock sentinel file should be created on first Match CAS"
        );
    }

    #[test]
    fn every_write_condition_waits_for_the_file_cas_guard() {
        use std::sync::mpsc;
        use std::time::Duration;
        for condition in [RefWriteCondition::Any, RefWriteCondition::Missing] {
            let dir = tmp();
            let lock = RefLock::acquire(dir.path()).unwrap();
            let root = dir.path().to_path_buf();
            let (tx, rx) = mpsc::channel();
            let worker = std::thread::spawn(move || {
                let t = FileTransport::new(root);
                tx.send(t.update_ref("refs/heads/main", condition, &blake3_hash(b"next")))
                    .unwrap();
            });
            let premature = rx.recv_timeout(Duration::from_millis(100));
            let observed = FileTransport::new(dir.path())
                .read_ref("refs/heads/main")
                .unwrap();
            drop(lock);
            worker.join().unwrap();
            assert!(
                matches!(premature, Err(mpsc::RecvTimeoutError::Timeout)),
                "unconditional/create mutation bypassed a held CAS guard: {premature:?}"
            );
            assert_eq!(
                observed, None,
                "publication must wait for guard acquisition"
            );
            rx.recv_timeout(Duration::from_secs(2)).unwrap().unwrap();
        }
    }

    /// Cross-process race simulation.
    ///
    /// We simulate two processes by spawning two threads that each
    /// construct their own [`FileTransport`] over the **same on-disk
    /// root**. Each [`FileTransport`] owns its own `RefLock` handle
    /// (a fresh `File` opened at lock-acquire time). Because the OS
    /// `flock(2)` / `LockFileEx` mutual exclusion is enforced between
    /// distinct open file descriptions — not between threads — two
    /// threads holding two separate `File` handles to the same path
    /// reproduce the same exclusion semantics as two OS processes.
    ///
    /// This is the simplification called out in the task spec; a true
    /// `fork()` / `Command::spawn` test would add the same coverage at
    /// higher cost.
    #[test]
    fn cross_process_match_cas_only_one_winner() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering as AOrdering};
        use std::thread;

        let dir = tmp();
        // Two transports → two independent in-process Mutexes →
        // two independent file-lock acquisitions. This is the only way
        // to exercise the OS lock from inside a single test process.
        let t_a = Arc::new(FileTransport::new(dir.path()));
        let t_b = Arc::new(FileTransport::new(dir.path()));

        let h_old = blake3_hash(b"xproc-old");
        let h_a = blake3_hash(b"xproc-a-wins");
        let h_b = blake3_hash(b"xproc-b-wins");

        t_a.write_ref("refs/heads/main", &h_old).unwrap();

        // Run many rounds: each round, both writers race from the
        // same starting hash. After each round we reset to h_old.
        // Across rounds, the file lock must guarantee exactly one
        // success per round.
        let rounds = 50;
        let a_wins = Arc::new(AtomicUsize::new(0));
        let b_wins = Arc::new(AtomicUsize::new(0));

        for _ in 0..rounds {
            // Reset starting state.
            t_a.write_ref("refs/heads/main", &h_old).unwrap();

            let ta = Arc::clone(&t_a);
            let tb = Arc::clone(&t_b);
            let aw = Arc::clone(&a_wins);
            let bw = Arc::clone(&b_wins);

            let ja = thread::spawn(move || {
                ta.update_ref("refs/heads/main", RefWriteCondition::Match(h_old), &h_a)
            });
            let jb = thread::spawn(move || {
                tb.update_ref("refs/heads/main", RefWriteCondition::Match(h_old), &h_b)
            });

            let result_a = ja.join().expect("thread a panicked");
            let result_b = jb.join().expect("thread b panicked");

            let won_a = result_a.is_ok();
            let won_b = result_b.is_ok();

            // Exactly one must succeed and the other must observe
            // RefConflict — never RemoteError, never both-success.
            assert!(
                won_a ^ won_b,
                "exactly one writer must win; got a={result_a:?}, b={result_b:?}"
            );
            let loser = if won_a { &result_b } else { &result_a };
            assert!(
                matches!(loser, Err(TransportError::RefConflict)),
                "loser must report RefConflict, got {loser:?}"
            );

            if won_a {
                aw.fetch_add(1, AOrdering::Relaxed);
                assert_eq!(t_a.read_ref("refs/heads/main").unwrap(), Some(h_a));
            } else {
                bw.fetch_add(1, AOrdering::Relaxed);
                assert_eq!(t_a.read_ref("refs/heads/main").unwrap(), Some(h_b));
            }
        }

        // Sanity: across many rounds, both writers should have won at
        // least once. (Probabilistically; if this is flaky, scheduling
        // pinned everything to one thread — still correct, just
        // unfortunate. Loosen by reducing the floor to 0 if needed.)
        let aw = a_wins.load(AOrdering::Relaxed);
        let bw = b_wins.load(AOrdering::Relaxed);
        assert_eq!(aw + bw, rounds, "every round must have exactly one winner");
    }

    /// Stress: many threads on the same root contend for `Match` CAS
    /// in a CAS-loop until they have each advanced the ref once. With
    /// the file lock + process mutex in place, no `RemoteError` may
    /// surface and the ref must end at the last writer's hash with
    /// no torn state visible to readers.
    #[test]
    fn cross_process_match_cas_no_torn_state() {
        use std::sync::Arc;
        use std::thread;

        let dir = tmp();
        // 8 distinct transports → 8 distinct file-lock handles, as
        // close as we can get to 8 processes inside one test binary.
        let transports: Vec<Arc<FileTransport>> = (0..8)
            .map(|_| Arc::new(FileTransport::new(dir.path())))
            .collect();

        let initial = blake3_hash(b"contended-initial");
        transports[0]
            .write_ref("refs/heads/main", &initial)
            .unwrap();

        // Each thread advances the ref to its own hash by retrying
        // CAS until it wins from the latest observed value.
        let handles: Vec<_> = transports
            .iter()
            .enumerate()
            .map(|(i, t)| {
                let t = Arc::clone(t);
                thread::spawn(move || {
                    let target = blake3_hash(format!("writer-{i}").as_bytes());
                    loop {
                        let current = t.read_ref("refs/heads/main").expect("read must not error");
                        let Some(current) = current else {
                            panic!("ref must always be present mid-flight");
                        };
                        match t.update_ref(
                            "refs/heads/main",
                            RefWriteCondition::Match(current),
                            &target,
                        ) {
                            Ok(()) => return target,
                            Err(TransportError::RefConflict) => {}
                            Err(e) => panic!("unexpected transport error: {e:?}"),
                        }
                    }
                })
            })
            .collect();

        let final_hashes: Vec<_> = handles
            .into_iter()
            .map(|h| h.join().expect("writer thread panicked"))
            .collect();

        // The final on-disk hash must be one of the writers' targets
        // (the last to commit). Reads must always have decoded to a
        // valid hash — verified by the assertion inside the loop.
        let final_h = transports[0]
            .read_ref("refs/heads/main")
            .unwrap()
            .expect("final ref must exist");
        assert!(
            final_hashes.contains(&final_h),
            "final ref must equal one of the writers' targets: got {final_h:?}, writers={final_hashes:?}"
        );
    }

    // ------------------------------------------------------------------
    // Durability: parent-dir fsync is propagated, not swallowed (C1)
    // ------------------------------------------------------------------

    /// Regression for C1: the parent-directory fsync that makes a
    /// rename's / hard-link's dirent durable is now propagated via `?`
    /// instead of being discarded as best-effort. This exercises the
    /// now-propagating path end-to-end across all three write conditions
    /// (`Any` and the `Missing` create path go through `write_atomic` /
    /// `write_create_new`, both of which `sync_parent(parent)?`). A true
    /// power-loss / fsync-fault injection is impractical in a unit test;
    /// this asserts the synced write path still succeeds for every verb.
    #[test]
    fn synced_write_path_succeeds_for_all_conditions() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());

        // pack upload → write_atomic → sync_parent(parent)?
        let data = b"durable pack payload";
        let key = pack_key_for(data);
        t.upload_pack(data, &key)
            .expect("upload_pack must succeed through the propagated parent fsync");
        assert_eq!(t.download_pack(&key).unwrap(), data);

        // Missing → write_create_new → sync_parent(parent)? on the link arm
        let h0 = blake3_hash(b"durable-missing");
        t.update_ref("refs/heads/main", RefWriteCondition::Missing, &h0)
            .expect("update_ref(Missing) must succeed through the propagated parent fsync");
        assert_eq!(t.read_ref("refs/heads/main").unwrap(), Some(h0));

        // Any → write_atomic → sync_parent(parent)?
        let h1 = blake3_hash(b"durable-any");
        t.update_ref("refs/heads/main", RefWriteCondition::Any, &h1)
            .expect("update_ref(Any) must succeed through the propagated parent fsync");
        assert_eq!(t.read_ref("refs/heads/main").unwrap(), Some(h1));

        // Match → read-check-write → write_atomic → sync_parent(parent)?
        let h2 = blake3_hash(b"durable-match");
        t.update_ref("refs/heads/main", RefWriteCondition::Match(h1), &h2)
            .expect("update_ref(Match) must succeed through the propagated parent fsync");
        assert_eq!(t.read_ref("refs/heads/main").unwrap(), Some(h2));
    }

    /// `sync_parent` tolerates a vanished directory as success (mirrors
    /// `atomic::sync_parent_dir`): if the parent was removed concurrently
    /// there is nothing left to make durable, so a `NotFound` must not be
    /// surfaced as an error.
    #[test]
    fn sync_parent_tolerates_missing_dir() {
        let dir = tmp();
        let gone = dir.path().join("does-not-exist");
        sync_parent(&gone).expect("sync_parent must treat a missing dir as success");
    }

    /// Write side: a symlink that already exists inside `<root>/` but
    /// points outside it MUST NOT be followed by an unconditional write.
    #[cfg(unix)]
    #[test]
    fn write_ref_rejects_symlink_escaping_root() {
        use kit_core::hash::hash as blake3_hash;
        use std::os::unix::fs::symlink;

        let dir = tmp();
        let outside = tmp();
        let outside_file = outside.path().join("target");
        fs::write(&outside_file, b"old").unwrap();

        let refs_heads = dir.path().join("refs").join("heads");
        fs::create_dir_all(&refs_heads).unwrap();
        symlink(&outside_file, refs_heads.join("evil")).unwrap();

        let t = FileTransport::new(dir.path());
        let h = blake3_hash(b"should-not-write");
        let err = t
            .update_ref("refs/heads/evil", RefWriteCondition::Any, &h)
            .expect_err("update_ref on path-escape symlink must return an error");
        assert!(matches!(err, TransportError::RemoteError(_)));

        // The outside file must NOT have been overwritten with the new
        // ref wire.
        let after = fs::read(&outside_file).unwrap();
        assert_eq!(after, b"old", "outside file was clobbered despite guard");
    }

    // ------------------------------------------------------------------
    // with_ref_lock / LockedRefs
    // ------------------------------------------------------------------

    #[test]
    fn with_ref_lock_holds_the_lock_file_and_writes_through_it() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let h = blake3_hash(b"locked");
        let held = t
            .with_ref_lock(|refs| {
                refs.update_ref("refs/heads/a", RefWriteCondition::Missing, &h)
                    .unwrap();
                assert_eq!(refs.read_ref("refs/heads/a").unwrap(), Some(h));
                // Another open file description cannot take the lock.
                let lock = dir.path().join(".kit").join("refs").join(".lock");
                let other = fs::File::open(lock).unwrap();
                other.try_lock().is_err()
            })
            .unwrap();
        assert!(held, "the ref lock is held inside with_ref_lock");
        assert_eq!(t.read_ref("refs/heads/a").unwrap(), Some(h));
    }

    #[test]
    fn with_ref_lock_recovers_after_a_panic() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            t.with_ref_lock(|_| panic!("panic under the ref lock"))
        }));
        assert!(panicked.is_err() && t.repo_gate.is_poisoned());
        let h = blake3_hash(b"after");
        t.update_ref("refs/heads/a", RefWriteCondition::Any, &h)
            .unwrap();
        assert_eq!(t.read_ref("refs/heads/a").unwrap(), Some(h));
    }

    #[test]
    fn with_ref_lock_for_recovers_after_a_panic() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            t.with_ref_lock_for("refs/heads/a", |_| panic!("panic under the ref lock"))
        }));
        assert!(panicked.is_err() && t.stripe_gates[ref_stripe("refs/heads/a")].is_poisoned());
        let h = blake3_hash(b"after");
        t.update_ref("refs/heads/a", RefWriteCondition::Any, &h)
            .unwrap();
        assert_eq!(t.read_ref("refs/heads/a").unwrap(), Some(h));
    }

    #[test]
    fn with_ref_lock_for_refuses_an_invalid_name() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let result = t.with_ref_lock_for("refs/heads/../x", |_| ());
        assert!(matches!(result, Err(RefFileError::InvalidName(_))));
    }

    /// Two ref names, in different stripes, that start with `refs/heads/`.
    fn refs_in_different_stripes() -> (String, String) {
        let a = "refs/heads/a".to_owned();
        let b = (0..1000)
            .map(|i| format!("refs/heads/b{i}"))
            .find(|n| ref_stripe(n) != ref_stripe(&a))
            .unwrap();
        (a, b)
    }

    /// The stripe is the first byte of the BLAKE3 digest of the name. Every
    /// process on a root must agree on it, so the mapping is pinned.
    /// The golden vectors of SPEC-REFS section 5.1.1:
    /// `rust/tests/golden/ref-locks/vectors.txt` lists, for each ref name,
    /// its stripe and lock file. `scripts/golden/ref_locks_ref.py` checks
    /// the same file independently.
    #[test]
    fn every_golden_ref_maps_to_its_stripe_and_lock_file() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/ref-locks");
        let raw = fs::read(dir.join("vectors.txt")).unwrap();
        let manifest = fs::read_to_string(dir.join("MANIFEST.txt")).unwrap();
        let pinned = manifest
            .lines()
            .find_map(|l| l.strip_prefix("vectors.txt "))
            .unwrap();
        assert_eq!(
            kit_core::hash::to_hex(&blake3_hash(&raw)),
            pinned,
            "vectors.txt does not match MANIFEST.txt"
        );
        let text = std::str::from_utf8(&raw).unwrap();
        let mut count = 0;
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let fields: Vec<&str> = line.split(' ').collect();
            let [name, hh, lock] = fields[..] else {
                panic!("malformed vector {line:?}");
            };
            assert!(validate_ref_name(name), "{name}");
            let stripe = usize::from_str_radix(hh, 16).unwrap();
            assert_eq!(ref_stripe(name), stripe, "{name}");
            assert_eq!(stripe_lock_file(ref_stripe(name)), lock, "{name}");
            count += 1;
        }
        assert_eq!(count, 57);
    }

    /// The golden vectors of SPEC-REFS section 5.1.2:
    /// `rust/tests/golden/ref-locks/versions.txt` lists lock file bytes with
    /// the stripe version they hold and the bytes one more write leaves, or
    /// marks them corrupt. `scripts/golden/ref_locks_ref.py` checks the same
    /// file independently.
    #[test]
    fn every_golden_lock_file_holds_its_stripe_version() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/ref-locks");
        let raw = fs::read(dir.join("versions.txt")).unwrap();
        let manifest = fs::read_to_string(dir.join("MANIFEST.txt")).unwrap();
        let pinned = manifest
            .lines()
            .find_map(|l| l.strip_prefix("versions.txt "))
            .unwrap();
        assert_eq!(
            kit_core::hash::to_hex(&blake3_hash(&raw)),
            pinned,
            "versions.txt does not match MANIFEST.txt"
        );
        let unhex = |field: &str| -> Vec<u8> {
            if field == "-" {
                return Vec::new();
            }
            (0..field.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&field[i..i + 2], 16).unwrap())
                .collect()
        };
        let scratch = tmp();
        let path = scratch.path().join("lock");
        let open = || {
            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap()
        };
        let text = std::str::from_utf8(&raw).unwrap();
        let (mut valid, mut corrupt) = (0, 0);
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let fields: Vec<&str> = line.split(' ').collect();
            fs::write(&path, unhex(fields[0])).unwrap();
            match fields[1..] {
                ["corrupt"] => {
                    let read = read_stripe_version(&open());
                    assert_eq!(read.unwrap_err().kind(), ErrorKind::InvalidData, "{line}");
                    assert!(bump_version_in(&open()).is_err(), "{line}");
                    assert_eq!(fs::read(&path).unwrap(), unhex(fields[0]), "{line}");
                    corrupt += 1;
                }
                [version, after] => {
                    let version: u64 = version.parse().unwrap();
                    assert_eq!(read_stripe_version(&open()).unwrap(), version, "{line}");
                    bump_version_in(&open()).unwrap();
                    assert_eq!(fs::read(&path).unwrap(), unhex(after), "{line}");
                    valid += 1;
                }
                _ => panic!("malformed vector {line:?}"),
            }
        }
        assert_eq!((valid, corrupt), (7, 4));
    }

    #[test]
    fn the_stripe_of_a_ref_is_pinned() {
        // First bytes of the BLAKE3 digests, computed with an independent
        // implementation.
        assert_eq!(ref_stripe("refs/heads/main"), 0xec);
        assert_eq!(ref_stripe("refs/heads/a"), 0x1b);
        assert_eq!(ref_stripe("refs/tags/v1"), 0xce);
        assert_eq!(REF_LOCK_STRIPES, 256);

        let dir = tmp();
        FileTransport::new(dir.path())
            .update_ref(
                "refs/heads/main",
                RefWriteCondition::Missing,
                &blake3_hash(b"x"),
            )
            .unwrap();
        let locks = dir.path().join(".kit").join("refs");
        assert!(locks.join(".lock").exists());
        assert!(locks.join("refs-ec.lock").exists());
    }

    #[test]
    fn a_write_to_another_stripe_does_not_wait_for_a_held_stripe() {
        use std::sync::mpsc;
        use std::time::Duration;
        let dir = tmp();
        let (held, other) = refs_in_different_stripes();
        let lock = RefLock::acquire_stripe(dir.path(), ref_stripe(&held)).unwrap();
        let root = dir.path().to_path_buf();
        let (tx, rx) = mpsc::channel();
        let name = other.clone();
        let worker = std::thread::spawn(move || {
            let t = FileTransport::new(root);
            tx.send(t.update_ref(&name, RefWriteCondition::Missing, &blake3_hash(b"b")))
                .unwrap();
        });
        let finished = rx.recv_timeout(Duration::from_secs(5));
        drop(lock);
        worker.join().unwrap();
        assert!(
            matches!(finished, Ok(Ok(()))),
            "a write to another stripe waited on a held stripe: {finished:?}"
        );
    }

    #[test]
    fn a_write_to_a_held_stripe_waits_for_it() {
        use std::sync::mpsc;
        use std::time::Duration;
        for condition in [
            RefWriteCondition::Any,
            RefWriteCondition::Missing,
            RefWriteCondition::Match(blake3_hash(b"absent")),
        ] {
            let dir = tmp();
            let lock = RefLock::acquire_stripe(dir.path(), ref_stripe("refs/heads/main")).unwrap();
            let root = dir.path().to_path_buf();
            let (tx, rx) = mpsc::channel();
            let worker = std::thread::spawn(move || {
                let t = FileTransport::new(root);
                tx.send(t.update_ref("refs/heads/main", condition, &blake3_hash(b"next")))
                    .unwrap();
            });
            let premature = rx.recv_timeout(Duration::from_millis(100));
            drop(lock);
            worker.join().unwrap();
            assert!(
                matches!(premature, Err(mpsc::RecvTimeoutError::Timeout)),
                "a write bypassed its held stripe lock: {premature:?}"
            );
            rx.recv_timeout(Duration::from_secs(2)).unwrap().ok();
        }
    }

    #[test]
    fn a_multi_file_step_excludes_single_ref_writes() {
        use std::sync::mpsc;
        use std::time::Duration;
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let root = dir.path().to_path_buf();
        let (tx, rx) = mpsc::channel();
        let inside = t
            .with_ref_lock(|_| {
                let worker = std::thread::spawn(move || {
                    let other = FileTransport::new(root);
                    tx.send(other.update_ref(
                        "refs/heads/main",
                        RefWriteCondition::Any,
                        &blake3_hash(b"next"),
                    ))
                    .unwrap();
                });
                let premature = rx.recv_timeout(Duration::from_millis(100));
                (worker, premature.is_err())
            })
            .unwrap();
        let (worker, waited) = inside;
        worker.join().unwrap();
        assert!(waited, "a single-ref write ran inside a multi-file step");
        rx.recv_timeout(Duration::from_secs(2)).unwrap().unwrap();
    }

    #[test]
    fn a_ref_write_does_not_wait_for_a_shared_repo_lock() {
        let dir = tmp();
        let shared = RefLock::acquire_shared(dir.path()).unwrap();
        let t = FileTransport::new(dir.path());
        t.update_ref(
            "refs/heads/main",
            RefWriteCondition::Missing,
            &blake3_hash(b"x"),
        )
        .unwrap();
        drop(shared);
    }

    /// Writers under different stripe locks race to create `refs/heads/c` and
    /// `refs/heads/c/x`. At most one wins, and the other reports the clash.
    #[test]
    fn a_ref_and_a_ref_below_it_race_without_a_false_outcome() {
        use std::sync::{Arc, Barrier};
        let (parent, child) = (0..1000)
            .map(|i| (format!("refs/heads/c{i}"), format!("refs/heads/c{i}/x")))
            .find(|(p, c)| ref_stripe(p) != ref_stripe(c))
            .unwrap();
        for _ in 0..100 {
            let dir = tmp();
            let barrier = Arc::new(Barrier::new(2));
            let run = |name: String| {
                let root = dir.path().to_path_buf();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let t = FileTransport::new(root);
                    barrier.wait();
                    t.update_ref(&name, RefWriteCondition::Missing, &blake3_hash(b"v"))
                })
            };
            let (a, b) = (run(parent.clone()), run(child.clone()));
            let (ra, rb) = (a.join().unwrap(), b.join().unwrap());
            let wins = usize::from(ra.is_ok()) + usize::from(rb.is_ok());
            assert!(wins <= 1, "both a ref and a ref below it were created");
            for r in [&ra, &rb] {
                assert!(
                    matches!(r, Ok(()) | Err(TransportError::InvalidRef(_))),
                    "a clash must be InvalidRef, got {r:?}"
                );
            }
            assert_eq!(wins, 1, "one of the two writers must win");
            let leaked: Vec<_> = fs::read_dir(dir.path().join("refs/heads"))
                .unwrap()
                .filter_map(Result::ok)
                .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
                .collect();
            assert!(leaked.is_empty(), "a failed write left a temp file");
        }
    }

    /// Every temp file left under `dir`, at any depth.
    fn temp_files_under(dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut todo = vec![dir.to_path_buf()];
        while let Some(d) = todo.pop() {
            for e in fs::read_dir(&d).unwrap().filter_map(Result::ok) {
                let path = e.path();
                if path.is_dir() {
                    todo.push(path);
                } else if e.file_name().to_string_lossy().contains(".tmp.") {
                    out.push(path);
                }
            }
        }
        out
    }

    /// A ref whose stripe is `stripe`, named so it clashes with nothing.
    fn ref_in_stripe(stripe: usize) -> String {
        (0..100_000)
            .map(|k| format!("refs/tags/victim-{k}"))
            .find(|n| ref_stripe(n) == stripe)
            .unwrap()
    }

    /// Single-ref creates of `refs/heads/a` and `refs/heads/a/b`, in
    /// different stripes, race on a fresh root each round, under every
    /// write condition that can create. Whatever the interleaving, the root
    /// stays usable: one name wins and reads back, the loser reports
    /// `InvalidRef`, no temp file is left, refs in both stripes can still be
    /// written, and the exclusive multi-file step still runs.
    #[test]
    fn a_ref_and_a_ref_below_it_race_and_leave_the_root_usable() {
        use std::sync::{Arc, Barrier};
        let (parent, child) = (0..1000)
            .map(|i| (format!("refs/heads/a{i}"), format!("refs/heads/a{i}/b")))
            .find(|(p, c)| ref_stripe(p) != ref_stripe(c))
            .unwrap();
        let victims = [
            ref_in_stripe(ref_stripe(&parent)),
            ref_in_stripe(ref_stripe(&child)),
        ];
        let conditions = [RefWriteCondition::Missing, RefWriteCondition::Any];
        for round in 0..200usize {
            let dir = tmp();
            let barrier = Arc::new(Barrier::new(2));
            let run = |name: String, condition: RefWriteCondition, v: &[u8]| {
                let root = dir.path().to_path_buf();
                let barrier = Arc::clone(&barrier);
                let id = blake3_hash(v);
                std::thread::spawn(move || {
                    let t = FileTransport::new(root);
                    barrier.wait();
                    (t.update_ref(&name, condition, &id), id)
                })
            };
            let a = run(parent.clone(), conditions[round % 2], b"parent");
            let b = run(child.clone(), conditions[(round / 2) % 2], b"child");
            let ((ra, ia), (rb, ib)) = (a.join().unwrap(), b.join().unwrap());
            for r in [&ra, &rb] {
                assert!(
                    matches!(r, Ok(()) | Err(TransportError::InvalidRef(_))),
                    "round {round}: a clash must be InvalidRef, got {r:?}"
                );
            }
            assert_eq!(
                usize::from(ra.is_ok()) + usize::from(rb.is_ok()),
                1,
                "round {round}: exactly one of the two names must win"
            );
            let t = FileTransport::new(dir.path());
            let (winner, id, loser) = if ra.is_ok() {
                (&parent, ia, &child)
            } else {
                (&child, ib, &parent)
            };
            assert_eq!(t.read_ref(winner).unwrap(), Some(id), "round {round}");
            let leaked = temp_files_under(&dir.path().join("refs"));
            assert!(leaked.is_empty(), "round {round}: temp files {leaked:?}");
            for v in &victims {
                t.update_ref(v, RefWriteCondition::Missing, &blake3_hash(v.as_bytes()))
                    .unwrap();
            }
            let listed: Vec<String> = t
                .list_refs("refs/heads/")
                .unwrap()
                .into_iter()
                .map(|r| r.name)
                .collect();
            // The loser is absent. A read by its name can fail instead: its
            // path runs through, or is, the winner's file system entry.
            let want = winner.strip_prefix("refs/heads/").unwrap();
            assert_eq!(listed, [want], "round {round}: loser {loser}");
            t.with_ref_lock(|refs| {
                refs.update_ref(winner, RefWriteCondition::Match(id), &blake3_hash(b"next"))
            })
            .unwrap()
            .unwrap();
        }
    }

    // ------------------------------------------------------------------
    // Two-ref advance
    // ------------------------------------------------------------------

    fn id(v: u64) -> Hash {
        let mut x = [0u8; 32];
        x[..8].copy_from_slice(&v.to_le_bytes());
        x[31] = 1;
        x
    }

    fn version(x: Option<Hash>) -> u64 {
        x.map_or(0, |x| {
            let mut v = [0u8; 8];
            v.copy_from_slice(&x[..8]);
            u64::from_le_bytes(v)
        })
    }

    fn cond(v: u64) -> RefWriteCondition {
        if v == 0 {
            RefWriteCondition::Missing
        } else {
            RefWriteCondition::Match(id(v))
        }
    }

    const HEAD: &str = "refs/heads/main";
    const PACKMAP: &str = "refs/kit/packmap/main";

    fn advance(t: &FileTransport, from: u64, to: u64) -> TransportResult<AdvanceOutcome> {
        t.advance_refs(HEAD, cond(from), &id(to), PACKMAP, cond(from), &id(to))
    }

    /// The outcomes of `Transport::advance_refs`: both refs move, or
    /// nothing changes and the packmap conflict is reported first.
    #[test]
    fn an_advance_moves_both_refs_or_changes_nothing() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        assert_eq!(advance(&t, 0, 1).unwrap(), AdvanceOutcome::Committed);
        assert_eq!(advance(&t, 1, 2).unwrap(), AdvanceOutcome::Committed);
        let state = |t: &FileTransport| (t.read_ref(HEAD).unwrap(), t.read_ref(PACKMAP).unwrap());
        assert_eq!(state(&t), (Some(id(2)), Some(id(2))));

        // Both conditions stale: the packmap conflict is reported.
        assert_eq!(advance(&t, 1, 3).unwrap(), AdvanceOutcome::PackmapConflict);
        // Only the head stale: nothing changes, the packmap included.
        let r = t.advance_refs(HEAD, cond(1), &id(3), PACKMAP, cond(2), &id(3));
        assert_eq!(r.unwrap(), AdvanceOutcome::HeadConflict);
        assert_eq!(state(&t), (Some(id(2)), Some(id(2))));
        // Only the packmap stale.
        let r = t.advance_refs(HEAD, cond(2), &id(3), PACKMAP, cond(1), &id(3));
        assert_eq!(r.unwrap(), AdvanceOutcome::PackmapConflict);
        assert_eq!(state(&t), (Some(id(2)), Some(id(2))));
        // A create of an existing ref is a conflict, not an overwrite.
        let r = t.advance_refs(HEAD, cond(0), &id(3), PACKMAP, cond(2), &id(3));
        assert_eq!(r.unwrap(), AdvanceOutcome::HeadConflict);
        assert_eq!(state(&t), (Some(id(2)), Some(id(2))));
        // Unconditional writes.
        let any = RefWriteCondition::Any;
        let r = t.advance_refs(HEAD, any, &id(4), PACKMAP, any, &id(4));
        assert_eq!(r.unwrap(), AdvanceOutcome::Committed);
        assert_eq!(state(&t), (Some(id(4)), Some(id(4))));
        assert!(temp_files_under(&dir.path().join("refs")).is_empty());
    }

    #[test]
    fn an_advance_refuses_names_that_cannot_both_be_refs() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let a = RefWriteCondition::Missing;
        for (head, packmap) in [
            ("refs/heads/x", "refs/heads/x"),
            ("refs/heads/x", "refs/heads/x/y"),
            ("refs/heads/x/y", "refs/heads/x"),
            ("refs/heads/../x", "refs/kit/packmap/x"),
        ] {
            let r = t.advance_refs(head, a, &id(1), packmap, a, &id(1));
            assert!(
                matches!(r, Err(TransportError::InvalidRef(_))),
                "{head} {packmap}: {r:?}"
            );
        }
        assert!(t.list_refs("").unwrap().is_empty());
    }

    /// Two refs in one stripe take that stripe once.
    #[test]
    fn an_advance_of_two_refs_in_one_stripe_commits() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let s = ref_stripe("refs/heads/same");
        let other = (0..100_000)
            .map(|k| format!("refs/kit/packmap/same-{k}"))
            .find(|n| ref_stripe(n) == s)
            .unwrap();
        for (from, to) in [(0, 1), (1, 2)] {
            let r = t.advance_refs(
                "refs/heads/same",
                cond(from),
                &id(to),
                &other,
                cond(from),
                &id(to),
            );
            assert_eq!(r.unwrap(), AdvanceOutcome::Committed);
        }
        assert_eq!(t.read_ref(&other).unwrap(), Some(id(2)));
    }

    /// A crash between the two writes leaves the new packmap and the old
    /// head, both readable; the next advance from that state commits.
    #[test]
    fn a_crash_between_the_writes_leaves_the_new_packmap_and_the_old_head() {
        for from in [0, 1] {
            let dir = tmp();
            let t = FileTransport::new(dir.path());
            if from == 1 {
                advance(&t, 0, 1).unwrap();
            }
            advance_fault::set(advance_fault::Fault::CrashAfterPackmap);
            assert!(advance(&t, from, 2).is_err());
            let t = FileTransport::new(dir.path());
            assert_eq!(t.read_ref(PACKMAP).unwrap(), Some(id(2)));
            assert_eq!(version(t.read_ref(HEAD).unwrap()), from);
            assert!(temp_files_under(&dir.path().join("refs")).is_empty());
            let r = t.advance_refs(HEAD, cond(from), &id(3), PACKMAP, cond(2), &id(3));
            assert_eq!(r.unwrap(), AdvanceOutcome::Committed);
            t.with_ref_lock(|_| ()).unwrap();
        }
    }

    /// A failed head write puts the packmap back: the advance changes
    /// nothing, including a create, which leaves no file or directory.
    #[test]
    fn a_failed_head_write_restores_the_packmap() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        advance_fault::set(advance_fault::Fault::FailHead);
        assert!(
            t.advance_refs(
                "refs/heads/n/m",
                cond(0),
                &id(1),
                "refs/kit/packmap/n/m",
                cond(0),
                &id(1)
            )
            .is_err()
        );
        assert!(t.list_refs("").unwrap().is_empty());
        assert!(!dir.path().join("refs/kit/packmap/n").exists());

        advance(&t, 0, 1).unwrap();
        // The packmap was written and put back: its stripe counts both.
        let stripe = t.lock_dir().join(stripe_lock_file(ref_stripe(PACKMAP)));
        let count = || read_stripe_version(&fs::File::open(&stripe).unwrap()).unwrap();
        let before = count();
        advance_fault::set(advance_fault::Fault::FailHead);
        assert!(advance(&t, 1, 2).is_err());
        assert_eq!(count(), before + 2);
        assert_eq!(t.read_ref(PACKMAP).unwrap(), Some(id(1)));
        assert_eq!(t.read_ref(HEAD).unwrap(), Some(id(1)));
        assert!(temp_files_under(&dir.path().join("refs")).is_empty());
    }

    /// One round of a race between creates of `refs/heads/<p>` and
    /// `refs/heads/<p>/b` (each as an advance with its packmap, or as a
    /// single-ref write). Whatever the interleaving, one name wins, the
    /// other reports `InvalidRef`, nothing is left half-written, and the
    /// root stays usable.
    fn nested_create_round(parent: &str, parent_advances: bool, child_advances: bool) {
        use std::sync::{Arc, Barrier};
        let child = format!("{parent}/b");
        let dir = tmp();
        let barrier = Arc::new(Barrier::new(2));
        let run = |branch: String, advances: bool, v: u64| {
            let root = dir.path().to_path_buf();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let t = FileTransport::new(root);
                let head = format!("refs/heads/{branch}");
                barrier.wait();
                if advances {
                    let packmap = format!("refs/kit/packmap/{branch}");
                    t.advance_refs(&head, cond(0), &id(v), &packmap, cond(0), &id(v))
                        .map(|o| assert_eq!(o, AdvanceOutcome::Committed))
                } else {
                    t.update_ref(&head, cond(0), &id(v))
                }
            })
        };
        let a = run(parent.to_owned(), parent_advances, 1);
        let b = run(child.clone(), child_advances, 2);
        let (ra, rb) = (a.join().unwrap(), b.join().unwrap());
        for r in [&ra, &rb] {
            assert!(
                matches!(r, Ok(()) | Err(TransportError::InvalidRef(_))),
                "{r:?}"
            );
        }
        assert_eq!(usize::from(ra.is_ok()) + usize::from(rb.is_ok()), 1);
        let t = FileTransport::new(dir.path());
        let (winner, advanced) = if ra.is_ok() {
            (parent.to_owned(), parent_advances)
        } else {
            (child, child_advances)
        };
        let mut want = vec![format!("heads/{winner}")];
        if advanced {
            want.push(format!("kit/packmap/{winner}"));
        }
        let listed: Vec<String> = t
            .list_refs("refs/")
            .unwrap()
            .into_iter()
            .map(|r| r.name)
            .collect();
        assert_eq!(listed, want);
        assert!(temp_files_under(&dir.path().join("refs")).is_empty());
        for name in [
            format!("refs/heads/{parent}"),
            format!("refs/heads/{parent}/b"),
            format!("refs/kit/packmap/{parent}"),
            format!("refs/kit/packmap/{parent}/b"),
        ] {
            let victim = ref_in_stripe(ref_stripe(&name));
            t.update_ref(&victim, RefWriteCondition::Any, &id(9))
                .unwrap();
        }
        FileTransport::new(dir.path())
            .with_ref_lock(|_| ())
            .unwrap();
    }

    #[test]
    fn concurrent_advances_of_a_ref_and_a_ref_below_it_leave_the_root_usable() {
        for _ in 0..200 {
            nested_create_round("a", true, true);
        }
    }

    #[test]
    fn an_advance_racing_a_single_ref_create_below_or_above_it_leaves_the_root_usable() {
        for round in 0..300 {
            nested_create_round("a", round % 2 == 0, round % 2 == 1);
        }
    }

    /// Readers take no lock. One that reads the head, then the packmap,
    /// never sees a packmap older than the head it read: the packmap moves
    /// first.
    #[test]
    fn a_reader_never_sees_a_head_newer_than_its_packmap() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicU64};
        let dir = tmp();
        let stop = Arc::new(AtomicBool::new(false));
        let torn = Arc::new(AtomicU64::new(0));
        let writer = {
            let (root, stop) = (dir.path().to_path_buf(), Arc::clone(&stop));
            std::thread::spawn(move || {
                let t = FileTransport::new(root);
                let mut v = 0;
                while !stop.load(Ordering::Relaxed) || v < 50 {
                    assert_eq!(advance(&t, v, v + 1).unwrap(), AdvanceOutcome::Committed);
                    v += 1;
                }
                v
            })
        };
        let readers: Vec<_> = (0..8)
            .map(|_| {
                let (root, stop, torn) = (
                    dir.path().to_path_buf(),
                    Arc::clone(&stop),
                    Arc::clone(&torn),
                );
                std::thread::spawn(move || {
                    let t = FileTransport::new(root);
                    let mut pairs = 0u64;
                    while !stop.load(Ordering::Relaxed) {
                        let head = version(t.read_ref(HEAD).unwrap());
                        let packmap = version(t.read_ref(PACKMAP).unwrap());
                        if packmap < head {
                            torn.fetch_add(1, Ordering::Relaxed);
                        }
                        pairs += 1;
                    }
                    pairs
                })
            })
            .collect();
        std::thread::sleep(std::time::Duration::from_secs(2));
        stop.store(true, Ordering::Relaxed);
        let advances = writer.join().unwrap();
        let pairs: u64 = readers.into_iter().map(|r| r.join().unwrap()).sum();
        assert!(advances >= 50 && pairs > 0);
        assert_eq!(
            torn.load(Ordering::Relaxed),
            0,
            "{advances} advances, {pairs} read pairs"
        );
    }

    /// Advances on overlapping pairs of refs, single-ref writes and
    /// exclusive steps, from many threads, all finish.
    #[test]
    fn mixed_advances_and_writes_do_not_deadlock() {
        use std::sync::mpsc;
        let dir = tmp();
        let names: Vec<String> = (0..6).map(|i| format!("refs/heads/d{i}")).collect();
        let (done_tx, done_rx) = mpsc::channel();
        for th in 0..8u64 {
            let (root, names, done_tx) = (dir.path().to_path_buf(), names.clone(), done_tx.clone());
            std::thread::spawn(move || {
                let t = FileTransport::new(root);
                let any = RefWriteCondition::Any;
                for i in 0..200u64 {
                    let pick =
                        |k: u64| names[usize::try_from((th * 7 + i * k) % 6).unwrap()].clone();
                    let (a, b) = (pick(1), pick(5));
                    match i % 4 {
                        0 | 1 if a != b => {
                            t.advance_refs(&a, any, &id(i), &b, any, &id(i)).unwrap();
                        }
                        2 => t.with_ref_lock(|_| ()).unwrap(),
                        _ => t.update_ref(&a, any, &id(i)).unwrap(),
                    }
                }
                done_tx.send(()).unwrap();
            });
        }
        for _ in 0..8 {
            done_rx
                .recv_timeout(std::time::Duration::from_secs(120))
                .expect("a writer did not finish: deadlock");
        }
    }

    #[test]
    fn writers_to_different_refs_all_commit() {
        use std::sync::Arc;
        let dir = tmp();
        let handles: Vec<_> = (0..16)
            .map(|i| {
                let root = dir.path().to_path_buf();
                std::thread::spawn(move || {
                    let t = FileTransport::new(root);
                    let name = format!("refs/heads/w{i}");
                    let mut prev = None;
                    for n in 0..20u8 {
                        let next = blake3_hash(&[i, n]);
                        let cond =
                            prev.map_or(RefWriteCondition::Missing, RefWriteCondition::Match);
                        t.update_ref(&name, cond, &next).unwrap();
                        prev = Some(next);
                    }
                    (name, prev.unwrap())
                })
            })
            .collect();
        let t = Arc::new(FileTransport::new(dir.path()));
        for h in handles {
            let (name, last) = h.join().unwrap();
            assert_eq!(t.read_ref(&name).unwrap(), Some(last));
        }
    }

    #[test]
    fn ref_writes_refuse_a_root_marked_for_server_sqlite_meta() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let h = blake3_hash(b"before");
        t.write_ref("refs/heads/main", &h).unwrap();
        fs::create_dir_all(dir.path().join(".kit")).unwrap();
        fs::write(dir.path().join(SERVER_META_MARKER), b"marked").unwrap();

        // Every write path refuses, naming the marker; nothing changes.
        let err = t.write_ref("refs/heads/main", &blake3_hash(b"after"));
        match err {
            Err(TransportError::RemoteError(msg)) => {
                assert!(
                    msg.contains("SQLite") && msg.contains("server-meta"),
                    "{msg}"
                );
            }
            other => panic!("{other:?}"),
        }
        let refused = t
            .with_ref_lock(|refs| {
                let update = refs.update_ref("refs/heads/x", RefWriteCondition::Missing, &h);
                let delete = refs.delete_ref("refs/heads/main");
                let file = refs.write_file(Path::new(".kit/server/rows/a"), b"x");
                let remove = refs.remove_file(Path::new(".kit/server/rows/a"));
                [update.err(), delete.err(), file.err(), remove.err()]
            })
            .unwrap();
        for err in refused {
            assert!(
                matches!(err, Some(RefFileError::MetaElsewhere(_))),
                "{err:?}"
            );
        }
        // Reads still work.
        assert_eq!(t.read_ref("refs/heads/main").unwrap(), Some(h));
        assert_eq!(t.list_refs("").unwrap().len(), 1);
        // Packs are shared with the server and still upload.
        let key = PackKey(blake3_hash(b"pack"));
        t.upload_pack(b"pack", &key).unwrap();
    }

    #[test]
    fn delete_ref_removes_the_file_once_and_prunes_empty_dirs() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let h = blake3_hash(b"gone");
        t.update_ref("refs/heads/team/a", RefWriteCondition::Any, &h)
            .unwrap();
        t.update_ref("refs/tags/v1", RefWriteCondition::Any, &h)
            .unwrap();
        let removed = t
            .with_ref_lock(|refs| {
                (
                    refs.delete_ref("refs/heads/team/a").unwrap(),
                    refs.delete_ref("refs/heads/team/a").unwrap(),
                )
            })
            .unwrap();
        assert_eq!(removed, (true, false));
        assert_eq!(t.read_ref("refs/heads/team/a").unwrap(), None);
        // The emptied `refs/heads/team` and `refs/heads` are gone; `refs`
        // and the non-empty `refs/tags` stay.
        assert!(!dir.path().join("refs/heads").exists());
        assert!(dir.path().join("refs/tags/v1").is_file());
        // So the name is free for a ref file again.
        t.update_ref("refs/heads/team", RefWriteCondition::Missing, &h)
            .unwrap();
        let invalid = t.with_ref_lock(|refs| refs.delete_ref("../x")).unwrap();
        assert!(matches!(invalid, Err(RefFileError::InvalidName(_))));
        // A directory where the ref file would be is no ref.
        let dir_ref = t.with_ref_lock(|refs| refs.delete_ref("refs")).unwrap();
        assert!(!dir_ref.unwrap());
    }

    #[test]
    fn ref_directory_file_clashes_are_invalid_names() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let h = blake3_hash(b"clash");
        t.update_ref("refs/heads/a/b", RefWriteCondition::Any, &h)
            .unwrap();
        t.update_ref("refs/heads/c", RefWriteCondition::Any, &h)
            .unwrap();
        for name in ["refs/heads/a", "refs/heads/c/d"] {
            for condition in [RefWriteCondition::Any, RefWriteCondition::Missing] {
                let err = t.update_ref(name, condition, &h).unwrap_err();
                assert!(
                    matches!(err, TransportError::InvalidRef(_)),
                    "{name}: {err:?}"
                );
            }
        }
        assert_eq!(t.read_ref_strict("refs/heads/a").unwrap(), None);
        assert_eq!(t.read_ref_strict("refs/heads/c").unwrap(), Some(h));
    }

    #[test]
    fn oversized_ref_file_is_corrupt_and_is_not_read_whole() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let h = blake3_hash(b"ok");
        t.update_ref("refs/heads/ok", RefWriteCondition::Any, &h)
            .unwrap();
        // A valid hash followed by blanks past the cap is still malformed.
        let mut big = format!("{}\n", kit_core::hash::to_hex(&h)).into_bytes();
        big.resize(usize::try_from(REF_FILE_MAX_BYTES).unwrap() + 1, b' ');
        fs::write(dir.path().join("refs/heads/big"), &big).unwrap();
        assert_eq!(t.read_ref("refs/heads/big").unwrap(), None);
        assert_eq!(t.list_refs("refs/").unwrap().len(), 1);
        assert!(matches!(
            t.read_ref_strict("refs/heads/big"),
            Err(RefFileError::Corrupt(_))
        ));
        assert_eq!(
            t.list_ref_files("refs/").unwrap(),
            vec![
                ("refs/heads/big".to_owned(), None),
                ("refs/heads/ok".to_owned(), Some(h)),
            ]
        );
    }

    #[test]
    fn strict_reads_report_corrupt_ref_files() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let h = blake3_hash(b"ok");
        t.update_ref("refs/heads/ok", RefWriteCondition::Any, &h)
            .unwrap();
        fs::write(dir.path().join("refs/heads/bad"), b"not a ref\n").unwrap();
        // The lenient verbs treat it as absent and skip it...
        assert_eq!(t.read_ref("refs/heads/bad").unwrap(), None);
        assert_eq!(t.list_refs("refs/").unwrap().len(), 1);
        // ...the strict ones report it.
        assert!(matches!(
            t.read_ref_strict("refs/heads/bad"),
            Err(RefFileError::Corrupt(_))
        ));
        assert_eq!(
            t.list_ref_files("refs/").unwrap(),
            vec![
                ("refs/heads/bad".to_owned(), None),
                ("refs/heads/ok".to_owned(), Some(h)),
            ]
        );
        fs::remove_file(dir.path().join("refs/heads/bad")).unwrap();
        // Temp and lock files are not refs.
        fs::write(dir.path().join("refs/heads/.ok.tmp.1.2"), b"junk").unwrap();
        assert_eq!(
            t.list_ref_files("refs").unwrap(),
            vec![("refs/heads/ok".to_owned(), Some(h))]
        );
        assert_eq!(t.list_ref_files("refs/tags/").unwrap(), vec![]);
        assert!(t.list_ref_files("").is_err());
    }

    #[test]
    fn locked_file_writes_stay_under_the_server_dir() {
        let dir = tmp();
        let t = FileTransport::new(dir.path());
        let rel = Path::new(".kit/server/row");
        t.with_ref_lock(|refs| {
            refs.write_file(rel, b"v1").unwrap();
            refs.write_file(rel, b"v2").unwrap();
            for bad in [
                "",
                "/abs",
                "../up",
                "a/../b",
                "./a",
                ".kit/server",
                ".kit/server/../refs/.lock",
                ".kit/refs/.lock",
                "refs/x",
                "packs/x",
            ] {
                let write = refs.write_file(Path::new(bad), b"x");
                assert!(matches!(write, Err(RefFileError::Escape(_))), "{bad}");
                let remove = refs.remove_file(Path::new(bad));
                assert!(matches!(remove, Err(RefFileError::Escape(_))), "{bad}");
            }
        })
        .unwrap();
        assert_eq!(fs::read(dir.path().join(rel)).unwrap(), b"v2");
        assert!(!dir.path().join("refs/x").exists() && !dir.path().join("packs").exists());
        let removed = t
            .with_ref_lock(|refs| {
                (
                    refs.remove_file(rel).unwrap(),
                    refs.remove_file(rel).unwrap(),
                )
            })
            .unwrap();
        assert_eq!(removed, (true, false));
    }

    #[cfg(unix)]
    #[test]
    fn locked_file_writes_reject_a_symlinked_server_dir() {
        use std::os::unix::fs::symlink;

        let dir = tmp();
        let outside = tmp();
        fs::create_dir_all(dir.path().join(".kit")).unwrap();
        symlink(outside.path(), dir.path().join(".kit/server")).unwrap();
        let t = FileTransport::new(dir.path());
        let result = t
            .with_ref_lock(|refs| refs.write_file(Path::new(".kit/server/row"), b"x"))
            .unwrap();
        assert!(matches!(result, Err(RefFileError::Escape(_))));
        assert!(!outside.path().join("row").exists());
        // A symlink to a directory inside the root is refused too.
        fs::remove_file(dir.path().join(".kit/server")).unwrap();
        fs::create_dir_all(dir.path().join("refs")).unwrap();
        symlink(dir.path().join("refs"), dir.path().join(".kit/server")).unwrap();
        assert!(matches!(
            t.server_path(Path::new(".kit/server/row")),
            Err(RefFileError::Escape(_))
        ));
    }

    #[test]
    fn create_dir_all_durably_creates_nested_dirs() {
        let dir = tmp();
        let nested = dir.path().join("a/b/c");
        create_dir_all_durably(&nested).unwrap();
        assert!(nested.is_dir());
        create_dir_all_durably(&nested).unwrap();
        fs::write(dir.path().join("file"), b"x").unwrap();
        assert!(create_dir_all_durably(&dir.path().join("file/sub")).is_err());
    }

    #[test]
    fn temp_paths_are_unique_hidden_siblings() {
        let dest = Path::new("/r/packs/abc");
        let (a, b) = (temp_path(dest).unwrap(), temp_path(dest).unwrap());
        assert_ne!(a, b);
        assert_eq!(a.parent(), dest.parent());
        let name = a.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with(".kit.tmp."), "{name}");
        assert!(temp_path(Path::new("/")).is_err());
    }

    type Hook = Option<Box<dyn FnMut()>>;

    thread_local! {
        /// Runs inside a ref write, after the rename and before the count.
        pub(super) static BETWEEN_WRITE_AND_COUNT: std::cell::RefCell<Hook> =
            const { std::cell::RefCell::new(None) };
    }

    /// The count comes after the rename: between them the ref already holds
    /// the new value and its stripe still holds the old count. A count
    /// before the rename would let a reader pair the new cursor with the
    /// old ref.
    #[test]
    fn a_write_counts_after_its_rename() {
        let dir = tmp();
        let tx = FileTransport::new(dir.path());
        let name = "refs/heads/main";
        tx.update_ref(name, RefWriteCondition::Missing, &value(0, 0))
            .unwrap();
        let stripe = tx.lock_dir().join(stripe_lock_file(ref_stripe(name)));
        let count = |path: &Path| read_stripe_version(&fs::File::open(path).unwrap()).unwrap();
        let before = count(&stripe);
        let seen = std::rc::Rc::new(std::cell::Cell::new(None));
        let (seen_in, ref_path, stripe_in) = (seen.clone(), tx.ref_path(name), stripe.clone());
        BETWEEN_WRITE_AND_COUNT.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                let current = read_ref_raw(&ref_path).unwrap();
                seen_in.set(Some((current, count(&stripe_in))));
            }));
        });
        tx.update_ref(name, RefWriteCondition::Match(value(0, 0)), &value(0, 1))
            .unwrap();
        BETWEEN_WRITE_AND_COUNT.with(|hook| *hook.borrow_mut() = None);
        assert_eq!(seen.get(), Some((Some(value(0, 1)), before)));
        assert_eq!(count(&stripe), before + 1);
    }

    /// A clock past the window in which a fresh directory time is not
    /// trusted, as if every write so far had settled.
    fn settled_now() -> std::time::SystemTime {
        std::time::SystemTime::now() + RACY_WINDOW + std::time::Duration::from_secs(1)
    }

    /// The cursor once every write so far has settled.
    #[cfg(target_os = "linux")]
    fn cursor(tx: &FileTransport) -> Hash {
        tx.repo_cursor_digest_at(settled_now())
            .unwrap()
            .expect("a cursor on Linux")
    }

    fn value(writer: usize, step: usize) -> Hash {
        let mut h = [0u8; 32];
        h[0] = 1;
        h[1] = u8::try_from(writer).unwrap();
        h[2..10].copy_from_slice(&(step as u64).to_le_bytes());
        h
    }

    /// The step of `writer` that `h` names.
    #[cfg(target_os = "linux")]
    fn step_of(h: &Hash) -> u64 {
        u64::from_le_bytes(h[2..10].try_into().unwrap())
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn every_committed_write_changes_the_cursor() {
        let dir = tmp();
        let tx = FileTransport::new(dir.path());
        let mut seen = std::collections::HashSet::new();
        assert!(seen.insert(cursor(&tx)));
        let name = "refs/heads/main";
        tx.update_ref(name, RefWriteCondition::Missing, &value(0, 0))
            .unwrap();
        assert!(seen.insert(cursor(&tx)), "a Missing write");
        tx.update_ref(name, RefWriteCondition::Match(value(0, 0)), &value(0, 1))
            .unwrap();
        assert!(seen.insert(cursor(&tx)), "a Match write");
        tx.update_ref(name, RefWriteCondition::Any, &value(0, 1))
            .unwrap();
        assert!(seen.insert(cursor(&tx)), "an Any write of the same value");
        tx.with_ref_lock(|refs| {
            refs.update_ref("refs/heads/b", RefWriteCondition::Any, &value(1, 0))
        })
        .unwrap()
        .unwrap();
        assert!(
            seen.insert(cursor(&tx)),
            "a write under the exclusive repo lock"
        );
        assert!(
            tx.with_ref_lock(|refs| refs.delete_ref(name))
                .unwrap()
                .unwrap()
        );
        assert!(seen.insert(cursor(&tx)), "a delete");
        // A failed CAS changes no ref. Its temporary file may still move a
        // directory time, and with it the cursor, which only costs a fetch.
        let failed = tx.update_ref("refs/heads/b", RefWriteCondition::Missing, &value(1, 1));
        assert!(matches!(failed, Err(TransportError::RefConflict)));
        // Reading the cursor writes no ref.
        assert_eq!(tx.list_refs("refs/").unwrap().len(), 1);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn a_recreated_root_never_reuses_a_cursor() {
        let dir = tmp();
        let root = dir.path().join("root");
        let first = {
            let tx = FileTransport::new(&root);
            tx.update_ref("refs/heads/main", RefWriteCondition::Missing, &value(0, 0))
                .unwrap();
            cursor(&tx)
        };
        fs::remove_dir_all(&root).unwrap();
        let tx = FileTransport::new(&root);
        tx.update_ref("refs/heads/main", RefWriteCondition::Missing, &value(0, 0))
            .unwrap();
        assert_ne!(cursor(&tx), first);
    }

    #[test]
    fn a_lock_file_without_a_version_is_corrupt() {
        let dir = tmp();
        let tx = FileTransport::new(dir.path());
        tx.update_ref("refs/heads/main", RefWriteCondition::Missing, &value(0, 0))
            .unwrap();
        let stripe = tx
            .lock_dir()
            .join(stripe_lock_file(ref_stripe("refs/heads/main")));
        fs::write(&stripe, b"abc").unwrap();
        let err = tx.update_ref("refs/heads/main", RefWriteCondition::Any, &value(0, 1));
        assert!(err.is_err(), "a garbled count fails the write");
        if cfg!(target_os = "linux") {
            assert!(matches!(
                tx.repo_cursor_digest_at(settled_now()),
                Err(RefFileError::Corrupt(_))
            ));
        }
    }

    /// Writers advance their own refs while a reader takes (cursor, listing)
    /// pairs. Whenever a later cursor equals an earlier one, the earlier
    /// listing already holds every write that completed before the later
    /// cursor was read.
    #[test]
    #[cfg(target_os = "linux")]
    fn an_equal_cursor_misses_no_completed_write() {
        // The race this checks is narrow, so the scenario runs many times.
        for _ in 0..20 {
            equal_cursor_round();
        }
    }

    #[cfg(target_os = "linux")]
    fn equal_cursor_round() {
        use std::sync::atomic::{AtomicU64, Ordering};
        const WRITERS: usize = 2;
        const STEPS: usize = 40;
        let dir = tmp();
        let done: Vec<AtomicU64> = (0..WRITERS).map(|_| AtomicU64::new(0)).collect();
        let finished = AtomicU64::new(0);
        std::thread::scope(|s| {
            for w in 0..WRITERS {
                let (done, finished, root) = (&done, &finished, dir.path());
                s.spawn(move || {
                    let tx = FileTransport::new(root);
                    let name = format!("refs/heads/w{w}");
                    for step in 1..=STEPS {
                        tx.update_ref(&name, RefWriteCondition::Any, &value(w, step))
                            .unwrap();
                        done[w].store(step as u64, Ordering::SeqCst);
                        // Quiet gaps let the reader see equal cursors.
                        std::thread::sleep(std::time::Duration::from_millis(2));
                    }
                    finished.fetch_add(1, Ordering::SeqCst);
                });
            }
            let tx = FileTransport::new(dir.path());
            let mut history: Vec<(Hash, Vec<u64>)> = Vec::new();
            let mut equal = 0usize;
            let mut after_last_write = 0;
            loop {
                let all_done = finished.load(Ordering::SeqCst) == WRITERS as u64;
                // Writes completed before the cursor read.
                let completed: Vec<u64> = done.iter().map(|d| d.load(Ordering::SeqCst)).collect();
                let c = cursor(&tx);
                let listing = tx.list_refs("refs/heads/").unwrap();
                let mut steps = vec![0u64; WRITERS];
                for r in &listing {
                    let w: usize = r.name.trim_start_matches('w').parse().unwrap();
                    steps[w] = step_of(&r.hash.unwrap());
                }
                for (earlier, earlier_steps) in &history {
                    if *earlier == c {
                        equal += 1;
                        for w in 0..WRITERS {
                            assert!(
                                earlier_steps[w] >= completed[w],
                                "writer {w}: listing at step {}, a write of step {} completed before an equal cursor",
                                earlier_steps[w],
                                completed[w]
                            );
                        }
                    }
                }
                history.push((c, steps));
                if all_done {
                    after_last_write += 1;
                    if after_last_write == 2 {
                        break;
                    }
                }
            }
            // The last two observations follow the last write, so their
            // cursors are equal and the check above ran.
            assert!(equal > 0);
        });
    }

    /// A write as kit 0.7.3 makes it: the repo lock exclusive, the ref file
    /// by a temporary file and a rename, no stripe count. `None` deletes.
    #[cfg(target_os = "linux")]
    fn old_writer(root: &Path, name: &str, value: Option<&Hash>) {
        let _lock = RefLock::acquire(root).unwrap();
        let dest = root.join(name);
        match value {
            Some(hash) => {
                fs::create_dir_all(dest.parent().unwrap()).unwrap();
                let tmp = temp_path(&dest).unwrap();
                fs::write(&tmp, encode_ref_wire(hash)).unwrap();
                fs::rename(&tmp, &dest).unwrap();
            }
            None => fs::remove_file(&dest).unwrap(),
        }
    }

    /// Set the modification time of every directory under `<root>/refs`
    /// `age` into the past, as if the last write were that old.
    #[cfg(target_os = "linux")]
    fn age_ref_dirs(root: &Path, age: std::time::Duration) {
        let when = std::time::SystemTime::now() - age;
        let mut dirs = vec![root.join("refs")];
        while let Some(dir) = dirs.pop() {
            for entry in fs::read_dir(&dir).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_dir() {
                    dirs.push(entry.path());
                }
            }
            fs::File::open(&dir).unwrap().set_modified(when).unwrap();
        }
    }

    /// A writer that takes the repo lock exclusive and writes no count, as
    /// kit 0.7.3 does, still changes the cursor: a create, an overwrite, a
    /// create in a new directory, an overwrite there and a delete each leave a cursor that
    /// differs from the one before, or no cursor.
    #[test]
    #[cfg(target_os = "linux")]
    fn a_writer_that_does_not_count_still_changes_the_cursor() {
        let dir = tmp();
        let tx = FileTransport::new(dir.path());
        tx.update_ref("refs/heads/main", RefWriteCondition::Missing, &value(0, 0))
            .unwrap();
        let steps: [(&str, Option<Hash>); 5] = [
            ("refs/heads/main", Some(value(0, 1))),
            ("refs/heads/other", Some(value(1, 0))),
            ("refs/heads/topic/x", Some(value(2, 0))),
            ("refs/heads/topic/x", Some(value(2, 1))),
            ("refs/heads/other", None),
        ];
        for (name, write) in steps {
            age_ref_dirs(dir.path(), std::time::Duration::from_secs(60));
            let before = tx.repo_cursor_digest().unwrap();
            assert!(before.is_some(), "a settled root offers a cursor");
            old_writer(dir.path(), name, write.as_ref());
            assert_ne!(
                tx.repo_cursor_digest().unwrap(),
                before,
                "{name}: an uncounted write left the cursor equal"
            );
            // Once the write is old enough to trust, the cursor is offered
            // again and still differs.
            let settled = tx.repo_cursor_digest_at(settled_now()).unwrap();
            assert!(settled.is_some() && settled != before, "{name}");
        }
    }

    /// Right after a write the directory's time is too fresh to tell a
    /// later write in the same clock tick apart, so no cursor is offered.
    #[test]
    #[cfg(target_os = "linux")]
    fn a_cursor_is_withheld_while_a_ref_directory_is_fresh() {
        let dir = tmp();
        let tx = FileTransport::new(dir.path());
        tx.update_ref("refs/heads/main", RefWriteCondition::Missing, &value(0, 0))
            .unwrap();
        assert_eq!(tx.repo_cursor_digest().unwrap(), None);
        assert!(tx.repo_cursor_digest_at(settled_now()).unwrap().is_some());
        // A directory time ahead of the clock is no more trusted.
        let ahead = std::time::SystemTime::now() + std::time::Duration::from_secs(3_600);
        fs::File::open(dir.path().join("refs/heads"))
            .unwrap()
            .set_modified(ahead)
            .unwrap();
        assert_eq!(tx.repo_cursor_digest_at(settled_now()).unwrap(), None);
    }

    /// A read that finds a fresh ref directory offers no cursor whatever the
    /// counts hold, so it reads no count and never waits behind a write that
    /// holds a stripe lock. A read past the window still waits for it.
    #[test]
    #[cfg(target_os = "linux")]
    fn a_withheld_cursor_does_not_wait_for_a_held_stripe() {
        use std::sync::mpsc;
        use std::time::Duration;
        let dir = tmp();
        let tx = FileTransport::new(dir.path());
        tx.update_ref("refs/heads/main", RefWriteCondition::Missing, &value(0, 0))
            .unwrap();
        let fresh = std::time::SystemTime::now();
        let lock = RefLock::acquire_stripe(dir.path(), ref_stripe("refs/heads/main")).unwrap();
        let (send, recv) = mpsc::channel();
        let reader = |now: std::time::SystemTime| {
            let (root, send) = (dir.path().to_path_buf(), send.clone());
            std::thread::spawn(move || {
                let t = FileTransport::new(root);
                send.send(t.repo_cursor_digest_at(now).map_err(|e| e.to_string()))
                    .unwrap();
            })
        };
        let withheld = reader(fresh);
        let got = recv.recv_timeout(Duration::from_secs(5));
        let settled = reader(settled_now());
        let premature = recv.recv_timeout(Duration::from_millis(100));
        drop(lock);
        withheld.join().unwrap();
        settled.join().unwrap();
        assert_eq!(got, Ok(Ok(None)), "a withheld cursor waited for a stripe");
        assert!(
            matches!(premature, Err(mpsc::RecvTimeoutError::Timeout)),
            "a cursor read bypassed a held stripe lock: {premature:?}"
        );
        assert!(matches!(
            recv.recv_timeout(Duration::from_secs(5)),
            Ok(Ok(Some(_)))
        ));
    }
}

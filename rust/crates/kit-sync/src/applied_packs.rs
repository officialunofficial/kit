//! Local record of pack digests already applied to this repo's object
//! store, keyed by remote — the fetch-side redownload-avoidance cache for
//!
//! Fetch walks only the packmap suffix after a verified branch checkpoint,
//! or the whole chain when no checkpoint is usable. [`AppliedPacks`] skips
//! previously applied packs within that walk. Checkpoints live separately
//! under `applied-packs/.heads/`; see the sync README for their format.
//!
//! # Format
//!
//! One file per remote: `.kit/applied-packs/<record>` (the `applied-packs/`
//! directory is created on first write). Contents are a lowercase 64-hex
//! BLAKE3 pack digest per line, LF-terminated, with no header. Unknown or
//! malformed lines are ignored on load, so a torn final line from a killed
//! process is harmless. A fetch appends one line per pack as it applies the
//! pack ([`AppliedPacks::record_applied`]), with no fsync. At the write limit,
//! compaction keeps the newest digests in file order and leaves room for
//! further appends. Persist makes no device flush: a lost line costs one
//! download. Compaction, a clear, and retries of failed appends rewrite the
//! record with a temporary file and a rename, with no flush. A shared
//! repository lock protects the writable record across replacements.
//!
//! `<record>` is the remote *name* with any `/` percent-encoded to `%2F`
//! (see [`record_file_name`]) so a legal multi-segment remote like
//! `team/upstream` maps to one flat file rather than a nested subdirectory.
//! [`AppliedPacks::load`] validates the name with
//! [`kit_core::refs::validate_ref_name`] — the same check `kit remote add`
//! applies, so any remote that can be configured can also be recorded. That
//! grammar admits `A-Za-z0-9._-` plus `/` as the segment separator, which
//! guarantees the name never contains `%` (keeping the `%2F` encoding
//! unambiguous and reversible) and rejects the control-char / `.lock` / `.`
//! / `..` cases a bespoke blacklist would miss.
//!
//! # Correctness posture
//!
//! [`kit_core::pack::PackReader::read`] is idempotent (content-addressed
//! writes, full digest re-verification), so skipping a recorded pack is
//! purely a performance win, never a correctness risk *on its own*. The one
//! hazard this record introduces is staleness relative to the object store
//! (e.g. `.kit/objects` wiped out-of-band while `applied-packs/` survives);
//! the fetch-side self-heal path in `apply_and_verify_chain` handles that by
//! clearing the record and retrying once with a full re-download whenever a
//! run that skipped at least one pack then finds an object missing.
//!
//! # Repo-layout classification (cross-link: `RepoLayout`)
//!
//! `RepoLayout` owns the path of this record. The path is classified as
//! **common-dir (shared) state**: the record
//! describes what is already in the shared object store, so every worktree
//! of a repo shares one record per remote — it is NOT per-worktree state.
//!
//! It is also a pure **cache**, never a root: `kit gc`'s
//! `ops::gc::collect_roots` must never treat any digest listed here as
//! pinning an object, and the file (and its containing directory) is always
//! safe to delete — a missing record just means the next fetch re-downloads
//! the whole chain once, per the self-heal behaviour above.
//!
//! # Lifecycle
//!
//! The record's lifecycle follows its remote's: `kit remote remove` calls
//! [`AppliedPacks::remove_record`] and `kit remote rename` calls
//! [`AppliedPacks::rename_record`], so a removed name never leaves a stale
//! record behind (which a later re-add would inherit, tripping the self-heal
//! full re-download once the store has been gc'd) and a renamed remote keeps
//! its cache instead of re-downloading its full closure. Both are idempotent:
//! a missing record is the normal state for a never-fetched remote, not an
//! error. Every path derivation — fetch-side loads and lifecycle ops alike —
//! routes through [`record_path`], so the two cannot drift.

use kit_core::layout::RepoLayout;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use kit_core::durable::Parents;
use kit_core::hash::{HEX_LEN, Hash, to_hex};
use kit_core::protocol::PackKey;
use kit_core::repo_lock::{RepoLock, acquire_default};

use crate::error::SyncError;
use crate::observer::{Observer, SyncEvent};

/// Longest applied-pack record that kit reads (64 MiB). The record is a
/// cache. A longer file is an error, and the fetch path then starts from
/// an empty record.
const RECORD_MAX_BYTES: u64 = 64 * 1024 * 1024;
const RECORD_MAX_ENTRIES: usize = 1_000_000;
const RECORD_LINE_BYTES: usize = HEX_LEN + 1;
const RECORD_WRITE_MAX_BYTES: u64 = (RECORD_MAX_ENTRIES * RECORD_LINE_BYTES) as u64;
const RECORD_COMPACT_ENTRIES: usize = 900_000;
const RECORD_LOCK: &str = "applied-packs.lock";

#[derive(Debug, Default)]
struct PackHints {
    /// A true value marks a failed append or a digest recorded after a clear.
    needs_write: HashMap<Hash, bool>,
    oldest_first: VecDeque<Hash>,
    pending: usize,
}

impl PackHints {
    fn load(bytes: &[u8]) -> Self {
        let mut hints = Self::default();
        for digest in digest_lines(bytes).rev() {
            if hints.oldest_first.len() == RECORD_MAX_ENTRIES {
                break;
            }
            if hints.needs_write.insert(digest, false).is_none() {
                hints.oldest_first.push_front(digest);
            }
        }
        hints
    }

    fn remember(&mut self, digest: Hash, needs_write: bool, limit: usize) {
        if self.oldest_first.len() == limit
            && let Some(oldest) = self.oldest_first.pop_front()
        {
            self.pending -= usize::from(self.needs_write.remove(&oldest) == Some(true));
        }
        self.oldest_first.push_back(digest);
        self.needs_write.insert(digest, needs_write);
        self.pending += usize::from(needs_write);
    }

    fn unwritten(&self) -> impl DoubleEndedIterator<Item = Hash> + '_ {
        self.oldest_first
            .iter()
            .copied()
            .filter(|digest| self.needs_write.get(digest) == Some(&true))
    }

    fn mark_written(&mut self) {
        self.pending = 0;
        for needs_write in self.needs_write.values_mut() {
            *needs_write = false;
        }
    }
}

/// A local record of pack digests already unpacked into this repo's object
/// store for one remote. See the module docs for the on-disk format and the
/// self-heal contract.
#[derive(Debug)]
pub struct AppliedPacks {
    hints: PackHints,
    path: PathBuf,
    lock_dir: PathBuf,
    clear_pending: bool,
    dirty: bool,
    /// A write to the record has failed and been reported. Later failures stay
    /// silent, so an unwritable record costs one warning per fetch, not one
    /// per pack.
    failure_reported: bool,
}

impl AppliedPacks {
    /// Load the record for `remote` under `kit_dir` (the `.kit/`
    /// directory). A missing file yields an empty set — this is the normal
    /// state for a fresh clone, not an error.
    ///
    /// # Errors
    ///
    /// [`SyncError::InvalidRemoteName`] if `remote` is not a legal ref
    /// name (per [`kit_core::refs::validate_ref_name`]). Any other I/O
    /// failure reading the file propagates as [`SyncError::Io`]. The
    /// fetch path treats both as non-fatal — the record is a pure cache — via
    /// [`Self::load_or_empty`].
    pub fn load(layout: &RepoLayout, remote: &str) -> Result<Self, SyncError> {
        validate_remote_name(remote)?;
        let path = record_path(layout, remote);
        let hints = match kit_core::bounded_read::read_capped(&path, RECORD_MAX_BYTES) {
            Ok(bytes) => PackHints::load(&bytes),
            Err(e) if e.kind() == io::ErrorKind::NotFound => PackHints::default(),
            Err(e) => return Err(SyncError::Io(e)),
        };
        Ok(Self {
            hints,
            path,
            lock_dir: layout.common_dir().to_owned(),
            clear_pending: false,
            dirty: false,
            failure_reported: false,
        })
    }

    /// [`Self::load`], with the fetch path's non-fatal policy folded in: the
    /// applied-pack record is purely a performance cache, so a fetch
    /// whose objects durably land must never fail because the cache couldn't
    /// be read. On any load error this warns and falls back to an empty
    /// in-memory record (every pack re-downloads, always correct); persisting
    /// is still attempted best-effort through the normal path.
    pub fn load_or_empty(
        layout: &RepoLayout,
        remote: &str,
        observer: &dyn Observer<SyncEvent>,
    ) -> Self {
        Self::load(layout, remote).unwrap_or_else(|e| {
            observer.event(&SyncEvent::AppliedPacksUnreadable {
                remote: remote.to_owned(),
                error: e.to_string(),
            });
            Self {
                hints: PackHints::default(),
                path: record_path(layout, remote),
                lock_dir: layout.common_dir().to_owned(),
                clear_pending: false,
                dirty: false,
                failure_reported: false,
            }
        })
    }

    /// True iff `key`'s digest is already recorded as applied.
    #[must_use]
    pub fn contains(&self, key: &PackKey) -> bool {
        self.hints.needs_write.contains_key(&key.into_hash())
    }

    /// Record `key`'s digest as applied and append it to the on-disk record
    /// at once, so a fetch that dies later still skips this pack. The append
    /// is one `hex\n` line with no fsync: the record is a cache, and a torn or
    /// lost line is ignored on load and costs one download. The digest is
    /// recorded in memory even when the append fails. At the write limit,
    /// the newest digests replace the file atomically. [`Self::persist`]
    /// retries failed appends, and flushes nothing. If a clear is
    /// pending, it publishes the digests recorded since the clear.
    ///
    /// # Errors
    ///
    /// The I/O error of creating the directory or appending the line, when no
    /// write to this record has failed before. Later failures return `Ok`, so a
    /// caller that reports each error reports an unwritable record once.
    pub fn record_applied(&mut self, key: &PackKey) -> io::Result<()> {
        let digest = key.into_hash();
        if self.contains(key) {
            return Ok(());
        }
        self.dirty = true;
        if self.clear_pending {
            self.hints.remember(digest, true, RECORD_MAX_ENTRIES);
            return Ok(());
        }
        let result = self.append_line(digest);
        self.hints
            .remember(digest, result.is_err(), RECORD_MAX_ENTRIES);
        match result {
            Err(e) if self.first_failure() => Err(e),
            Err(_) | Ok(()) => Ok(()),
        }
    }

    /// Whether this is the first failed write to the record, which the caller
    /// reports. Every later failed write is silent.
    pub(crate) fn first_failure(&mut self) -> bool {
        !std::mem::replace(&mut self.failure_reported, true)
    }

    fn lock(&self) -> io::Result<RepoLock> {
        fs::create_dir_all(&self.lock_dir)?;
        acquire_default(&self.lock_dir, RECORD_LOCK).map_err(io::Error::other)
    }

    fn append_line(&self, digest: Hash) -> io::Result<()> {
        let _lock = self.lock()?;
        fs::create_dir_all(self.path.parent().expect("record has a parent"))?;
        let mut line = to_hex(&digest);
        line.push('\n');
        let mut file = fs::OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&self.path)?;
        let len = file.metadata()?.len();
        // A killed process can leave a torn last line. Start a new line, so
        // this digest is not glued onto the torn one and lost.
        if len > 0 {
            let mut last = [0u8; 1];
            file.seek(SeekFrom::End(-1))?;
            file.read_exact(&mut last)?;
            if last[0] != b'\n' {
                line.insert(0, '\n');
            }
        }
        if len.saturating_add(line.len() as u64) > RECORD_WRITE_MAX_BYTES {
            drop(file);
            let bytes = read_record_for_rewrite(&self.path)?;
            return write_recent(&self.path, &bytes, [digest], RECORD_COMPACT_ENTRIES);
        }
        file.write_all(line.as_bytes())
    }

    /// Retry missing writes, or publish a pending clear. Appended lines are
    /// already in the record and need no flush. A successful persist clears
    /// the dirty flag.
    pub fn persist(&mut self) -> Result<(), SyncError> {
        if !self.dirty {
            return Ok(());
        }
        if self.clear_pending || self.hints.pending != 0 {
            let _lock = self.lock()?;
            let bytes = if self.clear_pending {
                Vec::new()
            } else {
                read_record_for_rewrite(&self.path)?
            };
            write_recent(
                &self.path,
                &bytes,
                self.hints.unwritten(),
                RECORD_MAX_ENTRIES,
            )?;
            self.hints.mark_written();
            self.clear_pending = false;
        }
        self.dirty = false;
        Ok(())
    }

    /// Discard every recorded digest, in memory only, and mark the record
    /// dirty. Used by the fetch-side self-heal path when the local record is
    /// suspected stale relative to the object store (e.g. the store was
    /// wiped but `applied-packs/` survived) — this does not touch disk
    /// itself, so the caller persists, as the self-heal path does at once.
    pub fn clear(&mut self) {
        self.hints = PackHints::default();
        self.clear_pending = true;
        self.dirty = true;
    }

    /// Delete the on-disk record for `remote`, if any. The record's
    /// lifecycle follows the remote's: `kit remote remove` calls
    /// this so a later re-add of the same name starts from an empty record
    /// instead of inheriting a stale one — which would skip packs a since
    /// gc'd store no longer holds and trip the self-heal's spurious full
    /// re-download on the first fetch.
    ///
    /// A missing record (or a missing `applied-packs/` directory) is Ok,
    /// not an error: removal is idempotent, and most removed remotes were
    /// never fetched.
    ///
    /// # Errors
    ///
    /// [`SyncError::InvalidRemoteName`] for an illegal name (same check
    /// as [`Self::load`]); any other deletion failure as
    /// [`SyncError::Io`]. Callers treat both as non-fatal — the record
    /// is a pure cache and the fetch-side self-heal still recovers.
    pub fn remove_record(layout: &RepoLayout, remote: &str) -> Result<(), SyncError> {
        validate_remote_name(remote)?;
        match fs::remove_file(record_path(layout, remote)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(SyncError::Io(e)),
        }
    }

    /// Move the on-disk record from `old` to `new`. The record's lifecycle
    /// follows the remote's: `kit remote rename` calls this so the
    /// renamed remote's next fetch reuses the cache instead of re-downloading
    /// its full pack chain, and no orphan record is left under the old name.
    ///
    /// A missing source record is Ok — the normal state for a never-fetched
    /// remote. A record already on disk under `new` can only be a stale
    /// orphan (the command handler has already established `new` is not a
    /// configured remote); it is overwritten by the rename when `old` has a
    /// record, but survives when `old` has none (`fs::rename` is a no-op on a
    /// missing source). A surviving orphan is harmless: the fetch-side
    /// self-heal discards any record that disagrees with the packmap.
    ///
    /// # Errors
    ///
    /// [`SyncError::InvalidRemoteName`] if either name is illegal; any
    /// other rename failure as [`SyncError::Io`]. Callers treat both as
    /// non-fatal — the worst case is one full re-download on the renamed
    /// remote's next fetch.
    pub fn rename_record(layout: &RepoLayout, old: &str, new: &str) -> Result<(), SyncError> {
        validate_remote_name(old)?;
        validate_remote_name(new)?;
        match fs::rename(record_path(layout, old), record_path(layout, new)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(SyncError::Io(e)),
        }
    }
}

/// Reject any remote name that isn't a legal ref name. A remote name *is* a
/// ref name — `kit remote add` runs it through
/// [`kit_core::refs::validate_ref_name`] — so reusing that check keeps the
/// two in lockstep and rejects the control-char / `.lock` / `.` / `..` /
/// backslash cases a bespoke blacklist misses. A legal name may still contain
/// `/` (a multi-segment remote like `team/upstream`); [`record_file_name`]
/// flattens that into the on-disk filename, so `/` is no longer rejected.
fn validate_remote_name(remote: &str) -> Result<(), SyncError> {
    if kit_core::refs::validate_ref_name(remote) {
        Ok(())
    } else {
        Err(SyncError::InvalidRemoteName(remote.to_string()))
    }
}

/// Map a validated remote name to its flat record filename under
/// `applied-packs/`. A legal remote may contain `/` (a multi-segment name
/// like `team/upstream`), which would otherwise be read as a subdirectory
/// separator; percent-encode it to `%2F` so every remote gets exactly one
/// flat file and the atomic sibling-tmp+rename write stays within
/// `applied-packs/`. [`validate_remote_name`] guarantees the name never
/// contains `%`, so this mapping is unambiguous and reversible.
fn record_file_name(remote: &str) -> String {
    remote.replace('/', "%2F")
}

/// The full record path for `remote`:
/// `<common dir>/applied-packs/<record_file_name(remote)>`. The single
/// source of truth for the derivation — [`AppliedPacks::load`]/
/// [`AppliedPacks::load_or_empty`] on the fetch path and
/// [`AppliedPacks::remove_record`]/[`AppliedPacks::rename_record`] on the
/// `remote remove`/`rename` path all route through it, so the command
/// handlers and the fetch path cannot drift.
fn record_path(layout: &RepoLayout, remote: &str) -> PathBuf {
    layout.applied_packs_dir().join(record_file_name(remote))
}

/// Parse the on-disk record format: one lowercase 64-hex digest per LF
/// line. Malformed lines (wrong length, non-hex, uppercase hex) are
/// silently ignored, per the module's contract.
fn digest_lines(bytes: &[u8]) -> impl DoubleEndedIterator<Item = Hash> + '_ {
    bytes.split(|&byte| byte == b'\n').filter_map(|line| {
        let text = core::str::from_utf8(line).ok()?;
        kit_core::refs::parse_lowercase_hash(text.trim_end_matches('\r').as_bytes())
    })
}

fn read_record_for_rewrite(path: &Path) -> io::Result<Vec<u8>> {
    match kit_core::bounded_read::read_capped(path, RECORD_MAX_BYTES) {
        // Replace a cache that could not be read or exceeded its read limit.
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::NotFound
                    | io::ErrorKind::InvalidData
                    | io::ErrorKind::PermissionDenied
            ) =>
        {
            Ok(Vec::new())
        }
        result => result,
    }
}

fn write_recent(
    path: &Path,
    bytes: &[u8],
    appended: impl IntoIterator<Item = Hash, IntoIter: DoubleEndedIterator>,
    limit: usize,
) -> io::Result<()> {
    // Read newest first so a repeated line takes its most recent position.
    let mut seen = HashSet::new();
    let newest_first: Vec<_> = appended
        .into_iter()
        .rev()
        .chain(digest_lines(bytes).rev())
        .filter(|hash| seen.insert(*hash))
        .take(limit)
        .collect();
    let mut body = String::with_capacity(newest_first.len() * RECORD_LINE_BYTES);
    for digest in newest_first.iter().rev() {
        body.push_str(&to_hex(digest));
        body.push('\n');
    }
    kit_core::durable::write_cache(path, body.as_bytes(), Parents::Create)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kit_core::hash;
    use tempfile::TempDir;

    fn h(seed: &str) -> Hash {
        hash::hash(seed.as_bytes())
    }

    fn pk(seed: &str) -> PackKey {
        PackKey::from_hash(h(seed))
    }

    fn fresh_kit_dir() -> (TempDir, RepoLayout) {
        let dir = TempDir::new().unwrap();
        let kit_dir = RepoLayout::single(dir.path());
        fs::create_dir_all(kit_dir.common_dir()).unwrap();
        (dir, kit_dir)
    }

    #[test]
    fn load_missing_yields_empty_set() {
        let (_dir, kit_dir) = fresh_kit_dir();
        let applied = AppliedPacks::load(&kit_dir, "origin").unwrap();
        assert!(!applied.contains(&pk("a")));
    }

    #[test]
    fn record_applied_appends_a_line_a_later_load_sees() {
        let (_dir, kit_dir) = fresh_kit_dir();
        let (k1, k2) = (pk("pack-1"), pk("pack-2"));
        let mut applied = AppliedPacks::load(&kit_dir, "origin").unwrap();
        applied.record_applied(&k1).unwrap();
        applied.record_applied(&k2).unwrap();
        // No persist: a process that died here still left both lines.
        let reloaded = AppliedPacks::load(&kit_dir, "origin").unwrap();
        assert!(reloaded.contains(&k1) && reloaded.contains(&k2));
        let text = fs::read_to_string(record_path(&kit_dir, "origin")).unwrap();
        assert_eq!(text.lines().count(), 2);
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn appending_at_the_record_limit_keeps_the_newest_digests_readable() {
        let (_dir, layout) = fresh_kit_dir();
        let path = record_path(&layout, "origin");
        let mut applied = AppliedPacks::load(&layout, "origin").unwrap();
        let old = pk("old");
        let last_that_fits = pk("last that fits");
        let newest = pk("newest");
        applied.record_applied(&old).unwrap();
        let mut other = AppliedPacks::load(&layout, "origin").unwrap();

        // Pad the file to the write boundary without generating a million
        // distinct digests. Compaction replaces this padding with valid lines.
        let mut file = fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(RECORD_WRITE_MAX_BYTES - RECORD_LINE_BYTES as u64)
            .unwrap();
        file.seek(SeekFrom::End(-1)).unwrap();
        file.write_all(b"\n").unwrap();
        drop(file);

        other.record_applied(&last_that_fits).unwrap();
        assert!(!applied.contains(&last_that_fits));
        assert_eq!(fs::metadata(&path).unwrap().len(), 65_000_000);
        applied.record_applied(&newest).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().len(), 3 * 65);
        applied.persist().unwrap();
        other.persist().unwrap();
        let reloaded = AppliedPacks::load(&layout, "origin").unwrap();
        for key in [old, last_that_fits, newest] {
            assert!(reloaded.contains(&key));
        }
    }

    #[test]
    fn retained_hints_evict_unwritten_digests_at_the_limit() {
        let mut hints = PackHints::default();
        let [old, middle, newest] = [3, 2, 1].map(|n| [n; 32]);
        hints.remember(old, true, 2);
        hints.remember(middle, false, 2);
        assert_eq!(hints.pending, 1);
        hints.remember(newest, true, 2);
        assert_eq!(hints.oldest_first, [middle, newest]);
        assert_eq!(hints.pending, 1);
        assert!(!hints.needs_write.contains_key(&old));
        assert_eq!(hints.unwritten().collect::<Vec<_>>(), vec![newest]);
    }

    #[test]
    fn compaction_drops_oldest_hints_instead_of_sorting_by_digest() {
        let (_dir, layout) = fresh_kit_dir();
        let mut applied = AppliedPacks::load(&layout, "origin").unwrap();
        let [old, middle, newest] = [3, 2, 1].map(|n| PackKey::from_hash([n; 32]));
        for key in [old, middle, newest] {
            applied.record_applied(&key).unwrap();
        }
        applied.persist().unwrap();

        let path = record_path(&layout, "origin");
        let bytes = fs::read(&path).unwrap();
        write_recent(&path, &bytes, [], 2).unwrap();
        let compacted = AppliedPacks::load(&layout, "origin").unwrap();
        assert!(!compacted.contains(&old));
        assert!(compacted.contains(&middle));
        assert!(compacted.contains(&newest));
        assert_eq!(fs::metadata(&compacted.path).unwrap().len(), 2 * 65);
    }

    #[test]
    fn a_torn_appended_line_is_ignored_on_load() {
        let (_dir, kit_dir) = fresh_kit_dir();
        let k1 = pk("pack-1");
        let mut applied = AppliedPacks::load(&kit_dir, "origin").unwrap();
        applied.record_applied(&k1).unwrap();
        let path = record_path(&kit_dir, "origin");
        let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(&to_hex(&h("torn")).as_bytes()[..30])
            .unwrap();
        let reloaded = AppliedPacks::load(&kit_dir, "origin").unwrap();
        assert!(reloaded.contains(&k1));
        assert!(!reloaded.contains(&pk("torn")));
        // The next append starts a new line instead of joining the torn one.
        let mut applied = reloaded;
        let k2 = pk("pack-2");
        applied.record_applied(&k2).unwrap();
        let reloaded = AppliedPacks::load(&kit_dir, "origin").unwrap();
        assert!(reloaded.contains(&k1) && reloaded.contains(&k2));
    }

    #[test]
    fn record_applied_keeps_the_digest_and_reports_only_the_first_failed_append() {
        let (_dir, kit_dir) = fresh_kit_dir();
        // A directory where the record file belongs makes the append fail.
        fs::create_dir_all(record_path(&kit_dir, "origin")).unwrap();
        let mut applied = AppliedPacks::load_or_empty(&kit_dir, "origin", &crate::NoopObserver);
        let key = pk("pack-1");
        assert!(applied.record_applied(&key).is_err());
        assert!(applied.contains(&key));
        // Only the first failure is reported; the digest is still recorded.
        let next = pk("pack-2");
        assert!(applied.record_applied(&next).is_ok());
        assert!(applied.contains(&next));

        fs::remove_dir(record_path(&kit_dir, "origin")).unwrap();
        applied.persist().unwrap();
        let reloaded = AppliedPacks::load(&kit_dir, "origin").unwrap();
        assert!(reloaded.contains(&key));
        assert!(reloaded.contains(&next));
    }

    #[test]
    fn insert_persist_reload_round_trip() {
        let (_dir, kit_dir) = fresh_kit_dir();
        let k1 = pk("pack-1");
        let k2 = pk("pack-2");
        {
            let mut applied = AppliedPacks::load(&kit_dir, "origin").unwrap();
            applied.record_applied(&k1).unwrap();
            applied.record_applied(&k2).unwrap();
            applied.persist().unwrap();
        }
        let reloaded = AppliedPacks::load(&kit_dir, "origin").unwrap();
        assert!(reloaded.contains(&k1));
        assert!(reloaded.contains(&k2));
        assert!(!reloaded.contains(&pk("pack-3")));
    }

    #[test]
    fn separate_remotes_get_separate_files() {
        let (_dir, kit_dir) = fresh_kit_dir();
        let k1 = pk("pack-1");
        let mut origin = AppliedPacks::load(&kit_dir, "origin").unwrap();
        origin.record_applied(&k1).unwrap();
        origin.persist().unwrap();

        let upstream = AppliedPacks::load(&kit_dir, "upstream").unwrap();
        assert!(
            !upstream.contains(&k1),
            "records must not leak across remotes"
        );
    }

    #[test]
    fn malformed_lines_are_ignored_on_load() {
        let (_dir, kit_dir) = fresh_kit_dir();
        let path = kit_dir.applied_packs_dir().join("origin");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let valid = h("valid");
        let mut content = String::new();
        content.push_str("short\n");
        content.push_str(&to_hex(&valid));
        content.push('\n');
        // Uppercase hex is malformed per this record's strict format.
        content.push_str(&"F".repeat(64));
        content.push('\n');
        content.push_str(&"z".repeat(64));
        content.push('\n');
        let mut content = content.into_bytes();
        content.extend_from_slice(b"\xff\n");
        fs::write(&path, content).unwrap();

        let mut applied = AppliedPacks::load(&kit_dir, "origin").unwrap();
        assert!(applied.contains(&PackKey::from_hash(valid)));
        let newest = pk("newest");
        applied.record_applied(&newest).unwrap();
        applied.persist().unwrap();
        let reloaded = AppliedPacks::load(&kit_dir, "origin").unwrap();
        assert!(reloaded.contains(&newest));
    }

    #[test]
    fn atomic_rewrite_leaves_no_tmp_file_on_success() {
        let (_dir, kit_dir) = fresh_kit_dir();
        let mut applied = AppliedPacks::load(&kit_dir, "origin").unwrap();
        applied.record_applied(&pk("old")).unwrap();
        applied.clear();
        applied.record_applied(&pk("new")).unwrap();
        applied.persist().unwrap();

        let reloaded = AppliedPacks::load(&kit_dir, "origin").unwrap();
        assert!(!reloaded.contains(&pk("old")));
        assert!(reloaded.contains(&pk("new")));

        let dir = kit_dir.applied_packs_dir();
        let leftover: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
            .collect();
        assert!(
            leftover.is_empty(),
            "no .tmp file should survive a successful persist"
        );
    }

    #[test]
    fn cache_records_are_written_with_no_full_flush() {
        let (_dir, kit_dir) = fresh_kit_dir();
        let dir = tempfile::tempdir().unwrap();
        let before = kit_core::fault::flushes();
        let mut applied = AppliedPacks::load(&kit_dir, "origin").unwrap();
        applied.record_applied(&pk("pack-1")).unwrap();
        applied.persist().unwrap();
        kit_core::durable::write_cache(&dir.path().join("record"), b"bytes", Parents::Existing)
            .unwrap();
        let tip = h("tip");
        crate::anchor::persist(&dir.path().join("verified"), &tip).unwrap();
        assert_eq!(kit_core::fault::flushes(), before);
        assert_eq!(crate::anchor::load(&dir.path().join("verified")), Some(tip));

        // A durable pointer flushes the file and its directory.
        kit_core::durable::write_pointer(&dir.path().join("pointer"), b"bytes", Parents::Existing)
            .unwrap();
        // Windows has no directory flush, so there it is the file alone.
        let pointer = if cfg!(unix) { 2 } else { 1 };
        assert_eq!(kit_core::fault::flushes(), before + pointer);
    }

    #[test]
    fn persist_is_noop_when_not_dirty() {
        let (_dir, kit_dir) = fresh_kit_dir();
        let mut applied = AppliedPacks::load(&kit_dir, "origin").unwrap();
        // Never inserted anything, so persist() must not create the file
        // (or the applied-packs/ directory) at all.
        applied.persist().unwrap();
        assert!(!kit_dir.applied_packs_dir().exists());
    }

    #[test]
    fn clear_empties_the_record_in_memory_and_marks_it_dirty() {
        let (_dir, kit_dir) = fresh_kit_dir();
        let k1 = pk("pack-1");
        let mut applied = AppliedPacks::load(&kit_dir, "origin").unwrap();
        applied.record_applied(&k1).unwrap();
        applied.persist().unwrap();
        assert!(applied.contains(&k1));

        applied.clear();
        assert!(!applied.contains(&k1));

        // `clear` is in-memory only — the on-disk record is untouched until
        // the caller persists.
        let reloaded = AppliedPacks::load(&kit_dir, "origin").unwrap();
        assert!(reloaded.contains(&k1));

        applied.persist().unwrap();
        let reloaded_after_persist = AppliedPacks::load(&kit_dir, "origin").unwrap();
        assert!(!reloaded_after_persist.contains(&k1));
    }

    #[test]
    fn multi_segment_remote_round_trips() {
        // A legal multi-segment remote (`kit remote add team/upstream`
        // passes `validate_ref_name`) must record without error, as one flat
        // file — the `/` is encoded, not turned into a subdirectory.
        let (_dir, kit_dir) = fresh_kit_dir();
        let k1 = pk("pack-1");
        {
            let mut applied = AppliedPacks::load(&kit_dir, "team/upstream").unwrap();
            applied.record_applied(&k1).unwrap();
            applied.persist().unwrap();
        }

        let dir = kit_dir.applied_packs_dir();
        let entries: Vec<_> = fs::read_dir(&dir).unwrap().filter_map(Result::ok).collect();
        assert_eq!(entries.len(), 1, "exactly one flat record file per remote");
        assert!(
            entries[0].file_type().unwrap().is_file(),
            "the `/` must not create a subdirectory"
        );
        assert_eq!(
            entries[0].file_name().to_string_lossy(),
            "team%2Fupstream",
            "the `/` is percent-encoded in the on-disk filename"
        );

        let reloaded = AppliedPacks::load(&kit_dir, "team/upstream").unwrap();
        assert!(reloaded.contains(&k1));
        // A different remote whose encoded name could otherwise collide stays
        // separate.
        let other = AppliedPacks::load(&kit_dir, "teamupstream").unwrap();
        assert!(!other.contains(&k1), "encoded names must not collide");
    }

    #[test]
    fn remove_record_deletes_and_is_idempotent_when_missing() {
        let (_dir, kit_dir) = fresh_kit_dir();
        // Missing record — and even a missing applied-packs/ directory — is
        // Ok, not an error (never-fetched remotes have no record).
        AppliedPacks::remove_record(&kit_dir, "origin").unwrap();

        let k1 = pk("pack-1");
        let mut applied = AppliedPacks::load(&kit_dir, "origin").unwrap();
        applied.record_applied(&k1).unwrap();
        applied.persist().unwrap();
        let path = kit_dir.applied_packs_dir().join("origin");
        assert!(path.is_file(), "precondition: record persisted");

        AppliedPacks::remove_record(&kit_dir, "origin").unwrap();
        assert!(!path.exists(), "remove_record must delete the record file");
        // A reload starts empty — no stale digests survive the removal.
        let reloaded = AppliedPacks::load(&kit_dir, "origin").unwrap();
        assert!(!reloaded.contains(&k1));
        // And removing again is still Ok.
        AppliedPacks::remove_record(&kit_dir, "origin").unwrap();
    }

    #[test]
    fn rename_record_moves_the_record_and_leaves_no_orphan() {
        let (_dir, kit_dir) = fresh_kit_dir();
        let k1 = pk("pack-1");
        let mut applied = AppliedPacks::load(&kit_dir, "old").unwrap();
        applied.record_applied(&k1).unwrap();
        applied.persist().unwrap();

        AppliedPacks::rename_record(&kit_dir, "old", "new").unwrap();
        assert!(
            !kit_dir.applied_packs_dir().join("old").exists(),
            "no orphan record may remain under the old name"
        );
        let renamed = AppliedPacks::load(&kit_dir, "new").unwrap();
        assert!(renamed.contains(&k1), "the record must move, not clear");
        let old = AppliedPacks::load(&kit_dir, "old").unwrap();
        assert!(!old.contains(&k1));
    }

    #[test]
    fn rename_record_missing_source_is_ok() {
        let (_dir, kit_dir) = fresh_kit_dir();
        // Neither a record nor the applied-packs/ directory exists yet.
        AppliedPacks::rename_record(&kit_dir, "old", "new").unwrap();
        assert!(!kit_dir.applied_packs_dir().exists());
    }

    #[test]
    fn rename_record_handles_multi_segment_names() {
        // The lifecycle ops must share the fetch path's percent-encoding:
        // `team/upstream` lives (and moves) as one flat `team%2Fupstream`
        // file, never as a nested path.
        let (_dir, kit_dir) = fresh_kit_dir();
        let k1 = pk("pack-1");
        let mut applied = AppliedPacks::load(&kit_dir, "team/upstream").unwrap();
        applied.record_applied(&k1).unwrap();
        applied.persist().unwrap();

        AppliedPacks::rename_record(&kit_dir, "team/upstream", "archive/upstream").unwrap();
        let dir = kit_dir.applied_packs_dir();
        let names: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["archive%2Fupstream".to_owned()]);
        let renamed = AppliedPacks::load(&kit_dir, "archive/upstream").unwrap();
        assert!(renamed.contains(&k1));

        AppliedPacks::remove_record(&kit_dir, "archive/upstream").unwrap();
        assert!(!dir.join("archive%2Fupstream").exists());
    }

    #[test]
    fn lifecycle_ops_reject_invalid_names() {
        let (_dir, kit_dir) = fresh_kit_dir();
        let err = AppliedPacks::remove_record(&kit_dir, "..").unwrap_err();
        assert!(matches!(err, SyncError::InvalidRemoteName(_)));
        let err = AppliedPacks::rename_record(&kit_dir, "..", "new").unwrap_err();
        assert!(matches!(err, SyncError::InvalidRemoteName(_)));
        let err = AppliedPacks::rename_record(&kit_dir, "old", "../escape").unwrap_err();
        assert!(matches!(err, SyncError::InvalidRemoteName(_)));
    }

    #[test]
    fn remote_name_rejects_backslash() {
        let (_dir, kit_dir) = fresh_kit_dir();
        let err = AppliedPacks::load(&kit_dir, "evil\\remote").unwrap_err();
        assert!(matches!(err, SyncError::InvalidRemoteName(_)));
    }

    #[test]
    fn remote_name_rejects_dotdot_and_empty() {
        let (_dir, kit_dir) = fresh_kit_dir();
        // A `.` / `..` path segment (validate_ref_name rejects both).
        let err = AppliedPacks::load(&kit_dir, "..").unwrap_err();
        assert!(matches!(err, SyncError::InvalidRemoteName(_)));
        let err = AppliedPacks::load(&kit_dir, "../escape").unwrap_err();
        assert!(matches!(err, SyncError::InvalidRemoteName(_)));
        let err = AppliedPacks::load(&kit_dir, "").unwrap_err();
        assert!(matches!(err, SyncError::InvalidRemoteName(_)));
    }
}

//! Recorded conflict resolutions: the `rr-cache/` of SPEC-RERERE.
//!
//! [`replay`] runs after [`crate::conflict::materialize`]. For each text
//! conflict it writes a recorded resolution into the file, or records the
//! sides so that a later resolution can be kept. [`record`] runs when an
//! operation continues past its conflicts, and keeps the staged content of
//! each tracked conflict as its resolution. [`status`], [`diff`],
//! [`forget`], [`clear`] and [`gc`] back `kit rerere`.
//!
//! The cache is advisory. A failure to read or write it never stops the
//! operation: [`replay`] and [`record`] report it as a
//! [`conflict::Event::RerereWarning`] and go on.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use kit_core::bounded_read;
use kit_core::durable::{self, Parents};
use kit_core::hash;
use kit_core::index::{self, EntryStatus, IndexEntry};
use kit_core::layout::RepoLayout;
use kit_core::observer::Observer;
use kit_core::ops::conflict_state::ConflictRecord;
use kit_core::ops::rerere::{MAX_FILE, VERSION, conflict_id, entry_is_valid, is_id, sorted_sides};
use kit_core::store::ObjectStore;
use kit_core::worktree;

use crate::conflict::{self, Event};

/// Whether the cache is used, and whether a replayed resolution is staged.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Settings {
    /// `rerere.enabled`.
    pub enabled: bool,
    /// `rerere.autoUpdate`.
    pub auto_update: bool,
}

/// Errors from the maintenance commands.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The cache cannot be read or changed.
    #[error("rr-cache: {0}")]
    Io(#[from] io::Error),
    /// `version` holds something kit does not know.
    #[error("rr-cache has an unknown version; run `kit rerere clear` to start over")]
    UnknownVersion,
    /// The path is not a conflict that the cache tracks.
    #[error("no recorded conflict at '{0}'")]
    NotTracked(String),
}

/// The directory of the cache.
#[must_use]
pub fn cache_dir(layout: &RepoLayout) -> PathBuf {
    layout.common_dir().join("rr-cache")
}

/// The state of the `version` file.
enum Version {
    Absent,
    Known,
    Unknown,
}

fn version(dir: &Path) -> Version {
    match bounded_read::read_capped(&dir.join("version"), 64) {
        Ok(v) if v == VERSION => Version::Known,
        Err(e) if e.kind() == io::ErrorKind::NotFound => Version::Absent,
        _ => Version::Unknown,
    }
}

/// The two sides of a text conflict, or `None` when the conflict does not
/// take part: a side that is not a readable blob, or not text.
fn text_sides(store: &ObjectStore, r: &ConflictRecord) -> Option<(Vec<u8>, Vec<u8>)> {
    let side = |h: Option<hash::Hash>| match h {
        None => Some(Vec::new()),
        Some(h) => worktree::read_blob(store, &h)
            .ok()
            .filter(|d| conflict::is_text(d)),
    };
    Some((side(r.ours_hash)?, side(r.theirs_hash)?))
}

/// What an entry on disk holds.
enum Entry {
    /// No directory.
    Absent,
    /// A directory that fails a validity rule.
    Invalid,
    /// A valid entry, with its postimage when one is recorded.
    Valid(Option<Vec<u8>>),
}

fn read_limited(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
        Ok(m) if !m.is_file() || m.len() > MAX_FILE => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a regular file",
            ));
        }
        Ok(_) => {}
    }
    bounded_read::read_capped(path, MAX_FILE).map(Some)
}

fn read_entry(dir: &Path, id: &str) -> Entry {
    let entry = dir.join(id);
    match fs::symlink_metadata(&entry) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Entry::Absent,
        Ok(m) if m.is_dir() => {}
        _ => return Entry::Invalid,
    }
    let (Ok(Some(side1)), Ok(Some(side2))) = (
        read_limited(&entry.join("side1")),
        read_limited(&entry.join("side2")),
    ) else {
        return Entry::Invalid;
    };
    if !entry_is_valid(id, &side1, &side2) {
        return Entry::Invalid;
    }
    match read_limited(&entry.join("postimage")) {
        Ok(post) => Entry::Valid(post),
        Err(_) => Entry::Invalid,
    }
}

fn write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    durable::write_pointer_shared(path, bytes, Parents::Create)
}

/// Create the entry for a conflict, and `version` with the first entry.
fn create_entry(dir: &Path, id: &str, ours: &[u8], theirs: &[u8]) -> io::Result<()> {
    if matches!(version(dir), Version::Absent) {
        write(&dir.join("version"), VERSION)?;
    }
    let (a, b) = sorted_sides(ours, theirs);
    let entry = dir.join(id);
    write(&entry.join("side1"), a)?;
    write(&entry.join("side2"), b)
}

/// The cache directory, when the cache may be used. A `version` with other
/// content is reported once and the whole cache is ignored.
fn usable_cache(layout: &RepoLayout, observer: &dyn Observer<Event>) -> Option<PathBuf> {
    let dir = cache_dir(layout);
    if matches!(version(&dir), Version::Unknown) {
        warn(
            observer,
            "rr-cache has an unknown version; ignoring it".to_owned(),
        );
        return None;
    }
    Some(dir)
}

fn warn(observer: &dyn Observer<Event>, message: String) {
    observer.event(&Event::RerereWarning { message });
}

/// Look up each text conflict of a paused operation in the cache.
///
/// With a recorded resolution, the file gets it, and with
/// `settings.auto_update` the index does too. Otherwise the sides of the
/// conflict are recorded. A path whose file no longer holds the markers that
/// [`crate::conflict::materialize`] wrote is left alone, so a conflict that
/// kept one side whole never takes part.
pub fn replay(
    layout: &RepoLayout,
    store: &ObjectStore,
    settings: Settings,
    records: &[ConflictRecord],
    observer: &dyn Observer<Event>,
) {
    if !settings.enabled || records.is_empty() {
        return;
    }
    let Some(dir) = usable_cache(layout, observer) else {
        return;
    };
    let mut staged = Vec::new();
    for r in records {
        let Some((ours, theirs)) = text_sides(store, r) else {
            continue;
        };
        let Ok(abs) = conflict::writable_path(layout.worktree_root(), &r.path) else {
            continue;
        };
        let markers = conflict::marker_bytes(&ours, &theirs);
        if bounded_read::read_capped(&abs, MAX_FILE).ok().as_deref() != Some(markers.as_slice()) {
            continue;
        }
        let id = conflict_id(&ours, &theirs);
        match read_entry(&dir, &id) {
            Entry::Invalid => warn(
                observer,
                format!("ignoring the invalid rr-cache entry {id} for '{}'", r.path),
            ),
            Entry::Valid(Some(post)) => {
                if let Err(e) = conflict::write_bytes(&abs, &post) {
                    warn(observer, e.to_string());
                    continue;
                }
                observer.event(&Event::ReusedResolution {
                    path: r.path.clone(),
                });
                if settings.auto_update {
                    staged.push((r.path.clone(), post));
                }
            }
            Entry::Valid(None) => {}
            Entry::Absent => match create_entry(&dir, &id, &ours, &theirs) {
                Ok(()) => observer.event(&Event::RecordedPreimage {
                    path: r.path.clone(),
                }),
                Err(e) => warn(observer, format!("record preimage for '{}': {e}", r.path)),
            },
        }
    }
    if !staged.is_empty()
        && let Err(e) = stage(layout, store, &staged)
    {
        warn(observer, format!("stage the replayed resolutions: {e}"));
    }
}

/// Stage each replayed resolution as a regular file.
fn stage(layout: &RepoLayout, store: &ObjectStore, files: &[(String, Vec<u8>)]) -> io::Result<()> {
    let mut idx = index::read_index(layout).map_err(io::Error::other)?;
    for (path, data) in files {
        let object_hash = worktree::store_file_object(store, data).map_err(io::Error::other)?;
        idx.upsert_entry(IndexEntry {
            path: path.clone(),
            status: EntryStatus::Blob,
            object_hash,
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
        });
    }
    index::write_index(layout, &idx).map_err(io::Error::other)
}

/// Keep the staged content of each tracked conflict as its resolution.
///
/// A conflict is tracked when its entry exists, which [`replay`] made when
/// the conflict appeared. A path staged as a removal, or as anything but a
/// regular file, records nothing. A postimage equal to the staged content is
/// left as it is.
pub fn record(
    layout: &RepoLayout,
    store: &ObjectStore,
    settings: Settings,
    records: &[ConflictRecord],
    observer: &dyn Observer<Event>,
) {
    if !settings.enabled || records.is_empty() {
        return;
    }
    let Some(dir) = usable_cache(layout, observer) else {
        return;
    };
    let Ok(idx) = index::read_index(layout) else {
        return;
    };
    for r in records {
        let Some((ours, theirs)) = text_sides(store, r) else {
            continue;
        };
        let id = conflict_id(&ours, &theirs);
        let post = match read_entry(&dir, &id) {
            Entry::Absent => continue,
            Entry::Invalid => {
                warn(
                    observer,
                    format!("ignoring the invalid rr-cache entry {id} for '{}'", r.path),
                );
                continue;
            }
            Entry::Valid(post) => post,
        };
        let Some(entry) = idx.find_entry(&r.path).map(|i| &idx.entries[i]) else {
            continue;
        };
        if entry.status != EntryStatus::Blob {
            continue;
        }
        let Ok(staged) = worktree::read_blob(store, &entry.object_hash) else {
            continue;
        };
        if post.as_deref() == Some(staged.as_slice()) {
            continue;
        }
        match write(&dir.join(&id).join("postimage"), &staged) {
            Ok(()) => observer.event(&Event::RecordedResolution {
                path: r.path.clone(),
            }),
            Err(e) => warn(observer, format!("record resolution for '{}': {e}", r.path)),
        }
    }
}

/// A conflict of the paused operation that the cache tracks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tracked {
    /// The repository-relative path.
    pub path: String,
    /// The file as the conflict wrote it, with markers.
    pub preimage: Vec<u8>,
    /// The entry id.
    pub id: String,
}

/// The conflicts of `records` that have a valid entry, in record order.
///
/// # Errors
/// [`Error::UnknownVersion`] when the cache cannot be used.
pub fn status(
    layout: &RepoLayout,
    store: &ObjectStore,
    records: &[ConflictRecord],
) -> Result<Vec<Tracked>, Error> {
    let dir = cache_dir(layout);
    if matches!(version(&dir), Version::Unknown) {
        return Err(Error::UnknownVersion);
    }
    let mut out = Vec::new();
    for r in records {
        let Some((ours, theirs)) = text_sides(store, r) else {
            continue;
        };
        let id = conflict_id(&ours, &theirs);
        if matches!(read_entry(&dir, &id), Entry::Valid(_)) {
            out.push(Tracked {
                path: r.path.clone(),
                preimage: conflict::marker_bytes(&ours, &theirs),
                id,
            });
        }
    }
    Ok(out)
}

/// The changes from the preimage of each tracked conflict to its file now,
/// as unified diffs.
///
/// # Errors
/// As [`status`].
pub fn diff(
    layout: &RepoLayout,
    store: &ObjectStore,
    records: &[ConflictRecord],
) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    for t in status(layout, store, records)? {
        let now = bounded_read::read_capped(&layout.worktree_root().join(&t.path), MAX_FILE)
            .unwrap_or_default();
        let Some(hunks) = kit_core::ops::diff::unified_hunks(&t.preimage, &now) else {
            continue;
        };
        if hunks.is_empty() {
            continue;
        }
        out.extend_from_slice(format!("--- a/{0}\n+++ b/{0}\n", t.path).as_bytes());
        out.extend_from_slice(&hunks);
    }
    Ok(out)
}

/// Delete the recorded resolution of the conflict at `path`.
///
/// # Errors
/// [`Error::NotTracked`] when `path` is not a tracked conflict, or as
/// [`status`].
pub fn forget(
    layout: &RepoLayout,
    store: &ObjectStore,
    records: &[ConflictRecord],
    path: &str,
) -> Result<(), Error> {
    let tracked = status(layout, store, records)?;
    let Some(t) = tracked.iter().find(|t| t.path == path) else {
        return Err(Error::NotTracked(path.to_owned()));
    };
    match fs::remove_file(cache_dir(layout).join(&t.id).join("postimage")) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(Error::Io(e)),
        _ => Ok(()),
    }
}

/// Delete every entry, and `version` with them.
///
/// # Errors
/// [`Error::Io`] when the cache cannot be removed.
pub fn clear(layout: &RepoLayout) -> Result<(), Error> {
    match fs::remove_dir_all(cache_dir(layout)) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(Error::Io(e)),
        _ => Ok(()),
    }
}

/// How long [`gc`] keeps entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Expiry {
    /// Days to keep an entry with a recorded resolution.
    pub resolved_days: u64,
    /// Days to keep an entry with no recorded resolution.
    pub unresolved_days: u64,
}

impl Default for Expiry {
    fn default() -> Self {
        Self {
            resolved_days: 60,
            unresolved_days: 15,
        }
    }
}

/// Delete each entry older than its limit: by the age of its postimage, or
/// of its `side1` when it has none. A directory that is not an entry stays.
/// Return the number of entries deleted.
///
/// # Errors
/// [`Error::Io`] when the cache cannot be listed or an entry removed.
pub fn gc(layout: &RepoLayout, now: SystemTime, expiry: Expiry) -> Result<usize, Error> {
    let dir = cache_dir(layout);
    let list = match fs::read_dir(&dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        other => other?,
    };
    let days = |d: u64| Duration::from_secs(d.saturating_mul(86_400));
    let mut removed = 0;
    for item in list {
        let item = item?;
        let name = item.file_name();
        if !name.to_str().is_some_and(is_id) || !item.file_type()?.is_dir() {
            continue;
        }
        let entry = item.path();
        let post = entry.join("postimage");
        let (file, limit) = if post.exists() {
            (post, days(expiry.resolved_days))
        } else {
            (entry.join("side1"), days(expiry.unresolved_days))
        };
        let age = fs::symlink_metadata(&file)
            .and_then(|m| m.modified())
            .map_or(Duration::MAX, |t| now.duration_since(t).unwrap_or_default());
        if age >= limit {
            fs::remove_dir_all(&entry)?;
            removed += 1;
        }
    }
    Ok(removed)
}

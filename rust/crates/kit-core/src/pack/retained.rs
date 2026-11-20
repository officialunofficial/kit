//! Verified packs kept after a failed apply, so a retry reads them from disk
//! instead of downloading them again.
//!
//! The directory is a disposable cache beside the spools. A file in it is
//! named for the key it claims, and nothing about it is trusted: [`take`]
//! reads it through a [`PackSpool`], which checks its length, its key and its
//! trailer again, so a stale, damaged, swapped or planted file is refused and
//! deleted, and the pack is downloaded instead. The cache holds few packs and
//! for a short time. A pack leaves it when a retry applies it, or when it
//! ages out.
//!
//! [`take`]: RetainedPacks::take

use super::{EMPTY_PACK_LEN, PackSpool, SPOOL_BUFFER, VerifiedPack};
use crate::protocol::{PACK_BODY_LIMIT, PackKey};
use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// The most packs the cache keeps. The oldest go first.
pub const MAX_RETAINED_PACKS: usize = 4;

/// How long a pack stays in the cache.
pub const MAX_RETAINED_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// The directory under the spool directory that holds the cache.
const DIR_NAME: &str = "retained";

/// The cache of verified packs, in `retained/` under a spool directory.
#[derive(Debug, Clone)]
pub struct RetainedPacks {
    spool_dir: PathBuf,
    dir: PathBuf,
}

impl RetainedPacks {
    /// The cache under `spool_dir`. Nothing is created until a pack is kept.
    #[must_use]
    pub fn new(spool_dir: &Path) -> Self {
        Self {
            spool_dir: spool_dir.to_owned(),
            dir: spool_dir.join(DIR_NAME),
        }
    }

    fn path(&self, key: &PackKey) -> PathBuf {
        self.dir.join(format!("{}.pack", key.to_hex()))
    }

    /// Keep a copy of `pack`, which was verified against `key`, for a retry.
    /// The copy appears whole or not at all. A cache over its bounds drops
    /// its oldest packs.
    ///
    /// # Errors
    /// An I/O error, or a cache directory that is a symlink. The caller keeps
    /// going: a pack that was not kept is downloaded again.
    pub fn keep(&self, key: &PackKey, pack: &VerifiedPack) -> io::Result<()> {
        ensure_dir(&self.dir)?;
        let mut copy = tempfile::Builder::new()
            .prefix(".tmp")
            .tempfile_in(&self.dir)?;
        let mut buf = vec![0u8; SPOOL_BUFFER];
        let mut offset = 0;
        while offset < pack.len() {
            let n =
                usize::try_from(pack.len() - offset).map_or(buf.len(), |left| left.min(buf.len()));
            pack.read_at(offset, &mut buf[..n])?;
            copy.write_all(&buf[..n])?;
            offset += n as u64;
        }
        copy.persist(self.path(key)).map_err(|error| error.error)?;
        self.trim();
        Ok(())
    }

    /// The pack kept for `key`, read again and verified against it, or
    /// `None` when there is none or it fails any check. A file that fails is
    /// deleted.
    #[must_use]
    pub fn take(&self, key: &PackKey) -> Option<VerifiedPack> {
        let path = self.path(key);
        let meta = std::fs::symlink_metadata(&path).ok()?;
        let readable =
            meta.is_file() && (EMPTY_PACK_LEN as u64..=PACK_BODY_LIMIT).contains(&meta.len());
        let pack = readable.then(|| read_verified(&path, meta.len(), &self.spool_dir, key));
        match pack {
            Some(Ok(pack)) => Some(pack),
            _ => {
                let _ = std::fs::remove_file(&path);
                None
            }
        }
    }

    /// Delete the pack kept for `key`, if any.
    pub fn discard(&self, key: &PackKey) {
        let _ = std::fs::remove_file(self.path(key));
    }

    /// Delete every file older than [`MAX_RETAINED_AGE`], then the oldest
    /// packs past [`MAX_RETAINED_PACKS`]. A missing or symlinked directory is
    /// left alone, so the sweep never deletes outside the repository.
    pub fn trim(&self) {
        trim_dir(&self.dir, SystemTime::now());
    }
}

fn ensure_dir(dir: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(dir) {
        Ok(meta) if meta.is_dir() => Ok(()),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "retained pack directory is not a directory",
        )),
        Err(_) => std::fs::create_dir_all(dir),
    }
}

/// Read `len` bytes of the file at `path` into a new spool in `spool_dir`
/// and verify them against `key`.
fn read_verified(
    path: &Path,
    len: u64,
    spool_dir: &Path,
    key: &PackKey,
) -> io::Result<VerifiedPack> {
    let invalid = |_| io::Error::from(io::ErrorKind::InvalidData);
    let mut file = File::open(path)?;
    let mut spool = PackSpool::create(spool_dir, PACK_BODY_LIMIT).map_err(invalid)?;
    spool.begin(Some(len)).map_err(invalid)?;
    let mut buf = vec![0u8; SPOOL_BUFFER];
    let mut left = len;
    while left > 0 {
        let n = usize::try_from(left).map_or(buf.len(), |left| left.min(buf.len()));
        file.read_exact(&mut buf[..n])?;
        spool.write(&buf[..n]).map_err(invalid)?;
        left -= n as u64;
    }
    spool.finish(key).map_err(invalid)
}

/// Apply the age and count bounds to the files directly in `dir`, as of `now`.
pub(super) fn trim_dir(dir: &Path, now: SystemTime) {
    if !std::fs::symlink_metadata(dir).is_ok_and(|meta| meta.is_dir()) {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut kept = Vec::new();
    for entry in entries.flatten() {
        let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        let age = now.duration_since(modified).unwrap_or_default();
        if age > MAX_RETAINED_AGE {
            let _ = std::fs::remove_file(entry.path());
        } else {
            kept.push((modified, entry.path()));
        }
    }
    kept.sort();
    let excess = kept.len().saturating_sub(MAX_RETAINED_PACKS);
    for (_, path) in kept.into_iter().take(excess) {
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack::{PackWriter, pack_key};

    fn pack_bytes(seed: u8) -> Vec<u8> {
        let mut writer = PackWriter::new();
        let object = crate::object::Object::Blob(crate::object::Blob {
            data: vec![seed; 64],
        });
        writer
            .push_raw(
                object.id().unwrap(),
                &crate::serialize::serialize(&object).unwrap(),
            )
            .unwrap();
        writer.finish().unwrap()
    }

    fn verified(bytes: &[u8], dir: &Path) -> (PackKey, VerifiedPack) {
        let key = PackKey::from_hash(pack_key(bytes));
        let mut spool = PackSpool::create(dir, PACK_BODY_LIMIT).unwrap();
        spool.begin(Some(bytes.len() as u64)).unwrap();
        spool.write(bytes).unwrap();
        (key, spool.finish(&key).unwrap())
    }

    fn read_all(pack: &VerifiedPack) -> Vec<u8> {
        let mut out = vec![0u8; usize::try_from(pack.len()).unwrap()];
        pack.read_at(0, &mut out).unwrap();
        out
    }

    fn files(cache: &RetainedPacks) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&cache.dir)
            .map(|entries| {
                entries
                    .flatten()
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    fn set_age(path: &Path, age: Duration) {
        let when = SystemTime::now() - age;
        File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(when)
            .unwrap();
    }

    #[test]
    fn a_kept_pack_comes_back_verified_and_is_discarded_on_request() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RetainedPacks::new(dir.path());
        let bytes = pack_bytes(1);
        let (key, pack) = verified(&bytes, dir.path());
        assert!(cache.take(&key).is_none());
        cache.keep(&key, &pack).unwrap();
        assert_eq!(files(&cache), [format!("{}.pack", key.to_hex())]);
        assert_eq!(read_all(&cache.take(&key).unwrap()), bytes);
        // Taking leaves the copy until the retry has applied it.
        assert_eq!(files(&cache).len(), 1);
        cache.discard(&key);
        assert!(files(&cache).is_empty());
        assert!(cache.take(&key).is_none());
    }

    #[test]
    fn a_damaged_short_or_swapped_file_is_refused_and_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RetainedPacks::new(dir.path());
        let bytes = pack_bytes(2);
        let (key, pack) = verified(&bytes, dir.path());
        let other = pack_bytes(3);
        let mut flipped = bytes.clone();
        flipped[bytes.len() / 2] ^= 1;
        let cases: [(&str, Vec<u8>); 4] = [
            ("flipped", flipped),
            ("truncated", bytes[..bytes.len() - 1].to_vec()),
            ("another pack", other),
            ("empty", Vec::new()),
        ];
        for (name, content) in cases {
            cache.keep(&key, &pack).unwrap();
            std::fs::write(cache.path(&key), content).unwrap();
            assert!(cache.take(&key).is_none(), "{name}");
            assert!(files(&cache).is_empty(), "{name} stays");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_in_the_cache_is_never_followed() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RetainedPacks::new(dir.path());
        let bytes = pack_bytes(4);
        let (key, pack) = verified(&bytes, dir.path());
        let outside = dir.path().join("outside");
        std::fs::write(&outside, &bytes).unwrap();
        ensure_dir(&cache.dir).unwrap();
        std::os::unix::fs::symlink(&outside, cache.path(&key)).unwrap();
        // A link to a file that does hold the pack is still not a kept pack.
        assert!(cache.take(&key).is_none());
        assert!(outside.exists(), "the target stays");
        assert!(files(&cache).is_empty());
        // A symlinked cache directory takes nothing and deletes nothing.
        std::fs::remove_dir(&cache.dir).unwrap();
        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::write(elsewhere.join("old"), b"x").unwrap();
        set_age(&elsewhere.join("old"), MAX_RETAINED_AGE * 2);
        std::os::unix::fs::symlink(&elsewhere, &cache.dir).unwrap();
        assert!(cache.keep(&key, &pack).is_err());
        cache.trim();
        assert!(elsewhere.join("old").exists());
        assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 1);
    }

    #[test]
    fn trim_drops_files_past_the_age_then_the_oldest_past_the_count() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RetainedPacks::new(dir.path());
        ensure_dir(&cache.dir).unwrap();
        for (name, age_hours) in [
            ("stale", 24 * 8),
            ("a", 5),
            ("b", 4),
            ("c", 3),
            ("d", 2),
            ("e", 1),
        ] {
            let path = cache.dir.join(name);
            std::fs::write(&path, b"x").unwrap();
            set_age(&path, Duration::from_secs(age_hours * 3600));
        }
        std::fs::create_dir(cache.dir.join("subdir")).unwrap();
        cache.trim();
        assert_eq!(files(&cache), ["b", "c", "d", "e", "subdir"]);
    }

    #[test]
    fn keeping_past_the_bound_drops_the_oldest() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RetainedPacks::new(dir.path());
        let mut keys = Vec::new();
        for seed in 0..=MAX_RETAINED_PACKS as u8 {
            let (key, pack) = verified(&pack_bytes(seed), dir.path());
            cache.keep(&key, &pack).unwrap();
            set_age(
                &cache.path(&key),
                Duration::from_secs((MAX_RETAINED_PACKS as u64 + 1 - u64::from(seed)) * 60),
            );
            keys.push(key);
        }
        // Each keep trimmed the cache, so only the oldest of the last set went.
        let names = files(&cache);
        assert_eq!(names.len(), MAX_RETAINED_PACKS);
        assert!(!names.contains(&format!("{}.pack", keys[0].to_hex())));
        assert!(names.contains(&format!("{}.pack", keys[MAX_RETAINED_PACKS].to_hex())));
    }

    #[test]
    fn trim_without_a_cache_does_nothing() {
        let dir = tempfile::tempdir().unwrap();
        RetainedPacks::new(dir.path()).trim();
        assert!(!dir.path().join(DIR_NAME).exists());
    }
}

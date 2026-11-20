use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use super::{Index, Location, read_pack_dir, scan_pair, visit_pairs};
use crate::atomic::sync_dir;
use crate::hash::Hash;
use crate::ops::gc::{GcReport, LiveSet, PackedGcReport};
use crate::store::{ObjectStore, StoreError, StoreResult};

#[derive(Default)]
pub(crate) struct PackSweep {
    pairs: BTreeMap<Hash, Retirement>,
    leftovers: BTreeMap<PathBuf, Stamp>,
}

struct Retirement {
    pack: Stamp,
    index: Stamp,
}

#[derive(PartialEq, Eq)]
struct Stamp {
    modified: SystemTime,
    len: u64,
    #[cfg(unix)]
    identity: (u64, u64, i64, i64),
    #[cfg(not(unix))]
    created: SystemTime,
}

impl Stamp {
    fn read(path: &Path) -> Option<Self> {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;

        let meta = fs::symlink_metadata(path).ok()?;
        if !meta.is_file() {
            return None;
        }
        Some(Self {
            modified: meta.modified().ok()?,
            len: meta.len(),
            #[cfg(unix)]
            identity: (meta.dev(), meta.ino(), meta.ctime(), meta.ctime_nsec()),
            #[cfg(not(unix))]
            created: meta.created().ok()?,
        })
    }

    fn old_enough(&self, now: u64, grace: u64) -> bool {
        self.modified
            .duration_since(std::time::UNIX_EPOCH)
            .is_ok_and(|mtime| now.saturating_sub(mtime.as_secs()) >= grace)
    }

    fn unchanged(&self, path: &Path) -> bool {
        Self::read(path).as_ref() == Some(self)
    }
}

impl ObjectStore {
    pub(crate) fn plan_pack_sweep(
        &self,
        live: &LiveSet,
        now: u64,
        grace: u64,
        report: &mut PackedGcReport,
    ) -> StoreResult<PackSweep> {
        let mut plan = PackSweep::default();
        if !self.local_packs_enabled()? {
            return Ok(plan);
        }
        let dir = self.pack_dir();
        visit_pairs(&dir, |pair| {
            report.packs_scanned += 1;
            let pack = Stamp::read(&pair.pack);
            let locator = Stamp::read(&pair.index);
            let index = Index::open(&pair)?;
            let (live_bytes, dead_bytes) = payload_bytes(&index, live);
            let old = pack
                .as_ref()
                .is_some_and(|stamp| stamp.old_enough(now, grace));
            if live_bytes == 0 {
                report.wholly_dead_bytes += dead_bytes;
            } else {
                report.mixed_dead_bytes += dead_bytes;
            }
            if old {
                report.eligible_dead_bytes += dead_bytes;
                if dead_bytes != 0 {
                    report.survivor_bytes += live_bytes;
                }
            }
            if live_bytes == 0
                && old
                && let (Some(pack), Some(locator)) = (pack, locator)
            {
                // An index checksum alone does not prove which ids the pack
                // holds. Verify the body before authorizing any deletion.
                let rows = match scan_pair(&pair) {
                    Ok(rows) => rows,
                    Err(StoreError::Io(error)) if error.kind() == io::ErrorKind::InvalidData => {
                        report.skipped_pack_errors.push(error.to_string());
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                };
                if !index.matches(&rows) {
                    return Err(pair.index_error("index does not match verified pack"));
                }
                plan.pairs.insert(
                    pair.key,
                    Retirement {
                        pack,
                        index: locator,
                    },
                );
            }
            Ok(())
        })?;
        if let Some(entries) = read_pack_dir(&dir)? {
            for entry in entries {
                let path = entry?.path();
                if is_leftover(&path)
                    && let Some(stamp) = Stamp::read(&path)
                    && stamp.old_enough(now, grace)
                {
                    plan.leftovers.insert(path, stamp);
                }
            }
        }
        Ok(plan)
    }
    pub(crate) fn sweep_loose_duplicates(
        &self,
        retirements: &PackSweep,
        live: &LiveSet,
        now: u64,
        grace: u64,
        report: &mut GcReport,
        packed: &mut PackedGcReport,
    ) -> StoreResult<BTreeSet<Hash>> {
        let mut loose_shards = [false; 256];
        for shard in 0..=u8::MAX {
            loose_shards[usize::from(shard)] = !self.list_loose_shard(shard)?.is_empty();
        }
        if !loose_shards.contains(&true) {
            return Ok(BTreeSet::new());
        }
        let dir = self.pack_dir();
        let mut previewed = BTreeSet::new();
        visit_pairs(&dir, |pair| {
            let (Some(pack), Some(locator)) = (Stamp::read(&pair.pack), Stamp::read(&pair.index))
            else {
                return Ok(());
            };
            // Dry run leaves its retirement candidates on disk.
            if report.dry_run && retirements.pairs.contains_key(&pair.key) {
                return Ok(());
            }
            let index = Arc::new(Index::open(&pair)?);
            let mut duplicates = Vec::new();
            for (id, frame) in index.entries() {
                if !loose_shards[usize::from(id[0])] || previewed.contains(&id) {
                    continue;
                }
                let path = self.path_for(&id);
                let Some(loose) = Stamp::read(&path) else {
                    continue;
                };
                let old = loose.old_enough(now, grace);
                if (!old && pack.modified < loose.modified) || (old && !live.contains(&id)) {
                    continue;
                }
                duplicates.push((id, frame, loose));
            }
            if duplicates.is_empty() {
                return Ok(());
            }

            #[cfg(test)]
            super::tests::before_duplicate_try_lock();
            let _guard = if report.dry_run {
                None
            } else {
                let file = fs::File::open(self.format_path())?;
                if file.try_lock().is_err() {
                    return Ok(());
                }
                Some(file)
            };
            if !pack.unchanged(&pair.pack) || !locator.unchanged(&pair.index) {
                return Ok(());
            }
            let mut durable = false;
            for (id, frame, loose) in duplicates {
                let path = self.path_for(&id);
                let location = Location::Packed(Arc::clone(&index), frame);
                if !loose.unchanged(&path)
                    || ObjectStore::raw_at(&location)
                        .and_then(|bytes| ObjectStore::verify_at(&location, &id, &bytes))
                        .is_err()
                {
                    continue;
                }
                if report.dry_run {
                    previewed.insert(id);
                } else {
                    if !durable {
                        crate::store::sync_reused_file(&pair.pack)?;
                        crate::store::sync_reused_file(&pair.index)?;
                        sync_dir(self.objects_root())?;
                        sync_dir(&dir)?;
                        durable = true;
                    }
                    fs::remove_file(path)?;
                }
                report.bytes_reclaimed += loose.len;
                packed.loose_duplicates_pruned += 1;
            }
            Ok(())
        })?;
        Ok(previewed)
    }
}

impl PackSweep {
    pub(crate) fn run(
        &self,
        store: &ObjectStore,
        report: &mut GcReport,
        packed: &mut PackedGcReport,
    ) -> StoreResult<()> {
        self.run_with(store, report, packed, || Ok(()))
    }

    pub(super) fn run_with(
        &self,
        store: &ObjectStore,
        report: &mut GcReport,
        packed: &mut PackedGcReport,
        after_pack_sync: impl FnOnce() -> StoreResult<()>,
    ) -> StoreResult<()> {
        if report.dry_run {
            packed.packs_retired = self.pairs.len();
            packed.pack_leftovers_pruned = self.leftovers.len();
            report.bytes_reclaimed += self
                .pairs
                .values()
                .map(|r| r.pack.len + r.index.len)
                .sum::<u64>()
                + self.leftovers.values().map(|s| s.len).sum::<u64>();
            return Ok(());
        }
        if self.pairs.is_empty() && self.leftovers.is_empty() {
            return Ok(());
        }
        let guard = fs::File::open(store.format_path())?;
        if guard.try_lock().is_err() {
            return Ok(());
        }
        let dir = store.pack_dir();
        let mut retire = Vec::new();
        // Writers may have published or refreshed a pair since the mark. Scan
        // under the guard and retire only the same pair with unchanged mtimes.
        visit_pairs(&dir, |pair| {
            if let Some(r) = self.pairs.get(&pair.key)
                && r.pack.unchanged(&pair.pack)
                && r.index.unchanged(&pair.index)
            {
                retire.push((pair, r));
            }
            Ok(())
        })?;
        let leftovers: Vec<_> = self
            .leftovers
            .iter()
            .filter(|(path, stamp)| is_leftover(path) && stamp.unchanged(path))
            .collect();

        for (pair, _) in &retire {
            fs::remove_file(&pair.pack)?;
        }
        // Flush the missing pack names before unlinking any index. This also
        // covers an index left by a prior retirement that died before syncing.
        if !retire.is_empty() || !leftovers.is_empty() {
            sync_dir(&dir)?;
        }
        if !retire.is_empty() {
            after_pack_sync()?;
        }
        for (pair, r) in &retire {
            fs::remove_file(&pair.index)?;
            store.packs.forget(&pair.key);
            packed.packs_retired += 1;
            report.bytes_reclaimed += r.pack.len + r.index.len;
        }
        for (path, stamp) in &leftovers {
            fs::remove_file(path)?;
            packed.pack_leftovers_pruned += 1;
            report.bytes_reclaimed += stamp.len;
        }
        if !retire.is_empty() || !leftovers.is_empty() {
            sync_dir(&dir)?;
        }
        Ok(())
    }
}

fn payload_bytes(index: &Index, live: &LiveSet) -> (u64, u64) {
    let mut live_bytes = 0;
    let mut dead_bytes = 0;
    for (id, frame) in index.entries() {
        if live.contains(&id) {
            live_bytes += u64::from(frame.len);
        } else {
            dead_bytes += u64::from(frame.len);
        }
    }
    (live_bytes, dead_bytes)
}

/// A recognized staging file or a final member with no counterpart.
fn is_leftover(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let has_hex_len = |value: &str, len| {
        value.len() == len
            && value
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    };
    for (suffix, sibling) in [(".pack", "idx"), (".idx", "pack")] {
        if let Some(stem) = name.strip_suffix(suffix) {
            if let Some(nonce) = stem.strip_prefix('.').and_then(|s| s.strip_suffix(".tmp")) {
                return has_hex_len(nonce, 32);
            }
            return has_hex_len(stem, 64)
                && fs::symlink_metadata(path.with_extension(sibling))
                    .is_err_and(|e| e.kind() == io::ErrorKind::NotFound);
        }
    }
    false
}

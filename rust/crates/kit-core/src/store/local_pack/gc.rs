use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use super::{Index, Location, read_pack_dir, scan_pair_checked, visit_pairs};
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
    #[cfg(test)]
    pub(crate) fn last_sweep_hold() -> std::time::Duration {
        SWEEP_HOLD.get()
    }

    pub(crate) fn plan_pack_sweep(
        &self,
        live: &LiveSet,
        now: u64,
        grace: u64,
        report: &mut PackedGcReport,
    ) -> StoreResult<PackSweep> {
        let mut plan = self.plan_pack_retirement(live, now, grace, report, &|| Ok(()))?;
        let dir = self.pack_dir();
        if self.local_packs_enabled()?
            && let Some(entries) = read_pack_dir(&dir)?
        {
            for entry in entries {
                let path = entry?.path();
                if is_leftover(&path) {
                    plan.add_old_leftover(path, now, grace);
                }
            }
        }
        Ok(plan)
    }

    pub(crate) fn plan_pack_retirement(
        &self,
        live: &LiveSet,
        now: u64,
        grace: u64,
        report: &mut PackedGcReport,
        checkpoint: &dyn Fn() -> StoreResult<()>,
    ) -> StoreResult<PackSweep> {
        let mut plan = PackSweep::default();
        if !self.local_packs_enabled()? {
            return Ok(plan);
        }
        let dir = self.pack_dir();
        visit_pairs(&dir, |pair| {
            checkpoint()?;
            report.packs_scanned += 1;
            let pack = Stamp::read(&pair.pack);
            let locator = Stamp::read(&pair.index);
            let index = Index::open(&pair)?;
            let (live_bytes, dead_bytes) = payload_bytes(&index, live, checkpoint)?;
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
                let rows = match scan_pair_checked(&pair, checkpoint) {
                    Ok(rows) => rows,
                    Err(StoreError::Io(error)) if error.kind() == io::ErrorKind::InvalidData => {
                        report.skipped_pack_errors.push(error.to_string());
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                };
                checkpoint()?;
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
        checkpoint()?;
        Ok(plan)
    }

    pub(crate) fn try_packed_for_maintenance(&self) -> StoreResult<bool> {
        use std::sync::atomic::Ordering;
        if self.packs.enabled.load(Ordering::Relaxed) {
            return Ok(true);
        }
        let enabled = super::format::try_check(&self.format_path())?;
        if enabled {
            self.packs.enabled.store(true, Ordering::Relaxed);
        }
        Ok(enabled)
    }

    pub(crate) fn plan_pack_leftovers(
        &self,
        now: u64,
        grace: u64,
    ) -> StoreResult<(PackSweep, usize)> {
        let mut plan = PackSweep::default();
        let mut pairs = 0;
        let dir = self.pack_dir();
        if let Some(entries) = read_pack_dir(&dir)? {
            let mut members = HashMap::<Hash, u8>::new();
            for entry in entries {
                let entry = entry?;
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                match leftover_name(name) {
                    Some(LeftoverName::Staging) => plan.add_old_leftover(entry.path(), now, grace),
                    Some(LeftoverName::Pack(key)) => *members.entry(key).or_default() |= 1,
                    Some(LeftoverName::Index(key)) => *members.entry(key).or_default() |= 2,
                    None => {}
                }
            }
            for (key, present) in members {
                if present == 3 {
                    pairs += 1;
                } else {
                    let pair = super::Pair::new(&dir, key);
                    let path = if present == 1 { pair.pack } else { pair.index };
                    plan.add_old_leftover(path, now, grace);
                }
            }
        }
        Ok((plan, pairs))
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
    fn add_old_leftover(&mut self, path: PathBuf, now: u64, grace: u64) {
        if let Some(stamp) = Stamp::read(&path)
            && stamp.old_enough(now, grace)
        {
            self.leftovers.insert(path, stamp);
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pairs.is_empty() && self.leftovers.is_empty()
    }

    pub(crate) fn run(
        &self,
        store: &ObjectStore,
        report: &mut GcReport,
        packed: &mut PackedGcReport,
    ) -> StoreResult<()> {
        self.run_with(store, report, packed, || Ok(())).map(|_| ())
    }

    pub(crate) fn run_with(
        &self,
        store: &ObjectStore,
        report: &mut GcReport,
        packed: &mut PackedGcReport,
        after_pack_sync: impl FnOnce() -> StoreResult<()>,
    ) -> StoreResult<bool> {
        if report.dry_run {
            packed.packs_retired = self.pairs.len();
            packed.pack_leftovers_pruned = self.leftovers.len();
            report.bytes_reclaimed += self
                .pairs
                .values()
                .map(|r| r.pack.len + r.index.len)
                .sum::<u64>()
                + self.leftovers.values().map(|s| s.len).sum::<u64>();
            return Ok(true);
        }
        if self.is_empty() {
            return Ok(true);
        }
        let guard = fs::File::open(store.format_path())?;
        if guard.try_lock().is_err() {
            return Ok(false);
        }
        #[cfg(test)]
        let locked_at = std::time::Instant::now();
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
        drop(guard);
        #[cfg(test)]
        SWEEP_HOLD.set(locked_at.elapsed());
        Ok(true)
    }
}

#[cfg(test)]
thread_local! {
    static SWEEP_HOLD: std::cell::Cell<std::time::Duration> = const {
        std::cell::Cell::new(std::time::Duration::ZERO)
    };
}

fn payload_bytes(
    index: &Index,
    live: &LiveSet,
    checkpoint: &dyn Fn() -> StoreResult<()>,
) -> StoreResult<(u64, u64)> {
    let mut live_bytes = 0;
    let mut dead_bytes = 0;
    for (id, frame) in index.entries() {
        checkpoint()?;
        if live.contains(&id) {
            live_bytes += u64::from(frame.len);
        } else {
            dead_bytes += u64::from(frame.len);
        }
    }
    Ok((live_bytes, dead_bytes))
}

enum LeftoverName {
    Staging,
    Pack(Hash),
    Index(Hash),
}

fn leftover_name(name: &str) -> Option<LeftoverName> {
    if name.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return None;
    }
    let (stem, final_name): (&str, fn(Hash) -> LeftoverName) =
        if let Some(stem) = name.strip_suffix(".pack") {
            (stem, LeftoverName::Pack)
        } else {
            (name.strip_suffix(".idx")?, LeftoverName::Index)
        };
    if let Some(nonce) = stem
        .strip_prefix('.')
        .and_then(|stem| stem.strip_suffix(".tmp"))
    {
        return (nonce.len() == 32 && nonce.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .then_some(LeftoverName::Staging);
    }
    crate::hash::from_hex(stem).ok().map(final_name)
}

/// A recognized staging file or a final member with no counterpart.
fn is_leftover(path: &Path) -> bool {
    let name = path.file_name().and_then(|name| name.to_str());
    let sibling = match name.and_then(leftover_name) {
        Some(LeftoverName::Staging) => return true,
        Some(LeftoverName::Pack(_)) => "idx",
        Some(LeftoverName::Index(_)) => "pack",
        None => return false,
    };
    fs::symlink_metadata(path.with_extension(sibling))
        .is_err_and(|e| e.kind() == io::ErrorKind::NotFound)
}

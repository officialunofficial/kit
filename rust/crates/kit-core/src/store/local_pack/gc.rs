use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use super::copy::{Copied, CopyPlan, Limit};
use super::{Index, Location, Pair, read_pack_dir, scan_pair_checked, visit_pairs};
use crate::atomic::sync_dir;
use crate::hash::Hash;
use crate::ops::gc::{GcReport, LiveSet};
use crate::store::{ObjectStore, StoreError, StoreResult};

#[derive(Default)]
pub(crate) struct PackSweep {
    pairs: BTreeMap<Hash, Retirement>,
    leftovers: BTreeMap<PathBuf, Stamp>,
    copy: Option<CopyPlan>,
    /// Planning stopped before it verified every wholly dead pack past grace,
    /// because [`Verify::room`] said no. The rest stay for a later run.
    cut_short: bool,
}

/// The most items one exclusive `format` hold retires: pack pairs, copy
/// inputs and leftovers together. A run takes the lock again for the next
/// batch, rechecking every stamp, so one hold stays short however many pairs
/// retire. [`RETIRE_BATCH_BYTES`] bounds a hold by size as well. Policy, not
/// format.
pub(crate) const RETIRE_BATCH: usize = 32;

/// The most file bytes one exclusive `format` hold unlinks, besides the item
/// count. A hold of 32 packs of 64 MiB took 150 ms and more on a shared VM;
/// 256 MiB, four such packs, took a median of 11 to 19 ms. The cap bounds the
/// work that scales with size, not a stalled flush. A batch always takes at
/// least one item, so a pack larger than the cap still retires, alone.
/// Policy, not format.
pub(crate) const RETIRE_BATCH_BYTES: u64 = 256 << 20;

/// How planning verifies the body of each wholly dead pack past grace, before
/// it may authorize an unlink.
pub(crate) struct Verify<'a> {
    /// Asked before each pack, oldest first. False stops verifying: the packs
    /// verified so far stay planned and the rest wait for a later run.
    pub(crate) room: &'a dyn Fn() -> bool,
    /// Asked while one pack is read. An error ends planning with nothing
    /// planned.
    pub(crate) scan: &'a dyn Fn() -> StoreResult<()>,
}

/// A wholly dead pack past grace that planning has seen but not yet verified.
struct Candidate {
    pair: Pair,
    pack: Stamp,
    locator: Stamp,
}

struct Retirement {
    pack: Stamp,
    index: Stamp,
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct Stamp {
    pub(super) modified: SystemTime,
    pub(super) len: u64,
    #[cfg(unix)]
    identity: (u64, u64, i64, i64),
    #[cfg(not(unix))]
    created: SystemTime,
}

impl Stamp {
    pub(super) fn read(path: &Path) -> Option<Self> {
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

    pub(super) fn old_enough(&self, now: u64, grace: u64) -> bool {
        self.modified
            .duration_since(std::time::UNIX_EPOCH)
            .is_ok_and(|mtime| now.saturating_sub(mtime.as_secs()) >= grace)
    }

    pub(super) fn unchanged(&self, path: &Path) -> bool {
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
        report: &mut GcReport,
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
        if self.local_packs_enabled()? {
            plan.plan_copy(self, live, now, grace, Limit::NONE, &|| Ok(()))?;
        }
        Ok(plan)
    }

    pub(crate) fn plan_pack_retirement(
        &self,
        live: &LiveSet,
        now: u64,
        grace: u64,
        report: &mut GcReport,
        checkpoint: &dyn Fn() -> StoreResult<()>,
    ) -> StoreResult<PackSweep> {
        self.plan_pack_retirement_within(
            live,
            now,
            grace,
            report,
            checkpoint,
            &Verify {
                room: &|| true,
                scan: checkpoint,
            },
        )
    }

    /// Plan the wholly dead retirement. A pass over every pair counts its
    /// bytes and lists the wholly dead packs past grace. A second pass
    /// verifies those, oldest first, while `verify.room` allows, so a run
    /// that stops early has planned the packs it verified and nothing else.
    pub(crate) fn plan_pack_retirement_within(
        &self,
        live: &LiveSet,
        now: u64,
        grace: u64,
        report: &mut GcReport,
        checkpoint: &dyn Fn() -> StoreResult<()>,
        verify: &Verify<'_>,
    ) -> StoreResult<PackSweep> {
        let mut plan = PackSweep::default();
        if !self.local_packs_enabled()? {
            return Ok(plan);
        }
        let dir = self.pack_dir();
        let mut candidates = Vec::new();
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
                candidates.push(Candidate {
                    pair,
                    pack,
                    locator,
                });
            }
            Ok(())
        })?;
        checkpoint()?;
        candidates.sort_by_key(|candidate| (candidate.pack.modified, candidate.pair.key));
        for candidate in candidates {
            if !(verify.room)() {
                plan.cut_short = true;
                break;
            }
            let Candidate {
                pair,
                pack,
                locator,
            } = candidate;
            // The stamps above came first, so a pair that changes after them
            // fails its recheck at retirement.
            let index = Index::open(&pair)?;
            // An index checksum alone does not prove which ids the pack
            // holds. Verify the body before authorizing any deletion.
            let rows = match scan_pair_checked(&pair, verify.scan) {
                Ok(rows) => rows,
                Err(error @ StoreError::LocalPackDamaged { .. }) => {
                    report.skipped_pack_errors.push(error.to_string());
                    continue;
                }
                Err(error) => return Err(error),
            };
            (verify.scan)()?;
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
                report.loose_duplicates_pruned += 1;
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

    /// For a copy step that returned `result`: when it failed with an I/O
    /// error, such as a full disk or an expired budget, drop the planned copy
    /// so that only wholly dead pairs and leftovers retire, as they do
    /// without a copy, and return the error kind. Interruption, damage and
    /// every other error pass on.
    pub(crate) fn defer_copy_on_io_error(
        &mut self,
        result: StoreResult<()>,
    ) -> StoreResult<Option<std::io::ErrorKind>> {
        match result {
            Ok(()) => Ok(None),
            Err(StoreError::Io(error)) if error.kind() != std::io::ErrorKind::Interrupted => {
                self.copy = None;
                Ok(Some(error.kind()))
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pairs.is_empty() && self.leftovers.is_empty() && self.copy.is_none()
    }

    /// Verification stopped before every wholly dead pack past grace was
    /// verified: the rest wait for a later run.
    pub(crate) fn verification_cut_short(&self) -> bool {
        self.cut_short
    }

    /// Whole packs planned for retirement.
    pub(crate) fn planned_packs(&self) -> usize {
        self.pairs.len()
    }

    #[cfg(test)]
    pub(super) fn plans(&self, pair: &Pair) -> bool {
        self.pairs.contains_key(&pair.key)
    }

    /// The copy plan left inputs for a later run, because one output pack
    /// could not hold their survivors as well.
    pub(crate) fn copy_left_inputs(&self) -> bool {
        self.copy.as_ref().is_some_and(CopyPlan::left_inputs)
    }

    pub(crate) fn run(&self, store: &ObjectStore, report: &mut GcReport) -> StoreResult<()> {
        self.run_with(store, report, || Ok(())).map(|_| ())
    }

    /// Plan copy-then-retire for the pairs that the wholly dead retirement
    /// leaves alone.
    fn plan_copy(
        &mut self,
        store: &ObjectStore,
        live: &LiveSet,
        now: u64,
        grace: u64,
        limit: Limit,
        checkpoint: &dyn Fn() -> StoreResult<()>,
    ) -> StoreResult<()> {
        self.copy = CopyPlan::plan(
            store,
            live,
            now,
            grace,
            limit,
            |key| self.pairs.contains_key(key),
            checkpoint,
        )?;
        Ok(())
    }

    /// The automatic step's plan: at most one output pack of survivors.
    pub(crate) fn plan_automatic_copy(
        &mut self,
        store: &ObjectStore,
        live: &LiveSet,
        now: u64,
        grace: u64,
        checkpoint: &dyn Fn() -> StoreResult<()>,
    ) -> StoreResult<()> {
        self.plan_copy(store, live, now, grace, Limit::automatic(), checkpoint)
    }

    /// Verify coverage, copy and publish, under the shared `format` guard
    /// that the copy releases before the exclusive try of [`Self::retire`]:
    /// the process would otherwise fail its own try. It reads pack bodies, so
    /// the automatic step calls it before it tries any worktree lock.
    ///
    /// A `strict` run stops at damage and publishes nothing; see
    /// `CopyPlan::execute`.
    pub(crate) fn copy_survivors(
        &self,
        store: &ObjectStore,
        report: &mut GcReport,
        checkpoint: &dyn Fn() -> StoreResult<()>,
        strict: bool,
    ) -> StoreResult<Option<Copied>> {
        self.copy
            .as_ref()
            .map(|copy| copy.execute(store, report, checkpoint, strict))
            .transpose()
    }

    pub(crate) fn run_with(
        &self,
        store: &ObjectStore,
        report: &mut GcReport,
        after_pack_sync: impl FnOnce() -> StoreResult<()>,
    ) -> StoreResult<bool> {
        if report.dry_run {
            report.packs_retired = self.pairs.len();
            report.pack_leftovers_pruned = self.leftovers.len();
            report.bytes_reclaimed += self
                .pairs
                .values()
                .map(|r| r.pack.len + r.index.len)
                .sum::<u64>()
                + self.leftovers.values().map(|s| s.len).sum::<u64>();
            if let Some(copy) = &self.copy {
                copy.preview(report);
            }
            return Ok(true);
        }
        if self.is_empty() {
            return Ok(true);
        }
        // A failed copy, such as a full disk, keeps every copy input and
        // still lets the wholly dead retirement free space.
        let copied = match self.copy_survivors(store, report, &|| Ok(()), false) {
            Ok(copied) => copied,
            Err(error) => {
                report.pack_copy_error = Some(error.to_string());
                None
            }
        };
        #[cfg(test)]
        super::tests::after_copy_publish()?;
        self.retire(store, report, copied.as_ref(), after_pack_sync)
    }

    fn batch() -> (usize, u64) {
        #[cfg(test)]
        if let Some(limits) = super::tests::retire_batch() {
            return limits;
        }
        (RETIRE_BATCH, RETIRE_BATCH_BYTES)
    }

    /// Retire the planned pairs, the copy inputs that `copied` covers and the
    /// leftovers, [`RETIRE_BATCH`] at a time. Each batch is its own exclusive
    /// `format` try-lock: it rechecks every stamp, flushes what its inputs
    /// rely on, unlinks the pack names, syncs, unlinks the indexes and syncs.
    /// A crash between batches leaves only pairs that the next run
    /// reconsiders, and inputs whose survivors already have copies.
    ///
    /// Returns false when an exclusive try fails. Earlier batches stay done.
    pub(crate) fn retire(
        &self,
        store: &ObjectStore,
        report: &mut GcReport,
        copied: Option<&Copied>,
        after_pack_sync: impl FnOnce() -> StoreResult<()>,
    ) -> StoreResult<bool> {
        let whole: Vec<&Hash> = self.pairs.keys().collect();
        let inputs = copied.map(Copied::candidates).unwrap_or_default();
        let leftovers: Vec<(&PathBuf, &Stamp)> = self.leftovers.iter().collect();
        let whole_bytes: Vec<u64> = whole
            .iter()
            .map(|key| self.pairs[*key].pack.len + self.pairs[*key].index.len)
            .collect();
        let input_bytes: Vec<u64> = inputs
            .iter()
            .map(|&at| copied.map_or(0, |copied| copied.input_bytes(at)))
            .collect();
        let leftover_bytes: Vec<u64> = leftovers.iter().map(|(_, stamp)| stamp.len).collect();
        let (size, byte_cap) = Self::batch();
        debug_assert!(size > 0, "a batch needs room for one item");
        let mut run = Run {
            hook: Some(after_pack_sync),
            flushed: BTreeSet::new(),
            copy_freed: 0,
        };
        let (mut at_whole, mut at_input, mut at_leftover) = (0, 0, 0);
        while at_whole < whole.len() || at_input < inputs.len() || at_leftover < leftovers.len() {
            // A batch holds at most `size` items and `byte_cap` file bytes,
            // and always at least one item, so every batch makes progress.
            let mut room = size;
            let mut bytes = byte_cap;
            let mut take = |from: &mut usize, sizes: &[u64]| {
                let start = *from;
                while *from < sizes.len() && room > 0 && (room == size || sizes[*from] <= bytes) {
                    room -= 1;
                    bytes = bytes.saturating_sub(sizes[*from]);
                    *from += 1;
                }
                start..*from
            };
            let whole_batch = take(&mut at_whole, &whole_bytes);
            let input_batch = take(&mut at_input, &input_bytes);
            let leftover_batch = take(&mut at_leftover, &leftover_bytes);
            let batch = Batch {
                whole: &whole[whole_batch],
                inputs: &inputs[input_batch],
                leftovers: &leftovers[leftover_batch],
            };
            if !self.retire_batch(store, report, copied, &batch, &mut run)? {
                report.pack_retirement_cut_short = true;
                Self::count_copy_freed(report, copied, &run);
                return Ok(false);
            }
            #[cfg(test)]
            super::tests::after_retire_batch(report.retire_batches)?;
        }
        Self::count_copy_freed(report, copied, &run);
        Ok(true)
    }

    /// Adds what retired copy inputs freed, net of the outputs, for the
    /// batches that ran, including a run that a later batch ended early.
    fn count_copy_freed<F: FnOnce() -> StoreResult<()>>(
        report: &mut GcReport,
        copied: Option<&Copied>,
        run: &Run<F>,
    ) {
        if let Some(copied) = copied {
            report.bytes_reclaimed += run.copy_freed.saturating_sub(copied.written());
        }
    }

    fn retire_batch<F: FnOnce() -> StoreResult<()>>(
        &self,
        store: &ObjectStore,
        report: &mut GcReport,
        copied: Option<&Copied>,
        batch: &Batch<'_>,
        run: &mut Run<F>,
    ) -> StoreResult<bool> {
        let guard = fs::File::open(store.format_path())?;
        if guard.try_lock().is_err() {
            return Ok(false);
        }
        let locked_at = std::time::Instant::now();
        let dir = store.pack_dir();
        // Writers may have published or refreshed a pair since the mark.
        // Retire only the same pair with unchanged stamps.
        let mut retire = Vec::new();
        for key in batch.whole {
            let r = &self.pairs[*key];
            let pair = Pair::new(&dir, **key);
            if r.pack.unchanged(&pair.pack) && r.index.unchanged(&pair.index) {
                retire.push((pair, r));
            }
        }
        let leftovers: Vec<_> = batch
            .leftovers
            .iter()
            .filter(|(path, stamp)| is_leftover(path) && stamp.unchanged(path))
            .collect();
        let copy_retire = copied
            .map(|copied| copied.select(&dir, &|key| self.pairs.contains_key(key), batch.inputs))
            .unwrap_or_default();

        // Make every pair that a retired input relies on durable before the
        // first unlink: a publisher may have died before its last directory
        // flush, and so may an earlier run. A pair that an earlier batch
        // flushed has unchanged stamps, so it is still durable.
        if let Some(copied) = copied {
            let mut fresh = false;
            for pair in copied.deps(&copy_retire) {
                if run.flushed.insert(pair.key) {
                    flush_file(&pair.pack)?;
                    flush_file(&pair.index)?;
                    fresh = true;
                }
            }
            if fresh {
                flush_dir(store.objects_root())?;
                flush_dir(&dir)?;
            }
        }

        let any = !retire.is_empty() || !copy_retire.is_empty();
        for pair in retire
            .iter()
            .map(|(pair, _)| pair)
            .chain(copy_retire.iter().map(|input| &input.pair))
        {
            unlink(&pair.pack)?;
        }
        // Flush the missing pack names before unlinking any index. This also
        // covers an index left by a prior retirement that died before syncing.
        if any || !leftovers.is_empty() {
            flush_dir(&dir)?;
        }
        if any && let Some(hook) = run.hook.take() {
            hook()?;
        }
        for (pair, r) in &retire {
            unlink(&pair.index)?;
            store.packs.forget(&pair.key);
            report.packs_retired += 1;
            report.bytes_reclaimed += r.pack.len + r.index.len;
        }
        for input in &copy_retire {
            unlink(&input.pair.index)?;
            store.packs.forget(&input.pair.key);
        }
        if let Some(copied) = copied {
            run.copy_freed += copied.report(&copy_retire, report);
        }
        for (path, stamp) in &leftovers {
            unlink(path)?;
            report.pack_leftovers_pruned += 1;
            report.bytes_reclaimed += stamp.len;
        }
        if any || !leftovers.is_empty() {
            flush_dir(&dir)?;
        }
        drop(guard);
        let held = locked_at.elapsed();
        report.retire_batches += 1;
        report.retire_hold_ms = report
            .retire_hold_ms
            .max(u64::try_from(held.as_millis()).unwrap_or(u64::MAX));
        #[cfg(test)]
        SWEEP_HOLD.set(held);
        Ok(true)
    }
}

/// What a retirement carries from one batch to the next.
struct Run<F> {
    /// Runs once, after the first batch that unlinks a pack name.
    hook: Option<F>,
    /// Pairs already flushed: their stamps are checked again, so they stay
    /// durable.
    flushed: BTreeSet<Hash>,
    /// File bytes of the retired copy inputs.
    copy_freed: u64,
}

/// One exclusive hold's share of a retirement.
struct Batch<'a> {
    whole: &'a [&'a Hash],
    inputs: &'a [usize],
    leftovers: &'a [(&'a PathBuf, &'a Stamp)],
}

pub(super) fn flush_file(path: &Path) -> StoreResult<()> {
    #[cfg(test)]
    super::tests::note_io("sync", path);
    crate::store::sync_reused_file(path)?;
    Ok(())
}

pub(super) fn flush_dir(path: &Path) -> StoreResult<()> {
    #[cfg(test)]
    super::tests::note_io("sync-dir", path);
    sync_dir(path)?;
    Ok(())
}

fn unlink(path: &Path) -> StoreResult<()> {
    #[cfg(test)]
    super::tests::note_io("unlink", path);
    fs::remove_file(path)?;
    Ok(())
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

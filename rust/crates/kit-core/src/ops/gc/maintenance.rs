//! Best-effort local pack maintenance after a fetch has published its refs.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::{
    AUTO_MAINTENANCE_STAMP, DEFAULT_GRACE_SECS, GcReport, GcRootsError, MarkLimits, PackedGcReport,
    collect_root_sets, mark_live_checked, reject_symlink,
};
use crate::layout::{RepoLayout, all_state_layouts};
use crate::repo_lock::{LockError, WORKTREE_LOCK, WORKTREES_REGISTRY_LOCK, acquire};
use crate::store::{ObjectStore, StoreError};

const MIN_PAIRS: usize = 32;
const BUDGET: Duration = Duration::from_secs(5);
const HOUR: u64 = 3600;

const INTERRUPTED: &str = "automatic maintenance interrupted";
const DEADLINE: &str = "automatic maintenance deadline";

/// Result of the automatic collection decision.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Collection {
    /// The repository has too few local packs, the interval has not passed, or the step was skipped.
    #[default]
    NotDue,
    /// The mark and retirement decision completed.
    Complete,
    /// A required lock was busy.
    Busy,
    /// Retention roots changed during the unlocked mark.
    RootsChanged,
    /// The mark and plan ran out of time.
    OverBudget,
    /// The attempt stopped on unreadable state, damage or interruption.
    Failed,
}

impl Collection {
    /// Stable name for machine-readable reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotDue => "not_due",
            Self::Complete => "complete",
            Self::Busy => "busy",
            Self::RootsChanged => "roots_changed",
            Self::OverBudget => "over_budget",
            Self::Failed => "failed",
        }
    }

    const fn interval(self) -> u64 {
        match self {
            Self::Busy | Self::RootsChanged => HOUR,
            Self::OverBudget => 30 * 24 * HOUR,
            Self::Complete | Self::Failed | Self::NotDue => 7 * 24 * HOUR,
        }
    }
}

/// What automatic local pack maintenance removed and whether collection ran.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MaintenanceReport {
    /// Abandoned staging files and lone pack members removed.
    pub leftovers_removed: usize,
    /// Wholly dead pack pairs retired.
    pub packs_retired: usize,
    /// Bytes of removed pack and index files, including leftovers.
    pub bytes_reclaimed: u64,
    /// Result of the collection decision.
    pub collection: Collection,
    /// Duration of the step.
    pub elapsed: Duration,
}

#[derive(Clone, Copy)]
struct Stamp {
    attempted: u64,
    outcome: Collection,
    complete_pairs: u64,
}

impl Stamp {
    fn read(file: &mut File) -> Option<Self> {
        let mut bytes = [0; 17];
        file.read_exact(&mut bytes).ok()?;
        if file.read(&mut [0]).ok()? != 0 {
            return None;
        }
        Self::decode(&bytes)
    }

    fn decode(bytes: &[u8; 17]) -> Option<Self> {
        let outcome = match bytes[8] {
            1 => Collection::NotDue,
            2 => Collection::Complete,
            3 => Collection::Busy,
            4 => Collection::RootsChanged,
            5 => Collection::OverBudget,
            6 => Collection::Failed,
            _ => return None,
        };
        Some(Self {
            attempted: u64::from_le_bytes(bytes[..8].try_into().ok()?),
            outcome,
            complete_pairs: u64::from_le_bytes(bytes[9..].try_into().ok()?),
        })
    }

    fn encode(self) -> [u8; 17] {
        let mut bytes = [0; 17];
        bytes[..8].copy_from_slice(&self.attempted.to_le_bytes());
        bytes[8] = match self.outcome {
            Collection::NotDue => 1,
            Collection::Complete => 2,
            Collection::Busy => 3,
            Collection::RootsChanged => 4,
            Collection::OverBudget => 5,
            Collection::Failed => 6,
        };
        bytes[9..].copy_from_slice(&self.complete_pairs.to_le_bytes());
        bytes
    }

    fn write(self, file: &mut File) -> io::Result<()> {
        file.rewind()?;
        file.set_len(0)?;
        file.write_all(&self.encode())
    }

    fn due(self, now: u64, pairs: usize) -> bool {
        pairs >= MIN_PAIRS
            && (now < self.attempted || now - self.attempted >= self.outcome.interval())
    }
}

fn lock_stamp(dir: &Path) -> io::Result<File> {
    let path = dir.join(AUTO_MAINTENANCE_STAMP);
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    reject_symlink(&path).map_err(io::Error::other)?;
    let file = options.open(&path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(io::ErrorKind::InvalidData.into());
        }
    }
    file.try_lock()?;
    Ok(file)
}

fn now_secs() -> u64 {
    #[cfg(test)]
    if let Some(now) = TEST_NOW.get() {
        return now;
    }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Sweep old pack leftovers and, when due, retire wholly dead local packs.
///
/// Call after the last ref publish has released its worktree lock and prune
/// guard. The step only tries locks and honors cancellation before removing
/// files. Its result never supersedes the fetch result.
#[doc(hidden)]
#[must_use]
pub fn maintain_packs(
    layout: &RepoLayout,
    store: &ObjectStore,
    cancelled: &dyn Fn() -> bool,
) -> MaintenanceReport {
    maintain_with(layout, store, cancelled, BUDGET, || {})
}

fn maintain_with(
    layout: &RepoLayout,
    store: &ObjectStore,
    cancelled: &dyn Fn() -> bool,
    budget: Duration,
    before_collection_locks: impl FnOnce(),
) -> MaintenanceReport {
    let start = Instant::now();
    let mut pack_report = PackedGcReport::default();
    let mut gc_report = GcReport::default();
    let collection = run(
        layout,
        store,
        cancelled,
        budget,
        before_collection_locks,
        &mut gc_report,
        &mut pack_report,
    );
    MaintenanceReport {
        leftovers_removed: pack_report.pack_leftovers_pruned,
        packs_retired: pack_report.packs_retired,
        bytes_reclaimed: gc_report.bytes_reclaimed,
        collection,
        elapsed: start.elapsed(),
    }
}

fn run(
    layout: &RepoLayout,
    store: &ObjectStore,
    cancelled: &dyn Fn() -> bool,
    budget: Duration,
    before_collection_locks: impl FnOnce(),
    gc: &mut GcReport,
    packed: &mut PackedGcReport,
) -> Collection {
    if cancelled()
        || layout.objects_dir() != store.objects_root()
        || reject_symlink(layout.common_dir()).is_err()
        || reject_symlink(store.objects_root()).is_err()
    {
        return Collection::NotDue;
    }
    let Ok(mut file) = lock_stamp(layout.common_dir()) else {
        return Collection::NotDue;
    };
    let now = now_secs();
    let Some(stamp) = Stamp::read(&mut file) else {
        let _ = Stamp {
            attempted: now,
            outcome: Collection::NotDue,
            complete_pairs: 0,
        }
        .write(&mut file);
        return Collection::NotDue;
    };
    if !matches!(store.try_packed_for_maintenance(), Ok(true)) {
        return Collection::NotDue;
    }
    let Ok((sweep, pairs)) = store.plan_pack_leftovers(now, DEFAULT_GRACE_SECS) else {
        return Collection::NotDue;
    };
    if cancelled() {
        return Collection::NotDue;
    }
    let due = stamp.due(now, pairs);
    let collection = match sweep.run_with(store, gc, packed, || Ok(())) {
        Ok(true) if due => {
            let clock = Budget {
                start: Instant::now(),
                limit: budget,
                cancelled,
            };
            collect(layout, store, &clock, before_collection_locks, gc, packed).unwrap_or_else(
                |error| match error {
                    GcRootsError::Io(error) | GcRootsError::Store(StoreError::Io(error))
                        if error.kind() == io::ErrorKind::TimedOut =>
                    {
                        Collection::OverBudget
                    }
                    _ => Collection::Failed,
                },
            )
        }
        Ok(false) if due => Collection::Busy,
        Err(_) if due => Collection::Failed,
        _ => return Collection::NotDue,
    };
    let _ = Stamp {
        attempted: now,
        outcome: collection,
        complete_pairs: if collection == Collection::Complete {
            pairs.saturating_sub(packed.packs_retired) as u64
        } else {
            stamp.complete_pairs
        },
    }
    .write(&mut file);
    collection
}

struct Budget<'a> {
    start: Instant,
    limit: Duration,
    cancelled: &'a dyn Fn() -> bool,
}

impl Budget<'_> {
    fn check(&self) -> io::Result<()> {
        self.check_cancellation()?;
        check_deadline(self.start, self.limit)
    }

    fn check_cancellation(&self) -> io::Result<()> {
        if (self.cancelled)() {
            return Err(io::Error::new(io::ErrorKind::Interrupted, INTERRUPTED));
        }
        Ok(())
    }
}

fn check_deadline(start: Instant, limit: Duration) -> io::Result<()> {
    if start.elapsed() >= limit {
        return Err(io::Error::new(io::ErrorKind::TimedOut, DEADLINE));
    }
    Ok(())
}

fn collect(
    layout: &RepoLayout,
    store: &ObjectStore,
    budget: &Budget<'_>,
    before_locks: impl FnOnce(),
    gc: &mut GcReport,
    packed: &mut PackedGcReport,
) -> Result<Collection, GcRootsError> {
    let now = now_secs();
    budget.check()?;
    let (hard, mut soft) = collect_root_sets(layout, &mut |_| {})?;
    soft.sort_unstable();
    let mut roots = hard.clone();
    roots.extend(soft.iter().map(|root| root.hash));
    let (start, limit) = (budget.start, budget.limit);
    // Walk all roots together. A missing soft closure stops the attempt as
    // a missing hard closure does. Only manual gc classifies stale roots.
    let live = mark_live_checked(
        store,
        &roots,
        MarkLimits::DEFAULT,
        &mut |_, _, _| {},
        &|| Ok(budget.check()?),
        &|| Ok(check_deadline(start, limit)?),
    )?;
    let retire = store.plan_pack_retirement(&live, now, DEFAULT_GRACE_SECS, packed, &|| {
        Ok(budget.check()?)
    })?;
    budget.check()?;
    if !packed.skipped_pack_errors.is_empty() {
        return Ok(Collection::Failed);
    }
    if retire.is_empty() {
        return Ok(Collection::Complete);
    }

    before_locks();
    budget.check_cancellation()?;
    let acquire_lock = |dir, name| match acquire(dir, name, Duration::ZERO) {
        Ok(lock) => Ok(Some(lock)),
        Err(LockError::Busy(_)) => Ok(None),
        Err(error) => Err(io::Error::other(error)),
    };
    let Some(_registry) = acquire_lock(layout.common_dir(), WORKTREES_REGISTRY_LOCK)? else {
        return Ok(Collection::Busy);
    };
    let trees = all_state_layouts(layout)?;
    let mut locks = Vec::with_capacity(trees.len());
    for tree in &trees {
        let Some(lock) = acquire_lock(tree.worktree_state_dir(), WORKTREE_LOCK)? else {
            return Ok(Collection::Busy);
        };
        locks.push(lock);
    }
    let (locked_hard, mut locked_soft) = collect_root_sets(layout, &mut |_| {})?;
    locked_soft.sort_unstable();
    if (hard, soft) != (locked_hard, locked_soft) {
        return Ok(Collection::RootsChanged);
    }
    budget.check_cancellation()?;
    Ok(if retire.run_with(store, gc, packed, || Ok(()))? {
        Collection::Complete
    } else {
        Collection::Busy
    })
}

#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_maintenance_stamp(bytes: &[u8]) {
    if let Ok(input) = bytes.try_into()
        && let Some(stamp) = Stamp::decode(input)
    {
        assert_eq!(&stamp.encode(), input);
    }
}

#[cfg(test)]
thread_local! {
    static TEST_NOW: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
mod tests;

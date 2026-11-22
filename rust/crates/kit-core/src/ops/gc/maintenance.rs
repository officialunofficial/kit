//! Best-effort local pack maintenance after a fetch has published its refs.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::{
    AUTO_MAINTENANCE_STAMP, DEFAULT_GRACE_SECS, GcReport, GcRootsError, LiveSet, MarkLimits,
    collect_root_sets, mark_live_checked, reject_symlink,
};
use crate::layout::{RepoLayout, all_state_layouts};
use crate::repo_lock::{LockError, WORKTREE_LOCK, WORKTREES_REGISTRY_LOCK, acquire};
use crate::store::{ObjectStore, PackSweep, StoreError, Verify};

const MIN_PAIRS: usize = 32;
/// Set in the pair count of a `progress` stamp written by an attempt that ran
/// out of time and retired nothing, so that the next such attempt waits 30
/// days. The pair count is read on a `complete` stamp and the mark bit on a
/// `progress` stamp, so this adds no field and no byte to the stamp. The mark
/// counts only while its stamp is under a day old, so a miss now and a miss
/// weeks later are not two in a row.
const MISSED: u64 = 1 << 63;
const BUDGET: Duration = Duration::from_secs(5);
const HOUR: u64 = 3600;
const DAY: u64 = 24 * HOUR;

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
    /// The mark, plan, verification or copy ran out of time before publish.
    /// An attempt that ran out of time and retired nothing is stamped
    /// `progress` the first time, so it is due again in an hour, and waits
    /// 30 days when the attempt after it ran out of time too.
    OverBudget,
    /// The step retired or copied what its limits allowed and left planned
    /// work for the next step, which is due in an hour and ignores the
    /// 32-pack floor.
    Progress,
    /// The attempt stopped on unreadable state, damage or interruption, or a
    /// copy failed with an I/O error after the wholly dead retirement
    /// finished.
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
            Self::Progress => "progress",
            Self::Failed => "failed",
        }
    }

    const fn interval(self) -> u64 {
        match self {
            Self::Busy | Self::RootsChanged | Self::Progress => HOUR,
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
    /// Pairs rewritten, their survivors copied into a new pack.
    pub packs_rewritten: usize,
    /// Small pairs merged into a new pack.
    pub packs_merged: usize,
    /// Pairs retired with no copy, because pairs that stay hold every live
    /// entry.
    pub packs_retired_covered: usize,
    /// Payload bytes copied into the new pack.
    pub bytes_copied: u64,
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
    /// The stamp of a step that has never run: due as soon as the floor is.
    const NEVER: Self = Self {
        attempted: 0,
        outcome: Collection::Complete,
        complete_pairs: 0,
    };

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
            7 => Collection::Progress,
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
            Collection::Progress => 7,
        };
        bytes[9..].copy_from_slice(&self.complete_pairs.to_le_bytes());
        bytes
    }

    fn write(self, file: &mut File) -> io::Result<()> {
        // Never truncate first: a failed write leaves a torn stamp, which is
        // rewritten and stops the step, and not an empty one, which means the
        // step has never run.
        file.rewind()?;
        file.write_all(&self.encode())?;
        file.set_len(17)
    }

    /// A step that left planned work is due again whatever the pair count: a
    /// store can fall under the floor with garbage still planned, and the
    /// step that made progress is the proof that the next one will too. A
    /// `complete` step is also due again once the store holds the floor's
    /// worth of pairs more than it left, so a repository that never fetches
    /// does not wait a week while its small packs build up.
    fn due(self, now: u64, pairs: usize) -> bool {
        (pairs >= MIN_PAIRS || self.outcome == Collection::Progress)
            && (now < self.attempted
                || now - self.attempted >= self.outcome.interval()
                || (self.outcome == Collection::Complete
                    && pairs as u64
                        >= (self.complete_pairs & !MISSED).saturating_add(MIN_PAIRS as u64)))
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
    #[cfg(not(unix))]
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

/// Sweep old pack leftovers and, when due, retire wholly dead local packs
/// and copy-then-retire the rest, at most one output pack per step.
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

/// [`maintain_packs`] for a command that writes objects, such as a commit.
///
/// A repository that has never run the step and holds fewer pairs than the
/// floor gets no stamp file and no sweep: its `.kit` layout is unchanged and
/// the step costs one listing of the pack directory. The first step runs once
/// the store holds the floor, or after any fetch has created the stamp.
#[doc(hidden)]
#[must_use]
pub fn maintain_packs_after_write(
    layout: &RepoLayout,
    store: &ObjectStore,
    cancelled: &dyn Fn() -> bool,
) -> MaintenanceReport {
    let unstamped = matches!(
        std::fs::symlink_metadata(layout.common_dir().join(AUTO_MAINTENANCE_STAMP)),
        Err(error) if error.kind() == io::ErrorKind::NotFound
    );
    if unstamped
        && !store
            .plan_pack_leftovers(now_secs(), DEFAULT_GRACE_SECS)
            .is_ok_and(|(_, pairs)| pairs >= MIN_PAIRS)
    {
        return MaintenanceReport::default();
    }
    maintain_packs(layout, store, cancelled)
}

fn maintain_with(
    layout: &RepoLayout,
    store: &ObjectStore,
    cancelled: &dyn Fn() -> bool,
    budget: Duration,
    before_collection_locks: impl FnOnce(),
) -> MaintenanceReport {
    let start = Instant::now();
    let mut gc_report = GcReport::default();
    let collection = run(
        layout,
        store,
        cancelled,
        budget,
        before_collection_locks,
        &mut gc_report,
    );
    MaintenanceReport {
        leftovers_removed: gc_report.pack_leftovers_pruned,
        packs_retired: gc_report.packs_retired,
        packs_rewritten: gc_report.packs_rewritten,
        packs_merged: gc_report.packs_merged,
        packs_retired_covered: gc_report.packs_retired_covered,
        bytes_copied: gc_report.survivor_bytes_copied,
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
    let stamp = match Stamp::read(&mut file) {
        Some(stamp) => stamp,
        // A step that has never run is due once the store holds the floor,
        // so a repository that never fetches is maintained too.
        None if file.metadata().is_ok_and(|meta| meta.len() == 0) => Stamp::NEVER,
        None => {
            let _ = Stamp {
                attempted: now,
                outcome: Collection::NotDue,
                complete_pairs: 0,
            }
            .write(&mut file);
            return Collection::NotDue;
        }
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
    let mut collection = match sweep.run_with(store, gc, || Ok(())) {
        Ok(true) if due => {
            let clock = Budget {
                start: Instant::now(),
                limit: budget,
                cancelled,
            };
            collect(layout, store, &clock, before_collection_locks, gc).unwrap_or_else(|error| {
                let outcome = match error {
                    GcRootsError::Io(error) | GcRootsError::Store(StoreError::Io(error))
                        if error.kind() == io::ErrorKind::TimedOut =>
                    {
                        Collection::OverBudget
                    }
                    _ => Collection::Failed,
                };
                Outcome::same(outcome)
            })
        }
        Ok(false) if due => Outcome::same(Collection::Busy),
        Err(_) if due => Outcome::same(Collection::Failed),
        _ => return Collection::NotDue,
    };
    // A step that left planned work, and retired or rewrote something, is
    // due again in an hour whatever the pair count. A step that did nothing
    // keeps its own interval, so the work cannot loop.
    let progressed =
        gc.packs_retired + gc.packs_rewritten + gc.packs_merged + gc.packs_retired_covered > 0;
    if collection.left
        && progressed
        && collection.stamped == Collection::Complete
        && matches!(
            collection.reported,
            Collection::Complete | Collection::OverBudget
        )
    {
        collection.reported = Collection::Progress;
        collection.stamped = Collection::Progress;
    }
    // A lock miss or changed roots after a step of progress keeps the work in
    // view: the retry is due in the same hour and still ignores the floor.
    if matches!(
        collection.stamped,
        Collection::Busy | Collection::RootsChanged
    ) && stamp.outcome == Collection::Progress
    {
        collection.stamped = Collection::Progress;
    }
    let marked = bound_misses(stamp, now, &mut collection.stamped, progressed);
    let _ = Stamp {
        attempted: now,
        outcome: collection.stamped,
        complete_pairs: if collection.stamped == Collection::Complete {
            (pairs + gc.packs_written).saturating_sub(
                gc.packs_retired + gc.packs_rewritten + gc.packs_merged + gc.packs_retired_covered,
            ) as u64
        } else if marked {
            (stamp.complete_pairs & !MISSED) + MISSED
        } else {
            stamp.complete_pairs & !MISSED
        },
    }
    .write(&mut file);
    collection.reported
}

/// An attempt that ran out of time and retired nothing may have met a busy
/// disk, so it is due again in an hour; the attempt after it that runs out of
/// time too keeps the 30 days, so a store that cannot be marked in the budget
/// does not pay it every hour. Returns whether the new stamp carries the mark
/// of such a miss: a lock miss or changed roots that restamped `progress`
/// with nothing retired keeps it, and a step that retired anything clears it.
/// A mark on a stamp more than a day old is ignored, so only two misses within
/// a day wait 30 days; a clock that moved back reads as recent.
fn bound_misses(prior: Stamp, now: u64, stamped: &mut Collection, progressed: bool) -> bool {
    let marked = prior.outcome == Collection::Progress
        && prior.complete_pairs & MISSED != 0
        && now.saturating_sub(prior.attempted) <= DAY;
    if *stamped == Collection::OverBudget && !marked {
        *stamped = Collection::Progress;
        return true;
    }
    *stamped == Collection::Progress && !progressed && marked
}

/// What a collection reports and what the stamp records. They differ only
/// when the copy was cut short, by the budget or an I/O error, but wholly dead
/// retirement finished: the report says `over_budget` or `failed`, and the
/// stamp keeps the weekly interval of a finished collection, so the
/// retirement main would do is not postponed.
struct Outcome {
    reported: Collection,
    stamped: Collection,
    /// The step left planned work for the next one: wholly dead packs it did
    /// not verify in time, or copy inputs that one output pack could not hold.
    left: bool,
}

impl Outcome {
    const fn same(collection: Collection) -> Self {
        Self {
            reported: collection,
            stamped: collection,
            left: false,
        }
    }

    /// The retirement of the wholly dead packs finished, with the copy done
    /// or deferred. A deferral is reported as it happened; the stamp keeps
    /// the weekly interval of a finished collection either way, because a
    /// step that does less than the one before the copy existed would be a
    /// regression.
    const fn finished(deferred: Option<Collection>, left: bool) -> Self {
        Self {
            reported: match deferred {
                Some(reason) => reason,
                None => Collection::Complete,
            },
            stamped: Collection::Complete,
            left,
        }
    }
}

/// How a deferred copy is reported: a timeout is the budget, any other I/O
/// error, such as a full disk, a failure.
fn deferral(kind: Option<io::ErrorKind>) -> Option<Collection> {
    kind.map(|kind| {
        if kind == io::ErrorKind::TimedOut {
            Collection::OverBudget
        } else {
            Collection::Failed
        }
    })
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
    #[cfg(test)]
    if TEST_CLOCK_OUT.get() {
        return Err(io::Error::new(io::ErrorKind::TimedOut, DEADLINE));
    }
    if start.elapsed() >= limit {
        return Err(io::Error::new(io::ErrorKind::TimedOut, DEADLINE));
    }
    Ok(())
}

/// Plan the wholly dead retirement. The budget bounds the verification of
/// those packs, oldest first, by stopping before the next pack and never
/// inside one. What was verified by then still retires, so each step makes
/// progress on a large dead set, including a step whose clock ends inside
/// its last pack: the later phases check the clock again and defer only
/// their own part.
fn plan_retirement(
    store: &ObjectStore,
    budget: &Budget<'_>,
    live: &LiveSet,
    now: u64,
    gc: &mut GcReport,
) -> Result<PackSweep, GcRootsError> {
    let room = || {
        #[cfg(test)]
        if let Some(left) = TEST_VERIFY_ROOM.get() {
            TEST_VERIFY_ROOM.set(Some(left.saturating_sub(1)));
            return left > 0;
        }
        budget.check().is_ok()
    };
    let scan = || Ok(budget.check_cancellation()?);
    let retire = store.plan_pack_retirement_within(
        live,
        now,
        DEFAULT_GRACE_SECS,
        gc,
        &|| Ok(budget.check()?),
        &Verify {
            room: &room,
            scan: &scan,
        },
    )?;
    #[cfg(test)]
    if TEST_PLAN_ENDS_CLOCK.get() {
        TEST_CLOCK_OUT.set(true);
    }
    if retire.verification_cut_short() || retire.planned_packs() > 0 {
        budget.check_cancellation()?;
    } else {
        budget.check()?;
    }
    Ok(retire)
}

fn collect(
    layout: &RepoLayout,
    store: &ObjectStore,
    budget: &Budget<'_>,
    before_locks: impl FnOnce(),
    gc: &mut GcReport,
) -> Result<Outcome, GcRootsError> {
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
    let mut retire = plan_retirement(store, budget, &live, now, gc)?;
    let cut = retire.verification_cut_short();
    if !gc.skipped_pack_errors.is_empty() {
        return Ok(Outcome::same(Collection::Failed));
    }
    if cut && retire.planned_packs() == 0 {
        // The budget ended before one pack was verified: no progress.
        return Ok(Outcome::same(Collection::OverBudget));
    }
    // Copy-then-retire is the added part of the step. A budget that runs out
    // in its planning, verification or copy defers only that part: the
    // wholly dead retirement planned above still runs, as it does today.
    // Cancellation and every other error still stop the step.
    // A verification that was cut short has used the whole budget, so the
    // copy waits for the next step.
    let mut deferred = if cut {
        Some(Collection::OverBudget)
    } else {
        let planned = retire.plan_automatic_copy(store, &live, now, DEFAULT_GRACE_SECS, &|| {
            #[cfg(test)]
            if TEST_COPY_EXPIRES.get() == Some(CopyPhase::Plan) {
                return Err(io::Error::new(io::ErrorKind::TimedOut, DEADLINE).into());
            }
            Ok(budget.check()?)
        });
        deferral(retire.defer_copy_on_io_error(planned)?)
    };
    if retire.is_empty() {
        return Ok(Outcome::finished(deferred, false));
    }

    // Copying reads pack bodies, so it runs before any worktree lock: the
    // step holds only the shared guard, and only inside the copy. Damage or
    // a failed coverage check stops the step with nothing published. The
    // budget ends the copy before it publishes; once published, the outputs
    // are harmless duplicates that the next step retires as covered, so the
    // retirement below is not on the clock.
    let mut copied = None;
    if deferred.is_none() {
        let checkpoint = || {
            #[cfg(test)]
            match TEST_COPY_EXPIRES.get() {
                Some(CopyPhase::Copy) => {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, DEADLINE).into());
                }
                Some(CopyPhase::DiskFull) => {
                    return Err(io::Error::from(io::ErrorKind::StorageFull).into());
                }
                Some(CopyPhase::Interrupt) => {
                    return Err(io::Error::new(io::ErrorKind::Interrupted, INTERRUPTED).into());
                }
                _ => {}
            }
            Ok(budget.check()?)
        };
        match retire.copy_survivors(store, gc, &checkpoint, true) {
            Ok(done) => copied = done,
            Err(error) => deferred = deferral(retire.defer_copy_on_io_error(Err(error))?),
        }
        if !gc.skipped_pack_errors.is_empty() {
            return Ok(Outcome::same(Collection::Failed));
        }
        if deferred.is_some() && retire.is_empty() {
            return Ok(Outcome::finished(deferred, false));
        }
    }

    before_locks();
    budget.check_cancellation()?;
    let acquire_lock = |dir, name| match acquire(dir, name, Duration::ZERO) {
        Ok(lock) => Ok(Some(lock)),
        Err(LockError::Busy(_)) => Ok(None),
        Err(error) => Err(io::Error::other(error)),
    };
    let Some(_registry) = acquire_lock(layout.common_dir(), WORKTREES_REGISTRY_LOCK)? else {
        return Ok(Outcome::same(Collection::Busy));
    };
    let trees = all_state_layouts(layout)?;
    let mut locks = Vec::with_capacity(trees.len());
    for tree in &trees {
        let Some(lock) = acquire_lock(tree.worktree_state_dir(), WORKTREE_LOCK)? else {
            return Ok(Outcome::same(Collection::Busy));
        };
        locks.push(lock);
    }
    let (locked_hard, mut locked_soft) = collect_root_sets(layout, &mut |_| {})?;
    locked_soft.sort_unstable();
    if (hard, soft) != (locked_hard, locked_soft) {
        return Ok(Outcome::same(Collection::RootsChanged));
    }
    budget.check_cancellation()?;
    let left = cut || retire.copy_left_inputs();
    Ok(if retire.retire(store, gc, copied.as_ref(), || Ok(()))? {
        Outcome::finished(deferred, left)
    } else {
        Outcome::same(Collection::Busy)
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

/// Where a test makes the copy part run out of budget or fail, after the
/// wholly dead plan.
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum CopyPhase {
    Plan,
    Copy,
    DiskFull,
    Interrupt,
}

#[cfg(test)]
thread_local! {
    static TEST_NOW: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
    static TEST_COPY_EXPIRES: std::cell::Cell<Option<CopyPhase>> =
        const { std::cell::Cell::new(None) };
    /// How many wholly dead packs verification may still start before the
    /// budget ends, in place of the clock.
    static TEST_VERIFY_ROOM: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    /// The clock runs out as retirement planning ends.
    static TEST_PLAN_ENDS_CLOCK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// The clock has run out, whatever it says.
    static TEST_CLOCK_OUT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
mod tests;

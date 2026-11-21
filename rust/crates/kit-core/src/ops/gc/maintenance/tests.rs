use std::fs;

use crate::hash::Hash;
use crate::object::{Blob, Object};
use crate::refs::{RefWriteCondition, update_tag};
use crate::serialize::serialize;
use crate::store::LocalPackWriter;

use super::*;

struct Repo {
    _dir: tempfile::TempDir,
    layout: RepoLayout,
    store: ObjectStore,
}

impl Repo {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        let store = ObjectStore::init(&layout).unwrap();
        store.try_activate_local_packs().unwrap();
        crate::refs::init(&layout).unwrap();
        let repo = Self {
            _dir: dir,
            layout,
            store,
        };
        assert_eq!(repo.run().collection, Collection::NotDue);
        repo
    }

    fn run(&self) -> MaintenanceReport {
        maintain_packs(&self.layout, &self.store, &|| false)
    }

    fn pack_count(&self) -> usize {
        fs::read_dir(self.pack_dir())
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .unwrap()
                    .path()
                    .extension()
                    .is_some_and(|ext| ext == "pack")
            })
            .count()
    }

    fn pack_dir(&self) -> std::path::PathBuf {
        self.store.objects_root().join("pack")
    }

    fn pack(&self, objects: &[&[u8]]) -> (std::path::PathBuf, Vec<Hash>) {
        fs::create_dir_all(self.pack_dir()).unwrap();
        let pack_paths = || {
            fs::read_dir(self.pack_dir())
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "pack"))
                .collect::<std::collections::BTreeSet<_>>()
        };
        let before = pack_paths();
        let guard = self.store.prune_guard().unwrap();
        let mut writer = LocalPackWriter::new(&self.store, &guard).unwrap();
        let ids = objects
            .iter()
            .map(|data| {
                writer
                    .write(
                        &serialize(&Object::Blob(Blob {
                            data: data.to_vec(),
                        }))
                        .unwrap(),
                    )
                    .unwrap()
            })
            .collect();
        writer.publish().unwrap();
        let path = pack_paths().difference(&before).next().unwrap().clone();
        (path, ids)
    }

    fn due(&self) {
        for n in 0..MIN_PAIRS {
            self.pack(&[format!("young {n}").as_bytes()]);
        }
        let mut file = lock_stamp(self.layout.common_dir()).unwrap();
        Stamp {
            attempted: 1,
            outcome: Collection::Complete,
            complete_pairs: 10,
        }
        .write(&mut file)
        .unwrap();
    }

    /// A due repository whose small packs each hold one live object.
    fn due_live(&self) -> Vec<Hash> {
        let ids: Vec<Hash> = (0..MIN_PAIRS)
            .map(|n| {
                let (_, ids) = self.pack(&[format!("live {n}").as_bytes()]);
                self.pin(&format!("live{n}"), &ids[0]);
                ids[0]
            })
            .collect();
        let mut file = lock_stamp(self.layout.common_dir()).unwrap();
        Stamp {
            attempted: 1,
            outcome: Collection::Complete,
            complete_pairs: 10,
        }
        .write(&mut file)
        .unwrap();
        ids
    }

    /// Staging files in the pack directory: what an abandoned copy leaves.
    fn staging(&self) -> usize {
        fs::read_dir(self.pack_dir())
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains(".tmp")
            })
            .count()
    }

    fn leftover(&self, nonce: u8, age: u64) -> std::path::PathBuf {
        let path = self.pack_dir().join(format!(".{nonce:032x}.tmp.pack"));
        fs::create_dir_all(self.pack_dir()).unwrap();
        fs::write(&path, b"staged").unwrap();
        age_file(&path, age);
        path
    }

    fn old_pack(&self, contents: &[&[u8]]) -> (std::path::PathBuf, Vec<Hash>) {
        let (path, ids) = self.pack(contents);
        age_file(&path, DEFAULT_GRACE_SECS + 86_400);
        (path, ids)
    }

    fn pin(&self, tag: &str, id: &Hash) {
        update_tag(&self.layout, tag, RefWriteCondition::Any, id).unwrap();
    }
}

fn age_file(path: &Path, age: u64) {
    File::open(path)
        .unwrap()
        .set_modified(UNIX_EPOCH + Duration::from_secs(now_secs() - age))
        .unwrap();
}

#[test]
fn sweep_keeps_young_files_and_yields_to_a_publisher() {
    TEST_NOW.set(Some(now_secs()));
    let fourteen_days = 1_209_600;
    let repo = Repo::new();
    let old = repo.leftover(1, fourteen_days);
    let old_index = repo.pack_dir().join(format!("{:064x}.idx", 7));
    fs::write(&old_index, b"orphan").unwrap();
    age_file(&old_index, fourteen_days + 86_400);
    let young = repo.leftover(2, fourteen_days - 1);
    let guard = repo.store.prune_guard().unwrap();
    let blocked = repo.run();
    assert_eq!(blocked.collection, Collection::NotDue);
    assert_eq!(blocked.leftovers_removed, 0);
    assert!(old.exists());
    drop(guard);
    crate::atomic::testing::reset_dir_sync_calls();
    let report = repo.run();
    assert_eq!(report.leftovers_removed, 2);
    assert_eq!(report.bytes_reclaimed, 12);
    assert_eq!(crate::atomic::testing::dir_sync_calls(), 2);
    assert!(!old.exists());
    assert!(!old_index.exists());
    assert!(young.exists());
    eprintln!(
        "sweep hold {:.3} ms",
        ObjectStore::last_sweep_hold().as_secs_f64() * 1000.0
    );
}

#[test]
fn collection_retires_wholly_dead_packs_and_copies_the_rest_past_grace() {
    TEST_NOW.set(Some(now_secs()));
    let repo = Repo::new();
    repo.due();
    let (dead, _) = repo.old_pack(&[b"dead"]);
    let (live, live_ids) = repo.old_pack(&[b"live"]);
    let (mixed, mixed_ids) = repo.old_pack(&[b"kept", b"dead mixed"]);
    let (young, _) = repo.pack(&[b"almost old enough"]);
    age_file(&young, DEFAULT_GRACE_SECS - 1);
    repo.pin("live", &live_ids[0]);
    repo.pin("mixed", &mixed_ids[0]);

    let report = repo.run();
    assert_eq!(report.collection, Collection::Complete);
    assert_eq!(report.packs_retired, 1);
    assert!(!dead.exists() && !dead.with_extension("idx").exists());
    // The mixed pack is rewritten without its dead entry; the live pack and
    // every small young pack are merged. Nothing unreachable inside grace goes.
    assert_eq!(report.packs_rewritten, 1);
    assert_eq!(report.packs_merged, MIN_PAIRS + 2);
    for path in [&live, &mixed, &young] {
        assert!(!path.exists() && !path.with_extension("idx").exists());
    }
    assert!(report.bytes_copied > 0);
    assert!(repo.store.read(&live_ids[0]).is_ok());
    assert!(repo.store.read(&mixed_ids[0]).is_ok());
    assert!(repo.store.read(&mixed_ids[1]).is_err());
    assert_eq!(repo.pack_count(), 1, "one output holds everything kept");

    let mut file = lock_stamp(repo.layout.common_dir()).unwrap();
    let stamp = Stamp::read(&mut file).unwrap();
    assert_eq!(stamp.complete_pairs, 1);
}

#[test]
fn busy_worktree_retries_in_an_hour() {
    let repo = Repo::new();
    repo.due();
    let (dead, ids) = repo.old_pack(&[b"owned by an in-flight writer"]);
    let lock = acquire(
        repo.layout.worktree_state_dir(),
        WORKTREE_LOCK,
        Duration::ZERO,
    )
    .unwrap();
    assert!(repo.store.read(&ids[0]).is_ok());
    let report = repo.run();
    assert_eq!(report.collection, Collection::Busy);
    assert_eq!(report.packs_retired, 0);
    assert!(dead.exists());
    drop(lock);
    let mut file = lock_stamp(repo.layout.common_dir()).unwrap();
    let stamp = Stamp::read(&mut file).unwrap();
    assert!(!stamp.due(stamp.attempted + HOUR - 1, MIN_PAIRS));
    assert!(stamp.due(stamp.attempted + HOUR, MIN_PAIRS));
}

#[test]
fn a_root_published_after_the_mark_keeps_the_pair() {
    let repo = Repo::new();
    repo.due();
    let (dead, ids) = repo.old_pack(&[b"becomes live"]);
    let report = maintain_with(&repo.layout, &repo.store, &|| false, BUDGET, || {
        let _lock = acquire(
            repo.layout.worktree_state_dir(),
            WORKTREE_LOCK,
            Duration::ZERO,
        )
        .unwrap();
        repo.pin("root", &ids[0]);
    });
    assert_eq!(report.collection, Collection::RootsChanged);
    assert!(dead.exists());
    assert!(repo.store.read(&ids[0]).is_ok());
}

#[test]
fn equivalent_roots_allow_retirement_after_a_ref_changes_back() {
    let repo = Repo::new();
    repo.due();
    let (dead, ids) = repo.old_pack(&[b"briefly live"]);
    let report = maintain_with(&repo.layout, &repo.store, &|| false, BUDGET, || {
        let _lock = acquire(
            repo.layout.worktree_state_dir(),
            WORKTREE_LOCK,
            Duration::ZERO,
        )
        .unwrap();
        repo.pin("root", &ids[0]);
        fs::remove_file(repo.layout.common_dir().join("refs/tags/root")).unwrap();
    });
    assert_eq!(report.collection, Collection::Complete);
    assert!(!dead.exists());
}

#[test]
fn an_expired_budget_backs_off_without_retiring_a_pair() {
    let repo = Repo::new();
    repo.due();
    let (dead, _) = repo.old_pack(&[b"dead"]);
    let report = maintain_with(&repo.layout, &repo.store, &|| false, Duration::ZERO, || {
        panic!("an expired mark must not reach the locks");
    });
    assert_eq!(report.collection, Collection::OverBudget);
    assert_eq!(repo.run().collection, Collection::NotDue);
    let mut file = lock_stamp(repo.layout.common_dir()).unwrap();
    let stamp = Stamp::read(&mut file).unwrap();
    let interval = 30 * 24 * HOUR;
    assert!(!stamp.due(stamp.attempted + interval - 1, MIN_PAIRS));
    assert!(stamp.due(stamp.attempted + interval, MIN_PAIRS));
    assert!(dead.exists());
}

#[test]
fn corrupted_index_stops_collection_and_preserves_the_completed_sweep() {
    let repo = Repo::new();
    repo.due();
    let (dead, _) = repo.old_pack(&[b"dead"]);
    let (bad, _) = repo.old_pack(&[b"bad"]);
    let index = bad.with_extension("idx");
    let mut bytes = fs::read(&index).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(&index, bytes).unwrap();
    let leftover = repo.leftover(1, DEFAULT_GRACE_SECS + 86_400);

    let report = repo.run();
    assert_eq!(report.collection, Collection::Failed);
    assert_eq!(report.leftovers_removed, 1);
    assert_eq!(report.packs_retired, 0);
    assert!(dead.exists() && bad.exists());
    assert!(!leftover.exists());
    assert!(
        super::super::run_gc(
            &repo.store,
            &repo.layout,
            now_secs(),
            DEFAULT_GRACE_SECS,
            true,
            &mut |_, _, _| {},
        )
        .is_err()
    );
}

#[test]
fn pack_refreshed_after_planning_survives_retirement() {
    let repo = Repo::new();
    repo.due();
    let (dead, _) = repo.old_pack(&[b"import reused this"]);
    let report = maintain_with(&repo.layout, &repo.store, &|| false, BUDGET, || {
        let _guard = repo.store.prune_guard().unwrap();
        age_file(&dead, 0);
    });
    assert_eq!(report.collection, Collection::Complete);
    assert_eq!(report.packs_retired, 0);
    assert!(dead.exists());
}

#[test]
fn a_second_step_leaves_the_stamp_and_leftovers_to_its_holder() {
    let repo = Repo::new();
    let old = repo.leftover(1, DEFAULT_GRACE_SECS + 86_400);
    let lock = lock_stamp(repo.layout.common_dir()).unwrap();
    assert_eq!(repo.run().leftovers_removed, 0);
    assert!(old.exists());
    drop(lock);
    assert_eq!(repo.run().leftovers_removed, 1);
}

#[test]
fn a_missing_soft_root_stops_collection() {
    let repo = Repo::new();
    repo.due();
    let (dead, _) = repo.old_pack(&[b"dead"]);
    let subject = repo.layout.attestations_dir().join(format!("{:064x}", 1));
    fs::create_dir_all(&subject).unwrap();
    fs::write(subject.join(format!("{:064x}.dsse", 2)), []).unwrap();
    assert_eq!(repo.run().collection, Collection::Failed);
    assert!(dead.exists());
}

#[test]
fn interruption_after_planning_preserves_the_pair() {
    let repo = Repo::new();
    repo.due();
    let (dead, _) = repo.old_pack(&[b"dead"]);
    let interrupted = std::cell::Cell::new(false);
    let report = maintain_with(
        &repo.layout,
        &repo.store,
        &|| interrupted.get(),
        BUDGET,
        || interrupted.set(true),
    );
    assert_eq!(report.collection, Collection::Failed);
    assert!(dead.exists());
}

#[test]
fn corrupt_pack_body_stops_retirement_of_other_candidates() {
    let repo = Repo::new();
    repo.due();
    let (dead, _) = repo.old_pack(&[b"intact dead pack"]);
    let (bad, _) = repo.old_pack(&[b"damaged body"]);
    let mut bytes = fs::read(&bad).unwrap();
    let position = bytes
        .windows(b"damaged body".len())
        .position(|window| window == b"damaged body")
        .unwrap();
    bytes[position] ^= 1;
    fs::write(&bad, bytes).unwrap();
    age_file(&bad, DEFAULT_GRACE_SECS + 86_400);

    assert_eq!(repo.run().collection, Collection::Failed);
    assert!(dead.exists());
    assert!(bad.exists());
}

#[test]
fn a_soft_root_published_after_the_mark_keeps_the_pair() {
    let repo = Repo::new();
    repo.due();
    let (dead, ids) = repo.old_pack(&[b"becomes attested"]);
    let report = maintain_with(&repo.layout, &repo.store, &|| false, BUDGET, || {
        let _lock = acquire(
            repo.layout.worktree_state_dir(),
            WORKTREE_LOCK,
            Duration::ZERO,
        )
        .unwrap();
        let root = repo
            .layout
            .attestations_dir()
            .join(crate::hash::to_hex(&ids[0]));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join(format!("{:064x}.dsse", 1)), []).unwrap();
    });
    assert_eq!(report.collection, Collection::RootsChanged);
    assert!(dead.exists());
    assert!(repo.store.read(&ids[0]).is_ok());
}

#[test]
fn an_old_stamp_does_not_lower_the_collection_floor() {
    let repo = Repo::new();
    let (dead, _) = repo.old_pack(&[b"dead below collection floor"]);
    let mut file = lock_stamp(repo.layout.common_dir()).unwrap();
    Stamp {
        attempted: 1,
        outcome: Collection::Complete,
        complete_pairs: MIN_PAIRS as u64,
    }
    .write(&mut file)
    .unwrap();
    drop(file);

    assert_eq!(repo.run().collection, Collection::NotDue);
    assert!(dead.exists());
}

#[test]
fn a_store_from_another_repository_cannot_be_swept() {
    let roots = Repo::new();
    let objects = Repo::new();
    let old = objects.leftover(1, DEFAULT_GRACE_SECS + 86_400);

    let report = maintain_packs(&roots.layout, &objects.store, &|| false);
    assert_eq!(report.leftovers_removed, 0);
    assert!(old.exists());
}

#[cfg(unix)]
#[test]
fn a_symlinked_store_cannot_be_swept() {
    let repo = Repo::new();
    let old = repo.leftover(1, DEFAULT_GRACE_SECS + 86_400);
    let external = repo.layout.worktree_root().join("external");
    fs::rename(repo.store.objects_root(), &external).unwrap();
    std::os::unix::fs::symlink(&external, repo.store.objects_root()).unwrap();

    assert_eq!(repo.run().leftovers_removed, 0);
    assert!(old.exists());
}

#[cfg(unix)]
#[test]
fn a_hard_link_to_the_stamp_is_never_rewritten() {
    let repo = Repo::new();
    let stamp = repo.layout.common_dir().join(AUTO_MAINTENANCE_STAMP);
    let target = repo.layout.worktree_root().join("outside-stamp");
    fs::remove_file(&stamp).unwrap();
    fs::write(&target, b"keep").unwrap();
    fs::hard_link(&target, &stamp).unwrap();

    assert_eq!(repo.run().collection, Collection::NotDue);
    assert_eq!(fs::read(target).unwrap(), b"keep");
}

#[test]
fn a_due_collection_backs_off_when_the_orphan_sweep_cannot_lock() {
    let repo = Repo::new();
    repo.due();
    let old = repo.leftover(1, DEFAULT_GRACE_SECS + 86_400);
    let (dead, _) = repo.old_pack(&[b"dead during a busy sweep"]);
    let _publisher = repo.store.prune_guard().unwrap();

    let report = repo.run();
    assert_eq!(report.collection, Collection::Busy);
    assert_eq!(report.leftovers_removed, 0);
    assert_eq!(report.packs_retired, 0);
    assert!(old.exists() && dead.exists());
}

#[test]
fn a_publisher_holding_the_format_lock_keeps_the_retirement_waiting() {
    let repo = Repo::new();
    repo.due();
    let _publisher = repo.store.prune_guard().unwrap();

    // The small pairs are merged: the copy runs under the shared guard, the
    // exclusive try then fails, and the inputs stay beside the output.
    let report = repo.run();
    assert_eq!(report.collection, Collection::Busy);
    assert_eq!(report.leftovers_removed, 0);
    assert_eq!(report.packs_retired, 0);
    assert_eq!(report.packs_merged, 0);
    assert!(report.bytes_copied > 0);
    assert_eq!(repo.pack_count(), MIN_PAIRS + 1);
}

#[test]
fn an_io_failure_in_the_sweep_stops_an_attempt_before_collection() {
    for (due, expected) in [(false, Collection::NotDue), (true, Collection::Failed)] {
        let repo = Repo::new();
        if due {
            repo.due();
        }
        let old = repo.leftover(1, DEFAULT_GRACE_SECS + 86_400);
        let marker = repo.layout.common_dir().join("format");
        let planning = std::cell::Cell::new(true);
        let report = maintain_packs(&repo.layout, &repo.store, &|| {
            if !planning.replace(false) {
                // The sweep will fail to open the format lock after planning.
                fs::remove_file(&marker).unwrap();
            }
            false
        });

        assert_eq!(report.collection, expected);
        assert_eq!(report.leftovers_removed, 0);
        assert!(old.exists());
    }
}

#[cfg(unix)]
#[test]
fn a_symlink_in_place_of_the_stamp_is_never_followed() {
    let repo = Repo::new();
    let old = repo.leftover(1, DEFAULT_GRACE_SECS + 86_400);
    let stamp = repo.layout.common_dir().join(AUTO_MAINTENANCE_STAMP);
    let target = repo.layout.worktree_root().join("outside-stamp");
    fs::remove_file(&stamp).unwrap();
    fs::write(&target, b"keep").unwrap();
    std::os::unix::fs::symlink(&target, &stamp).unwrap();

    assert_eq!(repo.run().collection, Collection::NotDue);
    assert_eq!(fs::read(target).unwrap(), b"keep");
    assert!(old.exists());
}

#[test]
fn cancellation_before_the_sweep_keeps_the_old_leftover() {
    let repo = Repo::new();
    let old = repo.leftover(1, DEFAULT_GRACE_SECS + 86_400);

    let report = maintain_packs(&repo.layout, &repo.store, &|| true);
    assert_eq!(report.collection, Collection::NotDue);
    assert_eq!(report.leftovers_removed, 0);
    assert!(old.exists());
}

#[test]
fn a_torn_stamp_only_creates_a_new_stamp_and_stops() {
    let repo = Repo::new();
    let old = repo.leftover(1, DEFAULT_GRACE_SECS + 86_400);
    let stamp = repo.layout.common_dir().join(AUTO_MAINTENANCE_STAMP);
    let mut bytes = fs::read(&stamp).unwrap();
    bytes.push(0);
    fs::write(stamp, bytes).unwrap();

    assert_eq!(repo.run().leftovers_removed, 0);
    assert!(old.exists());
    assert_eq!(repo.run().leftovers_removed, 1);
    assert!(!old.exists());
}

#[test]
fn a_loose_only_repository_keeps_files_named_like_pack_leftovers() {
    let dir = tempfile::tempdir().unwrap();
    let layout = RepoLayout::single(dir.path());
    let store = ObjectStore::init_loose(&layout).unwrap();
    let repo = Repo {
        _dir: dir,
        layout,
        store,
    };
    let _ = repo.run();
    let old = repo.leftover(1, DEFAULT_GRACE_SECS + 86_400);

    assert_eq!(repo.run().leftovers_removed, 0);
    assert!(old.exists());
}

#[test]
fn stamp_intervals_and_report_names_match_the_collection_outcomes() {
    for (outcome, interval, name) in [
        (Collection::NotDue, 7 * 24 * HOUR, "not_due"),
        (Collection::Complete, 7 * 24 * HOUR, "complete"),
        (Collection::Busy, HOUR, "busy"),
        (Collection::RootsChanged, HOUR, "roots_changed"),
        (Collection::OverBudget, 30 * 24 * HOUR, "over_budget"),
        (Collection::Failed, 7 * 24 * HOUR, "failed"),
    ] {
        let stamp = Stamp {
            attempted: 100,
            outcome,
            complete_pairs: 0,
        };
        assert_eq!(outcome.as_str(), name);
        assert!(!stamp.due(stamp.attempted + interval - 1, MIN_PAIRS));
        assert!(stamp.due(stamp.attempted + interval, MIN_PAIRS));
        assert!(!stamp.due(stamp.attempted, MIN_PAIRS));
        assert!(stamp.due(stamp.attempted - 1, MIN_PAIRS));
        assert_eq!(Stamp::decode(&stamp.encode()).unwrap().outcome, outcome);
    }
}

#[test]
fn a_budget_that_ends_before_the_copy_publishes_nothing() {
    TEST_NOW.set(Some(now_secs()));
    let repo = Repo::new();
    repo.due();
    let before = repo.pack_count();
    let report = maintain_with(&repo.layout, &repo.store, &|| false, Duration::ZERO, || {
        panic!("an expired step must not reach the locks");
    });
    assert_eq!(report.collection, Collection::OverBudget);
    assert_eq!(report.bytes_copied, 0);
    assert_eq!(repo.pack_count(), before);
    assert_eq!(repo.staging(), 0);
}

/// A budget that ends in the copy part defers only that part: the wholly
/// dead packs still retire, as before the copy existed, and the report says
/// `over_budget` while the stamp keeps the weekly interval of a finished run.
fn a_copy_that_runs_out_of_budget_still_retires_the_wholly_dead(phase: CopyPhase) {
    TEST_NOW.set(Some(now_secs()));
    TEST_COPY_EXPIRES.set(Some(phase));
    let repo = Repo::new();
    let ids = repo.due_live();
    let (dead_a, _) = repo.old_pack(&[b"dead a"]);
    let (dead_b, _) = repo.old_pack(&[b"dead b"]);
    let (mixed, mixed_ids) = repo.old_pack(&[b"kept", b"dead mixed"]);
    repo.pin("mixed", &mixed_ids[0]);
    let before = repo.pack_count();

    let report = repo.run();
    TEST_COPY_EXPIRES.set(None);
    assert_eq!(report.collection, Collection::OverBudget);
    assert_eq!(report.packs_retired, 2);
    assert!(!dead_a.exists() && !dead_b.exists());
    // Only the copy part waits: the mixed pack and the small packs stay.
    assert_eq!(report.packs_rewritten + report.packs_merged, 0);
    assert_eq!(report.bytes_copied, 0);
    assert!(mixed.exists());
    assert_eq!(repo.pack_count(), before - 2);
    assert_eq!(repo.staging(), 0);
    for id in ids.iter().chain(&mixed_ids[..1]) {
        assert!(repo.store.read(id).is_ok());
    }
    let mut file = lock_stamp(repo.layout.common_dir()).unwrap();
    let stamp = Stamp::read(&mut file).unwrap();
    assert_eq!(stamp.outcome, Collection::Complete);

    // The next due step, with the budget back, does the copy.
    age_file(&mixed, DEFAULT_GRACE_SECS + 1);
    Stamp {
        attempted: 1,
        outcome: Collection::Complete,
        complete_pairs: 10,
    }
    .write(&mut file)
    .unwrap();
    let next = repo.run();
    assert_eq!(next.collection, Collection::Complete);
    assert!(next.bytes_copied > 0);
}

#[test]
fn a_copy_plan_that_runs_out_of_budget_still_retires_the_wholly_dead() {
    a_copy_that_runs_out_of_budget_still_retires_the_wholly_dead(CopyPhase::Plan);
}

#[test]
fn a_copy_that_runs_out_of_budget_after_planning_still_retires_the_wholly_dead() {
    a_copy_that_runs_out_of_budget_still_retires_the_wholly_dead(CopyPhase::Copy);
}

#[test]
fn a_budget_that_ends_with_nothing_wholly_dead_reports_over_budget_for_30_days() {
    TEST_NOW.set(Some(now_secs()));
    TEST_COPY_EXPIRES.set(Some(CopyPhase::Plan));
    let repo = Repo::new();
    repo.due_live();
    let before = repo.pack_count();
    let report = repo.run();
    TEST_COPY_EXPIRES.set(None);
    assert_eq!(report.collection, Collection::OverBudget);
    assert_eq!(repo.pack_count(), before);
    let mut file = lock_stamp(repo.layout.common_dir()).unwrap();
    assert_eq!(
        Stamp::read(&mut file).unwrap().outcome,
        Collection::OverBudget
    );
}

#[test]
fn a_stop_at_any_checkpoint_leaves_nothing_half_done() {
    use std::cell::Cell;

    for stop_after in [
        0,
        1,
        2,
        5,
        10,
        20,
        40,
        80,
        120,
        160,
        200,
        260,
        340,
        460,
        usize::MAX,
    ] {
        TEST_NOW.set(Some(now_secs()));
        let repo = Repo::new();
        let ids = repo.due_live();
        let before = repo.pack_count();
        let calls = Cell::new(0_usize);
        let report = maintain_with(
            &repo.layout,
            &repo.store,
            &|| {
                calls.set(calls.get() + 1);
                calls.get() > stop_after
            },
            BUDGET,
            || {},
        );
        // Either nothing was published, or one output was and no input went.
        let after = repo.pack_count();
        match report.collection {
            Collection::Complete => assert_eq!(after, 1, "stop_after {stop_after}"),
            _ => assert!(
                after == before || after == before + 1,
                "stop_after {stop_after}: {before} -> {after}"
            ),
        }
        assert_eq!(repo.staging(), 0, "stop_after {stop_after}");
        for id in &ids {
            assert!(repo.store.read(id).is_ok(), "stop_after {stop_after}");
        }
    }
}

#[test]
fn a_busy_worktree_after_the_copy_leaves_duplicates_that_the_next_step_retires_as_covered() {
    TEST_NOW.set(Some(now_secs()));
    let repo = Repo::new();
    let ids = repo.due_live();
    let lock = acquire(
        repo.layout.worktree_state_dir(),
        WORKTREE_LOCK,
        Duration::ZERO,
    )
    .unwrap();
    let report = repo.run();
    assert_eq!(report.collection, Collection::Busy);
    assert_eq!(report.packs_merged, 0, "nothing retired under a busy lock");
    assert!(report.bytes_copied > 0);
    assert_eq!(
        repo.pack_count(),
        MIN_PAIRS + 1,
        "the output stays beside its inputs"
    );
    drop(lock);

    TEST_NOW.set(Some(now_secs() + HOUR + 1));
    let report = repo.run();
    assert_eq!(report.collection, Collection::Complete);
    assert_eq!(report.packs_retired_covered, MIN_PAIRS);
    assert_eq!(
        report.bytes_copied, 0,
        "the output already holds every entry"
    );
    assert_eq!(repo.pack_count(), 1);
    for id in &ids {
        assert!(repo.store.read(id).is_ok());
    }
}

#[test]
fn a_commit_in_flight_makes_the_step_miss_and_retire_nothing() {
    TEST_NOW.set(Some(now_secs()));
    let repo = Repo::new();
    repo.due_live();
    let _commit = acquire(
        repo.layout.worktree_state_dir(),
        WORKTREE_LOCK,
        Duration::ZERO,
    )
    .unwrap();
    let report = repo.run();
    assert_eq!(report.collection, Collection::Busy);
    assert_eq!(
        report.packs_retired + report.packs_merged + report.packs_retired_covered,
        0
    );
}

#[test]
fn a_damaged_input_frame_stops_collection_and_retires_nothing() {
    use std::io::{Seek, SeekFrom, Write};

    TEST_NOW.set(Some(now_secs()));
    let repo = Repo::new();
    repo.due();
    let (dead, _) = repo.old_pack(&[b"dead"]);
    let (mixed, ids) = repo.old_pack(&[b"kept", b"dead mixed"]);
    repo.pin("mixed", &ids[0]);
    // Flip a payload byte of the first frame, the live one, keeping the age.
    let mut file = fs::OpenOptions::new().write(true).open(&mixed).unwrap();
    file.seek(SeekFrom::Start(
        (crate::pack::HEADER_LEN + crate::pack::ENTRY_FRAME_LEN + 7) as u64,
    ))
    .unwrap();
    file.write_all(&[0xff]).unwrap();
    drop(file);
    age_file(&mixed, DEFAULT_GRACE_SECS + 86_400);
    let before = repo.pack_count();

    let report = repo.run();
    assert_eq!(report.collection, Collection::Failed);
    assert_eq!(
        report.packs_retired + report.packs_rewritten + report.packs_merged,
        0
    );
    assert_eq!(report.bytes_copied, 0);
    assert!(dead.exists() && mixed.exists());
    assert_eq!(repo.pack_count(), before, "nothing was published");
    assert_eq!(repo.staging(), 0);
}

#[test]
fn roots_that_change_after_the_copy_retire_nothing() {
    TEST_NOW.set(Some(now_secs()));
    let repo = Repo::new();
    repo.due_live();
    let (_, ids) = repo.old_pack(&[b"becomes live"]);
    let report = maintain_with(&repo.layout, &repo.store, &|| false, BUDGET, || {
        let _lock = acquire(
            repo.layout.worktree_state_dir(),
            WORKTREE_LOCK,
            Duration::ZERO,
        )
        .unwrap();
        repo.pin("root", &ids[0]);
    });
    assert_eq!(report.collection, Collection::RootsChanged);
    assert_eq!(
        report.packs_retired + report.packs_merged + report.packs_retired_covered,
        0
    );
    assert!(report.bytes_copied > 0);
    assert!(repo.store.read(&ids[0]).is_ok());
}

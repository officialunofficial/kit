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
    crate::durable::testing::reset_dir_sync_calls();
    let report = repo.run();
    assert_eq!(report.leftovers_removed, 2);
    assert_eq!(report.bytes_reclaimed, 12);
    assert_eq!(crate::durable::testing::dir_sync_calls(), 2);
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
    TEST_NOW.set(Some(now_secs()));
    let repo = Repo::new();
    repo.due();
    let (dead, _) = repo.old_pack(&[b"dead"]);
    let expired = |repo: &Repo| {
        maintain_with(&repo.layout, &repo.store, &|| false, Duration::ZERO, || {
            panic!("an expired mark must not reach the locks");
        })
    };
    // The first attempt may have met a busy disk: it is due in an hour.
    assert_eq!(expired(&repo).collection, Collection::OverBudget);
    assert_eq!(repo.run().collection, Collection::NotDue);
    let stamp = stamp_of(&repo);
    assert_eq!(stamp.outcome, Collection::Progress);
    assert!(!stamp.due(stamp.attempted + HOUR - 1, MIN_PAIRS));
    assert!(stamp.due(stamp.attempted + HOUR, 3));
    // The attempt after it that runs out of time too waits 30 days.
    TEST_NOW.set(Some(TEST_NOW.get().unwrap() + HOUR + 1));
    assert_eq!(expired(&repo).collection, Collection::OverBudget);
    let stamp = stamp_of(&repo);
    assert_eq!(stamp.outcome, Collection::OverBudget);
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

/// A stamp that cannot be read must cost one more attempt, not a week of
/// waiting: a torn stamp can only cause a new attempt.
#[test]
fn an_unreadable_stamp_does_not_postpone_the_next_collection() {
    let repo = Repo::new();
    for n in 0..MIN_PAIRS {
        repo.pack(&[format!("young {n}").as_bytes()]);
    }
    let stamp = repo.layout.common_dir().join(AUTO_MAINTENANCE_STAMP);
    fs::write(&stamp, [7; 5]).unwrap();

    assert_eq!(repo.run().collection, Collection::NotDue);
    assert_ne!(
        repo.run().collection,
        Collection::NotDue,
        "a store at the floor is due again after a torn stamp is replaced"
    );
}

/// A step that has never run is due as soon as the store holds the floor, so
/// a repository that never fetches does not wait a week for its first step.
#[test]
fn a_step_that_has_never_run_is_due_at_the_floor() {
    let repo = Repo::new();
    let stamp = repo.layout.common_dir().join(AUTO_MAINTENANCE_STAMP);
    for n in 0..MIN_PAIRS - 1 {
        repo.pack(&[format!("young {n}").as_bytes()]);
    }
    assert_eq!(repo.run().collection, Collection::NotDue);
    assert_eq!(
        fs::metadata(&stamp).unwrap().len(),
        0,
        "nothing was stamped"
    );

    repo.pack(&[b"the last pair"]);
    assert_eq!(repo.run().collection, Collection::Complete);
    assert_eq!(stamp_of(&repo).outcome, Collection::Complete);
    assert_eq!(repo.run().collection, Collection::NotDue, "then it waits");
}

/// A command that writes objects leaves a repository that never ran the step
/// as it is until the store holds the floor: no stamp file, no sweep.
#[test]
fn a_write_command_leaves_an_unstamped_repository_alone_under_the_floor() {
    let repo = Repo::new();
    let stamp = repo.layout.common_dir().join(AUTO_MAINTENANCE_STAMP);
    fs::remove_file(&stamp).unwrap();
    let old = repo.leftover(1, DEFAULT_GRACE_SECS + 86_400);
    for n in 0..MIN_PAIRS - 1 {
        repo.pack(&[format!("young {n}").as_bytes()]);
    }
    let run = || maintain_packs_after_write(&repo.layout, &repo.store, &|| false);
    assert_eq!(run(), MaintenanceReport::default());
    assert!(!stamp.exists() && old.exists());

    repo.pack(&[b"the last pair"]);
    assert_eq!(run().collection, Collection::Complete);
    assert!(!old.exists());
    assert_eq!(stamp_of(&repo).outcome, Collection::Complete);

    // With a stamp, the step is the one a fetch runs: it sweeps under the floor.
    let again = repo.leftover(2, DEFAULT_GRACE_SECS + 86_400);
    assert_eq!(run().leftovers_removed, 1);
    assert!(!again.exists());
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
        (Collection::Progress, HOUR, "progress"),
        (Collection::Failed, 7 * 24 * HOUR, "failed"),
    ] {
        // The pair count the stamp left equals the store's, so only the
        // interval is in play, not the pair-growth rule.
        let stamp = Stamp {
            attempted: 100,
            outcome,
            complete_pairs: MIN_PAIRS as u64,
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

/// A budget that ends in the copy part, or a copy that fails on a full disk,
/// defers only that part: the wholly dead packs still retire, as before the
/// copy existed. The report says `over_budget` or `failed`, and the stamp
/// keeps the weekly interval of a finished run.
fn a_copy_that_stops_still_retires_the_wholly_dead(phase: CopyPhase, expected: Collection) {
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
    assert_eq!(report.collection, expected);
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
    assert_eq!(stamp.complete_pairs, u64::try_from(before - 2).unwrap());

    // The next due step, with the budget back, does the copy.
    age_file(&mixed, DEFAULT_GRACE_SECS + 1);
    drop(file);
    let mut file = lock_stamp(repo.layout.common_dir()).unwrap();
    Stamp {
        attempted: 1,
        outcome: Collection::Complete,
        complete_pairs: 10,
    }
    .write(&mut file)
    .unwrap();
    drop(file);
    let next = repo.run();
    assert_eq!(next.collection, Collection::Complete);
    assert!(next.bytes_copied > 0);
}

#[test]
fn a_copy_plan_that_runs_out_of_budget_still_retires_the_wholly_dead() {
    a_copy_that_stops_still_retires_the_wholly_dead(CopyPhase::Plan, Collection::OverBudget);
}

#[test]
fn a_copy_that_runs_out_of_budget_after_planning_still_retires_the_wholly_dead() {
    a_copy_that_stops_still_retires_the_wholly_dead(CopyPhase::Copy, Collection::OverBudget);
}

#[test]
fn a_copy_that_fails_on_a_full_disk_still_retires_the_wholly_dead() {
    a_copy_that_stops_still_retires_the_wholly_dead(CopyPhase::DiskFull, Collection::Failed);
}

#[test]
fn a_budget_that_ends_with_nothing_wholly_dead_reports_over_budget_and_keeps_the_weekly_interval() {
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
        Collection::Complete
    );
}

#[test]
fn a_copy_that_runs_out_of_budget_with_nothing_wholly_dead_never_tries_the_locks() {
    TEST_NOW.set(Some(now_secs()));
    TEST_COPY_EXPIRES.set(Some(CopyPhase::Copy));
    let repo = Repo::new();
    repo.due_live();
    let before = repo.pack_count();
    let report = maintain_with(&repo.layout, &repo.store, &|| false, BUDGET, || {
        panic!("nothing is left to retire, so no lock is tried");
    });
    TEST_COPY_EXPIRES.set(None);
    assert_eq!(report.collection, Collection::OverBudget);
    assert_eq!(repo.pack_count(), before);
    assert_eq!(repo.staging(), 0);
    let mut file = lock_stamp(repo.layout.common_dir()).unwrap();
    assert_eq!(
        Stamp::read(&mut file).unwrap().outcome,
        Collection::Complete
    );
}

#[test]
fn an_interruption_in_the_copy_stops_the_step_and_is_not_deferred() {
    TEST_NOW.set(Some(now_secs()));
    TEST_COPY_EXPIRES.set(Some(CopyPhase::Interrupt));
    let repo = Repo::new();
    repo.due_live();
    let (dead, _) = repo.old_pack(&[b"dead"]);
    let before = repo.pack_count();
    let report = repo.run();
    TEST_COPY_EXPIRES.set(None);
    assert_eq!(report.collection, Collection::Failed);
    assert_eq!(report.packs_retired, 0);
    assert!(dead.exists());
    assert_eq!(repo.pack_count(), before);
    let mut file = lock_stamp(repo.layout.common_dir()).unwrap();
    assert_eq!(Stamp::read(&mut file).unwrap().outcome, Collection::Failed);
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

fn stamp_of(repo: &Repo) -> Stamp {
    let mut file = lock_stamp(repo.layout.common_dir()).unwrap();
    Stamp::read(&mut file).unwrap()
}

fn step_later(repo: &Repo) -> MaintenanceReport {
    TEST_NOW.set(Some(TEST_NOW.get().unwrap() + HOUR + 1));
    repo.run()
}

/// A step whose verification ends before every wholly dead pack is checked
/// retires the oldest ones it did check, stamps progress, and the next step
/// is due in an hour and takes the rest.
#[test]
fn a_step_that_runs_out_of_time_retires_what_it_verified_oldest_first() {
    TEST_NOW.set(Some(now_secs()));
    let repo = Repo::new();
    let ids = repo.due_live();
    let dead: Vec<_> = (0..5)
        .map(|n| {
            let (path, _) = repo.old_pack(&[format!("dead {n}").as_bytes()]);
            // Packs 0 and 1 are the youngest, 4 the oldest.
            age_file(&path, DEFAULT_GRACE_SECS + 86_400 * (n + 1));
            path
        })
        .collect();
    let before = repo.pack_count();

    TEST_VERIFY_ROOM.set(Some(2));
    let first = repo.run();
    TEST_VERIFY_ROOM.set(None);
    assert_eq!(first.collection, Collection::Progress);
    assert_eq!(first.packs_retired, 2);
    assert!(
        !dead[4].exists() && !dead[3].exists(),
        "the oldest go first"
    );
    assert!(dead[..3].iter().all(|path| path.exists()));
    assert_eq!(repo.pack_count(), before - 2);
    let stamp = stamp_of(&repo);
    assert_eq!(stamp.outcome, Collection::Progress);
    assert!(!stamp.due(stamp.attempted + HOUR - 1, 3));
    assert!(
        stamp.due(stamp.attempted + HOUR, 3),
        "the pair floor does not apply"
    );
    assert_eq!(repo.run().collection, Collection::NotDue, "not due yet");

    TEST_VERIFY_ROOM.set(Some(2));
    let second = step_later(&repo);
    TEST_VERIFY_ROOM.set(None);
    assert_eq!(
        (second.collection, second.packs_retired),
        (Collection::Progress, 2)
    );
    let third = step_later(&repo);
    assert_eq!(
        (third.collection, third.packs_retired),
        (Collection::Complete, 1)
    );
    assert!(dead.iter().all(|path| !path.exists()));
    assert_eq!(stamp_of(&repo).outcome, Collection::Complete);
    for id in &ids {
        assert!(repo.store.read(id).is_ok());
    }
}

/// With no time to verify one pack, nothing is retired: a busy disk is not a
/// reason to wait 30 days. The step reports the budget, stamps progress and is
/// due again in an hour, under the floor.
#[test]
fn a_step_that_verifies_no_pack_is_due_again_in_an_hour() {
    TEST_NOW.set(Some(now_secs()));
    let repo = Repo::new();
    repo.due();
    let (dead, _) = repo.old_pack(&[b"dead"]);
    TEST_VERIFY_ROOM.set(Some(0));
    let report = repo.run();
    TEST_VERIFY_ROOM.set(None);
    assert_eq!(report.collection, Collection::OverBudget);
    assert_eq!(report.packs_retired, 0);
    assert!(dead.exists());
    let stamp = stamp_of(&repo);
    assert_eq!(stamp.outcome, Collection::Progress);
    assert!(!stamp.due(stamp.attempted + HOUR - 1, 3));
    assert!(stamp.due(stamp.attempted + HOUR, 3));
    assert_eq!(repo.run().collection, Collection::NotDue, "not due yet");

    let next = step_later(&repo);
    assert_eq!(next.packs_retired, 1);
    assert!(!dead.exists());
    assert_eq!(stamp_of(&repo).outcome, Collection::Complete);
}

/// The attempt that runs out of time again right after one that did keeps the
/// 30 days, so a store that cannot be marked in the budget pays 5 seconds once,
/// not every hour; a step that retired something clears the mark.
#[test]
fn two_attempts_in_a_row_that_run_out_of_time_wait_30_days() {
    TEST_NOW.set(Some(now_secs()));
    let repo = Repo::new();
    repo.due_live();
    let dead: Vec<_> = (0..2)
        .map(|n| {
            let (path, _) = repo.old_pack(&[format!("dead {n}").as_bytes()]);
            age_file(&path, DEFAULT_GRACE_SECS + 86_400 * (n + 1));
            path
        })
        .collect();
    // A step of progress, then a miss, then a miss, then room again.
    TEST_VERIFY_ROOM.set(Some(1));
    assert_eq!(repo.run().collection, Collection::Progress);
    assert_eq!(stamp_of(&repo).complete_pairs & MISSED, 0);

    TEST_VERIFY_ROOM.set(Some(0));
    let first = step_later(&repo);
    assert_eq!(first.collection, Collection::OverBudget);
    let stamp = stamp_of(&repo);
    assert_eq!(stamp.outcome, Collection::Progress, "an hour, not 30 days");
    assert_ne!(stamp.complete_pairs & MISSED, 0);

    TEST_VERIFY_ROOM.set(Some(0));
    let second = step_later(&repo);
    assert_eq!(second.collection, Collection::OverBudget);
    let stamp = stamp_of(&repo);
    assert_eq!(stamp.outcome, Collection::OverBudget);
    assert_eq!(stamp.complete_pairs & MISSED, 0);
    TEST_VERIFY_ROOM.set(None);
    assert_eq!(dead.iter().filter(|path| path.exists()).count(), 1);

    // Thirty days later it takes the rest and finishes.
    TEST_NOW.set(Some(TEST_NOW.get().unwrap() + 30 * 24 * HOUR));
    let last = repo.run();
    assert_eq!(
        (last.collection, last.packs_retired),
        (Collection::Complete, 1)
    );
    assert!(dead.iter().all(|path| !path.exists()));
}

/// The mark has an age: a miss that comes more than a day after the one that
/// left it is a first miss again, due in an hour, and not a second in a row.
#[test]
fn a_miss_more_than_a_day_after_the_last_is_due_in_an_hour_again() {
    TEST_NOW.set(Some(now_secs()));
    let repo = Repo::new();
    repo.due_live();
    repo.old_pack(&[b"dead"]);
    TEST_VERIFY_ROOM.set(Some(0));
    assert_eq!(repo.run().collection, Collection::OverBudget);
    let stamp = stamp_of(&repo);
    assert_eq!(stamp.outcome, Collection::Progress);
    assert_ne!(stamp.complete_pairs & MISSED, 0);

    // A day and an hour later: the mark is stale, so this is a first miss.
    TEST_NOW.set(Some(TEST_NOW.get().unwrap() + DAY + HOUR));
    assert_eq!(repo.run().collection, Collection::OverBudget);
    let stamp = stamp_of(&repo);
    assert_eq!(stamp.outcome, Collection::Progress, "an hour, not 30 days");
    assert_ne!(stamp.complete_pairs & MISSED, 0, "marked afresh");
    assert!(stamp.due(stamp.attempted + HOUR, 3));

    // Within the day, the next miss waits 30 days as before.
    assert_eq!(step_later(&repo).collection, Collection::OverBudget);
    TEST_VERIFY_ROOM.set(None);
    assert_eq!(stamp_of(&repo).outcome, Collection::OverBudget);
}

/// The mark stands for exactly a day: a miss that comes a day after the last
/// waits 30 days, and one a second later is a first miss again.
#[test]
fn the_miss_mark_stands_for_exactly_a_day() {
    for (gap, outcome) in [
        (86_400, Collection::OverBudget),
        (86_401, Collection::Progress),
    ] {
        TEST_NOW.set(Some(now_secs()));
        let repo = Repo::new();
        repo.due_live();
        repo.old_pack(&[b"dead"]);
        TEST_VERIFY_ROOM.set(Some(0));
        assert_eq!(repo.run().collection, Collection::OverBudget);
        assert_ne!(stamp_of(&repo).complete_pairs & MISSED, 0);
        TEST_NOW.set(Some(TEST_NOW.get().unwrap() + gap));
        assert_eq!(repo.run().collection, Collection::OverBudget);
        TEST_VERIFY_ROOM.set(None);
        assert_eq!(stamp_of(&repo).outcome, outcome, "a gap of {gap} seconds");
    }
}

/// A step that retires something after a miss clears the mark, so a later miss
/// within the day is a first miss again.
#[test]
fn a_step_that_retires_after_a_miss_clears_the_mark() {
    TEST_NOW.set(Some(now_secs()));
    let repo = Repo::new();
    repo.due_live();
    let dead: Vec<_> = (0..2)
        .map(|n| repo.old_pack(&[format!("dead {n}").as_bytes()]).0)
        .collect();
    TEST_VERIFY_ROOM.set(Some(0));
    assert_eq!(repo.run().collection, Collection::OverBudget);
    assert_ne!(stamp_of(&repo).complete_pairs & MISSED, 0);

    TEST_VERIFY_ROOM.set(Some(1));
    assert_eq!(step_later(&repo).collection, Collection::Progress);
    assert_eq!(stamp_of(&repo).complete_pairs & MISSED, 0);
    assert_eq!(dead.iter().filter(|path| path.exists()).count(), 1);

    TEST_VERIFY_ROOM.set(Some(0));
    assert_eq!(step_later(&repo).collection, Collection::OverBudget);
    TEST_VERIFY_ROOM.set(None);
    assert_eq!(
        stamp_of(&repo).outcome,
        Collection::Progress,
        "a first miss"
    );
}

/// A lock miss that comes more than a day after a miss does not carry the
/// stale mark forward.
#[test]
fn a_lock_miss_a_day_after_a_miss_drops_the_stale_mark() {
    TEST_NOW.set(Some(now_secs()));
    let repo = Repo::new();
    repo.due_live();
    repo.old_pack(&[b"dead"]);
    TEST_VERIFY_ROOM.set(Some(0));
    assert_eq!(repo.run().collection, Collection::OverBudget);
    TEST_VERIFY_ROOM.set(None);
    assert_ne!(stamp_of(&repo).complete_pairs & MISSED, 0);

    let lock = acquire(
        repo.layout.worktree_state_dir(),
        WORKTREE_LOCK,
        Duration::ZERO,
    )
    .unwrap();
    TEST_NOW.set(Some(TEST_NOW.get().unwrap() + DAY + HOUR));
    assert_eq!(repo.run().collection, Collection::Busy);
    drop(lock);
    let stamp = stamp_of(&repo);
    assert_eq!(stamp.outcome, Collection::Progress);
    assert_eq!(stamp.complete_pairs & MISSED, 0);
}

/// A clock that ends as planning finishes, with no wholly dead pack planned,
/// is a miss like any other: nothing was verified, so the first one is due in
/// an hour and not stamped as a finished collection.
#[test]
fn a_clock_that_ends_as_planning_finishes_with_nothing_planned_is_a_miss() {
    TEST_NOW.set(Some(now_secs()));
    let repo = Repo::new();
    repo.due();
    TEST_PLAN_ENDS_CLOCK.set(true);
    let report = repo.run();
    TEST_PLAN_ENDS_CLOCK.set(false);
    TEST_CLOCK_OUT.set(false);
    assert_eq!(report.collection, Collection::OverBudget, "{report:?}");
    assert_eq!(report.packs_merged, 0);
    let stamp = stamp_of(&repo);
    assert_eq!(stamp.outcome, Collection::Progress);
    assert_ne!(stamp.complete_pairs & MISSED, 0);
}

/// A clock that ends inside the last wholly dead pack keeps every pack that
/// was verified: the later phases defer only their own part.
#[test]
fn a_clock_that_ends_inside_the_last_pack_keeps_the_verified_packs() {
    TEST_NOW.set(Some(now_secs()));
    let repo = Repo::new();
    let ids = repo.due_live();
    let dead: Vec<_> = (0..3)
        .map(|n| {
            let (path, _) = repo.old_pack(&[format!("dead {n}").as_bytes()]);
            age_file(&path, DEFAULT_GRACE_SECS + 86_400 * (n + 1));
            path
        })
        .collect();
    // Room for all three; the clock ends while the last one is verified.
    TEST_VERIFY_ROOM.set(Some(3));
    let report = maintain_with(
        &repo.layout,
        &repo.store,
        &|| {
            if TEST_VERIFY_ROOM.get() == Some(0) {
                TEST_CLOCK_OUT.set(true);
            }
            false
        },
        BUDGET,
        || {},
    );
    TEST_VERIFY_ROOM.set(None);
    TEST_CLOCK_OUT.set(false);
    assert_eq!(report.packs_retired, 3, "{report:?}");
    assert_eq!(report.collection, Collection::OverBudget, "the copy waited");
    assert!(dead.iter().all(|path| !path.exists()));
    // Everything wholly dead is gone: the weekly interval of a finished
    // collection, not an hour and not 30 days.
    assert_eq!(stamp_of(&repo).outcome, Collection::Complete);
    for id in &ids {
        assert!(repo.store.read(id).is_ok());
    }
}

/// Every step on a large dead set that retires at least one pack leaves the
/// store closer to the manual gc state: the set empties in a bounded number
/// of steps.
#[test]
fn a_large_dead_set_empties_in_a_bounded_number_of_steps() {
    TEST_NOW.set(Some(now_secs()));
    let repo = Repo::new();
    repo.due_live();
    let dead: Vec<_> = (0..40)
        .map(|n| {
            let (path, _) = repo.old_pack(&[format!("dead {n}").as_bytes()]);
            age_file(&path, DEFAULT_GRACE_SECS + 86_400 * (n + 1));
            path
        })
        .collect();

    let mut steps = 0;
    loop {
        TEST_VERIFY_ROOM.set(Some(7));
        let report = if steps == 0 {
            repo.run()
        } else {
            step_later(&repo)
        };
        TEST_VERIFY_ROOM.set(None);
        steps += 1;
        assert!(steps <= 6, "40 packs at 7 a step take 6 steps");
        if report.collection != Collection::Progress {
            assert_eq!(report.collection, Collection::Complete);
            break;
        }
        assert_eq!(report.packs_retired, 7, "every step makes progress");
    }
    assert!(dead.iter().all(|path| !path.exists()));
}

/// A step whose one output could not hold every input leaves work: it is due
/// again in an hour, under the pair floor, until the inputs are done.
#[test]
fn a_copy_capped_to_one_output_leaves_work_and_runs_again_under_the_floor() {
    TEST_NOW.set(Some(now_secs()));
    crate::store::set_test_output_entries(Some(8));
    let repo = Repo::new();
    let ids = repo.due_live();
    let before = repo.pack_count();

    let first = repo.run();
    assert_eq!(first.collection, Collection::Progress);
    assert_eq!(first.packs_merged, 8);
    assert!(
        repo.pack_count() < MIN_PAIRS,
        "{before} -> {}",
        repo.pack_count()
    );
    assert_eq!(stamp_of(&repo).outcome, Collection::Progress);

    let mut steps = 1;
    loop {
        let report = step_later(&repo);
        steps += 1;
        assert!(steps <= 6, "bounded: each step merges 8 of 32");
        if report.collection == Collection::Complete {
            break;
        }
        assert_eq!(report.collection, Collection::Progress);
        assert!(report.packs_merged > 0);
    }
    crate::store::set_test_output_entries(None);
    for id in &ids {
        assert!(repo.store.read(id).is_ok());
    }
}

/// A step that has left work but retired nothing keeps the interval of its
/// own outcome: a refresh of every verified pack cannot make the step loop
/// every hour.
#[test]
fn a_step_that_retires_nothing_is_never_stamped_progress() {
    TEST_NOW.set(Some(now_secs()));
    let repo = Repo::new();
    repo.due();
    repo.old_pack(&[b"dead one"]);
    repo.old_pack(&[b"dead two"]);
    // Room for one of the two: verification is cut with one pack planned.
    TEST_VERIFY_ROOM.set(Some(1));
    let report = maintain_with(&repo.layout, &repo.store, &|| false, BUDGET, || {
        // A writer refreshes every pack before the locks, so the planned
        // pair fails its recheck and nothing retires.
        for entry in fs::read_dir(repo.pack_dir()).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|ext| ext == "pack") {
                File::open(&path)
                    .unwrap()
                    .set_modified(SystemTime::now())
                    .unwrap();
            }
        }
    });
    TEST_VERIFY_ROOM.set(None);
    assert_eq!(report.packs_retired, 0, "{report:?}");
    assert_eq!(report.collection, Collection::OverBudget, "{report:?}");
    assert_eq!(stamp_of(&repo).outcome, Collection::Complete);
}

/// A lock miss after a step of progress keeps the floor bypass: the store may
/// have fallen under 32 pairs with work still planned.
#[test]
fn a_lock_miss_after_progress_still_ignores_the_pair_floor() {
    TEST_NOW.set(Some(now_secs()));
    let repo = Repo::new();
    repo.due();
    for n in 0..2 {
        repo.old_pack(&[format!("dead {n}").as_bytes()]);
    }
    let mut file = lock_stamp(repo.layout.common_dir()).unwrap();
    Stamp {
        attempted: 1,
        outcome: Collection::Progress,
        complete_pairs: 0,
    }
    .write(&mut file)
    .unwrap();
    drop(file);
    let lock = acquire(
        repo.layout.worktree_state_dir(),
        WORKTREE_LOCK,
        Duration::ZERO,
    )
    .unwrap();
    let report = repo.run();
    assert_eq!(report.collection, Collection::Busy);
    drop(lock);
    let stamp = stamp_of(&repo);
    assert_eq!(stamp.outcome, Collection::Progress);
    assert!(stamp.due(stamp.attempted + HOUR, 3));
    assert_eq!(stamp.complete_pairs & MISSED, 0, "no miss to remember");
}

/// A lock miss between two attempts that ran out of time does not reset the
/// bound: the second one still waits 30 days.
#[test]
fn a_lock_miss_between_two_misses_keeps_the_bound() {
    TEST_NOW.set(Some(now_secs()));
    let repo = Repo::new();
    repo.due_live();
    repo.old_pack(&[b"dead"]);
    TEST_VERIFY_ROOM.set(Some(0));
    assert_eq!(repo.run().collection, Collection::OverBudget);
    TEST_VERIFY_ROOM.set(None);
    let stamp = stamp_of(&repo);
    assert_eq!(stamp.outcome, Collection::Progress);
    assert_ne!(stamp.complete_pairs & MISSED, 0);

    let lock = acquire(
        repo.layout.worktree_state_dir(),
        WORKTREE_LOCK,
        Duration::ZERO,
    )
    .unwrap();
    assert_eq!(step_later(&repo).collection, Collection::Busy);
    drop(lock);
    let stamp = stamp_of(&repo);
    assert_eq!(stamp.outcome, Collection::Progress);
    assert_ne!(stamp.complete_pairs & MISSED, 0, "the mark stands");

    TEST_VERIFY_ROOM.set(Some(0));
    assert_eq!(step_later(&repo).collection, Collection::OverBudget);
    TEST_VERIFY_ROOM.set(None);
    assert_eq!(stamp_of(&repo).outcome, Collection::OverBudget);
}

/// A cancellation during the verification of a pack stops the step with
/// nothing retired: it is not a deadline, so it never reads as progress.
#[test]
fn a_cancellation_while_a_dead_pack_is_verified_retires_nothing() {
    TEST_NOW.set(Some(now_secs()));
    let repo = Repo::new();
    repo.due();
    let dead: Vec<_> = (0..3)
        .map(|n| repo.old_pack(&[format!("dead {n}").as_bytes()]).0)
        .collect();
    TEST_VERIFY_ROOM.set(Some(5));
    // The first verification start moves the counter, and every check after
    // it is a cancellation.
    let report = maintain_with(
        &repo.layout,
        &repo.store,
        &|| TEST_VERIFY_ROOM.get() != Some(5),
        BUDGET,
        || panic!("a cancelled step must not reach the locks"),
    );
    TEST_VERIFY_ROOM.set(None);
    assert_eq!(report.collection, Collection::Failed, "{report:?}");
    assert_eq!(report.packs_retired, 0);
    assert!(dead.iter().all(|path| path.exists()));
    assert_eq!(stamp_of(&repo).outcome, Collection::Failed);
}

#[test]
fn the_progress_stamp_round_trips_and_an_unknown_one_is_unreadable() {
    let stamp = Stamp {
        attempted: 7,
        outcome: Collection::Progress,
        complete_pairs: 3,
    };
    assert_eq!(
        Stamp::decode(&stamp.encode()).unwrap().outcome,
        Collection::Progress
    );
    let mut bytes = stamp.encode();
    bytes[8] = 8;
    assert!(Stamp::decode(&bytes).is_none());
}

/// A `complete` stamp is due again once the store holds the floor's worth of
/// pairs more than it left; no other outcome gains that rule.
#[test]
fn only_a_complete_stamp_is_due_by_pair_growth() {
    for outcome in [
        Collection::Complete,
        Collection::NotDue,
        Collection::Failed,
        Collection::OverBudget,
    ] {
        let stamp = Stamp {
            attempted: 100,
            outcome,
            complete_pairs: 40,
        };
        let grown = 40 + MIN_PAIRS;
        assert!(!stamp.due(101, grown - 1));
        assert_eq!(
            stamp.due(101, grown),
            outcome == Collection::Complete,
            "{outcome:?}"
        );
        assert!(!stamp.due(101, 0));
    }
    // A stamp that stored no count is due at the floor, as a first step is.
    let stamp = Stamp {
        attempted: 100,
        outcome: Collection::Complete,
        complete_pairs: 0,
    };
    assert!(!stamp.due(101, MIN_PAIRS - 1));
    assert!(stamp.due(101, MIN_PAIRS));
}

/// A repository that never fetches: after the step merges its first small
/// packs, the 32nd new pair makes the next step due, not the next week.
#[test]
fn a_repository_that_never_fetches_merges_again_every_floor_of_new_pairs() {
    TEST_NOW.set(Some(now_secs()));
    let repo = Repo::new();
    for n in 0..MIN_PAIRS {
        repo.pack(&[format!("first {n}").as_bytes()]);
    }
    assert_eq!(repo.run().collection, Collection::Complete);
    for round in 0..2 {
        let left = stamp_of(&repo).complete_pairs;
        assert_eq!(
            left,
            repo.pack_count() as u64,
            "the stamp holds the count left"
        );
        assert!(left < MIN_PAIRS as u64, "the step merged the small packs");
        for n in 0..MIN_PAIRS - 1 {
            repo.pack(&[format!("round {round} pack {n}").as_bytes()]);
        }
        assert_eq!(
            repo.run().collection,
            Collection::NotDue,
            "31 new pairs wait"
        );
        repo.pack(&[format!("round {round} last").as_bytes()]);
        let report = repo.run();
        assert_eq!(report.collection, Collection::Complete);
        assert!(report.packs_merged >= MIN_PAIRS, "{report:?}");
    }
}

/// A complete step that could not shrink the store, here because its copy was
/// deferred, stores the pair count it left: it is not due again until the
/// store holds 32 more pairs, so it cannot run on every command.
#[test]
fn a_complete_step_that_merged_nothing_waits_for_32_more_pairs() {
    TEST_NOW.set(Some(now_secs()));
    let repo = Repo::new();
    for n in 0..MIN_PAIRS {
        repo.pack(&[format!("first {n}").as_bytes()]);
    }
    TEST_COPY_EXPIRES.set(Some(CopyPhase::Plan));
    let first = repo.run();
    TEST_COPY_EXPIRES.set(None);
    assert_eq!(first.collection, Collection::OverBudget, "{first:?}");
    assert_eq!(first.packs_merged, 0);
    assert_eq!(stamp_of(&repo).outcome, Collection::Complete);
    assert_eq!(stamp_of(&repo).complete_pairs, MIN_PAIRS as u64);
    assert_eq!(repo.run().collection, Collection::NotDue);
    for n in 0..MIN_PAIRS - 1 {
        repo.pack(&[format!("later {n}").as_bytes()]);
    }
    assert_eq!(repo.run().collection, Collection::NotDue);
    repo.pack(&[b"later last"]);
    assert_eq!(repo.run().collection, Collection::Complete);
}

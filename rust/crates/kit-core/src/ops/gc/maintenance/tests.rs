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
    let repo = Repo::new();
    let old = repo.leftover(1, DEFAULT_GRACE_SECS + 86_400);
    let old_index = repo.pack_dir().join(format!("{:064x}.idx", 7));
    fs::write(&old_index, b"orphan").unwrap();
    age_file(&old_index, DEFAULT_GRACE_SECS + 86_400);
    let young = repo.leftover(2, 0);
    let guard = repo.store.prune_guard().unwrap();
    assert_eq!(repo.run().leftovers_removed, 0);
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
fn collection_retires_only_wholly_dead_packs_past_grace() {
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
    for path in [live, mixed, young] {
        assert!(path.is_file() && path.with_extension("idx").is_file());
    }
    assert!(repo.store.read(&live_ids[0]).is_ok());
    assert!(repo.store.read(&mixed_ids[0]).is_ok());
}

#[test]
fn busy_worktree_retries_in_an_hour() {
    let repo = Repo::new();
    repo.due();
    let (dead, _) = repo.old_pack(&[b"owned by an in-flight writer"]);
    let lock = acquire(
        repo.layout.worktree_state_dir(),
        WORKTREE_LOCK,
        Duration::ZERO,
    )
    .unwrap();
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
            true
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

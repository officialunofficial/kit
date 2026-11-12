//! Linked working trees: add, list, remove and prune.
#![cfg(feature = "sync")]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

use std::fs;
use std::path::{Path, PathBuf};

use kit_core::hash::Hash;
use kit_core::layout::{self, RepoLayout};
use kit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use kit_core::refs::{self, Head};
use kit_core::serialize;
use kit_core::store::ObjectStore;
use libkit::linked::{self, Checkout, Entry, Error, Pruned};
use libkit::repo::StoreConfig;
use libkit::{Environment, NoopObserver};

struct Fixture {
    _dir: tempfile::TempDir,
    /// The canonical path of the temporary directory.
    base: PathBuf,
    layout: RepoLayout,
    tip: Hash,
    environment: Environment,
}

impl Fixture {
    fn config(&self) -> StoreConfig<'_> {
        StoreConfig {
            environment: &self.environment,
            observer: &NoopObserver,
        }
    }

    fn add(&self, path: &str, commit_ish: Option<&str>) -> Result<linked::Added, Error> {
        linked::add(
            &self.layout,
            &self.config(),
            &self.base,
            path,
            commit_ish,
            &NoopObserver,
        )
    }

    fn remove(&self, path: &str, force: bool) -> Result<(), Error> {
        linked::remove(
            &self.layout,
            &self.config(),
            &self.base,
            path,
            force,
            false,
            &NoopObserver,
        )
    }
}

fn write(store: &ObjectStore, object: &Object) -> Hash {
    store.write(&serialize::serialize(object).unwrap()).unwrap()
}

/// A repository `main` with one commit that holds `a.txt`.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().canonicalize().unwrap();
    let main = base.join("main");
    fs::create_dir(&main).unwrap();
    let layout = RepoLayout::single(&main);
    let store = ObjectStore::init(&layout).unwrap();
    refs::init(&layout).unwrap();
    let blob = write(
        &store,
        &Object::Blob(Blob {
            data: b"one\n".to_vec(),
        }),
    );
    let tree = write(
        &store,
        &Object::Tree(Tree {
            entries: vec![TreeEntry {
                name: b"a.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob,
            }],
        }),
    );
    let tip = write(
        &store,
        &Object::Commit(Commit::new_unannotated(
            tree,
            vec![],
            Identity::ed25519([1; 32]),
            [1; 32],
            b"first\nbody".to_vec(),
            1,
            [0; 64],
        )),
    );
    refs::write_ref(&layout, "main", &tip).unwrap();
    refs::write_head_branch(&layout, "main").unwrap();
    Fixture {
        _dir: dir,
        environment: Environment::new(&base),
        base,
        layout,
        tip,
    }
}

fn names(entries: &[Entry]) -> Vec<&Path> {
    entries.iter().map(|e| e.path.as_path()).collect()
}

#[test]
fn add_without_a_commit_ish_makes_a_branch_named_after_the_path() {
    let f = fixture();
    let added = f.add("topic", None).unwrap();
    assert_eq!(
        added,
        linked::Added {
            checkout: Checkout::NewBranch("topic".to_owned()),
            commit: f.tip,
            subject: "first".to_owned(),
        }
    );
    assert_eq!(refs::read_ref(&f.layout, "topic").unwrap(), Some(f.tip));
    let tree = f.base.join("topic");
    assert_eq!(fs::read_to_string(tree.join("a.txt")).unwrap(), "one\n");
    let linked = layout::discover(&tree).unwrap();
    assert_eq!(
        refs::read_head(&linked).unwrap(),
        Head::Branch("topic".to_owned())
    );
}

#[test]
fn add_with_a_branch_checks_it_out_and_with_a_hash_detaches() {
    let f = fixture();
    refs::write_ref(&f.layout, "side", &f.tip).unwrap();
    let added = f.add("t1", Some("side")).unwrap();
    assert_eq!(added.checkout, Checkout::Branch("side".to_owned()));

    let hex = kit_core::hash::to_hex(&f.tip);
    let added = f.add("t2", Some(&hex)).unwrap();
    assert_eq!(added.checkout, Checkout::Detached);
    let linked = layout::discover(&f.base.join("t2")).unwrap();
    assert_eq!(refs::read_head(&linked).unwrap(), Head::Detached(f.tip));
}

#[test]
fn add_refuses_a_branch_that_a_tree_has() {
    let f = fixture();
    let err = f.add("t1", Some("main")).unwrap_err();
    assert!(
        matches!(err, Error::CheckedOutHere(ref b) if b == "main"),
        "{err:?}"
    );
    assert_eq!(
        err.to_string(),
        "branch 'main' is already checked out in this worktree"
    );

    refs::write_ref(&f.layout, "side", &f.tip).unwrap();
    f.add("t1", Some("side")).unwrap();
    let err = f.add("t2", Some("side")).unwrap_err();
    assert!(
        matches!(err, Error::CheckedOutElsewhere { ref branch, .. } if branch == "side"),
        "{err:?}"
    );
    assert!(!f.base.join("t2").exists());
}

#[test]
fn add_refuses_a_name_in_use_a_busy_directory_and_a_nested_path() {
    let f = fixture();
    refs::write_ref(&f.layout, "topic", &f.tip).unwrap();
    let err = f.add("topic", None).unwrap_err();
    assert!(
        matches!(err, Error::BranchExists(ref b) if b == "topic"),
        "{err:?}"
    );

    fs::create_dir(f.base.join("busy")).unwrap();
    fs::write(f.base.join("busy").join("x"), b"x").unwrap();
    let err = f.add("busy", Some("main~0")).unwrap_err();
    assert!(matches!(err, Error::TargetNotEmpty(_)), "{err:?}");

    fs::write(f.base.join("file"), b"x").unwrap();
    let err = f.add("file", None).unwrap_err();
    assert!(matches!(err, Error::TargetNotDirectory(_)), "{err:?}");

    let err = f.add("main/inner", None).unwrap_err();
    assert!(matches!(err, Error::InsideWorktree { .. }), "{err:?}");
}

#[test]
fn add_refuses_an_unknown_commit_ish_and_an_empty_repository() {
    let f = fixture();
    let err = f.add("t1", Some("nope")).unwrap_err();
    assert!(matches!(err, Error::UnknownCommitish { .. }), "{err:?}");
    assert!(
        err.to_string()
            .starts_with("no such branch, tag, or commit: nope (")
    );

    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().canonicalize().unwrap();
    let layout = RepoLayout::single(&base);
    ObjectStore::init(&layout).unwrap();
    refs::init(&layout).unwrap();
    let environment = Environment::new(&base);
    let config = StoreConfig {
        environment: &environment,
        observer: &NoopObserver,
    };
    // The target is outside the repository and does not exist.
    let elsewhere = tempfile::tempdir().unwrap();
    let target = elsewhere.path().canonicalize().unwrap().join("x");
    let err = linked::add(
        &layout,
        &config,
        &base,
        target.to_str().unwrap(),
        None,
        &NoopObserver,
    )
    .unwrap_err();
    assert!(matches!(err, Error::NoCommits), "{err:?}");
}

#[test]
fn list_gives_the_main_tree_first_then_the_linked_trees() {
    let f = fixture();
    f.add("t1", None).unwrap();
    let rows = linked::list(&f.layout, &f.config()).unwrap();
    assert_eq!(names(&rows), [f.base.join("main"), f.base.join("t1")]);
    assert_eq!(rows[0].branch.as_deref(), Some("main"));
    assert_eq!(rows[1].branch.as_deref(), Some("t1"));
    assert_eq!(rows[1].head, Some(f.tip));
    assert!(rows.iter().all(|r| r.prunable.is_none()));
}

#[test]
fn list_checks_that_the_path_holds_a_repository() {
    let dir = tempfile::tempdir().unwrap();
    let layout = RepoLayout::single(dir.path());
    let environment = Environment::new(dir.path());
    let config = StoreConfig {
        environment: &environment,
        observer: &NoopObserver,
    };
    let err = linked::list(&layout, &config).unwrap_err();
    assert!(matches!(err, Error::OpenStore(_)), "{err:?}");
    assert!(err.to_string().starts_with("open store: "));
}

#[test]
fn remove_deletes_a_clean_tree_and_its_state() {
    let f = fixture();
    f.add("t1", None).unwrap();
    f.remove("t1", false).unwrap();
    assert!(!f.base.join("t1").exists());
    assert_eq!(linked::list(&f.layout, &f.config()).unwrap().len(), 1);
    assert!(!f.layout.worktrees_dir().join("t1").exists());
}

#[test]
fn remove_keeps_a_tree_with_local_work_unless_forced() {
    let f = fixture();
    f.add("t1", None).unwrap();
    fs::write(f.base.join("t1").join("scratch"), b"x").unwrap();
    let err = f.remove("t1", false).unwrap_err();
    assert!(
        matches!(err, Error::Dirty(ref w) if w == "untracked file 'scratch'"),
        "{err:?}"
    );
    assert!(f.base.join("t1").exists());

    fs::remove_file(f.base.join("t1").join("scratch")).unwrap();
    fs::write(f.base.join("t1").join("a.txt"), b"changed\n").unwrap();
    // The main tree has no index yet, and the linked tree reads its own.
    let err = f.remove("t1", false).unwrap_err();
    assert!(
        matches!(err, Error::Dirty(ref w) if w == "local changes"),
        "{err:?}"
    );

    f.remove("t1", true).unwrap();
    assert!(!f.base.join("t1").exists());
}

#[test]
fn remove_refuses_the_main_tree_the_current_tree_and_a_stranger() {
    let f = fixture();
    f.add("t1", None).unwrap();
    let err = f.remove("main", true).unwrap_err();
    assert!(matches!(err, Error::RemoveMain), "{err:?}");

    let err = linked::remove(
        &f.layout,
        &f.config(),
        &f.base.join("t1"),
        ".",
        true,
        false,
        &NoopObserver,
    )
    .unwrap_err();
    assert!(matches!(err, Error::RemoveCurrent), "{err:?}");

    fs::create_dir(f.base.join("other")).unwrap();
    let err = f.remove("other", true).unwrap_err();
    assert!(matches!(err, Error::NotLinked(_)), "{err:?}");
    assert!(
        err.to_string()
            .ends_with("is not a linked worktree of this repository")
    );
}

#[test]
fn prune_removes_the_entry_of_a_tree_that_is_gone() {
    let f = fixture();
    f.add("t1", None).unwrap();
    fs::remove_dir_all(f.base.join("t1")).unwrap();

    let rows = linked::list(&f.layout, &f.config()).unwrap();
    assert!(rows.iter().any(|r| r.prunable.is_some()), "{rows:?}");

    let would = linked::prune(&f.layout, true, &NoopObserver).unwrap();
    assert_eq!(would.len(), 1);
    assert!(f.layout.worktrees_dir().join("t1").exists());

    let pruned = linked::prune(&f.layout, false, &NoopObserver).unwrap();
    assert_eq!(
        pruned.iter().map(|p| p.id.as_str()).collect::<Vec<_>>(),
        ["t1"]
    );
    assert!(!f.layout.worktrees_dir().join("t1").exists());
    assert_eq!(
        linked::prune(&f.layout, false, &NoopObserver).unwrap(),
        Vec::<Pruned>::new()
    );
}

#[test]
fn a_lock_stops_remove_move_and_prune_until_forced() {
    let f = fixture();
    f.add("t1", None).unwrap();
    linked::lock(&f.layout, &f.base, "t1", "away", &NoopObserver).unwrap();
    let rows = linked::list(&f.layout, &f.config()).unwrap();
    assert_eq!(rows[1].locked.as_deref(), Some("away"));
    assert_eq!(rows[0].locked, None);

    let err = f.remove("t1", true).unwrap_err();
    assert!(
        matches!(err, Error::Locked { ref reason } if reason == "away"),
        "{err:?}"
    );
    let err = linked::move_to(&f.layout, &f.base, "t1", "t2", false, &NoopObserver).unwrap_err();
    assert!(matches!(err, Error::Locked { .. }), "{err:?}");
    let err = linked::lock(&f.layout, &f.base, "t1", "", &NoopObserver).unwrap_err();
    assert!(matches!(err, Error::AlreadyLocked), "{err:?}");

    fs::remove_dir_all(f.base.join("t1")).unwrap();
    assert!(
        linked::prune(&f.layout, false, &NoopObserver)
            .unwrap()
            .is_empty()
    );
    assert!(f.layout.worktrees_dir().join("t1").exists());

    linked::unlock(&f.layout, &f.base, "t1", &NoopObserver).unwrap();
    let err = linked::unlock(&f.layout, &f.base, "t1", &NoopObserver).unwrap_err();
    assert!(matches!(err, Error::NotLocked), "{err:?}");
    assert_eq!(
        linked::prune(&f.layout, false, &NoopObserver)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn lock_and_unlock_refuse_the_main_tree_and_a_stranger() {
    let f = fixture();
    let main = f
        .layout
        .common_dir()
        .parent()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    for result in [
        linked::lock(&f.layout, &f.base, &main, "", &NoopObserver),
        linked::unlock(&f.layout, &f.base, &main, &NoopObserver),
    ] {
        assert!(matches!(result.unwrap_err(), Error::MainTree(_)));
    }
    let err = linked::lock(&f.layout, &f.base, "nowhere", "", &NoopObserver).unwrap_err();
    assert!(matches!(err, Error::NotLinked(_)), "{err:?}");
    f.add("t1", None).unwrap();
    let err = linked::lock(&f.layout, &f.base, "t1", "a\nb", &NoopObserver).unwrap_err();
    assert!(matches!(err, Error::LockFile(_)), "{err:?}");
}

#[test]
fn move_renames_the_tree_and_updates_both_links() {
    let f = fixture();
    f.add("t1", None).unwrap();
    let to = linked::move_to(&f.layout, &f.base, "t1", "t2", false, &NoopObserver).unwrap();
    assert_eq!(to, f.base.join("t2"));
    assert!(!f.base.join("t1").exists());
    let rows = linked::list(&f.layout, &f.config()).unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|r| r.prunable.is_none()), "{rows:?}");
    assert_eq!(rows[1].path, f.base.join("t2"));
    let back = fs::read_to_string(f.layout.worktrees_dir().join("t1/kitdir")).unwrap();
    assert_eq!(back, format!("{}\n", to.join(".kit").display()));
}

#[test]
fn move_refuses_a_bad_destination_the_main_tree_and_a_gone_tree() {
    let f = fixture();
    f.add("t1", None).unwrap();
    let mv = |from: &str, to: &str| {
        linked::move_to(&f.layout, &f.base, from, to, false, &NoopObserver).unwrap_err()
    };
    fs::create_dir(f.base.join("busy")).unwrap();
    assert!(matches!(mv("t1", "busy"), Error::MoveTargetExists(_)));
    assert!(matches!(mv("t1", "a/../b"), Error::MoveTargetInvalid(..)));
    assert!(matches!(mv("t1", "absent/b"), Error::MoveTargetInvalid(..)));
    assert!(matches!(mv("t1", ""), Error::MoveTargetInvalid(..)));
    assert!(matches!(mv("t1", "t1/inner"), Error::InsideWorktree { .. }));
    assert!(matches!(mv("nowhere", "t2"), Error::NotLinked(_)));
    let main = f
        .layout
        .common_dir()
        .parent()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert!(matches!(mv(&main, "t2"), Error::MainTree(_)));
    fs::remove_dir_all(f.base.join("t1")).unwrap();
    assert!(matches!(mv("t1", "t2"), Error::TreeMissing(_)));
}

#[test]
fn repair_fixes_the_back_pointer_of_a_tree_moved_by_hand() {
    let f = fixture();
    f.add("t1", None).unwrap();
    fs::rename(f.base.join("t1"), f.base.join("t2")).unwrap();
    let fixed = linked::repair(&f.layout, &f.base, &["t2".to_owned()], &NoopObserver).unwrap();
    assert_eq!(
        fixed,
        [linked::Repaired {
            id: "t1".to_owned(),
            what: "back-pointer"
        }]
    );
    assert!(
        linked::list(&f.layout, &f.config())
            .unwrap()
            .iter()
            .all(|r| r.prunable.is_none())
    );
    let again = linked::repair(&f.layout, &f.base, &["t2".to_owned()], &NoopObserver).unwrap();
    assert!(again.is_empty());
    let err =
        linked::repair(&f.layout, &f.base, &["nowhere".to_owned()], &NoopObserver).unwrap_err();
    assert!(matches!(err, Error::Unrepairable { .. }), "{err:?}");
}

//! The state of the tree against `HEAD` and the index.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

use std::fs;
use std::path::PathBuf;

use kit_core::hash::Hash;
use kit_core::index::{self, EntryStatus};
use kit_core::layout::RepoLayout;
use kit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use kit_core::ops::{DiffKind, StatusStaging};
use kit_core::refs;
use kit_core::serialize;
use kit_core::store::ObjectStore;
use libkit::NoopObserver;
use libkit::status::{self, Detail, Error, HeadState, Request};

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    layout: RepoLayout,
    tree: Hash,
}

fn write(store: &ObjectStore, object: &Object) -> Hash {
    store.write(&serialize::serialize(object).unwrap()).unwrap()
}

/// A repository with one commit that holds `a.txt` and `b.txt`. The tree and
/// the index match the commit.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let layout = RepoLayout::single(&root);
    let store = ObjectStore::init(&layout).unwrap();
    refs::init(&layout).unwrap();
    let mut entries = Vec::new();
    for (name, content) in [("a.txt", "one\n"), ("b.txt", "two\n")] {
        fs::write(root.join(name), content).unwrap();
        let blob = write(
            &store,
            &Object::Blob(Blob {
                data: content.as_bytes().to_vec(),
            }),
        );
        entries.push(TreeEntry {
            name: name.as_bytes().to_vec(),
            mode: EntryMode::Blob,
            object_hash: blob,
        });
    }
    let tree = write(&store, &Object::Tree(Tree { entries }));
    let tip = write(
        &store,
        &Object::Commit(Commit::new_unannotated(
            tree,
            vec![],
            Identity::ed25519([1; 32]),
            [1; 32],
            b"first".to_vec(),
            1,
            [0; 64],
        )),
    );
    refs::write_ref(&layout, "main", &tip).unwrap();
    refs::write_head_branch(&layout, "main").unwrap();
    index::write_index(&layout, &index::from_tree(&store, tree).unwrap()).unwrap();
    Fixture {
        _dir: dir,
        root,
        layout,
        tree,
    }
}

fn run(f: &Fixture, renames: bool) -> Result<status::Report, Error> {
    status::compute(
        &f.layout,
        &f.root,
        &Request {
            renames,
            rename_threshold: None,
        },
        &NoopObserver,
    )
}

fn listing(report: &status::Report) -> Vec<(String, String)> {
    status::records(&report.entries)
        .into_iter()
        .map(|r| {
            (
                std::str::from_utf8(&r.xy).unwrap().to_owned(),
                r.path.to_owned(),
            )
        })
        .collect()
}

#[test]
fn a_clean_tree_has_no_entries() {
    let f = fixture();
    let report = run(&f, true).unwrap();
    assert_eq!(report.head_tree, Some(f.tree));
    assert!(report.entries.is_empty(), "{:?}", report.entries);
}

#[test]
fn a_change_that_is_not_staged_and_an_untracked_file_are_listed() {
    let f = fixture();
    fs::write(f.root.join("a.txt"), "changed\n").unwrap();
    fs::write(f.root.join("new.txt"), "n\n").unwrap();
    let report = run(&f, true).unwrap();
    assert_eq!(
        listing(&report),
        vec![
            (" M".to_owned(), "a.txt".to_owned()),
            ("??".to_owned(), "new.txt".to_owned()),
        ]
    );
}

#[test]
fn a_staged_move_is_one_rename_unless_renames_are_off() {
    let f = fixture();
    fs::rename(f.root.join("a.txt"), f.root.join("c.txt")).unwrap();
    let mut idx = index::read_index(&f.layout).unwrap();
    let slot = idx.find_entry("a.txt").unwrap();
    let moved = idx.entries[slot].clone();
    idx.entries[slot].status = EntryStatus::Removed;
    idx.entries[slot].object_hash = kit_core::hash::ZERO;
    idx.upsert_entry(kit_core::index::IndexEntry {
        path: "c.txt".to_owned(),
        ..moved
    });
    index::write_index(&f.layout, &idx).unwrap();

    let report = run(&f, true).unwrap();
    let records = status::records(&report.entries);
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].xy, *b"R ");
    assert_eq!(records[0].path, "c.txt");
    assert_eq!(records[0].old_path, Some("a.txt"));

    let report = run(&f, false).unwrap();
    assert_eq!(
        listing(&report),
        vec![
            ("D ".to_owned(), "a.txt".to_owned()),
            ("A ".to_owned(), "c.txt".to_owned()),
        ]
    );
}

#[test]
fn a_rename_threshold_must_be_a_number() {
    let f = fixture();
    let request = |t| Request {
        renames: true,
        rename_threshold: Some(t),
    };
    for ok in ["", "50", "50%", "100"] {
        status::compute(&f.layout, &f.root, &request(ok), &NoopObserver).unwrap();
    }
    for bad in ["x", "-1", "256", "5 0"] {
        let err = status::compute(&f.layout, &f.root, &request(bad), &NoopObserver).unwrap_err();
        assert!(
            matches!(err, Error::InvalidRenameThreshold(ref t) if t == bad),
            "{err:?}"
        );
        assert_eq!(
            err.to_string(),
            format!("invalid --find-renames value: {bad}")
        );
    }
}

#[test]
fn a_damaged_index_is_an_error_and_not_a_comparison_with_head() {
    let f = fixture();
    fs::write(f.layout.index_file(), b"not an index").unwrap();
    let err = run(&f, true).unwrap_err();
    assert!(matches!(err, Error::ReadIndex(_)), "{err:?}");
    assert!(err.to_string().starts_with("read index: "));
}

#[test]
fn a_directory_without_a_store_is_not_a_repository() {
    let dir = tempfile::tempdir().unwrap();
    let layout = RepoLayout::single(dir.path());
    let err = status::compute(
        &layout,
        dir.path(),
        &Request {
            renames: true,
            rename_threshold: None,
        },
        &NoopObserver,
    )
    .unwrap_err();
    assert!(matches!(err, Error::NotARepository(_)), "{err:?}");
    assert!(err.to_string().starts_with("not a kit repo: "));
}

#[test]
fn head_state_names_the_branch_and_the_commit_that_is_missing() {
    let f = fixture();
    assert_eq!(
        status::head_state(&f.layout),
        Some(HeadState {
            head: refs::Head::Branch("main".to_owned()),
            unborn: false,
        })
    );
    let empty = tempfile::tempdir().unwrap();
    let layout = RepoLayout::single(empty.path());
    ObjectStore::init(&layout).unwrap();
    refs::init(&layout).unwrap();
    refs::write_head_branch(&layout, "dev").unwrap();
    assert_eq!(
        status::head_state(&layout),
        Some(HeadState {
            head: refs::Head::Branch("dev".to_owned()),
            unborn: true,
        })
    );
}

#[test]
fn detail_gives_the_modes_and_ids_of_head_the_index_and_the_tree() {
    let f = fixture();
    fs::write(f.root.join("a.txt"), "changed\n").unwrap();
    let report = run(&f, true).unwrap();
    let detail = Detail::load(&f.layout, report.head_tree.as_ref()).unwrap();
    let records = status::records(&report.entries);
    let record = records.iter().find(|r| r.path == "a.txt").unwrap();
    let d = detail.of(record);
    assert_eq!(d.head_mode, "100644");
    assert_eq!(d.index_mode, "100644");
    assert_eq!(d.worktree_mode, "100644");
    assert_eq!(d.head_hash, d.index_hash);
    assert_ne!(d.head_hash, kit_core::hash::ZERO);

    let untracked = fixture();
    fs::write(untracked.root.join("new.txt"), "n").unwrap();
    let report = run(&untracked, true).unwrap();
    let detail = Detail::load(&untracked.layout, report.head_tree.as_ref()).unwrap();
    let records = status::records(&report.entries);
    let d = detail.of(&records[0]);
    assert_eq!(
        (d.head_mode, d.index_mode, d.worktree_mode),
        ("000000", "000000", "100644")
    );
    assert_eq!(d.head_hash, kit_core::hash::ZERO);
}

#[test]
fn a_staged_deletion_is_listed_as_a_staged_change() {
    let f = fixture();
    let mut idx = index::read_index(&f.layout).unwrap();
    let slot = idx.find_entry("b.txt").unwrap();
    idx.entries[slot].status = EntryStatus::Removed;
    idx.entries[slot].object_hash = kit_core::hash::ZERO;
    index::write_index(&f.layout, &idx).unwrap();
    fs::remove_file(f.root.join("b.txt")).unwrap();
    let report = run(&f, true).unwrap();
    let kinds: Vec<_> = report
        .entries
        .iter()
        .map(|e| (e.diff.path.as_str(), e.staging, e.diff.kind))
        .collect();
    assert_eq!(
        kinds,
        vec![("b.txt", StatusStaging::Staged, DiffKind::Removed)]
    );
}

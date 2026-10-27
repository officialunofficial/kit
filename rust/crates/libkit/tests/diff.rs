//! Diffs through an open `Repo`.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

use std::fs;

use kit_core::hash::{self, Hash};
use kit_core::layout::RepoLayout;
use kit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use kit_core::ops::{DiffKind, WhitespaceMode};
use kit_core::refs;
use kit_core::serialize;
use kit_core::store::ObjectStore;
use libkit::diff::{self, PatchBody, Request, StatChange};
use libkit::{Environment, Error, Repo};

/// Two commits and a worktree.
///
/// - `first` has `a.txt` (two lines) and `gone.txt`.
/// - `second` has `a.txt` with a new second line, and `moved.txt` with the
///   content of `gone.txt`. `main` names it.
/// - The worktree has the files of `second`, plus a third line in `a.txt`
///   and an untracked `new.txt`.
struct Fixture {
    _dir: tempfile::TempDir,
    repo: Repo,
    first: Hash,
    second: Hash,
}

fn blob(store: &ObjectStore, data: &str) -> Hash {
    let object = Object::Blob(Blob {
        data: data.as_bytes().to_vec(),
    });
    store
        .write(&serialize::serialize(&object).unwrap())
        .unwrap()
}

fn tree(store: &ObjectStore, files: &[(&str, Hash)]) -> Hash {
    let entries = files
        .iter()
        .map(|(name, object_hash)| TreeEntry {
            name: name.as_bytes().to_vec(),
            mode: EntryMode::Blob,
            object_hash: *object_hash,
        })
        .collect();
    store
        .write(&serialize::serialize(&Object::Tree(Tree { entries })).unwrap())
        .unwrap()
}

fn commit(store: &ObjectStore, tree: Hash, parents: Vec<Hash>, time: u64) -> Hash {
    let commit = Commit::new_unannotated(
        tree,
        parents,
        Identity::ed25519([1; 32]),
        [1; 32],
        b"m".to_vec(),
        time,
        [0; 64],
    );
    store
        .write(&serialize::serialize(&Object::Commit(commit)).unwrap())
        .unwrap()
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let layout = RepoLayout::single(dir.path());
    let store = ObjectStore::init(&layout).unwrap();
    refs::init(&layout).unwrap();
    let one_two = blob(&store, "one\ntwo\n");
    let one_three = blob(&store, "one\nthree\n");
    let bye = blob(&store, "bye\n");
    let first_tree = tree(&store, &[("a.txt", one_two), ("gone.txt", bye)]);
    let first = commit(&store, first_tree, vec![], 1);
    let second_tree = tree(&store, &[("a.txt", one_three), ("moved.txt", bye)]);
    let second = commit(&store, second_tree, vec![first], 2);
    refs::write_ref(&layout, "main", &second).unwrap();
    fs::write(dir.path().join("a.txt"), "one\nthree\nfour\n").unwrap();
    fs::write(dir.path().join("moved.txt"), "bye\n").unwrap();
    fs::write(dir.path().join("new.txt"), "n\n").unwrap();
    let repo = Repo::open(dir.path(), &Environment::new(dir.path())).unwrap();
    Fixture {
        _dir: dir,
        repo,
        first,
        second,
    }
}

fn run(f: &Fixture, staged: bool, merge_base: bool, renames: bool, args: &[&str]) -> Vec<String> {
    try_run(f, staged, merge_base, renames, args)
        .unwrap()
        .into_iter()
        .map(|(path, kind)| format!("{kind:?} {path}"))
        .collect()
}

fn try_run(
    f: &Fixture,
    staged: bool,
    merge_base: bool,
    renames: bool,
    args: &[&str],
) -> Result<Vec<(String, DiffKind)>, diff::Error> {
    let args: Vec<String> = args.iter().map(ToString::to_string).collect();
    let request = Request {
        staged,
        merge_base,
        renames,
        args: &args,
    };
    let diff = diff::compute(&f.repo, &request)?;
    Ok(diff
        .entries()
        .iter()
        .map(|e| (e.path.clone(), e.kind))
        .collect())
}

fn hex(hash: &Hash) -> String {
    hash::to_hex(hash)
}

#[test]
fn no_argument_compares_head_with_the_worktree() {
    let f = fixture();
    assert_eq!(
        run(&f, false, false, true, &[]),
        ["Modified a.txt", "Added new.txt"]
    );
}

#[test]
fn two_revisions_compare_their_trees_and_a_rename_joins_a_delete_and_an_add() {
    let f = fixture();
    let (first, second) = (hex(&f.first), hex(&f.second));
    let expected = ["Modified a.txt", "Removed gone.txt", "Added moved.txt"];
    assert_eq!(run(&f, false, false, false, &[&first, &second]), expected);
    assert_eq!(
        run(&f, false, false, true, &[&first, &second]),
        ["Modified a.txt", "Renamed moved.txt"]
    );
    assert_eq!(
        run(&f, false, false, true, &[&format!("{first}..{second}")]),
        ["Modified a.txt", "Renamed moved.txt"]
    );
}

#[test]
fn a_symmetric_range_compares_the_merge_base_with_the_second_side() {
    let f = fixture();
    let spec = format!("{}...{}", hex(&f.first), hex(&f.second));
    assert_eq!(
        run(&f, false, false, true, &[&spec]),
        ["Modified a.txt", "Renamed moved.txt"]
    );
}

#[test]
fn paths_after_the_revisions_keep_the_entries_at_or_below_them() {
    let f = fixture();
    let (first, second) = (hex(&f.first), hex(&f.second));
    assert_eq!(
        run(&f, false, false, true, &[&first, &second, "a.txt"]),
        ["Modified a.txt"]
    );
    assert_eq!(
        run(&f, false, false, true, &[&first, &second, "./moved.txt"]),
        ["Renamed moved.txt"]
    );
    // A word that is not a revision starts the paths.
    assert_eq!(run(&f, false, false, true, &["new.txt"]), ["Added new.txt"]);
    assert!(run(&f, false, false, true, &["nothing-here"]).is_empty());
    // The root in any spelling keeps every entry.
    assert_eq!(run(&f, false, false, true, &["."]).len(), 2);
}

#[test]
fn staged_compares_head_with_the_index_and_refuses_a_revision() {
    let f = fixture();
    assert!(run(&f, true, false, true, &[]).is_empty());
    assert!(run(&f, true, false, true, &["a.txt"]).is_empty());
    let err = try_run(&f, true, false, true, &["HEAD"]).unwrap_err();
    assert!(
        matches!(err, diff::Error::StagedWithRevision),
        "got {err:?}"
    );
    let err = try_run(&f, true, false, true, &["deadbeef"]).unwrap_err();
    assert!(
        matches!(&err, diff::Error::UnknownRevision(spec) if spec == "deadbeef"),
        "got {err:?}"
    );
}

#[test]
fn merge_base_compares_the_base_with_the_worktree_or_the_second_revision() {
    let f = fixture();
    let (first, second) = (hex(&f.first), hex(&f.second));
    // merge-base(first, HEAD) is `first`.
    assert_eq!(
        run(&f, false, true, false, &[&first]),
        [
            "Modified a.txt",
            "Removed gone.txt",
            "Added moved.txt",
            "Added new.txt"
        ]
    );
    // merge-base(second, first) is `first`, so the two sides are equal.
    assert!(run(&f, false, true, true, &[&second, &first]).is_empty());
    let err = try_run(&f, false, true, true, &[]).unwrap_err();
    assert!(
        matches!(err, diff::Error::MergeBaseNeedsRevision),
        "got {err:?}"
    );
}

#[test]
fn a_revision_that_does_not_resolve_is_an_error_that_names_it() {
    let f = fixture();
    let err = try_run(&f, false, false, true, &["HEAD~9"]).unwrap_err();
    assert!(
        matches!(&err, diff::Error::BadRevision { spec, .. } if spec == "HEAD~9"),
        "got {err:?}"
    );
    assert!(err.to_string().starts_with("bad revision 'HEAD~9': "));
    let err = try_run(&f, false, false, true, &["a..nope"]).unwrap_err();
    assert!(
        matches!(err, diff::Error::BadRevision { .. }),
        "got {err:?}"
    );
    assert!(matches!(Error::from(err), Error::Diff(_)));
}

#[test]
fn a_patch_body_and_the_stats_come_from_the_same_entries() {
    let f = fixture();
    let (first, second) = (hex(&f.first), hex(&f.second));
    let args = [first, second];
    let request = Request {
        staged: false,
        merge_base: false,
        renames: true,
        args: &args,
    };
    let diff = diff::compute(&f.repo, &request).unwrap();
    let a = &diff.entries()[0];
    assert_eq!(
        diff.patch_body(a, 3, WhitespaceMode::Exact).unwrap(),
        PatchBody::Hunks(b"@@ -1,2 +1,2 @@\n one\n-two\n+three\n".to_vec())
    );
    let renamed = &diff.entries()[1];
    assert_eq!(
        diff.patch_body(renamed, 3, WhitespaceMode::Exact).unwrap(),
        PatchBody::Empty
    );
    let stats = diff.stats().unwrap();
    assert_eq!(stats.len(), 2);
    assert_eq!(stats[0].path, "a.txt");
    assert_eq!(
        stats[0].change,
        StatChange::Text {
            added: 1,
            deleted: 1
        }
    );
}

#[test]
fn a_diff_of_the_worktree_never_writes_to_the_store() {
    let f = fixture();
    assert!(!run(&f, false, false, true, &[]).is_empty());
    let untracked = Object::Blob(Blob {
        data: b"n\n".to_vec(),
    });
    let id = hash::hash(&serialize::serialize(&untracked).unwrap());
    assert!(!f.repo.store().contains(&id));
}

#[test]
fn a_missing_side_is_the_empty_tree() {
    let f = fixture();
    let tree = libkit::revspec::tree_of(f.repo.store(), &f.second).unwrap();
    let diff = diff::between_trees(&f.repo, None, Some(tree)).unwrap();
    let kinds: Vec<_> = diff.entries().iter().map(|e| e.kind).collect();
    assert_eq!(kinds, [DiffKind::Added, DiffKind::Added]);
}

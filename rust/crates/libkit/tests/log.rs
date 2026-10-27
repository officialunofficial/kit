//! History walks through an open `Repo`.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

use kit_core::hash::Hash;
use kit_core::layout::RepoLayout;
use kit_core::object::{Commit, Identity, Object};
use kit_core::refs;
use kit_core::serialize;
use kit_core::store::ObjectStore;
use libkit::log::{self, Filter, Query};
use libkit::{Environment, Error, Repo};

/// A repository with this history. `t` is a time, and each line is a commit.
///
/// ```text
/// root(t1) - a(t2) - m(t5) - tip(t6)
///        \          /
///         side(t3) -+
/// ```
struct Fixture {
    _dir: tempfile::TempDir,
    repo: Repo,
    root: Hash,
    a: Hash,
    side: Hash,
    merge: Hash,
    tip: Hash,
}

fn commit(store: &ObjectStore, parents: Vec<Hash>, seed: u8, time: u64, message: &str) -> Hash {
    let commit = Commit::new_unannotated(
        [seed; 32],
        parents,
        Identity::opaque(format!("author-{seed}").into_bytes()),
        [seed; 32],
        message.as_bytes().to_vec(),
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
    let root = commit(&store, vec![], 1, 1, "root");
    let a = commit(&store, vec![root], 2, 2, "alpha change");
    let side = commit(&store, vec![root], 3, 3, "side change");
    let merge = commit(&store, vec![a, side], 4, 5, "merge side");
    let tip = commit(&store, vec![merge], 5, 6, "tip");
    refs::write_ref(&layout, "main", &tip).unwrap();
    refs::write_ref(&layout, "side", &side).unwrap();
    let repo = Repo::open(dir.path(), &Environment::new(dir.path())).unwrap();
    Fixture {
        _dir: dir,
        repo,
        root,
        a,
        side,
        merge,
        tip,
    }
}

fn hashes(entries: Option<Vec<log::Entry>>) -> Vec<Hash> {
    entries.unwrap().into_iter().map(|e| e.hash).collect()
}

fn query(start: Option<&str>) -> Query {
    Query {
        start: start.map(str::to_owned),
        ..Query::default()
    }
}

#[test]
fn the_default_walk_starts_at_head_and_never_shows_a_parent_before_a_child() {
    let f = fixture();
    let walked = hashes(log::history(&f.repo, &query(None)).unwrap());
    assert_eq!(walked, [f.tip, f.merge, f.side, f.a, f.root]);
}

#[test]
fn first_parent_leaves_out_the_merged_branch() {
    let f = fixture();
    let q = Query {
        first_parent: true,
        ..query(None)
    };
    let walked = hashes(log::history(&f.repo, &q).unwrap());
    assert_eq!(walked, [f.tip, f.merge, f.a, f.root]);
}

#[test]
fn a_range_keeps_the_commits_that_the_other_side_lacks() {
    let f = fixture();
    let walked = hashes(log::history(&f.repo, &query(Some("side..main"))).unwrap());
    assert_eq!(walked, [f.tip, f.merge, f.a]);
    // An empty side is HEAD.
    let walked = hashes(log::history(&f.repo, &query(Some("side.."))).unwrap());
    assert_eq!(walked, [f.tip, f.merge, f.a]);
}

#[test]
fn a_symmetric_range_leaves_out_the_common_ancestors() {
    let f = fixture();
    let spec = format!("{}...side", kit_core::hash::to_hex(&f.a));
    let walked = hashes(log::history(&f.repo, &query(Some(&spec))).unwrap());
    assert_eq!(walked, [f.side, f.a]);
}

#[test]
fn a_filter_applies_before_the_limit() {
    let f = fixture();
    let q = Query {
        filter: Filter {
            grep: Some("change".to_owned()),
            ..Filter::default()
        },
        limit: Some(1),
        ..query(None)
    };
    // The newest commit with `change` in its message is `side`, not `tip`.
    let walked = hashes(log::history(&f.repo, &q).unwrap());
    assert_eq!(walked, [f.side]);
}

#[test]
fn a_filter_can_drop_merges_and_bound_the_time() {
    let f = fixture();
    let q = Query {
        filter: Filter {
            no_merges: true,
            since: Some(2),
            until: Some(5),
            ..Filter::default()
        },
        ..query(None)
    };
    let walked = hashes(log::history(&f.repo, &q).unwrap());
    assert_eq!(walked, [f.side, f.a]);
}

#[test]
fn a_limit_of_zero_returns_no_commit() {
    let f = fixture();
    let q = Query {
        limit: Some(0),
        ..query(None)
    };
    assert!(hashes(log::history(&f.repo, &q).unwrap()).is_empty());
}

#[test]
fn a_repository_without_a_commit_has_nothing_to_walk() {
    let dir = tempfile::tempdir().unwrap();
    let layout = RepoLayout::single(dir.path());
    ObjectStore::init(&layout).unwrap();
    refs::init(&layout).unwrap();
    let repo = Repo::open(dir.path(), &Environment::new(dir.path())).unwrap();
    assert!(log::history(&repo, &query(None)).unwrap().is_none());
    assert!(log::history(&repo, &query(Some("HEAD"))).unwrap().is_none());
}

#[test]
fn an_unknown_revision_is_an_error_that_names_it() {
    let f = fixture();
    let err = log::history(&f.repo, &query(Some("nope"))).unwrap_err();
    assert!(
        matches!(&err, log::Error::BadRevision { spec, .. } if spec == "nope"),
        "got {err:?}"
    );
    assert!(err.to_string().starts_with("bad revision 'nope': "));
    assert!(matches!(Error::from(err), Error::Log(_)));
}

#[test]
fn a_tree_is_not_a_commit() {
    let f = fixture();
    let tree =
        serialize::serialize(&Object::Tree(kit_core::object::Tree { entries: vec![] })).unwrap();
    let tree = f.repo.store().write(&tree).unwrap();
    let hex = kit_core::hash::to_hex(&tree);
    let err = log::history(&f.repo, &query(Some(&hex))).unwrap_err();
    assert!(
        matches!(err, log::Error::NotACommit(h) if h == tree),
        "got {err:?}"
    );
}

#[test]
fn the_subject_is_the_first_line_of_the_message() {
    let f = fixture();
    assert_eq!(log::subject(f.repo.store(), &f.merge), "merge side");
    assert_eq!(log::subject(f.repo.store(), &[0xee; 32]), "");
}

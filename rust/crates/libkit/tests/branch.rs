//! Create, delete, rename and list branches through the layout of a tree.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

use kit_core::hash::Hash;
use kit_core::layout::{self, RepoLayout};
use kit_core::object::{Commit, Identity, Object};
use kit_core::observer::NoopObserver;
use kit_core::refs;
use kit_core::repo_lock;
use kit_core::serialize;
use kit_core::store::ObjectStore;
use libkit::branch::{self, Branch, Error, Query};

fn commit(store: &ObjectStore, parents: Vec<Hash>, message: &[u8]) -> Hash {
    let commit = Commit::new_unannotated(
        [1; 32],
        parents,
        Identity::ed25519([1; 32]),
        [1; 32],
        message.to_vec(),
        0,
        [0; 64],
    );
    store
        .write(&serialize::serialize(&Object::Commit(commit)).unwrap())
        .unwrap()
}

/// A repository on `main` with the history `root <- tip`.
fn repo() -> (tempfile::TempDir, RepoLayout, Hash, Hash) {
    let dir = tempfile::tempdir().unwrap();
    let layout = RepoLayout::single(dir.path());
    let store = ObjectStore::init(&layout).unwrap();
    refs::init(&layout).unwrap();
    let root = commit(&store, vec![], b"root\nsecond line");
    let tip = commit(&store, vec![root], b"tip");
    refs::write_ref(&layout, "main", &tip).unwrap();
    refs::write_head_branch(&layout, "main").unwrap();
    (dir, layout, root, tip)
}

fn names(branches: &[Branch]) -> Vec<&str> {
    branches.iter().map(|b| b.name.as_str()).collect()
}

#[test]
fn create_starts_a_branch_at_head_and_refuses_a_name_in_use() {
    let (_dir, layout, _root, tip) = repo();
    branch::create(&layout, "topic").unwrap();
    assert_eq!(refs::read_ref(&layout, "topic").unwrap(), Some(tip));
    let err = branch::create(&layout, "topic").unwrap_err();
    assert!(
        matches!(err, Error::AlreadyExists(ref n) if n == "topic"),
        "{err:?}"
    );
    assert_eq!(err.to_string(), "branch 'topic' already exists");
}

#[test]
fn create_needs_a_head_commit() {
    let dir = tempfile::tempdir().unwrap();
    let layout = RepoLayout::single(dir.path());
    ObjectStore::init(&layout).unwrap();
    refs::init(&layout).unwrap();
    let err = branch::create(&layout, "topic").unwrap_err();
    assert!(matches!(err, Error::NoHeadCommit), "{err:?}");
    assert_eq!(err.to_string(), "no HEAD commit to branch from");
}

#[test]
fn delete_returns_the_old_tip_and_refuses_the_current_branch() {
    let (_dir, layout, root, tip) = repo();
    refs::write_ref(&layout, "old", &root).unwrap();
    assert_eq!(
        branch::delete(&layout, "old", &NoopObserver).unwrap(),
        Some(root)
    );
    assert_eq!(refs::read_ref(&layout, "old").unwrap(), None);

    let err = branch::delete(&layout, "main", &NoopObserver).unwrap_err();
    assert!(matches!(err, Error::Delete { .. }), "{err:?}");
    assert_eq!(refs::read_ref(&layout, "main").unwrap(), Some(tip));

    let err = branch::delete(&layout, "absent", &NoopObserver).unwrap_err();
    assert!(
        matches!(err, Error::NotFound(ref n) if n == "absent"),
        "{err:?}"
    );
    assert_eq!(err.to_string(), "branch 'absent' not found");
}

#[test]
fn delete_waits_for_the_registry_lock() {
    let (_dir, layout, root, _tip) = repo();
    refs::write_ref(&layout, "old", &root).unwrap();
    let held = repo_lock::acquire_default(layout.common_dir(), repo_lock::WORKTREES_REGISTRY_LOCK)
        .unwrap();
    // The lock is held by this process. A second taker in the same process
    // times out, which is the contention that a second `kit` sees.
    let err = branch::delete(&layout, "old", &NoopObserver).unwrap_err();
    assert!(matches!(err, Error::Lock(_)), "{err:?}");
    drop(held);
    assert_eq!(refs::read_ref(&layout, "old").unwrap(), Some(root));
}

#[test]
fn rename_moves_the_tip_and_follows_head() {
    let (_dir, layout, root, tip) = repo();
    refs::write_ref(&layout, "old", &root).unwrap();
    branch::rename(&layout, Some("old"), "new", &NoopObserver).unwrap();
    assert_eq!(refs::read_ref(&layout, "old").unwrap(), None);
    assert_eq!(refs::read_ref(&layout, "new").unwrap(), Some(root));

    // One name renames the branch that HEAD names, and HEAD follows.
    branch::rename(&layout, None, "trunk", &NoopObserver).unwrap();
    assert_eq!(refs::read_ref(&layout, "trunk").unwrap(), Some(tip));
    assert_eq!(branch::current(&layout).as_deref(), Some("trunk"));
}

#[test]
fn rename_to_the_same_name_does_nothing_even_for_a_missing_branch() {
    let (_dir, layout, _root, _tip) = repo();
    branch::rename(&layout, Some("absent"), "absent", &NoopObserver).unwrap();
}

#[test]
fn rename_refuses_a_name_in_use_a_missing_branch_and_a_detached_head() {
    let (_dir, layout, root, _tip) = repo();
    refs::write_ref(&layout, "old", &root).unwrap();
    let err = branch::rename(&layout, Some("old"), "main", &NoopObserver).unwrap_err();
    assert!(
        matches!(err, Error::AlreadyExists(ref n) if n == "main"),
        "{err:?}"
    );
    assert_eq!(refs::read_ref(&layout, "old").unwrap(), Some(root));

    let err = branch::rename(&layout, Some("absent"), "new", &NoopObserver).unwrap_err();
    assert!(
        matches!(err, Error::NotFound(ref n) if n == "absent"),
        "{err:?}"
    );

    refs::write_head_detached(&layout, &root).unwrap();
    let err = branch::rename(&layout, None, "new", &NoopObserver).unwrap_err();
    assert!(matches!(err, Error::DetachedHead), "{err:?}");
    assert_eq!(
        err.to_string(),
        "cannot rename: HEAD is detached (specify <old> <new>)"
    );
}

/// A linked tree `tree` next to the main tree, with `topic` checked out.
fn link_tree(layout: &RepoLayout, base: &std::path::Path) {
    let tree = base.join("tree");
    let state = layout.worktree_state_dir_for("tree");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(state.join(layout::COMMONDIR_FILE_NAME), b"../..\n").unwrap();
    std::fs::write(
        state.join(layout::BACKPOINTER_FILE_NAME),
        format!("{}\n", tree.join(kit_core::KIT_DIR).display()),
    )
    .unwrap();
    layout::write_pointer_file(&tree, &state).unwrap();
    let linked = layout::discover(&tree).unwrap();
    refs::write_head_branch(&linked, "topic").unwrap();
}

#[test]
fn a_branch_checked_out_in_a_sibling_tree_stays() {
    let (dir, layout, root, _tip) = repo();
    refs::write_ref(&layout, "topic", &root).unwrap();
    link_tree(&layout, dir.path());
    let err = branch::delete(&layout, "topic", &NoopObserver).unwrap_err();
    assert!(
        matches!(err, Error::CheckedOut { ref branch, .. } if branch == "topic"),
        "{err:?}"
    );
    assert!(
        err.to_string()
            .starts_with("branch 'topic' is checked out at '")
    );
    let err = branch::rename(&layout, Some("topic"), "other", &NoopObserver).unwrap_err();
    assert!(matches!(err, Error::CheckedOut { .. }), "{err:?}");
    assert_eq!(refs::read_ref(&layout, "topic").unwrap(), Some(root));
    assert_eq!(refs::read_ref(&layout, "other").unwrap(), None);
}

#[test]
fn list_gives_every_branch_with_its_tip() {
    let (_dir, layout, root, tip) = repo();
    refs::write_ref(&layout, "old", &root).unwrap();
    let mut listed = branch::list(&layout, &Query::default()).unwrap();
    listed.sort_by(|a, b| a.name.cmp(&b.name));
    assert_eq!(
        listed,
        vec![
            Branch {
                name: "main".to_owned(),
                hash: Some(tip),
                remote: false,
                subject: None
            },
            Branch {
                name: "old".to_owned(),
                hash: Some(root),
                remote: false,
                subject: None
            },
        ]
    );
    assert_eq!(branch::current(&layout).as_deref(), Some("main"));
}

#[test]
fn list_reads_the_first_line_of_each_tip_message_on_request() {
    let (_dir, layout, root, _tip) = repo();
    refs::write_ref(&layout, "old", &root).unwrap();
    let query = Query {
        subjects: true,
        ..Query::default()
    };
    let listed = branch::list(&layout, &query).unwrap();
    let subject = |name: &str| {
        listed
            .iter()
            .find(|b| b.name == name)
            .and_then(|b| b.subject.clone())
    };
    assert_eq!(subject("old").as_deref(), Some("root"));
    assert_eq!(subject("main").as_deref(), Some("tip"));
}

#[test]
fn list_keeps_the_names_that_match_a_pattern() {
    let (_dir, layout, root, _tip) = repo();
    refs::write_ref(&layout, "feature/a", &root).unwrap();
    refs::write_ref(&layout, "feature/b", &root).unwrap();
    let patterns = ["feature/*".to_owned()];
    let query = Query {
        patterns: &patterns,
        ..Query::default()
    };
    let mut listed = branch::list(&layout, &query).unwrap();
    listed.sort_by(|a, b| a.name.cmp(&b.name));
    assert_eq!(names(&listed), ["feature/a", "feature/b"]);
}

#[test]
fn list_filters_by_ancestry() {
    let (_dir, layout, root, _tip) = repo();
    refs::write_ref(&layout, "old", &root).unwrap();
    let only = |query: Query<'_>| {
        let mut listed = branch::list(&layout, &query).unwrap();
        listed.sort_by(|a, b| a.name.cmp(&b.name));
        listed.into_iter().map(|b| b.name).collect::<Vec<_>>()
    };
    // Both tips have the root as an ancestor.
    assert_eq!(
        only(Query {
            contains: Some("old"),
            ..Query::default()
        }),
        ["main", "old"]
    );
    // Only `main` contains its own tip's parent chain beyond `old`.
    assert_eq!(
        only(Query {
            no_contains: Some("main"),
            ..Query::default()
        }),
        ["old"]
    );
    assert_eq!(
        only(Query {
            merged: Some("old"),
            ..Query::default()
        }),
        ["old"]
    );
    assert_eq!(
        only(Query {
            no_merged: Some("old"),
            ..Query::default()
        }),
        ["main"]
    );
}

#[test]
fn a_filter_that_does_not_name_a_commit_is_an_error() {
    let (_dir, layout, _root, _tip) = repo();
    let query = Query {
        contains: Some("nope"),
        ..Query::default()
    };
    let err = branch::list(&layout, &query).unwrap_err();
    assert!(matches!(err, Error::BadRevision { .. }), "{err:?}");
    assert!(err.to_string().starts_with("bad revision 'nope': "));
}

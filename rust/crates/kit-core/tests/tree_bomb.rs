//! A tree bomb: trees T1..Tn each hold two entries `a` and `b` that both name
//! T(k-1), and T0 holds one file. The store holds `n + 2` objects, but the
//! trees expand to `2^n` paths. Every tree walker refuses one past the cap
//! before it allocates or writes, in time that does not depend on `n`.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::time::{Duration, Instant};

use kit_core::index::{self, IndexError};
use kit_core::layout::RepoLayout;
use kit_core::ops::restore::{self, RestoreError, RestoreOptions, restore_tree_to_worktree};
use kit_core::{
    Blob, EntryMode, Object, ObjectStore, StoreError, Tree, TreeEntry, diff_trees, serialize,
};
use tempfile::TempDir;

type Hash = [u8; 32];

/// What a refusal may take: a walk of the 2^levels paths takes minutes.
const FAST: Duration = Duration::from_secs(10);

fn put(store: &ObjectStore, obj: &Object) -> Hash {
    store.write(&serialize::serialize(obj).unwrap()).unwrap()
}

fn tree_entry(name: &[u8], mode: EntryMode, object_hash: Hash) -> TreeEntry {
    TreeEntry {
        name: name.to_vec(),
        mode,
        object_hash,
    }
}

/// `levels` trees over one file, each naming the level below twice.
fn tree_bomb(store: &ObjectStore, levels: usize) -> Hash {
    let blob = put(
        store,
        &Object::Blob(Blob {
            data: b"x\n".to_vec(),
        }),
    );
    let mut cur = put(
        store,
        &Object::Tree(Tree {
            entries: vec![tree_entry(b"f", EntryMode::Blob, blob)],
        }),
    );
    for _ in 0..levels {
        cur = put(
            store,
            &Object::Tree(Tree {
                entries: vec![
                    tree_entry(b"a", EntryMode::Tree, cur),
                    tree_entry(b"b", EntryMode::Tree, cur),
                ],
            }),
        );
    }
    cur
}

fn open() -> (TempDir, ObjectStore) {
    let dir = TempDir::new().unwrap();
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
    (dir, store)
}

fn is_too_large(error: &StoreError) -> bool {
    matches!(error, StoreError::TreeTooLarge)
}

#[test]
fn every_walker_refuses_a_tree_past_the_cap_in_bounded_time() {
    // 2^22 is past the cap; 2^60 would never finish if any walker visited it.
    for levels in [22usize, 60] {
        let (_dir, store) = open();
        let root = tree_bomb(&store, levels);
        let worktree = TempDir::new().unwrap();

        let started = Instant::now();
        let from_tree = index::from_tree(&store, root).unwrap_err();
        let diff = diff_trees(&store, None, Some(root)).unwrap_err();
        let diff_old = diff_trees(&store, Some(root), None).unwrap_err();
        let restore =
            restore_tree_to_worktree(&store, &root, worktree.path(), &RestoreOptions::default())
                .unwrap_err();
        let nested = restore::check_nested_repositories(
            &store,
            root,
            worktree.path(),
            &RestoreOptions::default(),
            None,
        )
        .unwrap_err();
        let took = started.elapsed();

        assert!(
            matches!(&from_tree, IndexError::Store(e) if is_too_large(e)),
            "{from_tree:?}"
        );
        assert!(is_too_large(&diff), "{diff:?}");
        assert!(is_too_large(&diff_old), "{diff_old:?}");
        for error in [&restore, &nested] {
            assert!(
                matches!(error, RestoreError::Store(e) if is_too_large(e)),
                "{error:?}"
            );
        }
        assert!(took < FAST, "n={levels} took {took:?}");
        assert_eq!(
            std::fs::read_dir(worktree.path()).unwrap().count(),
            0,
            "a refused restore writes nothing"
        );
    }
}

#[test]
fn a_tree_that_shares_subtrees_but_stays_under_the_cap_still_walks() {
    let (_dir, store) = open();
    let root = tree_bomb(&store, 6);

    assert_eq!(index::from_tree(&store, root).unwrap().entries.len(), 64);
    assert_eq!(
        diff_trees(&store, None, Some(root)).unwrap().entries.len(),
        64
    );
    let worktree = TempDir::new().unwrap();
    let report =
        restore_tree_to_worktree(&store, &root, worktree.path(), &RestoreOptions::default())
            .unwrap();
    assert_eq!(report.files_written, 64);
}

#[test]
fn a_tree_of_empty_directories_is_refused_too() {
    // 2^40 directories and not one file: a count of files alone sees nothing.
    let (_dir, store) = open();
    let mut cur = put(&store, &Object::Tree(Tree { entries: vec![] }));
    for _ in 0..40 {
        cur = put(
            &store,
            &Object::Tree(Tree {
                entries: vec![
                    tree_entry(b"a", EntryMode::Tree, cur),
                    tree_entry(b"b", EntryMode::Tree, cur),
                ],
            }),
        );
    }
    let worktree = TempDir::new().unwrap();

    let started = Instant::now();
    let from_tree = index::from_tree(&store, cur).unwrap_err();
    let diff = diff_trees(&store, None, Some(cur)).unwrap_err();
    let restore =
        restore_tree_to_worktree(&store, &cur, worktree.path(), &RestoreOptions::default())
            .unwrap_err();
    assert!(
        matches!(&from_tree, IndexError::Store(e) if is_too_large(e)),
        "{from_tree:?}"
    );
    assert!(is_too_large(&diff), "{diff:?}");
    assert!(
        matches!(&restore, RestoreError::Store(e) if is_too_large(e)),
        "{restore:?}"
    );
    assert!(started.elapsed() < FAST);
    assert_eq!(std::fs::read_dir(worktree.path()).unwrap().count(), 0);
}

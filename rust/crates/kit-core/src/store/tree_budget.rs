//! A cap on how many files one tree may expand to.
//!
//! A tree entry names a child by hash, so many entries may name the same
//! child. A chain of trees that each name the level below twice holds `n + 2`
//! objects and `2^n` paths. Every path walker would visit each of those paths.
//! [`check_tree_leaves`] counts the leaves once per distinct tree and refuses a
//! tree past [`MAX_TREE_LEAVES`] before a walker allocates or writes anything.

use std::collections::HashMap;

use crate::hash::Hash;
use crate::object::{EntryMode, Object};

use super::{MAX_TREE_DEPTH, ObjectSource, StoreError, StoreResult};

/// The most files, symlinks and executables one tree may expand to. It is the
/// entry count [`crate::index::MAX_INDEX_BYTES`] is sized for, so a tree under
/// the cap always fits in an index.
pub const MAX_TREE_LEAVES: u64 = 2_000_000;

/// Refuse a tree that expands to more than [`MAX_TREE_LEAVES`] leaves.
///
/// Each distinct tree is read once, so the cost is linear in the number of
/// tree objects however many paths they expand to. A root that is not a tree
/// passes: the walker that follows reports that on its own.
///
/// # Errors
/// [`StoreError::TreeTooLarge`] past the cap, [`StoreError::TreeTooDeep`] past
/// [`MAX_TREE_DEPTH`], and any error reading a tree.
pub fn check_tree_leaves<S: ObjectSource + ?Sized>(store: &S, root: Hash) -> StoreResult<()> {
    check_tree_leaves_within(store, root, MAX_TREE_LEAVES)
}

pub(crate) fn check_tree_leaves_within<S: ObjectSource + ?Sized>(
    store: &S,
    root: Hash,
    limit: u64,
) -> StoreResult<()> {
    let mut seen = HashMap::new();
    count_leaves(store, root, limit, &mut seen, 0).map(|_| ())
}

/// The leaf count of `tree`, memoised by tree id. A count past `limit` fails.
fn count_leaves<S: ObjectSource + ?Sized>(
    store: &S,
    tree: Hash,
    limit: u64,
    seen: &mut HashMap<Hash, u64>,
    depth: usize,
) -> StoreResult<u64> {
    if let Some(&n) = seen.get(&tree) {
        return Ok(n);
    }
    if depth > MAX_TREE_DEPTH {
        return Err(StoreError::TreeTooDeep);
    }
    let Object::Tree(t) = store.read_object(&tree)? else {
        return Ok(0);
    };
    let mut total = 0u64;
    for entry in &t.entries {
        total += match entry.mode {
            EntryMode::Tree => count_leaves(store, entry.object_hash, limit, seen, depth + 1)?,
            EntryMode::Blob | EntryMode::Executable | EntryMode::Symlink => 1,
        };
        if total > limit {
            return Err(StoreError::TreeTooLarge { limit });
        }
    }
    seen.insert(tree, total);
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::RepoLayout;
    use crate::object::{Blob, Tree, TreeEntry};
    use crate::serialize;
    use crate::store::ObjectStore;
    use tempfile::TempDir;

    fn put(store: &ObjectStore, obj: &Object) -> Hash {
        store.write(&serialize::serialize(obj).unwrap()).unwrap()
    }

    fn entry(name: &[u8], mode: EntryMode, object_hash: Hash) -> TreeEntry {
        TreeEntry {
            name: name.to_vec(),
            mode,
            object_hash,
        }
    }

    /// `levels` trees that each name the level below twice, over one file.
    fn bomb(store: &ObjectStore, levels: usize) -> Hash {
        let blob = put(store, &Object::Blob(Blob { data: b"x".to_vec() }));
        let mut cur = put(
            store,
            &Object::Tree(Tree {
                entries: vec![entry(b"f", EntryMode::Blob, blob)],
            }),
        );
        for _ in 0..levels {
            cur = put(
                store,
                &Object::Tree(Tree {
                    entries: vec![
                        entry(b"a", EntryMode::Tree, cur),
                        entry(b"b", EntryMode::Tree, cur),
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

    #[test]
    fn a_tree_at_the_limit_passes_and_one_past_it_fails() {
        let (_dir, store) = open();
        // 2^9 = 512 leaves.
        let root = bomb(&store, 9);
        check_tree_leaves_within(&store, root, 512).unwrap();
        let err = check_tree_leaves_within(&store, root, 511).unwrap_err();
        assert!(matches!(err, StoreError::TreeTooLarge { limit: 511 }));
    }

    #[test]
    fn a_shared_subtree_is_read_once() {
        let (_dir, store) = open();
        // 2^100 leaves from 102 objects: the walk must stop at the cap and
        // never visit the paths.
        let root = bomb(&store, 100);
        let started = std::time::Instant::now();
        let err = check_tree_leaves(&store, root).unwrap_err();
        assert!(matches!(err, StoreError::TreeTooLarge { .. }));
        assert!(started.elapsed().as_secs() < 5);
    }

    #[test]
    fn a_wide_tree_counts_each_entry() {
        let (_dir, store) = open();
        let blob = put(&store, &Object::Blob(Blob { data: b"x".to_vec() }));
        let entries = (0..1000)
            .map(|i| entry(format!("f{i:04}").as_bytes(), EntryMode::Blob, blob))
            .collect();
        let root = put(&store, &Object::Tree(Tree { entries }));
        check_tree_leaves_within(&store, root, 1000).unwrap();
        assert!(check_tree_leaves_within(&store, root, 999).is_err());
    }

    #[test]
    fn a_blob_root_passes_for_the_walker_to_report() {
        let (_dir, store) = open();
        let blob = put(&store, &Object::Blob(Blob { data: b"x".to_vec() }));
        check_tree_leaves(&store, blob).unwrap();
    }
}

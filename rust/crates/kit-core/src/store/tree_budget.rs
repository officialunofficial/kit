//! A cap on how large one tree may expand.
//!
//! A tree entry names a child by hash, so many entries may name the same
//! child. A chain of trees that each name the level below twice holds `n + 2`
//! objects and `2^n` paths. Every path walker would visit each of those paths,
//! and long entry names make each path large. [`check_tree_leaves`] sizes the
//! expansion once per distinct tree and refuses a tree that is past
//! [`MAX_TREE_LEAVES`] files, or whose paths would not fit in an index file
//! ([`crate::index::MAX_INDEX_BYTES`]), before a walker allocates or writes
//! anything.

use std::collections::HashMap;

use crate::hash::Hash;
use crate::index::MAX_INDEX_BYTES;
use crate::object::{EntryMode, Object};

use super::{MAX_TREE_DEPTH, ObjectSource, StoreError, StoreResult};

/// The most files, symlinks and executables one tree may expand to. It is the
/// entry count [`crate::index::MAX_INDEX_BYTES`] is sized for.
pub const MAX_TREE_LEAVES: u64 = 2_000_000;

/// Bytes of an index file besides its entries: header and checksum (SPEC-INDEX §5).
const INDEX_HEADER_BYTES: u64 = 41;
/// Bytes of an index entry besides its path (SPEC-INDEX §5).
const INDEX_ENTRY_FIXED_BYTES: u64 = 67;

/// The most entries, files and directories together, one tree may expand to.
/// A tree of [`MAX_TREE_LEAVES`] files may also hold a directory for each.
const MAX_TREE_ENTRIES: u64 = 2 * MAX_TREE_LEAVES;

/// What a tree expands to: its files, every entry (a directory entry counts
/// besides what lies below it, so a tree of empty directories is sized too),
/// and the bytes an index holds for the files.
#[derive(Clone, Copy, Default)]
struct Size {
    leaves: u64,
    entries: u64,
    index_bytes: u64,
}

/// What a size may not pass.
#[derive(Clone, Copy)]
struct Caps {
    leaves: u64,
    entries: u64,
    index_bytes: u64,
}

/// Refuse a tree that expands to more than [`MAX_TREE_LEAVES`] leaves, to more
/// than twice that many entries counting directories, or to paths an index
/// file could not hold. A tree under the caps always fits in an index.
///
/// Each distinct tree is read once, so the cost is linear in the number of
/// tree objects however many paths they expand to. A root that is not a tree
/// passes: the walker that follows reports that on its own.
///
/// # Errors
/// [`StoreError::TreeTooLarge`] past a cap, [`StoreError::TreeTooDeep`] past
/// [`MAX_TREE_DEPTH`], and any error reading a tree.
pub fn check_tree_leaves<S: ObjectSource + ?Sized>(store: &S, root: Hash) -> StoreResult<()> {
    check_within(
        store,
        root,
        Caps {
            leaves: MAX_TREE_LEAVES,
            entries: MAX_TREE_ENTRIES,
            index_bytes: MAX_INDEX_BYTES - INDEX_HEADER_BYTES,
        },
    )
}

fn check_within<S: ObjectSource + ?Sized>(store: &S, root: Hash, caps: Caps) -> StoreResult<()> {
    let mut seen = HashMap::new();
    measure(store, root, caps, &mut seen, 0).map(|_| ())
}

/// A budget for one walk that visits only some of a tree's entries, such as a
/// diff or a merge, and so must not size whole trees up front. It counts the
/// entries the walk compares and the entries of each subtree it takes whole,
/// files and directories both, and refuses past twice [`MAX_TREE_LEAVES`]. It
/// also counts the bytes of the paths the walk may build, with each path's
/// whole prefix, and refuses past twice what an index file holds. Subtrees are
/// sized with one memo for the walk.
pub(crate) struct WalkBudget {
    used: u64,
    limit: u64,
    bytes: u64,
    byte_limit: u64,
    seen: HashMap<Hash, Size>,
}

impl WalkBudget {
    pub(crate) fn new() -> Self {
        let mut budget = Self::with_limit(MAX_TREE_ENTRIES);
        budget.byte_limit *= 2;
        budget
    }

    pub(crate) fn with_limit(limit: u64) -> Self {
        Self {
            used: 0,
            limit,
            bytes: 0,
            byte_limit: MAX_INDEX_BYTES - INDEX_HEADER_BYTES,
            seen: HashMap::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_byte_limit(byte_limit: u64) -> Self {
        let mut budget = Self::with_limit(u64::MAX);
        budget.byte_limit = byte_limit;
        budget
    }

    fn check(&self) -> StoreResult<()> {
        if self.used > self.limit || self.bytes > self.byte_limit {
            return Err(StoreError::TreeTooLarge);
        }
        Ok(())
    }

    /// Count one compared entry whose path is `path_len` bytes long.
    pub(crate) fn visit(&mut self, path_len: usize) -> StoreResult<()> {
        self.used += 1;
        self.bytes += INDEX_ENTRY_FIXED_BYTES + path_len as u64;
        self.check()
    }

    /// Count the entries of `tree`, which the walk takes whole below a
    /// directory whose path is `prefix_len` bytes long.
    pub(crate) fn take_subtree<S: ObjectSource + ?Sized>(
        &mut self,
        store: &S,
        tree: Hash,
        prefix_len: usize,
    ) -> StoreResult<()> {
        let left = self.limit.saturating_sub(self.used);
        let caps = Caps {
            leaves: left,
            entries: left,
            index_bytes: self.byte_limit.saturating_sub(self.bytes),
        };
        let size = measure(store, tree, caps, &mut self.seen, 0)?;
        self.used += size.entries;
        self.bytes += size.index_bytes + size.leaves * (prefix_len as u64 + 1);
        self.check()
    }
}

/// The size of `tree`, memoised by tree id. A size past a cap fails.
fn measure<S: ObjectSource + ?Sized>(
    store: &S,
    tree: Hash,
    caps: Caps,
    seen: &mut HashMap<Hash, Size>,
    depth: usize,
) -> StoreResult<Size> {
    if let Some(&size) = seen.get(&tree) {
        return Ok(size);
    }
    if depth > MAX_TREE_DEPTH {
        return Err(StoreError::TreeTooDeep);
    }
    let Object::Tree(t) = store.read_object(&tree)? else {
        return Ok(Size::default());
    };
    let mut total = Size::default();
    for entry in &t.entries {
        // The path of each leaf below grows by this name and a `/`.
        let name = entry.name.len() as u64;
        match entry.mode {
            EntryMode::Tree => {
                let sub = measure(store, entry.object_hash, caps, seen, depth + 1)?;
                total.leaves += sub.leaves;
                total.entries += 1 + sub.entries;
                total.index_bytes += sub.index_bytes + sub.leaves * (name + 1);
            }
            EntryMode::Blob | EntryMode::Executable | EntryMode::Symlink => {
                total.leaves += 1;
                total.entries += 1;
                total.index_bytes += INDEX_ENTRY_FIXED_BYTES + name;
            }
        }
        if total.leaves > caps.leaves
            || total.entries > caps.entries
            || total.index_bytes > caps.index_bytes
        {
            return Err(StoreError::TreeTooLarge);
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
        let blob = put(
            store,
            &Object::Blob(Blob {
                data: b"x".to_vec(),
            }),
        );
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

    fn caps(leaves: u64, entries: u64, index_bytes: u64) -> Caps {
        Caps {
            leaves,
            entries,
            index_bytes,
        }
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
        check_within(&store, root, caps(512, u64::MAX, u64::MAX)).unwrap();
        let err = check_within(&store, root, caps(511, u64::MAX, u64::MAX)).unwrap_err();
        assert!(matches!(err, StoreError::TreeTooLarge));
    }

    #[test]
    fn a_subtree_taken_whole_counts_its_paths_below_the_prefix() {
        let (_dir, store) = open();
        let blob = put(
            &store,
            &Object::Blob(Blob {
                data: b"x".to_vec(),
            }),
        );
        let tree = put(
            &store,
            &Object::Tree(Tree {
                entries: vec![
                    entry(b"a", EntryMode::Blob, blob),
                    entry(b"b", EntryMode::Blob, blob),
                ],
            }),
        );
        // Two files under a 100 byte directory: 2 * (67 + 1) for the entries
        // as named in the tree, and 101 more bytes of prefix and `/` each.
        let exact = 2 * (67 + 1) + 2 * 101;
        let take =
            |byte_limit| WalkBudget::with_byte_limit(byte_limit).take_subtree(&store, tree, 100);
        take(exact).unwrap();
        assert!(matches!(take(exact - 1), Err(StoreError::TreeTooLarge)));
    }

    #[test]
    fn a_directory_name_counts_in_the_path_of_each_file_below_it() {
        let (_dir, store) = open();
        let blob = put(
            &store,
            &Object::Blob(Blob {
                data: b"x".to_vec(),
            }),
        );
        let inner = put(
            &store,
            &Object::Tree(Tree {
                entries: vec![
                    entry(b"a", EntryMode::Blob, blob),
                    entry(b"b", EntryMode::Blob, blob),
                ],
            }),
        );
        let root = put(
            &store,
            &Object::Tree(Tree {
                entries: vec![entry(b"0123456789", EntryMode::Tree, inner)],
            }),
        );
        // Two files named `a` and `b` under a 10 byte directory: 2 * (67 + 1)
        // for the entries and 11 more bytes of directory and `/` each.
        let exact = 2 * (67 + 1) + 2 * 11;
        check_within(&store, root, caps(u64::MAX, u64::MAX, exact)).unwrap();
        let err = check_within(&store, root, caps(u64::MAX, u64::MAX, exact - 1)).unwrap_err();
        assert!(matches!(err, StoreError::TreeTooLarge));
    }

    #[test]
    fn nesting_is_allowed_to_the_limit_and_refused_one_past_it() {
        let (_dir, store) = open();
        let blob = put(
            &store,
            &Object::Blob(Blob {
                data: b"x".to_vec(),
            }),
        );
        let mut cur = put(
            &store,
            &Object::Tree(Tree {
                entries: vec![entry(b"f", EntryMode::Blob, blob)],
            }),
        );
        let wrap = |inner| {
            put(
                &store,
                &Object::Tree(Tree {
                    entries: vec![entry(b"d", EntryMode::Tree, inner)],
                }),
            )
        };
        // The root is at depth 0, so the file's own tree is at depth
        // MAX_TREE_DEPTH once there are that many directories above it.
        for _ in 0..MAX_TREE_DEPTH {
            cur = wrap(cur);
        }
        check_tree_leaves(&store, cur).unwrap();
        cur = wrap(cur);
        assert!(matches!(
            check_tree_leaves(&store, cur),
            Err(StoreError::TreeTooDeep)
        ));
    }

    #[test]
    fn a_shared_subtree_is_read_once() {
        let (_dir, store) = open();
        // 2^100 leaves from 102 objects: the walk must stop at the cap and
        // never visit the paths.
        let root = bomb(&store, 100);
        let err = check_tree_leaves(&store, root).unwrap_err();
        assert!(matches!(err, StoreError::TreeTooLarge));
    }

    #[test]
    fn a_wide_tree_counts_each_entry() {
        let (_dir, store) = open();
        let blob = put(
            &store,
            &Object::Blob(Blob {
                data: b"x".to_vec(),
            }),
        );
        let entries = (0..1000)
            .map(|i| entry(format!("f{i:04}").as_bytes(), EntryMode::Blob, blob))
            .collect();
        let root = put(&store, &Object::Tree(Tree { entries }));
        check_within(&store, root, caps(1000, u64::MAX, u64::MAX)).unwrap();
        assert!(check_within(&store, root, caps(999, u64::MAX, u64::MAX)).is_err());
    }

    #[test]
    fn index_bytes_match_what_an_index_serialises_to() {
        let (_dir, store) = open();
        // `a/b/c.txt`, one entry under two directories.
        let blob = put(
            &store,
            &Object::Blob(Blob {
                data: b"x".to_vec(),
            }),
        );
        let inner = put(
            &store,
            &Object::Tree(Tree {
                entries: vec![entry(b"c.txt", EntryMode::Blob, blob)],
            }),
        );
        let mid = put(
            &store,
            &Object::Tree(Tree {
                entries: vec![entry(b"b", EntryMode::Tree, inner)],
            }),
        );
        let root = put(
            &store,
            &Object::Tree(Tree {
                entries: vec![entry(b"a", EntryMode::Tree, mid)],
            }),
        );
        let size = measure(
            &store,
            root,
            caps(u64::MAX, u64::MAX, u64::MAX),
            &mut HashMap::new(),
            0,
        )
        .unwrap();
        let idx = crate::index::from_tree(&store, root).unwrap();
        assert_eq!(size.leaves, 1);
        assert_eq!(
            INDEX_HEADER_BYTES + size.index_bytes,
            idx.serialize().len() as u64,
            "header and checksum + entries"
        );
        assert!(check_within(&store, root, caps(1, u64::MAX, INDEX_ENTRY_FIXED_BYTES + 9)).is_ok());
        assert!(
            check_within(&store, root, caps(1, u64::MAX, INDEX_ENTRY_FIXED_BYTES + 8)).is_err()
        );
    }

    #[test]
    fn long_names_trip_the_byte_cap_under_the_file_cap() {
        let (_dir, store) = open();
        // 2^17 leaves of ~4 KiB paths: far under 2,000,000 files, far over an
        // index file's bytes.
        let name = vec![b'n'; 255];
        let blob = put(
            &store,
            &Object::Blob(Blob {
                data: b"x".to_vec(),
            }),
        );
        let mut cur = put(
            &store,
            &Object::Tree(Tree {
                entries: vec![entry(&name, EntryMode::Blob, blob)],
            }),
        );
        for i in 0..17 {
            let (a, b) = (
                format!("a{}", "x".repeat(250 - i % 3)),
                format!("b{}", "y".repeat(250)),
            );
            cur = put(
                &store,
                &Object::Tree(Tree {
                    entries: vec![
                        entry(a.as_bytes(), EntryMode::Tree, cur),
                        entry(b.as_bytes(), EntryMode::Tree, cur),
                    ],
                }),
            );
        }
        let err = check_tree_leaves(&store, cur).unwrap_err();
        assert!(matches!(err, StoreError::TreeTooLarge));
    }

    #[test]
    fn a_tree_of_empty_directories_is_sized_by_its_entries() {
        let (_dir, store) = open();
        // 2^60 empty directories from 62 objects: no file anywhere.
        let empty = put(&store, &Object::Tree(Tree { entries: vec![] }));
        let mut cur = empty;
        for _ in 0..60 {
            cur = put(
                &store,
                &Object::Tree(Tree {
                    entries: vec![
                        entry(b"a", EntryMode::Tree, cur),
                        entry(b"b", EntryMode::Tree, cur),
                    ],
                }),
            );
        }
        assert!(matches!(
            check_tree_leaves(&store, cur),
            Err(StoreError::TreeTooLarge)
        ));
        assert!(matches!(
            WalkBudget::new().take_subtree(&store, cur, 0),
            Err(StoreError::TreeTooLarge)
        ));
    }

    #[test]
    fn a_blob_root_passes_for_the_walker_to_report() {
        let (_dir, store) = open();
        let blob = put(
            &store,
            &Object::Blob(Blob {
                data: b"x".to_vec(),
            }),
        );
        check_tree_leaves(&store, blob).unwrap();
    }
}

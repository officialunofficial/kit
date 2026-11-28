//! Read sessions: one walk of many reads that verifies each tree once and
//! checks each local pack once.
//!
//! A checkout reads every tree of its target several times: the safety
//! check, the tree budget, the name checks, the write and the index build.
//! Outside a session each read verifies the tree again, which recomputes the
//! BMT id over every entry, and checks again that the pack it came from is
//! still current. Inside a session the first read of a tree verifies it and
//! keeps the decoded tree, and later reads of the same id return that tree.
//! An object id names its bytes, so a tree verified once is the tree for the
//! rest of the session. A session also holds a [`PruneGuard`], which keeps gc
//! and index repair from retiring a pack, so one currency check per pack
//! stands for every read through it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use crate::hash::Hash;
use crate::object::Tree;

use super::local_pack::Currency;
use super::{ObjectStore, PruneGuard};

/// The tree entries a session keeps at most, over all of its trees. A walk
/// past this reads and verifies the trees it cannot keep, as a read outside a
/// session does.
pub(crate) const MAX_SESSION_TREE_ENTRIES: usize = 1 << 20;

/// The state of the session that is open on a store, shared by its clones.
#[derive(Debug, Default)]
pub(crate) struct SessionSlot(RwLock<Option<Arc<SessionState>>>);

impl SessionSlot {
    pub(crate) fn current(&self) -> Option<Arc<SessionState>> {
        self.0.read().expect("read session slot").clone()
    }
}

#[derive(Debug)]
pub(crate) struct SessionState {
    /// Present when the session holds a guard. Without one, every read
    /// checks its pack, as a read outside a session does.
    currency: Option<Currency>,
    trees: Mutex<TreeCache>,
}

#[derive(Debug, Default)]
struct TreeCache {
    by_id: HashMap<Hash, Arc<Tree>>,
    entries: usize,
}

impl SessionState {
    pub(crate) fn currency(&self) -> Option<&Currency> {
        self.currency.as_ref()
    }

    /// The verified tree with this id, if the session has read it.
    pub(crate) fn tree(&self, id: &Hash) -> Option<Tree> {
        let cache = self.trees.lock().expect("session tree cache");
        cache.by_id.get(id).map(|tree| Tree::clone(tree))
    }

    /// Keep `tree`, which a read verified against `id`.
    pub(crate) fn keep_tree(&self, id: Hash, tree: &Tree) {
        let mut cache = self.trees.lock().expect("session tree cache");
        if cache.by_id.contains_key(&id) {
            return;
        }
        let entries = tree.entries.len().max(1);
        if cache.entries + entries > MAX_SESSION_TREE_ENTRIES {
            return;
        }
        cache.entries += entries;
        cache.by_id.insert(id, Arc::new(tree.clone()));
    }
}

/// An open read session. Reads of the store and of its clones run in the
/// session until it drops. See the module docs.
#[must_use = "the session lasts only while it is alive"]
#[derive(Debug)]
pub struct ReadSession<'a> {
    store: &'a ObjectStore,
    /// Whether this value opened the session, and closes it on drop. A
    /// session opened inside another one joins it.
    owner: bool,
    _guard: Option<PruneGuard>,
}

impl ObjectStore {
    /// Open a read session on this store, or join the one that is open.
    ///
    /// The session takes a [`PruneGuard`] when it can. When the guard cannot
    /// be taken, the session still verifies each tree once, and every read
    /// checks its pack as before.
    ///
    /// # Panics
    /// If a thread panicked while it held the session slot's lock.
    pub fn read_session(&self) -> ReadSession<'_> {
        let mut slot = self.session.0.write().expect("read session slot");
        if slot.is_some() {
            return ReadSession {
                store: self,
                owner: false,
                _guard: None,
            };
        }
        let guard = self.prune_guard().ok();
        *slot = Some(Arc::new(SessionState {
            currency: guard.as_ref().map(|_| Currency::default()),
            trees: Mutex::default(),
        }));
        ReadSession {
            store: self,
            owner: true,
            _guard: guard,
        }
    }
}

impl Drop for ReadSession<'_> {
    fn drop(&mut self) {
        if self.owner {
            // Close the session before the guard drops, so no read relies
            // on a currency check that the guard no longer backs.
            *self.store.session.0.write().expect("read session slot") = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::RepoLayout;
    use crate::object::{Blob, EntryMode, Object, TreeEntry};
    use crate::serialize::serialize;
    use crate::store::StoreError;

    fn fresh() -> (tempfile::TempDir, ObjectStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
        (dir, store)
    }

    fn tree_of(store: &ObjectStore, names: &[&str]) -> Hash {
        let blob = store
            .write(
                &serialize(&Object::Blob(Blob {
                    data: b"x".to_vec(),
                }))
                .unwrap(),
            )
            .unwrap();
        let entries = names
            .iter()
            .map(|name| TreeEntry {
                name: name.as_bytes().to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob,
            })
            .collect();
        store
            .write(&serialize(&Object::Tree(Tree { entries })).unwrap())
            .unwrap()
    }

    #[test]
    fn a_session_reads_and_verifies_a_tree_once() {
        let (_dir, store) = fresh();
        let tree = tree_of(&store, &["a", "b"]);
        let session = store.read_session();
        let first = store.read_object(&tree).unwrap();
        let reads = store.read_call_count();
        // A clone of the store reads in the same session.
        let second = store.clone().read_object(&tree).unwrap();
        assert_eq!(store.read_call_count(), reads, "the second read is kept");
        assert_eq!(first, second);
        drop(session);
        store.read_object(&tree).unwrap();
        assert_eq!(store.read_call_count(), reads + 1, "closed: read again");
    }

    #[test]
    fn a_corrupted_tree_fails_every_read_in_a_session() {
        let (_dir, store) = fresh();
        let tree = tree_of(&store, &["a"]);
        let path = store.path_for(&tree);
        let mut bytes = std::fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        std::fs::write(&path, bytes).unwrap();
        let _session = store.read_session();
        for _ in 0..2 {
            assert!(matches!(
                store.read_object(&tree),
                Err(StoreError::HashMismatch { .. })
            ));
        }
    }

    #[test]
    fn a_session_opened_inside_another_joins_it_and_leaves_it_open() {
        let (_dir, store) = fresh();
        let tree = tree_of(&store, &["a"]);
        let outer = store.read_session();
        assert!(outer.owner);
        drop(store.read_session());
        store.read_object(&tree).unwrap();
        let reads = store.read_call_count();
        store.read_object(&tree).unwrap();
        assert_eq!(store.read_call_count(), reads, "the outer session is open");
        drop(outer);
        assert!(store.session.current().is_none());
    }

    #[test]
    fn a_session_with_a_guard_has_a_currency() {
        let (_dir, store) = fresh();
        let _session = store.read_session();
        assert!(store.session.current().unwrap().currency().is_some());
    }

    #[test]
    fn a_session_keeps_trees_up_to_its_entry_budget() {
        let state = SessionState {
            currency: None,
            trees: Mutex::default(),
        };
        let big = Tree {
            entries: vec![
                TreeEntry {
                    name: b"a".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: crate::hash::ZERO,
                };
                MAX_SESSION_TREE_ENTRIES
            ],
        };
        state.keep_tree([1; 32], &big);
        assert!(state.tree(&[1; 32]).is_some());
        state.keep_tree([2; 32], &Tree { entries: vec![] });
        assert!(state.tree(&[2; 32]).is_none(), "past the budget");
    }
}

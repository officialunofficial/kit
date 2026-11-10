//! Pushes through the push driver against the file transport, with a crash
//! between the packmap write and the head write of the two-ref advance.
//!
//! A reader takes no lock, and a crash can stop the advance after its first
//! rename, so either can see the new packmap with the old head. These tests
//! check that the old head stays rebuildable from that packmap: the driver
//! appends to the chain or re-baselines it, and both keep every pack the
//! chain listed.

use crate::FileTransport;
use crate::advance_fault::{self, Fault};
use kit_core::hash::Hash;
use kit_core::layout::RepoLayout;
use kit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use kit_core::ops::graph::reachable_objects;
use kit_core::pack::{self, PackReader};
use kit_core::protocol::{PackKey, RefWriteCondition, Transport};
use kit_core::store::ObjectStore;
use kit_core::{serialize, transfer};
use kit_sync::TransportSource;
use kit_sync::packmap::packmap_ref;
use kit_sync::push::{PushControl, PushError, push_branch_steps};
use std::path::Path;
use tempfile::TempDir;

const DEPTH: usize = 3;

fn store() -> (TempDir, ObjectStore) {
    let dir = TempDir::new().unwrap();
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
    (dir, store)
}

fn put(store: &ObjectStore, object: &Object) -> Hash {
    store.write(&serialize::serialize(object).unwrap()).unwrap()
}

fn commit(store: &ObjectStore, files: &[(&str, &str)], parents: &[Hash], seed: u8) -> Hash {
    let mut entries: Vec<TreeEntry> = files
        .iter()
        .map(|(name, data)| TreeEntry {
            name: name.as_bytes().to_vec(),
            mode: EntryMode::Blob,
            object_hash: put(
                store,
                &Object::Blob(Blob {
                    data: data.as_bytes().to_vec(),
                }),
            ),
        })
        .collect();
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    let tree = put(store, &Object::Tree(Tree { entries }));
    put(
        store,
        &Object::Commit(Commit::new_unannotated(
            tree,
            parents.to_vec(),
            Identity::ed25519([7; 32]),
            [0; 32],
            vec![seed],
            u64::from(seed),
            [0; 64],
        )),
    )
}

/// Push `tip` to `main` of the remote at `root`, through a fresh transport
/// as one `kit push` opens.
fn push(
    root: &Path,
    store: &ObjectStore,
    tip: Hash,
    condition: RefWriteCondition,
) -> Result<usize, PushError> {
    let remote = FileTransport::new(root);
    push_branch_steps(
        &TransportSource::new(&remote),
        store,
        "main",
        tip,
        condition,
        DEPTH,
        pack::MAX_TOTAL_PAYLOAD,
        &PushControl::default(),
        &mut |_| Ok(()),
    )
}

/// The packmap chain of `main`, newest node first.
fn chain(remote: &FileTransport) -> Vec<transfer::PackListNode> {
    let mut nodes = Vec::new();
    let mut cursor = remote.read_ref(&packmap_ref("main")).unwrap();
    while let Some(key) = cursor {
        let node =
            transfer::decode_packlist(&remote.download_blob(&PackKey::from_hash(key)).unwrap())
                .unwrap();
        cursor = node.prev;
        nodes.push(node);
    }
    nodes
}

/// Whether the packmap chain alone rebuilds the closure of `head`.
fn rebuilds(remote: &FileTransport, head: Hash) -> bool {
    let (_dir, fresh) = store();
    let mut nodes = chain(remote);
    nodes.reverse();
    for key in nodes.iter().flat_map(|node| &node.packs) {
        let bytes = remote.download_pack(&PackKey::from_hash(*key)).unwrap();
        if PackReader::read(&bytes, &fresh).is_err() {
            return false;
        }
    }
    reachable_objects(&fresh, &head).is_ok()
}

/// A crash after the packmap rename of the push that crosses the
/// re-baseline threshold. The push re-baselines, a fast-forward or not:
/// its node lists every pack of the chain it replaces, so it rebuilds the
/// head the crash left in place.
#[test]
fn a_crash_between_the_renames_of_a_push_leaves_the_old_head_rebuildable() {
    for fast_forward in [true, false] {
        let remote_dir = TempDir::new().unwrap();
        let root = remote_dir.path();
        let (_dir, store) = store();
        let c0 = commit(&store, &[("a", "zero")], &[], 0);
        let c1 = commit(&store, &[("a", "one"), ("keep", "kept")], &[c0], 1);
        let c2 = commit(&store, &[("a", "two"), ("keep", "kept")], &[c1], 2);
        push(root, &store, c0, RefWriteCondition::Missing).unwrap();
        push(root, &store, c1, RefWriteCondition::Match(c0)).unwrap();
        push(root, &store, c2, RefWriteCondition::Match(c1)).unwrap();
        assert_eq!(chain(&FileTransport::new(root)).len(), DEPTH);

        let tip = if fast_forward {
            commit(&store, &[("a", "three"), ("keep", "kept")], &[c2], 3)
        } else {
            commit(&store, &[("a", "aside")], &[c0], 4)
        };
        advance_fault::set(Fault::CrashAfterPackmap);
        assert!(push(root, &store, tip, RefWriteCondition::Match(c2)).is_err());

        let after = FileTransport::new(root);
        assert_eq!(after.read_ref("refs/heads/main").unwrap(), Some(c2));
        let nodes = chain(&after);
        assert_eq!(nodes.len(), 1, "fast-forward: {fast_forward}");
        assert_eq!(nodes[0].packs.len(), DEPTH + 1);
        assert!(rebuilds(&after, c2), "fast-forward: {fast_forward}");

        push(root, &store, tip, RefWriteCondition::Match(c2)).unwrap();
        let after = FileTransport::new(root);
        assert_eq!(after.read_ref("refs/heads/main").unwrap(), Some(tip));
        assert!(rebuilds(&after, tip), "fast-forward: {fast_forward}");
    }
}

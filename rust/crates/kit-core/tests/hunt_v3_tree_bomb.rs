//! Hunt V3a: a "tree bomb". Trees T1..Tn each hold two tree entries `a` and
//! `b` that both name T(k-1); T0 holds one blob `f`. The store holds n + 2
//! distinct objects, but every path walker expands 2^n leaves.
//!
//! `tree_bomb_expansion_is_bounded` FAILS today: it shows the leaf count of
//! `index::from_tree` and `diff_trees(None, root)` doubling per level while the
//! store stays at n + 2 objects, then asserts a fixed leaf budget for n = 20.
//!
//! The two `#[ignore]` tests are builders for the CLI runs: they write into an
//! existing kit repo named by `HUNT_V3_REPO` and print a signed commit id.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::time::Instant;

use kit_core::hash::ZERO;
use kit_core::index;
use kit_core::layout::RepoLayout;
use kit_core::object::{Commit, Identity};
use kit_core::sign::{KeyPair, sign_commit};
use kit_core::{Blob, EntryMode, Object, ObjectStore, Tree, TreeEntry, diff_trees, serialize};
use tempfile::TempDir;

type Hash = [u8; 32];

/// A leaf budget a guarded walker could enforce: the most entries one tree
/// object may hold (`serialize::MAX_TREE_ENTRIES`). 2^20 = 1,048,576 exceeds it.
const LEAF_BUDGET: usize = 1_000_000;

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

/// Build the doubling chain of `levels` trees over one blob. Returns the root.
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

#[test]
fn tree_bomb_expansion_is_bounded() {
    let mut last = None;
    for levels in [16usize, 18, 20] {
        let dir = TempDir::new().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
        let root = tree_bomb(&store, levels);
        let objects = store.iter_object_hashes().unwrap().len();

        let t = Instant::now();
        let idx = index::from_tree(&store, root).unwrap();
        let index_secs = t.elapsed().as_secs_f64();
        let index_entries = idx.entries.len();
        drop(idx);
        eprintln!(
            "n={levels} objects={objects} from_tree_entries={index_entries} \
             from_tree_secs={index_secs:.2}"
        );
        assert_eq!(objects, levels + 2, "store holds n + 2 distinct objects");
        assert_eq!(index_entries, 1usize << levels);
        if let Some(prev) = last {
            assert_eq!(index_entries, prev * 4, "two levels quadruple the leaves");
        }
        last = Some(index_entries);
        if levels == 20 {
            // What a budget would enforce: 22 objects must not seed an index
            // (or a checkout plan) of more leaves than one tree may hold.
            assert!(
                index_entries <= LEAF_BUDGET,
                "from_tree expanded {objects} objects into {index_entries} leaves \
                 (budget {LEAF_BUDGET}); no leaf, byte or disk budget applies"
            );
        }

        // The restore-safety check of clone/pull/checkout runs this diff.
        let t = Instant::now();
        let diff = diff_trees(&store, None, Some(root)).unwrap();
        let diff_secs = t.elapsed().as_secs_f64();
        eprintln!(
            "n={levels} diff_trees_entries={} diff_secs={diff_secs:.2}",
            diff.entries.len()
        );
        assert_eq!(diff.entries.len(), 1usize << levels);
    }
}

fn signed_commit(store: &ObjectStore, tree_hash: Hash) -> Hash {
    let kp = KeyPair::from_seed([0x33; 32]);
    let mut commit = Commit {
        tree_hash,
        parents: vec![],
        author: Identity::ed25519(kp.public.0),
        signer: kp.public.0,
        message: b"hunt v3".to_vec(),
        timestamp: 1_726_300_000,
        message_hash: ZERO,
        content_digest: ZERO,
        signature: [0u8; 64],
    };
    commit.signature = sign_commit(&commit, &kp).unwrap().0;
    put(store, &Object::Commit(commit))
}

fn repo_store() -> ObjectStore {
    let repo = std::env::var("HUNT_V3_REPO").expect("HUNT_V3_REPO names an initialized kit repo");
    ObjectStore::open(&RepoLayout::single(repo)).unwrap()
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// CLI builder: a tree bomb of `HUNT_V3_LEVELS` levels in `HUNT_V3_REPO`.
#[test]
#[ignore = "builder for the CLI run; needs HUNT_V3_REPO"]
fn build_tree_bomb_commit() {
    let store = repo_store();
    let root = tree_bomb(&store, env_usize("HUNT_V3_LEVELS", 14));
    let commit = signed_commit(&store, root);
    println!("COMMIT={}", kit_core::hash::to_hex(&commit));
}

/// CLI builder: a chain of `HUNT_V3_LEVELS` nested single-entry trees (V3c),
/// written in one batch so the run does not pay one flush per object.
#[test]
#[ignore = "builder for the CLI run; needs HUNT_V3_REPO"]
fn build_deep_chain_commit() {
    let store = repo_store();
    let levels = env_usize("HUNT_V3_LEVELS", 20_000);
    let mut batch = store.batch();
    let mut write = |obj: &Object| batch.write(&serialize::serialize(obj).unwrap()).unwrap();
    let blob = write(&Object::Blob(Blob {
        data: b"leaf\n".to_vec(),
    }));
    let mut cur = write(&Object::Tree(Tree {
        entries: vec![tree_entry(b"f", EntryMode::Blob, blob)],
    }));
    for _ in 0..levels {
        cur = write(&Object::Tree(Tree {
            entries: vec![tree_entry(b"d", EntryMode::Tree, cur)],
        }));
    }
    batch.commit().unwrap();
    let commit = signed_commit(&store, cur);
    println!("COMMIT={}", kit_core::hash::to_hex(&commit));
}

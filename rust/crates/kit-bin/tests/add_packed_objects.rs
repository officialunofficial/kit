//! Local staging reuses packed file content in a new process.
#![allow(clippy::unwrap_used)]

mod common;

use std::collections::HashSet;
use std::fs;

use common::Repo;
use kit_core::hash::{Hash, to_hex};
use kit_core::layout::RepoLayout;
use kit_core::store::{LocalPackWriter, ObjectStore};

fn loose_ids(store: &ObjectStore) -> HashSet<Hash> {
    store
        .iter_object_hashes()
        .unwrap()
        .into_iter()
        .filter(|id| loose_path(store, id).is_file())
        .collect()
}

fn loose_path(store: &ObjectStore, id: &Hash) -> std::path::PathBuf {
    let hex = to_hex(id);
    store.objects_root().join(&hex[..2]).join(&hex[2..])
}

#[test]
fn add_reuses_packed_chunks_and_writes_only_new_objects_after_an_edit() {
    let repo = Repo::new();
    let layout = RepoLayout::single(repo.path());
    let store = ObjectStore::open(&layout).unwrap();
    let initial = (0..6 * 1024 * 1024_u64)
        .map(|n| {
            let mixed = n.wrapping_mul(0x9e37_79b9_7f4a_7c15);
            (mixed ^ (mixed >> 23) ^ (mixed >> 41)).to_le_bytes()[0]
        })
        .collect::<Vec<_>>();
    repo.commit_file("large", &initial, "initial");
    let file = repo.path().join("large");

    let scratch = tempfile::tempdir().unwrap();
    let scratch_layout = RepoLayout::single(scratch.path());
    let original = ObjectStore::init(&scratch_layout).unwrap();
    kit_core::worktree::hash_file(&original, &file).unwrap();
    let packed = loose_ids(&original);
    assert!(packed.len() > 2);
    store.try_activate_local_packs().unwrap();
    {
        let guard = store.prune_guard().unwrap();
        let mut pack = LocalPackWriter::new(&store, &guard).unwrap();
        for id in &packed {
            assert_eq!(pack.write(&original.read(id).unwrap()).unwrap(), *id);
        }
        pack.publish().unwrap();
    }
    for id in &packed {
        fs::remove_file(loose_path(&store, id)).unwrap();
    }

    let before = loose_ids(&store);
    repo.write("copy", &initial);
    repo.ok(&["add", "copy"]);
    assert_eq!(loose_ids(&store), before);

    let mut edited = initial;
    for byte in &mut edited[2 * 1024 * 1024..3 * 1024 * 1024] {
        *byte ^= 0x51;
    }
    repo.write("large", &edited);
    let edited_id = kit_core::worktree::hash_file(&original, &file).unwrap();
    let expected: HashSet<_> = loose_ids(&original).difference(&packed).copied().collect();
    assert!(expected.contains(&edited_id));
    assert!(!expected.is_empty() && expected.len() < packed.len());

    repo.ok(&["add", "large"]);
    let after = loose_ids(&store);
    assert_eq!(
        after.difference(&before).copied().collect::<HashSet<_>>(),
        expected
    );
    repo.ok(&["commit", "-m", "edit"]);
}

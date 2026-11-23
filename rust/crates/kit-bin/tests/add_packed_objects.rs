//! Local staging reuses packed file content in a new process.
#![allow(clippy::unwrap_used)]

mod common;

use std::collections::HashSet;
use std::fs;

use common::Repo;
use kit_core::hash::{Hash, to_hex};
use kit_core::layout::RepoLayout;
use kit_core::store::ObjectStore;

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

fn packs(store: &ObjectStore) -> Vec<std::path::PathBuf> {
    let mut found: Vec<_> = fs::read_dir(store.objects_root().join("pack"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension().is_some_and(|ext| ext == "pack")
                && !path.file_name().unwrap().to_string_lossy().starts_with('.')
        })
        .collect();
    found.sort();
    found
}

#[test]
fn add_packs_chunks_reuses_them_and_writes_only_new_chunks_after_an_edit() {
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

    // The chunks of the first add sit in one local pack, and only the
    // manifest is loose.
    let first = packs(&store);
    assert_eq!(first.len(), 1);
    assert_eq!(
        loose_ids(&store).len(),
        3,
        "the manifest, a tree and a commit"
    );

    // Reference ids come from a scratch store that writes every object loose.
    let scratch = tempfile::tempdir().unwrap();
    let scratch_layout = RepoLayout::single(scratch.path());
    let original = ObjectStore::init(&scratch_layout).unwrap();
    kit_core::worktree::hash_file(&original, &file).unwrap();
    let packed = loose_ids(&original);
    assert!(packed.len() > 2);

    // A copy of the file adds nothing: every chunk is already packed.
    let before = loose_ids(&store);
    repo.write("copy", &initial);
    repo.ok(&["add", "copy"]);
    assert_eq!(loose_ids(&store), before);
    assert_eq!(packs(&store), first);

    let mut edited = initial;
    for byte in &mut edited[2 * 1024 * 1024..3 * 1024 * 1024] {
        *byte ^= 0x51;
    }
    repo.write("large", &edited);
    let edited_id = kit_core::worktree::hash_file(&original, &file).unwrap();
    let expected: HashSet<_> = loose_ids(&original).difference(&packed).copied().collect();
    assert!(expected.contains(&edited_id));
    assert!(expected.len() > 1 && expected.len() < packed.len());

    repo.ok(&["add", "large"]);
    // The new manifest is the only new loose object. The new chunks are in a
    // second pack that holds nothing else.
    let after = loose_ids(&store);
    assert_eq!(
        after.difference(&before).copied().collect::<HashSet<_>>(),
        HashSet::from([edited_id])
    );
    let now = packs(&store);
    assert_eq!(now.len(), 2);
    let new_pack = now.iter().find(|path| !first.contains(path)).unwrap();
    let new_chunks: Vec<_> = expected.iter().filter(|id| **id != edited_id).collect();
    let chunk_bytes: usize = new_chunks
        .iter()
        .map(|id| original.read(id).unwrap().len())
        .sum();
    let pack_len = usize::try_from(fs::metadata(new_pack).unwrap().len()).unwrap();
    assert!(pack_len > chunk_bytes);
    assert!(pack_len < chunk_bytes + new_chunks.len() * 16 + 128);
    for id in &expected {
        store.read(id).unwrap();
    }
    repo.ok(&["commit", "-m", "edit"]);
}

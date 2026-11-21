//! Small blobs of a large batch go to the local pack sink; small batches and
//! everything else stay loose.

use std::fs;
use std::path::PathBuf;

use tempfile::TempDir;

use super::*;
use crate::layout::RepoLayout;
use crate::store::{ChunkOrigin, PACK_SEAL_ENTRIES};

fn fresh_store() -> (TempDir, RepoLayout, ObjectStore) {
    let dir = TempDir::new().expect("tempdir");
    let layout = RepoLayout::single(dir.path());
    let store = ObjectStore::init(&layout).expect("init");
    (dir, layout, store)
}

/// `len` deterministic bytes that no two seeds share.
fn bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[3]
        })
        .collect()
}

fn blob_bytes(data: &[u8]) -> Vec<u8> {
    crate::serialize::serialize(&crate::object::Object::Blob(crate::object::Blob {
        data: data.to_vec(),
    }))
    .unwrap()
}

fn pack_files(store: &ObjectStore, suffix: &str) -> usize {
    fs::read_dir(store.pack_dir()).map_or(0, |entries| {
        entries
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                let name = path.file_name().unwrap().to_string_lossy();
                !name.starts_with('.') && name.ends_with(suffix)
            })
            .count()
    })
}

fn pairs(store: &ObjectStore) -> usize {
    let packs = pack_files(store, ".pack");
    assert_eq!(packs, pack_files(store, ".idx"));
    packs
}

fn staging(store: &ObjectStore) -> usize {
    fs::read_dir(store.pack_dir()).map_or(0, |entries| {
        entries
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.file_name().unwrap().to_string_lossy().starts_with('.'))
            .count()
    })
}

fn loose(store: &ObjectStore) -> usize {
    let mut count = 0;
    for shard in fs::read_dir(store.objects_root()).unwrap() {
        let shard: PathBuf = shard.unwrap().path();
        let two_hex = shard
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.len() == 2 && name.bytes().all(|b| b.is_ascii_hexdigit()));
        if two_hex && shard.is_dir() {
            count += fs::read_dir(&shard)
                .unwrap()
                .filter(|entry| {
                    !entry
                        .as_ref()
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .starts_with('.')
                })
                .count();
        }
    }
    count
}

/// Store the blob of `data` the way an inline file is stored.
fn put_file(batch: &WriteBatch<'_>, data: &[u8]) -> Hash {
    let prologue = crate::serialize::blob_prologue(data.len()).unwrap();
    batch
        .put_chunk_parts(
            &[&prologue, data],
            ChunkOrigin {
                path: std::path::Path::new("file"),
                offset: 0,
            },
        )
        .unwrap()
}

fn files(count: usize, len: usize, seed: u64) -> Vec<Vec<u8>> {
    (0..count as u64).map(|n| bytes(seed + n, len)).collect()
}

#[test]
fn a_small_batch_keeps_every_file_loose() {
    let (_dir, _layout, store) = fresh_store();
    let data = files(SMALL_PACK_AFTER, 3000, 1);
    let batch = store.batch();
    let ids: Vec<Hash> = data.iter().map(|d| put_file(&batch, d)).collect();
    batch.commit().unwrap();
    assert_eq!((pairs(&store), loose(&store)), (0, data.len()));
    for (id, d) in ids.iter().zip(&data) {
        assert_eq!(store.read(id).unwrap(), blob_bytes(d));
    }
}

#[test]
fn a_large_batch_packs_the_files_past_the_threshold() {
    let (_dir, _layout, store) = fresh_store();
    let data = files(SMALL_PACK_AFTER + 100, 3000, 1000);
    let batch = store.batch();
    let ids: Vec<Hash> = data.iter().map(|d| put_file(&batch, d)).collect();
    assert_eq!(pairs(&store), 0, "nothing is visible before the commit");
    batch.commit().unwrap();
    // The first files stay loose, the rest are in one pack.
    assert_eq!((pairs(&store), loose(&store)), (1, SMALL_PACK_AFTER));
    assert_eq!(staging(&store), 0);
    for (id, d) in ids.iter().zip(&data) {
        assert_eq!(store.read(id).unwrap(), blob_bytes(d));
    }
}

#[test]
fn a_file_above_the_small_size_stays_loose_in_a_large_batch() {
    let (_dir, _layout, store) = fresh_store();
    let batch = store.batch();
    for d in files(SMALL_PACK_AFTER, 100, 2000) {
        put_file(&batch, &d);
    }
    let at_limit = bytes(1, usize::try_from(SMALL_OBJECT_BYTES).unwrap() - 10);
    let over = bytes(2, usize::try_from(SMALL_OBJECT_BYTES).unwrap() - 9);
    let packed = put_file(&batch, &at_limit);
    let kept_loose = put_file(&batch, &over);
    batch.commit().unwrap();
    assert_eq!(pairs(&store), 1);
    assert!(!store.path_for(&packed).exists(), "the limit packs");
    assert!(store.path_for(&kept_loose).exists(), "above it stays loose");
}

#[test]
fn parts_that_are_not_a_canonical_blob_stay_loose() {
    let (_dir, _layout, store) = fresh_store();
    let batch = store.batch();
    for d in files(SMALL_PACK_AFTER, 100, 3000) {
        put_file(&batch, &d);
    }
    let origin = ChunkOrigin {
        path: std::path::Path::new("file"),
        offset: 0,
    };
    // One part, a prologue that names another length, and a tree.
    let one = blob_bytes(b"one part");
    let prologue = crate::serialize::blob_prologue(3).unwrap();
    let tree = crate::serialize::serialize(&crate::object::Object::Tree(crate::object::Tree {
        entries: Vec::new(),
    }))
    .unwrap();
    let a = batch.put_chunk_parts(&[&one], origin).unwrap();
    let b = batch
        .put_chunk_parts(&[&prologue, b"not three bytes"], origin)
        .unwrap();
    let c = batch.put_chunk_parts(&[&tree], origin).unwrap();
    batch.commit().unwrap();
    assert_eq!(pairs(&store), 0);
    for id in [a, b, c] {
        assert!(store.path_for(&id).exists());
    }
}

#[test]
fn a_per_object_batch_keeps_every_file_loose() {
    let (_dir, _layout, store) = fresh_store();
    let data = files(SMALL_PACK_AFTER + 50, 500, 4000);
    let batch = store.batch_with_policy(SyncPolicy::PerObject);
    for d in &data {
        put_file(&batch, d);
    }
    batch.commit().unwrap();
    assert_eq!((pairs(&store), loose(&store)), (0, data.len()));
}

#[test]
fn an_activation_miss_keeps_every_file_loose() {
    let (dir, layout, store) = fresh_store();
    fs::write(layout.format_file(), b"bmt-v2\n").unwrap();
    drop(store);
    let holder = ObjectStore::open(&layout).unwrap();
    let _shared = holder.prune_guard().unwrap();
    let store = ObjectStore::open(&layout).unwrap();
    let data = files(SMALL_PACK_AFTER + 50, 500, 5000);
    let batch = store.batch();
    for d in &data {
        put_file(&batch, d);
    }
    batch.commit().unwrap();
    assert_eq!((pairs(&store), loose(&store)), (0, data.len()));
    drop(dir);
}

#[test]
fn a_repeated_file_is_written_once_and_a_stored_one_not_again() {
    let (_dir, _layout, store) = fresh_store();
    let data = files(SMALL_PACK_AFTER + 20, 800, 6000);
    let batch = store.batch();
    for d in &data {
        put_file(&batch, d);
    }
    // The same content again, within the batch.
    for d in &data[SMALL_PACK_AFTER..] {
        put_file(&batch, d);
    }
    batch.commit().unwrap();
    assert_eq!((pairs(&store), loose(&store)), (1, SMALL_PACK_AFTER));
    let size = fs::metadata(
        fs::read_dir(store.pack_dir())
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|e| e == "pack"))
            .unwrap(),
    )
    .unwrap()
    .len();

    // A second batch of the same files writes nothing new, loose or packed.
    let again = store.batch();
    for d in &data {
        put_file(&again, d);
    }
    again.commit().unwrap();
    assert_eq!((pairs(&store), loose(&store)), (1, SMALL_PACK_AFTER));
    let first = fs::read_dir(store.pack_dir())
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "pack"))
        .unwrap();
    assert_eq!(fs::metadata(first).unwrap().len(), size);
}

#[test]
fn only_files_with_a_new_blob_count_toward_a_pack() {
    let (_dir, _layout, store) = fresh_store();
    let data = files(SMALL_PACK_AFTER + 100, 3000, 9000);
    let first = store.batch();
    for d in &data {
        put_file(&first, d);
    }
    first.commit().unwrap();
    assert_eq!((pairs(&store), loose(&store)), (1, SMALL_PACK_AFTER));

    // Every file is stored, loose or packed, and one blob is new.
    let second = store.batch();
    for d in &data {
        put_file(&second, d);
    }
    let fresh = bytes(1, 3000);
    let id = put_file(&second, &fresh);
    second.commit().unwrap();
    assert_eq!((pairs(&store), loose(&store)), (1, SMALL_PACK_AFTER + 1));
    assert_eq!(store.read(&id).unwrap(), blob_bytes(&fresh));
}

#[test]
fn a_file_repeated_in_a_batch_counts_once() {
    let (_dir, _layout, store) = fresh_store();
    let batch = store.batch();
    let same = bytes(5, 3000);
    for _ in 0..SMALL_PACK_AFTER + 50 {
        put_file(&batch, &same);
    }
    batch.commit().unwrap();
    assert_eq!((pairs(&store), loose(&store)), (0, 1));
}

#[test]
fn an_aborted_large_batch_leaves_no_pack_and_no_staging_file() {
    let (_dir, _layout, store) = fresh_store();
    {
        let batch = store.batch();
        for d in files(SMALL_PACK_AFTER + 30, 400, 7000) {
            put_file(&batch, &d);
        }
        assert!(staging(&store) >= 1, "the open pack is staged");
    }
    assert_eq!((pairs(&store), staging(&store), loose(&store)), (0, 0, 0));
}

#[test]
fn a_full_pack_of_small_files_seals_before_the_batch_ends() {
    let (_dir, _layout, store) = fresh_store();
    let batch = store.batch();
    // Past the entry limit, with tiny files.
    for n in 0..(SMALL_PACK_AFTER + PACK_SEAL_ENTRIES + 10) as u64 {
        put_file(&batch, &n.to_le_bytes());
    }
    batch.commit().unwrap();
    assert_eq!(pairs(&store), 2);
}

#[test]
fn a_checkpoint_that_shows_a_tree_seals_the_small_files_first() {
    let (_dir, _layout, store) = fresh_store();
    let batch = store.batch();
    let data = files(SMALL_PACK_AFTER + 10, 300, 8000);
    for d in &data {
        put_file(&batch, d);
    }
    let tree = crate::serialize::serialize(&crate::object::Object::Tree(crate::object::Tree {
        entries: Vec::new(),
    }))
    .unwrap();
    batch.write(&tree).unwrap();
    batch.checkpoint().unwrap();
    // The pack is durable and visible before the tree can be.
    assert_eq!(pairs(&store), 1);
    batch.commit().unwrap();
}

#[test]
fn identical_files_across_threads_are_all_stored() {
    let (_dir, _layout, store) = fresh_store();
    let data = files(SMALL_PACK_AFTER + 200, 1200, 9000);
    let batch = store.batch();
    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| {
                for d in &data {
                    put_file(&batch, d);
                }
            });
        }
    });
    batch.commit().unwrap();
    assert!(pairs(&store) >= 1);
    for d in &data {
        let id = crate::object::object_id_from_parts(&[&blob_bytes(d)]);
        assert!(store.contains(&id));
    }
}

#[test]
fn a_file_staged_loose_in_the_first_files_is_not_written_again_past_the_threshold() {
    let (_dir, _layout, store) = fresh_store();
    let data = files(SMALL_PACK_AFTER + 10, 700, 10_000);
    let batch = store.batch();
    for d in &data {
        put_file(&batch, d);
    }
    // The first files are staged loose; the same content again must be found
    // there, not written to the pack.
    for d in &data[..SMALL_PACK_AFTER] {
        put_file(&batch, d);
    }
    batch.commit().unwrap();
    assert_eq!((pairs(&store), loose(&store)), (1, SMALL_PACK_AFTER));
}

#[cfg(unix)]
#[test]
fn a_failed_seal_of_small_files_fails_the_commit_and_publishes_nothing() {
    let (_dir, _layout, store) = fresh_store();
    let batch = store.batch();
    for d in files(SMALL_PACK_AFTER + 20, 600, 11_000) {
        put_file(&batch, &d);
    }
    // Unlink the open pack's staging file, so its publication cannot find it.
    for path in fs::read_dir(store.pack_dir()).unwrap() {
        fs::remove_file(path.unwrap().path()).unwrap();
    }
    assert!(batch.commit().is_err());
    assert_eq!(pairs(&store), 0);
}

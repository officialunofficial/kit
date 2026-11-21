//! The local pack sink of a [`WriteBatch`]: chunks of a batch go to a pack in
//! order, everything else stays loose.

use std::fs;
use std::path::PathBuf;

use tempfile::TempDir;

use super::*;
use crate::layout::RepoLayout;
use crate::store::{HashedChunk, PACK_SEAL_ENTRIES};

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

fn files_in_pack_dir(store: &ObjectStore, suffix: &str) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(store.pack_dir()) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.to_string_lossy().ends_with(suffix))
        .collect();
    files.sort();
    files
}

fn pairs(store: &ObjectStore) -> usize {
    let packs = files_in_pack_dir(store, ".pack").len();
    assert_eq!(packs, files_in_pack_dir(store, ".idx").len());
    packs
}

fn loose(store: &ObjectStore) -> usize {
    store.iter_object_hashes().unwrap().len()
}

/// Staging files left in the pack directory.
fn staging(store: &ObjectStore) -> usize {
    fs::read_dir(store.pack_dir())
        .map(|entries| {
            entries
                .map(|entry| entry.unwrap().path())
                .filter(|path| {
                    let name = path.to_string_lossy();
                    !name.ends_with(".pack") && !name.ends_with(".idx")
                })
                .count()
        })
        .unwrap_or(0)
}

#[test]
fn a_hashed_chunk_has_the_id_of_the_blob_it_describes() {
    let (_dir, _layout, store) = fresh_store();
    for len in [0, 1, 1000, 70_000] {
        let data = bytes(len as u64, len);
        let chunk = HashedChunk::new(&data).unwrap();
        let stored = blob_bytes(&data);
        assert_eq!(chunk.id(), store.write(&stored).unwrap());
        assert_eq!(chunk.parts().concat(), stored);
        assert_eq!(chunk.len(), stored.len());
    }
}

#[test]
fn chunks_of_a_batch_go_to_one_pack_in_order() {
    let (_dir, _layout, store) = fresh_store();
    let data: Vec<Vec<u8>> = (0..20).map(|n| bytes(n, 30_000 + n as usize)).collect();
    let batch = store.batch();
    assert!(batch.orders_chunks());
    let ids: Vec<Hash> = data
        .iter()
        .map(|chunk| {
            batch
                .put_hashed_chunk(&HashedChunk::new(chunk).unwrap())
                .unwrap()
        })
        .collect();
    assert_eq!(pairs(&store), 0, "nothing is visible before the commit");
    batch.commit().unwrap();

    assert_eq!(pairs(&store), 1);
    assert_eq!(loose(&store), 0);
    let pack = fs::read(&files_in_pack_dir(&store, ".pack")[0]).unwrap();
    let mut from = 0;
    for (id, chunk) in ids.iter().zip(&data) {
        assert_eq!(store.read(id).unwrap(), blob_bytes(chunk));
        let at = pack[from..]
            .windows(chunk.len())
            .position(|window| window == chunk.as_slice())
            .expect("the chunk follows the previous one");
        from += at + chunk.len();
    }
}

#[test]
fn a_per_object_batch_keeps_chunks_loose() {
    let (_dir, _layout, store) = fresh_store();
    let data = bytes(1, 5000);
    let batch = store.batch_with_policy(SyncPolicy::PerObject);
    assert!(!batch.orders_chunks());
    let id = batch
        .put_hashed_chunk(&HashedChunk::new(&data).unwrap())
        .unwrap();
    batch.commit().unwrap();
    assert_eq!(pairs(&store), 0);
    assert!(store.path_for(&id).exists());
}

#[test]
fn an_activation_miss_keeps_chunks_loose() {
    let (dir, layout, store) = fresh_store();
    fs::write(layout.format_file(), b"bmt-v2\n").unwrap();
    drop(store);
    let holder = ObjectStore::open(&layout).unwrap();
    let _shared = holder.prune_guard().unwrap();
    let store = ObjectStore::open(&layout).unwrap();
    let data = bytes(2, 5000);
    let batch = store.batch();
    assert!(!batch.orders_chunks(), "the one try missed");
    let id = batch
        .put_hashed_chunk(&HashedChunk::new(&data).unwrap())
        .unwrap();
    batch.commit().unwrap();
    assert_eq!(pairs(&store), 0);
    assert!(store.path_for(&id).exists());
    drop(dir);
}

#[test]
fn a_loose_store_activates_on_the_first_question() {
    let (_dir, layout, store) = fresh_store();
    fs::write(layout.format_file(), b"bmt-v2\n").unwrap();
    drop(store);
    let store = ObjectStore::open(&layout).unwrap();
    assert!(!store.local_packs_enabled().unwrap());
    let batch = store.batch();
    assert!(batch.orders_chunks());
    let data = bytes(3, 5000);
    batch
        .put_hashed_chunk(&HashedChunk::new(&data).unwrap())
        .unwrap();
    batch.commit().unwrap();
    assert_eq!(pairs(&store), 1);
    assert_eq!(loose(&store), 0);
}

#[test]
fn a_full_pack_seals_before_the_batch_ends() {
    let (_dir, _layout, store) = fresh_store();
    let batch = store.batch();
    // 255 chunks of 256 KiB and their prologues fit in 64 MiB. The 256th
    // does not, so it opens a second pack and seals the first.
    let size = 256 << 10;
    for n in 0..255u64 {
        batch
            .put_hashed_chunk(&HashedChunk::new(&bytes(n, size)).unwrap())
            .unwrap();
    }
    assert_eq!(pairs(&store), 0);
    batch
        .put_hashed_chunk(&HashedChunk::new(&bytes(255, size)).unwrap())
        .unwrap();
    assert_eq!(pairs(&store), 1, "the full pack is sealed");
    batch.commit().unwrap();
    assert_eq!(pairs(&store), 2);
    assert_eq!(loose(&store), 0);
}

#[test]
fn a_pack_seals_at_its_entry_limit() {
    let (_dir, _layout, store) = fresh_store();
    let batch = store.batch();
    for n in 0..PACK_SEAL_ENTRIES as u64 {
        batch
            .put_hashed_chunk(&HashedChunk::new(&n.to_le_bytes()).unwrap())
            .unwrap();
    }
    assert_eq!(pairs(&store), 0, "the entry limit is full, not passed");
    batch
        .put_hashed_chunk(&HashedChunk::new(b"one more").unwrap())
        .unwrap();
    assert_eq!(pairs(&store), 1);
    batch.commit().unwrap();
    assert_eq!(pairs(&store), 2);
}

#[test]
fn a_checkpoint_leaves_the_pack_open_until_the_commit() {
    let (_dir, _layout, store) = fresh_store();
    let batch = store.batch();
    let data = bytes(4, 20_000);
    let id = batch
        .put_hashed_chunk(&HashedChunk::new(&data).unwrap())
        .unwrap();
    // A plain loose blob names nothing, so it does not seal the pack.
    batch.write(&blob_bytes(b"loose blob")).unwrap();
    batch.checkpoint().unwrap();
    assert_eq!(pairs(&store), 0);
    assert!(!store.contains(&id));
    batch.commit().unwrap();
    assert_eq!(pairs(&store), 1);
    assert!(store.contains(&id));
}

#[test]
fn a_checkpoint_seals_the_pack_before_it_shows_a_manifest() {
    let (_dir, _layout, store) = fresh_store();
    let batch = store.batch();
    let data = bytes(5, 20_000);
    let chunk = HashedChunk::new(&data).unwrap();
    let id = batch.put_hashed_chunk(&chunk).unwrap();
    let manifest = crate::serialize::serialize(&crate::object::Object::ChunkedBlob(
        crate::object::ChunkedBlob::from_parts(
            data.len() as u64,
            0,
            vec![id],
            vec![data.len() as u64],
        )
        .unwrap(),
    ))
    .unwrap();
    let manifest_id = batch.write(&manifest).unwrap();
    batch.checkpoint().unwrap();
    assert_eq!(pairs(&store), 1, "the chunk's pack is visible first");
    assert!(store.path_for(&manifest_id).exists());
    assert!(store.contains(&id));
    // The next chunk opens a new pack, and a plain checkpoint keeps it open.
    batch
        .put_hashed_chunk(&HashedChunk::new(&bytes(6, 20_000)).unwrap())
        .unwrap();
    batch.checkpoint().unwrap();
    assert_eq!(pairs(&store), 1);
    batch.commit().unwrap();
    assert_eq!(pairs(&store), 2);
}

#[test]
fn a_repeated_chunk_is_written_once() {
    let (_dir, _layout, once) = fresh_store();
    let (_dir2, _layout2, repeated) = fresh_store();
    let data = bytes(7, 40_000);
    let chunk = HashedChunk::new(&data).unwrap();
    for (store, times) in [(&once, 1), (&repeated, 5)] {
        let batch = store.batch();
        for _ in 0..times {
            assert_eq!(batch.put_hashed_chunk(&chunk).unwrap(), chunk.id());
        }
        assert!(batch.has(&chunk.id()));
        batch.commit().unwrap();
    }
    let size = |store: &ObjectStore| fs::metadata(&files_in_pack_dir(store, ".pack")[0]).unwrap().len();
    assert_eq!(size(&once), size(&repeated));
}

#[test]
fn a_chunk_already_stored_is_not_written_again() {
    let (_dir, _layout, store) = fresh_store();
    let packed = bytes(8, 30_000);
    let loose_chunk = bytes(9, 30_000);
    let guard = store.prune_guard().unwrap();
    let mut writer = crate::store::LocalPackWriter::new(&store, &guard).unwrap();
    writer.write(&blob_bytes(&packed)).unwrap();
    writer.publish().unwrap();
    drop(guard);
    store.write(&blob_bytes(&loose_chunk)).unwrap();
    assert_eq!((pairs(&store), loose(&store)), (1, 1));

    let batch = store.batch();
    batch
        .put_hashed_chunk(&HashedChunk::new(&packed).unwrap())
        .unwrap();
    batch
        .put_hashed_chunk(&HashedChunk::new(&loose_chunk).unwrap())
        .unwrap();
    batch.commit().unwrap();
    assert_eq!((pairs(&store), loose(&store)), (1, 1));

    // A copy of the wrong length is damage, not a reuse.
    let short = bytes(10, 30_000);
    let id = HashedChunk::new(&short).unwrap().id();
    fs::create_dir_all(store.path_for(&id).parent().unwrap()).unwrap();
    fs::write(store.path_for(&id), b"damaged").unwrap();
    let batch = store.batch();
    batch
        .put_hashed_chunk(&HashedChunk::new(&short).unwrap())
        .unwrap();
    batch.commit().unwrap();
    assert_eq!(pairs(&store), 2);
}

#[test]
fn an_aborted_batch_leaves_no_pack_and_no_staging_file() {
    let (_dir, _layout, store) = fresh_store();
    {
        let batch = store.batch();
        batch
            .put_hashed_chunk(&HashedChunk::new(&bytes(11, 20_000)).unwrap())
            .unwrap();
        assert_eq!(staging(&store), 1);
    }
    assert_eq!((pairs(&store), staging(&store)), (0, 0));
}

#[cfg(unix)]
#[test]
fn a_failed_seal_fails_the_batch_and_publishes_nothing_more() {
    let (_dir, _layout, store) = fresh_store();
    let batch = store.batch();
    let size = 256 << 10;
    for n in 0..255u64 {
        batch
            .put_hashed_chunk(&HashedChunk::new(&bytes(n, size)).unwrap())
            .unwrap();
    }
    // Unlink the open pack's staging file, so its publication cannot find it.
    for path in fs::read_dir(store.pack_dir()).unwrap() {
        fs::remove_file(path.unwrap().path()).unwrap();
    }
    let rollover = batch.put_hashed_chunk(&HashedChunk::new(&bytes(900, size)).unwrap());
    assert!(rollover.is_err());
    assert!(
        batch
            .put_hashed_chunk(&HashedChunk::new(&bytes(901, 100)).unwrap())
            .is_err()
    );
    assert!(batch.write(&blob_bytes(b"later")).is_err());
    assert!(batch.checkpoint().is_err());
    assert!(batch.commit().is_err());
    assert_eq!(pairs(&store), 0);
}

#[test]
fn a_panic_while_sealing_fails_the_batch() {
    let failed = AtomicBool::new(false);
    let result = std::panic::catch_unwind(|| {
        let _guard = FailUnlessDisarmed::new(&failed);
        panic!("a seal panicked");
    });
    assert!(result.is_err());
    assert!(failed.load(Ordering::Relaxed));

    let kept = AtomicBool::new(false);
    let mut guard = FailUnlessDisarmed::new(&kept);
    guard.disarm();
    drop(guard);
    assert!(!kept.load(Ordering::Relaxed));
}

#[test]
fn threads_share_one_pack_and_every_chunk_lands() {
    let (_dir, _layout, store) = fresh_store();
    let batch = store.batch();
    let data: Vec<Vec<u8>> = (0..64).map(|n| bytes(1000 + n, 20_000)).collect();
    std::thread::scope(|scope| {
        for part in data.chunks(16) {
            let batch = &batch;
            scope.spawn(move || {
                for chunk in part {
                    batch
                        .put_hashed_chunk(&HashedChunk::new(chunk).unwrap())
                        .unwrap();
                    batch.checkpoint().unwrap();
                }
            });
        }
    });
    batch.commit().unwrap();
    assert_eq!((pairs(&store), loose(&store)), (1, 0));
    for chunk in &data {
        let id = HashedChunk::new(chunk).unwrap().id();
        assert_eq!(store.read(&id).unwrap(), blob_bytes(chunk));
    }
}

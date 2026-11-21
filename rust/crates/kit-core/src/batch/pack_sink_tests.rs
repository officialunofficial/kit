//! The local pack sink of a [`WriteBatch`]: chunks of a batch go to a pack in
//! order, everything else stays loose.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

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
        .filter(|path| {
            let name = path.file_name().unwrap().to_string_lossy();
            !name.starts_with('.') && name.ends_with(suffix)
        })
        .collect();
    files.sort();
    files
}

fn pairs(store: &ObjectStore) -> usize {
    let packs = files_in_pack_dir(store, ".pack").len();
    assert_eq!(packs, files_in_pack_dir(store, ".idx").len());
    packs
}

/// Loose object files, which the pack directory does not count.
fn loose(store: &ObjectStore) -> usize {
    let mut count = 0;
    for shard in fs::read_dir(store.objects_root()).unwrap() {
        let shard = shard.unwrap().path();
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

/// Staging files left in the pack directory.
fn staging(store: &ObjectStore) -> usize {
    fs::read_dir(store.pack_dir()).map_or(0, |entries| {
        entries
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.file_name().unwrap().to_string_lossy().starts_with('.'))
            .count()
    })
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
        assert!(!chunk.is_empty());
    }
}

#[test]
fn chunks_of_a_batch_go_to_one_pack_in_order() {
    let (_dir, _layout, store) = fresh_store();
    let data: Vec<Vec<u8>> = (0..20u64)
        .map(|n| bytes(n, 30_000 + usize::try_from(n).unwrap()))
        .collect();
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
    batch.sealing.wait().unwrap();
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
    batch.sealing.wait().unwrap();
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
    let size = |store: &ObjectStore| {
        fs::metadata(&files_in_pack_dir(store, ".pack")[0])
            .unwrap()
            .len()
    };
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

/// Fill a pack to its entry limit with distinct tiny chunks.
fn fill_entries(batch: &WriteBatch<'_>, seed: u64) {
    for n in 0..PACK_SEAL_ENTRIES as u64 {
        batch
            .put_hashed_chunk(&HashedChunk::new(&(seed + n).to_le_bytes()).unwrap())
            .unwrap();
    }
}

#[cfg(unix)]
#[test]
fn a_seal_error_on_the_worker_fails_the_batch_and_leaves_no_index_entry() {
    let (_dir, _layout, store) = fresh_store();
    let batch = store.batch();
    fill_entries(&batch, 0);
    // Unlink the open pack's staging file, so its publication cannot find it.
    for path in fs::read_dir(store.pack_dir()).unwrap() {
        fs::remove_file(path.unwrap().path()).unwrap();
    }
    // The rollover only starts the seal, which fails on the worker.
    batch
        .put_hashed_chunk(&HashedChunk::new(b"first of the second pack").unwrap())
        .unwrap();
    // The second pack fills while the error waits, and its rollover returns it.
    let mut n = 1_000_000;
    let failed = loop {
        n += 1;
        let result = batch.put_hashed_chunk(&HashedChunk::new(&u64::to_le_bytes(n)).unwrap());
        if result.is_err() {
            break result;
        }
        assert!(n < 1_000_000 + PACK_SEAL_ENTRIES as u64 + 2, "no rollover");
    };
    assert!(failed.is_err());
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

#[cfg(unix)]
#[test]
fn a_seal_error_on_the_worker_reaches_the_commit() {
    let (_dir, _layout, store) = fresh_store();
    let batch = store.batch();
    fill_entries(&batch, 0);
    for path in fs::read_dir(store.pack_dir()).unwrap() {
        fs::remove_file(path.unwrap().path()).unwrap();
    }
    batch
        .put_hashed_chunk(&HashedChunk::new(b"first of the second pack").unwrap())
        .unwrap();
    assert!(batch.commit().is_err());
    assert_eq!(pairs(&store), 0);
}

/// Hand the open pack of `batch` to its sealing slot behind a gate: the seal
/// starts when the returned sender is used, and finishes after it.
fn block_the_seal(batch: &WriteBatch<'_>) -> std::sync::mpsc::Sender<()> {
    let (release, wait) = std::sync::mpsc::channel::<()>();
    let job = batch
        .pack
        .lock()
        .unwrap()
        .take()
        .expect("an open pack")
        .detach();
    batch
        .sealing
        .start_with(job, move |job| {
            let _ = wait.recv();
            job.publish()
        })
        .unwrap();
    release
}

fn manifest_of(data: &[u8], id: Hash) -> Vec<u8> {
    crate::serialize::serialize(&crate::object::Object::ChunkedBlob(
        crate::object::ChunkedBlob::from_parts(
            data.len() as u64,
            0,
            vec![id],
            vec![data.len() as u64],
        )
        .unwrap(),
    ))
    .unwrap()
}

#[test]
fn a_checkpoint_that_shows_a_manifest_waits_for_the_seal_in_flight() {
    let (_dir, layout, store) = fresh_store();
    let batch = store.batch();
    let data = bytes(20, 20_000);
    let id = batch
        .put_hashed_chunk(&HashedChunk::new(&data).unwrap())
        .unwrap();
    let release = block_the_seal(&batch);
    let manifest_id = batch.write(&manifest_of(&data, id)).unwrap();
    std::thread::scope(|scope| {
        let checkpoint = scope.spawn(|| batch.checkpoint());
        std::thread::sleep(std::time::Duration::from_millis(300));
        // The crash picture while the seal runs: no pair, no chunk, and no
        // manifest, so nothing names a chunk that is not durable.
        assert!(!checkpoint.is_finished());
        let other = ObjectStore::open(&layout).unwrap();
        assert_eq!(pairs(&other), 0);
        assert!(!other.contains(&id));
        assert!(!other.path_for(&manifest_id).exists());
        release.send(()).unwrap();
        checkpoint.join().unwrap().unwrap();
    });
    assert_eq!(pairs(&store), 1);
    assert!(store.contains(&id));
    assert!(store.path_for(&manifest_id).exists());
}

#[test]
fn the_commit_waits_for_the_seal_in_flight() {
    let (_dir, _layout, store) = fresh_store();
    let batch = store.batch();
    let id = batch
        .put_hashed_chunk(&HashedChunk::new(&bytes(21, 20_000)).unwrap())
        .unwrap();
    let release = block_the_seal(&batch);
    std::thread::scope(|scope| {
        let commit = scope.spawn(|| batch.flush(true));
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(!commit.is_finished());
        assert_eq!(pairs(&store), 0);
        release.send(()).unwrap();
        commit.join().unwrap().unwrap();
    });
    assert_eq!(pairs(&store), 1);
    assert!(store.contains(&id));
}

#[test]
fn a_checkpoint_of_plain_blobs_does_not_wait_for_the_seal() {
    let (_dir, _layout, store) = fresh_store();
    let batch = store.batch();
    batch
        .put_hashed_chunk(&HashedChunk::new(&bytes(22, 20_000)).unwrap())
        .unwrap();
    let release = block_the_seal(&batch);
    batch.write(&blob_bytes(b"loose blob")).unwrap();
    batch.checkpoint().unwrap();
    assert_eq!(pairs(&store), 0, "the seal is still running");
    release.send(()).unwrap();
    batch.commit().unwrap();
    assert_eq!(pairs(&store), 1);
}

#[test]
fn a_second_full_pack_waits_for_the_first_seal() {
    let sealing = Sealing::default();
    let (release, wait) = std::sync::mpsc::channel::<()>();
    let started = Arc::new(AtomicBool::new(false));
    sealing
        .start_with((), move |()| {
            let _ = wait.recv();
            Ok(())
        })
        .unwrap();
    std::thread::scope(|scope| {
        let flag = Arc::clone(&started);
        let second = scope.spawn(|| {
            let result = sealing.start_with((), move |()| {
                flag.store(true, Ordering::SeqCst);
                Ok(())
            });
            result.and_then(|()| sealing.wait())
        });
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(!second.is_finished());
        assert!(!started.load(Ordering::SeqCst), "one seal at a time");
        release.send(()).unwrap();
        second.join().unwrap().unwrap();
    });
    assert!(started.load(Ordering::SeqCst));
}

#[test]
fn an_error_of_the_first_seal_is_returned_when_the_second_starts() {
    let sealing = Sealing::default();
    sealing
        .start_with((), |()| Err(io::Error::other("first seal").into()))
        .unwrap();
    let second_ran = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&second_ran);
    let result = sealing.start_with((), move |()| {
        flag.store(true, Ordering::SeqCst);
        Ok(())
    });
    assert!(result.unwrap_err().to_string().contains("first seal"));
    assert!(!second_ran.load(Ordering::SeqCst));
    sealing.wait().unwrap();
}

#[test]
fn a_panic_in_the_seal_worker_is_surfaced_not_swallowed() {
    let sealing = Sealing::default();
    sealing
        .start_with((), |()| panic!("a seal panicked"))
        .unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sealing.wait()));
    assert!(result.is_err());
    // The slot is empty and usable afterwards.
    sealing.wait().unwrap();

    let (_dir, _layout, store) = fresh_store();
    let batch = store.batch();
    batch
        .put_hashed_chunk(&HashedChunk::new(&bytes(23, 20_000)).unwrap())
        .unwrap();
    batch
        .sealing
        .start_with((), |()| panic!("a seal panicked"))
        .unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| batch.commit()));
    assert!(result.is_err());
    assert_eq!(pairs(&store), 0);
}

#[test]
fn a_seal_runs_on_this_thread_when_no_worker_can_start() {
    let sealing = Sealing::default();
    let ran = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&ran);
    sealing
        .start_via(
            (),
            move |()| {
                flag.store(true, Ordering::SeqCst);
                Ok(())
            },
            |_| Err(io::Error::other("no threads")),
        )
        .unwrap();
    assert!(ran.load(Ordering::SeqCst));
    let failed = sealing.start_via(
        (),
        |()| Err(io::Error::other("inline seal").into()),
        |_| Err(io::Error::other("no threads")),
    );
    assert!(failed.unwrap_err().to_string().contains("inline seal"));
}

#[test]
fn a_dropped_batch_waits_for_the_seal_in_flight() {
    let (_dir, _layout, store) = fresh_store();
    let done = Arc::new(AtomicBool::new(false));
    {
        let batch = store.batch();
        batch
            .put_hashed_chunk(&HashedChunk::new(&bytes(24, 20_000)).unwrap())
            .unwrap();
        let flag = Arc::clone(&done);
        let job = batch.pack.lock().unwrap().take().unwrap().detach();
        batch
            .sealing
            .start_with(job, move |job| {
                std::thread::sleep(std::time::Duration::from_millis(300));
                flag.store(true, Ordering::SeqCst);
                job.publish()
            })
            .unwrap();
    }
    assert!(done.load(Ordering::SeqCst), "the drop joined the worker");
    assert_eq!(staging(&store), 0);
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

/// A file of `len` deterministic bytes that cuts into many chunks.
fn big_file(dir: &Path, name: &str, len: usize) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, bytes(77, len)).unwrap();
    path
}

fn only_pack_name(store: &ObjectStore) -> String {
    let packs = files_in_pack_dir(store, ".pack");
    assert_eq!(packs.len(), 1);
    packs[0].file_name().unwrap().to_string_lossy().into_owned()
}

#[test]
fn a_file_packs_the_same_through_the_sequential_and_the_fan_out_path() {
    let work = TempDir::new().unwrap();
    let file = big_file(work.path(), "big.bin", 6 << 20);

    let (_a, _la, sequential) = fresh_store();
    let batch = sequential.batch();
    let (manifest_a, _) = crate::worktree::hash_file_with_metadata(&batch, &file).unwrap();
    batch.commit().unwrap();

    let (_b, _lb, fanned) = fresh_store();
    let batch = fanned.batch();
    let (manifest_b, _) =
        crate::worktree::hash_file_with_metadata_with(&batch, &file, |sink, chunks| {
            assert!(sink.orders_chunks());
            let hashed = chunks
                .iter()
                .map(|chunk| crate::worktree::hash_chunk(chunk))
                .collect::<Result<Vec<_>, _>>()?;
            crate::worktree::put_hashed_chunks(sink, &hashed)
        })
        .unwrap();
    batch.commit().unwrap();

    assert_eq!(manifest_a, manifest_b);
    // The pack name is the digest of its bytes.
    assert_eq!(only_pack_name(&sequential), only_pack_name(&fanned));
    assert_eq!(loose(&sequential), 1, "one loose manifest");
    assert_eq!(loose(&fanned), 1);
}

#[test]
fn a_file_through_a_per_object_batch_stays_loose() {
    let work = TempDir::new().unwrap();
    let file = big_file(work.path(), "big.bin", 3 << 20);
    let (_dir, _layout, store) = fresh_store();
    let batch = store.batch_with_policy(SyncPolicy::PerObject);
    crate::worktree::hash_file_with_metadata(&batch, &file).unwrap();
    batch.commit().unwrap();
    assert_eq!(pairs(&store), 0);
    assert!(loose(&store) > 10);
}

/// A sink that says which method took each chunk.
#[derive(Default)]
struct Routing {
    order: bool,
    with_origin: Mutex<usize>,
    without_origin: Mutex<usize>,
}

impl ObjectSink for Routing {
    fn put(&self, bytes: &[u8]) -> StoreResult<Hash> {
        Ok(crate::object::object_id_from_bytes(bytes))
    }
    fn put_parts(&self, parts: &[&[u8]]) -> StoreResult<Hash> {
        *self.without_origin.lock().unwrap() += 1;
        Ok(crate::object::object_id_from_parts(parts))
    }
    fn put_chunk_parts(
        &self,
        parts: &[&[u8]],
        _origin: crate::store::ChunkOrigin<'_>,
    ) -> StoreResult<Hash> {
        *self.with_origin.lock().unwrap() += 1;
        Ok(crate::object::object_id_from_parts(parts))
    }
    fn has(&self, _h: &Hash) -> bool {
        false
    }
    fn orders_chunks(&self) -> bool {
        self.order
    }
}

#[test]
fn the_default_chunk_route_keeps_the_origin_a_source_sink_reads() {
    let work = TempDir::new().unwrap();
    let file = big_file(work.path(), "big.bin", 3 << 20);

    // A sink that does not ask for ordered chunks sees none of the token.
    let plain = Routing::default();
    crate::worktree::hash_file_with_metadata(&plain, &file).unwrap();
    assert!(*plain.with_origin.lock().unwrap() > 10);

    // One that asks gets the same routing from the default, with the origin.
    let ordered = Routing {
        order: true,
        ..Routing::default()
    };
    crate::worktree::hash_file_with_metadata(&ordered, &file).unwrap();
    assert_eq!(
        *ordered.with_origin.lock().unwrap(),
        *plain.with_origin.lock().unwrap()
    );
    assert_eq!(*ordered.without_origin.lock().unwrap(), 0);

    // A token with no origin falls back to `put_parts`.
    let chunk = HashedChunk::new(b"no origin").unwrap();
    plain.put_hashed_chunk(&chunk).unwrap();
    assert_eq!(*plain.without_origin.lock().unwrap(), 1);
}

#[test]
fn the_sinks_that_keep_no_bytes_do_not_ask_for_ordered_chunks() {
    let (_dir, _layout, store) = fresh_store();
    assert!(!store.orders_chunks());
    assert!(!crate::store::HashOnlySink::default().orders_chunks());
}

#[test]
fn a_pack_holds_exactly_its_byte_limit() {
    let (_dir, _layout, store) = fresh_store();
    let batch = store.batch();
    // 256 blobs of exactly 256 KiB with their prologues are 64 MiB.
    let data = (256 << 10) - crate::serialize::BLOB_PROLOGUE_LEN;
    for n in 0..256u64 {
        batch
            .put_hashed_chunk(&HashedChunk::new(&bytes(n, data)).unwrap())
            .unwrap();
    }
    assert_eq!(pairs(&store), 0, "64 MiB fits");
    batch
        .put_hashed_chunk(&HashedChunk::new(&bytes(256, data)).unwrap())
        .unwrap();
    batch.sealing.wait().unwrap();
    assert_eq!(pairs(&store), 1, "one byte more does not");
}

#[test]
fn a_chunk_above_the_chunker_size_is_stored_loose() {
    let (_dir, _layout, store) = fresh_store();
    let data = bytes(12, crate::chunker::MAX_SIZE + 1);
    let batch = store.batch();
    let id = batch
        .put_hashed_chunk(&HashedChunk::new(&data).unwrap())
        .unwrap();
    batch.commit().unwrap();
    assert_eq!(pairs(&store), 0);
    assert!(store.path_for(&id).exists());
}

#[test]
fn a_staged_tree_makes_a_checkpoint_seal_the_pack() {
    let (_dir, _layout, store) = fresh_store();
    let batch = store.batch();
    batch
        .put_hashed_chunk(&HashedChunk::new(&bytes(13, 20_000)).unwrap())
        .unwrap();
    let tree = crate::serialize::serialize(&crate::object::Object::Tree(crate::object::Tree {
        entries: Vec::new(),
    }))
    .unwrap();
    batch.write(&tree).unwrap();
    batch.checkpoint().unwrap();
    assert_eq!(pairs(&store), 1);
}

#[cfg(unix)]
#[test]
fn a_checkpoint_publishes_the_pack_before_it_renames_a_manifest() {
    let (_dir, _layout, store) = fresh_store();
    let batch = store.batch();
    let data = bytes(14, 20_000);
    let id = batch
        .put_hashed_chunk(&HashedChunk::new(&data).unwrap())
        .unwrap();
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
    // The pack cannot be published, so the manifest must not become visible.
    for path in fs::read_dir(store.pack_dir()).unwrap() {
        fs::remove_file(path.unwrap().path()).unwrap();
    }
    assert!(batch.checkpoint().is_err());
    assert!(!store.path_for(&manifest_id).exists());
    assert!(batch.commit().is_err());
}

#[test]
fn the_source_sink_does_not_ask_for_ordered_chunks() {
    let (_dir, _layout, store) = fresh_store();
    assert!(!crate::store::EphemeralSink::new(&store).orders_chunks());
}

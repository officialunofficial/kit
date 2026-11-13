//! A worktree file above 1 GiB, up to the chunked bound, ingests with bounded
//! memory, and a file above the bound is refused before anything is written.
//!
//! The files are sparse: a few islands of pseudo-random bytes in a hole, so the
//! chunks differ but the files cost little disk. A counting allocator records
//! the heap one ingest holds at once.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers
#![allow(unsafe_code)] // the counting allocator below wraps `System`

use std::alloc::{GlobalAlloc, Layout, System};
use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use kit_core::layout::RepoLayout;
use kit_core::object::{EntryMode, Object, Tree, TreeEntry};
use kit_core::ops::diff::status_diff;
use kit_core::serialize::{self, MAX_CHUNKED_TOTAL_SIZE};
use kit_core::worktree::{
    self, MAX_FILE_BYTES, WorktreeError, hash_file_with_metadata, hash_file_with_metadata_with,
};
use kit_core::{ObjectStore, index};

const MIB: usize = 1 << 20;
const GIB: u64 = 1 << 30;
/// What one ingest may hold at once. A chunk window is at most 16 MiB and a
/// 2 GiB file has about 32,000 chunk ids of 32 bytes each, so this is far above
/// a bounded ingest and far below the size of the file.
const INGEST_CEILING: usize = 96 * MIB;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
/// The tests share the counters, so each one holds this while it measures.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Records the bytes held at once and their high-water mark.
struct CountingAlloc;

fn grow(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Ordering::Relaxed) + bytes;
    PEAK.fetch_max(live, Ordering::Relaxed);
}

// SAFETY: every method forwards to `System` with the unchanged layout and
// pointer, so `System`'s contract holds. The counters have no effect on the
// allocation.
unsafe impl GlobalAlloc for CountingAlloc {
    // SAFETY: the caller upholds the `GlobalAlloc::alloc` contract. The call
    // forwards the same layout to `System`.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        grow(layout.size());
        // SAFETY: the caller upholds the `GlobalAlloc::alloc` contract for `layout`.
        unsafe { System.alloc(layout) }
    }

    // SAFETY: the caller passes a pointer and layout from a matching `alloc`.
    // The call forwards both to `System` unchanged.
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        // SAFETY: the caller passes a pointer and layout from a matching `alloc`.
        unsafe { System.dealloc(ptr, layout) }
    }

    // SAFETY: the caller passes a pointer and layout from a matching `alloc`.
    // The call forwards them with the new size to `System` unchanged.
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        grow(new_size);
        // SAFETY: the caller passes a pointer and layout from a matching `alloc`.
        let moved = unsafe { System.realloc(ptr, layout, new_size) };
        // The default `realloc` holds both blocks only while it copies, so
        // this keeps that overlap in the high-water mark.
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        moved
    }
}

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

/// The most that `call` holds at once on top of what is already live.
fn peak_of<T>(call: impl FnOnce() -> T) -> (T, usize) {
    let before = LIVE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let out = call();
    (out, PEAK.load(Ordering::Relaxed).saturating_sub(before))
}

/// `len` bytes that no chunk of another `seed` repeats.
fn island(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// A sparse file of `len` bytes with random islands at the start and middle.
fn write_sparse(path: &Path, len: u64) {
    let mut file = fs::File::create(path).unwrap();
    file.set_len(len).unwrap();
    for (n, offset) in [0, len / 2].into_iter().enumerate() {
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(&island(7 + n as u64, 8 * MIB)).unwrap();
    }
}

fn fresh_store(dir: &Path) -> ObjectStore {
    ObjectStore::init(&RepoLayout::single(dir)).unwrap()
}

fn manifest_total(store: &ObjectStore, id: kit_core::hash::Hash) -> u64 {
    match store.read_object(&id).unwrap() {
        Object::ChunkedBlob(manifest) => manifest.total_size(),
        other => panic!("expected a chunked blob, got {other:?}"),
    }
}

#[test]
fn a_two_gib_file_ingests_in_bounded_memory_and_status_stays_clean() {
    let _guard = serial();
    let dir = tempfile::tempdir().unwrap();
    let store = fresh_store(dir.path());
    let work = dir.path().join("work");
    fs::create_dir(&work).unwrap();
    let file = work.join("big.bin");
    write_sparse(&file, 2 * GIB);

    let (result, peak) = peak_of(|| hash_file_with_metadata(&store, &file));
    let (id, _) = result.unwrap();
    assert!(peak < INGEST_CEILING, "ingest held {} MiB", peak / MIB);
    assert_eq!(manifest_total(&store, id), 2 * GIB);

    // The batched, fanned-out path takes a file above 1 GiB within the same
    // bound. Its id differs from the first file's, so this checks memory only.
    let batched = work.join("batched.bin");
    write_sparse(&batched, GIB + 8 * MIB as u64);
    let (result, peak) = peak_of(|| {
        hash_file_with_metadata_with(&store, &batched, |sink, chunks| {
            chunks
                .iter()
                .map(|chunk| worktree::store_chunk_blob(sink, chunk))
                .collect()
        })
    });
    let (batched_id, _) = result.unwrap();
    assert_eq!(manifest_total(&store, batched_id), GIB + 8 * MIB as u64);
    assert!(
        peak < INGEST_CEILING,
        "batched ingest held {} MiB",
        peak / MIB
    );

    // `status` finds the batched file clean in bounded memory.
    let (id, file) = (batched_id, batched);
    let tree = Object::Tree(Tree {
        entries: vec![TreeEntry {
            name: b"big.bin".to_vec(),
            mode: EntryMode::Blob,
            object_hash: id,
        }],
    });
    let tree_id = store.write(&serialize::serialize(&tree).unwrap()).unwrap();
    let idx = index::from_tree(&store, tree_id).unwrap();
    fs::rename(&file, work.join("big.bin")).unwrap();
    let (clean, peak) = peak_of(|| status_diff(&store, Some(&tree_id), &work, Some(&idx)));
    assert!(clean.unwrap().is_empty());
    assert!(peak < INGEST_CEILING, "status held {} MiB", peak / MIB);
}

#[test]
fn a_file_above_the_chunked_bound_is_refused_before_anything_is_written() {
    let _guard = serial();
    let dir = tempfile::tempdir().unwrap();
    let store = fresh_store(dir.path());
    let file = dir.path().join("huge.bin");
    let handle = fs::File::create(&file).unwrap();
    handle.set_len(MAX_CHUNKED_TOTAL_SIZE + 1).unwrap();
    drop(handle);

    let err = hash_file_with_metadata(&store, &file).unwrap_err();
    match &err {
        WorktreeError::FileTooLarge { path, limit } => {
            assert_eq!(path, &file);
            assert_eq!(*limit, MAX_CHUNKED_TOTAL_SIZE);
        }
        other => panic!("expected FileTooLarge, got {other:?}"),
    }
    assert!(
        err.to_string()
            .contains(&MAX_CHUNKED_TOTAL_SIZE.to_string()),
        "the message names the bound: {err}"
    );
    assert!(store.iter_object_hashes().unwrap().is_empty());
}

#[test]
fn the_whole_file_reader_keeps_its_smaller_limit() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("big.bin");
    let handle = fs::File::create(&file).unwrap();
    handle.set_len(MAX_FILE_BYTES + 1).unwrap();
    drop(handle);

    match worktree::read_regular_file_bounded(&file) {
        Err(WorktreeError::FileTooLarge { limit, .. }) => assert_eq!(limit, MAX_FILE_BYTES),
        other => panic!("expected FileTooLarge, got {other:?}"),
    }
}

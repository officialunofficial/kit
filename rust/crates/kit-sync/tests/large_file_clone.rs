//! A file of many chunks clones within a staging budget far smaller than its
//! packs, and a fetch of it holds about one pack in memory.
//!
//! The remote holds one chunked blob spread over many packs. The source
//! measures the staging directory before every pack download, and a counting
//! allocator records the heap a fetch holds at once.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers
#![allow(unsafe_code)] // the counting allocator below wraps `System`

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use kit_core::hash::{self, Hash};
use kit_core::layout::RepoLayout;
use kit_core::object::{Blob, ChunkedBlob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use kit_core::pack::{self, PackWriter};
use kit_core::protocol::{PackKey, Transport};
use kit_core::refs::{self, RefWriteCondition};
use kit_core::sign::{self, KeyPair};
use kit_core::transfer;
use kit_sync::{
    CloneRemote, NoopObserver, RemoteSource, SourceError, SyncOptions, TransportSource, clone,
    fetch, init_clone_dir,
};
use kit_transport_memory::MemoryTransport;

const KIB: usize = 1 << 10;
const MIB: usize = 1 << 20;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
/// The tests share the counters, so each one holds this while it runs.
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

/// A remote whose `main` holds one file of `chunks` chunks of `chunk_len`
/// bytes, spread over packs of `per_pack` chunks each.
struct LargeFile {
    tx: MemoryTransport,
    tip: Hash,
    content: Vec<u8>,
    pack_bytes: usize,
    largest_pack: usize,
}

fn chunk_bytes(index: usize, chunk_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(chunk_len);
    let mut block = 0u64;
    while out.len() < chunk_len {
        let seed = [(index as u64).to_le_bytes(), block.to_le_bytes()].concat();
        out.extend_from_slice(&hash::hash(&seed));
        block += 1;
    }
    out.truncate(chunk_len);
    out
}

fn pack_of(objects: &[Object]) -> Vec<u8> {
    let mut writer = PackWriter::new();
    for object in objects {
        writer
            .push_raw(
                object.id().unwrap(),
                &kit_core::serialize::serialize(object).unwrap(),
            )
            .unwrap();
    }
    writer.finish().unwrap()
}

fn large_file(chunks: usize, chunk_len: usize, per_pack: usize) -> LargeFile {
    let tx = MemoryTransport::new();
    let mut keys = Vec::new();
    let mut content = Vec::with_capacity(chunks * chunk_len);
    let mut chunk_ids = Vec::with_capacity(chunks);
    let mut pending = Vec::new();
    let mut pack_bytes = 0;
    let mut largest_pack = 0;
    let mut upload = |objects: &mut Vec<Object>| {
        let bytes = pack_of(objects);
        objects.clear();
        let key = pack::pack_key(&bytes);
        tx.upload_pack(&bytes, &PackKey::from_hash(key)).unwrap();
        pack_bytes += bytes.len();
        largest_pack = largest_pack.max(bytes.len());
        keys.push(key);
    };
    for index in 0..chunks {
        let data = chunk_bytes(index, chunk_len);
        content.extend_from_slice(&data);
        let blob = Object::Blob(Blob { data });
        chunk_ids.push(blob.id().unwrap());
        pending.push(blob);
        if pending.len() == per_pack {
            upload(&mut pending);
        }
    }
    let manifest = Object::ChunkedBlob(ChunkedBlob {
        total_size: content.len() as u64,
        chunk_size: u32::try_from(chunk_len).unwrap(),
        chunks: chunk_ids,
    });
    let tree = Object::Tree(Tree {
        entries: vec![TreeEntry {
            name: b"large.bin".to_vec(),
            mode: EntryMode::Blob,
            object_hash: manifest.id().unwrap(),
        }],
    });
    let key = KeyPair::generate().unwrap();
    let mut commit = Commit::new_unannotated(
        tree.id().unwrap(),
        Vec::new(),
        Identity::ed25519(key.public.0),
        key.public.0,
        b"large file".to_vec(),
        1_700_000_000,
        [0u8; 64],
    );
    commit.signature = sign::sign_commit(&commit, &key).unwrap().0;
    let commit = Object::Commit(commit);
    let tip = commit.id().unwrap();
    pending.extend([manifest, tree, commit]);
    upload(&mut pending);

    let node = transfer::encode_packlist(None, &keys).unwrap();
    let node_key = hash::hash(&node);
    tx.upload_blob(&node, &PackKey::from_hash(node_key))
        .unwrap();
    tx.update_ref(
        "refs/kit/packmap/main",
        RefWriteCondition::Missing,
        &node_key,
    )
    .unwrap();
    tx.update_ref("refs/heads/main", RefWriteCondition::Missing, &tip)
        .unwrap();
    LargeFile {
        tx,
        tip,
        content,
        pack_bytes,
        largest_pack,
    }
}

/// Bytes in the files under `dir`, at any depth.
fn bytes_under(dir: &Path) -> u64 {
    let mut total = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let meta = entry.metadata().unwrap();
        total += if meta.is_dir() {
            bytes_under(&entry.path())
        } else {
            meta.len()
        };
    }
    total
}

/// Delegates to a transport, recording the staged bytes before each pack
/// download and how many packs it served.
struct MeasuredSource<'a> {
    inner: TransportSource<'a>,
    staging: &'a Path,
    peak_staged: Cell<u64>,
    packs: Cell<usize>,
}

impl RemoteSource for MeasuredSource<'_> {
    fn list_branches(&self) -> Result<Vec<refs::Ref>, SourceError> {
        self.inner.list_branches()
    }
    fn read_ref(&self, name: &str) -> Result<Option<Hash>, SourceError> {
        self.inner.read_ref(name)
    }
    fn download_blob_via_ref(&self, key: &PackKey, ref_name: &str) -> Result<Vec<u8>, SourceError> {
        self.inner.download_blob_via_ref(key, ref_name)
    }
    fn download_pack_via_ref(&self, key: &PackKey, ref_name: &str) -> Result<Vec<u8>, SourceError> {
        let staged = bytes_under(self.staging);
        self.peak_staged.set(self.peak_staged.get().max(staged));
        self.packs.set(self.packs.get() + 1);
        self.inner.download_pack_via_ref(key, ref_name)
    }
}

fn measured<'a>(file: &'a LargeFile, staging: &'a Path) -> MeasuredSource<'a> {
    MeasuredSource {
        inner: TransportSource::new(&file.tx),
        staging,
        peak_staged: Cell::new(0),
        packs: Cell::new(0),
    }
}

fn remote() -> CloneRemote {
    CloneRemote {
        name: "default".to_owned(),
        url: "kit+memory://large".to_owned(),
        kind: "memory".to_owned(),
    }
}

#[test]
fn a_file_of_many_chunks_clones_within_a_small_staging_budget() {
    let _guard = serial();
    let file = large_file(4_096, KIB, 128);
    let budget = 3 * file.largest_pack as u64;
    assert!(budget * 8 < file.pack_bytes as u64);
    let dir = tempfile::tempdir().unwrap();
    let staging = dir.path().join("stage");
    std::fs::create_dir(&staging).unwrap();
    let source = measured(&file, &staging);
    let options = SyncOptions::default()
        .with_staging_dir(Some(staging.clone()))
        .with_max_staged_bytes(budget);
    let target = dir.path().join("work");

    clone(&target, &source, &remote(), &options, &NoopObserver).unwrap();

    assert_eq!(
        std::fs::read(target.join("large.bin")).unwrap(),
        file.content
    );
    // Each pack downloads once, except the first past the budget, which is
    // dropped and downloaded again under the lock.
    assert_eq!(source.packs.get(), 4_096 / 128 + 2);
    let peak = source.peak_staged.get();
    assert!(peak > 0, "the packs that fit the budget are staged");
    assert!(
        peak <= budget,
        "staged {peak} bytes over a {budget}-byte budget"
    );
    assert_eq!(std::fs::read_dir(&staging).unwrap().count(), 0);
}

#[test]
fn fetching_a_file_of_many_chunks_holds_about_one_pack() {
    let _guard = serial();
    let file = large_file(16_384, 2 * KIB, 256);
    let dir = tempfile::tempdir().unwrap();
    let staging = dir.path().join("stage");
    std::fs::create_dir(&staging).unwrap();
    let source = measured(&file, &staging);
    let target = dir.path().join("work");
    init_clone_dir(&target, &remote()).unwrap();
    let options = SyncOptions::default()
        .with_staging_dir(Some(staging.clone()))
        .with_max_staged_bytes(0);

    let (report, peak) = peak_of(|| fetch(&target, &source, "default", &options, &NoopObserver));

    report.unwrap();
    assert_eq!(
        refs::read_remote_ref(&RepoLayout::single(&target), "default", "main").unwrap(),
        Some(file.tip)
    );
    assert_eq!(source.peak_staged.get(), 0, "a zero budget stages nothing");
    // One pack, its unpack working set and the manifest, far below the
    // 32 MiB of packs.
    let ceiling = 8 * MIB;
    assert!(ceiling * 4 <= file.pack_bytes);
    assert!(peak < ceiling, "a fetch held {} KiB at once", peak / KIB);
}

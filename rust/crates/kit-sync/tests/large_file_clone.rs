//! A file of many chunks clones with each pack downloaded once and nothing
//! staged on disk, and a fetch of it holds about one pack in memory.
//!
//! The remote holds one chunked blob spread over many packs. The source looks
//! for a staging directory in the clone before every pack download, and a
//! counting allocator records the heap a fetch holds at once.
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
    let mut upload = |objects: &mut Vec<Object>| {
        let bytes = pack_of(objects);
        objects.clear();
        let key = pack::pack_key(&bytes);
        tx.upload_pack(&bytes, &PackKey::from_hash(key)).unwrap();
        pack_bytes += bytes.len();
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
    let manifest = Object::ChunkedBlob(
        ChunkedBlob::new(
            content.len() as u64,
            u32::try_from(chunk_len).unwrap(),
            chunk_ids,
        )
        .unwrap(),
    );
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
    }
}

/// Entries named `kit-fetch-*` directly under `dir`. A fetch once staged its
/// packs in a directory of that name.
fn staging_entries(dir: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .filter(|entry| {
            entry
                .as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("kit-fetch-")
        })
        .count()
}

/// Delegates to a transport, counting the packs it served and the staging
/// directories it saw in the clone before each download.
struct MeasuredSource<'a> {
    inner: TransportSource<'a>,
    work: &'a Path,
    staging_seen: Cell<usize>,
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
        let seen = staging_entries(self.work) + staging_entries(&self.work.join(".kit"));
        self.staging_seen.set(self.staging_seen.get() + seen);
        self.packs.set(self.packs.get() + 1);
        self.inner.download_pack_via_ref(key, ref_name)
    }
}

fn measured<'a>(file: &'a LargeFile, work: &'a Path) -> MeasuredSource<'a> {
    MeasuredSource {
        inner: TransportSource::new(&file.tx),
        work,
        staging_seen: Cell::new(0),
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
fn a_file_of_many_chunks_clones_with_each_pack_downloaded_once() {
    let _guard = serial();
    let file = large_file(4_096, KIB, 128);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    let source = measured(&file, &target);

    clone(
        &target,
        &source,
        &remote(),
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();

    assert_eq!(
        std::fs::read(target.join("large.bin")).unwrap(),
        file.content
    );
    // 32 packs of chunks and one holding the manifest, tree and commit.
    assert_eq!(source.packs.get(), 4_096 / 128 + 1);
    assert_eq!(source.staging_seen.get(), 0, "no pack is staged on disk");
    assert_eq!(
        staging_entries(&target) + staging_entries(&target.join(".kit")),
        0
    );
}

#[test]
fn fetching_a_file_of_many_chunks_holds_about_one_pack() {
    let _guard = serial();
    let file = large_file(16_384, 2 * KIB, 256);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    let source = measured(&file, &target);
    init_clone_dir(&target, &remote()).unwrap();

    let (report, peak) = peak_of(|| {
        fetch(
            &target,
            &source,
            "default",
            &SyncOptions::default(),
            &NoopObserver,
        )
    });

    report.unwrap();
    assert_eq!(
        refs::read_remote_ref(&RepoLayout::single(&target), "default", "main").unwrap(),
        Some(file.tip)
    );
    assert_eq!(source.staging_seen.get(), 0, "no pack is staged on disk");
    // One pack, its unpack working set and the manifest, far below the
    // 32 MiB of packs.
    let ceiling = 8 * MIB;
    assert!(ceiling * 4 <= file.pack_bytes);
    assert!(peak < ceiling, "a fetch held {} KiB at once", peak / KIB);
}

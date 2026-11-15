//! A file of many chunks clones with each pack downloaded once and no named
//! staging file on disk, and a fetch of it holds about one window of a pack
//! in memory. A push and a fetch of one 1 GiB pack, and a push of 2 GiB of
//! small-file deltas, hold a heap that does not grow with the pack.
//!
//! The remote holds one chunked blob spread over many packs. The source looks
//! for a staging directory in the clone before every pack download: each
//! pack goes to an unnamed spool file in `.kit/tmp/`, which no directory
//! listing shows. A counting allocator records the heap a transfer holds at
//! once. The 1 GiB and 2 GiB tests run in the ignored lane.
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
        tx.upload_pack(
            &kit_core::protocol::SliceBody(&bytes),
            &PackKey::from_hash(key),
            None,
        )
        .unwrap();
        pack_bytes += bytes.len();
        keys.push(key);
    };
    for index in 0..chunks {
        let data = chunk_bytes(index, chunk_len);
        content.extend_from_slice(&data);
        let blob = Object::Blob(Blob { data });
        chunk_ids.push((blob.id().unwrap(), ((index + 1) * chunk_len) as u64));
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
    tx.upload_blob(&node, &PackKey::from_hash(node_key), None)
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

/// Entries in the clone's spool directory, `.kit/tmp/`.
fn spool_entries(work: &Path) -> usize {
    std::fs::read_dir(work.join(".kit").join("tmp")).map_or(0, Iterator::count)
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
    fn list_refs(&self, prefix: &str) -> Result<Vec<refs::Ref>, SourceError> {
        self.inner.list_refs(prefix)
    }
    fn read_ref(&self, name: &str) -> Result<Option<Hash>, SourceError> {
        self.inner.read_ref(name)
    }
    fn download_blob(&self, key: &PackKey, ref_name: &str) -> Result<Vec<u8>, SourceError> {
        self.inner.download_blob(key, ref_name)
    }
    fn download_pack(
        &self,
        key: &PackKey,
        ref_name: &str,
        sink: &mut dyn kit_core::protocol::PackSink,
    ) -> Result<(), SourceError> {
        let seen = staging_entries(self.work) + staging_entries(&self.work.join(".kit"));
        self.staging_seen.set(self.staging_seen.get() + seen);
        self.packs.set(self.packs.get() + 1);
        self.inner.download_pack(key, ref_name, sink)?;
        // The spool holds the whole pack now, and has no name.
        self.staging_seen
            .set(self.staging_seen.get() + spool_entries(self.work));
        Ok(())
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
    assert_eq!(source.staging_seen.get(), 0, "no named staging directory");
    assert_eq!(
        staging_entries(&target) + staging_entries(&target.join(".kit")),
        0
    );
    assert_eq!(spool_entries(&target), 0, "the spools are unnamed");
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
    assert_eq!(source.staging_seen.get(), 0, "no named staging directory");
    assert_eq!(spool_entries(&target), 0, "the spools are unnamed");
    // One spooled pack's window, its unpack working set and the manifest,
    // far below the 32 MiB of packs.
    let ceiling = 8 * MIB;
    assert!(ceiling * 4 <= file.pack_bytes);
    assert!(peak < ceiling, "a fetch held {} KiB at once", peak / KIB);
}

/// Fill `out` with incompressible bytes from `seed`.
fn noise_into(seed: u64, out: &mut [u8]) {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    for chunk in out.chunks_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        chunk.copy_from_slice(&state.to_le_bytes()[..chunk.len()]);
    }
}

/// A repository of `files` files of `len` incompressible bytes, every
/// fourth one ending in `zeros` zero bytes, in 256 directories, committed on top of `parent` by `key`.
/// With `edited`, each
/// file differs from the unedited one by two bytes, so a push of it against
/// the unedited commit sends a delta per file. The objects go straight to
/// the store, one file at a time; HEAD names `main`, which holds the new
/// commit.
fn commit_files(
    work: &Path,
    key: &KeyPair,
    parent: Option<Hash>,
    files: usize,
    len: usize,
    zeros: usize,
    edited: bool,
) -> Hash {
    let layout = RepoLayout::single(work);
    let store = kit_core::store::ObjectStore::open(&layout).unwrap();
    let batch = store.batch();
    let mut data = vec![0u8; len];
    let mut dirs = Vec::new();
    for dir in 0..256usize {
        let mut entries = Vec::new();
        for file in (dir..files).step_by(256) {
            let tail = if file % 4 == 0 { zeros } else { 0 };
            noise_into(file as u64, &mut data[..len - tail]);
            data[len - tail..].fill(0);
            if edited {
                data[len / 3] ^= 1;
                data[2 * len / 3] ^= 1;
            }
            let blob = Object::Blob(Blob {
                data: std::mem::take(&mut data),
            });
            let bytes = kit_core::serialize::serialize(&blob).unwrap();
            entries.push(TreeEntry {
                name: format!("f{file:06}").into_bytes(),
                mode: EntryMode::Blob,
                object_hash: batch.write(&bytes).unwrap(),
            });
            let Object::Blob(Blob { data: back }) = blob else {
                unreachable!()
            };
            data = back;
        }
        if entries.is_empty() {
            continue;
        }
        let tree = Object::Tree(Tree { entries });
        dirs.push(TreeEntry {
            name: format!("d{dir:03}").into_bytes(),
            mode: EntryMode::Tree,
            object_hash: batch
                .write(&kit_core::serialize::serialize(&tree).unwrap())
                .unwrap(),
        });
    }
    let root = Object::Tree(Tree { entries: dirs });
    let root = batch
        .write(&kit_core::serialize::serialize(&root).unwrap())
        .unwrap();
    let mut commit = Commit::new_unannotated(
        root,
        parent.into_iter().collect(),
        Identity::ed25519(key.public.0),
        key.public.0,
        b"many files".to_vec(),
        1_700_000_000 + u64::from(parent.is_some()),
        [0u8; 64],
    );
    commit.signature = sign::sign_commit(&commit, key).unwrap().0;
    let tip = batch
        .write(&kit_core::serialize::serialize(&Object::Commit(commit)).unwrap())
        .unwrap();
    batch.commit().unwrap();
    refs::write_ref(&layout, "main", &tip).unwrap();
    refs::write_head_branch(&layout, "main").unwrap();
    tip
}

/// The sizes of the packs a push uploaded.
#[derive(Default)]
struct Uploads(Mutex<Vec<u64>>);

impl kit_sync::Observer<kit_sync::SyncEvent> for Uploads {
    fn event(&self, event: &kit_sync::SyncEvent) {
        if let kit_sync::SyncEvent::PackUploaded { bytes } = event {
            self.0.lock().unwrap().push(*bytes);
        }
    }
}

/// Push `main` of `work` to `remote`, packs up to `cap` bytes. Returns the
/// sizes of the packs it uploaded and the peak heap.
fn measured_push(work: &Path, remote: &dyn RemoteSource, cap: u64) -> (Vec<u64>, usize) {
    let uploads = Uploads::default();
    let mut options = kit_sync::PushOptions::default();
    options.pack_payload_cap = cap;
    options.control.observer = &uploads;
    let (report, peak) = peak_of(|| kit_sync::push(work, remote, &options));
    report.unwrap();
    (uploads.0.into_inner().unwrap(), peak)
}

/// The entries of a pack of `files` files in 256 directories: the blobs,
/// the trees and the commit.
fn entries_of(files: usize) -> usize {
    files + files.min(256) + 2
}

/// A push and a fetch of one 1 GiB pack over the file transport each hold
/// one window of the pack and the per-entry charge, not the pack. Every
/// fourth file ends in zeros, so a quarter of the entries are zstd frames;
/// the frames' decoded bytes stay within the reader's budget, so the push
/// makes one pack. zstd's own contexts are allocated in C and not counted.
#[test]
#[ignore = "pushes and fetches a 1 GiB pack; run in the ignored lane"]
fn a_push_and_a_fetch_of_one_1_gib_pack_hold_under_96_mib_and_the_entry_charge() {
    const FILES: usize = 17_000;
    const LEN: usize = 64 * KIB;
    const ZEROS: usize = 8 * KIB;
    let _guard = serial();
    let dir = tempfile::tempdir().unwrap();
    let origin = dir.path().join("origin");
    init_clone_dir(&origin, &remote()).unwrap();
    let key = KeyPair::generate().unwrap();
    let tip = commit_files(&origin, &key, None, FILES, LEN, ZEROS, false);
    let tx = kit_transport_file::FileTransport::new(dir.path().join("remote"));
    let source = TransportSource::new(&tx);
    let bound = 96 * MIB + 320 * entries_of(FILES);

    let (packs, push_peak) = measured_push(&origin, &source, pack::MAX_TOTAL_PAYLOAD);
    eprintln!(
        "push of {packs:?} bytes: peak heap {} MiB, bound {} MiB",
        push_peak / MIB,
        bound / MIB
    );
    assert_eq!(packs.len(), 1, "{packs:?}");
    assert!(packs[0] > 1 << 30, "{packs:?}");
    assert!(push_peak < bound, "a push held {push_peak} bytes");

    let target = dir.path().join("work");
    init_clone_dir(&target, &remote()).unwrap();
    let (report, fetch_peak) = peak_of(|| {
        fetch(
            &target,
            &source,
            "default",
            &SyncOptions::default(),
            &NoopObserver,
        )
    });
    report.unwrap();
    eprintln!(
        "fetch of one {}-byte pack: peak heap {} MiB, bound {} MiB",
        packs[0],
        fetch_peak / MIB,
        bound / MIB
    );
    assert_eq!(
        refs::read_remote_ref(&RepoLayout::single(&target), "default", "main").unwrap(),
        Some(tip)
    );
    assert_eq!(spool_entries(&target), 0);
    assert!(fetch_peak < bound, "a fetch held {fetch_peak} bytes");
}

/// A push of 2 GiB of small files, each a delta against the remote's copy,
/// holds under 256 MiB: the streams wait in the push's delta spool, and the
/// encoders run within their in-flight budget.
#[test]
#[ignore = "pushes 2 GiB of deltas; run in the ignored lane"]
fn a_push_of_2_gib_of_small_file_deltas_holds_under_256_mib() {
    const FILES: usize = 65_536;
    const LEN: usize = 32 * KIB;
    let _guard = serial();
    let dir = tempfile::tempdir().unwrap();
    let origin = dir.path().join("origin");
    init_clone_dir(&origin, &remote()).unwrap();
    let key = KeyPair::generate().unwrap();
    let base = commit_files(&origin, &key, None, FILES, LEN, 0, false);
    let tx = kit_transport_file::FileTransport::new(dir.path().join("remote"));
    let source = TransportSource::new(&tx);
    measured_push(&origin, &source, kit_sync::push::DEFAULT_PACK_PAYLOAD_CAP);
    let tip = commit_files(&origin, &key, Some(base), FILES, LEN, 0, true);

    let (packs, peak) = measured_push(&origin, &source, kit_sync::push::DEFAULT_PACK_PAYLOAD_CAP);
    let sent: u64 = packs.iter().sum();
    eprintln!(
        "push of {} files of deltas in {} packs of {sent} bytes: peak heap {} MiB",
        FILES,
        packs.len(),
        peak / MIB
    );
    assert_eq!(source.read_ref("refs/heads/main").unwrap(), Some(tip));
    assert!(
        sent < (FILES * LEN / 8) as u64,
        "deltas, not files: {sent} bytes"
    );
    assert!(peak < 256 * MIB, "a push held {peak} bytes");
}

/// A file remote whose packmap names a 64 MiB "node" is refused at the
/// node bound from the file's length, before any byte of it is read.
#[test]
fn a_64_mib_node_is_refused_before_its_body_is_read() {
    let _guard = serial();
    let dir = tempfile::tempdir().unwrap();
    let tx = kit_transport_file::FileTransport::new(dir.path().join("remote"));
    let node = vec![0u8; 64 * MIB];
    let node_key = hash::hash(&node);
    tx.upload_blob(&node, &PackKey::from_hash(node_key), None)
        .unwrap();
    drop(node);
    tx.update_ref(
        "refs/kit/packmap/main",
        RefWriteCondition::Missing,
        &node_key,
    )
    .unwrap();
    tx.update_ref("refs/heads/main", RefWriteCondition::Missing, &node_key)
        .unwrap();
    let target = dir.path().join("work");
    init_clone_dir(&target, &remote()).unwrap();
    let source = TransportSource::new(&tx);

    let (result, peak) = peak_of(|| {
        fetch(
            &target,
            &source,
            "default",
            &SyncOptions::default(),
            &NoopObserver,
        )
    });

    match result {
        Err(kit_sync::SyncError::Source(SourceError::PayloadTooLarge(len))) => {
            assert_eq!(len, 64 * MIB, "refused from the declared length");
            assert!(transfer::MAX_PACKLIST_NODE_BYTES < len as u64);
        }
        other => panic!("expected the node to be refused, got {other:?}"),
    }
    assert!(peak < 4 * MIB, "the refused fetch held {peak} bytes");
}

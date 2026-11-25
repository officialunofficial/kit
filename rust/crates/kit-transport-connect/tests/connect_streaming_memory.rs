//! A multipart push and a fetch over Connect, streamed and from a pack
//! location, hold a heap that does not grow with the pack.
//!
//! The loopback server writes uploads to files and streams downloads from
//! its file remote, so the counted heap is the client's and a bounded
//! server's. The 1 GiB run is in the ignored lane.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers
#![allow(unsafe_code)] // the counting allocator below wraps `System`

#[path = "support/pack_server.rs"]
mod pack_server;
#[path = "support/streaming.rs"]
mod streaming;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use kit_core::layout::RepoLayout;
use kit_core::pack;
use kit_sync::{ClientSource, NoopObserver, SyncOptions, fetch, init_clone_dir};
use pack_server::{Location, PART_SIZE, PackServer};
use streaming::{Dalek, MIB, client, clone_remote, commit_files, entries_of, http};

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

/// The peak heap of each transfer.
struct Peaks {
    push: usize,
    stream: usize,
    location: usize,
}

/// Push one pack of `files` files of `len` bytes over Connect in parts,
/// then fetch it twice: streamed, and from a pack location. Returns the
/// pack's length and the peak heap of each transfer.
fn push_and_fetch(files: usize, len: usize) -> (u64, Peaks) {
    let dir = tempfile::tempdir().unwrap();
    let server = PackServer::start(&dir.path().join("server"));
    let origin = dir.path().join("origin");
    init_clone_dir(&origin, &clone_remote()).unwrap();
    let tip = commit_files(&origin, files, len);
    let http = http();
    let signer = Dalek::new();
    let client = client(&http, &signer, &server.origin());

    let uploads = Uploads::default();
    let mut options = kit_sync::PushOptions::default();
    options.pack_payload_cap = pack::MAX_TOTAL_PAYLOAD;
    options.control.observer = &uploads;
    let (report, push) = peak_of(|| {
        let source = ClientSource::new(&client, &http);
        kit_sync::push(&origin, &source, &options)
    });
    report.unwrap();
    let packs = uploads.0.into_inner().unwrap();
    assert_eq!(packs.len(), 1, "{packs:?}");
    assert!(
        server.counts().parts.len() as u64 > packs[0] / PART_SIZE,
        "the pack went in parts"
    );

    let mut fetched = Vec::new();
    for mode in [Location::Off, Location::Honest] {
        server.set_location(mode);
        server.reset_counts();
        let work = dir.path().join(format!("{mode:?}"));
        init_clone_dir(&work, &clone_remote()).unwrap();
        // A client caches the server's location support; each mode gets its own.
        let http = streaming::http();
        let client = streaming::client(&http, &signer, &server.origin());
        let (report, peak) = peak_of(|| {
            let source = ClientSource::new(&client, &http);
            fetch(
                &work,
                &source,
                "origin",
                &SyncOptions::default(),
                &NoopObserver,
            )
        });
        report.unwrap();
        assert_eq!(
            kit_core::refs::read_remote_ref(&RepoLayout::single(&work), "origin", "main").unwrap(),
            Some(tip),
            "{mode:?}"
        );
        let counts = server.counts();
        let located = counts.downloads.iter().all(|(_, accept)| *accept)
            && counts.location_gets.len() == counts.downloads.len();
        assert_eq!(located, mode == Location::Honest, "{mode:?}: {counts:?}");
        fetched.push(peak);
    }
    (
        packs[0],
        Peaks {
            push,
            stream: fetched[0],
            location: fetched[1],
        },
    )
}

fn report(pack_len: u64, peaks: &Peaks, bound: usize) {
    eprintln!(
        "pack {} MiB: peak heap push (multipart) {} MiB, fetch stream {} MiB, fetch location {} MiB; bound {} MiB",
        pack_len >> 20,
        peaks.push / MIB,
        peaks.stream / MIB,
        peaks.location / MIB,
        bound / MIB
    );
}

/// The bound of the 1 GiB run below, for `files` files.
fn bound(files: usize) -> usize {
    96 * MIB + 320 * entries_of(files)
}

/// A 160 MiB pack, larger than the bound, moves within it. The fetch's
/// unpack window alone holds up to 64 MiB, so a smaller pack would not
/// tell a held pack from the window.
#[test]
fn a_push_and_fetch_of_a_pack_over_the_bound_hold_under_it() {
    // Keep the 160 MiB payload while reducing durable object writes.
    const FILES: usize = 256;
    const LEN: usize = 640 << 10;
    let _guard = serial();
    let (pack_len, peaks) = push_and_fetch(FILES, LEN);
    let bound = bound(FILES);
    report(pack_len, &peaks, bound);
    assert!(pack_len > bound as u64, "{pack_len}");
    assert!(peaks.push < bound, "a push held {} bytes", peaks.push);
    assert!(peaks.stream < bound, "a fetch held {} bytes", peaks.stream);
    assert!(
        peaks.location < bound,
        "a location fetch held {} bytes",
        peaks.location
    );
}

/// A multipart push and a fetch of one 1 GiB pack, streamed and from a
/// location, each hold under 96 MiB and the per-entry charge.
#[test]
#[ignore = "pushes and fetches a 1 GiB pack; run in the ignored lane"]
fn a_1_gib_push_and_fetch_over_connect_hold_under_96_mib_and_the_entry_charge() {
    const FILES: usize = 17_000;
    const LEN: usize = 64 << 10;
    let _guard = serial();
    let (pack_len, peaks) = push_and_fetch(FILES, LEN);
    let bound = bound(FILES);
    report(pack_len, &peaks, bound);
    assert!(pack_len > 1 << 30, "{pack_len}");
    assert!(peaks.push < bound, "a push held {} bytes", peaks.push);
    assert!(peaks.stream < bound, "a fetch held {} bytes", peaks.stream);
    assert!(
        peaks.location < bound,
        "a location fetch held {} bytes",
        peaks.location
    );
}

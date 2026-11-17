//! A verified blob read holds the payload once. Reading an inline blob
//! allocates one buffer of the payload's size.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers
#![allow(unsafe_code)] // the counting allocator below wraps `System`

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use kit_core::layout::RepoLayout;
use kit_core::object::{Blob, Object};
use kit_core::serialize::serialize;
use kit_core::store::ObjectStore;

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;
/// Room for paths, file handles and other small allocations of one read.
const SLACK: usize = 64 * KIB;

/// Records the bytes held at once and their high-water mark.
struct CountingAlloc;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
/// The tests share the counters, so each one holds this while it measures.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

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
    (out, PEAK.load(Ordering::Relaxed) - before)
}

/// Pseudo-random bytes.
fn random_bytes(len: usize) -> Vec<u8> {
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[0]
        })
        .collect()
}

#[test]
fn an_inline_blob_read_holds_the_payload_once() {
    let _guard = serial();
    let dir = tempfile::tempdir().unwrap();
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
    for len in [0, 4 * KIB, 256 * KIB, MIB] {
        let data = random_bytes(len);
        let h = store
            .write(&serialize(&Object::Blob(Blob { data: data.clone() })).unwrap())
            .unwrap();
        let (read, peak) = peak_of(|| store.read_object(&h).unwrap());
        assert_eq!(read, Object::Blob(Blob { data }));
        assert!(
            peak <= len + SLACK,
            "reading a {len}-byte blob held {peak} bytes"
        );
    }
}

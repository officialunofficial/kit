//! A pack of many minimal entries must stay inside the per-entry charge.
//!
//! A minimal blob entry takes a few bytes on the wire. Ten million of them
//! fit in a pack of about 150 MB, yet each one needs bookkeeping in memory.
//! `PackReader::read` charges `PACK_ENTRY_RESIDENT_COST` bytes per entry to
//! its budget. This test counts the real peak heap use of a read and checks
//! that the charge covers it.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers
#![allow(unsafe_code)] // the counting allocator below wraps `System`

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use kit_core::layout::RepoLayout;
use kit_core::object::{Blob, Object};
use kit_core::pack::PACK_ENTRY_RESIDENT_COST;
use kit_core::{ObjectStore, PackReader, PackWriter, hash::hash, serialize};

/// Tracks live heap bytes and their peak.
struct CountingAlloc;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grow(by: usize) {
    let live = LIVE.fetch_add(by, Ordering::Relaxed) + by;
    PEAK.fetch_max(live, Ordering::Relaxed);
}

// SAFETY: every method forwards to `System` with the unchanged layout and
// pointer, so `System`'s contract holds. The counters have no effect on the
// allocation itself.
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
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        grow(new_size);
        // SAFETY: the caller passes a pointer and layout from a matching `alloc`.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

const ENTRIES: u32 = 30_000;

fn tiny_blob_pack(count: u32) -> Vec<u8> {
    let mut writer = PackWriter::new_raw_only();
    for i in 0..count {
        let bytes = serialize::serialize(&Object::Blob(Blob {
            data: i.to_le_bytes().to_vec(),
        }))
        .unwrap();
        writer.push_raw(hash(&bytes), &bytes).unwrap();
    }
    writer.finish().unwrap()
}

#[test]
fn many_tiny_entries_stay_inside_the_per_entry_charge() {
    let pack = tiny_blob_pack(ENTRIES);
    let dir = tempfile::TempDir::new().unwrap();
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();

    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);
    let report = PackReader::read(&pack, &store).unwrap();
    let peak = PEAK.load(Ordering::Relaxed) - baseline;

    assert_eq!(report.stored.len(), ENTRIES as usize);
    let per_entry = peak / ENTRIES as usize;
    eprintln!("measured {per_entry} bytes per entry, charged {PACK_ENTRY_RESIDENT_COST}");
    assert!(
        per_entry <= PACK_ENTRY_RESIDENT_COST,
        "a read used {per_entry} bytes per entry, above the {PACK_ENTRY_RESIDENT_COST} charged"
    );
}

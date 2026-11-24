//! A blob of N bytes of `\n` is N lines. The diff entry points count lines
//! before they build a line table and show a blob over the line cap as binary,
//! so memory does not grow with the line count.
//!
//! The test counts bytes held at once with a counting allocator (the pattern
//! in `tests/line_diff_memory.rs`).
#![allow(clippy::unwrap_used)]
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use kit_core::ops::{diff_line_counts, unified_hunks};

const MIB: usize = 1 << 20;
/// The counting allocator refuses to pass this, so a runaway stops quickly.
const HARD_CEILING: usize = 3 * 1024 * MIB;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

fn grow(bytes: usize) -> bool {
    // Wrapping arithmetic: the global allocator also sees the harness's own
    // allocations, so a `dealloc` of a block allocated before a reset can
    // drive LIVE below zero. Wrapping keeps the counter from panicking under
    // debug overflow checks; PEAK still captures the measured high-water mark.
    let live = LIVE.fetch_add(bytes, Ordering::Relaxed).wrapping_add(bytes);
    if live <= HARD_CEILING {
        PEAK.fetch_max(live, Ordering::Relaxed);
    }
    if live > HARD_CEILING {
        LIVE.fetch_sub(bytes, Ordering::Relaxed);
        return false;
    }
    true
}

struct CountingAlloc;

// SAFETY: every method forwards to `System` with the unchanged layout/pointer,
// or returns null (which `GlobalAlloc` permits). The counters are inert.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if !grow(layout.size()) {
            return std::ptr::null_mut();
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
            Some(v.saturating_sub(layout.size()))
        })
        .ok();
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if !grow(new_size) {
            return std::ptr::null_mut();
        }
        let moved = unsafe { System.realloc(ptr, layout, new_size) };
        LIVE.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
            Some(v.saturating_sub(layout.size()))
        })
        .ok();
        moved
    }
}

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

/// Peak extra bytes `f` holds at once, above its inputs.
fn peak_of(f: impl FnOnce()) -> usize {
    let _g = serial();
    LIVE.store(0, Ordering::Relaxed);
    PEAK.store(0, Ordering::Relaxed);
    f();
    PEAK.load(Ordering::Relaxed)
}

#[test]
fn newline_blob_past_the_cap_builds_no_line_table() {
    for n in [4 * MIB, 8 * MIB, 16 * MIB] {
        let blob = vec![b'\n'; n]; // n lines, no NUL
        let mut other = blob.clone();
        other[0] = b'x';
        // One byte changed: the diffstat shape pull and merge run.
        let peak = peak_of(|| {
            assert!(unified_hunks(&blob, &other).is_none());
            assert!(diff_line_counts(&blob, &other).is_none());
        });
        eprintln!("bytes={n} peak_bytes={peak}");
        // A table for {n} lines would be 24 bytes per line per side.
        assert!(
            peak <= MIB,
            "diffing {n} bytes of '\\n' held {peak} bytes; the line count must come first"
        );
    }
}

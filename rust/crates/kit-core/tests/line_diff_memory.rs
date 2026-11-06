//! One line diff or text merge of a file up to 1 MiB stays under a fixed memory
//! ceiling however many of its lines changed.
//!
//! These tests watch the bytes that a call holds at once. The allocator refuses
//! to pass a hard ceiling, so a search that grows with the input aborts here
//! and does not exhaust the machine.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers
#![allow(unsafe_code)] // the counting allocator below wraps `System`

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use kit_core::ops::{diff_line_counts, merge_blob_3way, unified_hunks};

const MIB: usize = 1 << 20;
/// What one call may hold at once, on top of its inputs.
const CALL_CEILING: usize = 128 * MIB;
/// The allocator refuses to go past this. It far exceeds `CALL_CEILING` and is
/// small enough that a failing search stops quickly.
const HARD_CEILING: usize = 2048 * MIB;

/// Records the bytes held at once and their high-water mark.
struct CountingAlloc;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
/// The tests share the counters, so each one holds this while it measures.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

fn grow(bytes: usize) -> bool {
    let live = LIVE.fetch_add(bytes, Ordering::Relaxed) + bytes;
    PEAK.fetch_max(live, Ordering::Relaxed);
    if live > HARD_CEILING {
        LIVE.fetch_sub(bytes, Ordering::Relaxed);
        return false;
    }
    true
}

// SAFETY: every method forwards to `System` with the unchanged layout and
// pointer, so `System`'s contract holds, or returns null, which `GlobalAlloc`
// allows for a failed request. The counters have no effect on the allocation.
unsafe impl GlobalAlloc for CountingAlloc {
    // SAFETY: the caller upholds the `GlobalAlloc::alloc` contract. The call
    // forwards the same layout to `System`.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if !grow(layout.size()) {
            return std::ptr::null_mut();
        }
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
        if !grow(new_size) {
            return std::ptr::null_mut();
        }
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

/// `lines` lines of `width` bytes each, all different from another `tag`.
fn rewritten(tag: u8, lines: usize, width: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(lines * width);
    for i in 0..lines {
        out.push(tag);
        out.extend_from_slice(format!("{i:0pad$}\n", pad = width - 2).as_bytes());
    }
    out
}

/// One byte of content per line, the same on every line of a `tag`.
fn short_lines(tag: u8, bytes: usize) -> Vec<u8> {
    [tag, b'\n'].repeat(bytes / 2)
}

fn assert_within_ceiling(what: &str, peak: usize) {
    assert!(peak < CALL_CEILING, "{what} held {} MiB", peak / MIB);
}

#[test]
fn a_rewritten_megabyte_stays_under_the_ceiling() {
    let _guard = serial();
    let old = rewritten(b'a', 13_107, 80);
    let new = rewritten(b'b', 13_107, 80);
    let theirs = rewritten(b'c', 13_107, 80);

    let (hunks, peak) = peak_of(|| unified_hunks(&old, &new));
    assert!(!hunks.unwrap().is_empty());
    assert_within_ceiling("unified_hunks", peak);

    let (counts, peak) = peak_of(|| diff_line_counts(&old, &new));
    assert_eq!(counts, Some((13_107, 13_107)));
    assert_within_ceiling("diff_line_counts", peak);

    let (merged, peak) = peak_of(|| merge_blob_3way(&old, &new, &theirs));
    assert_eq!(merged, None);
    assert_within_ceiling("merge_blob_3way", peak);
}

#[test]
fn short_lines_stay_under_the_ceiling() {
    let _guard = serial();
    for bytes in [32 * 1024, MIB] {
        let base = short_lines(b'a', bytes);
        let ours = short_lines(b'b', bytes);
        let theirs = short_lines(b'c', bytes);

        let (merged, peak) = peak_of(|| merge_blob_3way(&base, &ours, &theirs));
        assert_eq!(merged, None);
        assert_within_ceiling("merge_blob_3way", peak);

        let (counts, peak) = peak_of(|| diff_line_counts(&base, &ours));
        assert_eq!(counts, Some((bytes / 2, bytes / 2)));
        assert_within_ceiling("diff_line_counts", peak);
    }
}

#[test]
fn a_search_near_the_limit_stays_under_the_ceiling() {
    let _guard = serial();
    // Each side changes 2,047 lines of its own half, so each search nearly
    // fills its budget and the merge is clean.
    let lines = 13_107;
    let base = rewritten(b'a', lines, 80);
    let edited = |first_line: usize, tag: u8| {
        let mut out = base.clone();
        for line in 0..2047 {
            out[(first_line + line) * 80] = tag;
        }
        out
    };
    let (ours, theirs) = (edited(0, b'x'), edited(lines / 2, b'y'));

    let (merged, peak) = peak_of(|| merge_blob_3way(&base, &ours, &theirs));
    assert!(merged.is_some());
    assert_within_ceiling("merge_blob_3way", peak);
}

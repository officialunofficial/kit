//! A hostile pack of the smallest frames must not make the decode cursor
//! allocate a record per frame that outweighs the frame by a large factor.
//!
//! The pack header lets a frame be five bytes long, and the declared entry
//! count follows the input size, so what the cursor holds per frame decides
//! how far an untrusted pack amplifies. This test counts live heap bytes
//! across `PackDecodeCursor::new` and the first `resume`.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

use kit_core::hash;
use kit_core::pack::{DecodeLimits, NoExternalBases, PackDecodeCursor};

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grow(by: usize) {
    let live = LIVE.fetch_add(by, Relaxed) + by;
    PEAK.fetch_max(live, Relaxed);
}

// SAFETY: every call forwards to the system allocator unchanged and only
// counts the sizes that it sees.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller upholds the `GlobalAlloc::alloc` contract for `layout`.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            grow(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller passes a pointer and layout from a matching `alloc`.
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller passes a live pointer, its layout and a valid new size.
        let new = unsafe { System.realloc(ptr, layout, new_size) };
        if !new.is_null() {
            if new_size >= layout.size() {
                grow(new_size - layout.size());
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Relaxed);
            }
        }
        new
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// A pack of `frames` frames, each built by `frame(i)` as `(type, payload)`.
fn pack_of(version: u32, frames: usize, frame: impl Fn(usize) -> (u8, Vec<u8>)) -> Vec<u8> {
    let mut pack = b"KIT\0".to_vec();
    pack.extend(version.to_le_bytes());
    pack.extend(u32::try_from(frames).unwrap().to_le_bytes());
    for i in 0..frames {
        let (etype, payload) = frame(i);
        pack.push(etype);
        pack.extend(u32::try_from(payload.len()).unwrap().to_le_bytes());
        pack.extend(payload);
    }
    let trailer = hash::hash(&pack);
    pack.extend(trailer);
    pack
}

/// Peak heap bytes above the baseline while the cursor is built and its
/// first frame is decoded. None of these packs holds a valid object, so
/// `new` or the first `resume` ends in an error or a missing base.
fn peak_extra(pack: &[u8]) -> usize {
    let base = LIVE.load(Relaxed);
    PEAK.store(base, Relaxed);
    if let Ok(mut cursor) = PackDecodeCursor::new(pack, DecodeLimits::default()) {
        let _ = cursor.resume(&mut NoExternalBases, |_| Ok(()));
    }
    PEAK.load(Relaxed) - base
}

#[test]
fn tiny_frames_cost_a_bounded_number_of_bytes_each() {
    let empty_raw = 200_001;
    let pack = pack_of(2, empty_raw, |_| (0x00, Vec::new()));
    let peak = peak_extra(&pack);
    assert!(
        peak <= empty_raw * 32,
        "empty raw frames: {peak} bytes for {empty_raw} frames"
    );

    // A compressed entry too short to hold a zstd frame is refused when the
    // pack is drained, and it reserves nothing.
    let truncated = 200_001;
    let pack = pack_of(2, truncated, |_| (0x03, 0u32.to_le_bytes().to_vec()));
    let peak = peak_extra(&pack);
    assert!(
        peak < 64 * 1024,
        "truncated compressed frames: {peak} bytes for {truncated} frames"
    );

    #[cfg(feature = "pack-zstd")]
    {
        // The smallest zstd entry: a claim of zero and the empty frame.
        let empty = zstd::bulk::compress(&[], 3).unwrap();
        // Just above a power of two, so that growth without a reservation fails.
        let compressed = 33_000;
        let pack = pack_of(2, compressed, |_| {
            let mut payload = 0u32.to_le_bytes().to_vec();
            payload.extend(&empty);
            (0x03, payload)
        });
        let peak = peak_extra(&pack);
        assert!(
            peak <= compressed * 32,
            "compressed frames: {peak} bytes for {compressed} frames"
        );
    }

    // A delta frame names its base, so every distinct base costs one use-count
    // entry. The cost still follows the input: under three times its size.
    let deltas = 20_001;
    let pack = pack_of(1, deltas, |i| {
        let mut payload = [0u8; 32 + 9];
        payload[..8].copy_from_slice(&(i as u64).to_le_bytes());
        (0x02, payload.to_vec())
    });
    let peak = peak_extra(&pack);
    assert!(
        peak <= pack.len() * 3,
        "delta frames: {peak} bytes for a pack of {} bytes",
        pack.len()
    );
}

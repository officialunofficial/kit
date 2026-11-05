//! A compressed entry's claimed size must not drive an allocation before the
//! input backs it.
//!
//! A `0x03` entry carries a four-byte claim of its decompressed size. The
//! reader checks the zstd frame against that claim before it reserves a
//! buffer. These tests build hostile packs from a few bytes and watch the
//! largest allocation request. They never decode gigabytes.
#![cfg(feature = "pack-zstd")]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers
#![allow(unsafe_code)] // the counting allocator below wraps `System`

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use kit_core::layout::RepoLayout;
use kit_core::pack::{MAGIC, PackEntries, PackError, VERSION_V2};
use kit_core::{ObjectStore, PackReader, hash::hash};

/// Records the largest single allocation request.
struct CountingAlloc;

static LARGEST: AtomicUsize = AtomicUsize::new(0);
/// The tests share `LARGEST`, so each one holds this while it measures.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

// SAFETY: every method forwards to `System` with the unchanged layout and
// pointer, so `System`'s contract holds. The counter update has no effect
// on the allocation itself.
unsafe impl GlobalAlloc for CountingAlloc {
    // SAFETY: the caller upholds the `GlobalAlloc::alloc` contract. The call
    // forwards the same layout to `System`.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LARGEST.fetch_max(layout.size(), Ordering::Relaxed);
        // SAFETY: the caller upholds the `GlobalAlloc::alloc` contract for `layout`.
        unsafe { System.alloc(layout) }
    }

    // SAFETY: the caller passes a pointer and layout from a matching `alloc`.
    // The call forwards both to `System` unchanged.
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller passes a pointer and layout from a matching `alloc`.
        unsafe { System.dealloc(ptr, layout) }
    }

    // SAFETY: the caller passes a pointer and layout from a matching `alloc`.
    // The call forwards them with the new size to `System` unchanged.
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LARGEST.fetch_max(new_size, Ordering::Relaxed);
        // SAFETY: the caller passes a pointer and layout from a matching `alloc`.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

const GIB: usize = 1 << 30;
const BLOCK: usize = 128 << 10;
/// A claim well under the largest allocation that the tests tolerate.
const SMALL_ALLOCATION: usize = 1 << 20;

/// One zstd frame with a 128 KiB window and a four-byte content size.
/// `blocks` are `(type, size, body)` triples; the last one gets the flag.
fn frame(content_size: u32, blocks: &[(u32, usize, &[u8])]) -> Vec<u8> {
    let mut out = vec![0x28, 0xB5, 0x2F, 0xFD];
    out.push(0x80); // content size in four bytes, no checksum, no dictionary
    out.push(7 << 3); // window descriptor: 128 KiB
    out.extend_from_slice(&content_size.to_le_bytes());
    for (index, &(kind, size, body)) in blocks.iter().enumerate() {
        let last = u32::from(index + 1 == blocks.len());
        let header = last | (kind << 1) | (u32::try_from(size).unwrap() << 3);
        out.extend_from_slice(&header.to_le_bytes()[..3]);
        out.extend_from_slice(body);
    }
    out
}

/// A frame that declares and claims `size` bytes but holds one block.
fn tiny_frame(size: u32) -> Vec<u8> {
    frame(size, &[(1, BLOCK, &[0])])
}

/// A v2 pack of `0x03` entries: `(claim, frame)` pairs.
fn pack_of(entries: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut body = Vec::from(MAGIC.as_slice());
    body.extend_from_slice(&VERSION_V2.to_le_bytes());
    body.extend_from_slice(&u32::try_from(entries.len()).unwrap().to_le_bytes());
    for (claim, frame) in entries {
        body.push(0x03);
        body.extend_from_slice(&u32::try_from(4 + frame.len()).unwrap().to_le_bytes());
        body.extend_from_slice(&claim.to_le_bytes());
        body.extend_from_slice(frame);
    }
    let trailer = hash(&body);
    body.extend_from_slice(&trailer);
    body
}

fn fresh_store() -> (tempfile::TempDir, ObjectStore) {
    let dir = tempfile::TempDir::new().unwrap();
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
    (dir, store)
}

fn gib_claim() -> u32 {
    u32::try_from(GIB).unwrap()
}

#[test]
fn a_tiny_entry_claiming_a_gibibyte_reserves_nothing() {
    let _guard = serial();
    let (_dir, store) = fresh_store();
    let packs = [
        // The frame holds one block, so it cannot decode to the claim.
        pack_of(&[(gib_claim(), tiny_frame(gib_claim()))]),
        // The frame is not a frame at all.
        pack_of(&[(gib_claim(), vec![0xAA])]),
    ];
    for pack in &packs {
        LARGEST.store(0, Ordering::Relaxed);
        let err = PackReader::read(pack, &store).unwrap_err();
        assert!(
            matches!(
                err,
                PackError::ZstdDecompress(_) | PackError::DecompressedSizeMismatch(..)
            ),
            "got {err:?}"
        );
        assert!(
            LARGEST.load(Ordering::Relaxed) < SMALL_ALLOCATION,
            "reader asked for {} bytes",
            LARGEST.load(Ordering::Relaxed)
        );

        LARGEST.store(0, Ordering::Relaxed);
        let mut entries = PackEntries::new(pack).unwrap();
        let err = entries.next().unwrap().unwrap_err();
        assert!(
            matches!(
                err,
                PackError::ZstdDecompress(_) | PackError::DecompressedSizeMismatch(..)
            ),
            "got {err:?}"
        );
        assert!(
            LARGEST.load(Ordering::Relaxed) < SMALL_ALLOCATION,
            "entry iterator asked for {} bytes",
            LARGEST.load(Ordering::Relaxed)
        );
    }
}

#[test]
fn a_frame_whose_content_size_differs_from_the_claim_is_refused_early() {
    let _guard = serial();
    let (_dir, store) = fresh_store();
    let pack = pack_of(&[(gib_claim(), tiny_frame(u32::try_from(BLOCK).unwrap()))]);
    LARGEST.store(0, Ordering::Relaxed);
    let err = PackReader::read(&pack, &store).unwrap_err();
    assert!(
        matches!(err, PackError::DecompressedSizeMismatch(c, d) if c == GIB && d == BLOCK),
        "got {err:?}"
    );
    assert!(LARGEST.load(Ordering::Relaxed) < SMALL_ALLOCATION);
}

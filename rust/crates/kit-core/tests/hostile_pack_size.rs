//! A peer-declared pack size must not drive an allocation.
//!
//! A transport hands a `PackSink` the length the peer declares. A hostile
//! peer can declare the largest allowed size and send a few bytes. A sink
//! that keeps the body in memory must grow its buffer as bytes arrive. It
//! must not reserve the declared size up front.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers
#![allow(unsafe_code)] // the counting allocator below wraps `System`

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use kit_core::TransportError;
use kit_core::protocol::{MemorySink, PACK_BODY_LIMIT, PackSink};

/// Records the largest single allocation request.
struct CountingAlloc;

static LARGEST: AtomicUsize = AtomicUsize::new(0);

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

#[test]
fn hostile_declared_size_does_not_allocate() {
    let before = LARGEST.load(Ordering::Relaxed);
    let mut sink = MemorySink::new(PACK_BODY_LIMIT);
    sink.begin(Some(PACK_BODY_LIMIT)).unwrap();
    sink.write(&[1, 2, 3]).unwrap();
    let err = sink
        .into_bytes()
        .expect_err("a declared size that does not match the data must fail");
    let after = LARGEST.load(Ordering::Relaxed);

    assert!(matches!(err, TransportError::InvalidResponse));
    assert!(
        before < 1 << 20 && after < 1 << 20,
        "allocated {after} bytes"
    );
}

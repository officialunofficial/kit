//! A peer-declared pack size must not drive an allocation.
//!
//! `Transport::upload_pack_streaming` receives `total_bytes` from the peer.
//! A hostile peer can declare the largest allowed size and send a few bytes.
//! The default implementation must grow its buffer as chunks arrive. It
//! must not reserve the declared size up front.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers
#![allow(unsafe_code)] // the counting allocator below wraps `System`

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use kit_core::protocol::{PACK_BODY_LIMIT, PackChunk};
use kit_core::{Hash, PackKey, Ref, RefWriteCondition, Transport, TransportError, TransportResult};

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

struct SinkTransport;

impl Transport for SinkTransport {
    fn upload_pack(&self, _bytes: &[u8], _key: &PackKey) -> TransportResult<()> {
        Ok(())
    }

    fn download_pack(&self, _key: &PackKey) -> TransportResult<Vec<u8>> {
        Err(TransportError::PackNotFound)
    }

    fn pack_exists(&self, _key: &PackKey) -> TransportResult<bool> {
        Ok(false)
    }

    fn update_ref(
        &self,
        _name: &str,
        _condition: RefWriteCondition,
        _hash: &Hash,
    ) -> TransportResult<()> {
        Ok(())
    }

    fn read_ref(&self, _name: &str) -> TransportResult<Option<Hash>> {
        Ok(None)
    }

    fn list_refs(&self, _prefix: &str) -> TransportResult<Vec<Ref>> {
        Ok(Vec::new())
    }
}

#[test]
fn hostile_declared_size_does_not_allocate() {
    let key = PackKey::new([0x55; 32]);
    let mut chunks = core::iter::once(Ok(PackChunk {
        offset: 0,
        data: vec![1, 2, 3],
        last: true,
    }));

    let before = LARGEST.load(Ordering::Relaxed);
    let err = SinkTransport
        .upload_pack_streaming(&key, PACK_BODY_LIMIT, &mut chunks)
        .expect_err("a declared size that does not match the data must fail");
    let after = LARGEST.load(Ordering::Relaxed);

    assert!(matches!(err, TransportError::ProtocolError));
    assert!(
        before < 1 << 20 && after < 1 << 20,
        "allocated {after} bytes"
    );
}

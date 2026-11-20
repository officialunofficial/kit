//! cargo-fuzz target — local pack index decoder (`pack_index_decode`). See sibling `delta.rs` for guardrail
//! rationale. Invariant: no panic, and an accepted index has sorted ids and in-range entries and re-encodes to itself.

#![no_main]
#![cfg(feature = "libfuzzer")]

use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicU32, Ordering};

use kit_fuzz::{MAX_ITER, pack_index_decode_one_iteration, run_one};

static ITERS: AtomicU32 = AtomicU32::new(0);

fuzz_target!(|data: &[u8]| {
    let n = ITERS.fetch_add(1, Ordering::Relaxed);
    if n >= MAX_ITER {
        return;
    }
    let _ = run_one(data, pack_index_decode_one_iteration);
});

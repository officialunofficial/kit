//! cargo-fuzz target — chunked blob manifest builder (`chunked_blob_build`). See sibling `delta.rs` for guardrail
//! rationale. Invariant: no panic, and the checks in the matching `*_one_iteration` body hold.

#![no_main]
#![cfg(feature = "libfuzzer")]

use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicU32, Ordering};

use kit_fuzz::{MAX_ITER, chunked_blob_build_one_iteration, run_one};

static ITERS: AtomicU32 = AtomicU32::new(0);

fuzz_target!(|data: &[u8]| {
    let n = ITERS.fetch_add(1, Ordering::Relaxed);
    if n >= MAX_ITER {
        return;
    }
    let _ = run_one(data, chunked_blob_build_one_iteration);
});

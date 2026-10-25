//! cargo-fuzz target — sparse checkout wire decoders (`sparse_wire_decode`). See sibling `delta.rs` for guardrail
//! rationale. Invariant: no panic, and no accepted-input invariant beyond the size cap.

#![no_main]
#![cfg(feature = "libfuzzer")]

use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicU32, Ordering};

use kit_fuzz::{MAX_ITER, run_one, sparse_wire_decode_one_iteration};

static ITERS: AtomicU32 = AtomicU32::new(0);

fuzz_target!(|data: &[u8]| {
    let n = ITERS.fetch_add(1, Ordering::Relaxed);
    if n >= MAX_ITER {
        return;
    }
    let _ = run_one(data, sparse_wire_decode_one_iteration);
});

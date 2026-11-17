//! cargo-fuzz target — stored blob read (`ObjectStore::read_object`). See sibling
//! `delta.rs` for guardrail rationale. Invariant: a stored blob reads back exactly as `deserialize` decodes it.

#![no_main]
#![cfg(feature = "libfuzzer")]

use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicU32, Ordering};

use kit_fuzz::{MAX_ITER, run_one, store_read_blob_one_iteration};

static ITERS: AtomicU32 = AtomicU32::new(0);

fuzz_target!(|data: &[u8]| {
    let n = ITERS.fetch_add(1, Ordering::Relaxed);
    if n >= MAX_ITER {
        return;
    }
    let _ = run_one(data, store_read_blob_one_iteration);
});

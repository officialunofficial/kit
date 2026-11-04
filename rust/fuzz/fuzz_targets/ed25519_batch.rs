//! cargo-fuzz target for Ed25519 batch and single verification agreeing.

#![no_main]
#![cfg(feature = "libfuzzer")]

use kit_fuzz::{MAX_ITER, ed25519_batch_one_iteration, run_one};
use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicU32, Ordering};

static ITERS: AtomicU32 = AtomicU32::new(0);

fuzz_target!(|data: &[u8]| {
    let n = ITERS.fetch_add(1, Ordering::Relaxed);
    if n >= MAX_ITER {
        return;
    }
    let _ = run_one(data, ed25519_batch_one_iteration);
});

//! Exercise the bounded parser for the automatic maintenance stamp.

#![no_main]
#![cfg(feature = "libfuzzer")]

use std::sync::atomic::{AtomicU32, Ordering};

use kit_fuzz::{MAX_ITER, maintenance_stamp_one_iteration, run_one};
use libfuzzer_sys::fuzz_target;

static ITERS: AtomicU32 = AtomicU32::new(0);

fuzz_target!(|data: &[u8]| {
    if ITERS.fetch_add(1, Ordering::Relaxed) < MAX_ITER {
        let _ = run_one(data, maintenance_stamp_one_iteration);
    }
});

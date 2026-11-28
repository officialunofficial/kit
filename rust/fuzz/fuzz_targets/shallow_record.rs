//! Exercise the parser for the shallow boundary record `.kit/shallow`.

#![no_main]
#![cfg(feature = "libfuzzer")]

use std::sync::atomic::{AtomicU32, Ordering};

use kit_fuzz::{MAX_ITER, run_one, shallow_record_one_iteration};
use libfuzzer_sys::fuzz_target;

static ITERS: AtomicU32 = AtomicU32::new(0);

fuzz_target!(|data: &[u8]| {
    if ITERS.fetch_add(1, Ordering::Relaxed) < MAX_ITER {
        let _ = run_one(data, shallow_record_one_iteration);
    }
});

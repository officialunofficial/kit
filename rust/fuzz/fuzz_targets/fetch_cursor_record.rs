//! cargo-fuzz target — fetch cursor record parser (`fetch_cursor_record`). See sibling `delta.rs` for guardrail
//! rationale. Invariant: no panic, and an accepted record
//! survives a write and a parse.

#![no_main]
#![cfg(feature = "libfuzzer")]

use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicU32, Ordering};

use kit_fuzz::{MAX_ITER, fetch_cursor_record_one_iteration, run_one};

static ITERS: AtomicU32 = AtomicU32::new(0);

fuzz_target!(|data: &[u8]| {
    let n = ITERS.fetch_add(1, Ordering::Relaxed);
    if n >= MAX_ITER {
        return;
    }
    let _ = run_one(data, fetch_cursor_record_one_iteration);
});

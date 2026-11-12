//! cargo-fuzz target — the listing that the S3 cursor reads
//! (`s3_cursor_listing`). See sibling `delta.rs` for guardrail rationale.
//! Invariant: no panic, and an accepted page holds at most one entry per `<Contents>`
//! element, each with a key, an `ETag` and a `LastModified` time.

#![no_main]
#![cfg(feature = "libfuzzer")]

use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicU32, Ordering};

use kit_fuzz::{MAX_ITER, run_one, s3_cursor_listing_one_iteration};

static ITERS: AtomicU32 = AtomicU32::new(0);

fuzz_target!(|data: &[u8]| {
    let n = ITERS.fetch_add(1, Ordering::Relaxed);
    if n >= MAX_ITER {
        return;
    }
    let _ = run_one(data, s3_cursor_listing_one_iteration);
});

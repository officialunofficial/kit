//! cargo-fuzz target — field-level grant parsers (`grant_fields_parse`). See
//! sibling `delta.rs` for guardrail rationale. Invariant: no panic, and every
//! accepted value re-encodes to exactly the input.

#![no_main]
#![cfg(feature = "libfuzzer")]

use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicU32, Ordering};

use kit_fuzz::{MAX_ITER, grant_field_parsers_one_iteration, run_one};

static ITERS: AtomicU32 = AtomicU32::new(0);

fuzz_target!(|data: &[u8]| {
    let n = ITERS.fetch_add(1, Ordering::Relaxed);
    if n >= MAX_ITER {
        return;
    }
    let _ = run_one(data, grant_field_parsers_one_iteration);
});

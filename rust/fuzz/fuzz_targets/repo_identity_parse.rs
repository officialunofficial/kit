//! cargo-fuzz target — repository and remote identity parsers (`repo_identity_parse`). See sibling `delta.rs` for guardrail
//! rationale. Invariant: no panic, and an accepted value re-parses from its text form to the same text.

#![no_main]
#![cfg(feature = "libfuzzer")]

use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicU32, Ordering};

use kit_fuzz::{MAX_ITER, repo_identity_parse_one_iteration, run_one};

static ITERS: AtomicU32 = AtomicU32::new(0);

fuzz_target!(|data: &[u8]| {
    let n = ITERS.fetch_add(1, Ordering::Relaxed);
    if n >= MAX_ITER {
        return;
    }
    let _ = run_one(data, repo_identity_parse_one_iteration);
});

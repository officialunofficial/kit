//! cargo-fuzz target — trust-roots file text (`trust_roots_parse`). See sibling
//! `delta.rs` for guardrail rationale. Invariant: no panic, and an accepted file
//! round trips through `serialize`.

#![no_main]
#![cfg(feature = "libfuzzer")]

use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicU32, Ordering};

use kit_fuzz::{MAX_ITER, run_one, trust_roots_parse_one_iteration};

static ITERS: AtomicU32 = AtomicU32::new(0);

fuzz_target!(|data: &[u8]| {
    let n = ITERS.fetch_add(1, Ordering::Relaxed);
    if n >= MAX_ITER {
        return;
    }
    let _ = run_one(data, trust_roots_parse_one_iteration);
});

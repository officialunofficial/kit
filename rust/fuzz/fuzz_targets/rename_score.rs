//! cargo-fuzz target — rename scores (`rename_score`). See sibling
//! `delta.rs` for guardrail rationale. Invariant: a threshold parses the same
//! twice and stays in range; a rename pair is symmetric, scores at most 100%
//! and does not depend on chunking.

#![no_main]
#![cfg(feature = "libfuzzer")]

use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicU32, Ordering};

use kit_fuzz::{MAX_ITER, rename_score_one_iteration, run_one};

static ITERS: AtomicU32 = AtomicU32::new(0);

fuzz_target!(|data: &[u8]| {
    let n = ITERS.fetch_add(1, Ordering::Relaxed);
    if n >= MAX_ITER {
        return;
    }
    let _ = run_one(data, rename_score_one_iteration);
});

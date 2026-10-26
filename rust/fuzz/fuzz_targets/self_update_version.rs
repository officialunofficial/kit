//! cargo-fuzz target — release version and tag parsing (`self_update_version`). See sibling
//! `delta.rs` for guardrail rationale. Invariant: no panic, and the version order is reflexive, antisymmetric and transitive.

#![no_main]
#![cfg(feature = "libfuzzer")]

use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicU32, Ordering};

use kit_fuzz::{MAX_ITER, run_one, self_update_version_one_iteration};

static ITERS: AtomicU32 = AtomicU32::new(0);

fuzz_target!(|data: &[u8]| {
    let n = ITERS.fetch_add(1, Ordering::Relaxed);
    if n >= MAX_ITER {
        return;
    }
    let _ = run_one(data, self_update_version_one_iteration);
});

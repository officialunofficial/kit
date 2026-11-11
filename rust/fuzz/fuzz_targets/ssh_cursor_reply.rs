//! cargo-fuzz target — the reply to `ReadRepoCursor` (`ssh_cursor_reply`). See
//! sibling `delta.rs` for guardrail rationale. Invariant: no panic, and an
//! accepted cursor is 1 to 64 bytes from a reply with no unknown field.

#![no_main]
#![cfg(feature = "libfuzzer")]

use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicU32, Ordering};

use kit_fuzz::{MAX_ITER, run_one, ssh_cursor_reply_one_iteration};

static ITERS: AtomicU32 = AtomicU32::new(0);

fuzz_target!(|data: &[u8]| {
    let n = ITERS.fetch_add(1, Ordering::Relaxed);
    if n >= MAX_ITER {
        return;
    }
    let _ = run_one(data, ssh_cursor_reply_one_iteration);
});

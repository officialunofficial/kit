//! cargo-fuzz target for the ssh session of `kit-serve`: arbitrary client
//! bytes after a valid `Hello`.

#![no_main]
#![cfg(feature = "libfuzzer")]

use kit_fuzz::{MAX_ITER, run_one, ssh_session_one_iteration};
use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicU32, Ordering};

static ITERS: AtomicU32 = AtomicU32::new(0);

fuzz_target!(|data: &[u8]| {
    let n = ITERS.fetch_add(1, Ordering::Relaxed);
    if n >= MAX_ITER {
        return;
    }
    let _ = run_one(data, ssh_session_one_iteration);
});

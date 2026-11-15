//! `kit` — CLI binary entry point.
//!
//! The dispatch itself lives in `kit_bin::dispatch` so integration
//! tests can drive the same code path in-process without spawning a
//! subprocess.
#![deny(unsafe_code)]

use std::process::ExitCode;

use kit_bin::{dispatch, signal};

/// The size in bytes above which glibc serves an allocation by `mmap`, and
/// the free space at the top of the heap above which it gives memory back.
///
/// By default glibc raises the first whenever a large `mmap`ed block is
/// freed, up to 32 MiB, and the second with it (to twice that), and from then
/// on keeps the memory of freed blocks below those sizes. A clone of a large file decodes one multi-megabyte manifest per
/// step, so its peak memory grew with the file's size. Fixing the two values
/// stops that and costs no measurable time.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
const MALLOC_THRESHOLD_BYTES: libc::c_int = 128 * 1024;

/// Pin glibc's malloc thresholds before any thread starts.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[allow(unsafe_code)]
fn pin_malloc_thresholds() {
    // SAFETY: `mallopt` only sets a malloc parameter. It reads no pointer,
    // and the two parameter numbers and the value are ones glibc defines.
    // This runs first in `main`, before the process starts a thread, so no
    // allocation races with the change. A failure returns 0, which leaves
    // the defaults in place.
    unsafe {
        libc::mallopt(libc::M_MMAP_THRESHOLD, MALLOC_THRESHOLD_BYTES);
        libc::mallopt(libc::M_TRIM_THRESHOLD, MALLOC_THRESHOLD_BYTES);
    }
}

fn main() -> ExitCode {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    pin_malloc_thresholds();
    signal::install();
    let argv: Vec<String> = std::env::args().collect();
    let code = dispatch(&argv);
    ExitCode::from(code)
}

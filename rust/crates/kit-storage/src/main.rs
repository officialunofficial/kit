//! `kit` — CLI binary entry point.
//!
//! The dispatch itself lives in `kit_storage::dispatch` so integration
//! tests can drive the same code path in-process without spawning a
//! subprocess.
#![forbid(unsafe_code)]

use std::process::ExitCode;

use kit_storage::{dispatch, signal};

fn main() -> ExitCode {
    signal::install();
    let argv: Vec<String> = std::env::args().collect();
    let code = dispatch(&argv);
    ExitCode::from(code)
}

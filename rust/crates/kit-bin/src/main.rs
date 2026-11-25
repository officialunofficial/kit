//! `kit` — CLI binary entry point.
//!
//! The dispatch itself lives in `kit_bin::dispatch` so integration
//! tests can drive the same code path in-process without spawning a
//! subprocess.
#![forbid(unsafe_code)]

use std::process::ExitCode;

use kit_bin::{dispatch, fd_limit, signal};

fn main() -> ExitCode {
    // Before anything reads the limit: the pack handle cache and the worker
    // pools size themselves from it once.
    fd_limit::raise_open_file_limit();
    // Only the binary handles signals; a library caller of `dispatch` keeps
    // its own.
    signal::enable();
    let argv: Vec<String> = std::env::args().collect();
    let code = dispatch(&argv);
    ExitCode::from(code)
}

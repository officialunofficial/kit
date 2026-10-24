//! `mkit` — deprecated alias for `kit`.
//!
//! The shim prints a deprecation notice to stderr. Then it runs the `kit`
//! binary that sits next to it, with the same arguments. It falls back to
//! `kit` on `PATH` when no sibling exists. On Unix the shim replaces its own
//! process, so signals, exit codes and open file descriptors pass through.

use std::path::PathBuf;
use std::process::{Command, ExitCode};

const NOTICE: &str = "warning: `mkit` is deprecated. Use `kit` instead.";

fn kit_path() -> PathBuf {
    let name = format!("kit{}", std::env::consts::EXE_SUFFIX);
    if let Some(dir) = std::env::current_exe()
        .ok()
        .as_deref()
        .and_then(|p| p.parent())
    {
        let sibling = dir.join(&name);
        if sibling.is_file() {
            return sibling;
        }
    }
    PathBuf::from("kit")
}

fn main() -> ExitCode {
    eprintln!("{NOTICE}");
    let mut command = Command::new(kit_path());
    command.args(std::env::args_os().skip(1));
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = command.exec();
        eprintln!("mkit: cannot run kit: {err}");
        ExitCode::from(127)
    }
    #[cfg(not(unix))]
    {
        match command.status() {
            Ok(status) => ExitCode::from(u8::try_from(status.code().unwrap_or(1)).unwrap_or(1)),
            Err(err) => {
                eprintln!("mkit: cannot run kit: {err}");
                ExitCode::from(127)
            }
        }
    }
}

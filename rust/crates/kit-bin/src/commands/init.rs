//! `kit init [-q] [<dir>]` — create a fresh repository rooted at `<dir>`, or at
//! the current dir when `<dir>` is omitted.
//!
//! kit creates a missing `<dir>`, nested levels included. It refuses a
//! `<dir>` that is a symlink, so a repository never lands at a place that the
//! user did not name, and a `<dir>` that is a file.

use std::io::Write;
use std::path::{Path, PathBuf};

use clap::Parser;
use kit_core::refs;
use kit_core::store::{ObjectStore, StoreError};

use crate::clap_args;
use crate::exit;

#[derive(Debug, Parser)]
#[command(
    name = "kit init",
    about = "Create a new kit repository in the current or a named directory."
)]
struct InitOpts {
    /// Print nothing on success. Errors still print.
    #[arg(short = 'q', long)]
    quiet: bool,
    /// The directory to initialise. kit creates it when it is missing.
    dir: Option<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_args::parse::<InitOpts>("kit init", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cannot read cwd: {e}"), exit::NOINPUT),
    };
    let root = match &opts.dir {
        None => cwd,
        Some(dir) => match prepare_dir(&cwd, dir) {
            Ok(root) => root,
            Err(code) => return code,
        },
    };
    let layout = match super::resolve_layout(&root) {
        Ok(layout) => layout,
        Err(code) => return code,
    };
    match ObjectStore::init(&layout) {
        Ok(_) => {}
        Err(StoreError::AlreadyInitialized) => {
            return emit_err("already a kit repository", exit::GENERAL_ERROR);
        }
        Err(e) => return emit_err(&format!("init failed: {e}"), exit::CANTCREAT),
    }
    // Initialize refs + HEAD — HEAD points at refs/heads/main.
    if let Err(e) = refs::init(&layout) {
        return emit_err(&format!("refs init failed: {e}"), exit::CANTCREAT);
    }
    if !opts.quiet {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "initialized empty kit repository in {}/.kit/",
            display(&root)
        );
    }
    exit::OK
}

/// The directory to initialise for `dir`, relative to `cwd`. A missing
/// directory is created. The final component must not be a symlink, because
/// the repository would land where the link points. `components` drops a
/// trailing slash, which would make the OS follow the link.
fn prepare_dir(cwd: &Path, dir: &str) -> Result<PathBuf, u8> {
    if dir.is_empty() {
        return Err(super::usage_error("the directory must not be empty"));
    }
    let path: PathBuf = cwd.join(dir).components().collect();
    match std::fs::symlink_metadata(&path) {
        Ok(meta) if meta.is_dir() => {}
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(emit_err(
                &format!("'{}' is a symbolic link", path.display()),
                exit::CANTCREAT,
            ));
        }
        Ok(_) => {
            return Err(emit_err(
                &format!("'{}' is not a directory", path.display()),
                exit::CANTCREAT,
            ));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Err(e) = std::fs::create_dir_all(&path) {
                return Err(emit_err(
                    &format!("cannot create '{}': {e}", path.display()),
                    exit::CANTCREAT,
                ));
            }
        }
        Err(e) => {
            return Err(emit_err(
                &format!("cannot read '{}': {e}", path.display()),
                exit::CANTCREAT,
            ));
        }
    }
    Ok(path)
}

fn display(p: &Path) -> String {
    p.display().to_string()
}

use super::error as emit_err;

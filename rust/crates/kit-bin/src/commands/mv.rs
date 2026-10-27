//! `kit mv <source>... <dest>` — move or rename tracked paths, staging
//! the change (like `git mv`).
//!
//! Forms:
//! - `mv <src> <dst>` — rename `src` to `dst`, or move it into `dst` when
//!   `dst` is an existing directory.
//! - `mv <src>... <dir>` — move every source into the existing directory
//!   `<dir>`.
//!
//! For each source the worktree file is moved and the index updated: the
//! source path is staged as removed and the destination staged with the
//! source's blob (content is unchanged, so the existing object is reused)
//! and mode. All sources are **validated up front**; nothing on disk or in
//! the index is touched until every move is known to be legal, so a bad
//! source in a batch can't leave the worktree half-moved.
//!
//! Because kit is content-addressed, the moved blob keeps the same object
//! id at its new path, so `kit status` / `kit diff` detect the move as an
//! exact rename and report git's `R` (`renamed: old -> new`) by default —
//! no similarity heuristic needed. `--no-renames` opts back into the
//! delete-plus-add view.
//!
//! Directory sources (`mv dir newdir`, or `mv dir existing-dir/`) are also
//! supported: the directory is renamed on disk in one filesystem operation
//! — so untracked files inside it come along, exactly like `git mv` — and
//! every tracked file beneath it is restaged at its new path (each then
//! surfaces as an exact rename, per the note above). The same up-front
//! validation, clobber guard (`-f`), and repo-escape guard apply, plus a
//! refusal to move a directory into itself.
//!
//! Safety divergences:
//! - refuses to overwrite an existing destination without `-f` (matching
//!   git's `mv` clobber guard), and detects a dangling symlink at the
//!   destination as "exists" (git refuses that too);
//! - refuses a destination that escapes the repository through a
//!   symlinked parent directory (git would silently follow it) — kit
//!   keeps writes inside the repo.
//!
//! The logic is in [`libkit::mv`]. This module parses the arguments.

use clap::Parser;

use crate::clap_args;
use crate::exit;

#[derive(Debug, Parser)]
#[command(
    name = "kit mv",
    about = "Move or rename tracked paths, staging the change."
)]
struct MvOpts {
    /// Overwrite the destination if it already exists.
    #[arg(short = 'f', long)]
    force: bool,
    /// `<source>... <dest>`. With more than one source, `<dest>` must be
    /// an existing directory.
    #[arg(num_args = 2.., required = true)]
    paths: Vec<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_args::parse::<MvOpts>("kit mv", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return super::error(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let layout = match super::resolve_layout(&cwd) {
        Ok(layout) => layout,
        Err(code) => return code,
    };

    // Split `<source>... <dest>` (clap guarantees >= 2 args).
    let Some((dest, sources)) = opts.paths.split_last() else {
        return super::usage_error("usage: kit mv <source>... <dest>");
    };
    if sources.is_empty() {
        return super::usage_error("usage: kit mv <source>... <dest>");
    }

    match libkit::mv::mv(
        &layout,
        &cwd,
        sources,
        dest,
        opts.force,
        &crate::progress::ServedWarning,
    ) {
        Ok(()) => exit::OK,
        Err(e) => super::fail(e),
    }
}

//! `kit worktree` — manage linked working trees.
//!
//! `add <path> [<commit-ish>]`, `list [--porcelain]`,
//! `remove [--force] <path>`, `prune [--dry-run]`, with git's
//! semantics: every linked tree shares the one object store and the
//! shared refs; each tree has its own HEAD, index, and in-progress-op
//! state (see `kit_core::layout` for the split). The logic is in
//! [`libkit::linked`]. This module parses the arguments and prints.

use std::io::Write;
use std::path::Path;

use kit_core::layout::RepoLayout;
use libkit::linked::{self, Checkout};

use crate::clap_args;
use crate::exit;
use crate::format;
use crate::progress::ServedWarning;
use clap::Parser;
use clap::Subcommand;

#[derive(Debug, Parser)]
#[command(name = "kit worktree", about = "Manage linked working trees.")]
struct WorktreeOpts {
    #[command(subcommand)]
    sub: WorktreeCmd,
}

#[derive(Debug, Subcommand)]
enum WorktreeCmd {
    /// Create a linked working tree at <path>.
    ///
    /// With no <commit-ish>, creates a new branch named after the
    /// path's basename (refusing if it exists). A branch <commit-ish>
    /// is checked out (refusing if some other tree already has it);
    /// any other revision yields a detached HEAD.
    Add {
        path: String,
        commit_ish: Option<String>,
    },
    /// List the main and every linked working tree.
    List {
        /// Stable, script-friendly block output (like git's).
        #[arg(long)]
        porcelain: bool,
    },
    /// Remove a linked working tree and its state dir.
    Remove {
        /// Remove even if the tree has local changes or an operation
        /// in progress.
        #[arg(long, short)]
        force: bool,
        path: String,
    },
    /// Delete registry entries whose linked tree is gone.
    Prune {
        /// Report what would be pruned without deleting anything.
        #[arg(long)]
        dry_run: bool,
    },
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_args::parse::<WorktreeOpts>("kit worktree", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let cwd = match std::env::current_dir() {
        Ok(c) => c,
        Err(e) => return super::error(&format!("cwd: {e}"), exit::CONFIG_ERROR),
    };
    let layout = match super::resolve_layout(&cwd) {
        Ok(layout) => layout,
        Err(code) => return code,
    };

    match opts.sub {
        WorktreeCmd::Add { path, commit_ish } => add(&layout, &cwd, &path, commit_ish.as_deref()),
        WorktreeCmd::List { porcelain } => list(&layout, porcelain),
        WorktreeCmd::Remove { force, path } => remove(&layout, &cwd, &path, force),
        WorktreeCmd::Prune { dry_run } => prune(&layout, dry_run),
    }
}

fn add(layout: &RepoLayout, cwd: &Path, path: &str, commit_ish: Option<&str>) -> u8 {
    let added = match super::with_store_config(|config| {
        linked::add(layout, config, cwd, path, commit_ish, &ServedWarning)
    }) {
        Ok(added) => added,
        Err(e) => return super::fail(e),
    };

    let mut stdout = std::io::stdout().lock();
    match &added.checkout {
        Checkout::NewBranch(branch) => {
            let _ = writeln!(stdout, "Preparing worktree (new branch '{branch}')");
        }
        Checkout::Branch(branch) => {
            let _ = writeln!(stdout, "Preparing worktree (checking out '{branch}')");
        }
        Checkout::Detached => {
            let _ = writeln!(
                stdout,
                "Preparing worktree (detached HEAD {})",
                format::short_hash(&added.commit, 8)
            );
        }
    }
    let _ = writeln!(
        stdout,
        "HEAD is now at {} {}",
        format::short_hash(&added.commit, 8),
        added.subject
    );
    exit::OK
}

fn list(layout: &RepoLayout, porcelain: bool) -> u8 {
    let rows = match super::with_store_config(|config| linked::list(layout, config)) {
        Ok(rows) => rows,
        Err(e) => return super::fail(e),
    };

    let mut stdout = std::io::stdout().lock();
    for linked::Entry {
        path,
        head,
        branch,
        prunable,
    } in rows
    {
        if porcelain {
            let _ = writeln!(stdout, "worktree {}", path.display());
            if let Some(h) = head {
                let _ = writeln!(stdout, "HEAD {}", kit_core::hash::to_hex(&h));
            }
            match (&branch, &prunable) {
                (_, Some(reason)) => {
                    let _ = writeln!(stdout, "prunable {reason}");
                }
                (Some(b), None) => {
                    let _ = writeln!(stdout, "branch refs/heads/{b}");
                }
                (None, None) => {
                    let _ = writeln!(stdout, "detached");
                }
            }
            let _ = writeln!(stdout);
        } else {
            let hash_col = head.map_or_else(|| "-".repeat(8), |h| format::short_hash(&h, 8));
            let desc = match (&branch, &prunable) {
                (_, Some(reason)) => format!("(prunable: {reason})"),
                (Some(b), None) => format!("[{b}]"),
                (None, None) => "(detached HEAD)".to_owned(),
            };
            let _ = writeln!(stdout, "{}  {hash_col} {desc}", path.display());
        }
    }
    exit::OK
}

fn remove(layout: &RepoLayout, cwd: &Path, path: &str, force: bool) -> u8 {
    match super::with_store_config(|config| {
        linked::remove(layout, config, cwd, path, force, &ServedWarning)
    }) {
        Ok(()) => exit::OK,
        Err(e) => super::fail(e),
    }
}

fn prune(layout: &RepoLayout, dry_run: bool) -> u8 {
    let result = linked::prune(layout, dry_run, &ServedWarning);
    // A failed prune still reports the entries that went before the failure.
    let done: &[linked::Pruned] = match &result {
        Ok(pruned) | Err(linked::Error::Prune { pruned, .. }) => pruned,
        Err(_) => &[],
    };
    let verb = if dry_run { "would prune" } else { "pruned" };
    {
        let mut stdout = std::io::stdout().lock();
        for linked::Pruned { id, reason } in done {
            let _ = writeln!(stdout, "{verb} worktrees/{id}: {reason}");
        }
    }
    match result {
        Ok(_) => exit::OK,
        Err(e) => super::fail(e),
    }
}

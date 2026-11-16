//! `kit reset [--soft|--mixed] [<commit>]` — move the current branch
//! (or detached HEAD) to `<commit>`, optionally resetting the index.
//!
//! Two modes, mirroring `git reset`'s safe subset:
//!
//! - **`--soft`** — move HEAD / the current branch only. The index and
//!   the worktree are left exactly as they are, so the difference between
//!   the old tip and the new target shows up as staged changes.
//! - **`--mixed`** (the default) — move HEAD *and* rewrite `.kit/index`
//!   to mirror the target commit's tree. The worktree is untouched, so
//!   changes relative to the target appear as un-staged worktree edits.
//!
//! `<commit>` defaults to `HEAD` (a no-op move that still re-syncs the
//! index under `--mixed`) and is resolved through the shared revspec
//! resolver, so a branch, tag, `HEAD`, full/short hash, or `HEAD~n`/`^`
//! navigation all work.
//!
//! - **`--hard`** — move HEAD, reset the index to the target tree, AND
//!   reset the worktree to it (discarding tracked-file changes). Like
//!   git, untracked files are left in place. This is the one destructive
//!   variant, so it runs the same dirty/untracked guard as `checkout`:
//!   it **refuses** to discard locally-modified or staged content
//!   unless `-f`/`--force` is given. That guard is a kit safety
//!   divergence — git's `reset --hard` discards silently.

use std::io::Write;

use clap::Parser;
use kit_core::hash::Hash;
use kit_core::index::EntryStatus;
use kit_core::layout::RepoLayout;
use kit_core::object::Object;
use kit_core::ops::restore::{RestoreOptions, restore_tree_to_worktree_with};
use kit_core::refs::{self, RefWriteCondition};
use kit_core::store::ObjectStore;

use crate::clap_args;
use crate::exit;
use crate::format;

#[derive(Debug, Parser)]
#[command(
    name = "kit reset",
    about = "Move HEAD (and, by default, the index) to a commit."
)]
#[allow(clippy::struct_excessive_bools)] // clap option flags, not a state machine
struct ResetOpts {
    /// Move HEAD only; leave the index and worktree untouched.
    #[arg(long, conflicts_with = "mixed")]
    soft: bool,

    /// Move HEAD and reset the index to the target tree; leave the
    /// worktree untouched. This is the default.
    #[arg(long)]
    mixed: bool,

    /// Move HEAD, reset the index AND the worktree to the target tree
    /// (discarding tracked-file changes; untracked files are kept).
    /// Refuses to discard locally-modified/staged content without `-f`.
    #[arg(long, conflicts_with_all = ["soft", "mixed"])]
    hard: bool,

    /// With `--hard`, discard locally-modified or staged content instead
    /// of refusing (the kit safety guard). No effect without `--hard`.
    #[arg(short = 'f', long)]
    force: bool,

    /// Suppress the `HEAD is now at …` summary (git `-q`).
    #[arg(short = 'q', long)]
    quiet: bool,

    /// Commit to reset to (branch, tag, HEAD, full/short hash, `HEAD~n`,
    /// `^`). Defaults to `HEAD`.
    target: Option<String>,
}

#[must_use]
#[allow(clippy::too_many_lines)] // linear flow over the soft/mixed/hard modes
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_args::parse::<ResetOpts>("kit reset", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let layout = match super::resolve_layout(&cwd) {
        Ok(layout) => layout,
        Err(code) => return code,
    };
    let store = match ObjectStore::open(&layout) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a kit repo: {e}"), exit::GENERAL_ERROR),
    };
    let _lock = match super::acquire_worktree_lock(&layout) {
        Ok(l) => l,
        Err(code) => return code,
    };

    // --soft = HEAD only; --mixed (default) and --hard also reset the
    // index; --hard additionally resets the worktree.
    let reset_index = !opts.soft;

    let spec = opts.target.as_deref().unwrap_or("HEAD");
    let target = match libkit::revspec::resolve_revision(&store, &layout, spec) {
        Ok(h) => h,
        Err(e) => {
            return emit_err(
                &format!("no such commit: {spec} ({e})"),
                exit::GENERAL_ERROR,
            );
        }
    };

    // The target must be a commit/remix; we need its tree for --mixed and
    // we refuse to point HEAD at a bare tree/blob.
    let tree_hash = match store.read_object(&target) {
        Ok(Object::Commit(c)) => c.tree_hash,
        Ok(Object::Remix(r)) => r.tree_hash,
        Ok(_) => {
            return emit_err(
                &format!(
                    "{} does not resolve to a commit or remix",
                    format::short_hash(&target, 8)
                ),
                exit::GENERAL_ERROR,
            );
        }
        Err(e) => return emit_err(&format!("read target commit: {e}"), exit::GENERAL_ERROR),
    };

    // --hard is the one destructive variant: it overwrites the worktree.
    // `clean = false` so the guard/restore KEEP untracked files (git
    // `reset --hard` leaves them); we delete dropped *tracked* files
    // ourselves below.
    let restore_opts = RestoreOptions {
        clean: false,
        sparse_patterns: None,
    };

    // For --hard, capture the tracked paths the target DROPS — each with
    // its current index blob hash — computed from the current index BEFORE
    // it is re-synced. `clean = false` won't delete these, so we remove
    // them ourselves; the hashes let the guard below detect local edits to
    // ignored-but-tracked files that the shared guard cannot see.
    let hard_removed: Vec<(String, EntryStatus, Hash)> = if opts.hard {
        match super::dropped_tracked_paths(&layout, &store, tree_hash) {
            Ok(p) => p,
            Err(e) => return emit_err(&e, exit::GENERAL_ERROR),
        }
    } else {
        Vec::new()
    };

    // Guard BEFORE any mutation, unless `-f`. The shared `checkout` guard
    // refuses if discarding would lose locally-modified, staged, or
    // colliding-untracked content — a kit safety divergence (git's
    // `reset --hard` discards silently). The guard's worktree snapshot now
    // keeps tracked files even when they match an ignore rule, but the
    // dropped-path set (paths present at HEAD/index and gone in the target)
    // is computed and re-checked here directly regardless, so a
    // locally-modified ignored-but-tracked file is never discarded silently.
    if opts.hard && !opts.force {
        if let Err(e) =
            super::ensure_restore_safe_with_options(&layout, &store, tree_hash, &restore_opts)
        {
            return emit_err(
                &format!("{e}\nhint: use `kit reset --hard -f` to discard these changes"),
                exit::GENERAL_ERROR,
            );
        }
        match super::locally_modified_dropped_path(&cwd, &store, &hard_removed) {
            Ok(Some(path)) => {
                return emit_err(
                    &format!(
                        "reset --hard would discard local changes to '{path}'\n\
                         hint: use `kit reset --hard -f` to discard these changes"
                    ),
                    exit::GENERAL_ERROR,
                );
            }
            Ok(None) => {}
            Err(e) => return emit_err(&e, exit::GENERAL_ERROR),
        }
    }

    if opts.hard
        && let Err(e) = kit_core::ops::restore::check_nested_repositories(
            &store,
            tree_hash,
            &cwd,
            &restore_opts,
            None,
        )
    {
        return emit_err(&format!("reset worktree: {e}"), exit::CANTCREAT);
    }

    // If reset moves the branch off its current tip, that old tip may
    // become unreachable — record it right before the move (under the
    // worktree lock) so it stays recoverable, and abort if the log can't be
    // written. Fail closed: an unreadable/corrupt current ref
    // (`resolve_head` Err) aborts before anything is written rather than
    // letting `move_head` clobber it unlogged. `Ok(None)` is an unborn
    // branch (nothing to supersede); a no-op move (old == target) records
    // nothing.
    let superseded = match refs::resolve_head(&layout) {
        Ok(Some(old_head)) if old_head != target => {
            Some((super::head_branch_name(&layout), old_head))
        }
        Ok(_) => None,
        Err(e) => return emit_err(&format!("read HEAD: {e}"), exit::DATAERR),
    };

    // --hard: materialize the target tree into the worktree (overwriting
    // tracked files, keeping untracked ones), then delete the tracked
    // files the target dropped. The files go first and HEAD and the index
    // after, as git does: a reset stopped or failed partway leaves HEAD and
    // the index where they were, so the same reset run again with `-f`
    // finishes it, and the files it wrote show as local changes.
    if opts.hard {
        if let Err(e) = restore_tree_to_worktree_with(
            &store,
            &tree_hash,
            None,
            &cwd,
            &restore_opts,
            &crate::restore_fanout::read_chunks_fanout,
        ) {
            return emit_err(&format!("reset worktree: {e}"), exit::CANTCREAT);
        }
        for (path, _, _) in &hard_removed {
            if let Err(e) = super::remove_dropped_path(&cwd.join(path)) {
                return emit_err(
                    &format!("reset worktree: remove {path}: {e}"),
                    exit::CANTCREAT,
                );
            }
        }
    }

    // Signals are held across the log, HEAD and index writes, so a stopped
    // reset never leaves HEAD moved over the old index.
    let published = crate::signal::defer(|| {
        if let Some((branch, old_head)) = &superseded {
            super::record_superseded(&layout, "reset", branch, *old_head)?;
        }
        move_head(&layout, &target)?;
        if reset_index {
            super::sync_index_to_tree(&layout, &store, tree_hash)
                .map_err(|e| (e, exit::CANTCREAT))?;
        }
        Ok(())
    });
    if let Err((msg, code)) = published {
        return emit_err(&msg, code);
    }

    // git-shaped report: `--hard` prints `HEAD is now at <hash> <subject>`;
    // `--soft`/`--mixed` are silent (git's `--mixed` "Unstaged changes
    // after reset:" list is an optional follow-up).
    if opts.hard && !opts.quiet {
        let subject = match store.read_object(&target) {
            Ok(Object::Commit(c)) => String::from_utf8_lossy(&c.message)
                .lines()
                .next()
                .unwrap_or("")
                .to_owned(),
            _ => String::new(),
        };
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "HEAD is now at {} {subject}",
            format::short_hash(&target, format::SUMMARY_ABBREV),
        );
    }
    exit::OK
}

/// Point the current branch (or detached HEAD) at `target`. Routes branch
/// moves through the history-recording ref helper so a `history-mmr`
/// build journals the move; detached HEAD is rewritten directly.
fn move_head(layout: &RepoLayout, target: &Hash) -> Result<(), (String, u8)> {
    libkit::head::advance(layout, target, RefWriteCondition::Any).map_err(super::head_failure)
}

use super::error as emit_err;

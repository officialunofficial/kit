//! `kit rebase [-i] <revspec> | --continue | --abort | --skip` — replay
//! commits onto a different base. The target is resolved through the
//! shared revspec resolver, so a branch, tag, `HEAD~n`, or full/short
//! hash all work.
//!
//! The logic lives in [`libkit::rebase`]. This command parses the arguments,
//! holds the worktree lock, runs the editor of an interactive rebase and
//! prints the outcome as text or as JSON.

use std::io::Write;

use clap::{Parser, ValueEnum};
use kit_core::store::ObjectStore;
use libkit::Observer;
use libkit::rebase::{self, Editor, Event, Outcome, Request};

use super::error as emit_err;
use crate::clap_args;
use crate::editor;
use crate::exit;
use crate::format::{self, JsonObject, json_string_array};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RebaseFormat {
    Default,
    Json,
}

#[derive(Debug, Parser)]
#[command(name = "kit rebase", about = "Replay commits onto a different base.")]
// CLI flag struct: each bool is an independent clap switch.
#[allow(clippy::struct_excessive_bools)]
struct RebaseOpts {
    /// Continue an in-progress rebase after resolving conflicts.
    #[arg(long = "continue", conflicts_with_all = ["abort", "skip", "branch"])]
    cont: bool,
    /// Abort the in-progress rebase and restore the original HEAD.
    #[arg(long, conflicts_with_all = ["cont", "skip", "branch"])]
    abort: bool,
    /// Skip the current commit (drop it) and continue the rebase.
    #[arg(long, conflicts_with_all = ["cont", "abort", "branch"])]
    skip: bool,
    /// Edit the todo list in `$EDITOR` before replaying: reorder lines,
    /// `drop` (or delete) lines, `reword`, or fold with `squash`/`fixup`.
    /// (`edit` is not yet supported.)
    #[arg(short = 'i', long, conflicts_with_all = ["cont", "abort", "skip"])]
    interactive: bool,
    /// Emit a machine-readable JSON result object to stdout describing
    /// the outcome: a finished rebase, a conflict pause
    /// (`"conflicts":[<path>,...]`), or an error. Best-effort on the
    /// interactive (`-i`) editing path, which is inherently
    /// human-in-the-loop.
    #[arg(long, value_enum, default_value = "default")]
    format: RebaseFormat,
    /// Branch, tag, or revision (e.g. `HEAD~2`, a full/short hash) to
    /// replay commits onto. Resolved through the shared revspec resolver.
    branch: Option<String>,
}

/// Runs `$EDITOR` for the todo list and for commit messages.
struct TerminalEditor;

impl Editor for TerminalEditor {
    fn edit(&mut self, seed: &str) -> std::io::Result<String> {
        editor::spawn_editor(seed)
    }
}

/// Prints the notes of a rebase on stderr.
struct Notes;

impl Observer<Event> for Notes {
    fn event(&self, event: &Event) {
        match event {
            Event::Conflict(inner) => super::conflict::note(inner),
            Event::EmptyReword => {
                let mut stderr = std::io::stderr().lock();
                let _ = writeln!(stderr, "reword: empty message; keeping the original");
            }
            _ => {}
        }
    }
}

/// Print the failure, plus, when `json` is set, a `{"ok":false,...}` line on
/// stdout.
fn fail(failure: rebase::Error, json: bool) -> u8 {
    let failure = libkit::Error::from(failure);
    let message = crate::exit_map::message(&failure);
    if json {
        let mut obj = JsonObject::new();
        obj.field_bool("ok", false).field_str("error", &message);
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(stdout, "{}", obj.finish());
    }
    emit_err(&message, crate::exit_map::exit_code(&failure))
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_args::parse::<RebaseOpts>("kit rebase", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let json = matches!(opts.format, RebaseFormat::Json);
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

    let signing = super::signing::Configured;
    let mut editor = TerminalEditor;
    let result = if opts.abort {
        return abort(&layout, &store, json);
    } else if opts.cont || opts.skip {
        rebase::resume(&layout, &store, opts.skip, &signing, &mut editor, &Notes)
    } else if let Some(onto) = opts.branch.as_deref() {
        rebase::start(
            &layout,
            &store,
            &Request {
                onto,
                interactive: opts.interactive,
            },
            &signing,
            &mut editor,
            &Notes,
        )
    } else {
        return super::usage_error(
            "usage: kit rebase [-i] <revspec> | --continue | --abort | --skip",
        );
    };
    match result {
        Ok(outcome) => report(&outcome, json),
        Err(failure) => fail(failure, json),
    }
}

fn report(outcome: &Outcome, json: bool) -> u8 {
    match outcome {
        Outcome::UpToDate { branch, head } => {
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(stderr, "Current branch {branch} is up to date.");
            drop(stderr);
            if json {
                let mut obj = JsonObject::new();
                obj.field_bool("ok", true)
                    .field_str("kind", "up-to-date")
                    .field_hash("hash", head);
                let mut stdout = std::io::stdout().lock();
                let _ = writeln!(stdout, "{}", obj.finish());
            }
            exit::OK
        }
        Outcome::Paused {
            replaying,
            conflicts,
        } => {
            let mut stderr = std::io::stderr().lock();
            // The git-shaped line for each path, then the hint.
            for rec in conflicts {
                let _ = writeln!(stderr, "CONFLICT (content): Merge conflict in {}", rec.path);
            }
            let _ = writeln!(
                stderr,
                "rebase paused: conflict while replaying {}",
                format::short_hash(replaying, 8)
            );
            let _ = writeln!(
                stderr,
                "resolve the files above, `kit add` them, then run `kit rebase --continue` \
                 (or `--skip` to drop this commit, or `--abort`)"
            );
            drop(stderr);
            if json {
                let paths: Vec<&str> = conflicts.iter().map(|r| r.path.as_str()).collect();
                let mut obj = JsonObject::new();
                obj.field_bool("ok", false)
                    .field_str("kind", "conflict")
                    .field_hash("replaying", replaying)
                    .field_raw("conflicts", &json_string_array(&paths))
                    .field_str("error", "rebase paused: conflict while replaying");
                let mut stdout = std::io::stdout().lock();
                let _ = writeln!(stdout, "{}", obj.finish());
            }
            exit::GENERAL_ERROR
        }
        Outcome::Finished {
            branch,
            old,
            new,
            replayed,
        } => {
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(
                stderr,
                "Successfully rebased and updated refs/heads/{branch}."
            );
            drop(stderr);
            if json {
                let mut obj = JsonObject::new();
                obj.field_bool("ok", true)
                    .field_str("kind", "rebased")
                    .field_str("branch", branch)
                    .field_hash("old", old)
                    .field_hash("new", new)
                    .field_u64("commits_replayed", *replayed as u64);
                let mut stdout = std::io::stdout().lock();
                let _ = writeln!(stdout, "{}", obj.finish());
            }
            exit::OK
        }
        _ => exit::OK,
    }
}

fn abort(layout: &kit_core::layout::RepoLayout, store: &ObjectStore, json: bool) -> u8 {
    let aborted = match rebase::abort(layout, store) {
        Ok(aborted) => aborted,
        Err(failure) => return fail(failure, json),
    };
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(
        stderr,
        "rebase aborted; HEAD restored to {}",
        aborted.branch
    );
    drop(stderr);
    if json {
        let mut obj = JsonObject::new();
        obj.field_bool("ok", true)
            .field_str("kind", "aborted")
            .field_hash("hash", &aborted.head);
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(stdout, "{}", obj.finish());
    }
    exit::OK
}

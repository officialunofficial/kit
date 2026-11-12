//! `kit merge <branch> | --continue | --abort` — merge a branch into
//! HEAD, with a resolvable-conflict workflow.
//!
//! The logic lives in [`libkit::merge`]. This command parses the arguments,
//! holds the worktree lock and prints the outcome as text or as JSON.

use std::io::Write;

use clap::{Parser, ValueEnum};
use kit_core::hash::Hash;
use kit_core::layout::RepoLayout;
use kit_core::store::ObjectStore;
use libkit::merge::{self, Merged, Outcome, Request};

use super::{error as emit_err, load_tree_hash};
use crate::clap_args;
use crate::exit;
use crate::format::{self, JsonObject, json_string_array};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum MergeFormat {
    Default,
    Json,
}

#[derive(Debug, Parser)]
#[command(name = "kit merge", about = "Three-way merge a branch into HEAD.")]
struct MergeOpts {
    /// Continue an in-progress merge after resolving conflicts.
    #[arg(long = "continue", conflicts_with_all = ["abort", "branch"])]
    cont: bool,
    /// Abort the in-progress merge and restore the original HEAD.
    #[arg(long, conflicts_with_all = ["cont", "branch"])]
    abort: bool,
    /// Perform the merge but stop before creating the merge commit (like
    /// `git merge --no-commit`): stage the merged tree and record
    /// `MERGE_HEAD`. Finish with `kit commit` (a two-parent merge commit)
    /// or `kit merge --continue`. Fast-forward updates create no commit,
    /// so `--no-commit` does not affect them.
    #[arg(long = "no-commit", conflicts_with_all = ["cont", "abort"])]
    no_commit: bool,
    /// Override the merge commit message (default `Merge branch '<name>'`).
    #[arg(short = 'm', long = "message", conflicts_with_all = ["cont", "abort"])]
    message: Option<String>,
    /// Emit a machine-readable JSON result object to stdout describing
    /// the outcome: a clean merge/fast-forward, `--no-commit` staging, a
    /// conflict pause (`"conflicts":[<path>,...]`), or an error.
    #[arg(long, value_enum, default_value = "default")]
    format: MergeFormat,
    /// Branch to merge into HEAD.
    branch: Option<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_args::parse::<MergeOpts>("kit merge", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let json = matches!(opts.format, MergeFormat::Json);
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

    if opts.abort {
        abort(&layout, &store, json)
    } else if opts.cont {
        cont(&layout, &store, json)
    } else if let Some(branch) = opts.branch.as_deref() {
        start(
            &layout,
            &store,
            &Request {
                target: branch,
                no_commit: opts.no_commit,
                no_ff: false,
                message: opts.message.as_deref(),
            },
            json,
        )
    } else {
        super::usage_error("usage: kit merge <branch> | --continue | --abort")
    }
}

/// Print the failure, plus, when `json` is set, a `{"ok":false,...}` line on
/// stdout. Every exit path then leaves a `--format=json` caller with a
/// payload, and not only the documented conflict shape.
fn fail(failure: merge::Error, json: bool) -> u8 {
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

#[allow(clippy::too_many_lines)] // one arm of the report for each outcome
pub(super) fn start(
    layout: &RepoLayout,
    store: &ObjectStore,
    request: &Request<'_>,
    json: bool,
) -> u8 {
    let outcome = match merge::start(
        layout,
        store,
        request,
        &super::signing::Configured,
        &super::conflict::Notes,
    ) {
        Ok(outcome) => outcome,
        Err(failure) => return fail(failure, json),
    };
    match outcome {
        Outcome::UpToDate { head } => {
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(stderr, "Already up to date.");
            drop(stderr);
            if json {
                let mut obj = JsonObject::new();
                obj.field_bool("ok", true)
                    .field_str("kind", "up-to-date")
                    .field_hash("hash", &head);
                let mut stdout = std::io::stdout().lock();
                let _ = writeln!(stdout, "{}", obj.finish());
            }
        }
        Outcome::FastForward { old, new } => {
            // The git-shaped report: `Updating <old>..<new>`, `Fast-forward`
            // and the diffstat.
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(
                stderr,
                "Updating {}..{}",
                format::short_hash(&old, format::SUMMARY_ABBREV),
                format::short_hash(&new, format::SUMMARY_ABBREV),
            );
            let _ = writeln!(stderr, "Fast-forward");
            drop(stderr);
            print_merge_stat(store, old, new);
            if json {
                let mut obj = JsonObject::new();
                obj.field_bool("ok", true)
                    .field_str("kind", "fast-forward")
                    .field_hash("old", &old)
                    .field_hash("new", &new);
                let mut stdout = std::io::stdout().lock();
                let _ = writeln!(stdout, "{}", obj.finish());
            }
        }
        Outcome::Conflicted { conflicts } => {
            let mut stderr = std::io::stderr().lock();
            // The git-shaped conflict lines, then the hint for the resumable
            // flow.
            for rec in &conflicts {
                let _ = writeln!(stderr, "CONFLICT (content): Merge conflict in {}", rec.path);
            }
            let _ = writeln!(
                stderr,
                "Automatic merge failed; fix conflicts and then commit the result."
            );
            let _ = writeln!(
                stderr,
                "hint: resolve the files above, `kit add` them, then run \
                 `kit merge --continue` (or `kit merge --abort`)"
            );
            drop(stderr);
            if json {
                let paths: Vec<&str> = conflicts.iter().map(|r| r.path.as_str()).collect();
                let mut obj = JsonObject::new();
                obj.field_bool("ok", false)
                    .field_str("kind", "conflict")
                    .field_raw("conflicts", &json_string_array(&paths))
                    .field_str(
                        "error",
                        "automatic merge failed; fix conflicts and then commit the result",
                    );
                let mut stdout = std::io::stdout().lock();
                let _ = writeln!(stdout, "{}", obj.finish());
            }
            return exit::GENERAL_ERROR;
        }
        Outcome::Staged { tree } => {
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(
                stderr,
                "automatic merge went well; stopped before committing as requested\n\
                 commit the result with `kit commit` (or `kit merge --continue`)"
            );
            drop(stderr);
            if json {
                let mut obj = JsonObject::new();
                obj.field_bool("ok", true)
                    .field_str("kind", "no-commit")
                    .field_hash("tree", &tree);
                let mut stdout = std::io::stdout().lock();
                let _ = writeln!(stdout, "{}", obj.finish());
            }
        }
        Outcome::Merged(merged) => {
            // The git-shaped report of a true merge, and the diffstat from
            // the first parent to the merged tree.
            {
                let mut stderr = std::io::stderr().lock();
                let _ = writeln!(stderr, "Merge made by the 'ort' strategy.");
            }
            print_merge_stat_trees(
                store,
                load_tree_hash(store, merged.ours).ok(),
                Some(merged.tree),
            );
            print_merged_json(&merged, json);
        }
        _ => {}
    }
    exit::OK
}

/// The `--format=json` line of a merge commit.
fn print_merged_json(merged: &Merged, json: bool) {
    if json {
        let mut obj = JsonObject::new();
        obj.field_bool("ok", true)
            .field_str("kind", "merge-commit")
            .field_hash("hash", &merged.commit)
            .field_raw(
                "parents",
                &json_string_array(&[
                    format::hex_hash(&merged.ours),
                    format::hex_hash(&merged.theirs),
                ]),
            )
            .field_hash("tree", &merged.tree);
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(stdout, "{}", obj.finish());
    }
}

/// Best-effort `Fast-forward` / merge diffstat between two commits' trees,
/// reusing `diff`'s renderer. Failures are silent (the headline already
/// printed).
fn print_merge_stat(store: &ObjectStore, old: Hash, new: Hash) {
    let old_tree = load_tree_hash(store, old).ok();
    let new_tree = load_tree_hash(store, new).ok();
    print_merge_stat_trees(store, old_tree, new_tree);
}

fn print_merge_stat_trees(store: &ObjectStore, old_tree: Option<Hash>, new_tree: Option<Hash>) {
    if let Ok(result) = kit_core::ops::diff_trees(store, old_tree, new_tree) {
        let mut stderr = std::io::stderr().lock();
        if let Ok(rows) = libkit::diff::stats(store, &result.entries) {
            let _ = super::diff::render_stat(&mut stderr, &rows);
        }
    }
}

fn cont(layout: &RepoLayout, store: &ObjectStore, json: bool) -> u8 {
    let merged = match merge::resume(layout, store, &super::signing::Configured) {
        Ok(merged) => merged,
        Err(failure) => return fail(failure, json),
    };
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(
        stderr,
        "merge {} into HEAD ({})",
        format::short_hash(&merged.theirs, 8),
        format::short_hash(&merged.commit, 8)
    );
    drop(stderr);
    print_merged_json(&merged, json);
    exit::OK
}

fn abort(layout: &RepoLayout, store: &ObjectStore, json: bool) -> u8 {
    let head = match merge::abort(layout, store) {
        Ok(head) => head,
        Err(failure) => return fail(failure, json),
    };
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "merge aborted; HEAD restored");
    drop(stderr);
    if json {
        let mut obj = JsonObject::new();
        obj.field_bool("ok", true)
            .field_str("kind", "aborted")
            .field_hash("hash", &head);
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(stdout, "{}", obj.finish());
    }
    exit::OK
}

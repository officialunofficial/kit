//! `kit pull [--rebase] [<remote>]` — fetch refs from the configured remote
//! (named, or the flat default), then fast-forward the current branch or, with
//! `--rebase`, replay it onto the fetched branch.

use std::io::Write;
use std::path::Path;

use clap::{Parser, ValueEnum};
use kit_core::hash::Hash;
use kit_core::layout::RepoLayout;
use kit_core::object::Object;

use crate::clap_args;
use crate::config;
use crate::exit;
use crate::format::{self, JsonObject};
use crate::remote_dispatch;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum PullFormat {
    Default,
    Json,
}

#[derive(Debug, Parser)]
#[command(name = "kit pull", about = "Pull changes from the configured remote.")]
// CLI flag struct: each bool is an independent clap switch.
#[allow(clippy::struct_excessive_bools)]
struct PullOpts {
    /// Named remote to pull from (default: the flat default remote).
    remote: Option<String>,
    /// Skip Ed25519 signature verification on newly-fetched commits/
    /// remixes/tags. Verification is ON by default and fails
    /// closed on an unsigned or invalid signature — this flag, or the
    /// user-scoped `pull.require_signed = false` config, is the only way
    /// to opt out. Not settable from repo-scoped config.
    #[arg(long = "no-verify-signatures")]
    no_verify_signatures: bool,
    /// Pull from every configured remote (the flat default plus every
    /// named `remote.<name>.url`) instead of just one, fast-forwarding
    /// the current branch from each in turn. Mutually exclusive with an
    /// explicit `<remote>` argument.
    #[arg(long, conflicts_with = "remote")]
    all: bool,
    /// Fetch, then replay the current branch onto the fetched branch as
    /// `kit rebase` does, instead of fast-forwarding. A conflict pauses the
    /// rebase; finish it with `kit rebase --continue`, `--skip` or `--abort`.
    /// Does not combine with `--all`.
    #[arg(long, conflicts_with = "all")]
    rebase: bool,
    /// Fetch, then merge the fetched branch into the current branch and
    /// always write a merge commit, even when a fast-forward is possible. A
    /// conflict pauses the merge; finish it with `kit merge --continue` or
    /// `--abort`. Does not combine with `--all` or `--rebase`.
    #[arg(long = "no-ff", conflicts_with_all = ["all", "rebase"])]
    no_ff: bool,
    /// Emit a machine-readable JSON result object to stdout:
    /// `{"ok":true,"remote":"...","endpoint":"...","branch":"...",
    /// "old":"<hex>|null","new":"<hex>|null","up_to_date":<bool>}`. With
    /// `--all`, one JSON object is printed per remote pulled. With
    /// `--rebase`, the object is the one that `kit rebase` prints.
    #[arg(long, value_enum, default_value = "default")]
    format: PullFormat,
    /// Suppress transfer progress output on stderr.
    #[arg(short = 'q', long)]
    quiet: bool,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_args::parse::<PullOpts>("kit pull", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let json = matches!(opts.format, PullFormat::Json);
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let layout = match super::resolve_layout(&cwd) {
        Ok(layout) => layout,
        Err(code) => return code,
    };
    let cfg = match config::read_layered(&layout) {
        Ok(c) => c,
        Err(e) => return emit_err_json(&format!("config: {e}"), exit::CONFIG_ERROR, json),
    };
    // Fail closed by default: verify unless `--no-verify-signatures`
    // or the user-scoped `pull.require_signed = false` config opted out.
    let require_signed = !opts.no_verify_signatures && cfg.merged.pull_require_signed_or_default();
    if opts.all {
        let names = config::configured_remote_names(&cfg);
        if names.is_empty() {
            return emit_err_json(
                "no remote configured — use `kit remote add <url>`",
                exit::CONFIG_ERROR,
                json,
            );
        }
        // Pull from every remote in turn, continuing past a per-remote
        // failure so one broken remote doesn't block the others; the
        // worst exit code observed is returned at the end.
        let mut worst = exit::OK;
        for name in names {
            let code = pull_one(&cwd, &layout, &cfg, &name, require_signed, json, &opts);
            if code != exit::OK {
                worst = code;
            }
        }
        return worst;
    }
    pull_one(
        &cwd,
        &layout,
        &cfg,
        opts.remote.as_deref().unwrap_or(""),
        require_signed,
        json,
        &opts,
    )
}

/// Pull from a single named remote (or the flat default when `remote`
/// is empty), fast-forwarding the current branch and reporting a
/// git-style summary. Shared by the single-remote path and the `--all`
/// loop. With `--rebase` it fetches and then rebases.
fn pull_one(
    cwd: &Path,
    layout: &RepoLayout,
    cfg: &config::LayeredConfig,
    remote: &str,
    require_signed: bool,
    json: bool,
    opts: &PullOpts,
) -> u8 {
    let quiet = opts.quiet;
    let Some(resolved) = config::resolve_remote(cfg, remote) else {
        return emit_err_json(
            &if remote.is_empty() {
                "no remote configured — use `kit remote add <url>`".to_owned()
            } else {
                format!("unknown remote '{remote}'")
            },
            exit::CONFIG_ERROR,
            json,
        );
    };
    let endpoint = resolved.endpoint.as_str();
    let progress = crate::progress::start(
        "Unpacking objects",
        None,
        crate::progress::should_report(quiet),
        quiet,
    );
    match remote_dispatch::open_trusted(
        endpoint,
        &resolved.name,
        resolved.repo_chosen,
        cfg,
        layout,
        progress.terminal(),
    ) {
        Ok(tx) => {
            let pull_outcome = {
                let outcome = tx
                    .with_source(|source| {
                        if opts.rebase || opts.no_ff {
                            remote_dispatch::fetch_all_with_source(
                                cwd,
                                source,
                                &resolved.name,
                                require_signed,
                                false,
                                progress.terminal(),
                            )
                            .map(|_| None)
                        } else {
                            remote_dispatch::pull_all_with_source(
                                cwd,
                                source,
                                &resolved.name,
                                None,
                                require_signed,
                                progress.terminal(),
                            )
                            .map(Some)
                        }
                    })
                    .and_then(|result| result);
                // The progress guard's final line lands before the
                // `Updating <a>..<b>` / diffstat summary printed below,
                // not after it.
                drop(progress);
                outcome
            };
            match pull_outcome {
                Ok(None) if opts.no_ff => merge_fetched(layout, &resolved.name, json),
                Ok(None) => rebase_onto_fetched(layout, &resolved.name, json),
                Ok(Some(report)) => {
                    report_fast_forward(layout, &resolved.name, endpoint, report.outcome, json)
                }
                Err(libkit::transfer::Error::Interrupted) => {
                    emit_err_json("pull: interrupted", exit::TEMPFAIL, json)
                }
                Err(e @ libkit::transfer::Error::UnsignedOrInvalidObject { .. }) => {
                    emit_err_json(&format!("pull: {e}"), exit::DATAERR, json)
                }
                Err(e) => emit_err_json(&format!("pull: {e}"), exit::GENERAL_ERROR, json),
            }
        }
        Err(libkit::transfer::Error::UntrustedRemote(msg)) => {
            emit_err_json(&msg, exit::CONFIG_ERROR, json)
        }
        Err(e) => emit_err_json(&format!("open remote: {e}"), exit::PROTOCOL_ERROR, json),
    }
}

/// Print the summary of a fast-forward pull, and its JSON object when `json`
/// is set.
fn report_fast_forward(
    layout: &RepoLayout,
    remote: &str,
    endpoint: &str,
    outcome: kit_sync::PullOutcome,
    json: bool,
) -> u8 {
    let (branch, old_tip, new_tip, up_to_date) = match outcome {
        kit_sync::PullOutcome::UpToDate { branch } => {
            let tip = kit_core::refs::read_ref(layout, &branch).ok().flatten();
            (Some(branch), tip, tip, true)
        }
        kit_sync::PullOutcome::FastForwarded { branch, old, new } => {
            (Some(branch), old, Some(new), false)
        }
        kit_sync::PullOutcome::NoRemoteBranches => {
            let branch = match kit_core::refs::read_head(layout) {
                Ok(kit_core::refs::Head::Branch(branch)) => Some(branch),
                _ => None,
            };
            let tip = branch
                .as_deref()
                .and_then(|branch| kit_core::refs::read_ref(layout, branch).ok().flatten());
            (branch, tip, tip, true)
        }
        _ => {
            return emit_err_json("unsupported pull outcome", exit::GENERAL_ERROR, json);
        }
    };
    report_pull(layout, endpoint, old_tip, new_tip, up_to_date);
    if json {
        let mut obj = JsonObject::new();
        obj.field_bool("ok", true)
            .field_str("remote", remote)
            .field_str("endpoint", endpoint)
            .field_opt_str("branch", branch.as_deref())
            .field_opt_hash("old", old_tip.as_ref())
            .field_opt_hash("new", new_tip.as_ref())
            .field_bool("up_to_date", up_to_date);
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(stdout, "{}", obj.finish());
    }
    exit::OK
}

/// Rebase the current branch onto the branch that the fetch updated, unless
/// the branch has that tip already.
fn rebase_onto_fetched(layout: &RepoLayout, remote: &str, json: bool) -> u8 {
    let _lock = match super::acquire_worktree_lock(layout) {
        Ok(lock) => lock,
        Err(code) => return code,
    };
    let branch = match kit_core::refs::read_head(layout) {
        Ok(kit_core::refs::Head::Branch(branch)) => branch,
        Ok(kit_core::refs::Head::Detached(_)) => {
            return emit_err_json("pull: cannot rebase a detached HEAD", exit::USAGE, json);
        }
        Err(e) => {
            return emit_err_json(&format!("pull: read HEAD: {e}"), exit::GENERAL_ERROR, json);
        }
    };
    let upstream = match kit_core::refs::read_remote_ref(layout, remote, &branch) {
        Ok(Some(tip)) => tip,
        Ok(None) => {
            return emit_err_json(
                &format!("pull: the remote has no branch '{branch}' to rebase onto"),
                exit::GENERAL_ERROR,
                json,
            );
        }
        Err(e) => {
            return emit_err_json(
                &format!("pull: read tracking ref: {e}"),
                exit::GENERAL_ERROR,
                json,
            );
        }
    };
    let store = match crate::commands::open_store_configured(layout) {
        Ok(store) => store,
        Err(e) => {
            return emit_err_json(&format!("pull: open store: {e}"), exit::GENERAL_ERROR, json);
        }
    };
    // A branch that holds the fetched tip has nothing to replay. Replaying it
    // would rewrite its commits for no change.
    if let Ok(Some(head)) = kit_core::refs::resolve_head(layout) {
        match kit_core::ops::merge::is_ancestor_strict(&store, upstream, head) {
            Ok(true) => {
                let outcome = libkit::rebase::Outcome::UpToDate { branch, head };
                return super::rebase::report(&outcome, json);
            }
            Ok(false) => {}
            Err(e) => {
                return emit_err_json(&format!("pull: {e}"), exit::GENERAL_ERROR, json);
            }
        }
    }
    super::rebase::rebase_onto(layout, &store, &kit_core::hash::to_hex(&upstream), json)
}

/// Merge the branch that the fetch updated into the current branch, and write
/// a merge commit even when a fast-forward is possible. A branch that holds
/// the fetched tip is up to date and gets no commit.
fn merge_fetched(layout: &RepoLayout, remote: &str, json: bool) -> u8 {
    let _lock = match super::acquire_worktree_lock(layout) {
        Ok(lock) => lock,
        Err(code) => return code,
    };
    let branch = match kit_core::refs::read_head(layout) {
        Ok(kit_core::refs::Head::Branch(branch)) => branch,
        Ok(kit_core::refs::Head::Detached(_)) => {
            return emit_err_json("pull: cannot merge into a detached HEAD", exit::USAGE, json);
        }
        Err(e) => {
            return emit_err_json(&format!("pull: read HEAD: {e}"), exit::GENERAL_ERROR, json);
        }
    };
    let upstream = match kit_core::refs::read_remote_ref(layout, remote, &branch) {
        Ok(Some(tip)) => tip,
        Ok(None) => {
            return emit_err_json(
                &format!("pull: the remote has no branch '{branch}' to merge"),
                exit::GENERAL_ERROR,
                json,
            );
        }
        Err(e) => {
            return emit_err_json(
                &format!("pull: read tracking ref: {e}"),
                exit::GENERAL_ERROR,
                json,
            );
        }
    };
    let store = match crate::commands::open_store_configured(layout) {
        Ok(store) => store,
        Err(e) => {
            return emit_err_json(&format!("pull: open store: {e}"), exit::GENERAL_ERROR, json);
        }
    };
    // The merge treats a fetched tip that `HEAD` already holds as a base, and
    // would write an empty merge commit for it.
    if let Ok(Some(head)) = kit_core::refs::resolve_head(layout) {
        match kit_core::ops::merge::is_ancestor_strict(&store, upstream, head) {
            Ok(true) => {
                let _ = writeln!(std::io::stderr().lock(), "Already up to date.");
                return exit::OK;
            }
            Ok(false) => {}
            Err(e) => {
                return emit_err_json(&format!("pull: {e}"), exit::GENERAL_ERROR, json);
            }
        }
    }
    // The tracking ref names the target, so the message reads `Merge
    // remote-tracking branch '<remote>/<branch>'`.
    let target = format!("refs/remotes/{remote}/{branch}");
    super::merge::start(
        layout,
        &store,
        &libkit::merge::Request {
            target: &target,
            no_commit: false,
            no_ff: true,
            message: None,
        },
        json,
    )
}

/// `error(msg, code)` plus, when `json` is set, a `{"ok":false,...}`
/// line on stdout.
fn emit_err_json(msg: &str, code: u8, json: bool) -> u8 {
    if json {
        let mut obj = JsonObject::new();
        obj.field_bool("ok", false).field_str("error", msg);
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(stdout, "{}", obj.finish());
    }
    emit_err(msg, code)
}

/// Render git's post-pull summary on stderr: `Already up to date.` for a
/// no-op, else `From <url>` + `Updating <old>..<new>` + `Fast-forward` +
/// the diffstat. The diffstat is best-effort — a failure to compute it
/// still leaves the headline lines intact.
fn report_pull(
    layout: &RepoLayout,
    endpoint: &str,
    old: Option<Hash>,
    new: Option<Hash>,
    up_to_date: bool,
) {
    let mut stderr = std::io::stderr().lock();
    match (old, new) {
        _ if up_to_date => {
            let _ = writeln!(stderr, "Already up to date.");
        }
        (o, n) if o == n => {
            let _ = writeln!(stderr, "Completed interrupted pull.");
        }
        (Some(o), Some(n)) => {
            let _ = writeln!(stderr, "From {endpoint}");
            let _ = writeln!(
                stderr,
                "Updating {}..{}",
                format::short_hash(&o, format::SUMMARY_ABBREV),
                format::short_hash(&n, format::SUMMARY_ABBREV),
            );
            let _ = writeln!(stderr, "Fast-forward");
            drop(stderr);
            print_ff_stat(layout, o, n);
        }
        _ => {
            // First-ever pull populating an empty branch: objects, HEAD,
            // and worktree are already updated by `pull_all`; stay quiet
            // rather than print a misleading `Updating <none>..` line.
        }
    }
}

/// Best-effort `Fast-forward` diffstat between two commits' trees,
/// reusing `diff`'s renderer.
fn print_ff_stat(layout: &RepoLayout, old: Hash, new: Hash) {
    let Ok(store) = crate::commands::open_store_configured(layout) else {
        return;
    };
    let (Some(old_tree), Some(new_tree)) = (tree_of(&store, old), tree_of(&store, new)) else {
        return;
    };
    if let Ok(result) = kit_core::ops::diff_trees(&store, Some(old_tree), Some(new_tree)) {
        let mut stderr = std::io::stderr().lock();
        if let Ok(rows) = libkit::diff::stats(&store, &result.entries) {
            let _ = super::diff::render_stat(&mut stderr, &rows);
        }
    }
}

fn tree_of(store: &kit_core::store::ObjectStore, commit: Hash) -> Option<Hash> {
    match store.read_object(&commit).ok()? {
        Object::Commit(c) => Some(c.tree_hash),
        Object::Remix(r) => Some(r.tree_hash),
        _ => None,
    }
}

use super::error as emit_err;

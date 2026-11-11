//! `kit fetch [<remote>]` — like `pull` but does NOT move HEAD.
//! Downloads every object reachable from each remote ref and updates
//! the `refs/remotes/<remote>/<name>` tracking refs.

use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

use clap::{Parser, ValueEnum};
use kit_core::hash::Hash;
use kit_core::layout::RepoLayout;

use crate::clap_args;
use crate::config;
use crate::exit;
use crate::format::{self, JsonObject};
use crate::remote_dispatch;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FetchFormat {
    Default,
    Json,
}

#[derive(Debug, Parser)]
#[command(
    name = "kit fetch",
    about = "Download from the configured remote without merging."
)]
#[allow(clippy::struct_excessive_bools)] // clap option flags, not a state machine
struct FetchOpts {
    /// Named remote to fetch from (default: the flat default remote).
    remote: Option<String>,
    /// Skip Ed25519 signature verification on newly-fetched commits/
    /// remixes/tags. Verification is ON by default and fails
    /// closed on an unsigned or invalid signature — this flag, or the
    /// user-scoped `pull.require_signed = false` config, is the only way
    /// to opt out. Not settable from repo-scoped config.
    #[arg(long = "no-verify-signatures")]
    no_verify_signatures: bool,
    /// Fetch every configured remote (the flat default plus every
    /// named `remote.<name>.url`) instead of just one. Mutually
    /// exclusive with an explicit `<remote>` argument.
    #[arg(long, conflicts_with = "remote")]
    all: bool,
    /// After the fetch, delete the remote-tracking refs whose branch is gone
    /// from the remote. It deletes no local branch and no tag, and only after
    /// every remote branch was fetched and verified.
    #[arg(short = 'p', long)]
    prune: bool,
    /// Emit a machine-readable JSON result object to stdout:
    /// `{"ok":true,"remote":"...","endpoint":"...","updated":[{"name":"...",
    /// "old":"<hex>|null","new":"<hex>"}]}`, plus `"pruned":["..."]` with
    /// `--prune`. With `--all`, one JSON object is printed per remote
    /// fetched.
    #[arg(long, value_enum, default_value = "default")]
    format: FetchFormat,
    /// Suppress transfer progress output on stderr.
    #[arg(short = 'q', long)]
    quiet: bool,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_args::parse::<FetchOpts>("kit fetch", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let json = matches!(opts.format, FetchFormat::Json);
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
        // Fetch every remote in turn, continuing past a per-remote
        // failure so one broken remote doesn't block the others; the
        // worst exit code observed is returned at the end.
        let mut worst = exit::OK;
        for name in names {
            let code = fetch_one(&cwd, &layout, &cfg, &name, &opts, require_signed);
            if code != exit::OK {
                worst = code;
            }
        }
        return worst;
    }
    fetch_one(
        &cwd,
        &layout,
        &cfg,
        opts.remote.as_deref().unwrap_or(""),
        &opts,
        require_signed,
    )
}

/// Fetch a single named remote (or the flat default when `remote` is
/// empty), snapshotting + reporting its tracking-ref movement. Shared
/// by the single-remote path and the `--all` loop.
fn fetch_one(
    cwd: &Path,
    layout: &RepoLayout,
    cfg: &config::LayeredConfig,
    remote: &str,
    opts: &FetchOpts,
    require_signed: bool,
) -> u8 {
    let json = matches!(opts.format, FetchFormat::Json);
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
    // Snapshot the remote-tracking refs so we can report exactly which
    // ones moved (git prints nothing when nothing changed).
    let before = tracking_snapshot(layout, &resolved.name);
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
            let fetch_outcome = {
                let outcome = tx
                    .with_source(|source| {
                        remote_dispatch::fetch_all_with_source(
                            cwd,
                            source,
                            &resolved.name,
                            require_signed,
                            opts.prune,
                            progress.terminal(),
                        )
                    })
                    .and_then(|result| result);
                // The progress guard's final line lands before the
                // `From <url>` summary printed below.
                drop(progress);
                outcome
            };
            match fetch_outcome {
                Ok(_) => {
                    let after = tracking_snapshot(layout, &resolved.name);
                    report_fetch(endpoint, &resolved.name, &before, &after);
                    if json {
                        emit_fetch_json(&resolved.name, endpoint, &before, &after, opts.prune);
                    }
                    exit::OK
                }
                Err(libkit::transfer::Error::Interrupted) => {
                    emit_err_json("fetch: interrupted", exit::TEMPFAIL, json)
                }
                Err(e @ libkit::transfer::Error::UnsignedOrInvalidObject { .. }) => {
                    emit_err_json(&format!("fetch: {e}"), exit::DATAERR, json)
                }
                Err(e) => emit_err_json(&format!("fetch: {e}"), exit::GENERAL_ERROR, json),
            }
        }
        Err(libkit::transfer::Error::UntrustedRemote(msg)) => {
            emit_err_json(&msg, exit::CONFIG_ERROR, json)
        }
        Err(e) => emit_err_json(&format!("open remote: {e}"), exit::PROTOCOL_ERROR, json),
    }
}

/// Emit the `--format=json` success payload: the same changed-tracking-ref
/// set `report_fetch` prints as text, as a JSON array.
fn emit_fetch_json(
    remote: &str,
    endpoint: &str,
    before: &HashMap<String, Hash>,
    after: &HashMap<String, Hash>,
    prune: bool,
) {
    let mut changed: Vec<(&String, Option<Hash>, Hash)> = after
        .iter()
        .filter(|(name, new)| before.get(*name) != Some(*new))
        .map(|(name, new)| (name, before.get(name).copied(), *new))
        .collect();
    changed.sort_by(|a, b| a.0.cmp(b.0));
    let entries: Vec<String> = changed
        .iter()
        .map(|(name, old, new)| {
            let mut obj = JsonObject::new();
            obj.field_str("name", name)
                .field_opt_hash("old", old.as_ref())
                .field_hash("new", new);
            obj.finish()
        })
        .collect();
    let mut top = JsonObject::new();
    top.field_bool("ok", true)
        .field_str("remote", remote)
        .field_str("endpoint", endpoint)
        .field_raw("updated", &format!("[{}]", entries.join(",")));
    if prune {
        let names: Vec<String> = pruned_names(before, after)
            .iter()
            .map(|name| format!("\"{}\"", format::json_escape(name)))
            .collect();
        top.field_raw("pruned", &format!("[{}]", names.join(",")));
    }
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "{}", top.finish());
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

/// Map of `refs/remotes/<remote>/<branch>` → tip, used to diff the
/// tracking-ref state across a fetch.
fn tracking_snapshot(layout: &RepoLayout, remote: &str) -> HashMap<String, Hash> {
    super::list_remote_refs_parallel(layout, remote)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|r| r.hash.map(|h| (r.name, h)))
        .collect()
}

/// Print git's `From <url>` block with one summary line per moved
/// tracking ref. Stays silent when nothing changed.
fn report_fetch(
    endpoint: &str,
    remote: &str,
    before: &HashMap<String, Hash>,
    after: &HashMap<String, Hash>,
) {
    let mut changed: Vec<(&String, Option<Hash>, Hash)> = after
        .iter()
        .filter(|(name, new)| before.get(*name) != Some(*new))
        .map(|(name, new)| (name, before.get(name).copied(), *new))
        .collect();
    let pruned = pruned_names(before, after);
    if changed.is_empty() && pruned.is_empty() {
        return;
    }
    changed.sort_by(|a, b| a.0.cmp(b.0));
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "From {endpoint}");
    for name in pruned {
        let _ = writeln!(stderr, " - [deleted]         (none) -> {remote}/{name}");
    }
    for (name, old, new) in changed {
        // Tracking-ref updates are rendered as fast-forwards; detecting a
        // forced (`+ old...new`) tracking update would need per-ref
        // ancestry checks against the store — deferred (cosmetic only).
        let dst = format!("{remote}/{name}");
        let _ = writeln!(
            stderr,
            "{}",
            format::ref_update_line(old.as_ref(), &new, name, &dst, false)
        );
    }
}

/// The tracking refs that the fetch deleted: only a prune removes one.
fn pruned_names<'a>(
    before: &'a HashMap<String, Hash>,
    after: &HashMap<String, Hash>,
) -> Vec<&'a String> {
    let mut names: Vec<&String> = before.keys().filter(|n| !after.contains_key(*n)).collect();
    names.sort();
    names
}

use super::error as emit_err;

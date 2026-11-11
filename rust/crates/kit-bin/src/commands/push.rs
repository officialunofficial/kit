//! `kit push` — push refs/packs to a remote with CAS safety.
//!
//! Default (no `--all`): push the current branch to its upstream only,
//! with non-fast-forward rejection via CAS (the remote-tracking ref is
//! the lease). `--all` mirrors every `refs/heads/*` (now CAS-safe).
//! `--force` / `--force-with-lease` control the CAS policy; `--dry-run`
//! resolves the plan without contacting the remote.
//!
//! Every endpoint flows through `remote_dispatch::open_trusted`, so the
//! per-endpoint credential gate applies to named remotes too —
//! trust is keyed on the resolved ENDPOINT, never the remote name.

use std::io::Write;

use clap::{Parser, ValueEnum};
use kit_core::layout::RepoLayout;
use kit_core::protocol::UploadLimits;
use libkit::push::{self, PushLease};

use crate::clap_args;
use crate::config;
use crate::exit;
use crate::exit_map;
use crate::format::JsonObject;
use crate::remote_dispatch;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum PushFormat {
    Default,
    Json,
}

#[derive(Debug, Parser)]
#[command(
    name = "kit push",
    about = "Push the current branch to its upstream (or --all branches)."
)]
#[allow(clippy::struct_excessive_bools)]
struct PushOpts {
    /// Remote name to push to (defaults to the branch's upstream remote,
    /// else the configured default remote).
    remote: Option<String>,
    /// Push the local branch `<src>` to the remote branch `<dst>` as
    /// `<src>:<dst>`. Each side is a branch name or a `refs/heads/` ref.
    /// Wildcards, a leading `+`, an empty `<src>` (a delete) and refs outside
    /// `refs/heads/` are errors. Needs a `<remote>`.
    #[arg(requires = "remote", conflicts_with = "all")]
    refspec: Option<String>,
    /// Mirror every local branch instead of just the current one.
    #[arg(long)]
    all: bool,
    /// Overwrite the remote branch unconditionally (skip CAS).
    #[arg(short = 'f', long)]
    force: bool,
    /// Record the pushed remote as this branch's upstream, even if one is
    /// already set (`git push -u` / `--set-upstream`).
    #[arg(short = 'u', long = "set-upstream")]
    set_upstream: bool,
    /// Overwrite only if the remote hasn't moved past our last-seen tip.
    #[arg(long)]
    force_with_lease: bool,
    /// Print what would be pushed without contacting the remote.
    #[arg(long)]
    dry_run: bool,
    /// Emit a machine-readable JSON result object to stdout:
    /// `{"ok":true,"remote":"...","endpoint":"...","branch":"...",
    /// "remote_branch":"...","old":"<hex>|null","new":"<hex>",
    /// "forced":<bool>,"up_to_date":<bool>,"steps":<n>}` on success, or
    /// `{"ok":false,"error":"...","rejected":<bool>,...}` on a
    /// non-fast-forward (CAS) rejection.
    #[arg(long, value_enum, default_value = "default")]
    format: PushFormat,
    /// Suppress transfer progress output on stderr.
    #[arg(short = 'q', long)]
    quiet: bool,
}

fn interrupted_hint(endpoint: &str, limits: UploadLimits) -> &'static str {
    let connect = endpoint.starts_with("kit+https://") || endpoint.starts_with("kit+http://");
    if connect
        && limits.tickets_per_advance.is_some()
        && limits.ticket_threshold_bytes != Some(u64::MAX)
    {
        "push: interrupted; if BeginUpload issued a ticket, re-run push to resume the upload"
    } else {
        "push: interrupted; re-run push to retry"
    }
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_args::parse::<PushOpts>("kit push", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let json = matches!(opts.format, PushFormat::Json);
    let lease = match push::lease(opts.force, opts.force_with_lease) {
        Ok(lease) => lease,
        Err(e) => return plan_failure(e, false),
    };
    let refspec = match opts.refspec.as_deref().map(push::parse_refspec) {
        Some(Ok(spec)) => Some(spec),
        Some(Err(e)) => return plan_failure(e, json),
        None => None,
    };
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
        Err(e) => return emit_err(&format!("config: {e}"), exit::CONFIG_ERROR),
    };

    if opts.all {
        push_all(&layout, &cfg, &opts)
    } else {
        push_current(&layout, &cfg, &opts, lease, refspec.as_ref())
    }
}

/// Default push: current branch → its upstream, CAS-protected.
#[allow(clippy::too_many_lines)] // linear flow: resolve + no-op + push + report
fn push_current(
    layout: &RepoLayout,
    cfg: &config::LayeredConfig,
    opts: &PushOpts,
    lease: PushLease,
    refspec: Option<&push::Refspec>,
) -> u8 {
    let json = matches!(opts.format, PushFormat::Json);
    // An explicit `kit push <remote>` overrides the configured upstream.
    let planned = match (refspec, opts.remote.as_deref()) {
        (Some(spec), Some(remote)) => push::plan_refspec(layout, cfg, remote, spec),
        (_, remote) => push::plan(layout, cfg, remote),
    };
    let plan = match planned {
        Ok(plan) => plan,
        Err(e) => return plan_failure(e, json),
    };
    let up_to_date = plan.is_up_to_date(opts.force);
    let push::Plan {
        branch,
        remote: resolved,
        remote_branch,
        tracked: old_tracked,
        ..
    } = plan;
    // Nothing to do when the remote-tracking ref already matches the local
    // tip (and we're not forcing). Matches git's `Everything up-to-date`.
    if up_to_date {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "Everything up-to-date");
        if json {
            let mut obj = JsonObject::new();
            obj.field_bool("ok", true)
                .field_str("remote", &resolved.name)
                .field_str("endpoint", &resolved.endpoint)
                .field_str("branch", &branch)
                .field_str("remote_branch", &remote_branch)
                .field_opt_hash("old", old_tracked.as_ref())
                .field_opt_hash("new", old_tracked.as_ref())
                .field_bool("forced", false)
                .field_bool("up_to_date", true)
                .field_u64("steps", 0);
            emit_json_stdout(obj);
        }
        return exit::OK;
    }

    if opts.dry_run {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "(dry-run) would push {branch} -> {}:{remote_branch} ({})",
            resolved.name, resolved.endpoint
        );
        if json {
            let mut obj = JsonObject::new();
            obj.field_bool("ok", true)
                .field_bool("dry_run", true)
                .field_str("remote", &resolved.name)
                .field_str("endpoint", &resolved.endpoint)
                .field_str("branch", &branch)
                .field_str("remote_branch", &remote_branch);
            emit_json_stdout(obj);
        }
        return exit::OK;
    }

    let progress = crate::progress::start(
        "Writing objects",
        None,
        crate::progress::should_report(opts.quiet),
        opts.quiet,
    );
    let remote = match remote_dispatch::open_trusted_for_push(
        &resolved.endpoint,
        &resolved.name,
        resolved.repo_chosen,
        cfg,
        layout,
        progress.terminal(),
    ) {
        Ok(remote) => remote,
        Err(libkit::transfer::Error::UntrustedRemote(msg)) => {
            return emit_err_json(&msg, exit::CONFIG_ERROR, json);
        }
        Err(e) => return emit_err_json(&format!("open remote: {e}"), exit::PROTOCOL_ERROR, json),
    };
    let tx = remote.tx;

    let push_outcome = {
        let outcome = tx
            .with_source(|source| {
                remote_dispatch::push_branch_tracked_source(
                    layout.worktree_root(),
                    source,
                    &resolved.name,
                    &branch,
                    &remote_branch,
                    lease,
                    remote.authority.as_deref(),
                    progress.terminal(),
                )
            })
            .and_then(|result| result);
        // The progress guard's final `, done.` line lands before the
        // git-shaped `To <url>` / ref-update summary printed below, not
        // after it.
        drop(progress);
        outcome
    };
    match push_outcome.map_err(libkit::transfer::Error::into_published_prefix) {
        Ok((new_tip, steps)) => {
            // Remember the upstream so a bare `kit push` works next
            // time (Git-like first-push convenience). Only persisted
            // when not already set, and never for a detached/forced
            // overwrite of an unrelated branch.
            // Best-effort: the push has succeeded, so a failure to write the
            // upstream does not fail the command.
            // A refspec push records one only for `-u`.
            if refspec.is_none() || opts.set_upstream {
                let _ = config::record_upstream(
                    layout,
                    cfg,
                    &branch,
                    libkit::config::Upstream {
                        remote: resolved.name.clone(),
                        branch: remote_branch.clone(),
                    },
                    opts.set_upstream,
                );
            }
            // git-style ref-update summary block: `To <url>` then one
            // `<old>..<new>` / `* [new branch]` / `+ …(forced)` line.
            // On a store error during the ancestry check, assume a
            // fast-forward (don't mislabel an ordinary push as forced).
            let forced = !push::is_fast_forward(layout, old_tracked, new_tip).unwrap_or(true);
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(stderr, "To {}", resolved.endpoint);
            let _ = writeln!(
                stderr,
                "{}",
                crate::format::ref_update_line(
                    old_tracked.as_ref(),
                    &new_tip,
                    &branch,
                    &remote_branch,
                    forced,
                )
            );
            if json {
                let mut obj = JsonObject::new();
                obj.field_bool("ok", true)
                    .field_str("remote", &resolved.name)
                    .field_str("endpoint", &resolved.endpoint)
                    .field_str("branch", &branch)
                    .field_str("remote_branch", &remote_branch)
                    .field_opt_hash("old", old_tracked.as_ref())
                    .field_hash("new", &new_tip)
                    .field_bool("forced", forced)
                    .field_bool("up_to_date", false)
                    .field_u64("steps", steps as u64);
                emit_json_stdout(obj);
            }
            exit::OK
        }
        Err((libkit::transfer::Error::NonFastForwardPush { branch: rejected }, prefix)) => {
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(stderr, "To {}", resolved.endpoint);
            let _ = writeln!(
                stderr,
                "{}",
                crate::format::ref_rejected_line(&rejected, &rejected)
            );
            drop(stderr);
            let msg = with_prefix(
                format!(
                    "updates were rejected for '{rejected}' (non-fast-forward); \
                     `kit fetch` and merge/rebase first, or re-run with --force-with-lease / --force"
                ),
                prefix.as_ref(),
            );
            if json {
                let mut obj = JsonObject::new();
                obj.field_bool("ok", false)
                    .field_bool("rejected", true)
                    .field_str("remote", &resolved.name)
                    .field_str("endpoint", &resolved.endpoint)
                    .field_str("branch", &rejected)
                    .field_str("remote_branch", &remote_branch)
                    .field_str("error", &msg);
                emit_json_stdout(obj);
            }
            emit_err(&msg, exit::GENERAL_ERROR)
        }
        Err((libkit::transfer::Error::UploadInterrupted(message), prefix)) => emit_err_json(
            &with_prefix(format!("push: {message}"), prefix.as_ref()),
            exit::TEMPFAIL,
            json,
        ),
        Err((libkit::transfer::Error::Interrupted, prefix)) => emit_err_json(
            &with_prefix(
                interrupted_hint(&resolved.endpoint, tx.upload_limits()).to_owned(),
                prefix.as_ref(),
            ),
            exit::TEMPFAIL,
            json,
        ),
        Err((e, prefix)) => emit_push_error(e, prefix.as_ref(), json),
    }
}

/// `--all`: mirror every local branch to the remote (CAS-safe).
#[allow(clippy::too_many_lines)] // Linear branch loop keeps each push result and hint together.
fn push_all(layout: &RepoLayout, cfg: &config::LayeredConfig, opts: &PushOpts) -> u8 {
    let json = matches!(opts.format, PushFormat::Json);
    let resolved = match push::plan_all(cfg, opts.remote.as_deref()) {
        Ok(resolved) => resolved,
        Err(e) => return plan_failure(e, json),
    };
    if opts.dry_run {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "(dry-run) would mirror all branches to {} ({})",
            resolved.name, resolved.endpoint
        );
        if json {
            let mut obj = JsonObject::new();
            obj.field_bool("ok", true)
                .field_bool("dry_run", true)
                .field_str("remote", &resolved.name)
                .field_str("endpoint", &resolved.endpoint);
            emit_json_stdout(obj);
        }
        return exit::OK;
    }
    let progress = crate::progress::start(
        "Writing objects",
        None,
        crate::progress::should_report(opts.quiet),
        opts.quiet,
    );
    let remote = match remote_dispatch::open_trusted_for_push(
        &resolved.endpoint,
        &resolved.name,
        resolved.repo_chosen,
        cfg,
        layout,
        progress.terminal(),
    ) {
        Ok(remote) => remote,
        Err(libkit::transfer::Error::UntrustedRemote(msg)) => {
            return emit_err_json(&msg, exit::CONFIG_ERROR, json);
        }
        Err(e) => return emit_err_json(&format!("open remote: {e}"), exit::PROTOCOL_ERROR, json),
    };
    let tx = remote.tx;
    let push_outcome = {
        let outcome = tx
            .with_source(|source| {
                remote_dispatch::push_all_with_source(
                    layout.worktree_root(),
                    source,
                    Some(&resolved.name),
                    opts.force,
                    remote.authority.as_deref(),
                    progress.terminal(),
                )
            })
            .and_then(|result| result);
        drop(progress);
        outcome
    };
    match push_outcome.map_err(libkit::transfer::Error::into_published_prefix) {
        Ok(pushed) => {
            let n = pushed.refs;
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(
                stderr,
                "pushed {n} ref(s) to {} ({})",
                resolved.name, resolved.endpoint
            );
            if json {
                let mut obj = JsonObject::new();
                obj.field_bool("ok", true)
                    .field_str("remote", &resolved.name)
                    .field_str("endpoint", &resolved.endpoint)
                    .field_u64("ref_count", n as u64)
                    .field_u64("steps", pushed.steps as u64);
                emit_json_stdout(obj);
            }
            exit::OK
        }
        Err((libkit::transfer::Error::NonFastForwardPush { branch }, prefix)) => {
            let msg = with_prefix(
                format!(
                    "updates were rejected for '{branch}' (non-fast-forward); \
                     `kit fetch` first, or re-run with --force"
                ),
                prefix.as_ref(),
            );
            if json {
                let mut obj = JsonObject::new();
                obj.field_bool("ok", false)
                    .field_bool("rejected", true)
                    .field_str("remote", &resolved.name)
                    .field_str("endpoint", &resolved.endpoint)
                    .field_str("branch", &branch)
                    .field_str("error", &msg);
                emit_json_stdout(obj);
            }
            emit_err(&msg, exit::GENERAL_ERROR)
        }
        Err((libkit::transfer::Error::UploadInterrupted(message), prefix)) => emit_err_json(
            &with_prefix(format!("push: {message}"), prefix.as_ref()),
            exit::TEMPFAIL,
            json,
        ),
        Err((libkit::transfer::Error::Interrupted, prefix)) => emit_err_json(
            &with_prefix(
                interrupted_hint(&resolved.endpoint, tx.upload_limits()).to_owned(),
                prefix.as_ref(),
            ),
            exit::TEMPFAIL,
            json,
        ),
        Err((e, prefix)) => emit_push_error(e, prefix.as_ref(), json),
    }
}

/// Consume a [`JsonObject`] and print it as one line to stdout.
fn emit_json_stdout(obj: JsonObject) {
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "{}", obj.finish());
}

/// `error(msg, code)` plus, when `json` is set, a `{"ok":false,...}`
/// line on stdout — so every exit path (not just the documented
/// CAS-rejection shape) leaves `--format=json` callers with a
/// self-contained stdout payload.
fn emit_err_json(msg: &str, code: u8, json: bool) -> u8 {
    if json {
        let mut obj = JsonObject::new();
        obj.field_bool("ok", false).field_str("error", msg);
        if code == exit::NOPERM {
            obj.field_bool("admission_required", true);
        }
        emit_json_stdout(obj);
    }
    emit_err(msg, code)
}

/// `msg`, followed by the published prefix a split push left behind, if any.
fn with_prefix(msg: String, prefix: Option<&libkit::transfer::PublishedPrefix>) -> String {
    match prefix {
        Some(prefix) => format!("{msg}; {}", prefix.note()),
        None => msg,
    }
}

fn emit_push_error(
    error: libkit::transfer::Error,
    prefix: Option<&libkit::transfer::PublishedPrefix>,
    json: bool,
) -> u8 {
    match error {
        libkit::transfer::Error::Transport(
            kit_core::protocol::TransportError::AdmissionRequired(required),
        ) => {
            // The hint helps only when no helper ran; after a helper ran, the
            // reason (a second challenge or the run limit) says why it stopped.
            let hint = if required.reason.is_none() {
                "\nhint: configure admission_helper and trust this remote with kit config trusted_remote_endpoint"
            } else {
                ""
            };
            emit_err_json(&format!("push: {required}{hint}"), exit::NOPERM, json)
        }
        libkit::transfer::Error::Transport(
            kit_core::protocol::TransportError::AdmissionConfiguration(message),
        ) => emit_err_json(
            &format!("push: admission configuration: {message}"),
            exit::CONFIG_ERROR,
            json,
        ),
        other => emit_err_json(
            &with_prefix(format!("push: {other}"), prefix),
            exit::GENERAL_ERROR,
            json,
        ),
    }
}

/// Print a planning failure and give its exit code.
fn plan_failure(error: push::Error, json: bool) -> u8 {
    let error = libkit::Error::from(error);
    emit_err_json(
        &exit_map::message(&error),
        exit_map::exit_code(&error),
        json,
    )
}

use super::error as emit_err;

#[cfg(test)]
mod interrupted_hint_tests {
    use super::*;

    #[test]
    fn begin_upload_hint_only_for_ticketing_connect_remote() {
        let ticketing = UploadLimits {
            tickets_per_advance: Some(7),
            ticket_threshold_bytes: Some(0),
            ..UploadLimits::default()
        };
        assert!(
            interrupted_hint("kit+https://example.test/repo", ticketing).contains("BeginUpload")
        );
        assert!(!interrupted_hint("file:///repo", ticketing).contains("BeginUpload"));
        assert!(
            !interrupted_hint("kit+https://example.test/repo", UploadLimits::default())
                .contains("BeginUpload")
        );
    }
}

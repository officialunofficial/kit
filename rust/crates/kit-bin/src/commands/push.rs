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

use std::cell::RefCell;
use std::io::Write;

use clap::{Parser, ValueEnum};
use kit_core::layout::RepoLayout;
use kit_core::protocol::UploadLimits;
use kit_sync::push::{DeleteTarget, TagPushOutcome, TagSelection};
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
    /// `<src>:<dst>`, or a branch as `<branch>` for `<branch>:<branch>`.
    /// The branch need not be the current one. Each side is a branch name or
    /// a `refs/heads/` ref.
    /// A local tag, as `<tag>` or `refs/tags/<tag>`, pushes that tag under
    /// its own name; a name that is both a branch and a tag needs its full ref.
    /// Wildcards, a leading `+`, an empty `<src>` (use --delete) and other
    /// refs are errors. Needs a `<remote>`.
    #[arg(requires = "remote", conflicts_with = "all")]
    refspec: Option<String>,
    /// Delete the remote branch or tag `<refspec>` with its chain ref. A
    /// branch is deleted only while it holds its tracking ref's value, and
    /// the tracking ref goes too; a tag only while it holds the value just
    /// read. A short name the remote holds as both a branch and a tag needs
    /// its full ref. An s3 remote refuses every delete.
    #[arg(
        long,
        requires = "refspec",
        conflicts_with_all = ["all", "tags", "force", "force_with_lease", "set_upstream"]
    )]
    delete: bool,
    /// Mirror every local branch instead of just the current one.
    #[arg(long)]
    all: bool,
    /// Push every local tag, and no branch. A remote tag that holds another
    /// value is refused unless --force.
    #[arg(long, conflicts_with_all = ["all", "refspec", "set_upstream"])]
    tags: bool,
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
    /// Publish locally authored attestations permanently.
    #[arg(long)]
    attestations: bool,
    /// Suppress transfer progress output on stderr.
    #[arg(short = 'q', long)]
    quiet: bool,
}

fn interrupted_hint(endpoint: &str, limits: UploadLimits) -> &'static str {
    let connect = endpoint.starts_with("kit+https://") || endpoint.starts_with("kit+http://");
    if connect
        && limits.data_packs_per_advance.is_some()
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
        return push_all(&layout, &cfg, &opts);
    }
    if opts.tags {
        return push_tags(&layout, &cfg, &opts, TagSelection::All);
    }
    if opts.delete {
        return push_delete(&layout, &cfg, &opts);
    }
    match opts
        .refspec
        .as_deref()
        .map(|spec| push::resolve_push_name(&layout, spec))
    {
        Some(Ok(push::PushName::Tag(tag))) if opts.set_upstream => emit_err_json(
            &format!("-u records a branch's upstream; '{tag}' is a tag"),
            exit::USAGE,
            json,
        ),
        Some(Ok(push::PushName::Tag(tag))) => {
            push_tags(&layout, &cfg, &opts, TagSelection::Named(vec![tag]))
        }
        Some(Ok(push::PushName::Branch(spec))) => {
            push_current(&layout, &cfg, &opts, lease, Some(&spec))
        }
        Some(Err(e)) => plan_failure(e, json),
        None => push_current(&layout, &cfg, &opts, lease, None),
    }
}

/// `--tags`, or a tag by name: push tags to the named or default remote. Each
/// tag gets its own line, and a refused tag exits 1 after the others go.
#[allow(clippy::too_many_lines)] // linear flow: resolve + push + one line per tag
fn push_tags(
    layout: &RepoLayout,
    cfg: &config::LayeredConfig,
    opts: &PushOpts,
    selection: TagSelection,
) -> u8 {
    let json = matches!(opts.format, PushFormat::Json);
    let resolved = match push::plan_all(cfg, opts.remote.as_deref()) {
        Ok(resolved) => resolved,
        Err(e) => return plan_failure(e, json),
    };
    if opts.dry_run {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "(dry-run) would push tags to {} ({})",
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
    let published = RefCell::new(Vec::new());
    let outcome = {
        let outcome = tx
            .with_source(|source| {
                remote_dispatch::push_tags_with_source(
                    layout.worktree_root(),
                    source,
                    &resolved.name,
                    selection,
                    opts.force || opts.force_with_lease,
                    remote.authority.as_deref(),
                    (
                        opts.attestations || cfg.merged.push_attestations == "true",
                        &resolved.endpoint,
                    ),
                    progress.terminal(),
                    &published,
                )
            })
            .and_then(|result| result);
        drop(progress);
        outcome
    };
    let (results, failure) = match outcome {
        Ok(results) => (results, None),
        Err(error) => {
            let (message, code) = match error {
                libkit::transfer::Error::Interrupted => (
                    interrupted_hint(&resolved.endpoint, tx.upload_limits()).to_owned(),
                    exit::TEMPFAIL,
                ),
                other => push_error_details(other, None),
            };
            let mut published = published.into_inner();
            if published.is_empty() {
                return emit_err_json(&message, code, json);
            }
            published.sort_unstable_by(|a, b| a.name.cmp(&b.name));
            (published, Some((message, code)))
        }
    };
    let mut stderr = std::io::stderr().lock();
    let (mut pushed, mut rejected) = (0u64, 0u64);
    if results
        .iter()
        .all(|r| matches!(r.outcome, TagPushOutcome::UpToDate { .. }))
    {
        let _ = writeln!(stderr, "Everything up-to-date");
    } else {
        let _ = writeln!(stderr, "To {}", resolved.endpoint);
    }
    for result in &results {
        let t = &result.name;
        let line = match &result.outcome {
            TagPushOutcome::Created { .. } => format!(" * [new tag]         {t} -> {t}"),
            TagPushOutcome::Repaired { .. } => format!(" * [tag map]         {t} -> {t}"),
            TagPushOutcome::Forced { old, value } => format!(
                " + {}...{} {t} -> {t} (forced update)",
                crate::format::short_hash(old, crate::format::SUMMARY_ABBREV),
                crate::format::short_hash(value, crate::format::SUMMARY_ABBREV),
            ),
            TagPushOutcome::Rejected(reason) => {
                rejected += 1;
                let _ = writeln!(stderr, " ! [rejected]        {t} -> {t} ({reason})");
                continue;
            }
            _ => continue,
        };
        pushed += 1;
        let _ = writeln!(stderr, "{line}");
    }
    drop(stderr);
    if json {
        let mut obj = JsonObject::new();
        obj.field_bool("ok", failure.is_none() && rejected == 0)
            .field_str("remote", &resolved.name)
            .field_str("endpoint", &resolved.endpoint)
            .field_u64("tags_pushed", pushed);
        if let Some((message, code)) = &failure {
            set_json_error(&mut obj, message, *code);
        } else {
            obj.field_u64("tags_rejected", rejected);
        }
        emit_json_stdout(obj);
    }
    if let Some((message, code)) = failure {
        return emit_err(&message, code);
    }
    if rejected > 0 {
        return exit::GENERAL_ERROR;
    }
    exit::OK
}

/// The ref `--delete` names: a full `refs/heads/` or `refs/tags/` name, or a
/// short name that the remote resolves. A short name too long for a branch
/// can name only a tag.
fn delete_target(spec: &str) -> DeleteTarget {
    if let Some(branch) = spec.strip_prefix("refs/heads/") {
        DeleteTarget::Branch(branch.to_owned())
    } else if let Some(tag) = spec.strip_prefix("refs/tags/") {
        DeleteTarget::Tag(tag.to_owned())
    } else if !kit_core::refs::validate_ref_name(&format!("refs/heads/{spec}"))
        && kit_core::refs::validate_ref_name(&format!("refs/tags/{spec}"))
    {
        DeleteTarget::Tag(spec.to_owned())
    } else {
        DeleteTarget::Name(spec.to_owned())
    }
}

/// `--delete <remote> <name>`: delete one remote branch or tag.
fn push_delete(layout: &RepoLayout, cfg: &config::LayeredConfig, opts: &PushOpts) -> u8 {
    let json = matches!(opts.format, PushFormat::Json);
    let spec = opts.refspec.as_deref().unwrap_or_default();
    let resolved = match push::plan_all(cfg, opts.remote.as_deref()) {
        Ok(resolved) => resolved,
        Err(e) => return plan_failure(e, json),
    };
    if opts.dry_run {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "(dry-run) would delete {spec} on {} ({})",
            resolved.name, resolved.endpoint
        );
        if json {
            let mut obj = JsonObject::new();
            obj.field_bool("ok", true)
                .field_bool("dry_run", true)
                .field_str("remote", &resolved.name)
                .field_str("endpoint", &resolved.endpoint)
                .field_str("delete", spec);
            emit_json_stdout(obj);
        }
        return exit::OK;
    }
    let progress = crate::progress::start(
        "Deleting",
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
    let outcome = {
        let outcome = remote
            .tx
            .with_source(|source| {
                remote_dispatch::push_delete_with_source(
                    layout.worktree_root(),
                    source,
                    &resolved.name,
                    delete_target(spec),
                    progress.terminal(),
                )
            })
            .and_then(|result| result);
        drop(progress);
        outcome
    };
    let deleted = match outcome {
        Ok(deleted) => deleted,
        Err(libkit::transfer::Error::Interrupted) => {
            return emit_err_json("push: interrupted; re-run to retry", exit::TEMPFAIL, json);
        }
        Err(e) => return emit_push_error(e, None, json),
    };
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "To {}", resolved.endpoint);
    let _ = writeln!(stderr, " - [deleted]         {}", deleted.name);
    drop(stderr);
    if json {
        let mut obj = JsonObject::new();
        obj.field_bool("ok", true)
            .field_str("remote", &resolved.name)
            .field_str("endpoint", &resolved.endpoint)
            .field_str("deleted", &deleted.name)
            .field_opt_hash("old", deleted.value.as_ref());
        emit_json_stdout(obj);
    }
    exit::OK
}

/// Say that the remote holds the branch's tip already.
fn report_up_to_date(
    json: bool,
    resolved: &libkit::config::ResolvedRemote,
    branch: &str,
    remote_branch: &str,
    old: Option<kit_core::hash::Hash>,
    new: Option<kit_core::hash::Hash>,
    attestations: usize,
) {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "Everything up-to-date");
    if json {
        let mut obj = JsonObject::new();
        obj.field_bool("ok", true)
            .field_str("remote", &resolved.name)
            .field_str("endpoint", &resolved.endpoint)
            .field_str("branch", branch)
            .field_str("remote_branch", remote_branch)
            .field_opt_hash("old", old.as_ref())
            .field_opt_hash("new", new.as_ref())
            .field_bool("forced", false)
            .field_u64("attestations_pushed", attestations as u64)
            .field_bool("up_to_date", true)
            .field_u64("steps", 0);
        emit_json_stdout(obj);
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
    // A dry run does not contact the remote, so it goes by the tracking ref.
    // A real push asks the remote: it may have lost the branch since.
    if opts.dry_run && up_to_date {
        report_up_to_date(
            json,
            &resolved,
            &branch,
            &remote_branch,
            old_tracked,
            old_tracked,
            0,
        );
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
                // What the remote holds before the push, for the summary.
                // The tracking ref is only what it held when last seen.
                let old = source.read_ref(&format!("refs/heads/{remote_branch}"))?;
                remote_dispatch::push_branch_tracked_source(
                    layout.worktree_root(),
                    source,
                    &resolved.name,
                    &branch,
                    &remote_branch,
                    lease,
                    remote.authority.as_deref(),
                    (
                        opts.attestations || cfg.merged.push_attestations == "true",
                        &resolved.endpoint,
                    ),
                    progress.terminal(),
                )
                .map(|(tip, steps, attestations)| (old, tip, steps, attestations))
            })
            .and_then(|result| result);
        // The progress guard's final `, done.` line lands before the
        // git-shaped `To <url>` / ref-update summary printed below, not
        // after it.
        drop(progress);
        outcome
    };
    match push_outcome.map_err(libkit::transfer::Error::into_published_prefix) {
        Ok((old, new_tip, steps, attestations)) => {
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
            // The remote held the tip already. Matches git's
            // `Everything up-to-date`.
            if steps == 0 {
                report_up_to_date(
                    json,
                    &resolved,
                    &branch,
                    &remote_branch,
                    old,
                    Some(new_tip),
                    attestations,
                );
                return exit::OK;
            }
            // git-style ref-update summary block: `To <url>` then one
            // `<old>..<new>` / `* [new branch]` / `+ …(forced)` line.
            // On a store error during the ancestry check, assume a
            // fast-forward (don't mislabel an ordinary push as forced).
            let forced = !push::is_fast_forward(layout, old, new_tip).unwrap_or(true);
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(stderr, "To {}", resolved.endpoint);
            let _ = writeln!(
                stderr,
                "{}",
                crate::format::ref_update_line(
                    old.as_ref(),
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
                    .field_opt_hash("old", old.as_ref())
                    .field_hash("new", &new_tip)
                    .field_bool("forced", forced)
                    .field_u64("attestations_pushed", attestations as u64)
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
                    (
                        opts.attestations || cfg.merged.push_attestations == "true",
                        &resolved.endpoint,
                    ),
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
                    .field_u64("attestations_pushed", pushed.attestations_pushed as u64)
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
        obj.field_bool("ok", false);
        set_json_error(&mut obj, msg, code);
        emit_json_stdout(obj);
    }
    emit_err(msg, code)
}

fn set_json_error(obj: &mut JsonObject, msg: &str, code: u8) {
    obj.field_str("error", msg);
    if code == exit::NOPERM {
        obj.field_bool("admission_required", true);
    }
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
    let (message, code) = push_error_details(error, prefix);
    emit_err_json(&message, code, json)
}

fn push_error_details(
    error: libkit::transfer::Error,
    prefix: Option<&libkit::transfer::PublishedPrefix>,
) -> (String, u8) {
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
            (format!("push: {required}{hint}"), exit::NOPERM)
        }
        libkit::transfer::Error::Transport(
            kit_core::protocol::TransportError::AdmissionConfiguration(message),
        ) => (
            format!("push: admission configuration: {message}"),
            exit::CONFIG_ERROR,
        ),
        other => (
            with_prefix(format!("push: {other}"), prefix),
            exit::GENERAL_ERROR,
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
            data_packs_per_advance: Some(6),
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

#[cfg(test)]
mod delete_target_tests {
    use super::*;

    #[test]
    fn a_short_name_too_long_for_a_branch_names_the_tag() {
        let longest_tag = "t".repeat(kit_core::refs::MAX_REF_NAME_BYTES - "refs/tags/".len());
        assert_eq!(
            delete_target(&longest_tag),
            DeleteTarget::Tag(longest_tag.clone())
        );
        assert_eq!(delete_target("v1"), DeleteTarget::Name("v1".to_owned()));
        let too_long = format!("{longest_tag}t");
        assert_eq!(
            delete_target(&too_long),
            DeleteTarget::Name(too_long.clone())
        );
    }
}

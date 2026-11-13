//! `kit git verify` / `status` / `format-patch` (feature `git-bridge`):
//! bridge-state inspection and audit.
//!
//! The logic is in [`libkit::git::verify`], [`libkit::git::state`] and
//! [`libkit::git::patch`]. This module parses the arguments and prints the
//! results.

use std::io::Write;
use std::path::PathBuf;

use clap::Parser;
use libkit::git::patch;
use libkit::git::state;
use libkit::git::verify::{self, Request};
use libkit::git_bridge::gitobj::sha1_hex;

use super::git::failure;
use crate::exit;

type CmdResult<T> = Result<T, (String, u8)>;

#[derive(Debug, Parser)]
pub(super) struct VerifyArgs {
    /// Bridge state name under `.kit/git/`. Optional when exactly
    /// one state dir exists.
    #[arg(long = "remote-name", value_name = "NAME")]
    pub remote_name: Option<String>,
    /// Full fork audit (SPEC-GIT-BRIDGE §14.3): additionally
    /// re-derive every tree/blob referenced by bridge commits from
    /// its kit twin and require the exact sha1.
    #[arg(long = "fork-audit")]
    pub fork_audit: bool,
    /// Verify only these refs (full names). Default: every ref
    /// recorded in the state dir.
    #[arg(long = "ref", value_name = "REF")]
    pub refs: Vec<String>,
}

#[derive(Debug, Parser)]
pub(super) struct StatusArgs {}

#[derive(Debug, Parser)]
pub(super) struct FormatPatchArgs {
    /// Commit range `A..B` (or a single rev, meaning `<rev>..HEAD`).
    pub range: String,
    /// Write patch files into this directory (default: current dir).
    #[arg(short = 'o', long = "output-directory", value_name = "DIR")]
    pub output: Option<PathBuf>,
    /// Print all patches to stdout instead of writing files.
    #[arg(long)]
    pub stdout: bool,
}

fn current_dir() -> CmdResult<PathBuf> {
    std::env::current_dir().map_err(|e| (format!("cwd: {e}"), exit::NOINPUT))
}

// ─── kit git verify ────────────────────────────────────────────────

pub(super) fn verify(args: &VerifyArgs) -> CmdResult<()> {
    let cwd = current_dir()?;
    let report = verify::verify(
        &cwd,
        &Request {
            remote_name: args.remote_name.as_deref(),
            fork_audit: args.fork_audit,
            refs: &args.refs,
        },
    )
    .map_err(failure)?;

    let mut stderr = std::io::stderr().lock();
    for v in &report.verified {
        let _ = writeln!(
            stderr,
            "verified {} ({}, {})",
            v.ref_name,
            v.origin,
            sha1_hex(&v.tip)
        );
    }
    let summary = report.summary();
    if report.failures.is_empty() && report.unsigned > 0 {
        // §10: an all-zero kit-signature FAILS both verification
        // modes — reported as unsigned (never "tampered"), but never
        // as success either.
        return Err((
            format!("{} unsigned object(s) ({summary})", report.unsigned),
            exit::DATAERR,
        ));
    }
    if report.failures.is_empty() {
        let _ = writeln!(stderr, "ok: {summary}");
        Ok(())
    } else {
        for f in &report.failures {
            let _ = writeln!(stderr, "FAIL {f}");
        }
        Err((
            format!(
                "{} object(s) failed verification ({summary})",
                report.failures.len()
            ),
            exit::DATAERR,
        ))
    }
}

// ─── kit git status ────────────────────────────────────────────────

pub(super) fn status(_args: &StatusArgs) -> CmdResult<()> {
    let cwd = current_dir()?;
    let states = state::status(&cwd).map_err(failure)?;
    let mut out = std::io::stdout().lock();
    if states.is_empty() {
        let _ = writeln!(
            out,
            "no git bridge state (run `kit git import` or `kit git export` first)"
        );
        return Ok(());
    }
    for s in &states {
        let _ = writeln!(out, "{}  direction={}", s.name, s.direction);
        if let Some(source) = &s.source {
            let _ = writeln!(out, "  source: {source}");
        }
        if let Some(dest) = &s.dest {
            let _ = writeln!(out, "  dest: {dest}");
        }
        if let Some(key) = &s.importer_key {
            let _ = writeln!(out, "  importer key: {key}… (pinned)");
        }
        for (ref_name, id) in &s.tracking {
            let _ = writeln!(out, "  tracking {ref_name} @ {id} (import)");
        }
        for (ref_name, id) in &s.exported {
            let _ = writeln!(out, "  exported {ref_name} @ {id} (lease)");
        }
        let staging = if s.staging_present { "ok" } else { "missing" };
        let _ = writeln!(out, "  staging: {staging}");
    }
    Ok(())
}

// ─── kit git format-patch ──────────────────────────────────────────

pub(super) fn format_patch(args: &FormatPatchArgs) -> CmdResult<()> {
    let cwd = current_dir()?;
    let series = patch::series(&cwd, &args.range).map_err(failure)?;
    if series.skipped_merges() > 0 {
        eprintln!(
            "warning: {} merge commit(s) skipped (patches are linear)",
            series.skipped_merges()
        );
    }
    if series.is_empty() {
        eprintln!("no commits in range {}..{}", series.start(), series.end());
        return Ok(());
    }

    let outdir = args.output.clone().unwrap_or_else(|| cwd.clone());
    if !args.stdout {
        std::fs::create_dir_all(&outdir)
            .map_err(|e| (format!("create {}: {e}", outdir.display()), exit::CANTCREAT))?;
    }
    let mut stdout = std::io::stdout().lock();
    for item in series.patches() {
        let mut patch = item.map_err(failure)?;
        let text = render_patch(&mut patch)?;
        if args.stdout {
            stdout
                .write_all(text.as_bytes())
                .map_err(|e| (format!("write: {e}"), exit::GENERAL_ERROR))?;
        } else {
            let name = patch.file_name();
            let target = outdir.join(&name);
            std::fs::write(&target, &text)
                .map_err(|e| (format!("write {}: {e}", target.display()), exit::CANTCREAT))?;
            let _ = writeln!(stdout, "{name}");
        }
    }
    Ok(())
}

fn render_patch(patch: &mut patch::Patch) -> CmdResult<String> {
    use std::fmt::Write as _;
    let mut out = String::new();
    // mbox separator: git's fixed magic date; the id field is the
    // kit commit hash (git only needs the "From " prefix).
    let _ = writeln!(
        out,
        "From {} Mon Sep 17 00:00:00 2001",
        kit_core::to_hex(&patch.hash)
    );
    let _ = writeln!(out, "From: {}", patch.from);
    let _ = writeln!(out, "Date: {}", patch.date);
    if patch.total > 1 {
        let _ = write!(
            out,
            "Subject: [PATCH {}/{}] {}\n\n",
            patch.number, patch.total, patch.subject
        );
    } else {
        let _ = write!(out, "Subject: [PATCH] {}\n\n", patch.subject);
    }
    for line in &patch.body {
        out.push_str(line);
        out.push('\n');
    }
    out.push_str("---\n");

    let mut buf: Vec<u8> = Vec::new();
    for change in std::mem::take(&mut patch.changes) {
        super::diff::emit_entry_patch(&mut buf, &change.entry, || Ok(change.body))
            .map_err(super::diff::patch_failure)?;
    }
    out.push_str(&String::from_utf8_lossy(&buf));
    out.push_str("-- \nkit git format-patch\n\n");
    Ok(out)
}

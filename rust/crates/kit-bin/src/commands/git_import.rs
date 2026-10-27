//! `kit git import` / `kit git fetch` / `kit git pull` — the
//! importer-signed git→kit direction (SPEC-GIT-IMPORT; feature
//! `git-bridge`).
//!
//! The logic is in [`libkit::git::import`]. This module parses the
//! arguments and prints the summary.

use std::fmt::Write as _;
use std::path::Path;

use clap::Parser;
use libkit::git::import::{self, FetchRequest, Request, Summary};
use libkit::git_bridge::gitobj::sha1_hex;

use super::git::{Notices, fail};
use crate::exit;
use crate::format;

#[derive(Debug, Parser)]
pub struct ImportArgs {
    /// Upstream git URL or local path.
    pub url: String,
    /// Directory for the fresh-clone form (omit to import into the
    /// current kit repository as tracking refs only).
    pub dir: Option<String>,
    /// Bridge state name under `.kit/git/<name>/`.
    #[arg(long = "remote-name", value_name = "NAME", default_value = "upstream")]
    pub remote_name: String,
    /// Path to the import signing key (32-byte seed file). Default:
    /// `.kit/keys/git-import.key`, generated on first use.
    #[arg(long = "key", value_name = "PATH")]
    pub key: Option<String>,
    /// Machine-readable JSON on stdout.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Parser)]
pub struct FetchArgs {
    /// Bridge state name under `.kit/git/<name>/`.
    #[arg(long = "remote-name", value_name = "NAME", default_value = "upstream")]
    pub remote_name: String,
    /// Path to the import signing key (default: the pinned key file).
    #[arg(long = "key", value_name = "PATH")]
    pub key: Option<String>,
    /// Machine-readable JSON on stdout.
    #[arg(long)]
    pub json: bool,
}

// ─── entry points ───────────────────────────────────────────────────

#[must_use]
pub fn run_import(opts: &ImportArgs) -> u8 {
    let request = Request {
        url: &opts.url,
        remote_name: &opts.remote_name,
        key: opts.key.as_deref().map(Path::new),
    };
    let outcome = match opts.dir.as_deref() {
        Some(dir) => import::clone(Path::new(dir), &request, &Notices).map_err(fail),
        None => current_layout()
            .and_then(|layout| import::import(&layout, &request, &Notices).map_err(fail)),
    };
    finish(outcome, opts.json)
}

#[must_use]
pub fn run_fetch(opts: &FetchArgs, pull: bool) -> u8 {
    let request = FetchRequest {
        remote_name: &opts.remote_name,
        key: opts.key.as_deref().map(Path::new),
    };
    let outcome = current_layout()
        .and_then(|layout| import::fetch(&layout, &request, pull, &Notices).map_err(fail));
    finish(outcome, opts.json)
}

/// The layout of the current directory. On failure the error is printed and
/// the exit code comes back.
fn current_layout() -> Result<kit_core::layout::RepoLayout, u8> {
    let cwd = std::env::current_dir()
        .map_err(|e| super::error(&format!("cwd: {e}"), exit::CONFIG_ERROR))?;
    super::resolve_layout(&cwd)
}

fn finish(outcome: Result<Summary, u8>, json: bool) -> u8 {
    match outcome {
        Ok(summary) => {
            print_summary(&summary, json);
            if summary.imported.is_empty() && !summary.skipped.is_empty() {
                super::error(
                    &format!(
                        "every requested ref was skipped ({} refusals)",
                        summary.skipped.len()
                    ),
                    exit::GENERAL_ERROR,
                )
            } else {
                exit::OK
            }
        }
        Err(code) => code,
    }
}

fn print_summary(summary: &Summary, json: bool) {
    if json {
        // ok mirrors the exit code: an all-skipped run exits
        // non-zero and must not claim success on stdout.
        let ok = !summary.imported.is_empty() || summary.skipped.is_empty();
        let mut out = format!("{{\"ok\":{ok},\"imported\":[");
        for (i, imported) in summary.imported.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            let _ = write!(
                out,
                "{{\"ref\":\"{}\",\"git\":\"{}\",\"kit\":\"{}\"}}",
                format::json_escape(&imported.ref_name),
                sha1_hex(&imported.git_id),
                kit_core::to_hex(&imported.kit_hash)
            );
        }
        out.push_str("],\"skipped\":[");
        for (i, skipped) in summary.skipped.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            let _ = write!(
                out,
                "{{\"ref\":\"{}\",\"reason\":\"{}\"}}",
                format::json_escape(&skipped.ref_name),
                format::json_escape(&skipped.reason)
            );
        }
        out.push(']');
        if let Some(b) = &summary.checked_out {
            let _ = write!(out, ",\"checkedOut\":\"{}\"", format::json_escape(b));
        }
        if let Some(b) = &summary.pulled {
            let _ = write!(out, ",\"fastForwarded\":\"{}\"", format::json_escape(b));
        }
        out.push('}');
        println!("{out}");
        return;
    }
    for imported in &summary.imported {
        println!(
            "imported {} {} -> {}",
            imported.ref_name,
            &sha1_hex(&imported.git_id)[..8],
            &kit_core::to_hex(&imported.kit_hash)[..8]
        );
    }
    if summary.normalized {
        eprintln!(
            "warning: historic tree modes were normalized (declared-lossy; \
             originals retained in the staging mirror)"
        );
    }
    if let Some(b) = &summary.checked_out {
        eprintln!("checked out '{b}'");
    }
    if let Some(b) = &summary.pulled {
        eprintln!("fast-forwarded '{b}'");
    }
}

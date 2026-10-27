//! `kit git` — the git bridge subcommands (feature `git-bridge`):
//! deterministic export to git mirrors (SPEC-GIT-BRIDGE) and importer-signed
//! import (SPEC-GIT-IMPORT).
//!
//! The logic is in [`libkit::git`]. This module parses the arguments, prints
//! the notices and the report, and turns each error into an exit code.

use std::fmt::Write as _;

use clap::Parser;
use kit_core::layout::RepoLayout;
use libkit::Observer;
use libkit::attest::Signer;
use libkit::git::{self, Event, Skipped, export};
use libkit::git_bridge::gitobj::sha1_hex;

use crate::clap_args;
use crate::commands::attest_factory;
use crate::exit;
use crate::format;

#[derive(Debug, Parser)]
#[command(name = "kit git", about = "Git-bridge subcommands (SPEC-GIT-BRIDGE).")]
enum Cmd {
    /// Export refs to a git mirror (one-way, deterministic).
    Export(ExportArgs),
    /// Import a git upstream as an importer-signed downstream fork.
    Import(super::git_import::ImportArgs),
    /// Fetch new upstream commits into refs/remotes/<name>/* only.
    Fetch(super::git_import::FetchArgs),
    /// Fetch, then fast-forward the current branch from its tracking ref.
    Pull(super::git_import::FetchArgs),
    /// Verify bridge state: shallow-verify translated objects, check
    /// imported objects against the pinned importer key (--fork-audit
    /// re-derives the referenced content too).
    Verify(super::git_tools::VerifyArgs),
    /// Show every bridge state dir: direction, endpoints, key, refs.
    Status(super::git_tools::StatusArgs),
    /// Render native commits as `git am`-able patches.
    FormatPatch(super::git_tools::FormatPatchArgs),
}

#[derive(Debug, Parser)]
struct ExportArgs {
    /// Destination: a git URL or a local path (a missing local path
    /// is initialized as a bare repository).
    dest: String,
    /// Name for the per-remote bridge state under `.kit/git/<name>/`.
    #[arg(long = "remote-name", value_name = "NAME", default_value = "mirror")]
    remote_name: String,
    /// Export only these refs (full names, e.g. `refs/heads/main`).
    /// Default: every local branch and tag.
    #[arg(long = "ref", value_name = "REF")]
    refs: Vec<String>,
    /// Skip minting/publishing git-bridge provenance attestations.
    #[arg(long = "no-attest")]
    no_attest: bool,
    /// Attestation algorithm: `ed25519`, `secp256k1`, or `p256`
    /// (default: `attest.default_algorithm` from config, else ed25519).
    #[arg(long, value_name = "ALG")]
    algorithm: Option<String>,
    /// Attestation signer kind: `repo-key`, `external`, or `keystore`
    /// (default: the configured attest signer, like `kit attest`).
    #[arg(long, value_name = "KIND")]
    signer: Option<String>,
    /// Fork mode (SPEC-GIT-BRIDGE §14): re-emit imported history as
    /// the ORIGINAL git objects (shared SHAs with the upstream) and
    /// bridge-translate only native commits on top. Requires this
    /// remote-name's import state; upgrades its direction to `fork`.
    #[arg(long)]
    passthrough: bool,
    /// Machine-readable JSON on stdout.
    #[arg(long)]
    json: bool,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let cmd = match clap_args::parse::<Cmd>("kit git", args) {
        Ok(c) => c,
        Err(code) => return code,
    };
    match cmd {
        Cmd::Export(opts) => {
            let cwd = match std::env::current_dir() {
                Ok(c) => c,
                Err(e) => return emit_err(&format!("cwd: {e}"), exit::CONFIG_ERROR),
            };
            let layout = match super::resolve_layout(&cwd) {
                Ok(layout) => layout,
                Err(code) => return code,
            };
            run_export(&layout, &opts)
        }
        Cmd::Import(opts) => super::git_import::run_import(&opts),
        Cmd::Fetch(opts) => super::git_import::run_fetch(&opts, false),
        Cmd::Pull(opts) => super::git_import::run_fetch(&opts, true),
        Cmd::Verify(opts) => run_simple(|| super::git_tools::verify(&opts)),
        Cmd::Status(opts) => run_simple(|| super::git_tools::status(&opts)),
        Cmd::FormatPatch(opts) => run_simple(|| super::git_tools::format_patch(&opts)),
    }
}

fn run_simple(f: impl FnOnce() -> Result<(), (String, u8)>) -> u8 {
    match f() {
        Ok(()) => exit::OK,
        Err((msg, code)) => emit_err(&msg, code),
    }
}

/// Prints the notices of a bridge operation on stderr.
#[derive(Debug, Clone, Copy)]
pub(super) struct Notices;

impl Observer<Event> for Notices {
    fn event(&self, event: &Event) {
        match event {
            Event::RefSkipped { ref_name, reason } => {
                eprintln!("warning: skipping {ref_name}: {reason}");
            }
            Event::SigningKey { key_prefix, path } => {
                eprintln!(
                    "note: signing imported history with key {key_prefix}… ({})",
                    path.display()
                );
            }
            Event::KeyGenerated { path } => {
                eprintln!(
                    "note: generated a DEDICATED import key at {} — collaborative \
                     tracking of one upstream requires sharing this key (org/bot \
                     key); a different key produces an unrelated fork \
                     (SPEC-GIT-IMPORT §4)",
                    path.display()
                );
            }
            Event::ImportInterrupted => {
                eprintln!("note: previous import was interrupted; rebuilding the map cache");
            }
            Event::MapRebuilt => {
                eprintln!("note: map cache missing or corrupt; rebuilding from the staging mirror");
            }
            Event::UpstreamForcePushed { ref_name } => {
                eprintln!(
                    "warning: upstream force-pushed {ref_name}; tracking ref rewound \
                     (rebase local branches that built on the old history)"
                );
            }
            Event::TagKeptLocal { tag } => {
                eprintln!(
                    "warning: not updating tag '{tag}': it was moved locally \
                     (delete it with `kit tag -d {tag}` to track the upstream tag)"
                );
            }
            Event::TrackingRefRemoved {
                ref_name,
                remote,
                branch,
            } => {
                eprintln!(
                    "warning: upstream deleted {ref_name}; tracking ref {remote}/{branch} removed"
                );
            }
            Event::Lock(event) => crate::progress::ServedWarning.event(event),
            _ => {}
        }
    }
}

/// The message and exit code of a failed bridge operation.
/// [`crate::exit_map`] owns both.
pub(super) fn failure(error: git::Error) -> (String, u8) {
    let error = libkit::Error::from(error);
    (
        crate::exit_map::message(&error),
        crate::exit_map::exit_code(&error),
    )
}

/// Print a failed bridge operation and return its exit code.
pub(super) fn fail(error: git::Error) -> u8 {
    // A held worktree lock prints its own line first, then the line of the
    // pull that it stopped.
    if let git::Error::WorktreeBusy(lock) = &error {
        let _ = super::error(&lock.to_string(), exit::TEMPFAIL);
    }
    let (message, code) = failure(error);
    emit_err(&message, code)
}

/// Why the signer of the attestations cannot be built. The exit map reads
/// the code.
#[derive(Debug)]
pub(crate) struct SignerSetup {
    message: String,
    pub(crate) code: u8,
}

impl SignerSetup {
    pub(crate) fn new(message: String, code: u8) -> Self {
        Self { message, code }
    }
}

impl std::fmt::Display for SignerSetup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for SignerSetup {}

/// The signer of `kit attest`: the flag, else the configured default
/// (SPEC-GIT-BRIDGE §11: "the exporter's configured signer").
fn build_signer(
    layout: &RepoLayout,
    opts: &ExportArgs,
) -> Result<Box<dyn Signer>, git::SignerError> {
    let setup = |message: String, code: u8| -> git::SignerError {
        Box::new(SignerSetup::new(message, code))
    };
    let cfg = crate::config::read_or_default(layout)
        .map_err(|e| setup(format!("read config: {e}"), exit::CONFIG_ERROR))?;
    let alg_str = opts
        .algorithm
        .clone()
        .unwrap_or_else(|| cfg.attest.default_algorithm_or_fallback().to_owned());
    let algorithm = attest_factory::parse_algorithm(&alg_str)
        .map_err(|e| setup(format!("{e}"), exit::USAGE))?;
    let signer_kind = opts
        .signer
        .clone()
        .unwrap_or_else(|| cfg.attest.signer_or_fallback().to_owned());
    attest_factory::build_signer(layout, algorithm, &signer_kind, &cfg).map_err(|e| {
        setup(
            format!("build bridge signer: {e}"),
            crate::exit_map::attest_signer_exit_code(&e),
        )
    })
}

fn run_export(layout: &RepoLayout, opts: &ExportArgs) -> u8 {
    let request = export::Request {
        dest: &opts.dest,
        remote_name: &opts.remote_name,
        refs: &opts.refs,
        attest: !opts.no_attest,
        passthrough: opts.passthrough,
    };
    let mut signer = || build_signer(layout, opts);
    match export::export(layout, &request, &mut signer, &Notices) {
        Ok(outcome) => {
            if opts.json {
                println!("{}", json_report(true, &outcome.exported, &outcome.skipped));
            } else {
                for e in &outcome.exported {
                    println!(
                        "exported {} {} -> {}",
                        e.ref_name,
                        kit_core::to_hex(&e.kit_hash),
                        sha1_hex(&e.git_id)
                    );
                }
            }
            exit::OK
        }
        Err(error) => {
            if opts.json
                && let git::Error::AllRefsSkipped { skipped } = &error
            {
                // Same shape as the success report, ok:false — a JSON
                // consumer gets per-ref skip reasons here just like the
                // import side does.
                println!("{}", json_report(false, &[], skipped));
            }
            fail(error)
        }
    }
}

fn json_report(ok: bool, exported: &[export::Exported], skipped: &[Skipped]) -> String {
    let mut out = format!("{{\"ok\":{ok},\"exported\":[");
    for (i, e) in exported.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "{{\"ref\":\"{}\",\"kit\":\"{}\",\"git\":\"{}\"}}",
            format::json_escape(&e.ref_name),
            kit_core::to_hex(&e.kit_hash),
            sha1_hex(&e.git_id)
        );
    }
    out.push_str("],\"skipped\":[");
    for (i, s) in skipped.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "{{\"ref\":\"{}\",\"reason\":\"{}\"}}",
            format::json_escape(&s.ref_name),
            format::json_escape(&s.reason)
        );
    }
    out.push_str("]}");
    out
}

use super::error as emit_err;

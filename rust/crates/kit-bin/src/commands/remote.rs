//! `kit remote` — show / add / set the configured remote.
//!
//! The rules live in [`libkit::remote`]. This module parses the arguments,
//! prints the listing and turns each failure into its exit code.

use std::io::Write;

use clap::{Parser, Subcommand, ValueEnum};
use libkit::remote::{self, Event, Listing};

use crate::clap_args;
use crate::config;
use crate::exit;
use crate::exit_map;
use crate::format;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RemoteFormat {
    Default,
    Json,
}

#[derive(Debug, Parser)]
#[command(name = "kit remote", about = "Show or configure the remote.")]
struct RemoteOpts {
    /// Output format for the show form. JSON object with `--format=json`.
    #[arg(long, value_enum, default_value = "default")]
    format: RemoteFormat,
    /// Verbose: list each remote's URL and direction (`<name>\t<url>
    /// (fetch)` / `(push)`), like `git remote -v`.
    #[arg(short = 'v', long)]
    verbose: bool,
    #[command(subcommand)]
    sub: Option<RemoteCmd>,
}

#[derive(Debug, Subcommand)]
enum RemoteCmd {
    /// Configure a remote. With one argument, sets the flat default
    /// remote (`kit remote add <url>`). With two, adds/updates a named
    /// remote (`kit remote add <name> <url>`). The URL must be
    /// `kit+<scheme>://...`.
    Add {
        name_or_url: String,
        url: Option<String>,
    },
    /// Alias for `add`.
    Set {
        name_or_url: String,
        url: Option<String>,
    },
    /// Remove a named remote (`kit remote remove <name>`). Use the
    /// reserved name `default` to clear the flat default remote.
    #[command(alias = "rm")]
    Remove { name: String },
    /// Rename a named remote (`kit remote rename <old> <new>`). Also
    /// rewrites any `branch.<b>.remote` upstream pointing at `<old>`.
    #[command(alias = "mv")]
    Rename { old: String, new: String },
    /// Print a remote's URL (`kit remote get-url <name>`; use `default`
    /// for the flat default remote).
    #[command(name = "get-url")]
    GetUrl { name: String },
    /// Change a remote's URL (`kit remote set-url <name> <url>`).
    #[command(name = "set-url")]
    SetUrl { name: String, url: String },
}

/// Prints each tidy-step event on stderr.
struct StateWarnings;

impl libkit::Observer<Event> for StateWarnings {
    fn event(&self, event: &Event) {
        let mut stderr = std::io::stderr().lock();
        let _ = match event {
            Event::TrackingRefsNotMoved { old, new, error } => writeln!(
                stderr,
                "warning: could not move tracking refs {old} -> {new}: {error}; \
                 run `kit fetch {new}` to repopulate"
            ),
            Event::BridgeStateNotMoved { old, new, error } => writeln!(
                stderr,
                "warning: could not move git-bridge state {old} -> {new}: {error}"
            ),
            Event::AppliedPacksNotMoved { old, new, error } => writeln!(
                stderr,
                "warning: could not move applied-packs record {old} -> {new}: {error}"
            ),
            Event::AppliedPacksNotRemoved { name, error } => writeln!(
                stderr,
                "warning: could not remove applied-packs record for '{name}': {error}"
            ),
            Event::TrackingRefsNotRemoved { name, error } => writeln!(
                stderr,
                "warning: could not remove tracking refs for '{name}': {error}"
            ),
            Event::BridgeStateRemains { name } => writeln!(
                stderr,
                "note: git-bridge state for '{name}' remains at .kit/git/{name}/ \
                 (staging mirror + provenance); delete it manually if unwanted"
            ),
            _ => Ok(()),
        };
    }
}

/// Print `error` and give its exit code. `scheme_hint` adds the list of
/// schemes to the message about an address that has no accepted scheme.
fn fail(error: remote::Error, scheme_hint: bool) -> u8 {
    let error = libkit::Error::from(error);
    let mut message = exit_map::message(&error);
    if scheme_hint
        && matches!(
            error,
            libkit::Error::Remote(remote::Error::UnsupportedScheme(_))
        )
    {
        message.push_str(
            "\nhint: URL must start with kit+<scheme>:// (e.g. kit+https://, kit+ssh://, kit+file://, kit+s3://)",
        );
    }
    emit_err(&message, exit_map::exit_code(&error))
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_args::parse::<RemoteOpts>("kit remote", args) {
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
    let layered = match config::read_layered(&layout) {
        Ok(c) => c,
        Err(e) => return emit_err(&format!("config: {e}"), exit::CONFIG_ERROR),
    };
    // `show` reflects the merged view; every mutating subcommand operates
    // on and persists ONLY the repo layer, so a user-scoped value (e.g. a
    // private `user.email`) is never materialized into the clone-traveling
    // `.kit/config` by `config::write`.
    let Some(sub) = opts.sub else {
        return show(
            &remote::list(&layered.merged),
            matches!(opts.format, RemoteFormat::Json),
            opts.verbose,
        );
    };
    let mut cfg = layered.repo;

    match sub {
        RemoteCmd::Add { name_or_url, url } | RemoteCmd::Set { name_or_url, url } => {
            // Two forms:
            //   `kit remote add <url>`         -> flat default remote
            //   `kit remote add <name> <url>`  -> named remote
            let (name, url) = match url {
                Some(url) => (Some(name_or_url), url),
                None => (None, name_or_url),
            };
            match remote::add(&layout, &mut cfg, name.as_deref(), &url) {
                Ok(()) => exit::OK,
                Err(e) => fail(e, true),
            }
        }
        RemoteCmd::Remove { name } => {
            match remote::remove(&layout, &mut cfg, &name, &StateWarnings) {
                Ok(()) => exit::OK,
                Err(e) => fail(e, false),
            }
        }
        RemoteCmd::Rename { old, new } => {
            match remote::rename(&layout, &mut cfg, &old, &new, &StateWarnings) {
                Ok(()) => exit::OK,
                Err(e) => fail(e, false),
            }
        }
        RemoteCmd::GetUrl { name } => {
            // Read-only — reflect the merged view (a default endpoint may be
            // user-scoped).
            match remote::url_of(&layered.merged, &name) {
                Ok(url) => {
                    let mut stdout = std::io::stdout().lock();
                    let _ = writeln!(stdout, "{url}");
                    exit::OK
                }
                Err(e) => fail(e, false),
            }
        }
        RemoteCmd::SetUrl { name, url } => match remote::set_url(&layout, &mut cfg, &name, &url) {
            Ok(()) => exit::OK,
            Err(e) => fail(e, false),
        },
    }
}

fn show(listing: &Listing, json: bool, verbose: bool) -> u8 {
    let has_default = listing.default.is_some();
    if !has_default && listing.named.is_empty() {
        // Empty listing → empty stdout in both modes. The default
        // mode emits a human note on stderr.
        if !json {
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(stderr, "(no remote configured)");
        }
        return exit::OK;
    }
    let mut stdout = std::io::stdout().lock();
    if json {
        // Additive shape: when only the default remote is configured,
        // emit the historical single-line object so existing JSON
        // snapshots stay valid. When named remotes exist, emit one JSON
        // object per line (JSONL) carrying a `name` field; the default
        // remote (if any) appears as `name=default`.
        if let (Some(default), true) = (&listing.default, listing.named.is_empty()) {
            let _ = writeln!(
                stdout,
                "{{\"url\":\"{}\",\"transport\":\"{}\"}}",
                format::json_escape(&default.url),
                format::json_escape(&default.transport)
            );
            return exit::OK;
        }
        if let Some(default) = &listing.default {
            let _ = writeln!(
                stdout,
                "{{\"name\":\"{}\",\"url\":\"{}\",\"transport\":\"{}\"}}",
                config::DEFAULT_REMOTE_NAME,
                format::json_escape(&default.url),
                format::json_escape(&default.transport)
            );
        }
        for entry in &listing.named {
            let _ = writeln!(
                stdout,
                "{{\"name\":\"{}\",\"url\":\"{}\",\"transport\":\"{}\"}}",
                format::json_escape(&entry.name),
                format::json_escape(&entry.url),
                format::json_escape(&entry.transport)
            );
        }
        return exit::OK;
    }
    // Default (human) form, git-shaped:
    //   `kit remote`      → one remote NAME per line
    //   `kit remote -v`   → `<name>\t<url> (fetch)` and `(push)` per remote
    // The flat default remote shows under the reserved name `default`.
    let all = listing.default.iter().chain(&listing.named);
    for entry in all {
        if verbose {
            let _ = writeln!(stdout, "{}\t{} (fetch)", entry.name, entry.url);
            let _ = writeln!(stdout, "{}\t{} (push)", entry.name, entry.url);
        } else {
            let _ = writeln!(stdout, "{}", entry.name);
        }
    }
    exit::OK
}

use super::error as emit_err;

//! `kit branch` — list / create / delete branches.
//!
//! Output modes for the list form:
//!
//! - default — `<marker> <name>` per line, `*` marks current. Matches
//!   `git branch`: the commit id is **not** shown (it moved behind `-v`).
//! - `-v` / `--verbose` — `<marker> <name> <short> <subject>`, the name
//!   column padded to the longest branch name, like `git branch -v`. The
//!   abbreviated id is a BLAKE3 prefix (the documented hash-length
//!   divergence), not a 40-hex SHA-1 prefix.
//! - `--format=json` — JSONL: `{"name":"...","current":bool,"hash":"<64-hex>"}`.

use std::io::Write;

use clap::{Parser, ValueEnum};
use kit_core::layout::RepoLayout;

use crate::clap_args;
use crate::exit;
use crate::format;
use crate::progress::ServedWarning;
use libkit::branch::{self, Branch, Query, Scope};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum BranchFormat {
    Default,
    Json,
}

#[derive(Debug, Parser)]
#[command(
    name = "kit branch",
    about = "List, create, rename, or delete branches."
)]
#[allow(clippy::struct_excessive_bools)] // clap option flags, not a state machine
struct BranchOpts {
    /// Delete the named branch (safe — refuses the current branch and a
    /// non-existent branch).
    #[arg(short = 'd', long)]
    delete: bool,
    /// Force-delete the named branch. kit tracks no per-branch merge
    /// state, so `-D` behaves like `-d`: it still refuses the branch HEAD
    /// points at (that would leave HEAD dangling) and, like git, errors on
    /// an absent branch rather than reporting a silent success.
    #[arg(short = 'D')]
    force_delete: bool,
    /// Rename a branch. `branch -m <old> <new>` renames `<old>`;
    /// `branch -m <new>` renames the current branch. Moves HEAD when the
    /// renamed branch is the checked-out one.
    #[arg(short = 'm', long)]
    rename: bool,
    /// Verbose list: also show each branch tip's abbreviated id and
    /// commit subject (like `git branch -v`).
    #[arg(short = 'v', long)]
    verbose: bool,
    /// List branches (explicit selector, like `git branch --list`). Listing
    /// is already the default when no create/delete/rename flag is given;
    /// `--list` additionally enables positional `<pattern>` glob filtering.
    #[arg(long)]
    list: bool,
    /// List the remote-tracking branches, named `<remote>/<branch>`, instead
    /// of the local ones (like `git branch -r`).
    #[arg(short = 'r', long = "remotes", conflicts_with = "all")]
    remotes: bool,
    /// List the local branches and the remote-tracking branches. The latter
    /// are named `remotes/<remote>/<branch>` (like `git branch -a`).
    #[arg(short = 'a', long = "all")]
    all: bool,
    /// List only branches whose tip has `<commit>` as an ancestor (default
    /// HEAD when omitted, like `git branch --contains`).
    #[arg(long, value_name = "COMMIT", num_args = 0..=1, default_missing_value = "HEAD")]
    contains: Option<String>,
    /// List only branches whose tip does NOT contain `<commit>` (default HEAD).
    #[arg(long = "no-contains", value_name = "COMMIT", num_args = 0..=1, default_missing_value = "HEAD")]
    no_contains: Option<String>,
    /// List only branches already merged into `<commit>` (default HEAD) —
    /// the branch tip is an ancestor of it (like `git branch --merged`).
    #[arg(long, value_name = "COMMIT", num_args = 0..=1, default_missing_value = "HEAD")]
    merged: Option<String>,
    /// List only branches NOT merged into `<commit>` (default HEAD).
    #[arg(long = "no-merged", value_name = "COMMIT", num_args = 0..=1, default_missing_value = "HEAD")]
    no_merged: Option<String>,
    /// Print the current branch name and exit (like `git branch
    /// --show-current`). Empty output on a detached HEAD.
    #[arg(long = "show-current")]
    show_current: bool,
    /// Output format for the list form. JSONL with `--format=json`.
    #[arg(long, value_enum, default_value = "default")]
    format: BranchFormat,
    /// Positional arguments. In create/delete/rename mode these are branch
    /// names; in list mode (`--list` or an ancestry filter) they are shell
    /// glob patterns that filter the listing (like `git branch --list`).
    #[arg(num_args = 0..)]
    names: Vec<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_args::parse::<BranchOpts>("kit branch", args) {
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

    // `--show-current`: print the checked-out branch (nothing when
    // detached), then exit — like `git branch --show-current`.
    if opts.show_current {
        if let Some(name) = branch::current(&layout) {
            let mut stdout = std::io::stdout().lock();
            let _ = writeln!(stdout, "{name}");
        }
        return exit::OK;
    }

    // `-m` / `-d` / `-D` are mutually exclusive mode flags.
    let mode_flags = u8::from(opts.delete) + u8::from(opts.force_delete) + u8::from(opts.rename);
    if mode_flags > 1 {
        return super::usage_error("usage: kit branch [-d|-D|-m] ...  (modes are exclusive)");
    }

    let has_ancestry_filter = opts.contains.is_some()
        || opts.no_contains.is_some()
        || opts.merged.is_some()
        || opts.no_merged.is_some();
    let scope = match (opts.remotes, opts.all) {
        (true, _) => Scope::Remote,
        (_, true) => Scope::All,
        _ => Scope::Local,
    };
    let has_filter = opts.list || has_ancestry_filter || scope != Scope::Local;

    if opts.rename || opts.delete || opts.force_delete {
        if has_filter {
            return super::usage_error(
                "usage: kit branch [-r|-a|--list|--contains|--no-contains|--merged|--no-merged] only \
                 filter the listing — they cannot combine with -d/-D/-m",
            );
        }
        if opts.rename {
            return rename(&layout, &opts.names);
        }
        return delete(&layout, &opts.names, opts.force_delete);
    }

    let json = matches!(opts.format, BranchFormat::Json);

    // In list mode (`--list` or an ancestry filter present) the positionals
    // are glob patterns that filter the listing, like `git branch --list
    // <pattern>`. Otherwise the positional is a branch name to create.
    let query = |patterns| Query {
        scope,
        patterns,
        contains: opts.contains.as_deref(),
        no_contains: opts.no_contains.as_deref(),
        merged: opts.merged.as_deref(),
        no_merged: opts.no_merged.as_deref(),
        subjects: opts.verbose,
    };
    if has_filter {
        return list(&layout, json, opts.verbose, &query(&opts.names));
    }
    match opts.names.as_slice() {
        [] => list(&layout, json, opts.verbose, &query(&[])),
        [name] => create(&layout, name),
        _ => super::usage_error("usage: kit branch <name>  (create takes one name)"),
    }
}

/// `kit branch <name>` — create a new branch at HEAD.
fn create(layout: &RepoLayout, name: &str) -> u8 {
    match branch::create(layout, name) {
        Ok(()) => exit::OK,
        Err(e) => super::fail(e),
    }
}

/// `kit branch -d/-D <name>` — delete a branch.
///
/// `-d` and `-D` behave the same: kit tracks no per-branch merge status.
/// Both refuse the branch HEAD names, and both error on a missing branch,
/// like git, so a typo in the name is never swallowed.
fn delete(layout: &RepoLayout, names: &[String], force: bool) -> u8 {
    let [name] = names else {
        let flag = if force { "-D" } else { "-d" };
        return super::usage_error(&format!("usage: kit branch {flag} <name>"));
    };
    match branch::delete(layout, name, &ServedWarning) {
        Ok(was) => {
            let mut stderr = std::io::stderr().lock();
            match was {
                Some(h) => {
                    let _ = writeln!(
                        stderr,
                        "Deleted branch {name} (was {}).",
                        format::short_hash(&h, format::SUMMARY_ABBREV)
                    );
                }
                None => {
                    let _ = writeln!(stderr, "Deleted branch {name}.");
                }
            }
            exit::OK
        }
        Err(e) => super::fail(e),
    }
}

/// `kit branch -m [<old>] <new>` — rename a branch.
///
/// With two names renames `<old>` → `<new>`; with one name renames the
/// current branch → `<new>`.
fn rename(layout: &RepoLayout, names: &[String]) -> u8 {
    let (old, new) = match names {
        [new] => (None, new),
        [old, new] => (Some(old.as_str()), new),
        _ => return super::usage_error("usage: kit branch -m [<old>] <new>"),
    };
    match branch::rename(layout, old, new, &ServedWarning) {
        Ok(()) => exit::OK,
        Err(e) => super::fail(e),
    }
}

/// Abbreviated-id length for `branch -v`, matching `log`'s default and
/// git's default `core.abbrev` (7) in shape (kit's id is a BLAKE3 prefix).
const DEFAULT_ABBREV: usize = 7;

fn list(layout: &RepoLayout, json: bool, verbose: bool, query: &Query<'_>) -> u8 {
    let current = branch::current(layout);
    let branches = match branch::list(layout, query) {
        Ok(branches) => branches,
        Err(e) => return super::fail(e),
    };

    let mut stdout = std::io::stdout().lock();
    if json {
        for r in &branches {
            let is_current = !r.remote && current.as_deref() == Some(r.name.as_str());
            let _ = stdout.write_all(b"{");
            let _ = write!(stdout, "\"name\":\"{}\"", format::json_escape(&r.name));
            let _ = write!(stdout, ",\"current\":{is_current}");
            if r.remote {
                let _ = stdout.write_all(b",\"remote\":true");
            }
            if let Some(h) = &r.hash {
                let _ = write!(stdout, ",\"hash\":\"{}\"", format::hex_hash(h));
            } else {
                let _ = stdout.write_all(b",\"hash\":null");
            }
            let _ = stdout.write_all(b"}\n");
        }
        return exit::OK;
    }

    let marker_for = |r: &Branch| {
        current.as_deref().map_or(
            ' ',
            |cur| {
                if !r.remote && cur == r.name { '*' } else { ' ' }
            },
        )
    };

    if !verbose {
        // Default: `<marker> <name>` only — `git branch` omits the id.
        for r in &branches {
            let _ = writeln!(stdout, "{} {}", marker_for(r), r.name);
        }
        return exit::OK;
    }

    // Verbose: `<marker> <name> <short> <subject>`, name column padded to
    // the longest branch name (like `git branch -v`).
    let width = branches.iter().map(|r| r.name.len()).max().unwrap_or(0);
    for entry in &branches {
        let Branch {
            name,
            hash,
            subject,
            ..
        } = entry;
        let marker = marker_for(entry);
        match (hash, subject) {
            (Some(h), Some(subject)) => {
                let short = format::short_hash(h, DEFAULT_ABBREV);
                let _ = writeln!(stdout, "{marker} {name:<width$} {short} {subject}");
            }
            _ => {
                let _ = writeln!(stdout, "{marker} {name:<width$}");
            }
        }
    }
    exit::OK
}

use super::error as emit_err;

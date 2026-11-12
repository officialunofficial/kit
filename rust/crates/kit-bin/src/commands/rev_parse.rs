//! `kit rev-parse [--short[=N]] [--abbrev-ref] [--show-toplevel] [<rev>...]`
//! — resolve revisions to object ids, like `git rev-parse`.
//!
//! - bare `<rev>...` — print each resolved 64-hex id, one per line;
//! - `--short[=N]` — abbreviate to N chars (default 7);
//! - `--verify <rev>` — print the id of exactly one revision that resolves to
//!   an object, and fail with nothing on stdout otherwise (`-q` also drops the
//!   message);
//! - `--abbrev-ref <ref>` — print the short symbolic name (`HEAD` → the
//!   current branch);
//! - `--show-toplevel` — print the repository root (the dir holding
//!   `.kit`).
//!
//! Resolution reuses the shared revspec grammar (refs, full/short hashes,
//! `HEAD~n`/`^`, and `<rev>:<path>` for the object at a path in the tree of
//! a revision). The abbreviated id is a BLAKE3 prefix, not a SHA-1 one.

use std::io::Write;
use std::path::{Path, PathBuf};

use clap::Parser;
use kit_core::Hash;
use kit_core::layout::RepoLayout;
use kit_core::refs::{self, Head};
use kit_core::store::ObjectStore;

use crate::clap_args;
use crate::exit;
use crate::format;
use libkit::revspec;

const DEFAULT_ABBREV: usize = 7;

#[derive(Debug, Parser)]
#[command(name = "kit rev-parse", about = "Resolve revisions to object ids.")]
// CLI flag struct: each bool is an independent clap switch.
#[allow(clippy::struct_excessive_bools)]
struct RevParseOpts {
    /// Abbreviate the id to N chars (default 7). Value must be attached
    /// (`--short` or `--short=N`) so it does not swallow a following rev.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "7")]
    short: Option<usize>,
    /// Print the short symbolic ref name (`HEAD` → the current branch).
    #[arg(long = "abbrev-ref")]
    abbrev_ref: bool,
    /// Print the repository root and exit.
    #[arg(long = "show-toplevel")]
    show_toplevel: bool,
    /// Require exactly one revision that resolves to an object. Print its
    /// full id. On any other input print nothing on stdout and exit non-zero.
    #[arg(long, conflicts_with_all = ["abbrev_ref", "show_toplevel"])]
    verify: bool,
    /// With `--verify`, print no message when the revision does not resolve.
    #[arg(short = 'q', long, requires = "verify")]
    quiet: bool,
    /// Revisions to resolve.
    args: Vec<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_args::parse::<RevParseOpts>("kit rev-parse", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let mut stdout = std::io::stdout().lock();

    // `--show-toplevel` only needs to find the repo root (walking up from a
    // subdirectory), so handle it before opening the object store.
    if opts.show_toplevel {
        let Some(root) = find_repo_root(&cwd) else {
            return emit_err("not inside a kit repository", exit::GENERAL_ERROR);
        };
        let _ = writeln!(stdout, "{}", root.display());
        return exit::OK;
    }

    let layout = match super::resolve_layout(&cwd) {
        Ok(layout) => layout,
        Err(code) => return code,
    };
    let store = match ObjectStore::open(&layout) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a kit repo: {e}"), exit::GENERAL_ERROR),
    };

    if opts.args.is_empty() {
        return super::usage_error("usage: kit rev-parse [opts] <rev>...");
    }

    if opts.verify {
        let [spec] = opts.args.as_slice() else {
            return super::usage_error("--verify needs exactly one revision");
        };
        let found = revspec::resolve_object(&store, &layout, spec)
            .map_err(|e| e.to_string())
            .and_then(|h| {
                if store.contains(&h) {
                    Ok(h)
                } else {
                    Err("object is missing".to_string())
                }
            });
        return match found {
            Ok(hash) => {
                let _ = writeln!(stdout, "{}", render(&hash, opts.short));
                exit::OK
            }
            Err(_) if opts.quiet => exit::GENERAL_ERROR,
            Err(e) => emit_err(&format!("bad revision '{spec}': {e}"), exit::GENERAL_ERROR),
        };
    }

    for spec in &opts.args {
        if opts.abbrev_ref {
            match abbrev_ref(&layout, spec) {
                Ok(name) => {
                    let _ = writeln!(stdout, "{name}");
                }
                Err(code) => return code,
            }
            continue;
        }
        let hash = match revspec::resolve_object(&store, &layout, spec) {
            Ok(h) => h,
            Err(e) => {
                // A bad revision is an error. kit refuses rather than
                // echoing the bad token.
                return emit_err(&format!("bad revision '{spec}': {e}"), exit::GENERAL_ERROR);
            }
        };
        let _ = writeln!(stdout, "{}", render(&hash, opts.short));
    }
    exit::OK
}

/// The full id, or the `--short[=N]` abbreviation of it.
fn render(hash: &Hash, short: Option<usize>) -> String {
    match short {
        Some(n) => format::short_hash(hash, if n == 0 { DEFAULT_ABBREV } else { n }),
        None => format::hex_hash(hash),
    }
}

/// `--abbrev-ref` rendering: `HEAD` → the current branch (or `HEAD` when
/// detached); any other token is echoed as the already-short name.
fn abbrev_ref(layout: &RepoLayout, spec: &str) -> Result<String, u8> {
    if spec == "HEAD" {
        return match refs::read_head(layout) {
            Ok(Head::Branch(name)) => Ok(name),
            Ok(Head::Detached(_)) => Ok("HEAD".to_string()),
            Err(e) => Err(emit_err(&format!("read HEAD: {e}"), exit::DATAERR)),
        };
    }
    // Strip a fully-qualified ref prefix if present; else echo as-is.
    let short = spec
        .strip_prefix("refs/heads/")
        .or_else(|| spec.strip_prefix("refs/tags/"))
        .or_else(|| spec.strip_prefix("refs/remotes/"))
        .unwrap_or(spec);
    Ok(short.to_string())
}

/// Walk up from `start` to the directory that contains `.kit`.
fn find_repo_root(start: &Path) -> Option<PathBuf> {
    let mut cur = start;
    loop {
        if cur.join(kit_core::KIT_DIR).is_dir() {
            return Some(cur.to_path_buf());
        }
        cur = cur.parent()?;
    }
}

use super::error as emit_err;

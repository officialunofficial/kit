//! `kit rev-list [--count] [-n <n> | --max-count=<n>] <rev>` — list the
//! commit ids reachable from `<rev>` in reverse-chronological (topological)
//! order, or just their count. `<rev>` is a revision, a range `A..B` or a
//! symmetric range `A...B`, and `kit log` reads all three the same way. The
//! selection and the walk come from `libkit::log`, so the order matches
//! `kit log`. `--max-count` keeps the first `<n>` commits of that order, and
//! `--count` counts what is left. Object ids are full 64-hex BLAKE3 (the
//! documented divergence).

use std::io::Write;

use clap::Parser;
use libkit::log::{self, Query};

use crate::clap_args;
use crate::exit;
use crate::format;

#[derive(Debug, Parser)]
#[command(
    name = "kit rev-list",
    about = "List commit objects reachable from a revision."
)]
struct RevListOpts {
    /// Print the number of commits instead of the list.
    #[arg(long)]
    count: bool,
    /// Stop after this many commits. Zero lists none. A value that is not a
    /// non-negative integer is a usage error.
    #[arg(short = 'n', long = "max-count", value_name = "N")]
    max_count: Option<usize>,
    /// Starting revision (branch / tag / commit / HEAD), range `A..B` or
    /// symmetric range `A...B`.
    rev: String,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_args::parse::<RevListOpts>("kit rev-list", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let repo = match super::open_repo(&cwd) {
        Ok(repo) => repo,
        Err(code) => return code,
    };
    let query = Query {
        start: Some(opts.rev.clone()),
        limit: opts.max_count,
        ..Query::default()
    };
    let commits = match log::history(&repo, &query) {
        Ok(Some(c)) => c,
        // `HEAD` names no commit yet, so the revision has no meaning.
        Ok(None) => {
            return emit_err(
                &format!("bad revision '{}': HEAD has no commit", opts.rev),
                exit::GENERAL_ERROR,
            );
        }
        Err(e) => {
            let code = if matches!(e, log::Error::BadRevision { .. }) {
                exit::GENERAL_ERROR
            } else {
                exit::DATAERR
            };
            return emit_err(&e.to_string(), code);
        }
    };
    let mut stdout = std::io::stdout().lock();
    if opts.count {
        let _ = writeln!(stdout, "{}", commits.len());
    } else {
        for entry in &commits {
            let _ = writeln!(stdout, "{}", format::hex_hash(&entry.hash));
        }
    }
    exit::OK
}

use super::error as emit_err;

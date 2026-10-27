//! `kit rev-list [--count] <rev>` — list the commit ids reachable from
//! `<rev>` in reverse-chronological (topological) order, or just their
//! count. Uses the ordered walk of `libkit::log` so ordering matches `kit log`.
//! Object ids are full 64-hex BLAKE3 (the documented divergence).

use std::io::Write;

use clap::Parser;
use kit_core::store::ObjectStore;

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
    /// Starting revision (branch / tag / commit / HEAD).
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
    let layout = match super::resolve_layout(&cwd) {
        Ok(layout) => layout,
        Err(code) => return code,
    };
    let store = match ObjectStore::open(&layout) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a kit repo: {e}"), exit::GENERAL_ERROR),
    };
    let tip = match libkit::revspec::resolve_revision(&store, &layout, &opts.rev) {
        // Peel annotated/signed tags to the commit they point at, like
        // `log`/`diff`/`branch` (resolve_revision returns the tag object).
        Ok(h) => libkit::revspec::peel_tags(&store, h),
        Err(e) => {
            return emit_err(
                &format!("bad revision '{}': {e}", opts.rev),
                exit::GENERAL_ERROR,
            );
        }
    };
    let commits = match libkit::log::walk(&store, &[tip], false) {
        Ok(c) => c,
        Err(e) => return emit_err(&e.to_string(), exit::DATAERR),
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

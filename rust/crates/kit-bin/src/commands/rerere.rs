//! `kit rerere [status | diff | forget <path> | clear | gc]` — inspect and
//! maintain the recorded conflict resolutions. The cache, the replay and the
//! recording live in [`libkit::rerere`]; see SPEC-RERERE.

use std::io::Write;
use std::time::SystemTime;

use clap::{Parser, Subcommand};
use kit_core::layout::RepoLayout;
use kit_core::ops::conflict_state::{self, ConflictRecord};
use kit_core::ops::rebase::{is_rebase_in_progress, rebase_dir_path};
use kit_core::store::ObjectStore;
use libkit::rerere::{self, Expiry};

use crate::clap_args;
use crate::exit;

#[derive(Debug, Parser)]
#[command(name = "kit rerere", about = "Reuse recorded conflict resolutions.")]
struct RerereOpts {
    #[command(subcommand)]
    sub: Option<RerereCmd>,
}

#[derive(Debug, Subcommand)]
enum RerereCmd {
    /// List the conflicts of the paused operation that have a cache entry.
    Status,
    /// Show the changes from each tracked conflict to its file now.
    Diff,
    /// Drop the recorded resolution of the conflict at a path.
    Forget {
        /// The conflicting path.
        path: String,
    },
    /// Delete every entry.
    Clear,
    /// Delete entries older than `gc.rerereResolved` and
    /// `gc.rerereUnresolved` days.
    Gc,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_args::parse::<RerereOpts>("kit rerere", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return super::error(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let layout = match super::resolve_layout(&cwd) {
        Ok(layout) => layout,
        Err(code) => return code,
    };
    // Recording and replay run inside each operation, so the bare command
    // has nothing to do.
    let Some(sub) = opts.sub else {
        return exit::OK;
    };
    match sub {
        RerereCmd::Status => with_conflicts(&layout, |store, records| {
            let tracked = rerere::status(&layout, store, records).map_err(|e| fail(&e))?;
            let mut stdout = std::io::stdout().lock();
            for t in tracked {
                let _ = writeln!(stdout, "{}", super::display_path(&t.path));
            }
            Ok(())
        }),
        RerereCmd::Diff => with_conflicts(&layout, |store, records| {
            let out = rerere::diff(&layout, store, records).map_err(|e| fail(&e))?;
            let _ = std::io::stdout().lock().write_all(&out);
            Ok(())
        }),
        RerereCmd::Forget { path } => with_conflicts(&layout, |store, records| {
            rerere::forget(&layout, store, records, &path).map_err(|e| fail(&e))
        }),
        RerereCmd::Clear => match rerere::clear(&layout) {
            Ok(()) => exit::OK,
            Err(e) => fail(&e),
        },
        RerereCmd::Gc => {
            let expiry = crate::config::read_or_default(&layout).map_or_else(
                |_| Expiry::default(),
                |cfg| Expiry {
                    resolved_days: cfg.gc_rerere_resolved_days(),
                    unresolved_days: cfg.gc_rerere_unresolved_days(),
                },
            );
            match rerere::gc(&layout, SystemTime::now(), expiry) {
                Ok(_) => exit::OK,
                Err(e) => fail(&e),
            }
        }
    }
}

/// Run `f` over the conflicts of the paused operation: the rebase step when
/// a rebase is in progress, else the merge, cherry-pick or revert.
fn with_conflicts(
    layout: &RepoLayout,
    f: impl FnOnce(&ObjectStore, &[ConflictRecord]) -> Result<(), u8>,
) -> u8 {
    let store = match ObjectStore::open(layout) {
        Ok(s) => s,
        Err(e) => return super::error(&format!("not a kit repo: {e}"), exit::GENERAL_ERROR),
    };
    let dir = if is_rebase_in_progress(layout) {
        rebase_dir_path(layout)
    } else {
        layout.worktree_state_dir().to_path_buf()
    };
    let records = match conflict_state::read_conflicts(&dir) {
        Ok(r) => r,
        Err(e) => return super::error(&format!("read conflicts: {e}"), exit::DATAERR),
    };
    match f(&store, &records) {
        Ok(()) => exit::OK,
        Err(code) => code,
    }
}

fn fail(e: &rerere::Error) -> u8 {
    let code = match e {
        rerere::Error::NotTracked(_) => exit::USAGE,
        rerere::Error::UnknownVersion => exit::DATAERR,
        _ => exit::CANTCREAT,
    };
    super::error(&e.to_string(), code)
}

//! `kit apply` — apply unified diffs to the worktree, the index or both, all
//! or nothing (SPEC-PATCH). The parser lives in [`kit_core::ops::patch`] and
//! the writes in [`libkit::apply`].

use std::io::Read;

use clap::Parser;
use kit_core::ops::patch::{self, FilePatch, MAX_PATCH_BYTES};
use libkit::apply::Target;
use libkit::diff::{FileStat, StatChange};

use crate::clap_args;
use crate::exit;

#[derive(Debug, Parser)]
#[command(
    name = "kit apply",
    about = "Apply patches to the worktree, the index or both."
)]
#[allow(clippy::struct_excessive_bools)] // clap option flags, not a state machine
struct ApplyOpts {
    /// Apply to the index only.
    #[arg(long, conflicts_with = "index")]
    cached: bool,
    /// Apply to the worktree and the index, which must agree.
    #[arg(long)]
    index: bool,
    /// Apply the patches in reverse.
    #[arg(short = 'R', long)]
    reverse: bool,
    /// Report whether the patches apply; write nothing.
    #[arg(long, conflicts_with = "stat")]
    check: bool,
    /// Print a diffstat of the patches; write nothing.
    #[arg(long)]
    stat: bool,
    /// Patch files; `-` reads standard input.
    #[arg(required = true, value_name = "patch")]
    patches: Vec<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_args::parse::<ApplyOpts>("kit apply", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let mut files = Vec::new();
    for name in &opts.patches {
        let text = match read_patch(name) {
            Ok(t) => t,
            Err(code) => return code,
        };
        match patch::parse(&text) {
            Ok(f) => files.extend(f),
            Err(e) => return super::error(&format!("{name}: {e}"), exit::DATAERR),
        }
    }
    if opts.reverse {
        files = files.iter().rev().map(FilePatch::reversed).collect();
    }
    if opts.stat {
        return print_stat(&files);
    }
    let target = match (opts.cached, opts.index) {
        (true, _) => Target::Index,
        (_, true) => Target::Both,
        _ => Target::Worktree,
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return super::error(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let repo = match super::open_repo(&cwd) {
        Ok(repo) => repo,
        Err(code) => return code,
    };
    match libkit::apply::apply(
        repo.layout(),
        repo.store(),
        &files,
        target,
        opts.check,
        &crate::progress::ServedWarning,
    ) {
        Ok(()) => exit::OK,
        Err(e) if e.is_conflict() => super::error(&format!("patch does not apply: {e}"), 1),
        Err(e) => super::error(&e.to_string(), exit::IOERR),
    }
}

/// The text of a patch file, or of standard input for `-`, up to
/// [`MAX_PATCH_BYTES`].
pub(super) fn read_patch(name: &str) -> Result<Vec<u8>, u8> {
    let limit = u64::try_from(MAX_PATCH_BYTES).unwrap_or(u64::MAX) + 1;
    let mut text = Vec::new();
    let read = if name == "-" {
        std::io::stdin().lock().take(limit).read_to_end(&mut text)
    } else {
        std::fs::File::open(name).and_then(|f| f.take(limit).read_to_end(&mut text))
    };
    if let Err(e) = read {
        return Err(super::error(&format!("{name}: {e}"), exit::NOINPUT));
    }
    if text.len() > MAX_PATCH_BYTES {
        return Err(super::error(
            &format!("{name}: the patch is over {MAX_PATCH_BYTES} bytes"),
            exit::DATAERR,
        ));
    }
    Ok(text)
}

fn print_stat(files: &[FilePatch]) -> u8 {
    let rows: Vec<FileStat> = files
        .iter()
        .map(|f| {
            let (added, deleted) = f.counts();
            let path = f.new.clone().or_else(|| f.old.clone()).unwrap_or_default();
            FileStat {
                old_path: f.old.clone().filter(|o| f.new.is_some() && *o != path),
                path,
                change: StatChange::Text { added, deleted },
            }
        })
        .collect();
    let mut out = std::io::stdout().lock();
    match super::diff::stat::render_stat(&mut out, &rows) {
        Ok(()) => exit::OK,
        Err(e) => super::error(&e, exit::IOERR),
    }
}

//! `kit add <path>` / `kit add .` — stage a file (or the whole
//! worktree) into `.kit/index`. `add -p` additionally stages individual
//! hunks interactively (see `StdinChooser`).
//!
//! The logic is in [`libkit::add`]. This module parses the arguments, asks
//! for the hunks of `-p` and prints.

use std::io::{BufRead, Write};

use clap::Parser;
use kit_core::ops::{HunkLineKind, PatchHunk};
use libkit::Observer;
use libkit::add::{self, Choice, Event, HunkChooser, Request};

use crate::clap_args;
use crate::exit;

#[derive(Debug, Parser)]
#[command(
    name = "kit add",
    about = "Stage files (paths, `.`, `-A`, or `-u`) into the index."
)]
// CLI flag struct: each bool is an independent clap switch, not a state
// machine begging to be an enum.
#[allow(clippy::struct_excessive_bools)]
struct AddOpts {
    /// Stage every change in the worktree, including deletions of
    /// tracked files. Equivalent to `kit add .` plus deletion
    /// detection; takes no path arguments.
    #[arg(short = 'A', long)]
    all: bool,

    /// Restage only files already tracked in the index: update modified
    /// ones and record deletions, without adding untracked paths. Takes
    /// no path arguments.
    #[arg(short = 'u', long)]
    update: bool,

    /// Allow staging an explicitly-named path that is ignored by
    /// `.gitignore`/`.kitignore` (git refuses these without `-f`).
    #[arg(short = 'f', long)]
    force: bool,

    /// Interactively choose hunks to stage from each named file (like
    /// `git add -p`). Prompts per hunk: `y` stage, `n` skip, `a` stage
    /// the rest of the file, `d` skip the rest, `q` quit. Regular text
    /// files only: binary files are skipped (the command still succeeds),
    /// while symlinks and directories are refused. Requires explicit path
    /// arguments.
    #[arg(short = 'p', long)]
    patch: bool,

    /// Show what would be staged and change nothing: no index change and
    /// no object written. Takes neither `-p` nor `-u`.
    #[arg(short = 'n', long = "dry-run", conflicts_with_all = ["patch", "update"])]
    dry_run: bool,

    /// Paths to stage. Pass `.` to stage every non-ignored file under
    /// the current directory. Multiple paths may be given.
    paths: Vec<String>,
}

/// Asks on stdin which hunks to stage.
struct StdinChooser;

impl HunkChooser for StdinChooser {
    fn choose(&mut self, path: &str, hunks: &[PatchHunk]) -> std::io::Result<Choice> {
        let stdin = std::io::stdin();
        let (selected, quit) = select_hunks(path, hunks, &mut stdin.lock())?;
        Ok(Choice { selected, quit })
    }
}

/// Prints the notices of `-p` on stderr and the lines of `-n` on stdout.
struct AddNotices;

/// `<verb> '<path>'`, with the C-style quoting of `ls-files` for a path with
/// special bytes.
fn dry_run_line(verb: &str, path: &str) -> String {
    match super::c_quote_path(path) {
        Some(quoted) => format!("{verb} {quoted}"),
        None => format!("{verb} '{path}'"),
    }
}

impl Observer<Event> for AddNotices {
    fn event(&self, event: &Event) {
        match event {
            Event::BinarySkipped { path } => {
                eprintln!("{path}: binary file — skipped (use `kit add` to stage whole)");
            }
            Event::NoChanges { path } => eprintln!("{path}: no changes to stage"),
            Event::HunksStaged {
                path,
                selected,
                total,
            } => eprintln!("{path}: staged {selected} of {total} hunks"),
            Event::WouldAdd { path } => println!("{}", dry_run_line("add", path)),
            Event::WouldRemove { path } => println!("{}", dry_run_line("remove", path)),
            _ => {}
        }
    }
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_args::parse::<AddOpts>("kit add", args) {
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
    match super::with_store_config(|config| {
        add::stage(
            &layout,
            config,
            &cwd,
            &Request {
                all: opts.all,
                update: opts.update,
                patch: opts.patch,
                force: opts.force,
                dry_run: opts.dry_run,
                paths: &opts.paths,
            },
            &mut StdinChooser,
            &crate::progress::ServedWarning,
            &AddNotices,
        )
    }) {
        Ok(()) => exit::OK,
        Err(e) => super::fail(e),
    }
}

/// Prompt the user for each hunk and return the indices to stage plus
/// whether they asked to quit. Prompts and hunk rendering go to stderr
/// (human-facing); stdout stays clean.
fn select_hunks(
    path: &str,
    hunks: &[PatchHunk],
    input: &mut impl BufRead,
) -> std::io::Result<(Vec<usize>, bool)> {
    let mut stderr = std::io::stderr().lock();
    let mut selected = Vec::new();
    // `Some(true)` = stage all remaining (`a`), `Some(false)` = skip all
    // remaining (`d`).
    let mut auto: Option<bool> = None;
    let mut i = 0;
    while i < hunks.len() {
        if let Some(stage_rest) = auto {
            if stage_rest {
                selected.push(i);
            }
            i += 1;
            continue;
        }
        render_hunk(&mut stderr, path, i, hunks.len(), &hunks[i]);
        let _ = write!(stderr, "Stage this hunk [y,n,q,a,d,?]? ");
        let _ = stderr.flush();
        let mut line = String::new();
        let read = input.read_line(&mut line)?;
        if read == 0 {
            // EOF — treat as quit, staging whatever was chosen so far.
            return Ok((selected, true));
        }
        match line.trim().chars().next() {
            Some('y') => {
                selected.push(i);
                i += 1;
            }
            Some('n') => i += 1,
            Some('q') => return Ok((selected, true)),
            Some('a') => {
                selected.push(i);
                auto = Some(true);
                i += 1;
            }
            Some('d') => auto = Some(false),
            _ => {
                let _ = writeln!(
                    stderr,
                    "y - stage this hunk\nn - skip this hunk\nq - quit; stage selected hunks\na - stage this and all later hunks in the file\nd - skip this and all later hunks in the file\n? - print help"
                );
            }
        }
    }
    Ok((selected, false))
}

/// Render a hunk to `out` as a unified-diff fragment for display.
fn render_hunk(out: &mut impl Write, path: &str, idx: usize, total: usize, hunk: &PatchHunk) {
    let _ = writeln!(out, "--- {path} (hunk {}/{total}) ---", idx + 1);
    let _ = writeln!(
        out,
        "@@ -{} +{} @@",
        range_str(hunk.old_start, hunk.old_len),
        range_str(hunk.new_start, hunk.new_len)
    );
    for l in &hunk.lines {
        let prefix = match l.kind {
            HunkLineKind::Context => b' ',
            HunkLineKind::Added => b'+',
            HunkLineKind::Removed => b'-',
        };
        let mut buf = vec![prefix];
        buf.extend_from_slice(&l.text);
        buf.push(b'\n');
        let _ = out.write_all(&buf);
        if !l.has_newline {
            let _ = writeln!(out, "\\ No newline at end of file");
        }
    }
}

/// Format one side of an `@@` range: `start,len`, omitting `,len` when 1.
fn range_str(start: usize, len: usize) -> String {
    if len == 1 {
        start.to_string()
    } else {
        format!("{start},{len}")
    }
}

//! `kit status` — show working-tree changes relative to HEAD.
//!
//! ## Default (human) output
//!
//! ```text
//! on branch <name>           # to stderr  (or "detached HEAD at <hash>" / "no HEAD yet")
//!                            #
//! Changes to be committed:   # to stderr
//!   A  added.txt             # to stderr
//!   D  deleted.txt           # to stderr
//!
//! Changes not staged for commit:    # to stderr
//!   M  modified.txt                 # to stderr
//! ```
//!
//! Banners and section headers go to stderr; per-file lines also go to
//! stderr in default mode because they are formatted for humans.
//! Scripts should use `--porcelain` (see below) for stdout output
//! that is safe to parse.
//!
//! ## `--porcelain[=v1]` / `-s` (`--short`) output
//!
//! `-s`/`--short` is an alias for `--porcelain=v1`; both select the
//! same renderer. Compatible with `git status --porcelain` — one entry
//! per line,
//! two-character XY status code, space, path:
//!
//! ```text
//! M  modified-staged.txt
//!  M unstaged-edit.txt
//! A  newly-staged.txt
//! ?? untracked.txt
//! ```
//!
//! `X` is the staged-vs-HEAD state; `Y` is the worktree-vs-index
//! state. kit's `DiffKind::ModeChanged` renders as `T` (a non-git
//! extension). `??` is the conventional code for untracked files.
//!
//! Paths containing special bytes are C-style quoted (matching git's
//! default `core.quotePath`). With `-z`, records are NUL-terminated and
//! paths are emitted raw (unquoted) — the round-trip-safe form for paths
//! with newlines or other special bytes; `-z` implies porcelain.
//!
//! Empty stdout means "nothing to commit, working tree clean."
//!
//! ## `--porcelain=v2` output
//!
//! Selects git's richer per-path format. Each changed tracked path is a
//! `1` record:
//!
//! ```text
//! 1 <XY> <sub> <mH> <mI> <mW> <hH> <hI> <path>
//! ```
//!
//! where `XY` uses `.` (not space) for an unchanged column, `<sub>` is
//! always `N...` (kit is never a submodule), `<mH>/<mI>/<mW>` are the
//! octal file modes in HEAD / index / worktree, and `<hH>/<hI>` are the
//! HEAD and index object ids (full 64-hex BLAKE3; git's are 40-hex
//! SHA-1, so the differential harness masks length). Untracked paths are
//! `? <path>` records, and a rename emits a `2` record (`R100`, exact
//! content). There are no `--branch` header lines. Path quoting and `-z`
//! semantics match the v1 renderer.
//!
//! The logic is in [`libkit::status`]. This module parses the arguments and
//! prints.

use std::io::Write;

use clap::{Parser, ValueEnum};
use kit_core::layout::RepoLayout;
use kit_core::ops::{DiffKind, StatusEntry, StatusStaging};
use kit_core::refs;
use libkit::status::{self, Detail, Record};

use crate::clap_args;
use crate::exit;
use crate::format;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum PorcelainVersion {
    V1,
    V2,
}

#[derive(Debug, Parser)]
#[command(
    name = "kit status",
    about = "Show working-tree changes relative to HEAD."
)]
struct StatusOpts {
    /// Emit machine-readable XY-code-plus-path on stdout. Default
    /// `v1` matches `git status --porcelain=v1`.
    #[arg(long, value_name = "VERSION", num_args = 0..=1, default_missing_value = "v1")]
    porcelain: Option<PorcelainVersion>,

    /// Short format. Alias for `--porcelain=v1`: emits the same
    /// XY-code-plus-path lines on stdout.
    #[arg(short = 's', long = "short")]
    short: bool,

    /// NUL-terminate entries instead of newline, and emit raw (unquoted)
    /// paths — like `git status -z`. Implies porcelain output. Without
    /// `-z`, paths with special bytes are C-style quoted.
    #[arg(short = 'z')]
    z: bool,

    /// Turn off rename detection (on by default, like git). A move then
    /// reports as a separate deletion and addition.
    #[arg(long = "no-renames")]
    no_renames: bool,

    /// Detect renames, optionally with a similarity threshold. Accepted
    /// for git familiarity; kit pairs by identical content (exact, 100%),
    /// so any threshold ≤ 100 selects the same exact matches.
    #[arg(long = "find-renames", value_name = "N", num_args = 0..=1, require_equals = true)]
    find_renames: Option<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_args::parse::<StatusOpts>("kit status", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    // `-s`/`--short` is an alias for `--porcelain=v1`; `-z` also implies
    // porcelain output. All select the line-oriented XY renderer on stdout.
    let porcelain = opts.porcelain.is_some() || opts.short || opts.z;

    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return super::error(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let layout = match super::resolve_layout(&cwd) {
        Ok(layout) => layout,
        Err(code) => return code,
    };

    let report = match status::compute(
        &layout,
        &cwd,
        &status::Request {
            renames: !opts.no_renames,
            rename_threshold: opts.find_renames.as_deref(),
        },
        &crate::progress::ServedWarning,
    ) {
        Ok(report) => report,
        Err(e) => return super::fail(e),
    };

    if porcelain {
        if opts.porcelain == Some(PorcelainVersion::V2) {
            render_porcelain_v2(&layout, &report, opts.z)
        } else {
            render_porcelain(&report.entries, opts.z)
        }
    } else {
        render_human(&layout, &report.entries)
    }
}

/// `--porcelain[=v1]` output — XY-code-plus-path, one entry per record.
/// Empty stdout means clean. Matches `git status --porcelain` for the
/// codes kit and git share; `T ` (`ModeChanged`) is the only non-git
/// extension.
///
/// With `z = false` (default), records are newline-terminated and a path
/// containing special bytes is C-style quoted (matching git's default
/// `core.quotePath`). With `z = true` (`-z`), records are NUL-terminated
/// and paths are emitted **raw** (unquoted) — the round-trip-safe form
/// for paths that contain newlines or other special bytes.
fn render_porcelain(entries: &[StatusEntry], z: bool) -> u8 {
    let disp = |p: &str| super::c_quote_path(p).unwrap_or_else(|| p.to_string());
    let mut stdout = std::io::stdout().lock();
    for Record { xy, path, old_path } in status::records(entries) {
        // `xy` is two ASCII status columns by construction.
        let code = std::str::from_utf8(&xy).unwrap_or("??");
        match old_path {
            // Rename: git renders `old -> new` by default, and `new\0old\0`
            // under `-z` (destination first — verified against git).
            Some(old) if z => {
                let _ = write!(stdout, "{code} {path}\0{old}\0");
            }
            Some(old) => {
                let _ = writeln!(stdout, "{code} {} -> {}", disp(old), disp(path));
            }
            None if z => {
                let _ = write!(stdout, "{code} {path}\0");
            }
            None => {
                let _ = writeln!(stdout, "{code} {}", disp(path));
            }
        }
    }
    exit::OK
}

/// `--porcelain=v2` output — git's richer per-path format. Each changed
/// tracked path is a `1 <XY> <sub> <mH> <mI> <mW> <hH> <hI> <path>` line, a
/// rename is a `2 … <Xscore> <new>\t<old>` line (kit pairs exact-content
/// moves, so the score is always `R100`), and (kit having no submodules)
/// `<sub>` is always `N...`; untracked paths are `? <path>`.
///
/// `<XY>` uses `.` for an unchanged column (vs v1's space). `<mH>`/`<mI>` are
/// the HEAD/index octal modes, `<mW>` the worktree mode (`000000` when the
/// side is absent); `<hH>`/`<hI>` are the HEAD/index object ids (full 64-hex
/// BLAKE3 — longer than git's SHA-1, the documented hash-length divergence).
/// Without `--branch` there are no header lines, matching git.
fn render_porcelain_v2(layout: &RepoLayout, report: &status::Report, z: bool) -> u8 {
    let detail = match Detail::load(layout, report.head_tree.as_ref()) {
        Ok(detail) => detail,
        Err(e) => return super::fail(e),
    };

    let mut stdout = std::io::stdout().lock();
    for record in status::records(&report.entries) {
        if record.xy == *b"??" {
            emit_v2_record(&mut stdout, "? ", record.path, z);
            continue;
        }
        // v2 uses `.` for an unchanged column, not a space.
        let x = if record.xy[0] == b' ' {
            '.'
        } else {
            record.xy[0] as char
        };
        let y = if record.xy[1] == b' ' {
            '.'
        } else {
            record.xy[1] as char
        };
        let d = detail.of(&record);
        let (m_head, m_index, m_work) = (d.head_mode, d.index_mode, d.worktree_mode);
        let (h_head, h_index) = (
            format::hex_hash(&d.head_hash),
            format::hex_hash(&d.index_hash),
        );
        if let Some(old) = record.old_path {
            // `2` rename record. The HEAD side (mH/hH) describes the SOURCE
            // path; the index side (mI/hI) the DESTINATION. Exact content
            // means hH == hI and the score is `R100`. Verified vs git.
            let prefix =
                format!("2 {x}{y} N... {m_head} {m_index} {m_work} {h_head} {h_index} R100 ");
            emit_v2_rename_record(&mut stdout, &prefix, record.path, old, z);
            continue;
        }
        let prefix = format!("1 {x}{y} N... {m_head} {m_index} {m_work} {h_head} {h_index} ");
        emit_v2_record(&mut stdout, &prefix, record.path, z);
    }
    exit::OK
}

/// Write a v2 `2` rename record: `<prefix><dest><sep><src>` where `<sep>`
/// is a TAB by default and NUL under `-z` (destination first, then the
/// source — matching git). Paths are C-quoted when not in `-z` mode.
fn emit_v2_rename_record(out: &mut impl Write, prefix: &str, new: &str, old: &str, z: bool) {
    if z {
        let _ = write!(out, "{prefix}{new}\0{old}\0");
    } else {
        let nq = super::c_quote_path(new).unwrap_or_else(|| new.to_string());
        let oq = super::c_quote_path(old).unwrap_or_else(|| old.to_string());
        let _ = writeln!(out, "{prefix}{nq}\t{oq}");
    }
}

/// Write one v2 record: `<prefix><path>` with git's quoting/termination —
/// raw + NUL under `-z`, else C-style quoted + newline.
fn emit_v2_record(out: &mut impl Write, prefix: &str, path: &str, z: bool) {
    if z {
        let _ = write!(out, "{prefix}{path}\0");
    } else if let Some(quoted) = super::c_quote_path(path) {
        let _ = writeln!(out, "{prefix}{quoted}");
    } else {
        let _ = writeln!(out, "{prefix}{path}");
    }
}

/// Default human output, git-shaped. All lines go to stderr — stdout is
/// reserved for porcelain/data callers (a kit convention; documented in
/// docs/CLI.md). A consumer that wants the human format in a pipeline can
/// `kit status 2>&1` explicitly; the default pipeline behaviour stays
/// empty-on-clean. The (use "kit …") hints name kit commands, not git.
fn render_human(layout: &RepoLayout, entries: &[StatusEntry]) -> u8 {
    let mut stderr = std::io::stderr().lock();

    // Branch / HEAD line, matching git's banners.
    match status::head_state(layout) {
        Some(status::HeadState {
            head: refs::Head::Branch(name),
            unborn,
        }) => {
            let _ = writeln!(stderr, "On branch {name}");
            if unborn {
                let _ = writeln!(stderr, "\nNo commits yet");
            }
        }
        Some(status::HeadState {
            head: refs::Head::Detached(h),
            ..
        }) => {
            let _ = writeln!(
                stderr,
                "HEAD detached at {}",
                crate::format::short_hash(&h, crate::format::SUMMARY_ABBREV)
            );
        }
        None => {
            let _ = writeln!(stderr, "On branch main\n\nNo commits yet");
        }
    }

    if entries.is_empty() {
        let _ = writeln!(stderr, "\nnothing to commit, working tree clean");
        return exit::OK;
    }

    // An untracked path is an unstaged addition (porcelain `??`); git lists
    // those in their own section, separate from tracked-but-unstaged edits.
    let staged: Vec<_> = entries
        .iter()
        .filter(|e| e.staging == StatusStaging::Staged)
        .collect();
    let unstaged: Vec<_> = entries
        .iter()
        .filter(|e| e.staging == StatusStaging::Unstaged && e.diff.kind != DiffKind::Added)
        .collect();
    let untracked: Vec<_> = entries
        .iter()
        .filter(|e| e.staging == StatusStaging::Unstaged && e.diff.kind == DiffKind::Added)
        .collect();

    if !staged.is_empty() {
        let _ = writeln!(stderr, "\nChanges to be committed:");
        let _ = writeln!(
            stderr,
            "  (use \"kit restore --staged <file>...\" to unstage)"
        );
        for e in &staged {
            let _ = writeln!(stderr, "	{:<12}{}", human_label(e.diff.kind), human_path(e));
        }
    }
    if !unstaged.is_empty() {
        let _ = writeln!(stderr, "\nChanges not staged for commit:");
        let _ = writeln!(
            stderr,
            "  (use \"kit add <file>...\" to update what will be committed)"
        );
        let _ = writeln!(
            stderr,
            "  (use \"kit restore <file>...\" to discard changes in working directory)"
        );
        for e in &unstaged {
            let _ = writeln!(stderr, "	{:<12}{}", human_label(e.diff.kind), human_path(e));
        }
    }
    if !untracked.is_empty() {
        let _ = writeln!(stderr, "\nUntracked files:");
        let _ = writeln!(
            stderr,
            "  (use \"kit add <file>...\" to include in what will be committed)"
        );
        for e in &untracked {
            let _ = writeln!(stderr, "\t{}", e.diff.path);
        }
    }

    // Footer guidance, like git's.
    if staged.is_empty() {
        if !unstaged.is_empty() {
            let _ = writeln!(
                stderr,
                "\nno changes added to commit (use \"kit add\" and/or \"kit commit -a\")"
            );
        } else if !untracked.is_empty() {
            let _ = writeln!(
                stderr,
                "\nnothing added to commit but untracked files present (use \"kit add\" to track)"
            );
        }
    }

    exit::OK
}

/// git's word label for a change kind.
fn human_label(kind: DiffKind) -> &'static str {
    match kind {
        DiffKind::Added => "new file:",
        DiffKind::Removed => "deleted:",
        DiffKind::Modified => "modified:",
        DiffKind::ModeChanged => "typechange:",
        DiffKind::Renamed => "renamed:",
    }
}

/// The path column for the human listing. A rename renders `old -> new`
/// (git's form); every other kind is just its path.
fn human_path(e: &StatusEntry) -> String {
    match (e.diff.kind, &e.diff.old_path) {
        (DiffKind::Renamed, Some(old)) => format!("{old} -> {}", e.diff.path),
        _ => e.diff.path.clone(),
    }
}

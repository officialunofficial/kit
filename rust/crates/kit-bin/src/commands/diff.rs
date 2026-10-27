//! `kit diff` — show changes as a unified patch.
//!
//! Modes:
//!
//! - no args — HEAD tree vs a fresh worktree snapshot;
//! - `--staged` / `--cached` — HEAD tree vs the staged index tree
//!   (what `kit commit` would record);
//! - one revision (`<rev>`) — that revision's tree vs the worktree (or
//!   vs the staged index with `--staged`);
//! - two revisions (`<a> <b>`) or a range (`<a>..<b>`) — diff the two
//!   resolved trees against each other.
//!
//! A leading positional that is not a resolvable revision is treated as
//! the start of the pathspec list; a leading positional that *looks*
//! like a revision (ref / commit / range) but fails to resolve is a
//! hard error rather than a silent empty diff.
//!
//! Trailing positional paths (pathspecs) filter the output to entries
//! at or below those paths. The default output is a Git-compatible
//! unified diff: a git-shaped `diff --git a/<p> b/<p>` header per changed
//! path (with `new file mode`/`deleted file mode`/`index`/`--- a/p`/`+++ b/p`
//! lines, `/dev/null` for adds/deletes) followed by Myers-diff hunks (or a
//! `Binary files … differ` line). The `index` ids are abbreviated BLAKE3
//! prefixes — the one inherent divergence from `git diff`.
//!
//! `--name-only` / `--name-status` switch to summary output: one record
//! per changed path — just the path, or an `A`/`D`/`M` status letter
//! (`T` for a kit mode change) plus the path. Special-byte paths are
//! C-style quoted (git `core.quotePath`); `-z` instead NUL-terminates
//! records and emits raw paths (and, for `--name-status`, NUL-terminates
//! the status letter and path as separate fields).
//!
//! `-w`/`--ignore-all-space` and `-b`/`--ignore-space-change` change
//! which lines the hunk generator treats as equal (`-w` wins if both are
//! given); `-U<n>`/`--unified=<n>` sets the number of unchanged context
//! lines around each hunk (default 3). Neither affects the bytes of a
//! line that does render — only which lines end up part of a hunk.

use std::io::Write;

use clap::Parser;
use kit_core::hash::Hash;
use kit_core::object::EntryMode;
use kit_core::ops::{DEFAULT_CONTEXT_LINES, DiffEntry, DiffKind, WhitespaceMode};
use libkit::diff::{self, PatchBody};

use crate::clap_args;
use crate::exit;
use crate::exit_map;
use crate::format;

mod stat;
pub(super) use stat::render_stat;

#[derive(Debug, Parser)]
#[command(
    name = "kit diff",
    about = "Show changes as a unified patch (HEAD vs worktree, --staged, or two trees)."
)]
#[allow(clippy::struct_excessive_bools)] // clap option flags, not a state machine
struct DiffOpts {
    /// Diff the staged index tree against HEAD (the change `kit commit`
    /// would record) instead of HEAD vs worktree.
    #[arg(long, visible_alias = "cached")]
    staged: bool,

    /// Show only the names of changed files, one per line, instead of a
    /// patch (like `git diff --name-only`).
    #[arg(long, conflicts_with = "name_status")]
    name_only: bool,

    /// Show a status letter (`A`/`D`/`M`; `T` for a kit mode change)
    /// and the name of each changed file (like `git diff --name-status`).
    #[arg(long)]
    name_status: bool,

    /// Show a diffstat: per-file changed-line counts and a `+`/`-` graph,
    /// plus a summary line (like `git diff --stat`). Honors `COLUMNS`
    /// (default 80) for the graph width.
    #[arg(long, conflicts_with_all = ["name_only", "name_status"])]
    stat: bool,

    /// Diff against the merge base of the revisions, like `git diff
    /// --merge-base`. With one revision: `merge-base(<rev>, HEAD)` vs the
    /// worktree. With two: `merge-base(<a>, <b>)` vs `<b>`. (Equivalent to
    /// the `<a>...<b>` symmetric range, but spelled as a flag.)
    #[arg(long = "merge-base", conflicts_with = "staged")]
    merge_base: bool,

    /// NUL-terminate `--name-only` / `--name-status` records and emit raw
    /// (unquoted) paths — like `git diff -z`. In `--name-status`, the
    /// status letter and path are each NUL-terminated. Only valid with
    /// `--name-only` / `--name-status`.
    #[arg(short = 'z')]
    z: bool,

    /// Exit with 1 when there are differences, 0 when there are none (the
    /// patch is still printed) — like `git diff --exit-code`. The CI
    /// idiom for "fail if the tree changed".
    #[arg(long = "exit-code")]
    exit_code: bool,

    /// Like `--exit-code` but print nothing (`git diff --quiet`).
    #[arg(long)]
    quiet: bool,

    /// Turn off rename detection (on by default, like git). A move then
    /// shows as a separate deletion and addition.
    #[arg(long = "no-renames")]
    no_renames: bool,

    /// Detect renames, optionally with a similarity threshold (`-M`,
    /// `--find-renames[=N]`). kit pairs by identical content (exact,
    /// 100%), so any threshold ≤ 100 selects the same matches.
    #[arg(short = 'M', long = "find-renames", value_name = "N", num_args = 0..=1, default_missing_value = "100")]
    find_renames: Option<String>,

    /// Colorize the patch: `always`, `auto` (default, tty-only), or
    /// `never` (like `git diff --color[=<when>]`). Honors `NO_COLOR` /
    /// `CLICOLOR_FORCE` under `auto`.
    #[arg(long = "color", value_name = "WHEN", num_args = 0..=1, require_equals = true, default_missing_value = "always", conflicts_with = "no_color")]
    color: Option<String>,

    /// Disable colorized output (`git diff --no-color`).
    #[arg(long = "no-color")]
    no_color: bool,

    /// Ignore whitespace when comparing lines — like git's `-w` /
    /// `--ignore-all-space`. A line that differs from its counterpart only
    /// in whitespace is treated as unchanged context; the printed line
    /// still shows its own real (unmodified) bytes. Takes precedence over
    /// `-b` when both are given.
    #[arg(short = 'w', long = "ignore-all-space")]
    ignore_all_space: bool,

    /// Ignore changes in the *amount* of whitespace — like git's `-b` /
    /// `--ignore-space-change`. Runs of whitespace compare equal
    /// regardless of length, but a line with whitespace where the other
    /// side has none still differs (unlike `-w`).
    #[arg(short = 'b', long = "ignore-space-change")]
    ignore_space_change: bool,

    /// Number of unchanged context lines shown around each hunk (default
    /// 3) — like git's `-U<n>` / `--unified=<n>`.
    #[arg(short = 'U', long = "unified", value_name = "N")]
    unified: Option<usize>,

    /// Optional revisions (refs, full/short hashes, `HEAD~n`, or an
    /// `A..B` range) followed by optional pathspecs to limit the
    /// output. With no revisions, diffs HEAD vs worktree (or HEAD vs
    /// index with --staged). A leading argument that is not a resolvable
    /// revision starts the pathspec list.
    args: Vec<String>,
}

impl DiffOpts {
    /// Resolve `-w`/`-b` into the single [`WhitespaceMode`] the hunk
    /// renderer consumes. `-w` wins when both are given, matching git
    /// (the more aggressive mode takes precedence rather than erroring).
    fn whitespace_mode(&self) -> WhitespaceMode {
        if self.ignore_all_space {
            WhitespaceMode::IgnoreAllSpace
        } else if self.ignore_space_change {
            WhitespaceMode::IgnoreSpaceChange
        } else {
            WhitespaceMode::Exact
        }
    }
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_args::parse::<DiffOpts>("kit diff", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    // `-z` only governs the `--name-only` / `--name-status` record
    // framing (per the parity matrix); it has no defined meaning for the
    // unified-patch output yet, so reject it rather than silently ignore.
    if opts.z && !(opts.name_only || opts.name_status) {
        return emit_err(
            "`-z` is only valid with `--name-only` or `--name-status`",
            exit::USAGE,
        );
    }
    let Some(color_choice) = crate::term::ColorChoice::parse(opts.color.as_deref()) else {
        return emit_err("--color expects always, auto, or never", exit::USAGE);
    };
    let use_color = !opts.no_color
        && color_choice.resolve(std::io::IsTerminal::is_terminal(&std::io::stdout()));
    let ws_mode = opts.whitespace_mode();
    let context = opts.unified.unwrap_or(DEFAULT_CONTEXT_LINES);
    // A provided rename threshold must parse. The exact matcher ignores its
    // magnitude.
    if let Some(t) = &opts.find_renames {
        let n = t.trim_end_matches('%');
        if !n.is_empty() && n.parse::<u8>().is_err() {
            return emit_err(&format!("invalid --find-renames value: {t}"), exit::USAGE);
        }
    }
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let repo = match super::open_repo(&cwd) {
        Ok(repo) => repo,
        Err(code) => return code,
    };

    // Rename detection is on by default, like git's `diff.renames`. It
    // collapses identical-content delete/add pairs into `R` entries before
    // the path filter and the rendering.
    let request = diff::Request {
        staged: opts.staged,
        merge_base: opts.merge_base,
        renames: !opts.no_renames,
        args: &opts.args,
    };
    let diff = match diff::compute(&repo, &request) {
        Ok(diff) => diff,
        Err(e) => return fail(e),
    };
    let selected = diff.entries();

    // `--exit-code`/`--quiet` report difference via the exit status (1 =
    // changed, 0 = clean). `--quiet` additionally suppresses output.
    let report_exit = opts.exit_code || opts.quiet;
    let diff_status = if report_exit && !selected.is_empty() {
        exit::GENERAL_ERROR
    } else {
        exit::OK
    };
    if opts.quiet {
        return diff_status;
    }

    let mut stdout = std::io::stdout().lock();
    if opts.stat {
        return match diff.stats() {
            Ok(rows) => match render_stat(&mut stdout, &rows) {
                Ok(()) => diff_status,
                Err(msg) => emit_err(&msg, exit::GENERAL_ERROR),
            },
            Err(e) => fail(e),
        };
    }
    for e in selected {
        let res = if opts.name_only || opts.name_status {
            emit_entry_name(&mut stdout, e, opts.name_status, opts.z);
            Ok(())
        } else if use_color {
            // Render the entry to a buffer, then colorize line-by-line so
            // the byte-exact patch machinery stays color-agnostic.
            let mut buf: Vec<u8> = Vec::new();
            match emit_entry_patch(&mut buf, e, || diff.patch_body(e, context, ws_mode)) {
                // Colorize on RAW BYTES (not via from_utf8_lossy) so a
                // non-UTF-8 patch body round-trips byte-for-byte, matching
                // the uncolored path.
                Ok(()) => stdout
                    .write_all(&colorize_patch(&buf))
                    .map_err(|err| format!("write: {err}")),
                Err(msg) => Err(msg),
            }
        } else {
            emit_entry_patch(&mut stdout, e, || diff.patch_body(e, context, ws_mode))
        };
        if let Err(msg) = res {
            return emit_err(&msg, exit::GENERAL_ERROR);
        }
    }
    diff_status
}

/// Print a library failure and return its exit code.
fn fail(error: diff::Error) -> u8 {
    let error = libkit::Error::from(error);
    emit_err(&exit_map::message(&error), exit_map::exit_code(&error))
}

/// ANSI-colorize a unified-diff patch line-by-line, matching git's default
/// palette: metadata bold, hunk headers cyan, additions green, deletions
/// red. Context lines are left uncolored. Operates on raw bytes so a
/// non-UTF-8 patch body round-trips unchanged (only ASCII line prefixes
/// drive the coloring).
fn colorize_patch(text: &[u8]) -> Vec<u8> {
    const RESET: &[u8] = b"\x1b[0m";
    let mut out: Vec<u8> = Vec::with_capacity(text.len() + 64);
    for line in text.split_inclusive(|&b| b == b'\n') {
        let (body, nl): (&[u8], &[u8]) = if line.last() == Some(&b'\n') {
            (&line[..line.len() - 1], b"\n")
        } else {
            (line, b"")
        };
        let code: Option<&[u8]> = if body.starts_with(b"@@") {
            Some(b"\x1b[36m") // hunk header: cyan
        } else if body.starts_with(b"diff ")
            || body.starts_with(b"index ")
            || body.starts_with(b"new file")
            || body.starts_with(b"deleted file")
            || body.starts_with(b"old mode")
            || body.starts_with(b"new mode")
            || body.starts_with(b"rename ")
            || body.starts_with(b"similarity ")
            || body.starts_with(b"--- ")
            || body.starts_with(b"+++ ")
        {
            Some(b"\x1b[1m") // metadata: bold
        } else if body.first() == Some(&b'+') {
            Some(b"\x1b[32m") // addition: green
        } else if body.first() == Some(&b'-') {
            Some(b"\x1b[31m") // deletion: red
        } else {
            None
        };
        match code {
            Some(c) => {
                out.extend_from_slice(c);
                out.extend_from_slice(body);
                out.extend_from_slice(RESET);
                out.extend_from_slice(nl);
            }
            None => out.extend_from_slice(line),
        }
    }
    out
}

/// Display name for stat/summary rows: C-style quoted like git's default
/// `core.quotePath` when the path has special bytes, else the raw path.
fn c_quote_name(path: &str) -> String {
    super::c_quote_path(path).unwrap_or_else(|| path.to_string())
}

/// Status letter for `--name-status`. kit's `ModeChanged` maps to `T`
/// (git's type-change letter) — a documented kit extension, since kit
/// tracks a pure mode flip as its own diff kind.
fn name_status_letter(kind: DiffKind) -> char {
    match kind {
        DiffKind::Added => 'A',
        DiffKind::Removed => 'D',
        DiffKind::Modified => 'M',
        DiffKind::ModeChanged => 'T',
        // Renames carry a similarity score (`R100`) and two paths, so
        // `--name-status` formats them specially in `emit_entry_name`;
        // this bare letter is the fallback / name-only case.
        DiffKind::Renamed => 'R',
    }
}

/// Emit one `--name-only` / `--name-status` record for a changed entry.
///
/// Newline mode: `<path>\n` (name-only) or `<letter>\t<path>\n`
/// (name-status); a path with special bytes is C-style quoted like git's
/// default `core.quotePath`. `-z` mode: paths are raw (unquoted) and
/// records are NUL-terminated — `<path>\0`, or `<letter>\0<path>\0` where
/// the status letter and path are each their own NUL-terminated field
/// (matching `git diff --name-status -z`).
fn emit_entry_name(out: &mut impl Write, e: &DiffEntry, name_status: bool, z: bool) {
    // `--name-status` rename: git emits `R100<sep><src><sep><dst>` (source
    // first, unlike status's porcelain `-z`), TAB-separated by default and
    // NUL-separated under `-z`. Verified against git.
    if name_status && e.kind == DiffKind::Renamed {
        let src = e.old_path.as_deref().unwrap_or(&e.path);
        if z {
            let _ = write!(out, "R100\0{src}\0{}\0", e.path);
        } else {
            let sq = super::c_quote_path(src).unwrap_or_else(|| src.to_string());
            let dq = super::c_quote_path(&e.path).unwrap_or_else(|| e.path.clone());
            let _ = writeln!(out, "R100\t{sq}\t{dq}");
        }
        return;
    }
    if z {
        if name_status {
            let _ = write!(out, "{}\0", name_status_letter(e.kind));
        }
        let _ = write!(out, "{}\0", e.path);
        return;
    }
    let path = super::c_quote_path(&e.path);
    let shown = path.as_deref().unwrap_or(&e.path);
    if name_status {
        let _ = writeln!(out, "{}\t{shown}", name_status_letter(e.kind));
    } else {
        let _ = writeln!(out, "{shown}");
    }
}

/// Abbreviated all-zero blob id git prints for an absent side of `index`.
const ZERO_ABBREV: &str = "0000000";

/// git octal mode string for a [`DiffEntry`] side (`None` → regular file).
fn git_octal(mode: Option<EntryMode>) -> &'static str {
    match mode {
        Some(EntryMode::Executable) => "100755",
        Some(EntryMode::Symlink) => "120000",
        Some(EntryMode::Tree) => "040000",
        _ => "100644",
    }
}

/// Abbreviated blob id for an `index` line side (`None` → all-zero).
fn abbrev(h: Option<Hash>) -> String {
    h.map_or_else(|| ZERO_ABBREV.to_string(), |h| format::short_hash(&h, 7))
}

/// Emit a git-shaped `diff --git` header plus unified-diff hunks for one
/// changed entry. The `index <old>..<new>` ids are abbreviated BLAKE3
/// prefixes (longer than git's SHA-1 prefixes for the same `core.abbrev`),
/// the one inherent divergence; everything else matches `git diff`.
///
/// Shared with `kit show` and `format-patch`, so a commit's diff body is
/// byte-identical to `kit diff <parent> <commit>` when both use the default
/// context and the exact comparison (git's `-U3`).
///
/// `read_body` supplies the patch body after the header lines are written.
/// The caller picks the context, the whitespace mode and the read source
/// that it passes to the library.
pub(super) fn emit_entry_patch(
    out: &mut impl Write,
    e: &DiffEntry,
    read_body: impl FnOnce() -> Result<PatchBody, diff::Error>,
) -> Result<(), String> {
    // git C-style quotes special-byte paths in the header (core.quotePath),
    // quoting the whole `a/<path>` / `b/<path>` token as a unit. For a
    // rename the `a/` side is the source path, the `b/` side the dest.
    let a_src = if e.kind == DiffKind::Renamed {
        e.old_path.as_deref().unwrap_or(&e.path)
    } else {
        e.path.as_str()
    };
    let a_path = quoted_side('a', a_src);
    let b_path = quoted_side('b', &e.path);
    let _ = writeln!(out, "diff --git {a_path} {b_path}");

    match e.kind {
        DiffKind::Renamed => {
            // Exact rename: identical content, so 100% similar and no hunk.
            let from = super::c_quote_path(a_src).unwrap_or_else(|| a_src.to_string());
            let to = super::c_quote_path(&e.path).unwrap_or_else(|| e.path.clone());
            let _ = writeln!(out, "similarity index 100%");
            let _ = writeln!(out, "rename from {from}");
            let _ = writeln!(out, "rename to {to}");
            return Ok(());
        }
        DiffKind::ModeChanged => {
            // Identical content, mode flip — only the mode lines, no hunks.
            let _ = writeln!(out, "old mode {}", git_octal(e.old_mode));
            let _ = writeln!(out, "new mode {}", git_octal(e.new_mode));
            return Ok(());
        }
        DiffKind::Added => {
            let _ = writeln!(out, "new file mode {}", git_octal(e.new_mode));
            let _ = writeln!(out, "index {}..{}", ZERO_ABBREV, abbrev(e.new_hash));
        }
        DiffKind::Removed => {
            let _ = writeln!(out, "deleted file mode {}", git_octal(e.old_mode));
            let _ = writeln!(out, "index {}..{}", abbrev(e.old_hash), ZERO_ABBREV);
        }
        DiffKind::Modified if e.old_mode != e.new_mode => {
            // Content and mode both changed: mode lines, index without mode.
            let _ = writeln!(out, "old mode {}", git_octal(e.old_mode));
            let _ = writeln!(out, "new mode {}", git_octal(e.new_mode));
            let _ = writeln!(out, "index {}..{}", abbrev(e.old_hash), abbrev(e.new_hash));
        }
        DiffKind::Modified => {
            let _ = writeln!(
                out,
                "index {}..{} {}",
                abbrev(e.old_hash),
                abbrev(e.new_hash),
                git_octal(e.new_mode)
            );
        }
    }

    let body = read_body().map_err(|err| err.to_string())?;
    // `--- a/p` / `+++ b/p` (quoted), with `/dev/null` for the absent side.
    let (minus, plus) = match e.kind {
        DiffKind::Added => ("/dev/null".to_string(), b_path.clone()),
        DiffKind::Removed => (a_path.clone(), "/dev/null".to_string()),
        _ => (a_path.clone(), b_path.clone()),
    };
    match body {
        PatchBody::Binary => {
            let _ = writeln!(out, "Binary files {minus} and {plus} differ");
        }
        PatchBody::Empty => {}
        PatchBody::Hunks(hunks) => {
            let _ = writeln!(out, "--- {minus}");
            let _ = writeln!(out, "+++ {plus}");
            let _ = out.write_all(&hunks);
        }
    }
    Ok(())
}

/// The git-quoted `a/<path>` / `b/<path>` token for a patch header: C-style
/// quoted (with surrounding quotes) when the path has special bytes, else the
/// plain `<side>/<path>`.
fn quoted_side(side: char, path: &str) -> String {
    let s = format!("{side}/{path}");
    super::c_quote_path(&s).unwrap_or(s)
}

use super::error as emit_err;

#[cfg(test)]
mod tests {
    use super::*;

    fn de(path: &str, kind: DiffKind) -> DiffEntry {
        DiffEntry {
            path: path.to_string(),
            kind,
            old_hash: None,
            new_hash: None,
            old_mode: None,
            new_mode: None,
            old_path: None,
        }
    }

    fn render(e: &DiffEntry, name_status: bool, z: bool) -> String {
        let mut buf = Vec::new();
        emit_entry_name(&mut buf, e, name_status, z);
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn name_status_letters_cover_every_kind() {
        assert_eq!(name_status_letter(DiffKind::Added), 'A');
        assert_eq!(name_status_letter(DiffKind::Removed), 'D');
        assert_eq!(name_status_letter(DiffKind::Modified), 'M');
        assert_eq!(name_status_letter(DiffKind::ModeChanged), 'T');
    }
    #[test]
    fn name_only_newline_plain_path() {
        assert_eq!(
            render(&de("a.txt", DiffKind::Modified), false, false),
            "a.txt\n"
        );
    }

    #[test]
    fn name_status_newline_is_letter_tab_path() {
        assert_eq!(
            render(&de("a.txt", DiffKind::Added), true, false),
            "A\ta.txt\n"
        );
    }

    #[test]
    fn name_only_quotes_special_path_in_newline_mode() {
        // A tab is C-style quoted like git core.quotePath.
        assert_eq!(
            render(&de("a\tb.txt", DiffKind::Modified), false, false),
            "\"a\\tb.txt\"\n"
        );
    }

    #[test]
    fn z_mode_is_raw_and_nul_terminated() {
        // name-only -z: `<path>\0`, path emitted raw (unquoted).
        assert_eq!(
            render(&de("a\tb.txt", DiffKind::Modified), false, true),
            "a\tb.txt\0"
        );
        // name-status -z: `<letter>\0<path>\0` — two NUL-terminated fields.
        assert_eq!(
            render(&de("del.txt", DiffKind::Removed), true, true),
            "D\0del.txt\0"
        );
    }
}

//! `kit blame [-w] [-M] [-C] [--ignore-rev <rev>] [--ignore-revs-file <file>]
//! [--ignore-rev-precise] [--first-parent] [--reverse] [<rev>] [-L <range>]
//! <file>` — line-level attribution.
//!
//! Blames `<file>` as of `<rev>` (default `HEAD`), optionally restricted
//! to a line range with `-L`. `-w` ignores whitespace when matching
//! lines across revisions (git `-w`); `-M`/`-C` detect lines moved within
//! the file / copied from other files (git `-M`/`-C`); `--ignore-rev` /
//! `--ignore-revs-file` skip "noise" commits during attribution (git
//! `--ignore-rev`), falling through to the commit that previously changed
//! each line. `--ignore-rev-precise` (kit-only; requires `--ignore-rev`/
//! `--ignore-revs-file`) refines that fall-through with content matching
//! instead of git's positional per-hunk guess — a documented divergence,
//! opt-in only. Blame is merge-aware by default (a line merged from a side
//! branch is credited to the commit that wrote it); `--first-parent`
//! restricts the walk to first parents (git `--first-parent`).
//! `--reverse <start>..<end>` instead walks history forward, attributing
//! each line of the `<start>` version to the last commit in the range in
//! which it still existed (git `--reverse`).
//!
//! Output modes:
//!
//! - default — `<short12>\t<line_num>\t<text>\n` per line, pinned by
//!   the integration test in `tests/cli_wire.rs:233-243`.
//! - `--format=json` — JSONL, one self-contained record per line with
//!   keys `hash`, `line_num`, `author`, `timestamp`, `text`. Schema
//!   diverges from the tab format because kit's author is an
//!   Identity, not a `Name <email>` string — see commands/log.rs for
//!   the same divergence.
//!
//! Line numbers in the output are always the file's own 1-based numbers,
//! so a `-L 40,60` slice still prints `40..=60`, matching `git blame -L`.

use std::collections::{HashMap, HashSet};
use std::io::Write;

use clap::{Parser, ValueEnum};
use kit_core::hash::Hash;
use kit_core::ops::blame::format_blame_text;
use kit_core::store::ObjectStore;

use crate::clap_args;
use crate::exit;
use crate::exit_map;
use crate::format;
use libkit::blame::{self, BlameResult, CopyDetection, MoveDetection};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum BlameFormat {
    Default,
    Json,
}

#[derive(Debug, Parser)]
#[command(
    name = "kit blame",
    about = "Show line-level commit attribution.",
    override_usage = "kit blame [OPTIONS] [<rev>] [--] <file>"
)]
// A CLI flag struct: each bool is an independent `git blame` toggle, so the
// "too many bools" heuristic (which targets state that should be an enum)
// does not apply.
#[allow(clippy::struct_excessive_bools)]
struct BlameOpts {
    /// Output format. Default emits `<short12>\t<line_num>\t<text>`
    /// per line; `json` emits JSONL with `hash`, `line_num`,
    /// `author`, `timestamp`, `text` keys.
    #[arg(long, value_enum, default_value = "default")]
    format: BlameFormat,
    /// Emit git's grouped porcelain: a per-line header block (commit id,
    /// original + final line numbers, author/committer, summary, `boundary`,
    /// `filename`) with each content line tab-prefixed; the metadata block
    /// is emitted once per commit. See [`render_porcelain`] for kit's
    /// documented field mapping (identity, UTC tz, `filename` on `-C`).
    #[arg(long = "porcelain", conflicts_with = "format")]
    porcelain: bool,
    /// Like `--porcelain`, but repeat the full header block for every line.
    #[arg(long = "line-porcelain", conflicts_with = "format")]
    line_porcelain: bool,
    /// Ignore whitespace when matching lines across revisions, like
    /// `git blame -w`, so a whitespace-only edit (reindent, tab↔space,
    /// spacing tweak) doesn't reattribute the line. Output still shows
    /// the file's current bytes.
    #[arg(short = 'w', long = "ignore-whitespace")]
    ignore_whitespace: bool,
    /// Restrict output to a line range, like `git blame -L`. Accepts
    /// `<start>,<end>`, `<start>,+<n>` (n lines forward), `<start>,-<n>`
    /// (n lines back, ending at start), `<start>,` (start to EOF),
    /// `,<end>` (start of file to end), or a bare `<start>` (start to
    /// EOF). Lines are 1-based and inclusive; an inverted range is
    /// swapped and an over-long end is clamped to EOF, matching git.
    // `allow_hyphen_values` so a pathological negative start (`-3,5`)
    // reaches the parser for a git-faithful diagnostic instead of clap
    // mistaking `-3` for a flag. Valid values never start with `-` (the
    // `-<n>` offset is always the second field).
    #[arg(
        short = 'L',
        long = "lines",
        value_name = "START,END",
        allow_hyphen_values = true
    )]
    lines: Option<String>,
    /// Detect lines moved *within* the file, like `git blame -M`: a moved
    /// block of at least 20 alphanumeric characters is credited to its
    /// origin commit rather than the editing one. The inline
    /// `-M<num>`/`-M<num>%` form overrides the threshold and is pulled out
    /// of argv by [`extract_inline_thresholds`] before clap runs; this
    /// bool captures the bare `-M`/`--find-moves` flag.
    #[arg(short = 'M', long = "find-moves")]
    find_moves: bool,
    /// Detect lines copied *from other files*, like `git blame -C`
    /// (implies `-M`). Repeat to widen the search: `-C` covers files
    /// changed in the same commit, `-C -C` every file in the parent
    /// commit. A copied block needs at least 40 alphanumeric characters.
    /// The inline `-C<num>`/`-C<num>%` form overrides the threshold and
    /// still counts toward the level; [`extract_inline_thresholds`] pulls
    /// those out of argv before clap runs, so this count captures only the
    /// bare `-C`/`--find-copies` occurrences.
    #[arg(short = 'C', long = "find-copies", action = clap::ArgAction::Count)]
    find_copies: u8,
    /// Ignore a "noise" commit (mass reformat, license header, rename)
    /// when attributing lines, like `git blame --ignore-rev`. A line that
    /// would be credited to an ignored commit falls through to the commit
    /// that previously changed it; a genuine insertion stays put. Accepts
    /// any revision (short hash, ref, `HEAD~2`) and may be repeated.
    #[arg(long = "ignore-rev", value_name = "REV")]
    ignore_rev: Vec<String>,
    /// Ignore every commit listed in `<file>`, like
    /// `git blame --ignore-revs-file`. One full hex object name per line;
    /// blank lines and `#` comments (including inline) are skipped. May be
    /// repeated.
    #[arg(long = "ignore-revs-file", value_name = "FILE")]
    ignore_revs_file: Vec<String>,
    /// Refine `--ignore-rev`/`--ignore-revs-file` fall-through with content
    /// matching instead of git's positional per-hunk guess (kit-only
    /// divergence; the default fall-through stays git-identical). git pairs
    /// a fallen-through line with whatever line sits at the same offset in
    /// the hunk; kit hashes content, so it can often identify the line's
    /// true surviving origin even when a reformat/reorder moved it to a
    /// different offset. Requires `--ignore-rev` or `--ignore-revs-file`.
    #[arg(long = "ignore-rev-precise")]
    ignore_rev_precise: bool,
    /// Walk history *forward* instead of backward, like
    /// `git blame --reverse`. Blames the `<start>` version of the file and
    /// attributes each line to the last commit in the range in which it
    /// still existed. Requires the `<rev>` argument to be a
    /// `<start>..<end>` range (`<start>..` defaults `<end>` to HEAD); a
    /// bare revision or a missing `<start>` is rejected. Cannot be combined
    /// with `-M`/`-C` or `--ignore-rev`/`--ignore-revs-file`.
    #[arg(long = "reverse")]
    reverse: bool,
    /// Follow only each commit's first parent, like `git blame
    /// --first-parent`. By default blame is merge-aware: a line merged in
    /// from a side branch is credited to the commit that wrote it. With
    /// `--first-parent` such a line is credited to the merge commit instead.
    /// Composes with `-w`/`-M`/`-C`/`--ignore-rev`; redundant with
    /// `--reverse` (reverse blame is already first-parent only).
    #[arg(long = "first-parent")]
    first_parent: bool,
    /// `[<rev>] <file>`: the file to blame, optionally preceded by the
    /// revision to blame it at (a ref, hash, or `HEAD~2`-style spec).
    /// Without a revision the file is blamed against HEAD. A `--`
    /// separator before the file is accepted and ignored.
    #[arg(value_name = "REV/FILE", num_args = 1..=2, required = true)]
    rev_and_file: Vec<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    // git's inline `-M<num>`/`-C<num>` forms can't be expressed with clap
    // derive (a short flag that both repeats *and* takes an optional glued
    // value), so pull them out of argv first; bare `-M`/`-C` and stacked
    // short clusters (`-CC`, `-Mw`) fall through to clap below.
    let (clap_args, inline) = extract_inline_thresholds(args);
    let opts = match clap_args::parse::<BlameOpts>("kit blame", &clap_args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let json = matches!(opts.format, BlameFormat::Json);

    // Merge the inline-form results with clap's bare-flag results: a
    // `-M<num>` counts as `-M`, and each `-C<num>` still adds to the copy
    // level like a bare `-C`.
    let find_moves = opts.find_moves || inline.moves;
    let find_copies = opts.find_copies.saturating_add(inline.copies);

    // `rev_and_file` is clamped to 1..=2 by clap: one value is the file
    // (blame against HEAD); two values are `<rev> <file>`.
    let (rev_spec, file) = match opts.rev_and_file.as_slice() {
        [file] => (None, file),
        [rev, file] => (Some(rev), file),
        // Unreachable: clap enforces num_args = 1..=2.
        _ => return emit_err("expected [<rev>] <file>", exit::USAGE),
    };

    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let repo = match super::open_repo(&cwd) {
        Ok(repo) => repo,
        Err(code) => return code,
    };

    // `-M` enables move detection; `-C` (a repeat count) sets the copy
    // search level. An inline `-M<num>`/`-C<num>` overrides the default
    // threshold, otherwise git's defaults (20 for `-M`, 40 for `-C`) apply.
    // `-C` implies `-M` in the core, so a bare `-C` still credits
    // within-file moves too.
    let moves = if find_moves {
        match inline.move_threshold {
            Some(threshold) => MoveDetection::On { threshold },
            None => MoveDetection::GIT_DEFAULT,
        }
    } else {
        MoveDetection::Off
    };
    let copies = if find_copies > 0 {
        match inline.copy_threshold {
            Some(threshold) => CopyDetection::On {
                level: find_copies,
                threshold,
            },
            None => CopyDetection::git_default(find_copies),
        }
    } else {
        CopyDetection::Off
    };

    let request = blame::Request {
        file,
        revision: rev_spec.map(String::as_str),
        reverse: opts.reverse,
        ignore_whitespace: opts.ignore_whitespace,
        moves,
        copies,
        ignore_revs: &opts.ignore_rev,
        ignore_revs_files: &opts.ignore_revs_file,
        ignore_rev_precise: opts.ignore_rev_precise,
        first_parent: opts.first_parent,
        lines: opts.lines.as_deref(),
    };
    let result = match blame::blame(&repo, &request) {
        Ok(result) => result,
        Err(error) => {
            let error = libkit::Error::from(error);
            return emit_err(&exit_map::message(&error), exit_map::exit_code(&error));
        }
    };

    if opts.porcelain || opts.line_porcelain {
        render_porcelain(repo.store(), &result, file, opts.line_porcelain)
    } else if json {
        render_json(&result)
    } else {
        let text = format_blame_text(&result);
        let mut stdout = std::io::stdout().lock();
        let _ = stdout.write_all(text.as_bytes());
        exit::OK
    }
}

/// Inline `-M<num>`/`-C<num>` threshold state pulled from argv before clap
/// parsing. Bare `-M`/`-C` are left for clap (which owns the help text and
/// the `-C` repeat count); only the glued-value forms — which clap-derive
/// can't model — are handled here.
#[derive(Default)]
struct InlineThresholds {
    /// A `-M<num>` was seen (implies move detection, like a bare `-M`).
    moves: bool,
    /// Threshold from the last `-M<num>` seen, if any.
    move_threshold: Option<usize>,
    /// Count of `-C<num>` occurrences; each still adds to the copy level.
    copies: u8,
    /// Threshold from the last `-C<num>` seen, if any.
    copy_threshold: Option<usize>,
}

/// Pull git's inline `-M<num>`/`-C<num>`/`-M<num>%` forms out of `args`,
/// returning the remaining args (for clap) and the parsed thresholds.
///
/// clap-derive can't model a short flag that both repeats (`-C` sets the
/// copy level) and takes an optional glued value (`-C40` sets the
/// threshold), so the valued forms are handled here and the bare `-M`/`-C`
/// flags fall through to clap unchanged. Only glued values are consumed:
/// bare `-M`/`-C`, the `-L` range value (even a `-3,5`), and every
/// positional pass through untouched, and nothing after a `--` end-of-
/// options marker is inspected (so a file literally named `-C9` survives).
///
/// A glued value is consumed as a threshold **only when it is numeric**
/// (`-M20`, `-C40%`). Everything else — bare `-M`/`-C`, stacked short
/// clusters (`-CC` = copy level 2, `-Mw` = `-M -w`), the `-L` range value
/// (even a `-3,5`), and positionals — passes through untouched to clap, and
/// nothing after a `--` end-of-options marker is inspected (so a file
/// literally named `-C9` survives). Passing non-numeric `-M`/`-C` tokens on
/// to clap keeps git's/clap's short-flag stacking working and lets clap own
/// the diagnostic for a genuinely bad flag.
///
/// The number is a minimum alphanumeric-character count — git's non-`%`
/// `-M<n>` unit, which maps 1:1 onto kit's core threshold. A trailing `%`
/// is accepted, but the number is still used
/// as a char count: kit's block detector has no similarity-ratio model, a
/// deliberate, `log`-consistent divergence (documented in `docs/CLI.md`).
fn extract_inline_thresholds(args: &[String]) -> (Vec<String>, InlineThresholds) {
    let mut rest = Vec::with_capacity(args.len());
    let mut out = InlineThresholds::default();
    let mut opts_ended = false;
    for arg in args {
        if opts_ended {
            rest.push(arg.clone());
            continue;
        }
        if arg == "--" {
            opts_ended = true;
            rest.push(arg.clone());
            continue;
        }
        if let Some(t) = arg.strip_prefix("-M").and_then(parse_threshold) {
            out.move_threshold = Some(t);
            out.moves = true;
        } else if let Some(t) = arg.strip_prefix("-C").and_then(parse_threshold) {
            out.copy_threshold = Some(t);
            out.copies = out.copies.saturating_add(1);
        } else {
            // Bare `-M`/`-C`, a stacked cluster, or a non-`-M`/`-C` token:
            // clap handles it.
            rest.push(arg.clone());
        }
    }
    (rest, out)
}

/// Parse the value glued to `-M`/`-C` into a threshold, or `None` when it
/// is not a bare number — an empty suffix (bare `-M`), a stacked cluster
/// (`-CC` → `"C"`), or otherwise non-numeric. A single trailing `%` is
/// stripped first (the number is still a char
/// count). An all-digit value that overflows `usize` clamps to `MAX` — an
/// unreachable threshold — rather than being mis-read as a stacked cluster.
fn parse_threshold(val: &str) -> Option<usize> {
    let num = val.strip_suffix('%').unwrap_or(val);
    if num.is_empty() || !num.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(num.parse::<usize>().unwrap_or(usize::MAX))
}

/// JSONL output for `--format=json`. One record per source line:
///
/// ```json
/// {"hash":"<64-hex>","line_num":<int>,"author":"<identity>","timestamp":<int>,"text":"<line>"}
/// ```
fn render_json(result: &BlameResult) -> u8 {
    let mut stdout = std::io::stdout().lock();
    for line in &result.lines {
        let _ = stdout.write_all(b"{");
        let _ = write!(
            stdout,
            "\"hash\":\"{}\"",
            format::hex_hash(&line.commit_hash)
        );
        let _ = write!(stdout, ",\"line_num\":{}", line.line_num);
        let _ = write!(
            stdout,
            ",\"author\":\"{}\"",
            format::json_escape(&libkit::identity::full(&line.author))
        );
        let _ = write!(stdout, ",\"timestamp\":{}", line.timestamp);
        // Line text may contain arbitrary bytes from the source file.
        // Render via lossy UTF-8 — the original bytes are recoverable
        // via the default tab format for callers that care.
        let text = String::from_utf8_lossy(&line.text);
        let _ = write!(stdout, ",\"text\":\"{}\"", format::json_escape(&text));
        let _ = stdout.write_all(b"}\n");
    }
    exit::OK
}

/// Grouped / line porcelain output (`--porcelain` / `--line-porcelain`),
/// matching git 2.50.1's field ordering and grouping for the in-scope
/// fields.
///
/// Each line emits a header `<64-hex-sha> <orig> <final>` — plus the group
/// length on the first line of a run of one commit — then a metadata block
/// (once per commit for `--porcelain`, for **every** line under
/// `--line-porcelain`), then the tab-prefixed content bytes.
///
/// kit field mapping — deliberate, `log`-consistent divergences from git,
/// same spirit as `blame --format=json`:
/// - `author`/`committer` carry kit's Identity string (e.g. `ed25519:…`),
///   not a `Name`; `author-mail`/`committer-mail` are empty (`<>`) — kit
///   has no email.
/// - kit commits hold a single author + timestamp, so `committer*` mirror
///   `author*` and both `*-tz` are `+0000` (kit timestamps are UTC).
/// - `filename` is the blamed path, or the `-C` copy source for a
///   cross-file copy. git's `previous` line is outside the in-scope field
///   set and is not emitted.
fn render_porcelain(
    store: &ObjectStore,
    result: &BlameResult,
    file: &str,
    line_porcelain: bool,
) -> u8 {
    let mut summaries: HashMap<Hash, String> = HashMap::new();
    let mut seen: HashSet<Hash> = HashSet::new();
    let lines = &result.lines;
    let mut stdout = std::io::stdout().lock();

    let mut i = 0;
    while i < lines.len() {
        // A group is a maximal run of consecutive lines from one commit; its
        // length is printed on the group's first header (git's 4th field).
        let commit = lines[i].commit_hash;
        let mut group_len = 1;
        while i + group_len < lines.len() && lines[i + group_len].commit_hash == commit {
            group_len += 1;
        }
        for g in 0..group_len {
            let line = &lines[i + g];
            let hex = format::hex_hash(&line.commit_hash);
            if g == 0 {
                let _ = writeln!(
                    stdout,
                    "{hex} {} {} {group_len}",
                    line.orig_line_num, line.line_num
                );
            } else {
                let _ = writeln!(stdout, "{hex} {} {}", line.orig_line_num, line.line_num);
            }
            // Grouped porcelain emits the metadata once per commit;
            // line-porcelain repeats it for every line.
            let emit_meta = line_porcelain || seen.insert(line.commit_hash);
            if emit_meta {
                let ident = libkit::identity::full(&line.author);
                let summary = summaries
                    .entry(line.commit_hash)
                    .or_insert_with(|| libkit::log::subject(store, &line.commit_hash));
                let _ = writeln!(stdout, "author {ident}");
                let _ = writeln!(stdout, "author-mail <>");
                let _ = writeln!(stdout, "author-time {}", line.timestamp);
                let _ = writeln!(stdout, "author-tz +0000");
                let _ = writeln!(stdout, "committer {ident}");
                let _ = writeln!(stdout, "committer-mail <>");
                let _ = writeln!(stdout, "committer-time {}", line.timestamp);
                let _ = writeln!(stdout, "committer-tz +0000");
                let _ = writeln!(stdout, "summary {summary}");
                if line.boundary {
                    let _ = writeln!(stdout, "boundary");
                }
                let filename = line.source_path.as_deref().unwrap_or(file);
                let _ = writeln!(stdout, "filename {filename}");
            }
            // Content line: tab prefix + raw bytes + newline (git puts each
            // line's exact bytes after the tab).
            let _ = stdout.write_all(b"\t");
            let _ = stdout.write_all(&line.text);
            let _ = stdout.write_all(b"\n");
        }
        i += group_len;
    }
    exit::OK
}

use super::error as emit_err;

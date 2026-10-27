//! `kit log [<rev>] [<A>..<B> | <A>...<B>]` — walk commit history.
//!
//! With no argument the walk starts at `HEAD`. A single `<rev>` starts there
//! instead; a range `A..B` shows commits reachable from `B` but not `A`
//! (empty side = `HEAD`, so `A..` is `A..HEAD` and `..B` is `HEAD..B`).
//! An `A...B` symmetric range shows commits reachable from `A` or `B` but not
//! their common ancestors (the merge base). Commits are ordered
//! reverse-chronologically with a topological tie-break (a parent never
//! precedes a child) — git's `--date-order`. This is identical to git's
//! default for linear history and monotonic-timestamp merges; it can differ
//! only on merge DAGs with non-monotonic (skewed or imported) timestamps.
//!
//! Output modes:
//!
//! - default — human-oriented multi-line per commit on stdout. The
//!   full commit message body is printed indented (four spaces) and the
//!   timestamp is rendered as a stable UTC date
//!   (`YYYY-MM-DD HH:MM:SS +0000`), not the raw integer.
//! - `--oneline` — `<abbrev-hex> <title>` per commit on stdout. The
//!   abbreviation length defaults to 7 (`DEFAULT_ABBREV`) and is
//!   overridable with `--abbrev[=N]`.
//! - `--format=json` — JSONL, one self-contained JSON object per
//!   commit. Suitable for piping into `jq`.
//!
//! History filters — `--author`/`--grep` (substring matches),
//! `--since`/`--until` (a small explicit date grammar, see
//! `libkit::log::date`), and `--no-merges`/`--first-parent` — are
//! applied to the walk before `-n`'s limit, so the limit caps the
//! filtered result like git's does. `--first-parent` prunes the *walk*
//! itself (a merged side branch never enters the candidate set);
//! `--no-merges` only hides merge commits from the already-walked
//! output.
//!
//! Argument parsing is delegated to clap-derive via
//! [`crate::clap_args::parse`]; clap emits standard diagnostics on
//! errors and the parser maps them to kit sysexits (`USAGE` for
//! unknown flags, `DATAERR` for malformed `-n` values, etc.).

use std::io::Write;

use clap::{Parser, ValueEnum};
use kit_core::Hash;
use kit_core::object::Commit;
use libkit::log::{self, Filter, Query};

use crate::clap_args;
use crate::exit;
use crate::exit_map;
use crate::format;
use crate::signal;

/// Default abbreviated-hash length, matching git's nominal `core.abbrev`
/// starting point. Overridable with `--abbrev[=N]`.
const DEFAULT_ABBREV: usize = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    Default,
    Oneline,
    Json,
}

#[derive(Debug, Parser)]
#[command(
    name = "kit log",
    about = "Show commit history.",
    disable_help_flag = false,
    disable_version_flag = true
)]
#[allow(clippy::struct_excessive_bools)] // clap option flags, not a state machine
struct LogOpts {
    /// Compact one-line-per-commit output. Equivalent to
    /// `--format=oneline`; if both are given, `--format` wins.
    #[arg(long)]
    oneline: bool,

    /// Output format.
    #[arg(long, value_enum)]
    format: Option<Format>,

    /// Cap the number of commits printed.
    #[arg(short = 'n')]
    limit: Option<usize>,

    /// Abbreviate commit hashes in the default format (implied by
    /// `--oneline`).
    #[arg(long = "abbrev-commit")]
    abbrev_commit: bool,

    /// Minimum length of abbreviated hashes. Bare `--abbrev` uses the
    /// default (7); `--abbrev=N` sets the length.
    #[arg(long, value_name = "N", num_args = 0..=1, default_missing_value = "7")]
    abbrev: Option<usize>,

    /// Only show commits whose author identity contains `<pattern>`
    /// (substring match against both the short display form — `kit
    /// log`'s `Author:` line — and the full `kind:hex`/`mid:N` form used
    /// by `--format=json`'s `author` field). Unlike git, kit identities
    /// are opaque (Ed25519 keys, `mid:N` numbers, DID keys) rather than
    /// free-text `Name <email>`, so this is a plain substring match, not
    /// a regex.
    #[arg(long, value_name = "PATTERN")]
    author: Option<String>,

    /// Only show commits whose message (title + body) contains
    /// `<pattern>` (substring match, case-sensitive — like git's default
    /// `--grep`).
    #[arg(long, value_name = "PATTERN")]
    grep: Option<String>,

    /// Only show commits at or after this time. Accepts `@<unix-seconds>`,
    /// `now`/`today`/`yesterday`, `<N> <unit> ago`
    /// (second/minute/hour/day/week/month/year), `YYYY-MM-DD`, or
    /// `YYYY-MM-DD HH:MM:SS` (UTC).
    #[arg(long, value_name = "DATE")]
    since: Option<String>,

    /// Only show commits at or before this time. Same formats as
    /// `--since`.
    #[arg(long, value_name = "DATE")]
    until: Option<String>,

    /// Hide merge commits (more than one parent) from the output. The
    /// walk itself is unchanged — this only filters what gets printed —
    /// like `git log --no-merges`.
    #[arg(long = "no-merges")]
    no_merges: bool,

    /// Follow only the first parent at each merge, so a merged side
    /// branch never enters the walk at all (stronger than `--no-merges`,
    /// which still walks through merges but hides them from the
    /// output). Like `git log --first-parent`.
    #[arg(long = "first-parent")]
    first_parent: bool,

    /// Optional starting revision (`<rev>`), range (`A..B`, `A..`, `..B`), or
    /// symmetric range (`A...B`). Defaults to `HEAD`; an empty range side
    /// means `HEAD`.
    start: Option<String>,
}

impl LogOpts {
    /// Resolve `(oneline, format)` into the single `Format` the
    /// renderer consumes. Explicit `--format` wins over `--oneline`.
    fn render_format(&self) -> Format {
        match self.format {
            Some(f) => f,
            None if self.oneline => Format::Oneline,
            None => Format::Default,
        }
    }

    /// Abbreviation length for commit ids, or `None` to print the full
    /// 64-hex hash. `--abbrev=N` sets the length (and implies
    /// abbreviation); `--abbrev-commit` (or the `Oneline` format)
    /// abbreviates at `DEFAULT_ABBREV`. `short_hash` clamps the length
    /// to `[4, 64]`, so out-of-range `N` is harmless.
    fn abbrev_len(&self) -> Option<usize> {
        if let Some(n) = self.abbrev {
            return Some(n);
        }
        if self.abbrev_commit || self.render_format() == Format::Oneline {
            return Some(DEFAULT_ABBREV);
        }
        None
    }
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_args::parse::<LogOpts>("kit log", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let fmt = opts.render_format();
    let abbrev = opts.abbrev_len();

    // `--since`/`--until` are validated up front (a bad date is a usage
    // error, not a silent no-match) before touching the repository.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let since = match opts.since.as_deref() {
        Some(s) => match log::date::parse(s, now) {
            Ok(t) => Some(t),
            Err(e) => return emit_err(&format!("--since: {e}"), exit::USAGE),
        },
        None => None,
    };
    let until = match opts.until.as_deref() {
        Some(s) => match log::date::parse(s, now) {
            Ok(t) => Some(t),
            Err(e) => return emit_err(&format!("--until: {e}"), exit::USAGE),
        },
        None => None,
    };

    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let repo = match super::open_repo(&cwd) {
        Ok(repo) => repo,
        Err(code) => return code,
    };
    // `-n <limit>` caps the *filtered* set, not the raw walk, so it
    // composes with `--author`/`--grep`/`--since`/`--until`/`--no-merges`
    // the way git's does.
    let query = Query {
        start: opts.start.clone(),
        first_parent: opts.first_parent,
        filter: Filter {
            author: opts.author.clone(),
            grep: opts.grep.clone(),
            since,
            until,
            no_merges: opts.no_merges,
        },
        limit: opts.limit,
    };
    let entries = match log::history(&repo, &query) {
        Ok(Some(entries)) => entries,
        Ok(None) => {
            // No HEAD yet and no explicit revision → nothing to show.
            if opts.start.is_none() && matches!(fmt, Format::Default | Format::Oneline) {
                let mut stderr = std::io::stderr().lock();
                let _ = writeln!(stderr, "no commits yet");
            }
            return exit::OK;
        }
        Err(e) => {
            let e = libkit::Error::from(e);
            return emit_err(&exit_map::message(&e), exit_map::exit_code(&e));
        }
    };

    let mut stdout = std::io::stdout().lock();
    for entry in &entries {
        if signal::is_shutdown() {
            return exit::TEMPFAIL;
        }
        render_commit(&mut stdout, fmt, abbrev, &entry.hash, &entry.commit);
    }
    exit::OK
}

/// Render one commit in the selected format.
fn render_commit(
    out: &mut impl Write,
    fmt: Format,
    abbrev: Option<usize>,
    hash: &Hash,
    c: &Commit,
) {
    let full_message: String = String::from_utf8_lossy(&c.message).into_owned();
    let title = full_message.lines().next().unwrap_or("");
    match fmt {
        Format::Oneline => {
            let id = format::short_hash(hash, abbrev.unwrap_or(DEFAULT_ABBREV));
            let _ = writeln!(out, "{id} {title}");
        }
        Format::Default => {
            let id = match abbrev {
                Some(n) => format::short_hash(hash, n),
                None => format::hex_hash(hash),
            };
            let _ = writeln!(out, "commit {id}");
            let _ = writeln!(out, "Author: {}", libkit::identity::short(&c.author));
            let _ = writeln!(out, "Date:   {}", format::human_date_utc(c.timestamp));
            let _ = writeln!(out);
            // Full message body, indented like git. Each line is prefixed
            // with four spaces; blank lines stay blank.
            for line in full_message.lines() {
                if line.is_empty() {
                    let _ = writeln!(out);
                } else {
                    let _ = writeln!(out, "    {line}");
                }
            }
            let _ = writeln!(out);
        }
        Format::Json => {
            emit_json_entry(out, hash, c, title, &full_message);
        }
    }
}

/// Emit one JSONL record for a commit. Schema:
///
/// ```json
/// {
///   "hash": "<64-hex>",
///   "parents": ["<64-hex>", ...],
///   "tree": "<64-hex>",
///   "author": "<identity-string>",
///   "timestamp": <unix-seconds>,
///   "title": "<first line of message>",
///   "message": "<full message, JSON-escaped>"
/// }
/// ```
///
/// Keys are written in a deterministic order so the output is
/// reproducible and easy to snapshot-test.
fn emit_json_entry(
    out: &mut impl Write,
    hash: &kit_core::Hash,
    c: &kit_core::object::Commit,
    title: &str,
    full_message: &str,
) {
    let _ = out.write_all(b"{");
    let _ = write!(out, "\"hash\":\"{}\"", format::hex_hash(hash));
    let _ = out.write_all(b",\"parents\":[");
    for (i, p) in c.parents.iter().enumerate() {
        if i > 0 {
            let _ = out.write_all(b",");
        }
        let _ = write!(out, "\"{}\"", format::hex_hash(p));
    }
    let _ = out.write_all(b"]");
    let _ = write!(out, ",\"tree\":\"{}\"", format::hex_hash(&c.tree_hash));
    let _ = write!(
        out,
        ",\"author\":\"{}\"",
        format::json_escape(&libkit::identity::full(&c.author))
    );
    let _ = write!(out, ",\"timestamp\":{}", c.timestamp);
    let _ = write!(out, ",\"title\":\"{}\"", format::json_escape(title));
    let _ = write!(
        out,
        ",\"message\":\"{}\"",
        format::json_escape(full_message)
    );
    let _ = out.write_all(b"}\n");
}

use super::error as emit_err;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_format_explicit_format_wins_over_oneline() {
        let opts = LogOpts {
            oneline: true,
            format: Some(Format::Default),
            limit: None,
            abbrev_commit: false,
            abbrev: None,
            author: None,
            grep: None,
            since: None,
            until: None,
            no_merges: false,
            first_parent: false,
            start: None,
        };
        assert_eq!(opts.render_format(), Format::Default);
    }

    #[test]
    fn render_format_oneline_alone_resolves_to_oneline() {
        let opts = LogOpts {
            oneline: true,
            format: None,
            limit: None,
            abbrev_commit: false,
            abbrev: None,
            author: None,
            grep: None,
            since: None,
            until: None,
            no_merges: false,
            first_parent: false,
            start: None,
        };
        assert_eq!(opts.render_format(), Format::Oneline);
    }

    #[test]
    fn render_format_default_when_no_flags() {
        let opts = LogOpts {
            oneline: false,
            format: None,
            limit: None,
            abbrev_commit: false,
            abbrev: None,
            author: None,
            grep: None,
            since: None,
            until: None,
            no_merges: false,
            first_parent: false,
            start: None,
        };
        assert_eq!(opts.render_format(), Format::Default);
    }

    #[test]
    fn render_format_json_via_format_flag() {
        let opts = LogOpts {
            oneline: false,
            format: Some(Format::Json),
            limit: None,
            abbrev_commit: false,
            abbrev: None,
            author: None,
            grep: None,
            since: None,
            until: None,
            no_merges: false,
            first_parent: false,
            start: None,
        };
        assert_eq!(opts.render_format(), Format::Json);
    }

    fn opts_for_abbrev(oneline: bool, abbrev_commit: bool, abbrev: Option<usize>) -> LogOpts {
        LogOpts {
            oneline,
            format: None,
            limit: None,
            abbrev_commit,
            abbrev,
            author: None,
            grep: None,
            since: None,
            until: None,
            no_merges: false,
            first_parent: false,
            start: None,
        }
    }

    #[test]
    fn abbrev_len_off_by_default() {
        assert_eq!(opts_for_abbrev(false, false, None).abbrev_len(), None);
    }

    #[test]
    fn abbrev_len_default_for_oneline_and_abbrev_commit() {
        assert_eq!(
            opts_for_abbrev(true, false, None).abbrev_len(),
            Some(DEFAULT_ABBREV)
        );
        assert_eq!(
            opts_for_abbrev(false, true, None).abbrev_len(),
            Some(DEFAULT_ABBREV)
        );
    }

    #[test]
    fn abbrev_len_explicit_value_wins() {
        assert_eq!(
            opts_for_abbrev(true, false, Some(12)).abbrev_len(),
            Some(12)
        );
    }
}

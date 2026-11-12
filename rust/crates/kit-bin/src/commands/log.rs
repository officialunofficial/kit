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
//! `-p` (`--patch`) and `--stat` follow each commit with its diff against its
//! first parent, or against an empty tree for a root commit. They render the
//! same text as `kit show`, which calls the same code. A merge commit shows
//! its diff against the first parent, as `kit show` does. The two flags
//! exclude each other and `--format=json`.
//!
//! `--all` starts the walk at `HEAD`, every local branch, every
//! remote-tracking ref and every tag. A commit shows once, in the order above.
//! It is a usage error together with a revision or a range.
//!
//! `--decorate` prints the refs that name a commit after its id, in
//! parentheses, as `(HEAD -> main, v1, origin/main)` with a `tag: ` prefix on
//! a tag. The order is `HEAD`, the local branches, the tags, then the
//! remote-tracking refs. kit reads the refs once for the whole run. Ref names
//! print through [`format::safe_text`]. The flag excludes `--format=json`,
//! because the JSON record has a fixed set of keys.
//!
//! `--graph` draws the commit graph in the left margin, for the default and
//! the `--oneline` format. See the `graph` module. It draws an edge only to a parent
//! that the output shows, so a filter or a limit leaves no open line. It
//! excludes `-p`, `--stat` and `--format=json`.
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

use std::collections::{HashMap, HashSet};
use std::io::Write;

use clap::{Parser, ValueEnum};
use kit_core::Hash;
use kit_core::object::Commit;
use kit_core::refs::{self, Head};
use libkit::log::{self, Filter, Query, RefKind};

use crate::clap_args;
use crate::exit;
use crate::exit_map;
use crate::format;
use crate::signal;

mod graph;

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

    /// Show the patch of each commit against its first parent (a root
    /// commit against an empty tree).
    #[arg(short = 'p', long = "patch", conflicts_with = "stat")]
    patch: bool,

    /// Show the diffstat of each commit against its first parent.
    #[arg(long)]
    stat: bool,

    /// Start the walk at `HEAD`, every local branch, every remote-tracking
    /// ref and every tag, not at `HEAD` alone. Each commit appears once. It
    /// cannot combine with a revision or a range.
    #[arg(long, conflicts_with = "start")]
    all: bool,

    /// Print the refs that name each commit after its id: `HEAD`, the local
    /// branches, the tags (as `tag: <name>`) and the remote-tracking refs.
    /// It cannot combine with `--format=json`.
    #[arg(long)]
    decorate: bool,

    /// Draw the commit graph in the left margin with `*`, `|`, `/` and `\`.
    /// It cannot combine with `-p`, `--stat` or `--format=json`.
    #[arg(long, conflicts_with_all = ["patch", "stat"])]
    graph: bool,

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
    if fmt == Format::Json && (opts.patch || opts.stat) {
        return emit_err(
            "-p and --stat do not combine with --format=json",
            exit::USAGE,
        );
    }
    if fmt == Format::Json && opts.graph {
        return emit_err("--graph does not combine with --format=json", exit::USAGE);
    }
    if fmt == Format::Json && opts.decorate {
        return emit_err(
            "--decorate does not combine with --format=json",
            exit::USAGE,
        );
    }

    // `--since`/`--until` are validated up front (a bad date is a usage
    // error, not a silent no-match) before touching the repository.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let since = match parse_date("--since", opts.since.as_deref(), now) {
        Ok(t) => t,
        Err(code) => return code,
    };
    let until = match parse_date("--until", opts.until.as_deref(), now) {
        Ok(t) => t,
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
    // `-n <limit>` caps the *filtered* set, not the raw walk, so it
    // composes with `--author`/`--grep`/`--since`/`--until`/`--no-merges`
    // the way git's does.
    let query = Query {
        start: opts.start.clone(),
        all: opts.all,
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

    let decorations = if opts.decorate {
        match decorations(&repo) {
            Ok(map) => map,
            Err(code) => return code,
        }
    } else {
        HashMap::new()
    };

    print_entries(&opts, &repo, &entries, &decorations)
}

/// Print the commits, each with its decoration and its diff when asked.
fn print_entries(
    opts: &LogOpts,
    repo: &libkit::Repo,
    entries: &[log::Entry],
    decorations: &HashMap<Hash, Vec<String>>,
) -> u8 {
    let (fmt, abbrev) = (opts.render_format(), opts.abbrev_len());
    let mut stdout = std::io::stdout().lock();
    let mut graph = opts.graph.then(graph::Graph::default);
    // The graph draws an edge only to a parent that is in the output.
    let shown: HashSet<Hash> = if opts.graph {
        entries.iter().map(|entry| entry.hash).collect()
    } else {
        HashSet::new()
    };
    for entry in entries {
        if signal::is_shutdown() {
            return exit::TEMPFAIL;
        }
        let decoration = decorations
            .get(&entry.hash)
            .map(|names| format!("({})", names.join(", ")));
        if let Some(graph) = graph.as_mut() {
            if let Err(code) = print_graph_commit(
                &mut stdout,
                (graph, &shown),
                opts,
                entry,
                decoration.as_deref(),
            ) {
                return code;
            }
            continue;
        }
        render_commit(
            &mut stdout,
            fmt,
            abbrev,
            (&entry.hash, &entry.commit),
            decoration.as_deref(),
        );
        if opts.patch || opts.stat {
            let c = &entry.commit;
            match super::show::write_commit_diff(
                &mut stdout,
                repo,
                c.parents.first().copied(),
                c.tree_hash,
                opts.stat,
            ) {
                // The default format ends each commit with a blank line.
                Ok(true) if fmt == Format::Default => {
                    let _ = writeln!(stdout);
                }
                Ok(_) => {}
                Err((msg, code)) => return emit_err(&msg, code),
            }
        }
    }
    exit::OK
}

/// Print one commit with the graph in the left margin. The error is the exit
/// code, after the message.
fn print_graph_commit(
    out: &mut impl Write,
    (graph, shown): (&mut graph::Graph, &HashSet<Hash>),
    opts: &LogOpts,
    entry: &log::Entry,
    decoration: Option<&str>,
) -> Result<(), u8> {
    let walked = if opts.first_parent { 1 } else { usize::MAX };
    let parents: Vec<Hash> = entry
        .commit
        .parents
        .iter()
        .take(walked)
        .filter(|parent| shown.contains(*parent))
        .copied()
        .collect();
    let row = graph
        .push(&entry.hash, &parents)
        .map_err(|graph::TooWide| {
            let msg = format!("--graph: more than {} open branches", graph::MAX_COLUMNS);
            emit_err(&msg, exit::DATAERR)
        })?;
    let mut text = Vec::new();
    render_commit(
        &mut text,
        opts.render_format(),
        opts.abbrev_len(),
        (&entry.hash, &entry.commit),
        decoration,
    );
    for line in &row.before {
        let _ = writeln!(out, "{line}");
    }
    for (n, line) in text.split_inclusive(|b| *b == b'\n').enumerate() {
        let margin = if n == 0 { &row.first } else { &row.rest };
        // A blank line keeps no trailing space after its margin.
        let margin = if line == b"\n" {
            margin.trim_end()
        } else {
            margin
        };
        let _ = out.write_all(margin.as_bytes());
        let _ = out.write_all(line);
    }
    for line in &row.after {
        let _ = writeln!(out, "{line}");
    }
    Ok(())
}

/// Parse the value of `--since` or `--until`. A bad date is a usage error,
/// and the error is the exit code, after the message.
fn parse_date(flag: &str, text: Option<&str>, now: u64) -> Result<Option<u64>, u8> {
    let Some(text) = text else {
        return Ok(None);
    };
    log::date::parse(text, now)
        .map(Some)
        .map_err(|e| emit_err(&format!("{flag}: {e}"), exit::USAGE))
}

/// The decoration names of each commit that a ref names, read once. Each
/// name is safe to print. The error is the exit code, after the message.
fn decorations(repo: &libkit::Repo) -> Result<HashMap<Hash, Vec<String>>, u8> {
    let tips = log::ref_tips(repo).map_err(|e| {
        let e = libkit::Error::from(e);
        emit_err(&exit_map::message(&e), exit_map::exit_code(&e))
    })?;
    let mut names: HashMap<Hash, Vec<String>> = HashMap::new();
    for kind in [RefKind::Branch, RefKind::Tag, RefKind::Remote] {
        for tip in tips.iter().filter(|tip| tip.kind == kind) {
            let name = format::safe_text(&tip.name);
            let name = if kind == RefKind::Tag {
                format!("tag: {name}")
            } else {
                name
            };
            names.entry(tip.commit).or_default().push(name);
        }
    }
    // `HEAD` leads the names of its commit. On a branch it replaces the
    // name of that branch.
    let layout = repo.layout();
    if let Some(head) = refs::resolve_head(layout).ok().flatten() {
        let list = names.entry(head).or_default();
        match refs::read_head(layout) {
            Ok(Head::Branch(branch)) => {
                let branch = format::safe_text(&branch);
                list.retain(|name| *name != branch);
                list.insert(0, format!("HEAD -> {branch}"));
            }
            _ => list.insert(0, "HEAD".to_owned()),
        }
    }
    Ok(names)
}

/// Render one commit in the selected format. `decoration` is the text that
/// follows the commit id.
fn render_commit(
    out: &mut impl Write,
    fmt: Format,
    abbrev: Option<usize>,
    (hash, c): (&Hash, &Commit),
    decoration: Option<&str>,
) {
    let decoration = decoration.map_or_else(String::new, |d| format!(" {d}"));
    let full_message: String = String::from_utf8_lossy(&c.message).into_owned();
    let title = full_message.lines().next().unwrap_or("");
    match fmt {
        Format::Oneline => {
            let id = format::short_hash(hash, abbrev.unwrap_or(DEFAULT_ABBREV));
            let _ = writeln!(out, "{id}{decoration} {}", format::safe_text(title));
        }
        Format::Default => {
            let id = match abbrev {
                Some(n) => format::short_hash(hash, n),
                None => format::hex_hash(hash),
            };
            let _ = writeln!(out, "commit {id}{decoration}");
            let _ = writeln!(
                out,
                "Author: {}",
                format::safe_text(&libkit::identity::short(&c.author))
            );
            let _ = writeln!(out, "Date:   {}", format::human_date_utc(c.timestamp));
            let _ = writeln!(out);
            // Full message body, indented like git. Each line is prefixed
            // with four spaces; blank lines stay blank.
            for line in full_message.lines() {
                if line.is_empty() {
                    let _ = writeln!(out);
                } else {
                    let _ = writeln!(out, "    {}", format::safe_text(line));
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
            patch: false,
            stat: false,
            all: false,
            decorate: false,
            graph: false,
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
            patch: false,
            stat: false,
            all: false,
            decorate: false,
            graph: false,
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
            patch: false,
            stat: false,
            all: false,
            decorate: false,
            graph: false,
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
            patch: false,
            stat: false,
            all: false,
            decorate: false,
            graph: false,
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
            patch: false,
            stat: false,
            all: false,
            decorate: false,
            graph: false,
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

//! `kit range-diff` — show how each commit of a series changed between two
//! versions of it. The pairing lives in [`kit_core::ops::range_diff`].

use std::io::Write;

use clap::Parser;
use kit_core::hash::{self, Hash};
use kit_core::ops::diff::{WhitespaceMode, unified_hunks_opts};
use kit_core::ops::merge::find_merge_base_within;
use kit_core::ops::range_diff::{MAX_SERIES, Patch, Status, correspond};
use libkit::log::{self, Entry, Filter, Query};

use crate::clap_args;
use crate::exit;
use crate::exit_map;
use crate::format;

/// The id length of the output.
const ABBREV: usize = 7;

#[derive(Debug, Parser)]
#[command(
    name = "kit range-diff",
    about = "Show how each commit of a series changed between two versions of it."
)]
struct RangeDiffOpts {
    /// The cost of leaving a commit unpaired, in percent of its patch size.
    #[arg(long, value_name = "n")]
    creation_factor: Option<String>,
    /// Accepted for git; kit prints no color.
    #[arg(long)]
    no_dual_color: bool,
    /// `<old-base>..<old-tip> <new-base>..<new-tip>`, `<old>...<new>`, or
    /// `<base> <old-tip> <new-tip>`.
    ranges: Vec<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_args::parse::<RangeDiffOpts>("kit range-diff", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let factor = match opts.creation_factor.as_deref().map(str::parse::<u32>) {
        None => 60,
        Some(Ok(n)) => n,
        Some(Err(_)) => return super::usage_error("--creation-factor takes a number"),
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return super::error(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let repo = match super::open_repo(&cwd) {
        Ok(repo) => repo,
        Err(code) => return code,
    };
    let (old_range, new_range) = match ranges(&repo, &opts.ranges) {
        Ok(r) => r,
        Err(code) => return code,
    };
    let old = match series(&repo, &old_range) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let new = match series(&repo, &new_range) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let old_patches: Vec<Patch> = match old.iter().map(|e| patch(&repo, e)).collect() {
        Ok(p) => p,
        Err(code) => return code,
    };
    let new_patches: Vec<Patch> = match new.iter().map(|e| patch(&repo, e)).collect() {
        Ok(p) => p,
        Err(code) => return code,
    };
    let width = old.len().max(new.len()).to_string().len();
    let side = |n: Option<usize>, entries: &[Entry]| match n {
        Some(i) => format!(
            "{:>width$}:  {}",
            i + 1,
            format::short_hash(&entries[i].hash, ABBREV)
        ),
        None => format!("{:>width$}:  {}", "-", "-".repeat(ABBREV)),
    };
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    for pair in correspond(&old_patches, &new_patches, factor) {
        let mark = match pair.status {
            Status::Same => '=',
            Status::Changed => '!',
            Status::Dropped => '<',
            Status::Added => '>',
        };
        // The subject is the old commit's when there is one, as in git.
        let entry = pair
            .old
            .map(|i| &old[i])
            .or_else(|| pair.new.map(|j| &new[j]));
        let subject = entry.map_or_else(String::new, |e| {
            String::from_utf8_lossy(&e.commit.message)
                .lines()
                .next()
                .unwrap_or("")
                .to_owned()
        });
        let _ = writeln!(
            out,
            "{} {mark} {} {}",
            side(pair.old, &old),
            side(pair.new, &new),
            format::safe_text(&subject)
        );
        if let (Status::Changed, Some(i), Some(j)) = (pair.status, pair.old, pair.new) {
            let diff = unified_hunks_opts(
                &old_patches[i].text,
                &new_patches[j].text,
                3,
                WhitespaceMode::Exact,
            )
            .unwrap_or_default();
            for line in String::from_utf8_lossy(&diff).lines() {
                let _ = writeln!(out, "    {}", format::safe_text(line));
            }
        }
    }
    let _ = out.flush();
    exit::OK
}

/// The two ranges, as `<base>..<tip>`, from the three ways git names them.
fn ranges(repo: &libkit::Repo, args: &[String]) -> Result<(String, String), u8> {
    let resolve = |spec: &str| -> Result<Hash, u8> {
        libkit::revspec::resolve_revision(repo.store(), repo.layout(), spec)
            .map(|h| libkit::revspec::peel_tags(repo.store(), h))
            .map_err(|e| super::usage_error(&format!("{spec}: {e}")))
    };
    match args {
        [one] => {
            let Some((a, b)) = one.split_once("...") else {
                return Err(super::usage_error(
                    "one argument must be a symmetric range <old>...<new>",
                ));
            };
            let (a, b) = (
                if a.is_empty() { "HEAD" } else { a },
                if b.is_empty() { "HEAD" } else { b },
            );
            let (ha, hb) = (resolve(a)?, resolve(b)?);
            let boundary = kit_core::shallow::read(repo.layout())
                .map_err(|e| super::error(&format!("merge base: {e}"), exit::DATAERR))?;
            let base = match find_merge_base_within(repo.store(), &boundary, ha, hb) {
                Ok(Some(base)) => hash::to_hex(&base),
                Ok(None) => {
                    return Err(super::error(
                        &format!("{one}: the two sides share no history"),
                        exit::GENERAL_ERROR,
                    ));
                }
                Err(e) => return Err(super::error(&format!("merge base: {e}"), exit::DATAERR)),
            };
            Ok((format!("{base}..{a}"), format!("{base}..{b}")))
        }
        [a, b] if is_range(a) && is_range(b) => Ok((a.clone(), b.clone())),
        [base, a, b] if ![base, a, b].iter().any(|s| s.contains("..")) => {
            Ok((format!("{base}..{a}"), format!("{base}..{b}")))
        }
        _ => Err(super::usage_error(
            "give <old-base>..<old-tip> <new-base>..<new-tip>, <old>...<new>, \
             or <base> <old-tip> <new-tip>",
        )),
    }
}

fn is_range(s: &str) -> bool {
    s.contains("..") && !s.contains("...")
}

/// The commits of `range`, oldest first, without merges.
fn series(repo: &libkit::Repo, range: &str) -> Result<Vec<Entry>, u8> {
    let query = Query {
        start: Some(range.to_owned()),
        filter: Filter {
            no_merges: true,
            ..Filter::default()
        },
        limit: Some(MAX_SERIES + 1),
        ..Query::default()
    };
    let mut entries = match log::history(repo, &query) {
        Ok(Some(e)) => e,
        Ok(None) => Vec::new(),
        Err(e) => {
            let e = libkit::Error::from(e);
            return Err(super::error(
                &exit_map::message(&e),
                exit_map::exit_code(&e),
            ));
        }
    };
    if entries.len() > MAX_SERIES {
        return Err(super::error(
            &format!("{range}: a side holds over {MAX_SERIES} commits"),
            exit::GENERAL_ERROR,
        ));
    }
    entries.reverse();
    Ok(entries)
}

/// The lines of a file header that a patch leaves out.
const HEADER_LINES: [&str; 8] = [
    "index ",
    "--- ",
    "+++ ",
    "similarity index",
    "rename from",
    "rename to",
    "old mode",
    "new mode",
];

/// The patch of a commit: its message, then its diff with each file named
/// on a `## <path> ##` line and no line numbers in the hunk headers.
fn patch(repo: &libkit::Repo, e: &Entry) -> Result<Patch, u8> {
    let mut diff = Vec::new();
    super::show::write_commit_diff(
        &mut diff,
        repo,
        e.commit.parents.first().copied(),
        e.commit.tree_hash,
        false,
        &[],
    )
    .map_err(|(msg, code)| super::error(&msg, code))?;
    // As git: the author, then the message, then the diff part. Only the
    // diff part counts toward the size and the cost of a pair, its
    // `## <path> ##` lines included.
    let mut text = format!(
        "## Metadata ##\nAuthor: {}\n\n## Commit message ##\n",
        libkit::identity::short(&e.commit.author)
    );
    for line in String::from_utf8_lossy(&e.commit.message).lines() {
        text.push_str("    ");
        text.push_str(line.trim_end());
        text.push('\n');
    }
    let mut file: Option<(String, &str)> = None;
    let diff = String::from_utf8_lossy(&diff);
    let mut size = 0u64;
    let mut diff_start: Option<usize> = None;
    let flush = |file: &mut Option<(String, &str)>,
                 text: &mut String,
                 size: &mut u64,
                 diff_start: &mut Option<usize>| {
        if let Some((name, note)) = file.take() {
            text.push('\n');
            diff_start.get_or_insert(text.len());
            text.push_str("## ");
            text.push_str(&name);
            text.push_str(note);
            text.push_str(" ##\n");
            *size += 1;
        }
    };
    for line in diff.lines() {
        if let Some(rest) = line.strip_prefix("diff --git ") {
            flush(&mut file, &mut text, &mut size, &mut diff_start);
            file = Some((file_name(rest), ""));
        } else if line.starts_with("new file mode") {
            if let Some(f) = file.as_mut() {
                f.1 = " (new)";
            }
        } else if line.starts_with("deleted file mode") {
            if let Some(f) = file.as_mut() {
                f.1 = " (deleted)";
            }
        } else if !(file.is_some() && HEADER_LINES.iter().any(|p| line.starts_with(p))) {
            flush(&mut file, &mut text, &mut size, &mut diff_start);
            if let Some(hunk) = line.strip_prefix("@@ ") {
                // `@@ -a,b +c,d @@ context` keeps only the context.
                let context = hunk.split_once(" @@").map_or("", |(_, c)| c);
                text.push_str("@@");
                text.push_str(context);
            } else {
                text.push_str(line);
            }
            text.push('\n');
            size += 1;
        }
    }
    flush(&mut file, &mut text, &mut size, &mut diff_start);
    Ok(Patch {
        diff_start: diff_start.unwrap_or(text.len()),
        text: text.into_bytes(),
        size,
    })
}

/// The name of a file from the rest of its `diff --git` line: the new path,
/// or `old => new` for a rename.
fn file_name(rest: &str) -> String {
    let half = rest.len() / 2;
    let (a, b) = if rest.len() % 2 == 1 && rest.as_bytes().get(half) == Some(&b' ') {
        (&rest[..half], &rest[half + 1..])
    } else {
        rest.split_once(" b/").map_or((rest, rest), |(a, b)| (a, b))
    };
    let strip = |p: &str| {
        p.strip_prefix("a/")
            .or_else(|| p.strip_prefix("b/"))
            .unwrap_or(p)
            .to_owned()
    };
    let (a, b) = (strip(a), strip(b));
    if a == b { b } else { format!("{a} => {b}") }
}

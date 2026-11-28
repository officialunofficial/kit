//! `kit shortlog` — group the commits that `kit log` shows by author, for
//! release notes and contributor counts.
//!
//! The walk is [`libkit::log::history`], with the revision and path rules
//! of `kit log`. With no revision and standard input that is not a
//! terminal, the commits come from `kit log` text on standard input, as in
//! git.

use std::collections::BTreeMap;
use std::io::{BufRead, IsTerminal, Write};

use clap::{Parser, ValueEnum};
use kit_core::object::{Identity, IdentityKind};
use libkit::log::{self, Query};

use crate::clap_args;
use crate::exit;
use crate::exit_map;
use crate::format::{self, JsonObject};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ShortlogFormat {
    Default,
    Json,
}

#[derive(Debug, Parser)]
#[command(
    name = "kit shortlog",
    about = "Group commits by author, for release notes and contributor counts."
)]
struct ShortlogOpts {
    /// Print only the count of each author.
    #[arg(short = 's', long)]
    summary: bool,
    /// Sort by count, largest first, instead of by author.
    #[arg(short = 'n', long)]
    numbered: bool,
    /// Keep the email, or the key id of a key author.
    #[arg(short = 'e', long)]
    email: bool,
    /// `default` or `json`, one object per author.
    #[arg(long, value_enum, default_value = "default")]
    format: ShortlogFormat,
    /// A revision or a range, then paths, as `kit log` reads them.
    args: Vec<String>,
}

/// The commits of one author.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Group {
    author: String,
    /// Oldest first.
    subjects: Vec<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let (args, explicit) = match args.iter().position(|a| a == "--") {
        Some(at) => (&args[..at], Some(&args[at + 1..])),
        None => (args, None),
    };
    let opts = match clap_args::parse::<ShortlogOpts>("kit shortlog", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let commits = if opts.args.is_empty() && explicit.is_none() && !std::io::stdin().is_terminal() {
        from_log_text(std::io::stdin().lock(), opts.email)
    } else {
        match from_history(&opts, explicit) {
            Ok(c) => c,
            Err(code) => return code,
        }
    };
    let mut groups = group(commits);
    if opts.numbered {
        groups.sort_by(|a, b| {
            b.subjects
                .len()
                .cmp(&a.subjects.len())
                .then_with(|| a.author.cmp(&b.author))
        });
    }
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    for g in &groups {
        let author = format::safe_text(&g.author);
        let _ = match (opts.format, opts.summary) {
            (ShortlogFormat::Json, _) => {
                let subjects: Vec<String> =
                    g.subjects.iter().map(|s| format::safe_text(s)).collect();
                let mut obj = JsonObject::new();
                obj.field_str("author", &author)
                    .field_u64("count", u64::try_from(subjects.len()).unwrap_or(u64::MAX))
                    .field_raw("subjects", &format::json_string_array(&subjects));
                writeln!(out, "{}", obj.finish())
            }
            (ShortlogFormat::Default, true) => {
                writeln!(out, "{:>6}\t{author}", g.subjects.len())
            }
            (ShortlogFormat::Default, false) => {
                let mut text = format!("{author} ({}):\n", g.subjects.len());
                for s in &g.subjects {
                    text.push_str("      ");
                    text.push_str(&format::safe_text(s));
                    text.push('\n');
                }
                writeln!(out, "{text}")
            }
        };
    }
    let _ = out.flush();
    exit::OK
}

/// The `(author, subject)` of each commit of the walk, newest first.
fn from_history(
    opts: &ShortlogOpts,
    explicit: Option<&[String]>,
) -> Result<Vec<(String, String)>, u8> {
    let cwd =
        std::env::current_dir().map_err(|e| super::error(&format!("cwd: {e}"), exit::NOINPUT))?;
    let repo = super::open_repo(&cwd)?;
    let (start, paths) = super::log::split_args(&repo, &cwd, &opts.args, false, explicit)?;
    let query = Query {
        start,
        paths,
        ..Query::default()
    };
    let entries = match log::history(&repo, &query) {
        Ok(Some(entries)) => entries,
        Ok(None) => return Ok(Vec::new()),
        Err(e) => {
            let e = libkit::Error::from(e);
            return Err(super::error(
                &exit_map::message(&e),
                exit_map::exit_code(&e),
            ));
        }
    };
    Ok(entries
        .iter()
        .map(|e| {
            let message = String::from_utf8_lossy(&e.commit.message);
            let subject = message.lines().next().unwrap_or("").to_owned();
            (author_name(&e.commit.author, opts.email), subject)
        })
        .collect())
}

/// The name a commit groups under: the name `kit log` prints, without a
/// trailing `<email>` unless `email`. With `email`, a key author shows its
/// key id.
fn author_name(id: &Identity, email: bool) -> String {
    let shown = libkit::identity::short(id);
    if email {
        let text_author =
            id.kind == IdentityKind::Opaque && shown == String::from_utf8_lossy(&id.bytes);
        return if text_author {
            shown
        } else {
            format!("{shown} <{}>", libkit::identity::full(id))
        };
    }
    strip_email(&shown)
}

/// `Name <email>` without ` <email>`.
fn strip_email(s: &str) -> String {
    match s.strip_suffix('>').and_then(|t| t.rsplit_once(" <")) {
        Some((name, _)) if !name.is_empty() => name.to_owned(),
        _ => s.to_owned(),
    }
}

/// The `(author, subject)` of each commit in `kit log` text, newest first:
/// the `Author:` line, then the first indented line after it.
fn from_log_text(input: impl BufRead, email: bool) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut author: Option<String> = None;
    for line in input.lines().map_while(Result::ok) {
        if line.starts_with("commit ") {
            author = None;
        } else if let Some(a) = line.strip_prefix("Author: ") {
            let a = a.trim();
            author = Some(if email { a.to_owned() } else { strip_email(a) });
        } else if let Some(subject) = line.strip_prefix("    ")
            && let Some(a) = author.take()
        {
            out.push((a, subject.to_owned()));
        }
    }
    out
}

/// Group commits, given newest first, by author: authors in order, each
/// with its subjects oldest first.
fn group(commits: Vec<(String, String)>) -> Vec<Group> {
    let mut by: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (author, subject) in commits.into_iter().rev() {
        by.entry(author).or_default().push(subject);
    }
    by.into_iter()
        .map(|(author, subjects)| Group { author, subjects })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn names_drop_the_email() {
        assert_eq!(strip_email("Ann <a@x>"), "Ann");
        assert_eq!(strip_email("Ann"), "Ann");
        assert_eq!(strip_email("<a@x>"), "<a@x>");
    }

    #[test]
    fn log_text_reads_author_and_subject() {
        let text = "commit 1\nAuthor: Ann <a@x>\nDate:   d\n\n    two\n\n    body\ncommit 2\nAuthor: Ann <a@x>\nDate:   d\n\n    one\n";
        let got = from_log_text(text.as_bytes(), false);
        assert_eq!(
            got,
            vec![("Ann".into(), "two".into()), ("Ann".into(), "one".into())]
        );
        assert_eq!(group(got)[0].subjects, vec!["one", "two"]);
    }

    proptest::proptest! {
        /// Each commit lands in exactly one group, the groups are sorted
        /// and distinct, and each keeps its commits oldest first.
        #[test]
        fn groups_partition(commits in proptest::collection::vec(("[ab]", "[xyz]{1,3}"), 0..20)) {
            let groups = group(commits.clone());
            let total: usize = groups.iter().map(|g| g.subjects.len()).sum();
            proptest::prop_assert_eq!(total, commits.len());
            for w in groups.windows(2) {
                proptest::prop_assert!(w[0].author < w[1].author);
            }
            for g in &groups {
                let mut want: Vec<String> = commits
                    .iter()
                    .filter(|(a, _)| *a == g.author)
                    .map(|(_, s)| s.clone())
                    .collect();
                want.reverse();
                proptest::prop_assert_eq!(&g.subjects, &want);
            }
        }
    }
}

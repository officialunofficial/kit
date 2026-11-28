//! `kit describe` — name a commit after the nearest tag that reaches it, as
//! `<tag>-<n>-k<short id>`. The choice of tag lives in
//! [`kit_core::ops::describe`].

use std::io::Write;

use clap::Parser;
use kit_core::hash::Hash;
use kit_core::object::Object;
use kit_core::ops::describe::{Candidate, nearest, parents_in};
use kit_core::ops::diff::{DiffKind, StatusStaging};
use kit_core::refs;
use kit_core::store::ObjectStore;

use crate::clap_args;
use crate::exit;
use crate::format;

/// The id length when `--abbrev` is not given, as elsewhere in kit.
const DEFAULT_ABBREV: usize = 7;

#[derive(Debug, Parser)]
#[command(
    name = "kit describe",
    about = "Name a commit after the nearest tag that reaches it."
)]
struct DescribeOpts {
    /// Count lightweight tags too.
    #[arg(long)]
    tags: bool,
    /// Print the short id when no tag reaches the commit.
    #[arg(long)]
    always: bool,
    /// The length of the id; 0 prints the tag alone.
    #[arg(long, value_name = "n")]
    abbrev: Option<String>,
    /// Print the long form even for a tag on the commit.
    #[arg(long)]
    long: bool,
    /// Append a mark when a tracked file differs from `HEAD`.
    #[arg(
        long,
        value_name = "mark",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "-dirty"
    )]
    dirty: Option<String>,
    /// Keep only tags whose names match the glob; repeatable.
    #[arg(long = "match", value_name = "glob")]
    matches: Vec<String>,
    /// Drop tags whose names match the glob; repeatable.
    #[arg(long, value_name = "glob")]
    exclude: Vec<String>,
    /// The commit to describe (default `HEAD`).
    revs: Vec<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_args::parse::<DescribeOpts>("kit describe", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let abbrev = match opts.abbrev.as_deref().map(str::parse::<usize>) {
        None => DEFAULT_ABBREV,
        Some(Ok(n)) => n,
        Some(Err(_)) => return super::usage_error("--abbrev takes a number"),
    };
    if opts.revs.len() > 1 {
        return super::usage_error("kit describe takes at most one revision");
    }
    if opts.dirty.is_some() && !opts.revs.is_empty() {
        return super::usage_error("--dirty does not combine with a revision");
    }
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return super::error(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let repo = match super::open_repo(&cwd) {
        Ok(repo) => repo,
        Err(code) => return code,
    };
    let store = repo.store();
    let spec = opts.revs.first().map_or("HEAD", String::as_str);
    let commit = match libkit::revspec::resolve_revision(store, repo.layout(), spec) {
        Ok(h) => libkit::revspec::peel_tags(store, h),
        Err(e) => return super::usage_error(&format!("{spec}: {e}")),
    };
    let candidates = match candidates(&repo, &opts) {
        Ok(c) => c,
        Err(code) => return code,
    };
    let found = match nearest(commit, &candidates, |h| parents_in(store, h)) {
        Ok(found) => found,
        Err(e) => return super::error(&format!("walk history: {e}"), exit::DATAERR),
    };
    let mut name = match found {
        Some(d) if (d.distance == 0 && !opts.long) || abbrev == 0 => {
            candidates[d.index].name.clone()
        }
        Some(d) => format!(
            "{}-{}-k{}",
            candidates[d.index].name,
            d.distance,
            format::short_hash(&commit, abbrev)
        ),
        None if opts.always => {
            format::short_hash(&commit, if abbrev == 0 { DEFAULT_ABBREV } else { abbrev })
        }
        None => {
            return super::error(
                &format!("no names found, cannot describe '{spec}'; try --always or --tags"),
                exit::GENERAL_ERROR,
            );
        }
    };
    if let Some(mark) = &opts.dirty {
        match is_dirty(&repo, &cwd) {
            Ok(true) => name.push_str(mark),
            Ok(false) => {}
            Err(code) => return code,
        }
    }
    let _ = writeln!(std::io::stdout().lock(), "{name}");
    exit::OK
}

/// The tags that may name the commit, after `--tags`, `--match` and
/// `--exclude`.
fn candidates(repo: &libkit::Repo, opts: &DescribeOpts) -> Result<Vec<Candidate>, u8> {
    let store = repo.store();
    let tags = refs::list_tags(repo.layout())
        .map_err(|e| super::error(&format!("list tags: {e}"), exit::DATAERR))?;
    let glob = libkit::branch::glob_match;
    let mut out = Vec::new();
    for tag in tags {
        let Some(hash) = tag.hash else { continue };
        if (!opts.matches.is_empty() && !opts.matches.iter().any(|p| glob(p, &tag.name)))
            || opts.exclude.iter().any(|p| glob(p, &tag.name))
        {
            continue;
        }
        let (commit, date) = match store.read_object(&hash) {
            Ok(Object::Tag(t)) => (libkit::revspec::peel_tags(store, hash), t.timestamp),
            Ok(Object::Commit(c)) if opts.tags => (hash, c.timestamp),
            _ => continue,
        };
        if commit_date(store, commit).is_none() {
            continue;
        }
        out.push(Candidate {
            name: tag.name,
            commit,
            date,
        });
    }
    Ok(out)
}

/// The date of a commit or remix, or `None` for another object.
fn commit_date(store: &ObjectStore, h: Hash) -> Option<u64> {
    match store.read_object(&h) {
        Ok(Object::Commit(c)) => Some(c.timestamp),
        Ok(Object::Remix(r)) => Some(r.timestamp),
        _ => None,
    }
}

/// Whether a tracked file differs from `HEAD` in the index or the worktree.
/// Untracked files do not count, as in git.
fn is_dirty(repo: &libkit::Repo, cwd: &std::path::Path) -> Result<bool, u8> {
    let report = libkit::status::compute(
        repo.layout(),
        cwd,
        &libkit::status::Request {
            renames: false,
            rename_threshold: None,
        },
        &crate::progress::ServedWarning,
    )
    .map_err(super::fail)?;
    Ok(report
        .entries
        .iter()
        .any(|e| !(e.staging == StatusStaging::Unstaged && e.diff.kind == DiffKind::Added)))
}

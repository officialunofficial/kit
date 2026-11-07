//! Patch series that `git am` applies.
//!
//! [`series`] resolves a range of native commits. A [`Patch`] holds the mail
//! headers, the message and the changes of one commit. The caller writes the
//! text of each patch, so a contribution can reach a git upstream even when
//! there is no writable fork.
//!
//! A merge commit has no linear patch, so a series leaves merge commits out.
//! A series refuses binary content, because `git am` cannot apply the
//! textual notice of a binary change.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use kit_core::Hash;
use kit_core::object::{Commit, IdentityKind, Object};
use kit_core::ops::diff::DiffEntry;
use kit_core::store::ObjectStore;
use kit_git_bridge::author;

use super::{Class, Error, open_repo, step};
use crate::diff::PatchBody;
use crate::revspec;

/// The most commits that the two walks of one series read together. It
/// matches the history walk of `kit log`.
const MAX_SERIES_COMMITS: usize = 1_000_000;

/// A range of commits, as patches.
#[derive(Debug)]
pub struct Series {
    store: ObjectStore,
    commits: Vec<(Hash, Commit)>,
    start: String,
    end: String,
    skipped_merges: usize,
}

/// One changed file of a [`Patch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// The entry of the tree diff.
    pub entry: DiffEntry,
    /// The lines of the change, after the header of the entry.
    pub body: PatchBody,
}

/// One commit as a mail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Patch {
    /// The kit hash of the commit.
    pub hash: Hash,
    /// The place of the patch in the series, from 1.
    pub number: usize,
    /// The number of patches in the series.
    pub total: usize,
    /// The value of the `From:` header.
    pub from: String,
    /// The value of the `Date:` header.
    pub date: String,
    /// The first line of the message.
    pub subject: String,
    /// The lines of the message after the subject. A line that `git` would
    /// read as the start of a new mail starts with `>`.
    pub body: Vec<String>,
    /// The changed files.
    pub changes: Vec<Change>,
}

impl Patch {
    /// The name of the file for this patch, such as `0001-Add-foo.patch`.
    #[must_use]
    pub fn file_name(&self) -> String {
        format!("{:04}-{}.patch", self.number, slug(&self.subject))
    }
}

/// Split a range into its two ends. `A..B` has the ends `A` and `B`. `A..`
/// and a single revision `A` have the ends `A` and `HEAD`.
#[must_use]
pub fn split_range(range: &str) -> (&str, &str) {
    match range.split_once("..") {
        Some((a, b)) => (a, if b.is_empty() { "HEAD" } else { b }),
        None => (range, "HEAD"),
    }
}

/// Resolve `range` in the repository at `cwd`.
///
/// # Errors
/// An error when `cwd` is not inside a kit repository, when an end of the
/// range does not name a commit, when a commit of either side cannot be read
/// or names a parent that is not a commit, or when the history has a cycle.
pub fn series(cwd: &Path, range: &str) -> Result<Series, Error> {
    let (layout, store) = open_repo(cwd)?;
    let (a, b) = split_range(range);
    let resolve = |spec: &str| -> Result<Hash, Error> {
        revspec::resolve_revision(&store, &layout, spec).map_err(|e| step(Class::Data, spec, e))
    };
    let exclude_tip = revspec::peel_tags(&store, resolve(a)?);
    let include_tip = revspec::peel_tags(&store, resolve(b)?);
    for (spec, h) in [(a, exclude_tip), (b, include_tip)] {
        if !matches!(store.read_object(&h), Ok(Object::Commit(_))) {
            // A non-commit end would silently exclude nothing and
            // render the entire history as the series.
            return Err(Error::RangeNotACommit(spec.to_owned()));
        }
    }

    let mut commits = collect_range(&store, exclude_tip, include_tip, MAX_SERIES_COMMITS)?;

    // Oldest first: parents before children, the timestamp as the tiebreak.
    let mut remaining: Vec<Hash> = commits.keys().copied().collect();
    remaining.sort_by_key(|h| (commits[h].timestamp, *h));
    let mut ordered: Vec<Hash> = Vec::with_capacity(remaining.len());
    let mut placed: HashSet<Hash> = HashSet::new();
    while !remaining.is_empty() {
        let before = ordered.len();
        remaining.retain(|h| {
            let ready = commits[h]
                .parents
                .iter()
                .all(|p| placed.contains(p) || !commits.contains_key(p));
            if ready {
                ordered.push(*h);
                placed.insert(*h);
            }
            !ready
        });
        if ordered.len() == before {
            return Err(Error::CommitCycle);
        }
    }

    let total = ordered.len();
    let linear: Vec<(Hash, Commit)> = ordered
        .into_iter()
        .filter_map(|h| commits.remove(&h).map(|c| (h, c)))
        .filter(|(_, c)| c.parents.len() <= 1)
        .collect();
    Ok(Series {
        store,
        skipped_merges: total - linear.len(),
        commits: linear,
        start: a.to_owned(),
        end: b.to_owned(),
    })
}

/// The commits reachable from `include_tip` and not from `exclude_tip`.
///
/// Ancestors of `exclude_tip` drop out of the patch series. Every one is
/// read: a walk that ended at a commit it could not read would leave its
/// ancestors in the series. Both walks share one budget of `cap` commits,
/// checked before each commit is read.
///
/// # Errors
/// An error that names the commit when a commit of either side cannot be
/// read or names a parent that is not a commit, and an error that names
/// `cap` when the two walks would read more commits than that. It never
/// returns part of the range.
fn collect_range(
    store: &ObjectStore,
    exclude_tip: Hash,
    include_tip: Hash,
    cap: usize,
) -> Result<HashMap<Hash, Commit>, Error> {
    let over_cap = || {
        step(
            Class::Data,
            "patch series",
            format!("the range reaches more than {cap} commits; no patch is written"),
        )
    };
    let mut excluded: HashSet<Hash> = HashSet::new();
    let mut stack = vec![exclude_tip];
    while let Some(h) = stack.pop() {
        if excluded.contains(&h) {
            continue;
        }
        if excluded.len() >= cap {
            return Err(over_cap());
        }
        excluded.insert(h);
        stack.extend(read_commit(store, h)?.parents);
    }
    let mut commits: HashMap<Hash, Commit> = HashMap::new();
    let mut stack = vec![include_tip];
    while let Some(h) = stack.pop() {
        if excluded.contains(&h) || commits.contains_key(&h) {
            continue;
        }
        if excluded.len().saturating_add(commits.len()) >= cap {
            return Err(over_cap());
        }
        let c = read_commit(store, h)?;
        stack.extend(c.parents.iter().copied());
        commits.insert(h, c);
    }
    Ok(commits)
}

/// Read the commit `h` of a range.
fn read_commit(store: &ObjectStore, h: Hash) -> Result<Commit, Error> {
    match store.read_object(&h) {
        Ok(Object::Commit(c)) => Ok(c),
        Ok(_) => Err(step(Class::Data, "not a commit", kit_core::to_hex(&h))),
        Err(e) => Err(step(
            Class::Data,
            format!("read {}", kit_core::to_hex(&h)),
            e,
        )),
    }
}

impl Series {
    /// The start of the range, as the caller wrote it.
    #[must_use]
    pub fn start(&self) -> &str {
        &self.start
    }

    /// The end of the range, as the caller wrote it.
    #[must_use]
    pub fn end(&self) -> &str {
        &self.end
    }

    /// The number of merge commits that the series left out.
    #[must_use]
    pub fn skipped_merges(&self) -> usize {
        self.skipped_merges
    }

    /// The number of patches.
    #[must_use]
    pub fn len(&self) -> usize {
        self.commits.len()
    }

    /// Whether the series has no patch.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.commits.is_empty()
    }

    /// The patches, oldest first. Each one is made when the iterator reaches
    /// it, so a caller that stops at the first error leaves the later
    /// commits unread.
    pub fn patches(&self) -> impl Iterator<Item = Result<Patch, Error>> + '_ {
        let total = self.commits.len();
        self.commits
            .iter()
            .enumerate()
            .map(move |(index, (hash, commit))| self.patch(hash, commit, index + 1, total))
    }

    fn patch(&self, hash: &Hash, c: &Commit, number: usize, total: usize) -> Result<Patch, Error> {
        let msg = String::from_utf8_lossy(&c.message);
        let mut lines = msg.lines();
        let subject = lines.next().unwrap_or("").to_owned();
        let body = lines
            .skip_while(|l| l.is_empty())
            .map(|l| {
                // git mailsplit treats a date-shaped "From <x> <ctime>" body
                // line as a new-message separator and FAILS the apply — on
                // git's own format-patch output too. Escape exactly that
                // shape; `git am` applies cleanly and the line round-trips
                // with a leading '>' (the classic mboxrd artifact), instead
                // of a broken series.
                if is_mbox_from_line(l) {
                    format!(">{l}")
                } else {
                    l.to_owned()
                }
            })
            .collect();

        let old_tree = match c.parents.first() {
            Some(p) => match self.store.read_object(p) {
                Ok(Object::Commit(pc)) => Some(pc.tree_hash),
                _ => None,
            },
            None => None,
        };
        let diff = kit_core::ops::diff::diff_trees(&self.store, old_tree, Some(c.tree_hash))
            .map_err(|e| step(Class::General, "diff", e))?;
        let mut changes = Vec::with_capacity(diff.entries.len());
        for entry in diff.entries {
            // Deliberately NOT wrapped in `DisplaySource`: this patch body is
            // format-patch-style output that `git am` applies into new
            // commits elsewhere, not a render a human just glances at.
            // Corruption here must surface as a loud `HashMismatch`, not
            // propagate into someone's history — keep this read verified.
            let body = crate::diff::patch_body(
                &self.store,
                &entry,
                kit_core::ops::DEFAULT_CONTEXT_LINES,
                kit_core::ops::WhitespaceMode::Exact,
            )
            .map_err(|e| super::plain(Class::General, e))?;
            // `git am` cannot apply the textual "Binary files differ"
            // notice (and we don't emit git's base85 binary literals), so
            // a series touching binary content would fail at the
            // MAINTAINER's end — refuse here instead.
            if body == PatchBody::Binary {
                return Err(Error::BinaryChange {
                    path: entry.path,
                    commit: kit_core::to_hex(hash)[..12].to_owned(),
                });
            }
            changes.push(Change { entry, body });
        }
        Ok(Patch {
            hash: *hash,
            number,
            total,
            from: from_header(c),
            date: rfc2822(c.timestamp),
            subject,
            body,
            changes,
        })
    }
}

/// The name part of a file name: the ASCII letters and digits of `subject`,
/// with each other run replaced by one `-`, cut to 52 characters. A subject
/// with no letter and no digit gives `patch`.
#[must_use]
pub fn slug(subject: &str) -> String {
    let mut out = String::new();
    for ch in subject.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
        } else if !out.ends_with('-') && !out.is_empty() {
            out.push('-');
        }
    }
    let trimmed = out.trim_end_matches('-');
    let cut = trimmed.chars().take(52).collect::<String>();
    if cut.is_empty() { "patch".into() } else { cut }
}

/// `From:` header. An opaque identity that already looks like a git
/// person ("Name <email>") passes through; anything else renders the
/// bridge's display name with its sentinel email (matching what
/// `kit git export` would emit).
fn from_header(c: &Commit) -> String {
    if let Ok(s) = std::str::from_utf8(&c.author.bytes)
        && c.author.kind == IdentityKind::Opaque
        && s.contains('<')
        && s.ends_with('>')
        && !s.chars().any(char::is_control)
    {
        return s.to_owned();
    }
    format!(
        "{} <{}>",
        author::display_name(&c.author),
        author::BRIDGE_EMAIL
    )
}

/// The shape `git mailsplit` splits on: `From <token> … <ctime> …`
/// where ctime is `Www Mmm [D]D HH:MM:SS YYYY`. mailsplit accepts
/// trailing tokens after the date (verified: a `+0000` timezone
/// suffix still splits), so the ctime window is searched ANYWHERE
/// after the first token, not anchored at the line end. Looser lines
/// (a plain "From the start..." sentence) do NOT split and must not
/// be escaped.
#[must_use]
pub fn is_mbox_from_line(line: &str) -> bool {
    const WDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let Some(rest) = line.strip_prefix("From ") else {
        return false;
    };
    let tokens: Vec<&str> = rest.split_whitespace().collect();
    // At least one token (the "sender") before the date window.
    tokens.len() >= 6
        && tokens.windows(5).skip(1).any(|w| {
            let [wday, mon, day, time, year] = w else {
                return false;
            };
            WDAYS.contains(wday)
                && MONS.contains(mon)
                && (1..=2).contains(&day.len())
                && day.bytes().all(|b| b.is_ascii_digit())
                && time.len() == 8
                && time.as_bytes()[2] == b':'
                && time.as_bytes()[5] == b':'
                && year.len() == 4
                && year.bytes().all(|b| b.is_ascii_digit())
        })
}

/// RFC 2822 date from a unix timestamp (UTC).
#[must_use]
pub fn rfc2822(ts: u64) -> String {
    const WDAY: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MON: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    #[allow(clippy::cast_possible_wrap)] // ts/86400 < i64::MAX
    let days = (ts / 86_400) as i64;
    let secs = ts % 86_400;
    let (y, m, d) = civil_from_days(days);
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // rem_euclid(7) ∈ 0..7
    let wd = ((days + 4).rem_euclid(7)) as usize; // 1970-01-01 = Thu
    format!(
        "{}, {} {} {} {:02}:{:02}:{:02} +0000",
        WDAY[wd],
        d,
        MON[(m - 1) as usize],
        y,
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

/// Days-since-epoch → (year, month, day). Howard Hinnant's
/// `civil_from_days`, exact over the proleptic Gregorian calendar.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // d ∈ 1..=31, m ∈ 1..=12
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_range_over_the_cap_fails_and_never_returns_a_part() {
        use kit_core::layout::RepoLayout;
        use kit_core::object::Identity;
        let dir = tempfile::TempDir::new().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
        let mut chain: Vec<Hash> = Vec::new();
        for ts in 0..6u64 {
            let commit = Commit::new_unannotated(
                [0; 32],
                chain.last().copied().into_iter().collect(),
                Identity::ed25519([0; 32]),
                [0; 32],
                b"msg".to_vec(),
                ts,
                [0; 64],
            );
            let bytes = kit_core::serialize::serialize(&Object::Commit(commit)).unwrap();
            chain.push(store.write(&bytes).unwrap());
        }
        // Three excluded commits and three in the series: six together.
        let (base, tip) = (chain[2], chain[5]);
        assert_eq!(collect_range(&store, base, tip, 6).unwrap().len(), 3);
        // An empty series still reads its whole excluded side.
        assert!(collect_range(&store, tip, base, 6).unwrap().is_empty());
        let err = collect_range(&store, tip, base, 5).unwrap_err();
        assert!(err.to_string().contains("more than 5 commits"), "{err}");
        for cap in [2, 3, 5] {
            let err = collect_range(&store, base, tip, cap).unwrap_err();
            assert!(
                err.to_string()
                    .contains(&format!("more than {cap} commits")),
                "{err}"
            );
        }
    }

    #[test]
    fn rfc2822_known_dates() {
        assert_eq!(rfc2822(0), "Thu, 1 Jan 1970 00:00:00 +0000");
        // date -u -r 1700000000 → Tue Nov 14 22:13:20 UTC 2023
        assert_eq!(rfc2822(1_700_000_000), "Tue, 14 Nov 2023 22:13:20 +0000");
        // Leap-day check: 2024-02-29 12:00:00 UTC = 1709208000
        assert_eq!(rfc2822(1_709_208_000), "Thu, 29 Feb 2024 12:00:00 +0000");
    }

    #[test]
    fn mbox_from_line_shapes() {
        assert!(is_mbox_from_line(
            "From 1234567890abcdef1234567890abcdef12345678 Mon Sep 17 00:00:00 2001"
        ));
        assert!(is_mbox_from_line("From x Thu Jan 1 00:00:00 1970"));
        // mailsplit also splits with trailing tokens after the date
        // (verified against native git) — a timezone suffix must not
        // defeat the escape.
        assert!(is_mbox_from_line(
            "From sender Fri Jun 12 12:00:00 2026 +0000"
        ));
        // The shapes mailsplit does NOT split on stay unescaped.
        assert!(!is_mbox_from_line("From the start, this was true."));
        assert!(!is_mbox_from_line("From: someone <a@b>"));
        assert!(!is_mbox_from_line("From abc Mon Sep 17 00:00 2001")); // bad time
    }

    #[test]
    fn slugs() {
        assert_eq!(slug("Add foo, bar & baz!"), "Add-foo-bar-baz");
        assert_eq!(slug("???"), "patch");
    }

    #[test]
    fn ranges_split_at_the_dots() {
        assert_eq!(split_range("a..b"), ("a", "b"));
        assert_eq!(split_range("a.."), ("a", "HEAD"));
        assert_eq!(split_range("a"), ("a", "HEAD"));
        assert_eq!(split_range("..b"), ("", "b"));
    }
}

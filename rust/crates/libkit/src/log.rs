//! Commit history.
//!
//! [`history`] walks the commits that a revision selection reaches and
//! returns them in order. The order is reverse-chronological. A parent never
//! comes before a child. That is the date order of git. It matches the
//! default order of git for a linear history and for a merge history with
//! monotonic timestamps. It can differ for a merge history with skewed or
//! imported timestamps.
//!
//! A [`Query`] names the selection, and it can limit and filter the result.
//! The selection is one of these forms:
//!
//! - No text, which walks `HEAD`.
//! - `<rev>`, which walks the history of that revision.
//! - `A..B`, which keeps the commits reachable from `B` and not from `A`.
//! - `A...B`, which keeps the commits reachable from `A` or `B` and not from
//!   their common ancestors.
//!
//! An empty side of a range means `HEAD`. A tag is followed to the commit
//! that it names.

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};

use kit_core::hash::{self, Hash};
use kit_core::object::{Commit, Object};
use kit_core::ops::merge::find_merge_base;
use kit_core::refs;
use kit_core::store::{ObjectStore, StoreError};

use crate::{Repo, identity, revspec};

pub mod date;

/// The most commits that one walk reads. A walk that would read more fails
/// with [`Error::TooManyCommits`]. It never returns part of the history.
const MAX_LOG_COMMITS: usize = 1_000_000;

/// Errors from walking the history.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A revision in the selection could not be resolved.
    #[error("bad revision '{spec}': {source}")]
    BadRevision {
        /// The text that the caller gave.
        spec: String,
        /// Why it did not resolve.
        source: revspec::Error,
    },
    /// The ancestors of the excluded side of a range could not be read.
    #[error("walk range base: {0}")]
    WalkRangeBase(StoreError),
    /// The merge base of the two sides of a symmetric range could not be
    /// found.
    #[error("merge base: {0}")]
    MergeBase(StoreError),
    /// The ancestors of the merge base could not be read.
    #[error("walk merge base: {0}")]
    WalkMergeBase(StoreError),
    /// An object in the walk is not a commit.
    #[error("not a commit: {}", hash::to_hex(.0))]
    NotACommit(Hash),
    /// The walk reaches more commits than one walk may read. Nothing is
    /// returned, because a part of the history would look complete.
    #[error("the walk reaches more than {limit} commits; no history is shown")]
    TooManyCommits {
        /// The most commits that one walk may read.
        limit: usize,
    },
    /// A commit in the walk could not be read.
    #[error("read {}: {source}", hash::to_hex(.hash))]
    ReadCommit {
        /// The commit that failed to read.
        hash: Hash,
        /// Why it failed.
        source: StoreError,
    },
}

/// Which commits pass. A commit has to pass every set condition.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filter {
    /// Keep a commit when its author, in the short form or the full form of
    /// [`identity`], contains this text. The match is a plain substring
    /// match.
    pub author: Option<String>,
    /// Keep a commit when its message contains this text. The match is a
    /// plain, case-sensitive substring match.
    pub grep: Option<String>,
    /// Keep a commit made at or after this time, in Unix seconds.
    pub since: Option<u64>,
    /// Keep a commit made at or before this time, in Unix seconds.
    pub until: Option<u64>,
    /// Drop a commit that has more than one parent.
    pub no_merges: bool,
}

impl Filter {
    /// Does `commit` pass every set condition?
    #[must_use]
    pub fn matches(&self, commit: &Commit) -> bool {
        if self.no_merges && commit.parents.len() > 1 {
            return false;
        }
        if self.since.is_some_and(|since| commit.timestamp < since) {
            return false;
        }
        if self.until.is_some_and(|until| commit.timestamp > until) {
            return false;
        }
        if let Some(pattern) = &self.author
            && !(identity::short(&commit.author).contains(pattern.as_str())
                || identity::full(&commit.author).contains(pattern.as_str()))
        {
            return false;
        }
        if let Some(pattern) = &self.grep
            && !String::from_utf8_lossy(&commit.message).contains(pattern.as_str())
        {
            return false;
        }
        true
    }
}

/// What to walk and what to keep.
#[derive(Debug, Clone, Default)]
pub struct Query {
    /// The revision selection. `None` walks `HEAD`.
    pub start: Option<String>,
    /// Follow only the first parent of each commit. A side branch that a
    /// merge brought in never enters the walk.
    pub first_parent: bool,
    /// Which commits pass. The filter applies before `limit`.
    pub filter: Filter,
    /// Keep at most this many commits after the filter.
    pub limit: Option<usize>,
}

/// One commit of the history.
#[derive(Debug, Clone)]
pub struct Entry {
    /// The id of the commit.
    pub hash: Hash,
    /// The commit.
    pub commit: Commit,
}

/// Walk the history that `query` selects.
///
/// The result is `None` when there is nothing to walk. That happens when the
/// selection needs `HEAD` and `HEAD` has no commit. An unreadable `HEAD`
/// counts as no commit.
///
/// # Errors
/// [`Error::BadRevision`] when a named revision does not resolve. The other
/// variants report an object that is missing or is not a commit.
pub fn history(repo: &Repo, query: &Query) -> Result<Option<Vec<Entry>>, Error> {
    let store = repo.store();
    let selection = parse_selection(query.start.as_deref());
    let Some((tips, excluded)) = resolve_selection(repo, &selection, MAX_LOG_COMMITS)? else {
        return Ok(None);
    };
    select(store, &tips, &excluded, query, MAX_LOG_COMMITS).map(Some)
}

/// Walk the history of `tips` in the order of [`history`], with no
/// exclusion and no filter. Each tip has to be a commit. A caller that has
/// resolved a revision to a commit uses this.
///
/// # Errors
/// [`Error::NotACommit`] or [`Error::ReadCommit`] when an object of the walk
/// is not a commit or cannot be read. [`Error::TooManyCommits`] when the
/// history is larger than one walk may read.
pub fn walk(store: &ObjectStore, tips: &[Hash], first_parent: bool) -> Result<Vec<Entry>, Error> {
    let mut entries = Vec::new();
    emit_sorted(
        store,
        tips,
        &HashSet::new(),
        first_parent,
        (0, MAX_LOG_COMMITS),
        |entry| {
            entries.push(entry);
            true
        },
    )?;
    Ok(entries)
}

/// The commits of the walk that pass the filter of `query`, in order, and
/// at most its limit.
fn select(
    store: &ObjectStore,
    tips: &[Hash],
    excluded: &HashSet<Hash>,
    query: &Query,
    max_commits: usize,
) -> Result<Vec<Entry>, Error> {
    let limit = query.limit.unwrap_or(usize::MAX);
    let mut entries = Vec::new();
    if limit == 0 {
        return Ok(entries);
    }
    emit_sorted(
        store,
        tips,
        excluded,
        query.first_parent,
        (0, max_commits),
        |entry| {
            if query.filter.matches(&entry.commit) {
                entries.push(entry);
            }
            entries.len() < limit
        },
    )?;
    Ok(entries)
}

/// The first line of the message of a commit or remix. The result is empty
/// when the object cannot be read or has another kind.
#[must_use]
pub fn subject(store: &ObjectStore, commit: &Hash) -> String {
    let message = match store.read_object(commit) {
        Ok(Object::Commit(c)) => c.message,
        _ => return String::new(),
    };
    String::from_utf8_lossy(&message)
        .lines()
        .next()
        .unwrap_or("")
        .to_owned()
}

/// The tips to walk, and the commits to leave out.
type WalkSet = (Vec<Hash>, HashSet<Hash>);

/// A revision selection, split into its parts.
enum Selection {
    /// No text. Walk `HEAD`.
    Default,
    /// One revision.
    Single(String),
    /// `A..B`.
    Range { exclude: String, include: String },
    /// `A...B`.
    Symmetric { a: String, b: String },
}

/// Split the selection text. An empty range side becomes `HEAD`.
fn parse_selection(text: Option<&str>) -> Selection {
    let Some(text) = text else {
        return Selection::Default;
    };
    let side = |side: &str| {
        if side.is_empty() {
            "HEAD".to_owned()
        } else {
            side.to_owned()
        }
    };
    // The three-dot form goes first, because it contains the two-dot form.
    if let Some((a, b)) = text.split_once("...") {
        return Selection::Symmetric {
            a: side(a),
            b: side(b),
        };
    }
    if let Some((a, b)) = text.split_once("..") {
        return Selection::Range {
            exclude: side(a),
            include: side(b),
        };
    }
    Selection::Single(text.to_owned())
}

/// Resolve the selection. The excluded side of a range may hold at most
/// `max_commits` commits.
fn resolve_selection(
    repo: &Repo,
    selection: &Selection,
    max_commits: usize,
) -> Result<Option<WalkSet>, Error> {
    let mut excluded: HashSet<Hash> = HashSet::new();
    let tips: Vec<Hash> = match selection {
        Selection::Default => match resolve_tip(repo, None)? {
            Some(tip) => vec![tip],
            None => return Ok(None),
        },
        Selection::Single(spec) => match resolve_tip(repo, Some(spec))? {
            Some(tip) => vec![tip],
            None => return Ok(None),
        },
        Selection::Range { exclude, include } => {
            let Some(include) = resolve_tip(repo, Some(include))? else {
                return Ok(None);
            };
            if let Some(base) = resolve_tip(repo, Some(exclude))? {
                collect_excluded(repo.store(), base, &mut excluded, max_commits)
                    .map_err(|e| e.into_error(Error::WalkRangeBase))?;
            }
            vec![include]
        }
        Selection::Symmetric { a, b } => {
            let a = resolve_tip(repo, Some(a))?;
            let b = resolve_tip(repo, Some(b))?;
            // Leave out the common ancestors, which are the ancestors of the
            // merge base.
            if let (Some(a), Some(b)) = (a, b)
                && let Some(base) = find_merge_base(repo.store(), a, b).map_err(Error::MergeBase)?
            {
                collect_excluded(repo.store(), base, &mut excluded, max_commits)
                    .map_err(|e| e.into_error(Error::WalkMergeBase))?;
            }
            let tips: Vec<Hash> = a.into_iter().chain(b).collect();
            if tips.is_empty() {
                return Ok(None);
            }
            tips
        }
    };
    Ok(Some((tips, excluded)))
}

/// Resolve one end of a selection. `None` or `HEAD` reads `HEAD`, which can
/// have no commit yet. Any other text has to resolve. A tag is followed to
/// the commit that it names.
fn resolve_tip(repo: &Repo, spec: Option<&str>) -> Result<Option<Hash>, Error> {
    let raw = match spec {
        None | Some("HEAD") => refs::resolve_head(repo.layout()).ok().flatten(),
        Some(spec) => Some(
            revspec::resolve_revision(repo.store(), repo.layout(), spec).map_err(|source| {
                Error::BadRevision {
                    spec: spec.to_owned(),
                    source,
                }
            })?,
        ),
    };
    Ok(raw.map(|hash| revspec::peel_tags(repo.store(), hash)))
}

/// A commit that is ready to emit. The newest timestamp comes first, and the
/// hash breaks a tie in a fixed way.
struct HeapItem {
    timestamp: u64,
    hash: Hash,
}

impl Ord for HeapItem {
    fn cmp(&self, other: &Self) -> Ordering {
        self.timestamp
            .cmp(&other.timestamp)
            .then_with(|| self.hash.cmp(&other.hash))
    }
}

impl PartialOrd for HeapItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for HeapItem {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for HeapItem {}

/// Why the excluded side of a range could not be collected.
enum ExcludeError {
    /// It holds more commits than one walk may read.
    TooMany(usize),
    /// An object could not be read.
    Store(StoreError),
}

impl ExcludeError {
    fn into_error(self, store: fn(StoreError) -> Error) -> Error {
        match self {
            Self::TooMany(limit) => Error::TooManyCommits { limit },
            Self::Store(source) => store(source),
        }
    }
}

/// Add `base` and all of its ancestors to `excluded`. The walk records
/// `base` even when its object is missing. A missing object or an object of
/// another kind ends the walk on that path. Any other read error fails the
/// walk. More than `max_commits` commits in `excluded` fails the walk too,
/// because a part of the set would let excluded commits through.
fn collect_excluded(
    store: &ObjectStore,
    base: Hash,
    excluded: &mut HashSet<Hash>,
    max_commits: usize,
) -> Result<(), ExcludeError> {
    let mut stack = vec![base];
    while let Some(current) = stack.pop() {
        if excluded.contains(&current) {
            continue;
        }
        if excluded.len() >= max_commits {
            return Err(ExcludeError::TooMany(max_commits));
        }
        excluded.insert(current);
        match store.read_object(&current) {
            Ok(Object::Commit(commit)) => stack.extend(commit.parents),
            Ok(_) | Err(StoreError::ObjectNotFound(_)) => {}
            Err(source) => return Err(ExcludeError::Store(source)),
        }
    }
    Ok(())
}

/// Read the commit `hash`.
fn read_commit(store: &ObjectStore, hash: Hash) -> Result<Commit, Error> {
    match store.read_object(&hash) {
        Ok(Object::Commit(commit)) => Ok(commit),
        Ok(_) => Err(Error::NotACommit(hash)),
        Err(source) => Err(Error::ReadCommit { hash, source }),
    }
}

/// The parents of `commit` that the walk follows.
fn walked_parents<'a>(
    commit: &'a Commit,
    excluded: &'a HashSet<Hash>,
    first_parent: bool,
) -> impl Iterator<Item = Hash> + 'a {
    let parents: &[Hash] = if first_parent {
        commit.parents.get(..1).unwrap_or(&[])
    } else {
        &commit.parents
    };
    parents
        .iter()
        .copied()
        .filter(|parent| !excluded.contains(parent))
}

/// Collect every commit reachable from `tips` and not in `excluded`, then
/// pass them to `emit` in date order until `emit` returns `false`. The order
/// is reverse-chronological, and a parent never comes before any of its
/// children. Equal timestamps keep the natural order from child to parent,
/// and the hash breaks a remaining tie. `cap` holds the commits that the
/// walk has read already and the most commits that the whole walk may read.
///
/// # Errors
/// [`Error::TooManyCommits`] when the walk reaches more commits than the
/// cap allows. Otherwise a read error of a commit.
fn emit_sorted(
    store: &ObjectStore,
    tips: &[Hash],
    excluded: &HashSet<Hash>,
    first_parent: bool,
    (streamed, max_commits): (usize, usize),
    mut emit: impl FnMut(Entry) -> bool,
) -> Result<(), Error> {
    // Collect the candidates. A depth-first walk over the parents skips the
    // excluded commits.
    let mut commits: HashMap<Hash, Commit> = HashMap::new();
    let mut stack: Vec<Hash> = tips.to_vec();
    while let Some(hash) = stack.pop() {
        if excluded.contains(&hash) || commits.contains_key(&hash) {
            continue;
        }
        if streamed.saturating_add(commits.len()) >= max_commits {
            return Err(Error::TooManyCommits { limit: max_commits });
        }
        let commit = read_commit(store, hash)?;
        stack.extend(walked_parents(&commit, excluded, first_parent));
        commits.insert(hash, commit);
    }

    // The in-degree of a commit is its number of children in the candidate
    // set.
    let mut in_degree: HashMap<Hash, usize> = commits.keys().map(|hash| (*hash, 0)).collect();
    for commit in commits.values() {
        for parent in &commit.parents {
            if let Some(degree) = in_degree.get_mut(parent) {
                *degree += 1;
            }
        }
    }

    // A max-heap on the timestamp holds the commits whose children are all
    // emitted.
    let mut heap: BinaryHeap<HeapItem> = BinaryHeap::new();
    for (hash, commit) in &commits {
        if in_degree[hash] == 0 {
            heap.push(HeapItem {
                timestamp: commit.timestamp,
                hash: *hash,
            });
        }
    }
    while let Some(item) = heap.pop() {
        // Each commit enters the heap once, when its last child is emitted.
        let Some(commit) = commits.remove(&item.hash) else {
            continue;
        };
        for parent in &commit.parents {
            if let Some(degree) = in_degree.get_mut(parent) {
                *degree -= 1;
                if *degree == 0 {
                    heap.push(HeapItem {
                        timestamp: commits[parent].timestamp,
                        hash: *parent,
                    });
                }
            }
        }
        if !emit(Entry {
            hash: item.hash,
            commit,
        }) {
            return Ok(());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use kit_core::object::Identity;

    use super::*;

    fn commit_for(parents: Vec<Hash>, author: Identity, message: &str, timestamp: u64) -> Commit {
        Commit::new_unannotated(
            hash::ZERO,
            parents,
            author,
            [0u8; 32],
            message.as_bytes().to_vec(),
            timestamp,
            [0u8; 64],
        )
    }

    fn alice() -> Identity {
        Identity::opaque(b"alice".to_vec())
    }

    fn filter() -> Filter {
        Filter::default()
    }

    #[test]
    fn an_empty_filter_passes_every_commit() {
        let c = commit_for(vec![], alice(), "m", 100);
        assert!(filter().matches(&c));
    }

    #[test]
    fn author_is_a_substring_of_the_short_or_the_full_form() {
        let c = commit_for(vec![], alice(), "m", 100);
        let by = |pattern: &str| Filter {
            author: Some(pattern.to_owned()),
            ..filter()
        };
        assert!(by("alice").matches(&c));
        assert!(by("lic").matches(&c));
        assert!(!by("bob").matches(&c));
        // The full form of an opaque key of another length starts with
        // `opaque:`. Only the full form has that text.
        assert!(by("opaque:").matches(&c));
    }

    #[test]
    fn grep_checks_the_message() {
        let c = commit_for(vec![], alice(), "fix: widget overflow", 100);
        let by = |pattern: &str| Filter {
            grep: Some(pattern.to_owned()),
            ..filter()
        };
        assert!(by("widget").matches(&c));
        assert!(!by("gadget").matches(&c));
        assert!(!by("WIDGET").matches(&c));
    }

    #[test]
    fn since_and_until_bound_the_timestamp_and_include_the_ends() {
        let c = commit_for(vec![], alice(), "m", 500);
        let between = |since, until| Filter {
            since,
            until,
            ..filter()
        };
        assert!(between(Some(500), Some(500)).matches(&c));
        assert!(between(Some(499), Some(501)).matches(&c));
        assert!(!between(Some(501), None).matches(&c));
        assert!(!between(None, Some(499)).matches(&c));
    }

    #[test]
    fn no_merges_drops_a_commit_with_two_parents() {
        let solo = commit_for(vec![], alice(), "m", 1);
        let merge = commit_for(vec![hash::ZERO, hash::ZERO], alice(), "m", 1);
        let no_merges = Filter {
            no_merges: true,
            ..filter()
        };
        assert!(no_merges.matches(&solo));
        assert!(!no_merges.matches(&merge));
        assert!(filter().matches(&merge));
    }

    #[test]
    fn the_selection_text_splits_in_the_documented_forms() {
        assert!(matches!(parse_selection(None), Selection::Default));
        assert!(matches!(
            parse_selection(Some("main")),
            Selection::Single(spec) if spec == "main"
        ));
        assert!(matches!(
            parse_selection(Some("a..b")),
            Selection::Range { exclude, include } if exclude == "a" && include == "b"
        ));
        assert!(matches!(
            parse_selection(Some("..b")),
            Selection::Range { exclude, include } if exclude == "HEAD" && include == "b"
        ));
        assert!(matches!(
            parse_selection(Some("a...")),
            Selection::Symmetric { a, b } if a == "a" && b == "HEAD"
        ));
    }

    /// A store in a temporary directory.
    fn temp_store() -> (tempfile::TempDir, ObjectStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = ObjectStore::init(&kit_core::layout::RepoLayout::single(dir.path())).unwrap();
        (dir, store)
    }

    /// Write a commit. `seed` makes commits with equal fields distinct.
    fn put(store: &ObjectStore, parents: Vec<Hash>, timestamp: u64, seed: u32) -> Hash {
        let message = format!("commit {seed}");
        let commit = commit_for(parents, alice(), &message, timestamp);
        store
            .write(&kit_core::serialize::serialize(&Object::Commit(commit)).unwrap())
            .unwrap()
    }

    /// A linear history of `n` commits, oldest first.
    fn chain(store: &ObjectStore, n: u32) -> Vec<Hash> {
        let mut hashes: Vec<Hash> = Vec::new();
        for i in 0..n {
            let parents = hashes.last().copied().into_iter().collect();
            hashes.push(put(store, parents, u64::from(i), i));
        }
        hashes
    }

    fn query_with(limit: Option<usize>, first_parent: bool) -> Query {
        Query {
            first_parent,
            limit,
            ..Query::default()
        }
    }

    fn ids(entries: &[Entry]) -> Vec<Hash> {
        entries.iter().map(|entry| entry.hash).collect()
    }

    #[test]
    fn a_linear_walk_over_the_cap_fails_and_never_returns_a_prefix() {
        let (_dir, store) = temp_store();
        let hashes = chain(&store, 5);
        let tip = [hashes[4]];
        let none = HashSet::new();
        for first_parent in [false, true] {
            let all = query_with(None, first_parent);
            let err = select(&store, &tip, &none, &all, 4).unwrap_err();
            assert!(matches!(err, Error::TooManyCommits { limit: 4 }), "{err:?}");
            assert!(err.to_string().contains("more than 4 commits"));
            assert_eq!(select(&store, &tip, &none, &all, 5).unwrap().len(), 5);
        }
    }

    #[test]
    fn a_merge_walk_over_the_cap_fails_and_never_returns_a_prefix() {
        let (_dir, store) = temp_store();
        // root - a - m - tip, with side between root and m.
        let root = put(&store, vec![], 1, 0);
        let a = put(&store, vec![root], 2, 1);
        let side = put(&store, vec![root], 3, 2);
        let merge = put(&store, vec![a, side], 4, 3);
        let tip = put(&store, vec![merge], 5, 4);
        let none = HashSet::new();
        let all = query_with(None, false);
        for cap in 0..5 {
            let err = select(&store, &[tip], &none, &all, cap).unwrap_err();
            assert!(matches!(err, Error::TooManyCommits { limit } if limit == cap));
        }
        let walked = select(&store, &[tip], &none, &all, 5).unwrap();
        assert_eq!(ids(&walked), [tip, merge, side, a, root]);
        let two_tips = select(&store, &[a, side], &none, &all, 2).unwrap_err();
        assert!(matches!(two_tips, Error::TooManyCommits { limit: 2 }));
    }

    #[test]
    fn an_excluded_side_over_the_cap_fails() {
        let (_dir, store) = temp_store();
        let hashes = chain(&store, 5);
        let mut excluded = HashSet::new();
        let err = collect_excluded(&store, hashes[4], &mut excluded, 4)
            .err()
            .unwrap()
            .into_error(Error::WalkRangeBase);
        assert!(matches!(err, Error::TooManyCommits { limit: 4 }), "{err:?}");
        let mut excluded = HashSet::new();
        assert!(collect_excluded(&store, hashes[4], &mut excluded, 5).is_ok());
        assert_eq!(excluded.len(), 5);
    }

    #[test]
    fn heap_items_order_by_time_and_then_by_hash() {
        let old = HeapItem {
            timestamp: 1,
            hash: [9; 32],
        };
        let new = HeapItem {
            timestamp: 2,
            hash: [0; 32],
        };
        let tie_low = HeapItem {
            timestamp: 2,
            hash: [1; 32],
        };
        assert!(new > old);
        assert!(tie_low > new);
    }
}

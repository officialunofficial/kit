//! The history of ranges of lines, for `kit log -L`.
//!
//! [`history`] reads each range in its file at the starting commit, then
//! walks the history in the order of [`super::walk`] and carries the
//! ranges from each commit to its parents with
//! [`kit_core::ops::line_log`]. It keeps the commits that change a line of
//! a range, as git's line-log does:
//!
//! - A commit with one parent, or none, is kept when a change of its diff
//!   touches a range. The ranges go on to the parent.
//! - At a merge, if the diff against one parent touches no range, that
//!   parent takes the ranges alone and the merge is left out. Otherwise each
//!   parent takes its ranges and the merge is kept, without hunks.
//!
//! A range ends at the commit that creates its file: renames are not
//! followed.

use std::collections::{BTreeMap, HashMap};

use kit_core::hash::{self, Hash};
use kit_core::object::{Commit, EntryMode};
use kit_core::ops::blame::find_file_in_tree;
use kit_core::ops::line_log::{RangeHunk, RangeSet, changes, hunks, map_across};
use kit_core::store::ObjectStore;
use kit_core::worktree::read_blob;

use crate::Repo;
use crate::blame::line_range;

/// Errors from following ranges of lines.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The walk failed.
    #[error(transparent)]
    Log(#[from] super::Error),
    /// A range is not valid for its file.
    #[error(transparent)]
    Range(#[from] line_range::Error),
    /// The file of a range does not exist at the starting commit.
    #[error("there is no path {path} in the commit {}", hash::to_hex(.commit))]
    NoSuchPath {
        /// The path, in the form of the index.
        path: String,
        /// The starting commit.
        commit: Hash,
    },
    /// A file or a tree could not be read.
    #[error("read {path}: {message}")]
    ReadFile {
        /// The path, in the form of the index.
        path: String,
        /// Why it failed.
        message: String,
    },
}

/// What to follow.
#[derive(Debug, Clone, Default)]
pub struct Request<'a> {
    /// The starting revision. `None` starts at `HEAD`.
    pub start: Option<&'a str>,
    /// Each range as `(range, path)`: the range in the syntax of
    /// [`line_range`] and the path in the form of the index.
    pub ranges: &'a [(String, String)],
    /// Follow only the first parent of each commit.
    pub first_parent: bool,
    /// Keep at most this many commits.
    pub limit: Option<usize>,
}

/// What a kept commit did to the ranges of one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHunks {
    /// The path, in the form of the index.
    pub path: String,
    /// Whether the commit creates the file.
    pub created: bool,
    /// The blob and mode of the file in the first parent, or `None` when
    /// the commit creates the file.
    pub old: Option<(Hash, EntryMode)>,
    /// The blob and mode of the file in the commit.
    pub new: (Hash, EntryMode),
    /// The hunks, one for each range of the file that the commit changes.
    pub hunks: Vec<RangeHunk>,
}

/// One kept commit.
#[derive(Debug, Clone)]
pub struct LineEntry {
    /// The id of the commit.
    pub hash: Hash,
    /// The commit.
    pub commit: Commit,
    /// The files whose ranges it changes, in path order. A merge has none.
    pub files: Vec<FileHunks>,
}

/// The followed ranges, by path.
type Ranges = BTreeMap<String, RangeSet>;

/// Follow the ranges of `request` back through the history. The result is
/// `None` when the walk needs `HEAD` and `HEAD` has no commit.
///
/// # Errors
/// [`Error::Log`] when the revision does not resolve or the walk fails,
/// [`Error::NoSuchPath`] and [`Error::Range`] when a range does not fit its
/// file at the starting commit, and [`Error::ReadFile`] when a file or a
/// tree cannot be read.
pub fn history(repo: &Repo, request: &Request<'_>) -> Result<Option<Vec<LineEntry>>, Error> {
    let store = repo.store();
    let Some(tip) = super::resolve_tip(repo, request.start)? else {
        return Ok(None);
    };
    let tip_commit = super::read_commit(store, tip)?;
    let mut start = Ranges::new();
    for (spec, path) in request.ranges {
        let blob =
            blob_at(store, tip_commit.tree_hash, path)?.ok_or_else(|| Error::NoSuchPath {
                path: path.clone(),
                commit: tip,
            })?;
        let total = line_count(&read(store, &blob.0, path)?);
        let (first, last) = line_range::parse(spec, total, path)?;
        let set = start.entry(path.clone()).or_default();
        *set = set.union(&RangeSet::new(std::iter::once(first - 1..last)));
    }
    let limit = request.limit.unwrap_or(usize::MAX);
    let mut out = Vec::new();
    if limit == 0 {
        return Ok(Some(out));
    }
    let mut pending: HashMap<Hash, Ranges> = HashMap::from([(tip, start)]);
    for entry in super::walk(store, &[tip], request.first_parent)? {
        let Some(mut ranges) = pending.remove(&entry.hash) else {
            continue;
        };
        ranges.retain(|_, set| !set.is_empty());
        if ranges.is_empty() {
            continue;
        }
        let parents: Vec<Hash> = if request.first_parent {
            entry.commit.parents.iter().take(1).copied().collect()
        } else {
            entry.commit.parents.clone()
        };
        let kept = if let [] | [_] = parents.as_slice() {
            let step = carry(store, &entry.commit, parents.first(), &ranges)?;
            if let Some(parent) = parents.first() {
                give(&mut pending, *parent, step.ranges);
            }
            (!step.files.is_empty()).then_some(step.files)
        } else {
            let mut steps = Vec::with_capacity(parents.len());
            let mut explained = false;
            for parent in &parents {
                let step = carry(store, &entry.commit, Some(parent), &ranges)?;
                if step.files.is_empty() {
                    give(&mut pending, *parent, step.ranges);
                    explained = true;
                    break;
                }
                steps.push(step.ranges);
            }
            if !explained {
                for (parent, ranges) in parents.iter().zip(steps) {
                    give(&mut pending, *parent, ranges);
                }
            }
            (!explained).then(Vec::new)
        };
        if let Some(files) = kept {
            out.push(LineEntry {
                hash: entry.hash,
                commit: entry.commit,
                files,
            });
            if out.len() >= limit {
                break;
            }
        }
    }
    Ok(Some(out))
}

/// The ranges carried to one parent, and the hunks of the files whose
/// ranges the commit changes against it.
struct Step {
    ranges: Ranges,
    files: Vec<FileHunks>,
}

/// Carry `ranges` from `commit` to `parent`, or to nothing for a root.
fn carry(
    store: &ObjectStore,
    commit: &Commit,
    parent: Option<&Hash>,
    ranges: &Ranges,
) -> Result<Step, Error> {
    let parent_tree = match parent {
        Some(p) => Some(super::read_commit(store, *p)?.tree_hash),
        None => None,
    };
    let mut step = Step {
        ranges: Ranges::new(),
        files: Vec::new(),
    };
    for (path, set) in ranges {
        let Some(target_file) = blob_at(store, commit.tree_hash, path)? else {
            // The file is not in this commit; nothing to diff.
            step.ranges.insert(path.clone(), set.clone());
            continue;
        };
        let target_blob = target_file.0;
        let parent_file = match parent_tree {
            Some(tree) => blob_at(store, tree, path)?,
            None => None,
        };
        let parent_blob = parent_file.map(|(hash, _)| hash);
        if parent_blob == Some(target_blob) {
            step.ranges.insert(path.clone(), set.clone());
            continue;
        }
        let target = read(store, &target_blob, path)?;
        let parent_text = match parent_blob {
            Some(blob) => read(store, &blob, path)?,
            None => Vec::new(),
        };
        let (carried, touched) = map_across(set, &changes(&parent_text, &target));
        step.ranges.insert(path.clone(), carried);
        if !touched.is_empty() {
            step.files.push(FileHunks {
                path: path.clone(),
                created: parent_blob.is_none(),
                old: parent_file,
                new: target_file,
                hunks: hunks(set, &touched, &parent_text, &target),
            });
        }
    }
    Ok(step)
}

/// Add `ranges` to what `parent` follows.
fn give(pending: &mut HashMap<Hash, Ranges>, parent: Hash, ranges: Ranges) {
    let held = pending.entry(parent).or_default();
    for (path, set) in ranges {
        let slot = held.entry(path).or_default();
        *slot = slot.union(&set);
    }
}

/// The blob at `path` in `tree`, if there is one.
fn blob_at(
    store: &ObjectStore,
    tree: Hash,
    path: &str,
) -> Result<Option<(Hash, EntryMode)>, Error> {
    find_file_in_tree(store, tree, path).map_err(|e| Error::ReadFile {
        path: path.to_owned(),
        message: e.to_string(),
    })
}

/// The content of the blob `hash` of `path`.
fn read(store: &ObjectStore, hash: &Hash, path: &str) -> Result<Vec<u8>, Error> {
    read_blob(store, hash).map_err(|e| Error::ReadFile {
        path: path.to_owned(),
        message: e.to_string(),
    })
}

/// The number of lines of `text`, a last line without a newline included.
fn line_count(text: &[u8]) -> usize {
    let newlines = text.split(|&b| b == b'\n').count() - 1;
    newlines + usize::from(!text.is_empty() && !text.ends_with(b"\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_count_a_last_line_without_newline() {
        assert_eq!(line_count(b""), 0);
        assert_eq!(line_count(b"a\n"), 1);
        assert_eq!(line_count(b"a\nb"), 2);
    }
}

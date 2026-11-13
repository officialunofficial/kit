//! Differences between trees.
//!
//! [`compute`] picks two trees from a [`Request`] and returns their
//! [`Diff`]. The request has the revisions and the paths that a person types
//! to `kit diff`. The [`Diff`] holds the changed entries. It also gives the
//! body of each patch and the change counts of each file, read from the
//! store without a hash check, because both only feed a display.
//!
//! The two trees come from the arguments in this order:
//!
//! - With `merge_base`, the first revision is the base. One revision gives
//!   the merge base of it and `HEAD`, against the worktree. Two revisions
//!   give the merge base of them, against the second one.
//! - With `staged`, the tree of `HEAD` against the staged tree. A revision
//!   argument is an error, because `staged` fixes both trees.
//! - `A...B` gives the merge base of `A` and `B`, against `B`. An empty side
//!   is `HEAD`.
//! - `A..B` gives the tree of `A` against the tree of `B`.
//! - One revision gives its tree against the worktree. Two revisions give
//!   the tree of the first against the tree of the second.
//! - No revision gives the tree of `HEAD` against the worktree.
//!
//! The arguments after the revisions are paths. They keep the entries at or
//! below one of them. A first argument that is not a revision starts the
//! paths. A first argument that looks like a revision and does not resolve is
//! an error, not a path.

use kit_core::hash::Hash;
use kit_core::index;
use kit_core::object::Object;
use kit_core::ops::graph::AncestorError;
use kit_core::ops::merge::find_merge_base_strict;
use kit_core::ops::{
    BINARY_SNIFF_LEN, DiffEntry, DiffKind, WhitespaceMode, detect_content_renames,
    diff_line_counts, diff_trees, is_binary, unified_hunks_opts,
};
use kit_core::refs::{self, RefError};
use kit_core::store::{DisplaySource, EphemeralSink, ObjectSource, StoreError};
use kit_core::worktree::{self, LoadedBlob, WorktreeError};

use crate::{Repo, revspec};

pub use kit_core::ops::DEFAULT_CONTEXT_LINES;

/// Errors from computing a diff.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// `merge_base` is set and the arguments name no revision.
    #[error("`--merge-base` requires at least one revision")]
    MergeBaseNeedsRevision,
    /// `staged` is set and the arguments start with a revision.
    #[error("`--staged` diffs HEAD vs the index; it cannot take an explicit revision")]
    StagedWithRevision,
    /// A revision does not resolve.
    #[error("bad revision '{spec}': {source}")]
    BadRevision {
        /// The text that the caller gave.
        spec: String,
        /// Why it did not resolve.
        source: revspec::Error,
    },
    /// An argument looks like a revision and names no ref, commit or short
    /// hash.
    #[error("bad revision '{0}': not a known ref, commit, or short hash")]
    UnknownRevision(String),
    /// A revision resolves to an object without a tree.
    #[error(transparent)]
    Tree(revspec::Error),
    /// The two revisions of a symmetric range share no ancestor.
    #[error("no merge base between '{a}' and '{b}'")]
    NoMergeBaseBetween {
        /// The left side.
        a: String,
        /// The right side.
        b: String,
    },
    /// The revisions of a merge-base diff share no ancestor.
    #[error("no merge base between the given revisions")]
    NoMergeBase,
    /// The merge base could not be computed: the walk reached its limit.
    #[error("merge base: {0}")]
    MergeBase(StoreError),
    /// A commit of the history is missing or corrupt, or a parent is not a
    /// commit. The error names it.
    #[error("merge base: {0}")]
    History(AncestorError),
    /// `HEAD` could not be read.
    #[error("resolve HEAD: {0}")]
    ResolveHead(RefError),
    /// `HEAD` has no commit, and the diff needs one for a merge base.
    #[error("HEAD has no commit to take a merge base with")]
    HeadWithoutCommit,
    /// The commit of `HEAD` could not be read.
    #[error("read HEAD: {0}")]
    ReadHead(StoreError),
    /// The index could not be read or seeded from `HEAD`. The text names the
    /// step that failed.
    #[error("{0}")]
    Index(String),
    /// The staged tree could not be built.
    #[error("build index tree: {0}")]
    BuildIndexTree(WorktreeError),
    /// The worktree tree could not be built.
    #[error("build tree: {0}")]
    BuildTree(WorktreeError),
    /// The two trees could not be compared.
    #[error("diff: {0}")]
    Diff(StoreError),
    /// Rename detection failed.
    #[error("rename detection: {0}")]
    RenameDetection(StoreError),
    /// A blob of the diff could not be read.
    #[error("read object: {0}")]
    ReadObject(WorktreeError),
}

/// What to compare. See the module documentation for the meaning of the
/// arguments.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// Compare `HEAD` with the staged tree.
    pub staged: bool,
    /// Compare against the merge base of the revisions.
    pub merge_base: bool,
    /// Join a deleted file and an added file of the same content into one
    /// rename entry.
    pub renames: bool,
    /// The revisions, then the paths.
    pub args: &'a [String],
}

/// The body of a patch for one file, after its header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatchBody {
    /// No lines to show. A rename and a pure mode change have none. A content
    /// change that the whitespace mode hides has none.
    Empty,
    /// One side, or both, is binary.
    Binary,
    /// The unified hunks, as raw bytes. A line can hold any byte.
    Hunks(Vec<u8>),
}

/// How much one file changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileStat {
    /// The path of the file.
    pub path: String,
    /// The change.
    pub change: StatChange,
}

/// The shape of a change in a [`FileStat`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatChange {
    /// A text change. A pure mode change counts as no line.
    Text {
        /// Lines added.
        added: usize,
        /// Lines deleted.
        deleted: usize,
    },
    /// A binary change. A chunked blob has its size in its manifest, so the
    /// size is a `u64` and needs no reassembled copy.
    Binary {
        /// The size before, in bytes.
        old_len: u64,
        /// The size after, in bytes.
        new_len: u64,
    },
}

/// The changed entries between two trees.
///
/// The value borrows the repository. It keeps the trees that it built from
/// the worktree or the index in memory, and it never writes them to the
/// store.
#[derive(Debug)]
pub struct Diff<'r> {
    snapshot: EphemeralSink<'r>,
    entries: Vec<DiffEntry>,
}

/// Compute the diff that `request` asks for.
///
/// # Errors
/// [`Error`], with one variant per failed step. A revision that does not
/// resolve gives [`Error::BadRevision`] or [`Error::UnknownRevision`].
pub fn compute<'r>(repo: &'r Repo, request: &Request<'_>) -> Result<Diff<'r>, Error> {
    let snapshot = EphemeralSink::new(repo.store());
    let (old, new, pathspecs) = resolve_endpoints(repo, &snapshot, request)?;
    let mut entries = diff_trees(&snapshot, old, new)
        .map_err(Error::Diff)?
        .entries;
    if request.renames {
        detect_content_renames(&snapshot, &mut entries).map_err(Error::RenameDetection)?;
    }
    let pathspecs: Vec<String> = pathspecs.iter().map(|p| normalize_pathspec(p)).collect();
    entries.retain(|e| pathspecs.is_empty() || path_matches_any(&e.path, &pathspecs));
    Ok(Diff { snapshot, entries })
}

/// Compute the diff between two trees. A side that is `None` is the empty
/// tree, so a root commit shows every file as added. The diff has no rename
/// detection.
///
/// # Errors
/// [`Error::Diff`] when a tree cannot be read.
pub fn between_trees(repo: &Repo, old: Option<Hash>, new: Option<Hash>) -> Result<Diff<'_>, Error> {
    let snapshot = EphemeralSink::new(repo.store());
    let entries = diff_trees(&snapshot, old, new)
        .map_err(Error::Diff)?
        .entries;
    Ok(Diff { snapshot, entries })
}

impl Diff<'_> {
    /// The changed entries, sorted as `diff_trees` sorts them.
    #[must_use]
    pub fn entries(&self) -> &[DiffEntry] {
        &self.entries
    }

    /// The body of the patch for `entry`. It reads through [`patch_body`]
    /// without a hash check.
    ///
    /// # Errors
    /// [`Error::ReadObject`] when a blob of the entry cannot be read.
    pub fn patch_body(
        &self,
        entry: &DiffEntry,
        context: usize,
        mode: WhitespaceMode,
    ) -> Result<PatchBody, Error> {
        patch_body(&DisplaySource::new(&self.snapshot), entry, context, mode)
    }

    /// The change counts of every entry, in the order of [`Diff::entries`].
    ///
    /// # Errors
    /// [`Error::ReadObject`] when a blob of an entry cannot be read.
    pub fn stats(&self) -> Result<Vec<FileStat>, Error> {
        stats(&self.snapshot, &self.entries)
    }
}

/// The body of the patch for `entry`, read from `source`.
///
/// `context` is the number of unchanged lines around each hunk. `mode` says
/// which lines compare as equal. It changes which lines join a hunk, not the
/// bytes of a line that joins one. The function reads through `source` as
/// given. A caller that makes a patch to apply elsewhere passes a source that
/// checks each hash. A caller that only shows the patch can pass a
/// [`DisplaySource`].
///
/// # Errors
/// [`Error::ReadObject`] when a blob of the entry cannot be read.
pub fn patch_body<S: ObjectSource + ?Sized>(
    source: &S,
    entry: &DiffEntry,
    context: usize,
    mode: WhitespaceMode,
) -> Result<PatchBody, Error> {
    if matches!(entry.kind, DiffKind::Renamed | DiffKind::ModeChanged) {
        return Ok(PatchBody::Empty);
    }
    let load = |hash: Option<Hash>| match hash {
        Some(hash) => LoadedBlob::load(source, &hash).map_err(Error::ReadObject),
        None => Ok(LoadedBlob::empty()),
    };
    let old = load(entry.old_hash)?;
    let new = load(entry.new_hash)?;
    if sides_are_binary(source, &old, &new)? {
        return Ok(PatchBody::Binary);
    }
    let old_bytes = old.into_content(source).map_err(Error::ReadObject)?;
    let new_bytes = new.into_content(source).map_err(Error::ReadObject)?;
    Ok(
        match unified_hunks_opts(&old_bytes, &new_bytes, context, mode) {
            None => PatchBody::Binary,
            Some(hunks) if hunks.is_empty() => PatchBody::Empty,
            Some(hunks) => PatchBody::Hunks(hunks),
        },
    )
}

/// Whether either side is binary. The check reads a bounded prefix of each
/// side, never a whole chunked blob.
fn sides_are_binary<S: ObjectSource + ?Sized>(
    source: &S,
    old: &LoadedBlob,
    new: &LoadedBlob,
) -> Result<bool, Error> {
    let old_prefix = old
        .prefix(source, BINARY_SNIFF_LEN)
        .map_err(Error::ReadObject)?;
    let new_prefix = new
        .prefix(source, BINARY_SNIFF_LEN)
        .map_err(Error::ReadObject)?;
    Ok(is_binary(&old_prefix) || is_binary(&new_prefix))
}

/// The change counts of `entries`, read from `source`.
///
/// A change count is for display, so the function reads every blob without a
/// hash check, through a [`DisplaySource`].
///
/// # Errors
/// [`Error::ReadObject`] when a blob of an entry cannot be read.
pub fn stats<S: ObjectSource + ?Sized>(
    source: &S,
    entries: &[DiffEntry],
) -> Result<Vec<FileStat>, Error> {
    let source = &DisplaySource::new(source);
    entries
        .iter()
        .map(|entry| {
            Ok(FileStat {
                path: entry.path.clone(),
                change: stat_change(source, entry)?,
            })
        })
        .collect()
}

/// Classify one entry as text or binary.
///
/// Each side loads once, as a [`LoadedBlob`]. The binary check, the sizes and
/// the text all come from that one load. The check reads a bounded prefix,
/// never a whole chunked blob. It uses the same rule as `diff_line_counts`:
/// a NUL byte in the first [`BINARY_SNIFF_LEN`] bytes. A binary entry takes
/// its sizes from the blob metadata and reads nothing more. Only a text entry
/// reads its whole content, to count lines.
fn stat_change<S: ObjectSource + ?Sized>(
    source: &S,
    entry: &DiffEntry,
) -> Result<StatChange, Error> {
    if entry.kind == DiffKind::ModeChanged {
        return Ok(StatChange::Text {
            added: 0,
            deleted: 0,
        });
    }
    let load = |hash: Option<Hash>| match hash {
        Some(hash) => LoadedBlob::load(source, &hash).map_err(Error::ReadObject),
        None => Ok(LoadedBlob::empty()),
    };
    let old = load(entry.old_hash)?;
    let new = load(entry.new_hash)?;
    if sides_are_binary(source, &old, &new)? {
        return Ok(StatChange::Binary {
            old_len: old.len(),
            new_len: new.len(),
        });
    }
    let old_bytes = old.into_content(source).map_err(Error::ReadObject)?;
    let new_bytes = new.into_content(source).map_err(Error::ReadObject)?;
    Ok(match diff_line_counts(&old_bytes, &new_bytes) {
        Some((added, deleted)) => StatChange::Text { added, deleted },
        // The prefix check already found both sides text. If the two checks
        // ever disagree, report sizes instead of panicking.
        None => StatChange::Binary {
            old_len: old_bytes.len() as u64,
            new_len: new_bytes.len() as u64,
        },
    })
}

/// The two trees and the paths.
type Endpoints = (Option<Hash>, Option<Hash>, Vec<String>);

fn resolve_endpoints(
    repo: &Repo,
    snapshot: &EphemeralSink<'_>,
    request: &Request<'_>,
) -> Result<Endpoints, Error> {
    let args = request.args;
    if request.merge_base {
        return merge_base_endpoints(repo, snapshot, args);
    }

    // `staged` fixes both trees, so a revision is a contradiction. A first
    // argument that looks like a revision fails closed in both cases. A typo
    // must not turn into a path that matches nothing and succeeds with an
    // empty diff.
    if request.staged {
        if let Some(first) = args.first()
            && looks_like_rev_request(first)
        {
            if revspec::resolve_revision(repo.store(), repo.layout(), strip_range_end(first))
                .is_ok()
            {
                return Err(Error::StagedWithRevision);
            }
            return Err(Error::UnknownRevision(first.clone()));
        }
        let head = head_tree(repo)?;
        let staged = staged_tree(repo, snapshot)?;
        return Ok((head, staged, args.to_vec()));
    }

    // `A...B` goes before `A..B`, which it contains.
    if let Some(first) = args.first()
        && let Some((a, b)) = split_symmetric(first)
    {
        let commit_a = peeled(repo, a)?;
        let commit_b = peeled(repo, b)?;
        let base = find_merge_base_strict(repo.store(), commit_a, commit_b)
            .map_err(merge_base_error)?
            .ok_or_else(|| Error::NoMergeBaseBetween {
                a: a.to_owned(),
                b: b.to_owned(),
            })?;
        let old = tree_of(repo, &base)?;
        let new = tree_of(repo, &commit_b)?;
        return Ok((Some(old), Some(new), args[1..].to_vec()));
    }

    if let Some(first) = args.first()
        && let Some((a, b)) = split_range(first)
    {
        let old = revision_tree(repo, a)?;
        let new = revision_tree(repo, b)?;
        return Ok((Some(old), Some(new), args[1..].to_vec()));
    }

    match args.first().and_then(|a| try_revision_tree(repo, a)) {
        None => {
            // No revision, so the paths are all of the arguments.
            if let Some(first) = args.first()
                && looks_like_rev_request(first)
            {
                return Err(Error::UnknownRevision(first.clone()));
            }
            let head = head_tree(repo)?;
            let worktree = Some(worktree_tree(repo, snapshot)?);
            Ok((head, worktree, args.to_vec()))
        }
        Some(Err(e)) => Err(e),
        Some(Ok(old)) => match args.get(1).and_then(|a| try_revision_tree(repo, a)) {
            Some(Ok(new)) => Ok((Some(old), Some(new), args[2..].to_vec())),
            Some(Err(e)) => Err(e),
            None => {
                let worktree = Some(worktree_tree(repo, snapshot)?);
                Ok((Some(old), worktree, args[1..].to_vec()))
            }
        },
    }
}

/// The trees of a merge-base diff. A tag is followed to its commit before the
/// merge base walk, as git does.
fn merge_base_endpoints(
    repo: &Repo,
    snapshot: &EphemeralSink<'_>,
    args: &[String],
) -> Result<Endpoints, Error> {
    let first = args.first().ok_or(Error::MergeBaseNeedsRevision)?;
    let a = peeled(repo, first)?;

    // A second argument that resolves selects the two-revision form.
    if let Some(second) = args.get(1) {
        match revspec::resolve_revision(repo.store(), repo.layout(), second) {
            Ok(hash) => {
                let b = revspec::peel_tags(repo.store(), hash);
                let base = merge_base_of(repo, a, b)?;
                let old = tree_of(repo, &base)?;
                let new = tree_of(repo, &b)?;
                return Ok((Some(old), Some(new), args[2..].to_vec()));
            }
            // An argument that does not resolve is a path only when it is
            // clearly path-shaped. Otherwise it is a typo in a revision, and
            // it fails. This avoids an empty diff, and it matches git.
            Err(e)
                if matches!(e, revspec::Error::Unknown(_)) && looks_like_pathspec(repo, second) => {
            }
            Err(source) => {
                return Err(Error::BadRevision {
                    spec: second.clone(),
                    source,
                });
            }
        }
    }

    // One revision: its merge base with `HEAD`, against the worktree.
    let head = refs::resolve_head(repo.layout())
        .map_err(Error::ResolveHead)?
        .ok_or(Error::HeadWithoutCommit)?;
    let head = revspec::peel_tags(repo.store(), head);
    let base = merge_base_of(repo, a, head)?;
    let old = tree_of(repo, &base)?;
    let new = worktree_tree(repo, snapshot)?;
    Ok((Some(old), Some(new), args[1..].to_vec()))
}

fn merge_base_of(repo: &Repo, a: Hash, b: Hash) -> Result<Hash, Error> {
    find_merge_base_strict(repo.store(), a, b)
        .map_err(merge_base_error)?
        .ok_or(Error::NoMergeBase)
}

/// The error of a strict merge base walk. A base found in part of the
/// history would diff the wrong changes, so the diff fails instead.
fn merge_base_error(err: AncestorError) -> Error {
    match err {
        AncestorError::Limit(limit) => Error::MergeBase(limit),
        other => Error::History(other),
    }
}

/// Resolve `spec` and follow tags to the commit.
fn peeled(repo: &Repo, spec: &str) -> Result<Hash, Error> {
    let hash = revspec::resolve_revision(repo.store(), repo.layout(), spec).map_err(|source| {
        Error::BadRevision {
            spec: spec.to_owned(),
            source,
        }
    })?;
    Ok(revspec::peel_tags(repo.store(), hash))
}

fn tree_of(repo: &Repo, hash: &Hash) -> Result<Hash, Error> {
    revspec::tree_of(repo.store(), hash).map_err(Error::Tree)
}

/// The tree of the revision `spec`.
fn revision_tree(repo: &Repo, spec: &str) -> Result<Hash, Error> {
    let hash = revspec::resolve_revision(repo.store(), repo.layout(), spec).map_err(|source| {
        Error::BadRevision {
            spec: spec.to_owned(),
            source,
        }
    })?;
    tree_of(repo, &hash)
}

/// Like [`revision_tree`], but `None` when `spec` is not a revision at all.
/// `Some(Err(..))` means that `spec` looks like a revision and is broken.
fn try_revision_tree(repo: &Repo, spec: &str) -> Option<Result<Hash, Error>> {
    match revspec::resolve_revision(repo.store(), repo.layout(), spec) {
        Ok(hash) => Some(tree_of(repo, &hash)),
        Err(revspec::Error::Unknown(_)) => {
            // An unknown name is a path unless it is shaped like a revision.
            looks_like_rev_request(spec).then(|| Err(Error::UnknownRevision(spec.to_owned())))
        }
        Err(source) => Some(Err(Error::BadRevision {
            spec: spec.to_owned(),
            source,
        })),
    }
}

/// The tree of the worktree. The tracked set starts from the index, or from
/// `HEAD` when no index file exists. A tracked file that an ignore rule
/// matches stays in the tree, so it does not show as deleted.
fn worktree_tree(repo: &Repo, snapshot: &EphemeralSink<'_>) -> Result<Hash, Error> {
    let index = index::read_or_seed_from_head(repo.layout(), repo.store()).map_err(Error::Index)?;
    worktree::build_tree_filtered_observed_with_source(
        snapshot,
        snapshot,
        repo.layout().worktree_root(),
        Some(&index),
        &mut Vec::new(),
    )
    .map_err(Error::BuildTree)
}

/// The tree of `HEAD`, or `None` when `HEAD` has no commit or names another
/// kind of object.
fn head_tree(repo: &Repo) -> Result<Option<Hash>, Error> {
    let Some(head) = refs::resolve_head(repo.layout()).map_err(Error::ResolveHead)? else {
        return Ok(None);
    };
    match repo.store().read_object(&head).map_err(Error::ReadHead)? {
        Object::Commit(c) => Ok(Some(c.tree_hash)),
        Object::Remix(r) => Ok(Some(r.tree_hash)),
        _ => Ok(None),
    }
}

/// The staged tree. The diff only shows it, so the tree is not hashed again.
/// A read verifies each object that it touches.
fn staged_tree(repo: &Repo, snapshot: &EphemeralSink<'_>) -> Result<Option<Hash>, Error> {
    let index = index::read_or_seed_from_head(repo.layout(), repo.store()).map_err(Error::Index)?;
    worktree::build_tree_from_index_with(repo.store(), snapshot, &index, false)
        .map(Some)
        .map_err(Error::BuildIndexTree)
}

/// Split `A..B`. `None` when there is no `..` or a side is empty.
fn split_range(text: &str) -> Option<(&str, &str)> {
    let (a, b) = text.split_once("..")?;
    if a.is_empty() || b.is_empty() {
        return None;
    }
    Some((a, b))
}

/// Split `A...B`. An empty side is `HEAD`.
fn split_symmetric(text: &str) -> Option<(&str, &str)> {
    let (a, b) = text.split_once("...")?;
    Some((
        if a.is_empty() { "HEAD" } else { a },
        if b.is_empty() { "HEAD" } else { b },
    ))
}

/// The left side of a possible range.
fn strip_range_end(text: &str) -> &str {
    match text.split_once("..") {
        Some((a, _)) if !a.is_empty() => a,
        _ => text,
    }
}

/// Does the caller mean a revision with this argument? A resolve failure is
/// then an error. A path-like word (`src/`, `./x`, `*.rs`) is a path.
///
/// These count as revisions: a word with `..` in it, `HEAD` with or without
/// `~` and `^` steps, and a hash-shaped word of at least
/// [`revspec::MIN_SHORT_HASH`] hex characters.
fn looks_like_rev_request(text: &str) -> bool {
    if text.contains("..") {
        return true;
    }
    let base = text.split(['~', '^']).next().unwrap_or(text);
    if base == "HEAD" {
        return true;
    }
    base.len() >= revspec::MIN_SHORT_HASH
        && !base.contains('/')
        && !base.contains('.')
        && base.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Is `arg` clearly a path, and not a revision with a typo? It is when it
/// names an existing path in the worktree, or a tracked path. A path that is
/// tracked and deleted from the worktree counts, as in git. A `/` is not
/// enough, because branch names contain `/`. A mistyped `feature/typo` must
/// fail as a bad revision.
fn looks_like_pathspec(repo: &Repo, arg: &str) -> bool {
    if repo
        .layout()
        .worktree_root()
        .join(arg)
        .symlink_metadata()
        .is_ok()
    {
        return true;
    }
    let spec = normalize_pathspec(arg);
    let Ok(index) = index::read_index(repo.layout()) else {
        return false;
    };
    let prefix = format!("{spec}/");
    index
        .entries
        .iter()
        .any(|e| e.path == spec || e.path.starts_with(&prefix))
}

/// Put a path in the form of the index. A leading `./` goes. `\` becomes
/// `/`. A trailing `/` goes. The root in any spelling (`.`, `./`, `/` or
/// nothing) becomes the empty string, which matches every path.
fn normalize_pathspec(spec: &str) -> String {
    let spec = spec.replace('\\', "/");
    let spec = spec.strip_prefix("./").unwrap_or(&spec);
    let spec = spec.strip_suffix('/').unwrap_or(spec);
    if spec == "." {
        String::new()
    } else {
        spec.to_owned()
    }
}

fn path_matches_any(path: &str, specs: &[String]) -> bool {
    specs
        .iter()
        .any(|spec| spec.is_empty() || index::path_matches_or_descends(path, spec))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::HashMap;

    use kit_core::hash;
    use kit_core::object::{Blob, ChunkedBlob};
    use kit_core::store::StoreResult;

    use super::*;

    #[test]
    fn a_pathspec_takes_the_form_of_the_index() {
        for (input, expected) in [
            ("a.txt", "a.txt"),
            ("./a.txt", "a.txt"),
            ("dir/", "dir"),
            ("dir\\sub", "dir/sub"),
            (".", ""),
            ("./", ""),
            ("", ""),
        ] {
            assert_eq!(normalize_pathspec(input), expected, "input {input:?}");
        }
    }

    #[test]
    fn the_empty_pathspec_matches_every_path_and_others_match_whole_components() {
        assert!(path_matches_any("a/b.txt", &[String::new()]));
        assert!(path_matches_any("a/b.txt", &["a".to_owned()]));
        assert!(path_matches_any("a", &["a".to_owned()]));
        assert!(!path_matches_any("ab/c.txt", &["a".to_owned()]));
        assert!(!path_matches_any("a.txt", &[]));
    }

    #[test]
    fn ranges_split_on_the_dots() {
        assert_eq!(split_range("a..b"), Some(("a", "b")));
        assert_eq!(split_range("a.."), None);
        assert_eq!(split_range("..b"), None);
        assert_eq!(split_range("ab"), None);
        assert_eq!(split_symmetric("a...b"), Some(("a", "b")));
        assert_eq!(split_symmetric("...b"), Some(("HEAD", "b")));
        assert_eq!(split_symmetric("a..."), Some(("a", "HEAD")));
        assert_eq!(split_symmetric("a..b"), None);
        assert_eq!(strip_range_end("a..b"), "a");
        assert_eq!(strip_range_end("..b"), "..b");
        assert_eq!(strip_range_end("a"), "a");
    }

    #[test]
    fn only_revision_shaped_words_count_as_revisions() {
        for yes in [
            "HEAD",
            "HEAD~2",
            "HEAD^",
            "a..b",
            "abcd",
            "0123456789abcdef",
        ] {
            assert!(looks_like_rev_request(yes), "{yes}");
        }
        for no in [
            "src/",
            "file.txt",
            "./x",
            "*.rs",
            "abc",
            "feature/x",
            "main",
        ] {
            assert!(!looks_like_rev_request(no), "{no}");
        }
    }

    // The tests below read through a source that records each read. A stat
    // has to read each side once, and a chunked blob must not read more than
    // its first chunk to find that it is binary.

    /// A fake [`ObjectSource`]. The objects are arbitrary bytes under
    /// arbitrary keys, and the source does not check the keys against the
    /// content. It records every hash that a caller reads.
    #[derive(Default)]
    struct RecordingSource {
        objects: HashMap<Hash, Vec<u8>>,
        reads: RefCell<Vec<Hash>>,
    }

    impl RecordingSource {
        fn put(&mut self, h: Hash, obj: &Object) {
            self.objects
                .insert(h, kit_core::serialize::serialize(obj).unwrap());
        }
    }

    impl ObjectSource for RecordingSource {
        fn read(&self, h: &Hash) -> StoreResult<Vec<u8>> {
            self.reads.borrow_mut().push(*h);
            self.objects
                .get(h)
                .cloned()
                .ok_or_else(|| StoreError::ObjectNotFound(hash::to_hex(h)))
        }
    }

    fn fake_hash(tag: u8) -> Hash {
        [tag; 32]
    }

    /// A buffer of `len` bytes of `fill` with a NUL at offset 10. It is binary
    /// and well inside `BINARY_SNIFF_LEN`.
    fn binary_bytes(fill: u8, len: usize) -> Vec<u8> {
        let mut data = vec![fill; len];
        data[10] = 0;
        data
    }

    fn modified(path: &str, old_hash: Hash, new_hash: Hash) -> DiffEntry {
        DiffEntry {
            path: path.to_owned(),
            kind: DiffKind::Modified,
            old_hash: Some(old_hash),
            new_hash: Some(new_hash),
            old_mode: None,
            new_mode: None,
            old_path: None,
        }
    }

    fn reads_of(source: &RecordingSource, hash: &Hash) -> usize {
        source.reads.borrow().iter().filter(|h| *h == hash).count()
    }

    #[test]
    fn a_chunked_binary_reads_no_trailing_chunk_and_takes_sizes_from_the_manifest() {
        // Only the manifest and the first chunk of each side are stored. A
        // read of any other chunk would fail the call.
        let mut source = RecordingSource::default();
        let old_chunk0 = fake_hash(1);
        let old_chunk1 = fake_hash(2);
        let old_manifest = fake_hash(3);
        source.put(
            old_chunk0,
            &Object::Blob(Blob {
                data: binary_bytes(b'a', BINARY_SNIFF_LEN + 1000),
            }),
        );
        source.put(
            old_manifest,
            &Object::ChunkedBlob(ChunkedBlob {
                total_size: 3_000_000,
                chunk_size: 0,
                chunks: vec![old_chunk0, old_chunk1],
            }),
        );
        let new_chunk0 = fake_hash(4);
        let new_chunk1 = fake_hash(5);
        let new_manifest = fake_hash(6);
        source.put(
            new_chunk0,
            &Object::Blob(Blob {
                data: binary_bytes(b'b', BINARY_SNIFF_LEN + 500),
            }),
        );
        source.put(
            new_manifest,
            &Object::ChunkedBlob(ChunkedBlob {
                total_size: 4_000_000,
                chunk_size: 0,
                chunks: vec![new_chunk0, new_chunk1],
            }),
        );

        let entry = modified("big.bin", old_manifest, new_manifest);
        let rows = stats(&source, std::slice::from_ref(&entry)).unwrap();
        assert_eq!(
            rows,
            [FileStat {
                path: "big.bin".to_owned(),
                change: StatChange::Binary {
                    old_len: 3_000_000,
                    new_len: 4_000_000
                }
            }]
        );
        assert_eq!(reads_of(&source, &old_chunk1), 0);
        assert_eq!(reads_of(&source, &new_chunk1), 0);
    }

    #[test]
    fn an_inline_binary_reads_each_side_once() {
        let mut source = RecordingSource::default();
        let (old, new) = (fake_hash(21), fake_hash(22));
        source.put(
            old,
            &Object::Blob(Blob {
                data: binary_bytes(b'a', 10_240),
            }),
        );
        source.put(
            new,
            &Object::Blob(Blob {
                data: binary_bytes(b'b', 12_288),
            }),
        );
        let rows = stats(&source, &[modified("f.bin", old, new)]).unwrap();
        assert_eq!(
            rows[0].change,
            StatChange::Binary {
                old_len: 10_240,
                new_len: 12_288
            }
        );
        assert_eq!((reads_of(&source, &old), reads_of(&source, &new)), (1, 1));
    }

    #[test]
    fn an_inline_text_reads_each_side_once_and_counts_lines() {
        let mut source = RecordingSource::default();
        let (old, new) = (fake_hash(23), fake_hash(24));
        source.put(
            old,
            &Object::Blob(Blob {
                data: b"one\ntwo\n".to_vec(),
            }),
        );
        source.put(
            new,
            &Object::Blob(Blob {
                data: b"one\nthree\nfour\n".to_vec(),
            }),
        );
        let rows = stats(&source, &[modified("f.txt", old, new)]).unwrap();
        assert_eq!(
            rows[0].change,
            StatChange::Text {
                added: 2,
                deleted: 1
            }
        );
        assert_eq!((reads_of(&source, &old), reads_of(&source, &new)), (1, 1));
    }

    #[test]
    fn a_pure_mode_change_has_no_lines_and_reads_nothing() {
        let source = RecordingSource::default();
        let mut entry = modified("run.sh", fake_hash(1), fake_hash(1));
        entry.kind = DiffKind::ModeChanged;
        let rows = stats(&source, &[entry.clone()]).unwrap();
        assert_eq!(
            rows[0].change,
            StatChange::Text {
                added: 0,
                deleted: 0
            }
        );
        assert_eq!(
            patch_body(&source, &entry, 3, WhitespaceMode::Exact).unwrap(),
            PatchBody::Empty
        );
        assert!(source.reads.borrow().is_empty());
    }

    #[test]
    fn a_patch_body_is_hunks_binary_or_empty() {
        let mut source = RecordingSource::default();
        let (old, new, bin) = (fake_hash(61), fake_hash(62), fake_hash(63));
        source.put(
            old,
            &Object::Blob(Blob {
                data: b"a\nb\n".to_vec(),
            }),
        );
        source.put(
            new,
            &Object::Blob(Blob {
                data: b"a\nc\n".to_vec(),
            }),
        );
        source.put(
            bin,
            &Object::Blob(Blob {
                data: binary_bytes(b'x', 100),
            }),
        );
        let hunks = patch_body(
            &source,
            &modified("f.txt", old, new),
            3,
            WhitespaceMode::Exact,
        )
        .unwrap();
        assert_eq!(
            hunks,
            PatchBody::Hunks(b"@@ -1,2 +1,2 @@\n a\n-b\n+c\n".to_vec())
        );
        assert_eq!(
            patch_body(
                &source,
                &modified("f.bin", old, bin),
                3,
                WhitespaceMode::Exact
            )
            .unwrap(),
            PatchBody::Binary
        );
        assert_eq!(
            patch_body(
                &source,
                &modified("same", old, old),
                3,
                WhitespaceMode::Exact
            )
            .unwrap(),
            PatchBody::Empty
        );
    }

    /// A chunked blob of two chunks. Only the first chunk is stored, so a
    /// read of the second fails the call. The manifest claims `total_size`.
    fn chunked_with_first_chunk_only(
        source: &mut RecordingSource,
        tag: u8,
        first: Vec<u8>,
        total_size: u64,
    ) -> (Hash, Hash) {
        let (chunk0, chunk1, manifest) = (fake_hash(tag), fake_hash(tag + 1), fake_hash(tag + 2));
        source.put(chunk0, &Object::Blob(Blob { data: first }));
        source.put(
            manifest,
            &Object::ChunkedBlob(ChunkedBlob {
                total_size,
                chunk_size: 0,
                chunks: vec![chunk0, chunk1],
            }),
        );
        (manifest, chunk1)
    }

    #[test]
    fn a_chunked_binary_patch_body_reads_no_trailing_chunk() {
        let mut source = RecordingSource::default();
        let (old, old_tail) = chunked_with_first_chunk_only(
            &mut source,
            1,
            binary_bytes(b'a', BINARY_SNIFF_LEN + 1000),
            3_000_000,
        );
        let (new, new_tail) = chunked_with_first_chunk_only(
            &mut source,
            4,
            binary_bytes(b'b', BINARY_SNIFF_LEN + 500),
            4_000_000,
        );
        let body = patch_body(
            &source,
            &modified("big.bin", old, new),
            3,
            WhitespaceMode::Exact,
        )
        .unwrap();
        assert_eq!(body, PatchBody::Binary);
        assert_eq!(reads_of(&source, &old_tail), 0);
        assert_eq!(reads_of(&source, &new_tail), 0);
    }

    #[test]
    fn a_binary_side_makes_the_pair_binary_without_reading_the_text_side() {
        let mut source = RecordingSource::default();
        let (bin, bin_tail) = chunked_with_first_chunk_only(
            &mut source,
            1,
            binary_bytes(b'a', BINARY_SNIFF_LEN + 1000),
            3_000_000,
        );
        let (text, text_tail) = chunked_with_first_chunk_only(
            &mut source,
            4,
            vec![b'x'; BINARY_SNIFF_LEN + 500],
            4_000_000,
        );
        let body = patch_body(
            &source,
            &modified("big", text, bin),
            3,
            WhitespaceMode::Exact,
        )
        .unwrap();
        assert_eq!(body, PatchBody::Binary);
        assert_eq!(reads_of(&source, &bin_tail), 0);
        assert_eq!(reads_of(&source, &text_tail), 0);
    }

    #[test]
    fn a_stored_text_above_the_memory_limit_is_refused_before_a_chunk_is_read() {
        let mut source = RecordingSource::default();
        let (old, old_tail) = chunked_with_first_chunk_only(
            &mut source,
            1,
            vec![b'a'; BINARY_SNIFF_LEN + 1000],
            worktree::MAX_FILE_BYTES + 1,
        );
        let (new, new_tail) = chunked_with_first_chunk_only(
            &mut source,
            4,
            vec![b'b'; BINARY_SNIFF_LEN + 500],
            worktree::MAX_FILE_BYTES + 1,
        );
        let err = patch_body(
            &source,
            &modified("big.txt", old, new),
            3,
            WhitespaceMode::Exact,
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                Error::ReadObject(WorktreeError::ContentTooLarge { size })
                    if size == worktree::MAX_FILE_BYTES + 1
            ),
            "got {err:?}"
        );
        // Only the sniffed prefix was read.
        assert_eq!(reads_of(&source, &old_tail), 0);
        assert_eq!(reads_of(&source, &new_tail), 0);
    }

    #[test]
    fn a_missing_blob_is_a_read_error() {
        let source = RecordingSource::default();
        let err = patch_body(
            &source,
            &modified("f", fake_hash(1), fake_hash(2)),
            3,
            WhitespaceMode::Exact,
        )
        .unwrap_err();
        assert!(matches!(err, Error::ReadObject(_)), "got {err:?}");
        assert!(err.to_string().starts_with("read object: "));
    }
}

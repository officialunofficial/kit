//! Branches: create, delete, rename, list and set the upstream.
//!
//! Each operation takes the [`RepoLayout`] of the tree that runs it. A
//! branch write goes through the ref writers of `kit-core`, so a build with
//! `history-mmr` publishes and drops the ancestry of the branch with it.
//!
//! [`delete`] and [`rename`] take the registry lock from [`crate::lock`] for
//! their whole run. A branch has one writer at a time, and the lock keeps a
//! concurrent `checkout` or `worktree add` from taking the branch between the
//! check and the change.
//!
//! [`set_upstream`] and [`unset_upstream`] change the `branch.<name>.remote`
//! and `branch.<name>.merge` keys of the repo config, the keys that a first
//! push with `-u` writes.
//!
//! [`glob_match`] is the name pattern of [`list`]. [`list`] can also keep the
//! branches whose tips contain, or are merged into, a commit.

use std::path::PathBuf;

use kit_core::hash::Hash;
use kit_core::layout::RepoLayout;
use kit_core::object::Object;
use kit_core::observer::Observer;
use kit_core::ops::graph::AncestorError;
use kit_core::ops::merge::is_ancestor_strict;
use kit_core::refs::{self, Head, Ref, RefError, RefWriteCondition};
use kit_core::store::{ObjectStore, StoreError};

use crate::config::{self, ConfigError, ConfigEvent, Upstream};
use crate::{Environment, lock, revspec, worktrees};

/// Errors from a branch operation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// `HEAD` has no commit to start a branch from.
    #[error("no HEAD commit to branch from")]
    NoHeadCommit,
    /// The branch exists already.
    #[error("branch '{0}' already exists")]
    AlreadyExists(String),
    /// A branch ref could not be written.
    #[error("write {name}: {source}")]
    Write {
        /// The branch.
        name: String,
        /// Why the write failed.
        source: RefError,
    },
    /// The branch does not exist.
    #[error("branch '{0}' not found")]
    NotFound(String),
    /// A branch ref could not be read.
    #[error("read {name}: {source}")]
    Read {
        /// The branch.
        name: String,
        /// Why the read failed.
        source: RefError,
    },
    /// A branch ref could not be deleted.
    #[error("delete {name}: {source}")]
    Delete {
        /// The branch.
        name: String,
        /// Why the delete failed.
        source: RefError,
    },
    /// A sibling tree has the branch checked out.
    #[error("branch '{branch}' is checked out at '{}'", at.display())]
    CheckedOut {
        /// The branch.
        branch: String,
        /// The root of the tree that has it.
        at: PathBuf,
    },
    /// `HEAD` is detached and the rename named one branch only.
    #[error("cannot rename: HEAD is detached (specify <old> <new>)")]
    DetachedHead,
    /// The source branch moved while it was renamed. The rename was undone.
    #[error("branch '{0}' moved while renaming (a concurrent commit?) — rename aborted, re-run")]
    MovedWhileRenaming(String),
    /// The source branch moved while it was renamed, and the new name could
    /// not be removed again.
    #[error(
        "branch '{old}' moved while renaming (a concurrent commit?) — rename aborted, but rolling back the partially-created '{new}' also failed: {source}; run `kit branch -d {new}` manually, then re-run the rename"
    )]
    RollbackFailed {
        /// The source branch.
        old: String,
        /// The new name that is left behind.
        new: String,
        /// Why the removal failed.
        source: RefError,
    },
    /// `HEAD` could not move to the new name.
    #[error("update HEAD to {name}: {source}")]
    UpdateHead {
        /// The new name.
        name: String,
        /// Why the write failed.
        source: RefError,
    },
    /// The branch refs could not be listed.
    #[error("list refs: {0}")]
    ListRefs(RefError),
    /// The object store cannot be opened.
    #[error("open store: {0}")]
    OpenStore(StoreError),
    /// A revision of a filter does not resolve.
    #[error("bad revision '{spec}': {source}")]
    BadRevision {
        /// The revision text.
        spec: String,
        /// Why it does not resolve.
        source: revspec::Error,
    },
    /// A revision of a filter names an object that is not a commit.
    #[error("not a commit: '{0}'")]
    NotACommit(String),
    /// The object of a revision of a filter cannot be read.
    #[error("read '{spec}': {source}")]
    ReadRevision {
        /// The revision text.
        spec: String,
        /// Why the object cannot be read.
        source: StoreError,
    },
    /// The ancestry of two commits cannot be found: the walk reached its
    /// limit.
    #[error("ancestry: {0}")]
    Ancestry(StoreError),
    /// A commit of the history is missing or corrupt, or a parent is not a
    /// commit. The error names it.
    #[error("ancestry: {0}")]
    History(AncestorError),
    /// The trees of the repository cannot be read.
    #[error(transparent)]
    Worktrees(#[from] worktrees::Error),
    /// The registry lock cannot be taken.
    #[error(transparent)]
    Lock(#[from] lock::Error),
    /// `HEAD` is detached and no branch was named.
    #[error("HEAD is detached (name the branch)")]
    NoCurrentBranch,
    /// The requested upstream is not a remote-tracking branch that exists.
    #[error("the requested upstream branch '{0}' does not exist")]
    UpstreamNotFound(String),
    /// The branch has no upstream in the repo config.
    #[error("branch '{0}' has no upstream information")]
    NoUpstream(String),
    /// The config cannot be read or written.
    #[error("config: {0}")]
    Config(#[from] ConfigError),
}

/// Start a branch at `HEAD`.
///
/// # Errors
/// [`Error::NoHeadCommit`] when `HEAD` has no commit. [`Error::AlreadyExists`]
/// when the branch exists. [`Error::Write`] when the write fails.
pub fn create(layout: &RepoLayout, name: &str) -> Result<(), Error> {
    let Ok(Some(head)) = refs::resolve_head(layout) else {
        return Err(Error::NoHeadCommit);
    };
    // `Missing` refuses to replace a branch of the same name.
    refs::write_ref_recording_history(layout, name, RefWriteCondition::Missing, &head).map_err(
        |source| match source {
            RefError::Conflict(_) => Error::AlreadyExists(name.to_owned()),
            source => Error::Write {
                name: name.to_owned(),
                source,
            },
        },
    )
}

/// Delete a branch. Return the commit that it pointed at, when it had one.
///
/// The operation refuses the branch that `HEAD` names, because `HEAD` would
/// dangle. It refuses a branch that a sibling tree has checked out. Kit keeps
/// no per-branch merge state, so no check of merge status exists.
///
/// # Errors
/// [`Error::Lock`], [`Error::Worktrees`] or [`Error::CheckedOut`] when the
/// branch cannot go. [`Error::NotFound`] when it does not exist.
/// [`Error::Delete`] on any other failure.
pub fn delete(
    layout: &RepoLayout,
    name: &str,
    observer: &dyn Observer<lock::Event>,
) -> Result<Option<Hash>, Error> {
    let was = refs::read_ref(layout, name).ok().flatten();
    let _registry = lock::acquire_registry(layout, observer)?;
    refuse_if_checked_out(layout, name)?;
    match delete_ref_recording_history(layout, name) {
        Ok(()) => Ok(was),
        Err(RefError::NotFound(_)) => Err(Error::NotFound(name.to_owned())),
        Err(source) => Err(Error::Delete {
            name: name.to_owned(),
            source,
        }),
    }
}

/// Rename `old` to `new`. With no `old`, rename the branch that `HEAD` names.
/// `HEAD` follows the rename when it names the renamed branch.
///
/// The operation writes the new name first and refuses to replace a branch.
/// Then it deletes the old name only if the tip is still the one it read, so
/// a concurrent commit is never lost. A failed delete removes the new name
/// again.
///
/// # Errors
/// [`Error::DetachedHead`], [`Error::NotFound`], [`Error::Lock`],
/// [`Error::Worktrees`], [`Error::CheckedOut`], [`Error::AlreadyExists`],
/// [`Error::MovedWhileRenaming`], [`Error::RollbackFailed`],
/// [`Error::UpdateHead`], or a read, write or delete failure.
pub fn rename(
    layout: &RepoLayout,
    old: Option<&str>,
    new: &str,
    observer: &dyn Observer<lock::Event>,
) -> Result<(), Error> {
    let old = match old {
        Some(old) => old.to_owned(),
        None => match refs::read_head(layout) {
            Ok(Head::Branch(current)) => current,
            _ => return Err(Error::DetachedHead),
        },
    };
    if old == new {
        return Ok(());
    }

    let hash = match refs::read_ref(layout, &old) {
        Ok(Some(hash)) => hash,
        Ok(None) => return Err(Error::NotFound(old)),
        Err(source) => return Err(Error::Read { name: old, source }),
    };

    // A sibling tree must not lose the branch from under its `HEAD`. The
    // tree that runs the rename is fine, because `HEAD` moves below.
    let _registry = lock::acquire_registry(layout, observer)?;
    refuse_if_checked_out(layout, &old)?;

    // Write the new name first, so a failure never loses the tip.
    refs::write_ref_recording_history(layout, new, RefWriteCondition::Missing, &hash).map_err(
        |source| match source {
            RefError::Conflict(_) => Error::AlreadyExists(new.to_owned()),
            source => Error::Write {
                name: new.to_owned(),
                source,
            },
        },
    )?;

    // `hash` is the tip from before the new name existed. A concurrent
    // commit may have moved `old` since. The delete then sees another value
    // and refuses, so the commit keeps a ref.
    match delete_ref_dropping_history_if_matches(layout, &old, hash) {
        Ok(()) => {}
        Err(RefError::Conflict(_)) => {
            // The new name has the value `hash`: it was written with
            // `Missing`. A guarded delete reports a concurrent write to it
            // instead of replacing it.
            return Err(
                match delete_ref_dropping_history_if_matches(layout, new, hash) {
                    Ok(()) => Error::MovedWhileRenaming(old),
                    Err(source) => Error::RollbackFailed {
                        old,
                        new: new.to_owned(),
                        source,
                    },
                },
            );
        }
        Err(source) => return Err(Error::Delete { name: old, source }),
    }

    if let Ok(Head::Branch(current)) = refs::read_head(layout)
        && current == old
        && let Err(source) = refs::write_head_branch(layout, new)
    {
        return Err(Error::UpdateHead {
            name: new.to_owned(),
            source,
        });
    }
    Ok(())
}

/// The local branch that a set or unset names, or the branch of `HEAD`. The
/// branch must exist.
fn existing_branch(layout: &RepoLayout, name: Option<&str>) -> Result<String, Error> {
    let name = match name {
        Some(name) => name.to_owned(),
        None => current(layout).ok_or(Error::NoCurrentBranch)?,
    };
    match refs::read_ref(layout, &name) {
        Ok(Some(_)) => Ok(name),
        Ok(None) => Err(Error::NotFound(name)),
        Err(source) => Err(Error::Read { name, source }),
    }
}

/// Make `upstream`, a remote-tracking branch written `<remote>/<branch>`, the
/// upstream of `branch`, or of the branch of `HEAD` when `branch` is `None`.
/// Return the branch that changed and its new upstream.
///
/// The remote-tracking ref must exist. A remote name may hold a `/`, so the
/// call tries each split of `upstream` from the left, and the first split
/// whose ref exists is the one in use. The call
/// changes the repo layer of the config only, as [`crate::push::record_upstream`]
/// does, and it replaces an upstream that is set already.
///
/// # Errors
/// [`Error::NoCurrentBranch`] for a detached `HEAD` with no branch named.
/// [`Error::NotFound`] when the branch does not exist.
/// [`Error::UpstreamNotFound`] when no remote-tracking ref matches.
/// [`Error::Config`] when the config cannot be read or written.
pub fn set_upstream(
    layout: &RepoLayout,
    environment: &Environment,
    observer: &dyn Observer<ConfigEvent>,
    branch: Option<&str>,
    upstream: &str,
) -> Result<(String, Upstream), Error> {
    let branch = existing_branch(layout, branch)?;
    let found = upstream
        .match_indices('/')
        .map(|(at, _)| (&upstream[..at], &upstream[at + 1..]))
        .filter(|(remote, name)| !remote.is_empty() && !name.is_empty())
        .find(|(remote, name)| matches!(refs::read_remote_ref(layout, remote, name), Ok(Some(_))));
    let Some((remote, name)) = found else {
        return Err(Error::UpstreamNotFound(upstream.to_owned()));
    };
    let upstream = Upstream {
        remote: remote.to_owned(),
        branch: name.to_owned(),
    };
    let mut repo = config::read_layered(layout, environment, observer)?.repo;
    repo.branch_upstreams
        .insert(branch.clone(), upstream.clone());
    config::write(layout, &repo)?;
    Ok((branch, upstream))
}

/// Remove the upstream of `branch`, or of the branch of `HEAD` when `branch`
/// is `None`, from the repo config. Return the branch that changed.
///
/// # Errors
/// [`Error::NoCurrentBranch`] for a detached `HEAD` with no branch named.
/// [`Error::NotFound`] when the branch does not exist. [`Error::NoUpstream`]
/// when the repo config holds no upstream for it. [`Error::Config`] when the
/// config cannot be read or written.
pub fn unset_upstream(
    layout: &RepoLayout,
    environment: &Environment,
    observer: &dyn Observer<ConfigEvent>,
    branch: Option<&str>,
) -> Result<String, Error> {
    let branch = existing_branch(layout, branch)?;
    let mut repo = config::read_layered(layout, environment, observer)?.repo;
    if repo.branch_upstreams.remove(&branch).is_none() {
        return Err(Error::NoUpstream(branch));
    }
    config::write(layout, &repo)?;
    Ok(branch)
}

/// The branch that `HEAD` names. `None` for a detached or unreadable `HEAD`.
#[must_use]
pub fn current(layout: &RepoLayout) -> Option<String> {
    match refs::read_head(layout) {
        Ok(Head::Branch(name)) => Some(name),
        _ => None,
    }
}

/// Which branches to list, and what to read for each.
///
/// A branch must pass every filter that is set. A filter value is a revision.
/// It must name a commit, or a tag of a commit.
#[derive(Debug, Clone, Copy, Default)]
pub struct Query<'a> {
    /// Which branches to list: local, remote-tracking or both.
    pub scope: Scope,
    /// Keep a branch whose name matches any of these patterns, as
    /// [`glob_match`] reads them. No pattern keeps every branch.
    pub patterns: &'a [String],
    /// Keep the branches whose tips contain this commit.
    pub contains: Option<&'a str>,
    /// Keep the branches whose tips do not contain this commit.
    pub no_contains: Option<&'a str>,
    /// Keep the branches that are merged into this commit.
    pub merged: Option<&'a str>,
    /// Keep the branches that are not merged into this commit.
    pub no_merged: Option<&'a str>,
    /// Read the subject of each tip.
    pub subjects: bool,
}

/// The branches that a listing covers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Scope {
    /// The local branches, named `<branch>`.
    #[default]
    Local,
    /// The remote-tracking branches, named `<remote>/<branch>`.
    Remote,
    /// The local branches, then the remote-tracking branches named
    /// `remotes/<remote>/<branch>`.
    All,
}

impl Query<'_> {
    fn has_ancestry_filter(&self) -> bool {
        self.contains.is_some()
            || self.no_contains.is_some()
            || self.merged.is_some()
            || self.no_merged.is_some()
    }
}

/// One listed branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Branch {
    /// The branch name.
    pub name: String,
    /// The tip, when the ref holds one.
    pub hash: Option<Hash>,
    /// The branch is a remote-tracking branch.
    pub remote: bool,
    /// The first line of the message of the tip. `Some` only when the query
    /// asked for subjects and the branch has a tip. It is empty when the tip
    /// is not a commit or a remix.
    pub subject: Option<String>,
}

/// List the branches that `query` keeps, in the order of the ref store.
///
/// # Errors
/// [`Error::ListRefs`] when the refs cannot be read. [`Error::OpenStore`]
/// when the query needs the store and it cannot be opened. A filter that does
/// not resolve gives [`Error::BadRevision`], [`Error::ReadRevision`] or
/// [`Error::NotACommit`]. [`Error::History`] when a commit of an ancestry
/// walk cannot be read, and [`Error::Ancestry`] when the walk reaches its
/// limit.
pub fn list(layout: &RepoLayout, query: &Query<'_>) -> Result<Vec<Branch>, Error> {
    let mut branches: Vec<(Ref, bool)> = Vec::new();
    if query.scope != Scope::Remote {
        branches.extend(
            list_refs(layout)
                .map_err(Error::ListRefs)?
                .into_iter()
                .map(|r| (r, false)),
        );
    }
    if query.scope != Scope::Local {
        let prefix = if query.scope == Scope::All {
            "remotes/"
        } else {
            ""
        };
        for remote in refs::list_remote_names(layout).map_err(Error::ListRefs)? {
            for r in refs::list_remote_refs(layout, &remote).map_err(Error::ListRefs)? {
                branches.push((
                    Ref {
                        name: format!("{prefix}{remote}/{}", r.name),
                        hash: r.hash,
                    },
                    true,
                ));
            }
        }
    }

    // Cut by name first, so no commit of an excluded branch is read.
    if !query.patterns.is_empty() {
        branches.retain(|(r, _)| query.patterns.iter().any(|p| glob_match(p, &r.name)));
    }

    let store = if query.subjects || query.has_ancestry_filter() {
        Some(ObjectStore::open(layout).map_err(Error::OpenStore)?)
    } else {
        None
    };

    if query.has_ancestry_filter()
        && let Some(store) = &store
    {
        let filter = Filter::resolve(store, layout, query)?;
        let mut kept = Vec::with_capacity(branches.len());
        for entry in branches {
            // A ref with no tip cannot pass a commit filter.
            if let Some(tip) = &entry.0.hash
                && filter.keeps(store, tip)?
            {
                kept.push(entry);
            }
        }
        branches = kept;
    }

    Ok(branches
        .into_iter()
        .map(|(r, remote)| {
            let subject = match (&store, &r.hash) {
                (Some(store), Some(tip)) if query.subjects => Some(tip_subject(store, tip)),
                _ => None,
            };
            Branch {
                name: r.name,
                hash: r.hash,
                remote,
                subject,
            }
        })
        .collect())
}

/// The ancestry filters of a query, resolved to commits.
struct Filter {
    contains: Option<Hash>,
    no_contains: Option<Hash>,
    merged: Option<Hash>,
    no_merged: Option<Hash>,
}

impl Filter {
    fn resolve(store: &ObjectStore, layout: &RepoLayout, query: &Query<'_>) -> Result<Self, Error> {
        let one = |spec: Option<&str>| spec.map(|s| commit_of(store, layout, s)).transpose();
        Ok(Self {
            contains: one(query.contains)?,
            no_contains: one(query.no_contains)?,
            merged: one(query.merged)?,
            no_merged: one(query.no_merged)?,
        })
    }

    /// Whether `tip` passes every filter that is set. `contains C` keeps tips
    /// that have C as an ancestor. `merged M` keeps tips that are ancestors
    /// of M. The `no_*` forms are the complements.
    fn keeps(&self, store: &ObjectStore, tip: &Hash) -> Result<bool, Error> {
        // A missing commit would turn "ancestor" into "not an ancestor" and
        // keep or drop a branch wrongly, so the walk reads every commit.
        let ancestor = |a: Hash, d: Hash| {
            is_ancestor_strict(store, a, d).map_err(|e| match e {
                AncestorError::Limit(limit) => Error::Ancestry(limit),
                other => Error::History(other),
            })
        };
        if let Some(c) = self.contains
            && !ancestor(c, *tip)?
        {
            return Ok(false);
        }
        if let Some(c) = self.no_contains
            && ancestor(c, *tip)?
        {
            return Ok(false);
        }
        if let Some(m) = self.merged
            && !ancestor(*tip, m)?
        {
            return Ok(false);
        }
        if let Some(m) = self.no_merged
            && ancestor(*tip, m)?
        {
            return Ok(false);
        }
        Ok(true)
    }
}

/// Resolve `spec` to a commit and peel annotated tags.
///
/// A tree or a blob would pass as a commit with no parents and filter every
/// branch wrongly, so the object must be a commit.
fn commit_of(store: &ObjectStore, layout: &RepoLayout, spec: &str) -> Result<Hash, Error> {
    let hash =
        revspec::resolve_revision(store, layout, spec).map_err(|source| Error::BadRevision {
            spec: spec.to_owned(),
            source,
        })?;
    let hash = revspec::peel_tags(store, hash);
    match store.read_object(&hash) {
        Ok(Object::Commit(_)) => Ok(hash),
        Ok(_) => Err(Error::NotACommit(spec.to_owned())),
        Err(source) => Err(Error::ReadRevision {
            spec: spec.to_owned(),
            source,
        }),
    }
}

/// The first line of the message of a commit or remix. Empty when the tip
/// cannot be read or has another kind: a subject is a display aid and must not
/// fail a listing.
fn tip_subject(store: &ObjectStore, tip: &Hash) -> String {
    let message = match store.read_object(tip) {
        Ok(Object::Commit(c)) => c.message,
        Ok(Object::Remix(r)) => r.message,
        _ => return String::new(),
    };
    String::from_utf8_lossy(&message)
        .lines()
        .next()
        .unwrap_or("")
        .to_owned()
}

/// The branches of the repository. With `sync`, the read of each ref runs in
/// parallel once there is enough work.
#[cfg(feature = "sync")]
fn list_refs(layout: &RepoLayout) -> Result<Vec<Ref>, RefError> {
    refs::list_refs_with(layout, kit_sync::worktree::fanout_read_batch)
}

#[cfg(not(feature = "sync"))]
fn list_refs(layout: &RepoLayout) -> Result<Vec<Ref>, RefError> {
    refs::list_refs(layout)
}

/// Refuse a branch that a sibling tree has checked out.
fn refuse_if_checked_out(layout: &RepoLayout, branch: &str) -> Result<(), Error> {
    match worktrees::checked_out_elsewhere(layout, branch)? {
        Some(at) => Err(Error::CheckedOut {
            branch: branch.to_owned(),
            at,
        }),
        None => Ok(()),
    }
}

/// Delete a branch that `HEAD` does not name. With `history-mmr`, the ancestry
/// pointer of the branch goes with it. The earlier snapshots stay. A later
/// branch of the same name gets a new generation.
fn delete_ref_recording_history(layout: &RepoLayout, branch: &str) -> Result<(), RefError> {
    #[cfg(feature = "history-mmr")]
    {
        if matches!(refs::read_head(layout)?, Head::Branch(current) if current == branch) {
            return Err(RefError::CurrentBranch(branch.to_owned()));
        }
        let store = ObjectStore::open(layout).map_err(|e| RefError::InvalidRef(e.to_string()))?;
        refs::delete_ref_with_ancestry(layout, branch, None, &store)
    }
    #[cfg(not(feature = "history-mmr"))]
    {
        refs::delete_ref_safe(layout, branch)
    }
}

/// Delete a ref only when its tip is still `expected`. With `history-mmr`,
/// the ancestry pointer goes with it. A rename uses this to remove the old
/// name, and to undo the new name, without deleting a concurrent advance.
fn delete_ref_dropping_history_if_matches(
    layout: &RepoLayout,
    branch: &str,
    expected: Hash,
) -> Result<(), RefError> {
    #[cfg(feature = "history-mmr")]
    {
        let store = ObjectStore::open(layout).map_err(|e| RefError::InvalidRef(e.to_string()))?;
        refs::delete_ref_with_ancestry(layout, branch, Some(expected), &store)
    }
    #[cfg(not(feature = "history-mmr"))]
    {
        refs::delete_ref_if_matches(layout, branch, expected)
    }
}

/// Shell-glob match, as `git branch --list` reads a pattern.
///
/// - `*` matches any run, `/` included, so `feature/*` works.
/// - `?` matches one character.
/// - `[...]` is a class: `[a-z]`, and a leading `!` or `^` negates it. A `[`
///   with no closing `]` is a plain `[`.
/// - A backslash escapes the next character.
///
/// A pattern with no metacharacter must match the whole name. The match takes
/// time in proportion to the product of the two lengths at most.
#[must_use]
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    // Backtrack point for the most recent `*`.
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        let advanced = if pi < p.len() {
            match p[pi] {
                '*' => {
                    star = Some((pi, ti));
                    pi += 1;
                    true
                }
                '?' => {
                    pi += 1;
                    ti += 1;
                    true
                }
                '[' => match match_class(&p, pi, t[ti]) {
                    Some((matched, next_pi)) if matched => {
                        pi = next_pi;
                        ti += 1;
                        true
                    }
                    Some(_) => false, // well-formed class, no match
                    None => {
                        // Malformed class — treat `[` literally.
                        if t[ti] == '[' {
                            pi += 1;
                            ti += 1;
                            true
                        } else {
                            false
                        }
                    }
                },
                '\\' if pi + 1 < p.len() => {
                    if p[pi + 1] == t[ti] {
                        pi += 2;
                        ti += 1;
                        true
                    } else {
                        false
                    }
                }
                c => {
                    if c == t[ti] {
                        pi += 1;
                        ti += 1;
                        true
                    } else {
                        false
                    }
                }
            }
        } else {
            false
        };
        if advanced {
            continue;
        }
        // Mismatch: backtrack to the last `*`, extending what it consumed.
        match star {
            Some((sp, st)) => {
                pi = sp + 1;
                ti = st + 1;
                star = Some((sp, st + 1));
            }
            None => return false,
        }
    }
    // Trailing `*`s match the empty remainder.
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Match a bracket class that starts at `p[start]` (the opening bracket)
/// against `ch`. Return `Some((matched, next_index))` for a well-formed class,
/// where `next_index` is just past the closing bracket. Return `None` when
/// there is no closing bracket.
fn match_class(p: &[char], start: usize, ch: char) -> Option<(bool, usize)> {
    let mut i = start + 1;
    let mut negate = false;
    if i < p.len() && (p[i] == '!' || p[i] == '^') {
        negate = true;
        i += 1;
    }
    let mut matched = false;
    let mut first = true;
    while i < p.len() {
        if p[i] == ']' && !first {
            return Some((matched ^ negate, i + 1));
        }
        if i + 2 < p.len() && p[i + 1] == '-' && p[i + 2] != ']' {
            if ch >= p[i] && ch <= p[i + 2] {
                matched = true;
            }
            i += 3;
        } else {
            if p[i] == ch {
                matched = true;
            }
            i += 1;
        }
        first = false;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::glob_match;

    #[test]
    fn literal_matches_whole_name() {
        assert!(glob_match("main", "main"));
        assert!(!glob_match("main", "maintenance"));
        assert!(!glob_match("main", " main"));
    }

    #[test]
    fn star_matches_any_run_including_slash() {
        assert!(glob_match("feat*", "feature"));
        assert!(glob_match("feature/*", "feature/login"));
        // `*` spans `/`, matching git's non-pathname wildmatch.
        assert!(glob_match("*", "any/branch/name"));
        assert!(glob_match("*login", "feature/login"));
        assert!(!glob_match("feature/*", "main"));
    }

    #[test]
    fn question_matches_single_char() {
        assert!(glob_match("v?", "v1"));
        assert!(!glob_match("v?", "v10"));
    }

    #[test]
    fn char_classes_and_negation() {
        assert!(glob_match("v[0-9]", "v3"));
        assert!(!glob_match("v[0-9]", "vx"));
        assert!(glob_match("v[!0-9]", "vx"));
        assert!(!glob_match("v[!0-9]", "v3"));
    }

    #[test]
    fn backslash_escapes_metacharacter() {
        assert!(glob_match(r"feat\*", "feat*"));
        assert!(!glob_match(r"feat\*", "feature"));
    }

    #[test]
    fn star_backtracks() {
        assert!(glob_match("a*b*c", "axxbyyc"));
        assert!(!glob_match("a*b*c", "axxbyy"));
    }

    #[test]
    fn an_unclosed_class_is_a_literal_bracket() {
        assert!(glob_match("a[b", "a[b"));
        assert!(!glob_match("a[b", "ab"));
    }
}

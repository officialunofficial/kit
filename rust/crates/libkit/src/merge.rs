//! Merge a branch into `HEAD`, with a workflow for conflicts.
//!
//! [`start`] resolves the target and finds the merge base. When `HEAD` is the
//! base, it moves `HEAD` forward to the target. Otherwise it runs a three-way
//! merge of the trees. A merge with conflicts writes the conflict material
//! with [`crate::conflict::materialize`], records the state that
//! [`resume`] and [`abort`] need, and returns [`Outcome::Conflicted`]. A merge
//! without conflicts signs a commit with two parents and moves the current
//! branch to it.
//!
//! [`resume`] refuses while a text conflict still has markers or a resolution
//! is not staged. It builds the final tree from the resolved index. [`abort`]
//! puts `HEAD`, the branch, the index and the files back to the state before
//! the merge, and clears the recorded state.
//!
//! The caller holds the worktree lock for the whole run. See [`crate::lock`].

use std::time::{SystemTime, UNIX_EPOCH};

use kit_core::hash::Hash;
use kit_core::layout::RepoLayout;
use kit_core::object::{KitError, Object};
use kit_core::observer::Observer;
use kit_core::ops::conflict_state::{
    self, ConflictRecord, ConflictStateError, MergeState, in_progress_op_name, is_merge_in_progress,
};
use kit_core::ops::merge::{find_merge_base, merge_trees};
use kit_core::refs::{self, RefError, RefWriteCondition};
use kit_core::store::{ObjectStore, StoreError};
use kit_core::worktree::{self, WorktreeError};
use kit_sync::worktree::{
    ensure_restore_safe, read_or_seed_index_from_head, restore_worktree_and_index,
    sync_index_to_tree,
};

use crate::signing::{self, Author, Signing, WriteError, write_signed};
use crate::{conflict, head, revspec};

/// Errors from a merge.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Another merge, cherry-pick, revert or rebase is unfinished.
    #[error("a {0} is already in progress (use --continue or --abort)")]
    InProgress(&'static str),
    /// `HEAD` has no commit to merge into.
    #[error("no commits on current branch")]
    NoHeadCommit,
    /// `HEAD` cannot be resolved.
    #[error("resolve HEAD: {0}")]
    ResolveHead(RefError),
    /// The target does not resolve.
    #[error("merge target: {0}")]
    Target(revspec::Error),
    /// The merge base cannot be found.
    #[error("find merge base: {0}")]
    MergeBase(StoreError),
    /// An object that must be a commit is another kind of object.
    #[error("object is not a commit")]
    NotACommit,
    /// A commit cannot be read.
    #[error("read commit: {0}")]
    ReadCommit(StoreError),
    /// The trees cannot be merged.
    #[error("merge: {0}")]
    Merge(StoreError),
    /// A restore primitive of the worktree failed. The text is final.
    #[error("{0}")]
    Worktree(String),
    /// `HEAD` cannot move to the new commit.
    #[error("{0}")]
    AdvanceHead(head::Error),
    /// `HEAD` cannot go back to the commit before the merge.
    #[error("{0}")]
    RestoreHead(head::Error),
    /// The state of the merge cannot be written.
    #[error("write merge state: {0}")]
    WriteState(ConflictStateError),
    /// No merge is in progress.
    #[error("no merge in progress")]
    NoMergeInProgress,
    /// The state of the merge cannot be read.
    #[error("read merge state: {0}")]
    ReadState(ConflictStateError),
    /// The conflict records cannot be read.
    #[error("read conflicts: {0}")]
    ReadConflicts(ConflictStateError),
    /// A conflicting file still holds markers.
    #[error("unresolved conflict markers remain in '{0}'; resolve and `kit add` it")]
    UnresolvedMarkers(String),
    /// The tree of the resolved index cannot be built.
    #[error("build tree from index: {0}")]
    BuildTree(WorktreeError),
    /// The state of the merge cannot be cleared.
    #[error("clear merge state: {0}")]
    ClearState(ConflictStateError),
    /// The conflict workflow failed.
    #[error(transparent)]
    Conflict(#[from] conflict::Error),
    /// The key or the author identity is not usable.
    #[error(transparent)]
    Signing(#[from] signing::Error),
    /// The merge commit cannot be encoded.
    #[error("serialize: {0}")]
    Serialize(KitError),
    /// The merge commit cannot be stored.
    #[error("store commit: {0}")]
    StoreCommit(StoreError),
}

/// What to merge.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// A branch, tag, remote-tracking ref, hash or other revision. An
    /// annotated tag peels to its commit.
    pub target: &'a str,
    /// Stage the merged tree and record the merge, but write no commit. A
    /// fast-forward ignores this.
    pub no_commit: bool,
    /// The message of the merge commit. Without it the message is
    /// `Merge branch '<target>'`, or `Merge remote-tracking branch
    /// '<remote>/<branch>'` for a remote-tracking ref.
    pub message: Option<&'a str>,
}

/// A merge commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Merged {
    /// The merge commit.
    pub commit: Hash,
    /// The first parent, the tip of the branch before the merge.
    pub ours: Hash,
    /// The second parent, the merged tip.
    pub theirs: Hash,
    /// The tree of the merge commit.
    pub tree: Hash,
}

/// How a merge that started has ended.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Outcome {
    /// `HEAD` is the target already.
    UpToDate {
        /// The commit of both.
        head: Hash,
    },
    /// `HEAD` was an ancestor of the target and moved to it.
    FastForward {
        /// `HEAD` before.
        old: Hash,
        /// `HEAD` after.
        new: Hash,
    },
    /// The merge paused for conflicts. The material is in the index and the
    /// files, and the state is on disk.
    Conflicted {
        /// One record for each conflicting path.
        conflicts: Vec<ConflictRecord>,
    },
    /// The merge is staged and recorded, and no commit exists.
    Staged {
        /// The tree of the merge result.
        tree: Hash,
    },
    /// The merge wrote a commit and moved the branch to it.
    Merged(Merged),
}

fn commit_tree(store: &ObjectStore, commit: Hash) -> Result<Hash, Error> {
    match store.read_object(&commit) {
        Ok(Object::Commit(c)) => Ok(c.tree_hash),
        Ok(_) => Err(Error::NotACommit),
        Err(e) => Err(Error::ReadCommit(e)),
    }
}

/// Merge `request.target` into `HEAD`.
///
/// A commit takes its signer from `signing`. The function asks for it only
/// when it is about to write a commit, so a merge that needs no commit loads
/// no key.
///
/// # Errors
/// [`Error::InProgress`] when another operation is unfinished. [`Error`] when
/// a revision, the store, the files or the key fail.
#[allow(clippy::too_many_lines)] // one linear sequence of guarded steps
pub fn start(
    layout: &RepoLayout,
    store: &ObjectStore,
    request: &Request<'_>,
    signing: &dyn Signing,
    observer: &dyn Observer<conflict::Event>,
) -> Result<Outcome, Error> {
    if let Some(op) = in_progress_op_name(layout) {
        return Err(Error::InProgress(op));
    }

    let ours = match refs::resolve_head(layout) {
        Ok(Some(h)) => h,
        Ok(None) => return Err(Error::NoHeadCommit),
        Err(e) => return Err(Error::ResolveHead(e)),
    };
    // Any revision is a valid target. A branch name keeps its precedence,
    // because the resolver checks the branches first.
    let theirs = revspec::resolve_revision(store, layout, request.target)
        .map(|h| revspec::peel_tags(store, h))
        .map_err(Error::Target)?;

    if ours == theirs {
        return Ok(Outcome::UpToDate { head: ours });
    }

    let base = find_merge_base(store, ours, theirs).map_err(Error::MergeBase)?;

    if base == Some(ours) {
        let theirs_tree = commit_tree(store, theirs)?;
        ensure_restore_safe(layout, store, theirs_tree).map_err(Error::Worktree)?;
        restore_worktree_and_index(layout, store, theirs_tree).map_err(Error::Worktree)?;
        head::advance(layout, &theirs, RefWriteCondition::Any).map_err(Error::AdvanceHead)?;
        return Ok(Outcome::FastForward {
            old: ours,
            new: theirs,
        });
    }

    let ours_tree = commit_tree(store, ours)?;
    let theirs_tree = commit_tree(store, theirs)?;
    let base_tree = base.map(|b| commit_tree(store, b)).transpose()?;

    let result =
        merge_trees(store, base_tree, Some(ours_tree), Some(theirs_tree)).map_err(Error::Merge)?;

    let message = match request.message {
        Some(m) => m.to_owned(),
        None if is_remote_tracking(layout, request.target) => {
            let short = request
                .target
                .strip_prefix("refs/remotes/")
                .unwrap_or(request.target);
            format!("Merge remote-tracking branch '{short}'")
        }
        None => format!("Merge branch '{}'", request.target),
    };
    let state = MergeState {
        merge_head: theirs,
        orig_head: ours,
        message: message.clone().into_bytes(),
    };

    if result.has_conflicts() {
        // Never overwrite dirty tracked files or untracked collisions.
        ensure_restore_safe(layout, store, result.tree_hash).map_err(Error::Worktree)?;
        let records =
            conflict::materialize(layout, store, result.tree_hash, &result.conflicts, observer)?;
        conflict_state::write_merge_state(layout, &state, &records).map_err(Error::WriteState)?;
        // The result tree lets an abort treat the clean hunks of the merge,
        // and not only the conflict paths, as material to discard.
        conflict_state::write_result_tree(layout.worktree_state_dir(), &result.tree_hash)
            .map_err(Error::WriteState)?;
        return Ok(Outcome::Conflicted { conflicts: records });
    }

    ensure_restore_safe(layout, store, result.tree_hash).map_err(Error::Worktree)?;

    if request.no_commit {
        restore_worktree_and_index(layout, store, result.tree_hash).map_err(Error::Worktree)?;
        // A tree cannot hold a deletion. Without a removal entry, a merge
        // that only deletes files would leave an empty index, and a continue
        // or an abort would seed it from the old tree of `HEAD`.
        conflict::stage_removals(layout, store, Some(ours_tree), result.tree_hash)?;
        conflict_state::write_merge_state(layout, &state, &[]).map_err(Error::WriteState)?;
        // The result tree tells the staged merge, which an abort discards,
        // from the work that the user staged on top of it.
        conflict_state::write_result_tree(layout.worktree_state_dir(), &result.tree_hash)
            .map_err(Error::WriteState)?;
        return Ok(Outcome::Staged {
            tree: result.tree_hash,
        });
    }

    let commit = create_merge_commit(
        layout,
        store,
        signing,
        result.tree_hash,
        ours,
        theirs,
        message.as_bytes(),
    )?;
    restore_worktree_and_index(layout, store, result.tree_hash).map_err(Error::Worktree)?;
    head::advance(layout, &commit, RefWriteCondition::Any).map_err(Error::AdvanceHead)?;
    Ok(Outcome::Merged(Merged {
        commit,
        ours,
        theirs,
        tree: result.tree_hash,
    }))
}

/// Finish a merge that paused or was staged, after the conflicts are
/// resolved and staged.
///
/// The final tree comes from the resolved index. The files are not rewritten,
/// so an edit that the user made after staging stays.
///
/// # Errors
/// [`Error::NoMergeInProgress`] when no merge is recorded.
/// [`Error::UnresolvedMarkers`] or [`conflict::Error::NotStaged`] when a
/// resolution is not complete. [`Error`] when the store or the key fail.
pub fn resume(
    layout: &RepoLayout,
    store: &ObjectStore,
    signing: &dyn Signing,
) -> Result<Merged, Error> {
    let (state, records) = read_state(layout)?;
    if let Some(path) = conflict::first_unresolved_marker(layout.worktree_root(), &records)? {
        return Err(Error::UnresolvedMarkers(path));
    }
    conflict::ensure_staged(layout, store, &records)?;

    let idx = read_or_seed_index_from_head(layout, store).map_err(Error::Worktree)?;
    let tree = worktree::build_tree_from_index(store, &idx).map_err(Error::BuildTree)?;

    let commit = create_merge_commit(
        layout,
        store,
        signing,
        tree,
        state.orig_head,
        state.merge_head,
        &state.message,
    )?;
    // The index follows the committed tree. The files stay as they are.
    sync_index_to_tree(layout, store, tree).map_err(Error::Worktree)?;
    head::advance(layout, &commit, RefWriteCondition::Any).map_err(Error::AdvanceHead)?;
    conflict_state::clear_merge_state(layout).map_err(Error::ClearState)?;
    Ok(Merged {
        commit,
        ours: state.orig_head,
        theirs: state.merge_head,
        tree,
    })
}

/// Put `HEAD`, the branch, the index and the files back to the state before
/// the merge. Clear the recorded state. Return the commit of `HEAD`.
///
/// The function refuses, before it changes anything, when it would overwrite
/// work that is not material of the merge.
///
/// # Errors
/// [`Error::NoMergeInProgress`] when no merge is recorded. [`Error`] when the
/// guards refuse or the store or the files fail.
pub fn abort(layout: &RepoLayout, store: &ObjectStore) -> Result<Hash, Error> {
    let (state, records) = read_state(layout)?;
    let target = state.orig_head;
    let target_tree = commit_tree(store, target)?;
    // Both a merge with conflicts and a staged merge record their result
    // tree. It lets the guards treat the output of the merge, which the user
    // did not touch, as material to discard. They still protect a conflict
    // resolution, an unrelated `kit add` and an edit of a clean file.
    let op_result = conflict_state::read_result_tree(layout.worktree_state_dir())
        .ok()
        .flatten();
    // Refuse before the reset. The reset destroys the material of the merge.
    conflict::ensure_abort_safe(layout, store, &records, target_tree, op_result)?;
    conflict::reset_paths(layout, store, &records, target_tree, op_result)?;
    ensure_restore_safe(layout, store, target_tree).map_err(Error::Worktree)?;
    restore_worktree_and_index(layout, store, target_tree).map_err(Error::Worktree)?;
    head::advance(layout, &target, RefWriteCondition::Any).map_err(Error::RestoreHead)?;
    conflict_state::clear_merge_state(layout).map_err(Error::ClearState)?;
    Ok(target)
}

fn read_state(layout: &RepoLayout) -> Result<(MergeState, Vec<ConflictRecord>), Error> {
    if !is_merge_in_progress(layout) {
        return Err(Error::NoMergeInProgress);
    }
    let state = match conflict_state::read_merge_state(layout) {
        Ok(Some(s)) => s,
        Ok(None) => return Err(Error::NoMergeInProgress),
        Err(e) => return Err(Error::ReadState(e)),
    };
    let records = conflict_state::read_conflicts(layout.worktree_state_dir())
        .map_err(Error::ReadConflicts)?;
    Ok((state, records))
}

fn create_merge_commit(
    layout: &RepoLayout,
    store: &ObjectStore,
    signing: &dyn Signing,
    tree: Hash,
    ours: Hash,
    theirs: Hash,
    message: &[u8],
) -> Result<Hash, Error> {
    let mut signer = signing.open(layout)?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    write_signed(
        store,
        signer.as_mut(),
        tree,
        vec![ours, theirs],
        Author::Signer,
        message.to_vec(),
        timestamp,
    )
    .map_err(|e| match e {
        WriteError::Signing(e) => Error::Signing(e),
        WriteError::Serialize(e) => Error::Serialize(e),
        WriteError::Store(e) => Error::StoreCommit(e),
    })
}

/// Whether `spec` names a remote-tracking ref. A local branch or tag of the
/// same spelling wins, as it does for the revision resolver.
fn is_remote_tracking(layout: &RepoLayout, spec: &str) -> bool {
    let rel = spec.strip_prefix("refs/remotes/").map_or(spec, |r| r);
    let Some((remote, branch)) = rel.split_once('/') else {
        return false;
    };
    if refs::read_ref(layout, spec).is_ok_and(|r| r.is_some())
        || refs::read_tag(layout, spec).is_ok_and(|r| r.is_some())
    {
        return false;
    }
    refs::read_remote_ref(layout, remote, branch).is_ok_and(|r| r.is_some())
}

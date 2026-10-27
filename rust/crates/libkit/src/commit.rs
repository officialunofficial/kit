//! Make a signed commit from the index.
//!
//! A commit has two steps. [`begin`] reads the state that the message may
//! depend on: a merge in progress, and, for an amend, the commit to replace.
//! The caller may take its time over the message after that, for example in an
//! editor. [`create`] then takes the worktree lock, checks that the state of
//! [`begin`] still holds, and makes the commit.
//!
//! [`create`] builds the tree from the index, signs the commit, writes it, and
//! only then moves `HEAD`. The commit and its trees are durable before any ref
//! names them. The move of `HEAD` is conditional on the tip that the commit was
//! built on, so a concurrent writer is never overwritten. An amend records the
//! commit it replaces in the recovery log first. A commit that concludes a
//! merge has the two parents of the merge, and it clears the merge state.
//!
//! A plain commit needs no check of its parent against the state of
//! [`begin`]. It reads its parent from `HEAD` under the lock, and builds its
//! tree from the index under the same lock. A commit that landed in the
//! meantime becomes the parent, as if the two commits had run in turn.

use std::time::{SystemTime, UNIX_EPOCH};

use kit_core::hash::{self, Hash};
use kit_core::index;
use kit_core::layout::RepoLayout;
use kit_core::object::{Commit, Identity, Object};
use kit_core::observer::Observer;
use kit_core::ops::conflict_state::{self, ConflictRecord, MergeState};
use kit_core::ops::recovery::{self, RecoveryEntry};
use kit_core::refs::{self, Head, RefError, RefWriteCondition};
use kit_core::serialize;
use kit_core::store::ObjectStore;
use kit_core::worktree;
use kit_sync::worktree::sync_index_to_tree;

use crate::signer::{self, Signer};
use crate::{add, head, lock};

/// Errors from [`begin`] and [`create`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The state of a merge cannot be read.
    #[error("read merge state: {0}")]
    ReadMergeState(conflict_state::ConflictStateError),
    /// An amend and a merge in progress.
    #[error(
        "cannot --amend while a merge is in progress; finish it with `kit commit` or abandon it with `kit merge --abort`"
    )]
    AmendDuringMerge,
    /// `HEAD` cannot be read.
    #[error("read HEAD: {0}")]
    ReadHead(RefError),
    /// An amend and no commit.
    #[error("nothing to amend: HEAD has no commit yet")]
    NothingToAmend,
    /// An amend and a `HEAD` that is not a commit.
    #[error("cannot amend: HEAD {} is not a commit", hash::to_hex(.0))]
    AmendNotACommit(Hash),
    /// The commit to amend cannot be read.
    #[error("read HEAD commit {}: {source}", hash::to_hex(commit))]
    ReadAmendTarget {
        /// The commit.
        commit: Hash,
        /// Why it cannot be read.
        source: kit_core::store::StoreError,
    },
    /// The worktree lock cannot be taken.
    #[error(transparent)]
    Lock(#[from] lock::Error),
    /// The merge changed while the message was composed.
    #[error(
        "commit aborted: the in-progress merge changed while the commit message was being composed (concluded or aborted concurrently) — re-run `kit commit`"
    )]
    MergeChanged,
    /// `HEAD` moved while the message was composed.
    #[error(
        "commit aborted: HEAD changed while the commit message was being composed (a concurrent commit landed) — re-run `kit commit --amend`"
    )]
    HeadMoved,
    /// The tracked files cannot be staged.
    #[error("stage tracked changes: {0}")]
    StageTracked(add::Error),
    /// The conflict records of the merge cannot be read.
    #[error("read conflicts: {0}")]
    ReadConflicts(conflict_state::ConflictStateError),
    /// A conflict of the merge is not resolved. The text says which.
    #[error("{0}")]
    Unresolved(String),
    /// The index cannot be read.
    #[error("read index: {0}")]
    ReadIndex(index::IndexError),
    /// Nothing is staged.
    #[error("nothing staged: index is empty; run `kit add <path>` (or `kit add .`) before commit")]
    NothingStaged,
    /// The tree cannot be built from the index.
    #[error("build tree: {0}")]
    BuildTree(worktree::WorktreeError),
    /// The staged merge was discarded.
    #[error(
        "nothing to commit: the staged merge was discarded (its result differs from HEAD but the index matches HEAD); re-stage it or run `kit merge --abort`"
    )]
    MergeDiscarded,
    /// The key cannot sign.
    #[error(transparent)]
    Signer(#[from] signer::Error),
    /// The commit cannot be encoded.
    #[error("serialize commit: {0}")]
    Serialize(kit_core::KitError),
    /// The commit cannot be stored.
    #[error("store commit: {0}")]
    Store(kit_core::store::StoreError),
    /// The recovery log cannot be written.
    #[error("recovery log: {0}")]
    Recovery(recovery::RecoveryError),
    /// The branch moved while the commit was made.
    #[error(
        "commit aborted: branch '{branch}' moved underneath this commit (a concurrent commit landed) — the commit object {} is durable but currently unreferenced (GC-recoverable), nothing is corrupted; re-run `kit commit`",
        hash::to_hex(commit)
    )]
    BranchMoved {
        /// The branch.
        branch: String,
        /// The commit that no ref names.
        commit: Hash,
    },
    /// `HEAD` cannot move to the commit.
    #[error(transparent)]
    Head(head::Error),
    /// The index cannot follow the new tree.
    #[error("{0}")]
    SyncIndex(String),
    /// The merge state cannot be cleared.
    #[error("clear merge state: {0}")]
    ClearMergeState(conflict_state::ConflictStateError),
}

/// The state that a commit reads before its message is composed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    merge: Option<MergeState>,
    amend: Option<Commit>,
    head: Option<Hash>,
}

impl Pending {
    /// The message that the commit takes when the caller gives none. An amend
    /// reuses the message of the commit it replaces. A merge in progress has
    /// its own message. A plain commit has none.
    #[must_use]
    pub fn default_message(&self) -> Option<String> {
        if let Some(prev) = &self.amend {
            return Some(String::from_utf8_lossy(&prev.message).into_owned());
        }
        self.merge
            .as_ref()
            .map(|state| String::from_utf8_lossy(&state.message).into_owned())
    }
}

/// Read the state that the commit depends on.
///
/// With `amend`, this finds the commit to replace.
///
/// # Errors
/// [`Error`] when the merge state or `HEAD` cannot be read, when an amend meets
/// a merge in progress, or when there is no commit to amend.
pub fn begin(layout: &RepoLayout, store: &ObjectStore, amend: bool) -> Result<Pending, Error> {
    let merge = read_merge(layout)?;
    if merge.is_some() && amend {
        return Err(Error::AmendDuringMerge);
    }
    let amend_target = if amend {
        Some(resolve_amend_target(layout, store)?)
    } else {
        None
    };
    // The amend takes its parents, and its message when none is given, from
    // this snapshot of `HEAD`. [`create`] checks that `HEAD` is still there.
    let head = if amend {
        refs::resolve_head(layout).map_err(Error::ReadHead)?
    } else {
        None
    };
    Ok(Pending {
        merge,
        amend: amend_target,
        head,
    })
}

fn read_merge(layout: &RepoLayout) -> Result<Option<MergeState>, Error> {
    if conflict_state::is_merge_in_progress(layout) {
        conflict_state::read_merge_state(layout).map_err(Error::ReadMergeState)
    } else {
        Ok(None)
    }
}

/// The commit that an amend replaces. Its parents and, with no message of the
/// caller, its message carry over to the new commit.
fn resolve_amend_target(layout: &RepoLayout, store: &ObjectStore) -> Result<Commit, Error> {
    let head = refs::resolve_head(layout)
        .map_err(Error::ReadHead)?
        .ok_or(Error::NothingToAmend)?;
    match store.read_object(&head) {
        Ok(Object::Commit(c)) => Ok(c),
        Ok(_) => Err(Error::AmendNotACommit(head)),
        Err(source) => Err(Error::ReadAmendTarget {
            commit: head,
            source,
        }),
    }
}

/// What [`create`] makes the commit from.
#[derive(Debug, Clone)]
pub struct Request<'a> {
    /// The commit message.
    pub message: &'a str,
    /// The author.
    pub author: Identity,
    /// The public key of the signer.
    pub signer_public: [u8; 32],
    /// Stage the changes of tracked files first.
    pub all: bool,
}

/// The commit that [`create`] made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Created {
    /// The commit.
    pub commit: Hash,
    /// The tree of the commit.
    pub tree: Hash,
    /// The parents of the commit.
    pub parents: Vec<Hash>,
    /// The branch that `HEAD` names after the commit. `None` for a detached
    /// `HEAD`.
    pub branch: Option<String>,
    /// The tree to show the change against. The first parent has it. A merge
    /// has the new tree, so its change is empty.
    pub base_tree: Option<Hash>,
}

impl Created {
    /// The commit has no parent.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.parents.is_empty()
    }

    /// The commit has two parents or more.
    #[must_use]
    pub fn is_merge(&self) -> bool {
        self.parents.len() >= 2
    }
}

/// Make the commit.
///
/// `gate` checks the conflicts of a merge that the commit concludes. It
/// returns the text of the first conflict that is not resolved and staged. A
/// merge that is clean has no record, so the gate sees an empty list.
///
/// # Errors
/// [`Error`], with one variant for each refused or failed step. A refusal
/// before the write of the commit changes nothing. [`Error::BranchMoved`]
/// leaves a commit that no ref names, which `gc` can reclaim.
pub fn create(
    layout: &RepoLayout,
    store: &ObjectStore,
    pending: &Pending,
    request: &Request<'_>,
    signer: &mut Signer,
    gate: &dyn Fn(&[ConflictRecord]) -> Result<(), String>,
    observer: &dyn Observer<lock::Event>,
) -> Result<Created, Error> {
    // The message and the key took as long as they took, and none of that
    // needed the lock. Everything from here on changes the repository, or
    // reads what must not shift under a change.
    let _lock = lock::acquire_worktree(layout, observer)?;

    // The state of [`begin`] could change before the lock. Any change to the
    // merge decides which parents the commit has, so any change is an abort.
    if read_merge(layout)? != pending.merge {
        return Err(Error::MergeChanged);
    }
    // The parents and the message of an amend come from the commit that
    // [`begin`] found. A `HEAD` that moved makes it the wrong commit.
    if pending.amend.is_some()
        && refs::resolve_head(layout).map_err(Error::ReadHead)? != pending.head
    {
        return Err(Error::HeadMoved);
    }

    if request.all {
        add::stage_tracked(layout, store).map_err(Error::StageTracked)?;
    }

    // A merge needs every conflict resolved and staged, as `merge --continue`
    // does. A clean merge has no record, so both checks pass.
    if pending.merge.is_some() {
        let records = conflict_state::read_conflicts(layout.worktree_state_dir())
            .map_err(Error::ReadConflicts)?;
        gate(&records).map_err(Error::Unresolved)?;
    }

    // An absent index and an empty one are the same error. An index with only
    // removed entries is a real change, a commit of deletions with an empty
    // tree. A merge may have an empty tree too, when both sides deleted
    // everything.
    let idx = index::read_index(layout).map_err(Error::ReadIndex)?;
    if idx.entries.is_empty() && pending.merge.is_none() {
        return Err(Error::NothingStaged);
    }
    // One durability batch holds the trees and the commit. It commits before
    // any ref names them.
    let batch = store.batch();
    // The staged objects are verified before the tree names them.
    let tree = worktree::build_tree_from_index_with(store, &batch, &idx, true)
        .map_err(Error::BuildTree)?;
    refuse_discarded_merge(layout, store, pending, tree)?;

    // A plain commit builds on `HEAD`. An amend takes the parents of `HEAD`,
    // so the replaced commit leaves the chain. A merge takes the base of the
    // merge and the other side, not the live `HEAD`. The result then matches
    // `merge --continue` after a `reset` moved `HEAD`.
    let parents = if let Some(prev) = &pending.amend {
        prev.parents.clone()
    } else if let Some(state) = &pending.merge {
        vec![state.orig_head, state.merge_head]
    } else {
        match refs::resolve_head(layout) {
            Ok(Some(h)) => vec![h],
            _ => vec![],
        }
    };
    let first_parent = parents.first().copied();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut unsigned = Commit::new_unannotated(
        tree,
        parents.clone(),
        request.author.clone(),
        request.signer_public,
        request.message.as_bytes().to_vec(),
        timestamp,
        [0u8; 64],
    );
    unsigned.signature = signer.sign_commit(&unsigned)?;
    let bytes = serialize::serialize(&Object::Commit(unsigned)).map_err(Error::Serialize)?;
    let commit = batch.write(&bytes).map_err(Error::Store)?;
    // The tree and the commit are durable before the recovery log, the ref
    // and the index name them.
    batch.commit().map_err(Error::Store)?;

    // An amend replaces `HEAD`. The log records the old tip before the branch
    // moves, so the replaced commit stays recoverable. A log that cannot be
    // written stops the amend.
    if pending.amend.is_some()
        && let Some(old_head) = refs::resolve_head(layout).map_err(Error::ReadHead)?
    {
        record_superseded(layout, old_head)?;
    }
    // The tip that the commit was built on is the condition of the move.
    // - Amend: the commit that was replaced, which was checked against `HEAD`
    //   above. `parents` is one generation further back.
    // - Merge: `HEAD` as it is now. The parents come from the merge state, not
    //   from `HEAD`, so they would let the move pass after `HEAD` moved.
    // - Plain: the first parent, which is a fresh read of `HEAD` under this
    //   lock.
    let expected_tip = if pending.amend.is_some() {
        pending.head
    } else if pending.merge.is_some() {
        refs::resolve_head(layout).map_err(Error::ReadHead)?
    } else {
        first_parent
    };
    advance_head(layout, &commit, expected_tip)?;
    sync_index_to_tree(layout, store, tree).map_err(Error::SyncIndex)?;
    // The merge is recorded, so the repository is no longer merging.
    if pending.merge.is_some() {
        conflict_state::clear_merge_state(layout).map_err(Error::ClearMergeState)?;
    }

    let branch = match refs::read_head(layout) {
        Ok(Head::Branch(b)) => Some(b),
        _ => None,
    };
    let base_tree = if parents.len() >= 2 {
        Some(tree)
    } else {
        first_parent.and_then(|p| commit_tree(store, &p))
    };
    Ok(Created {
        commit,
        tree,
        parents,
        branch,
        base_tree,
    })
}

/// Refuse a commit that records a merge that was discarded. A `reset` between
/// `merge --no-commit` and the commit does that. The staged tree that equals
/// the tree before the merge is not proof enough. A merge of branches that
/// diverged can give the tree of `HEAD`, for example when both sides deleted
/// the same file. So the commit is refused only when the result of the merge
/// differs from `HEAD` and the staged tree is back at `HEAD`. A merge with no
/// recorded result is not refused.
fn refuse_discarded_merge(
    layout: &RepoLayout,
    store: &ObjectStore,
    pending: &Pending,
    tree: Hash,
) -> Result<(), Error> {
    if let Some(state) = &pending.merge
        && let Ok(Object::Commit(orig)) = store.read_object(&state.orig_head)
        && orig.tree_hash == tree
        && conflict_state::read_result_tree(layout.worktree_state_dir())
            .ok()
            .flatten()
            .is_some_and(|result| result != orig.tree_hash)
    {
        return Err(Error::MergeDiscarded);
    }
    Ok(())
}

fn record_superseded(layout: &RepoLayout, superseded: Hash) -> Result<(), Error> {
    let branch = match refs::read_head(layout) {
        Ok(Head::Branch(name)) => name,
        _ => String::new(),
    };
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    recovery::record(
        layout,
        &RecoveryEntry {
            timestamp,
            op: "amend".to_owned(),
            superseded,
            branch,
        },
    )
    .map_err(Error::Recovery)
}

/// Move the branch of `HEAD`, or a detached `HEAD`, to `commit`.
///
/// `expected` is the tip that the commit was built on: `Some(parent)` for a
/// normal move, `None` for a root commit or the first commit of an unborn
/// branch. It is the condition of the move, so a writer that landed in the
/// meantime is never overwritten. A detached `HEAD` has no branch, and the
/// condition does not apply to it.
fn advance_head(layout: &RepoLayout, commit: &Hash, expected: Option<Hash>) -> Result<(), Error> {
    let condition = match expected {
        Some(h) => RefWriteCondition::Match(h),
        None => RefWriteCondition::Missing,
    };
    head::advance(layout, commit, condition).map_err(|e| match e {
        head::Error::WriteRef {
            branch,
            source: RefError::Conflict(_),
        } => Error::BranchMoved {
            branch,
            commit: *commit,
        },
        other => Error::Head(other),
    })
}

/// The tree of a commit or a remix. `None` for any other object, and for a
/// read that fails. It bounds the change that is shown after the commit.
fn commit_tree(store: &ObjectStore, commit: &Hash) -> Option<Hash> {
    match store.read_object(commit).ok()? {
        Object::Commit(c) => Some(c.tree_hash),
        Object::Remix(r) => Some(r.tree_hash),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use kit_core::object::Tree;
    use kit_core::refs::write_ref_recording_history;

    use super::*;

    fn fresh_repo() -> (tempfile::TempDir, RepoLayout) {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        // Ancestry validation reads the real persisted first-parent graph.
        ObjectStore::init(&layout).unwrap();
        refs::init(&layout).unwrap();
        (dir, layout)
    }

    fn commit(layout: &RepoLayout, message: &[u8], parents: Vec<Hash>) -> Hash {
        let store = ObjectStore::open(layout).unwrap();
        let tree = Object::Tree(Tree {
            entries: Vec::new(),
        });
        let tree_hash = store.write(&serialize::serialize(&tree).unwrap()).unwrap();
        let commit = Object::Commit(Commit::new_unannotated(
            tree_hash,
            parents,
            Identity::ed25519([1; 32]),
            [1; 32],
            message.to_vec(),
            0,
            [0; 64],
        ));
        store
            .write(&serialize::serialize(&commit).unwrap())
            .unwrap()
    }

    fn seed(layout: &RepoLayout, tip: &Hash) {
        write_ref_recording_history(layout, "main", RefWriteCondition::Missing, tip).unwrap();
    }

    /// The branch moved to a value other than `expected` since the caller read
    /// it. The move must refuse and leave the concurrent value untouched.
    #[test]
    fn advance_head_conflicts_when_the_branch_moved_since_expected_was_read() {
        let (_dir, layout) = fresh_repo();
        let t0 = commit(&layout, b"t0", vec![]);
        seed(&layout, &t0);
        let moved = commit(&layout, b"moved-concurrently", vec![t0]);
        write_ref_recording_history(&layout, "main", RefWriteCondition::Match(t0), &moved).unwrap();

        let new_commit = commit(&layout, b"new-commit", vec![t0]);
        let error = advance_head(&layout, &new_commit, Some(t0)).unwrap_err();
        assert!(
            matches!(error, Error::BranchMoved { ref branch, commit } if branch == "main" && commit == new_commit),
            "{error:?}"
        );
        assert!(error.to_string().contains("commit aborted"));
        assert_eq!(refs::read_ref(&layout, "main").unwrap(), Some(moved));
    }

    #[test]
    fn advance_head_succeeds_when_expected_matches_the_current_value() {
        let (_dir, layout) = fresh_repo();
        let t0 = commit(&layout, b"t0", vec![]);
        seed(&layout, &t0);
        let c1 = commit(&layout, b"c1", vec![t0]);
        advance_head(&layout, &c1, Some(t0)).unwrap();
        assert_eq!(refs::read_ref(&layout, "main").unwrap(), Some(c1));
    }

    /// A root commit has no expected tip, so the branch must not exist yet.
    #[test]
    fn advance_head_accepts_a_branch_that_does_not_exist_yet() {
        let (_dir, layout) = fresh_repo();
        let c1 = commit(&layout, b"root-commit", vec![]);
        advance_head(&layout, &c1, None).unwrap();
        assert_eq!(refs::read_ref(&layout, "main").unwrap(), Some(c1));
    }

    #[test]
    fn advance_head_refuses_a_branch_that_a_concurrent_root_commit_made() {
        let (_dir, layout) = fresh_repo();
        let raced_in = commit(&layout, b"raced-in-first", vec![]);
        seed(&layout, &raced_in);
        let c1 = commit(&layout, b"root-commit", vec![]);
        let error = advance_head(&layout, &c1, None).unwrap_err();
        assert!(matches!(error, Error::BranchMoved { .. }), "{error:?}");
        assert_eq!(refs::read_ref(&layout, "main").unwrap(), Some(raced_in));
    }
}

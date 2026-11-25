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

use kit_core::durable::{Flushed, Group};
use kit_core::hash::{self, Hash};
use kit_core::index;
use kit_core::layout::RepoLayout;
use kit_core::object::{Commit, EntryMode, Identity, Object, TreeEntry};
use kit_core::observer::Observer;
use kit_core::ops::conflict_state::{self, ConflictRecord, MergeState};
use kit_core::ops::pull_state::PullState;
use kit_core::ops::recovery::{self, RecoveryEntry};
use kit_core::refs::{self, Head, RefError, RefWriteCondition};
use kit_core::serialize;
use kit_core::store::{MAX_TREE_DEPTH, ObjectStore};
use kit_core::worktree;
use kit_sync::worktree::sync_index_to_tree_staged;

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
    /// The merge is recorded without its conflict list: a write that stopped
    /// part way, or a state from an older version.
    #[error(
        "the merge in progress has no conflict list (its state was not fully written); run `kit merge --abort` or `kit reset --hard` to drop it"
    )]
    MergeStateIncomplete,
    /// A cherry-pick or a revert is recorded without its conflict list: a
    /// write that stopped part way, or a state from an older version. The
    /// text names it.
    #[error(
        "the {0} in progress has no conflict list (its state was not fully written); run `kit {0} --abort` or `kit reset --hard` to drop it"
    )]
    OperationStateIncomplete(&'static str),
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
    /// The state of the merge, cherry-pick or revert that the commit
    /// concluded cannot be cleared.
    #[error("clear operation state: {0}")]
    ClearMergeState(conflict_state::ConflictStateError),
    /// The record of an unfinished pull cannot be read.
    #[error(
        "read the unfinished pull: {0}; if no pull is running, check the files, then remove `.kit/PULL_HEAD`"
    )]
    ReadPullState(std::io::Error),
    /// An interrupted pull has not finished restoring the index and files.
    #[error(
        "an interrupted pull has not finished: HEAD is at {} but the index still holds files from before the pull, so a commit would undo the pulled change; run `kit pull` to finish it, or, with no remote, `kit reset --hard -f` to restore the files of HEAD and discard uncommitted changes; after that reset, remove `.kit/PULL_HEAD` to commit a deliberate undo of the pull",
        hash::to_hex(.0)
    )]
    PullUnfinished(Hash),
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
    refuse_unfinished_pull(layout, store)?;
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

/// Refuse while a pull that stopped partway leaves the index behind `HEAD`.
fn refuse_unfinished_pull(layout: &RepoLayout, store: &ObjectStore) -> Result<(), Error> {
    match unfinished_pull(layout, store)? {
        Some(target) => Err(Error::PullUnfinished(target)),
        None => Ok(()),
    }
}

/// The commit of a pull that stopped partway, when a commit would undo it.
///
/// A pull records its target, moves the branch and `HEAD`, restores the files
/// and writes the index last. A pull stopped in the restore leaves `HEAD` at
/// the target and the index at the tree from before the pull. A commit of
/// that index undoes the pulled change, and `commit -a` records a mixture of
/// both trees.
///
/// The pull is unfinished while its record names `HEAD` and the index still
/// holds the pre-pull entry, content and mode, at a path that the pull
/// changed, or lacks a path that the pull added. Staging other paths does not
/// hide it. A restore that reached the index, `reset --hard`
/// and a pull that has not moved `HEAD` leave no such path, and a commit goes
/// on. The check reads the index and writes nothing.
///
/// # Errors
/// [`Error::ReadPullState`] when the record or a tree cannot be read,
/// [`Error::ReadIndex`] when the index cannot. A commit waits for a repair.
pub fn unfinished_pull(layout: &RepoLayout, store: &ObjectStore) -> Result<Option<Hash>, Error> {
    let Some(state) = PullState::at_head(layout).map_err(Error::ReadPullState)? else {
        return Ok(None);
    };
    let Some(target_tree) = commit_tree(store, &state.target) else {
        return Err(Error::ReadPullState(std::io::Error::other(
            "the target of the pull is not a commit",
        )));
    };
    let idx = index::read_index(layout).map_err(Error::ReadIndex)?;
    let behind =
        Behind { store, index: &idx }.walk(Some(state.before_tree), Some(target_tree), "", 0)?;
    Ok(behind.then_some(state.target))
}

/// A walk over the trees of a pull that finds a path where the index is still
/// behind the pull.
struct Behind<'a> {
    store: &'a ObjectStore,
    index: &'a index::Index,
}

impl Behind<'_> {
    fn entries(&self, tree: Option<Hash>) -> Result<Vec<TreeEntry>, Error> {
        let Some(hash) = tree else {
            return Ok(Vec::new());
        };
        match self.store.read_object(&hash) {
            Ok(Object::Tree(tree)) => Ok(tree.entries),
            Ok(_) => Err(unreadable("a pull tree is not a tree")),
            Err(e) => Err(unreadable(e)),
        }
    }

    /// Whether some path under `before` and `target` is behind. The walk
    /// skips a subtree that both sides share and stops at the first path.
    fn walk(
        &self,
        before: Option<Hash>,
        target: Option<Hash>,
        prefix: &str,
        depth: usize,
    ) -> Result<bool, Error> {
        if before == target {
            return Ok(false);
        }
        if depth > MAX_TREE_DEPTH {
            return Err(unreadable("a pull tree is too deep"));
        }
        let old = self.entries(before)?;
        let new = self.entries(target)?;
        let (mut i, mut j) = (0, 0);
        while i < old.len() || j < new.len() {
            let order = match (old.get(i), new.get(j)) {
                (Some(o), Some(n)) => o.name.cmp(&n.name),
                (Some(_), None) => std::cmp::Ordering::Less,
                _ => std::cmp::Ordering::Greater,
            };
            let (o, n) = match order {
                std::cmp::Ordering::Less => (old.get(i), None),
                std::cmp::Ordering::Greater => (None, new.get(j)),
                std::cmp::Ordering::Equal => (old.get(i), new.get(j)),
            };
            if order != std::cmp::Ordering::Greater {
                i += 1;
            }
            if order != std::cmp::Ordering::Less {
                j += 1;
            }
            if self.entry_behind(o, n, prefix, depth)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn entry_behind(
        &self,
        old: Option<&TreeEntry>,
        new: Option<&TreeEntry>,
        prefix: &str,
        depth: usize,
    ) -> Result<bool, Error> {
        let Some(name) = old.or(new).map(|entry| &entry.name) else {
            return Ok(false);
        };
        let path = if prefix.is_empty() {
            String::from_utf8_lossy(name).into_owned()
        } else {
            format!("{prefix}/{}", String::from_utf8_lossy(name))
        };
        let tree_of = |entry: Option<&TreeEntry>| {
            entry
                .filter(|entry| entry.mode == EntryMode::Tree)
                .map(|entry| entry.object_hash)
        };
        let (old_tree, new_tree) = (tree_of(old), tree_of(new));
        if (old_tree.is_some() || new_tree.is_some())
            && self.walk(old_tree, new_tree, &path, depth + 1)?
        {
            return Ok(true);
        }
        match (leaf_of(old), leaf_of(new)) {
            (Some(o), Some(n)) if o.object_hash == n.object_hash && o.mode == n.mode => Ok(false),
            (Some(o), _) => Ok(self.holds(&path, Some(o))),
            (None, Some(_)) => Ok(self.holds(&path, None)),
            (None, None) => Ok(false),
        }
    }

    /// Whether the index holds `entry` at `path`, with the same content and
    /// mode, or holds nothing there for `None`.
    fn holds(&self, path: &str, entry: Option<&TreeEntry>) -> bool {
        let staged = self
            .index
            .find_entry(path)
            .map(|i| &self.index.entries[i])
            .filter(|staged| staged.status != index::EntryStatus::Removed);
        match entry {
            Some(entry) => staged.is_some_and(|staged| {
                staged.object_hash == entry.object_hash && staged.status as u8 == entry.mode as u8
            }),
            None => staged.is_none(),
        }
    }
}

/// The entry when it is a file or a link, `None` for a directory.
fn leaf_of(entry: Option<&TreeEntry>) -> Option<&TreeEntry> {
    entry.filter(|entry| entry.mode != EntryMode::Tree)
}

fn unreadable(reason: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Error {
    Error::ReadPullState(std::io::Error::other(reason))
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
    /// Let the first commit of a branch have an empty index, and so an empty
    /// tree. A commit that has a parent never needs this.
    pub allow_empty: bool,
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

/// The parents of the commit. A plain commit builds on `HEAD`. An amend takes
/// the parents of `HEAD`, so the replaced commit leaves the chain. A merge
/// takes the base of the merge and the other side, not the live `HEAD`. The
/// result then matches `merge --continue` after a `reset` moved `HEAD`.
fn commit_parents(layout: &RepoLayout, pending: &Pending) -> Vec<Hash> {
    if let Some(prev) = &pending.amend {
        prev.parents.clone()
    } else if let Some(state) = &pending.merge {
        vec![state.orig_head, state.merge_head]
    } else {
        match refs::resolve_head(layout) {
            Ok(Some(h)) => vec![h],
            _ => vec![],
        }
    }
}

/// The tip that the commit was built on, the condition of the move.
/// - Amend: the commit that was replaced, which was checked against `HEAD`
///   already. `first_parent` is one generation further back.
/// - Merge: `HEAD` as it is now. The parents come from the merge state, not
///   from `HEAD`, so they would let the move pass after `HEAD` moved.
/// - Plain: the first parent, which is a fresh read of `HEAD` under the lock.
fn expected_tip(
    layout: &RepoLayout,
    pending: &Pending,
    first_parent: Option<Hash>,
) -> Result<Option<Hash>, Error> {
    if pending.amend.is_some() {
        Ok(pending.head)
    } else if pending.merge.is_some() {
        refs::resolve_head(layout).map_err(Error::ReadHead)
    } else {
        Ok(first_parent)
    }
}

/// Flush 3: the ref and the index names, published on the token of flush 2.
/// The ref lock is held until the flush that covers the rename returns, also
/// when the index cannot be published: the ref is then renamed already, so
/// the flush is tried once before the error returns. A poisoned group refuses
/// it without a device call.
fn publish_pointers(
    layout: &RepoLayout,
    group: &mut Group,
    (staged_head, staged_index): (head::StagedAdvance, Option<index::StagedIndex>),
    condition: RefWriteCondition,
    durable: &Flushed,
    commit: &Hash,
) -> Result<(), Error> {
    let ref_lock = head::publish_advance(layout, group, staged_head, condition, durable)
        .map_err(|e| branch_moved(e, commit))?;
    if let Some(staged_index) = staged_index
        && let Err(e) = index::publish_staged_index(group, staged_index, durable)
    {
        let _ = group.flush();
        drop(ref_lock);
        return Err(Error::SyncIndex(format!("write index: {e}")));
    }
    let _named = group.flush().map_err(store_io)?;
    drop(ref_lock);
    Ok(())
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

    // This runs before `all` stages the files: a pull stopped partway leaves
    // some files new and the index old, and staging them would record a
    // mixture.
    refuse_unfinished_pull(layout, store)?;

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

    let picking = operation_list(layout, pending)?;

    if request.all {
        add::stage_tracked(layout, store).map_err(Error::StageTracked)?;
    }

    gate_operation(layout, pending, picking, gate)?;

    // An absent index and an empty one are the same error. An index with only
    // removed entries is a real change, a commit of deletions with an empty
    // tree. A merge may have an empty tree too, when both sides deleted
    // everything. A first commit may be empty on request.
    let idx = index::read_index(layout).map_err(Error::ReadIndex)?;
    let empty_root_allowed = request.allow_empty && pending.head.is_none();
    if idx.entries.is_empty() && pending.merge.is_none() && !empty_root_allowed {
        return Err(Error::NothingStaged);
    }
    // One durability batch holds the trees and the commit. It commits before
    // any ref names them.
    let batch = store.batch();
    // The staged objects are verified before the tree names them, except
    // those the tree of `HEAD` already names at the same path with the same
    // mode: the new tree adds no reference to them. A `HEAD` that cannot be
    // read gives no base, and every staged object is verified.
    let base = refs::resolve_head(layout)
        .ok()
        .flatten()
        .and_then(|head| commit_tree(store, &head));
    let tree = worktree::build_tree_from_index_against(store, &batch, &idx, true, base)
        .map_err(Error::BuildTree)?;
    refuse_discarded_merge(layout, store, pending, tree)?;

    let parents = commit_parents(layout, pending);
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

    // One group of writes shares the flushes of this commit (SPEC-OBJECTS
    // §10.1, "Shared flush points"). The temp file of the ref is staged
    // before the objects become visible, so its bytes ride the same flush.
    let mut group = store.group();
    let staged_head = head::stage_advance(layout, &mut group, &commit).map_err(Error::Head)?;
    // The bytes of the trees, the commit and the ref are durable (flush 1),
    // then the objects are renamed into place and their directories written
    // out. Their names are not durable until the next flush.
    batch.commit_in(&mut group).map_err(Error::Store)?;

    // An amend replaces `HEAD`. The log records the old tip before the branch
    // moves, so the replaced commit stays recoverable: its line is written
    // out before the flush that licenses the ref rename. A log that cannot be
    // written stops the amend.
    if pending.amend.is_some()
        && let Some(old_head) = refs::resolve_head(layout).map_err(Error::ReadHead)?
    {
        record_superseded(layout, old_head, &mut group)?;
    }
    // A plain commit leaves the index as it was: the tree came from these
    // entries, so rebuilding them from the tree would read every tree object
    // and write the same index again. A staged removal is not in the tree, so
    // it rebuilds the index. So does a merge or an amend, which keep their
    // own rebuild. The new trees are visible now, so the rebuild reads them,
    // and its bytes ride the next flush.
    let staged_index = if pending.merge.is_some()
        || pending.amend.is_some()
        || !index_is_the_tree(&idx)
    {
        Some(sync_index_to_tree_staged(&mut group, layout, store, tree).map_err(Error::SyncIndex)?)
    } else {
        None
    };
    // Flush 2: the names of the objects, the recovery line and the bytes of
    // the index are durable before a ref or the index names them.
    let durable = group.flush().map_err(store_io)?;

    let expected_tip = expected_tip(layout, pending, first_parent)?;
    let condition = match expected_tip {
        Some(h) => RefWriteCondition::Match(h),
        None => RefWriteCondition::Missing,
    };
    // Flush 3 is inside: the ref and the index names.
    publish_pointers(
        layout,
        &mut group,
        (staged_head, staged_index),
        condition,
        &durable,
        &commit,
    )?;

    // The merge is recorded, so the repository is no longer merging. This
    // goes after the ref name is durable: a crash before it leaves the merge
    // state over the new commit, never a commit that lost its second parent.
    if pending.merge.is_some() {
        conflict_state::clear_merge_state_in(layout, &mut group).map_err(Error::ClearMergeState)?;
        group.finish().map_err(store_io)?;
    } else if picking {
        // A cherry-pick or a revert that the commit concludes is over, as in
        // git. Left behind, a later `--abort` would move the branch back over
        // this commit.
        conflict_state::clear_operation_state_in(layout, &mut group)
            .map_err(Error::ClearMergeState)?;
        group.finish().map_err(store_io)?;
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

/// Whether a cherry-pick or a revert is in progress, after a check that the
/// operation that the commit concludes has its conflict list.
///
/// An operation always has a conflict list, empty for a clean one. Without the
/// file the state is torn, and a commit would record "ours" with the other
/// side as a parent, or commit its markers. The check runs before `all` stages
/// the files, so a refused commit changes nothing.
fn operation_list(layout: &RepoLayout, pending: &Pending) -> Result<bool, Error> {
    let picking = pending.merge.is_none()
        && (conflict_state::is_cherry_pick_in_progress(layout)
            || conflict_state::is_revert_in_progress(layout));
    if (pending.merge.is_some() || picking) && !layout.conflicts_file().is_file() {
        return Err(match conflict_state::in_progress_op_name(layout) {
            Some(op) if picking => Error::OperationStateIncomplete(op),
            _ => Error::MergeStateIncomplete,
        });
    }
    Ok(picking)
}

/// Check the conflicts of the operation that the commit concludes.
///
/// A merge needs every conflict resolved and staged, as `merge --continue`
/// does. A clean merge has no record, so both checks pass. A cherry-pick and a
/// revert need the same before a commit goes over their markers.
fn gate_operation(
    layout: &RepoLayout,
    pending: &Pending,
    picking: bool,
    gate: &dyn Fn(&[ConflictRecord]) -> Result<(), String>,
) -> Result<(), Error> {
    if pending.merge.is_some() || picking {
        let records = conflict_state::read_conflicts(layout.worktree_state_dir())
            .map_err(Error::ReadConflicts)?;
        gate(&records).map_err(Error::Unresolved)?;
    }
    Ok(())
}

/// Whether every entry of `idx` is a file or a link that the tree built from
/// it holds. A removal is dropped from the tree, and a tree entry is not
/// staged.
fn index_is_the_tree(idx: &index::Index) -> bool {
    !idx.entries.iter().any(|entry| {
        matches!(
            entry.status,
            index::EntryStatus::Removed | index::EntryStatus::Tree
        )
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

fn record_superseded(
    layout: &RepoLayout,
    superseded: Hash,
    group: &mut Group,
) -> Result<(), Error> {
    let branch = match refs::read_head(layout) {
        Ok(Head::Branch(name)) => name,
        _ => String::new(),
    };
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    recovery::record_in(
        layout,
        &RecoveryEntry {
            timestamp,
            op: "amend".to_owned(),
            superseded,
            branch,
        },
        group,
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
#[cfg(test)]
fn advance_head(layout: &RepoLayout, commit: &Hash, expected: Option<Hash>) -> Result<(), Error> {
    let condition = match expected {
        Some(h) => RefWriteCondition::Match(h),
        None => RefWriteCondition::Missing,
    };
    head::advance(layout, commit, condition).map_err(|e| branch_moved(e, commit))
}

/// A move of `HEAD` that lost the race is [`Error::BranchMoved`]. Any other
/// failure is [`Error::Head`].
fn branch_moved(error: head::Error, commit: &Hash) -> Error {
    match error {
        head::Error::WriteRef {
            branch,
            source: RefError::Conflict(_),
        } => Error::BranchMoved {
            branch,
            commit: *commit,
        },
        other => Error::Head(other),
    }
}

/// A failed flush of the commit's group.
fn store_io(error: std::io::Error) -> Error {
    Error::Store(kit_core::store::StoreError::Io(error))
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

    use kit_core::index::IndexEntry;
    use kit_core::object::Blob;
    use kit_core::sign::KeyPair;

    /// A repository with one commit of `a.txt`, `HEAD` on `main`, and the file
    /// staged again with new bytes.
    fn repo_with_staged_edit() -> (tempfile::TempDir, RepoLayout, ObjectStore, Hash) {
        let (dir, layout) = fresh_repo();
        let store = ObjectStore::open(&layout).unwrap();
        stage(&layout, &store, "a.txt", b"one\n");
        let first = create_commit(&layout, &store, "first", None);
        stage(&layout, &store, "a.txt", b"two\n");
        (dir, layout, store, first)
    }

    fn stage(layout: &RepoLayout, store: &ObjectStore, path: &str, bytes: &[u8]) {
        let blob = Object::Blob(Blob {
            data: bytes.to_vec(),
        });
        let hash = store.write(&serialize::serialize(&blob).unwrap()).unwrap();
        let mut idx = index::read_index(layout).unwrap();
        idx.entries.retain(|entry| entry.path != path);
        idx.entries.push(IndexEntry {
            path: path.to_owned(),
            status: index::EntryStatus::Blob,
            object_hash: hash,
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
        });
        index::write_index(layout, &idx).unwrap();
    }

    fn create_commit(
        layout: &RepoLayout,
        store: &ObjectStore,
        message: &str,
        amend: Option<bool>,
    ) -> Hash {
        let pending = begin(layout, store, amend.is_some()).unwrap();
        let mut signer = Signer::File(KeyPair::from_seed([1; 32]));
        let public = signer.public_key().unwrap();
        let created = create(
            layout,
            store,
            &pending,
            &Request {
                message,
                author: Identity::ed25519(public),
                signer_public: public,
                all: false,
                allow_empty: false,
            },
            &mut signer,
            &|_| Ok(()),
            &kit_core::observer::NoopObserver,
        )
        .unwrap();
        created.commit
    }

    #[test]
    fn a_plain_commit_moves_the_ref_and_leaves_the_index_and_no_temp_file() {
        let (_dir, layout, store, first) = repo_with_staged_edit();
        let index_before = std::fs::read(layout.index_file()).unwrap();
        let second = create_commit(&layout, &store, "second", None);
        assert_ne!(first, second);
        assert_eq!(refs::read_ref(&layout, "main").unwrap(), Some(second));
        assert_eq!(std::fs::read(layout.index_file()).unwrap(), index_before);
        let Object::Commit(commit) = store.read_object(&second).unwrap() else {
            panic!("a commit");
        };
        assert_eq!(commit.parents, [first]);
        for dir in [layout.heads_dir(), layout.common_dir().to_path_buf()] {
            let temps = std::fs::read_dir(dir)
                .unwrap()
                .filter(|e| {
                    e.as_ref()
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".kit.tmp.")
                })
                .count();
            assert_eq!(temps, 0, "no temp file is left behind");
        }
    }

    /// The count the full flushes of a commit are pinned to on Apple file
    /// systems: the bytes, the names, then the names of the ref and the index.
    /// A build with `history-mmr` writes the ref with its ancestry in one step
    /// of its own.
    #[cfg(all(target_os = "macos", not(feature = "history-mmr")))]
    #[test]
    fn a_plain_commit_and_an_amend_make_three_full_flushes_each() {
        let (_dir, layout, store, _first) = repo_with_staged_edit();
        let before = kit_core::fault::flushes();
        create_commit(&layout, &store, "second", None);
        assert_eq!(kit_core::fault::flushes() - before, 3, "a commit");
        stage(&layout, &store, "a.txt", b"three\n");
        let before = kit_core::fault::flushes();
        create_commit(&layout, &store, "amended", Some(true));
        assert_eq!(kit_core::fault::flushes() - before, 3, "an amend");
    }

    #[test]
    fn an_amend_records_the_replaced_tip_before_it_moves_the_ref() {
        let (_dir, layout, store, first) = repo_with_staged_edit();
        let second = create_commit(&layout, &store, "second", None);
        stage(&layout, &store, "a.txt", b"three\n");
        let amended = create_commit(&layout, &store, "amended", Some(true));
        assert_ne!(amended, second);
        assert_eq!(refs::read_ref(&layout, "main").unwrap(), Some(amended));
        let log = recovery::read_all(&layout).unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].superseded, second);
        assert_eq!(log[0].op, "amend");
        assert_eq!(log[0].branch, "main");
        let Object::Commit(commit) = store.read_object(&amended).unwrap() else {
            panic!("a commit");
        };
        assert_eq!(commit.parents, [first], "the amend replaced the tip");
        // The rebuilt index holds the tree of the amended commit.
        let idx = index::read_index(&layout).unwrap();
        assert_eq!(idx.entries.len(), 1);
        assert_eq!(
            idx.entries[0].object_hash,
            index::from_tree(&store, commit.tree_hash).unwrap().entries[0].object_hash
        );
    }

    #[test]
    fn a_lost_race_is_a_branch_that_moved_and_other_failures_are_not() {
        let commit = [3; 32];
        let moved = branch_moved(
            head::Error::WriteRef {
                branch: "main".to_owned(),
                source: RefError::Conflict("main".to_owned()),
            },
            &commit,
        );
        assert!(
            matches!(moved, Error::BranchMoved { ref branch, commit: c } if branch == "main" && c == commit),
            "{moved:?}"
        );
        let other = branch_moved(
            head::Error::WriteRef {
                branch: "main".to_owned(),
                source: RefError::NoHead,
            },
            &commit,
        );
        assert!(matches!(other, Error::Head(_)), "{other:?}");
    }

    #[test]
    fn a_failed_flush_is_a_store_error() {
        let error = store_io(std::io::Error::other("flush failed"));
        assert!(
            matches!(&error, Error::Store(kit_core::store::StoreError::Io(e)) if e.to_string() == "flush failed"),
            "{error:?}"
        );
    }
}

//! Replay the commits of the current branch onto another base.
//!
//! [`start`] detaches `HEAD` at the new base and replays the commits one at a
//! time. A replay that conflicts pauses: the conflict material is in the index
//! and the files, the state is on disk, and the call returns
//! [`Outcome::Paused`]. [`resume`] either commits the resolution that the user
//! staged or, with `skip`, drops the paused commit. Then it replays the rest.
//! [`abort`] puts the branch and the files back to the state before the
//! rebase. The state machine itself lives in `kit_core::ops::rebase`.
//!
//! An interactive rebase asks an [`Editor`] to edit a todo list before it
//! changes anything. [`parse_todo`] reads the edited text. The same editor
//! rewords a commit and combines the messages of a squash.
//!
//! A replayed commit keeps the author and the time of the original, and the
//! signer signs it again. The caller holds the worktree lock for the whole
//! run. See [`crate::lock`].

use std::fmt::Write as _;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use kit_core::hash::{self, Hash};
use kit_core::layout::RepoLayout;
use kit_core::object::{Commit, Identity, KitError, Object};
use kit_core::observer::Observer;
use kit_core::ops::cherry_pick::{CherryPickError, cherry_pick};
use kit_core::ops::conflict_state::{
    self, ConflictRecord, ConflictStateError, in_progress_op_name,
};
pub use kit_core::ops::rebase::RebaseAction;
use kit_core::ops::rebase::{
    RebaseError, RebaseState, cleanup_rebase, collect_commits_to_replay, is_rebase_in_progress,
    read_state, rebase_dir_path, write_state,
};
use kit_core::ops::recovery::{self, RecoveryEntry, RecoveryError};
use kit_core::refs::{self, Head, RefError, RefWriteCondition};
use kit_core::store::{ObjectStore, StoreError};
use kit_core::worktree::{self, WorktreeError};
use kit_sync::worktree::{
    ensure_restore_safe, read_or_seed_index_from_head, restore_worktree_and_index,
    sync_index_to_tree,
};

use crate::signing::{self, Author, Signer, Signing, WriteError, write_signed};
use crate::{conflict, revspec};

/// The longest todo text that [`parse_todo`] reads (1 MiB). It is the longest
/// message that an editor may return.
pub const MAX_TODO_BYTES: usize = 1024 * 1024;

/// The hex characters that identify a commit in the todo list.
const TODO_ABBREV: usize = 12;

/// Errors from reading the todo list.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TodoError {
    /// The text is longer than [`MAX_TODO_BYTES`].
    #[error("todo list is longer than {MAX_TODO_BYTES} bytes")]
    TooLong,
    /// The `edit` command stops to amend a commit. A rebase does not support
    /// it.
    #[error(
        "'edit' (stop to amend) is not yet supported; use pick, reword, squash, fixup, or drop"
    )]
    EditUnsupported,
    /// A line starts with a word that is no command.
    #[error("unknown rebase command '{0}'")]
    UnknownCommand(String),
    /// A squash or a fixup has no commit before it to fold into.
    #[error("cannot '{0}' as the first commit; it has nothing to fold into")]
    NothingToFoldInto(String),
    /// A line has a command and no commit.
    #[error("missing commit on todo line: '{0}'")]
    MissingCommit(String),
    /// A line names a commit that the rebase does not replay.
    #[error("todo line refers to an unknown commit: '{0}'")]
    UnknownCommit(String),
    /// A line names a prefix that matches more than one commit.
    #[error("ambiguous commit '{token}' on todo line: '{line}'")]
    AmbiguousCommit {
        /// The prefix.
        token: String,
        /// The line.
        line: String,
    },
}

/// Errors from a rebase.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Another merge, cherry-pick, revert or rebase is unfinished.
    #[error("a {0} is already in progress (use --continue or --abort)")]
    InProgress(&'static str),
    /// No rebase is in progress.
    #[error("no rebase in progress")]
    NoRebaseInProgress,
    /// The new base does not resolve.
    #[error("no such commit: {spec} ({source})")]
    NoSuchCommit {
        /// The revision text.
        spec: String,
        /// Why it does not resolve.
        source: revspec::Error,
    },
    /// `HEAD` has no commit to replay.
    #[error("no commits on current branch")]
    NoHeadCommit,
    /// `HEAD` cannot be resolved.
    #[error("resolve HEAD: {0}")]
    ResolveHead(RefError),
    /// `HEAD` cannot be read.
    #[error("read HEAD: {0}")]
    ReadHead(RefError),
    /// `HEAD` names no branch.
    #[error("cannot rebase with detached HEAD")]
    DetachedHead,
    /// The commits to replay cannot be listed.
    #[error("collect commits: {0}")]
    CollectCommits(RebaseError),
    /// The editor failed.
    #[error("editor: {0}")]
    Editor(io::Error),
    /// The todo list is wrong.
    #[error(transparent)]
    Todo(#[from] TodoError),
    /// An object that must be a commit is another kind of object.
    #[error("object is not a commit")]
    NotACommit,
    /// A commit cannot be read.
    #[error("read commit: {0}")]
    ReadCommit(StoreError),
    /// A restore primitive of the worktree failed. The text is final.
    #[error("{0}")]
    Worktree(String),
    /// The rebase state cannot be written at the start.
    #[error("write rebase state: {0}")]
    WriteState(RebaseError),
    /// `HEAD` cannot detach at the new base.
    #[error("detach HEAD: {0}")]
    DetachHead(RefError),
    /// The rebase state cannot be read.
    #[error("read state: {0}")]
    ReadState(RebaseError),
    /// The conflict records cannot be read.
    #[error("read conflicts: {0}")]
    ReadConflicts(ConflictStateError),
    /// There is no paused commit to drop.
    #[error("nothing to skip; no commit is paused")]
    NothingToSkip,
    /// A conflicting file still holds markers.
    #[error("unresolved conflict markers remain in '{0}'; resolve and `kit add` it")]
    UnresolvedMarkers(String),
    /// The state names records and no paused commit.
    #[error("rebase state is inconsistent: no paused commit")]
    InconsistentState,
    /// The tree of the resolved index cannot be built.
    #[error("build tree from index: {0}")]
    BuildTree(WorktreeError),
    /// `HEAD` cannot move to the replayed commit.
    #[error("update HEAD: {0}")]
    UpdateHead(RefError),
    /// The conflict records cannot be cleared.
    #[error("clear conflicts: {0}")]
    ClearConflicts(ConflictStateError),
    /// The rebase state cannot be written between commits.
    #[error("persist state: {0}")]
    PersistState(RebaseError),
    /// A commit cannot be replayed.
    #[error("cherry-pick: {0}")]
    CherryPick(CherryPickError),
    /// The conflict records or the result tree cannot be written.
    #[error("write conflicts: {0}")]
    WriteConflicts(ConflictStateError),
    /// A squash or a fixup finds no commit to fold into.
    #[error("'squash'/'fixup' has no preceding commit to fold into")]
    NoPrecedingCommit,
    /// The key or the author identity is not usable.
    #[error(transparent)]
    Signing(#[from] signing::Error),
    /// The replayed commit cannot be encoded.
    #[error("serialize: {0}")]
    Serialize(KitError),
    /// The replayed commit cannot be stored.
    #[error("store: {0}")]
    Store(StoreError),
    /// `HEAD` has no commit after the last replay.
    #[error("rebase: HEAD missing at finalize (in-progress state may be corrupted); aborting")]
    HeadMissingAtFinish,
    /// `HEAD` cannot be read after the last replay.
    #[error("read HEAD: {0}")]
    ReadFinalHead(RefError),
    /// The old tip cannot be recorded for recovery.
    #[error("recovery log: {0}")]
    Recovery(RecoveryError),
    /// The branch cannot move to the new tip.
    #[error("write ref: {0}")]
    WriteRef(RefError),
    /// `HEAD` cannot attach to the branch again.
    #[error("reattach HEAD: {0}")]
    ReattachHead(RefError),
    /// The branch cannot go back to the old tip.
    #[error("restore ref: {0}")]
    RestoreRef(RefError),
    /// `HEAD` cannot go back to the branch.
    #[error("restore HEAD: {0}")]
    RestoreHead(RefError),
    /// The conflict workflow failed.
    #[error(transparent)]
    Conflict(#[from] conflict::Error),
}

/// What a rebase reports to its [`Observer`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// A conflict path is written into the files.
    Conflict(conflict::Event),
    /// An editor returned an empty message for a reword. The original message
    /// stays.
    EmptyReword,
}

/// Forwards the events of the conflict workflow to the observer of a rebase.
struct ConflictEvents<'a>(&'a dyn Observer<Event>);

impl Observer<conflict::Event> for ConflictEvents<'_> {
    fn event(&self, event: &conflict::Event) {
        self.0.event(&Event::Conflict(event.clone()));
    }
}

/// An editor for the todo list and for commit messages.
pub trait Editor {
    /// Show `seed` to the user and return the text that comes back. Lines
    /// that start with `#` are comments. The editor strips them.
    ///
    /// # Errors
    /// [`io::Error`] when the editor cannot run or fails.
    fn edit(&mut self, seed: &str) -> io::Result<String>;
}

/// What to rebase onto.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// A branch, tag, `HEAD~n`, hash or other revision.
    pub onto: &'a str,
    /// Edit the todo list before the replay.
    pub interactive: bool,
}

/// How a rebase has ended or paused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Outcome {
    /// The branch is at the new base already.
    UpToDate {
        /// The branch.
        branch: String,
        /// Its tip.
        head: Hash,
    },
    /// A replay conflicted. The user resolves it, then runs [`resume`].
    Paused {
        /// The commit that was replayed.
        replaying: Hash,
        /// One record for each conflicting path.
        conflicts: Vec<ConflictRecord>,
    },
    /// Every commit is replayed and the branch is at the new tip.
    Finished {
        /// The branch.
        branch: String,
        /// The tip before the rebase.
        old: Hash,
        /// The tip after the rebase.
        new: Hash,
        /// The count of commits that were replayed.
        replayed: usize,
    },
}

/// The branch that [`abort`] restored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aborted {
    /// The branch.
    pub branch: String,
    /// Its tip, from before the rebase.
    pub head: Hash,
}

fn commit_tree(store: &ObjectStore, commit: Hash) -> Result<Hash, Error> {
    read_commit(store, commit).map(|c| c.tree_hash)
}

fn read_commit(store: &ObjectStore, h: Hash) -> Result<Commit, Error> {
    match store.read_object(&h) {
        Ok(Object::Commit(c)) => Ok(c),
        Ok(_) => Err(Error::NotACommit),
        Err(e) => Err(Error::ReadCommit(e)),
    }
}

/// `HEAD` as a commit, or `onto` when `HEAD` is empty.
fn head_or(layout: &RepoLayout, onto: Hash) -> Hash {
    match refs::resolve_head(layout) {
        Ok(Some(h)) => h,
        _ => onto,
    }
}

/// Start a rebase of the current branch onto `request.onto`.
///
/// The function resolves the base and lists the commits to replay. An
/// interactive request lets the editor change the list. Nothing changes
/// before the key is loaded and the restore guards pass. Then it records the
/// state, restores the files to the base, detaches `HEAD` and replays.
///
/// # Errors
/// [`Error::InProgress`] when another operation is unfinished. [`Error`] when
/// a revision, the todo list, the key, the store or the files fail.
pub fn start(
    layout: &RepoLayout,
    store: &ObjectStore,
    request: &Request<'_>,
    signing: &dyn Signing,
    editor: &mut dyn Editor,
    observer: &dyn Observer<Event>,
) -> Result<Outcome, Error> {
    if let Some(op) = in_progress_op_name(layout) {
        return Err(Error::InProgress(op));
    }
    // The name of the branch to rebase comes from `HEAD`, and not from the
    // target.
    let onto = revspec::resolve_revision(store, layout, request.onto).map_err(|source| {
        Error::NoSuchCommit {
            spec: request.onto.to_owned(),
            source,
        }
    })?;
    let orig_head = match refs::resolve_head(layout) {
        Ok(Some(h)) => h,
        Ok(None) => return Err(Error::NoHeadCommit),
        Err(e) => return Err(Error::ResolveHead(e)),
    };
    let head_name = match refs::read_head(layout) {
        Ok(Head::Branch(name)) => name,
        Ok(Head::Detached(_)) => return Err(Error::DetachedHead),
        Err(e) => return Err(Error::ReadHead(e)),
    };
    let candidates =
        collect_commits_to_replay(store, orig_head, onto).map_err(Error::CollectCommits)?;

    // A branch at the base needs nothing, in both modes. A branch behind the
    // base falls through, and the finish moves it forward.
    if orig_head == onto {
        return Ok(Outcome::UpToDate {
            branch: head_name,
            head: orig_head,
        });
    }

    let (todo, actions) = if request.interactive {
        if candidates.is_empty() {
            (Vec::new(), Vec::new())
        } else {
            edit_todo(store, &candidates, orig_head, onto, editor)?
        }
    } else {
        let actions = vec![RebaseAction::Pick; candidates.len()];
        (candidates, actions)
    };
    let state = RebaseState {
        head_name,
        orig_head,
        onto,
        todo,
        actions,
        done: Vec::new(),
    };
    let signer = signing.open(layout)?;
    let onto_tree = commit_tree(store, onto)?;
    ensure_restore_safe(layout, store, onto_tree).map_err(Error::Worktree)?;
    write_state(layout, &state).map_err(Error::WriteState)?;
    restore_worktree_and_index(layout, store, onto_tree).map_err(Error::Worktree)?;
    refs::write_head_detached(layout, &onto).map_err(Error::DetachHead)?;
    replay(layout, store, Some(signer), signing, editor, observer)
}

/// Continue a paused rebase. With `skip`, drop the paused commit and discard
/// its material. Otherwise commit the resolution of the user as the replayed
/// commit. Then replay the rest.
///
/// # Errors
/// [`Error::NoRebaseInProgress`] when no rebase is recorded. [`Error`] when
/// a resolution is not complete, the guards refuse, or the key, the store or
/// the files fail.
pub fn resume(
    layout: &RepoLayout,
    store: &ObjectStore,
    skip: bool,
    signing: &dyn Signing,
    editor: &mut dyn Editor,
    observer: &dyn Observer<Event>,
) -> Result<Outcome, Error> {
    if !is_rebase_in_progress(layout) {
        return Err(Error::NoRebaseInProgress);
    }
    let rebase_dir = rebase_dir_path(layout);
    let mut state = read_state(layout).map_err(Error::ReadState)?;
    let records = conflict_state::read_conflicts(&rebase_dir).map_err(Error::ReadConflicts)?;

    if skip {
        skip_paused_commit(layout, store, &rebase_dir, &mut state, &records)?;
    } else if !records.is_empty() {
        commit_resolved_commit(
            layout,
            store,
            &rebase_dir,
            &mut state,
            &records,
            signing,
            editor,
            observer,
        )?;
    }
    // Either no commit was paused, or the paused commit is consumed now.
    replay(layout, store, None, signing, editor, observer)
}

/// Drop the paused front commit with no replacement. Discard its material.
fn skip_paused_commit(
    layout: &RepoLayout,
    store: &ObjectStore,
    rebase_dir: &std::path::Path,
    state: &mut RebaseState,
    records: &[ConflictRecord],
) -> Result<(), Error> {
    if state.todo.is_empty() {
        return Err(Error::NothingToSkip);
    }
    let head_tree = commit_tree(store, head_or(layout, state.onto))?;
    // The clean hunks of the skipped commit go too, and not only the
    // conflict paths.
    let op_result = conflict_state::read_result_tree(rebase_dir).ok().flatten();
    // Refuse before any change when the discard would destroy user work. An
    // abort applies the same guard.
    conflict::ensure_abort_safe(layout, store, records, head_tree, op_result)?;
    conflict::reset_paths(layout, store, records, head_tree, op_result)?;
    state.consume_front();
    persist_after_consume(layout, rebase_dir, state)
}

/// Commit the resolution of the paused front commit and move it to the done
/// list.
///
/// The tree comes from the resolved index. The conflict-time tree is not
/// used.
#[allow(clippy::too_many_arguments)] // the state of one step of the operation
fn commit_resolved_commit(
    layout: &RepoLayout,
    store: &ObjectStore,
    rebase_dir: &std::path::Path,
    state: &mut RebaseState,
    records: &[ConflictRecord],
    signing: &dyn Signing,
    editor: &mut dyn Editor,
    observer: &dyn Observer<Event>,
) -> Result<(), Error> {
    if let Some(path) = conflict::first_unresolved_marker(layout.worktree_root(), records)? {
        return Err(Error::UnresolvedMarkers(path));
    }
    conflict::ensure_staged(layout, store, records)?;
    let Some(&target) = state.todo.first() else {
        return Err(Error::InconsistentState);
    };
    let head_hash = head_or(layout, state.onto);
    let idx = read_or_seed_index_from_head(layout, store).map_err(Error::Worktree)?;
    let tree = worktree::build_tree_from_index(store, &idx).map_err(Error::BuildTree)?;
    let mut signer = signing.open(layout)?;
    // The parent and the message follow the rule of a replay without a
    // conflict. The editor of a reword or a squash opens now, because the
    // tree is resolved.
    let plan = plan_step_commit(
        store,
        state.front_action(),
        target,
        head_hash,
        editor,
        observer,
    )?;
    let new_hash = build_commit(store, signer.as_mut(), plan, tree)?;
    // The index follows the committed tree. The files stay, because they hold
    // the resolution and the edits that the user made after staging.
    sync_index_to_tree(layout, store, tree).map_err(Error::Worktree)?;
    refs::write_head_detached(layout, &new_hash).map_err(Error::UpdateHead)?;
    state.done.push(target);
    state.consume_front();
    persist_after_consume(layout, rebase_dir, state)
}

/// Clear the conflict records and save the state.
fn persist_after_consume(
    layout: &RepoLayout,
    rebase_dir: &std::path::Path,
    state: &RebaseState,
) -> Result<(), Error> {
    conflict_state::write_conflicts(rebase_dir, &[]).map_err(Error::ClearConflicts)?;
    write_state(layout, state).map_err(Error::PersistState)
}

/// Stop the rebase. Put `HEAD`, the branch, the index and the files back to
/// the state before the rebase, and clear the recorded state.
///
/// The function refuses, before it changes anything, when it would overwrite
/// work that is not material of the rebase.
///
/// # Errors
/// [`Error::NoRebaseInProgress`] when no rebase is recorded. [`Error`] when
/// the guards refuse or the store or the files fail.
pub fn abort(layout: &RepoLayout, store: &ObjectStore) -> Result<Aborted, Error> {
    if !is_rebase_in_progress(layout) {
        return Err(Error::NoRebaseInProgress);
    }
    let state = read_state(layout).map_err(Error::ReadState)?;
    let orig_tree = commit_tree(store, state.orig_head)?;
    let rebase_dir = rebase_dir_path(layout);
    let records = conflict_state::read_conflicts(&rebase_dir).map_err(Error::ReadConflicts)?;
    // The result tree of the paused commit lets the guards treat its clean
    // hunks as material to discard.
    let op_result = conflict_state::read_result_tree(&rebase_dir).ok().flatten();
    // The final restore goes to `orig_tree`, so the guards judge the other
    // paths against it. They run before the reset, which destroys material.
    conflict::ensure_abort_safe(layout, store, &records, orig_tree, op_result)?;
    if !records.is_empty() || op_result.is_some() {
        // Reset the paths to the tree of the detached `HEAD`. The files and
        // the index then match `HEAD`, and the restore below moves cleanly to
        // `orig_head`.
        let head_tree = commit_tree(store, head_or(layout, state.onto))?;
        conflict::reset_paths(layout, store, &records, head_tree, op_result)?;
    }
    ensure_restore_safe(layout, store, orig_tree).map_err(Error::Worktree)?;
    restore_worktree_and_index(layout, store, orig_tree).map_err(Error::Worktree)?;
    // The rollback goes through the ref writer that records history, so a
    // build with `history-mmr` appends it under the repository lock.
    refs::write_ref_recording_history(
        layout,
        &state.head_name,
        RefWriteCondition::Any,
        &state.orig_head,
    )
    .map_err(Error::RestoreRef)?;
    refs::write_head_branch(layout, &state.head_name).map_err(Error::RestoreHead)?;
    let _ = cleanup_rebase(layout);
    Ok(Aborted {
        branch: state.head_name,
        head: state.orig_head,
    })
}

/// Replay the commits that remain in the state. Pause on a conflict. At the
/// end, move the branch to the new tip and attach `HEAD`.
///
/// `signer` is the key that [`start`] loaded, if any. A call from [`resume`]
/// loads its own.
#[allow(clippy::too_many_lines)] // one loop and its finish
fn replay(
    layout: &RepoLayout,
    store: &ObjectStore,
    signer: Option<Box<dyn Signer>>,
    signing: &dyn Signing,
    editor: &mut dyn Editor,
    observer: &dyn Observer<Event>,
) -> Result<Outcome, Error> {
    let mut state = read_state(layout).map_err(Error::ReadState)?;
    let mut signer = match signer {
        Some(signer) => signer,
        None => signing.open(layout)?,
    };
    let rebase_dir = rebase_dir_path(layout);

    while let Some(&target) = state.todo.first() {
        // A result tree from an earlier conflict is stale now. A later pause
        // must not make an abort or a skip read it.
        conflict_state::clear_result_tree(&rebase_dir);
        // A squash or a fixup folds into a commit that this rebase applied.
        // A skip of a conflicting first pick can leave one as the first step.
        // `done` is empty while nothing is applied, so the check fails before
        // any change, and an abort still works.
        if state.front_action().folds_into_previous() && state.done.is_empty() {
            let verb = if state.front_action() == RebaseAction::Fixup {
                "fixup"
            } else {
                "squash"
            };
            return Err(TodoError::NothingToFoldInto(verb.to_owned()).into());
        }
        let head_hash = head_or(layout, state.onto);
        let ours_tree = commit_tree(store, head_hash)?;
        // The first-parent walk keeps merge commits. The cherry-pick of a
        // merge needs a mainline, so a merge replays against its first
        // parent. Without it the rebase would fail with the ref already
        // moved.
        let mainline = match store.read_object(&target) {
            Ok(Object::Commit(c)) if c.parents.len() >= 2 => Some(1),
            _ => None,
        };
        let result = cherry_pick(store, target, ours_tree, mainline).map_err(Error::CherryPick)?;
        if result.has_conflicts() {
            // Save the state first. Then the material goes into the files and
            // the index, and a resume commits the resolved tree. A resume
            // never runs the cherry-pick again.
            let _ = write_state(layout, &state);
            ensure_restore_safe(layout, store, result.tree_hash).map_err(Error::Worktree)?;
            let records = conflict::materialize(
                layout,
                store,
                result.tree_hash,
                &result.conflicts,
                &ConflictEvents(observer),
            )?;
            conflict_state::write_conflicts(&rebase_dir, &records)
                .map_err(Error::WriteConflicts)?;
            // The result tree lets an abort treat the clean hunks of this
            // step as material to discard.
            conflict_state::write_result_tree(&rebase_dir, &result.tree_hash)
                .map_err(Error::WriteConflicts)?;
            return Ok(Outcome::Paused {
                replaying: target,
                conflicts: records,
            });
        }
        ensure_restore_safe(layout, store, result.tree_hash).map_err(Error::Worktree)?;
        // An editor, for a reword or a squash, opens here. The tree is clean.
        let plan = plan_step_commit(
            store,
            state.front_action(),
            target,
            head_hash,
            editor,
            observer,
        )?;
        let new_hash = build_commit(store, signer.as_mut(), plan, result.tree_hash)?;
        restore_worktree_and_index(layout, store, result.tree_hash).map_err(Error::Worktree)?;
        refs::write_head_detached(layout, &new_hash).map_err(Error::UpdateHead)?;
        state.done.push(target);
        state.consume_front();
        write_state(layout, &state).map_err(Error::PersistState)?;
    }

    // `HEAD` is detached for the whole rebase, so it always has a commit
    // here. Even an empty rebase leaves it at the base. A missing commit
    // means that the state is corrupt. Fail closed. Do not move the branch to
    // the base and lose the replayed tip.
    let final_head = match refs::resolve_head(layout) {
        Ok(Some(h)) => h,
        Ok(None) => return Err(Error::HeadMissingAtFinish),
        Err(e) => return Err(Error::ReadFinalHead(e)),
    };
    // The replayed history supersedes the old tip. Record the old tip before
    // the branch moves, while the lock is held. The state pins it until the
    // cleanup below, and the record keeps it alive after.
    if state.orig_head != final_head {
        let entry = RecoveryEntry {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            op: "rebase".to_owned(),
            superseded: state.orig_head,
            branch: state.head_name.clone(),
        };
        recovery::record(layout, &entry).map_err(Error::Recovery)?;
    }
    refs::write_ref_recording_history(
        layout,
        &state.head_name,
        RefWriteCondition::Any,
        &final_head,
    )
    .map_err(Error::WriteRef)?;
    refs::write_head_branch(layout, &state.head_name).map_err(Error::ReattachHead)?;
    let _ = cleanup_rebase(layout);
    Ok(Outcome::Finished {
        branch: state.head_name,
        old: state.orig_head,
        new: final_head,
        replayed: state.done.len(),
    })
}

/// The parent, message, author and time of a replayed commit.
///
/// A pick or a reword makes a child of `HEAD`. A squash or a fixup folds the
/// target into `HEAD`: the new commit takes the place of `HEAD`, so its parent
/// is the parent of `HEAD`. A squash combines the messages, and a fixup keeps
/// the message of `HEAD`. A replay keeps the authorship, and only the signature
/// is new. The time is the author time.
struct StepCommit {
    parent: Hash,
    message: Vec<u8>,
    author: Identity,
    timestamp: u64,
}

fn plan_step_commit(
    store: &ObjectStore,
    action: RebaseAction,
    target: Hash,
    head_hash: Hash,
    editor: &mut dyn Editor,
    observer: &dyn Observer<Event>,
) -> Result<StepCommit, Error> {
    match action {
        RebaseAction::Pick => {
            let original = read_commit(store, target)?;
            Ok(StepCommit {
                parent: head_hash,
                message: original.message,
                author: original.author,
                timestamp: original.timestamp,
            })
        }
        RebaseAction::Reword => {
            let original = read_commit(store, target)?;
            Ok(StepCommit {
                parent: head_hash,
                message: reworded_message(&original.message, editor, observer)?,
                author: original.author,
                timestamp: original.timestamp,
            })
        }
        RebaseAction::Squash | RebaseAction::Fixup => {
            // The rebase refuses a fold as the first applied commit, so
            // `HEAD` is a commit that the rebase just built, and it has one
            // parent.
            let head_commit = read_commit(store, head_hash)?;
            let parent = head_commit
                .parents
                .first()
                .copied()
                .ok_or(Error::NoPrecedingCommit)?;
            let message = if action == RebaseAction::Fixup {
                head_commit.message.clone()
            } else {
                let target_message = read_commit(store, target)?.message;
                squashed_message(&head_commit.message, &target_message, editor)?
            };
            Ok(StepCommit {
                parent,
                message,
                author: head_commit.author,
                timestamp: head_commit.timestamp,
            })
        }
    }
}

fn build_commit(
    store: &ObjectStore,
    signer: &mut dyn Signer,
    plan: StepCommit,
    tree: Hash,
) -> Result<Hash, Error> {
    write_signed(
        store,
        signer,
        tree,
        vec![plan.parent],
        Author::Given(plan.author),
        plan.message,
        plan.timestamp,
    )
    .map_err(|e| match e {
        WriteError::Signing(e) => Error::Signing(e),
        WriteError::Serialize(e) => Error::Serialize(e),
        WriteError::Store(e) => Error::Store(e),
    })
}

/// Open the editor on a reword seed. An empty result keeps the original
/// message and does not abort the rebase.
fn reworded_message(
    original: &[u8],
    editor: &mut dyn Editor,
    observer: &dyn Observer<Event>,
) -> Result<Vec<u8>, Error> {
    let seed = format!(
        "{}\n\
         # Reword: edit the commit message above. Lines starting with '#'\n\
         # are ignored. An empty message keeps the original message.\n",
        String::from_utf8_lossy(original)
    );
    let edited = editor.edit(&seed).map_err(Error::Editor)?;
    if edited.trim().is_empty() {
        observer.event(&Event::EmptyReword);
        Ok(original.to_vec())
    } else {
        Ok(edited.into_bytes())
    }
}

/// Combine the message of the kept commit with the message of the squashed
/// commit, through the editor. An empty result joins the two messages.
fn squashed_message(
    head_message: &[u8],
    target_message: &[u8],
    editor: &mut dyn Editor,
) -> Result<Vec<u8>, Error> {
    let seed = format!(
        "{}\n\n{}\n\n\
         # This is a combination of 2 commits; the first message is the one\n\
         # being squashed into. Edit the combined message above. Lines\n\
         # starting with '#' are ignored.\n",
        String::from_utf8_lossy(head_message),
        String::from_utf8_lossy(target_message),
    );
    let edited = editor.edit(&seed).map_err(Error::Editor)?;
    if edited.trim().is_empty() {
        let mut combined = head_message.to_vec();
        combined.extend_from_slice(b"\n\n");
        combined.extend_from_slice(target_message);
        Ok(combined)
    } else {
        Ok(edited.into_bytes())
    }
}

/// The first line of the message of a commit, for the todo list.
fn commit_subject(store: &ObjectStore, h: Hash) -> String {
    match store.read_object(&h) {
        Ok(Object::Commit(c)) => String::from_utf8_lossy(&c.message)
            .lines()
            .next()
            .unwrap_or("")
            .trim()
            .to_owned(),
        _ => String::new(),
    }
}

/// Write the todo list for `candidates`, let the editor change it, and read
/// the result. The result can be empty. Then the branch resets to the base.
/// Nothing changes before this returns.
fn edit_todo(
    store: &ObjectStore,
    candidates: &[Hash],
    orig_head: Hash,
    onto: Hash,
    editor: &mut dyn Editor,
) -> Result<(Vec<Hash>, Vec<RebaseAction>), Error> {
    // One `pick` line for each candidate, the oldest first.
    let mut template = String::new();
    for h in candidates {
        let _ = writeln!(
            template,
            "pick {} {}",
            abbreviate(h),
            commit_subject(store, *h)
        );
    }
    let _ = write!(
        template,
        "\n\
         # Rebase {}..{} onto {}.\n\
         #\n\
         # Commands (one per line, in apply order — top is applied first):\n\
         #   p, pick   <commit>  = use the commit\n\
         #   r, reword <commit>  = use the commit, but edit its message\n\
         #   s, squash <commit>  = fold into the previous commit, combining messages\n\
         #   f, fixup  <commit>  = fold into the previous commit, discard this message\n\
         #   d, drop   <commit>  = remove the commit\n\
         #\n\
         # Reorder lines to reorder commits. Deleting a line drops that commit.\n\
         # A squash/fixup cannot be the first line. 'edit' is not yet supported.\n\
         # Removing every line resets the branch to the base.\n",
        abbreviate(&onto),
        abbreviate(&orig_head),
        abbreviate(&onto),
    );
    let edited = editor.edit(&template).map_err(Error::Editor)?;
    Ok(parse_todo(candidates, &edited)?)
}

fn abbreviate(h: &Hash) -> String {
    hash::to_hex(h)[..TODO_ABBREV].to_owned()
}

/// Read an edited todo list. Return the commits to replay in the new order,
/// each with its action.
///
/// A line is a command and a commit. The command is `pick`, `reword`,
/// `squash`, `fixup` or `drop`, or the first letter. The commit is a prefix of
/// the hash of one of `candidates`. A blank line and a line that starts with
/// `#` are ignored. A `drop` line must still name a commit, so a typo is
/// caught.
///
/// # Errors
/// A [`TodoError`] for text longer than [`MAX_TODO_BYTES`], an unknown or
/// unsupported command, a squash or fixup as the first line, and a missing,
/// unknown or ambiguous commit.
pub fn parse_todo(
    candidates: &[Hash],
    edited: &str,
) -> Result<(Vec<Hash>, Vec<RebaseAction>), TodoError> {
    if edited.len() > MAX_TODO_BYTES {
        return Err(TodoError::TooLong);
    }
    let mut todo = Vec::new();
    let mut actions = Vec::new();
    for raw in edited.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let verb = parts.next().unwrap_or("");
        let action = match verb {
            "p" | "pick" => RebaseAction::Pick,
            "r" | "reword" => RebaseAction::Reword,
            "s" | "squash" => RebaseAction::Squash,
            "f" | "fixup" => RebaseAction::Fixup,
            "d" | "drop" => {
                resolve_todo_hash(candidates, parts.next(), line)?;
                continue;
            }
            "e" | "edit" => return Err(TodoError::EditUnsupported),
            other => return Err(TodoError::UnknownCommand(other.to_owned())),
        };
        // A fold needs a commit before it.
        if todo.is_empty() && action.folds_into_previous() {
            return Err(TodoError::NothingToFoldInto(verb.to_owned()));
        }
        todo.push(resolve_todo_hash(candidates, parts.next(), line)?);
        actions.push(action);
    }
    Ok((todo, actions))
}

/// Find the candidate that `token` names, by a full hash or an unambiguous
/// prefix.
fn resolve_todo_hash(
    candidates: &[Hash],
    token: Option<&str>,
    line: &str,
) -> Result<Hash, TodoError> {
    let token = token.ok_or_else(|| TodoError::MissingCommit(line.to_owned()))?;
    let token = token.to_ascii_lowercase();
    let mut matches = candidates
        .iter()
        .filter(|h| hash::to_hex(h).starts_with(&token));
    match (matches.next(), matches.next()) {
        (Some(h), None) => Ok(*h),
        (None, _) => Err(TodoError::UnknownCommit(line.to_owned())),
        (Some(_), Some(_)) => Err(TodoError::AmbiguousCommit {
            token,
            line: line.to_owned(),
        }),
    }
}

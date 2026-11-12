//! Linked working trees: add, list, remove, prune, move, lock, unlock and
//! repair.
//!
//! Every linked tree shares the object store and the shared refs of the main
//! tree. Each tree has its own `HEAD`, index and in-progress operation state.
//! The registry in the common directory lists the linked trees. [`add`],
//! [`remove`], [`prune`], [`move_to`], [`fn@lock`], [`unlock`] and [`repair`] take
//! the registry lock for their whole change, so two of them never run side by
//! side.
//!
//! [`add`] writes in a crash-safe order. The state directory of the new tree
//! is complete before the pointer file exists. A crash in between leaves a
//! registry entry that [`prune`] removes, and never a tree that points at half
//! of its state. The files of the tree come last, into a fresh directory. A
//! crash while they are written leaves a valid tree with missing files.

use std::io;
use std::path::{Path, PathBuf};

use kit_core::hash::{self, Hash};
use kit_core::layout::{self, DiscoverError, RepoLayout};
use kit_core::object::Object;
use kit_core::observer::Observer;
use kit_core::ops::conflict_state;
use kit_core::refs::{self, Head, RefError, RefWriteCondition};
use kit_core::store::{ObjectStore, StoreError};
use kit_sync::worktree::{
    collect_worktree_paths, current_head_tree, ensure_restore_safe,
    index_tracks_path_or_descendant, read_or_seed_index_from_head, restore_worktree_and_index,
};

use crate::repo::StoreConfig;
use crate::{lock, log, revspec, worktrees};

/// Errors from a linked tree operation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The object store cannot be opened.
    #[error("open store: {0}")]
    OpenStore(StoreError),
    /// The new tree would sit inside a tree of the repository. The tree walkers
    /// treat a nested `.kit` as the edge of another repository, so the outer
    /// tree would skip the inner one.
    #[error(
        "'{}' is inside the worktree at '{}'; choose a path outside every existing worktree",
        target.display(),
        at.display()
    )]
    InsideWorktree {
        /// The path of the new tree.
        target: PathBuf,
        /// The root of the tree that holds it.
        at: PathBuf,
    },
    /// The path of the new tree is a directory with entries.
    #[error("'{}' already exists and is not empty", .0.display())]
    TargetNotEmpty(PathBuf),
    /// The path of the new tree is a file.
    #[error("'{}' already exists and is not a directory", .0.display())]
    TargetNotDirectory(PathBuf),
    /// The path of the new tree cannot be inspected.
    #[error("inspect '{}': {source}", path.display())]
    InspectTarget {
        /// The path of the new tree.
        path: PathBuf,
        /// Why the inspection failed.
        source: io::Error,
    },
    /// The name of a new branch cannot come from the path.
    #[error("cannot derive a branch name from '{}'; pass a commit-ish", .0.display())]
    NoBranchName(PathBuf),
    /// The name of a new branch is in use.
    #[error("branch '{0}' already exists; pass it explicitly to check it out")]
    BranchExists(String),
    /// The repository has no commit to start from.
    #[error("cannot add a worktree: the repository has no commits yet")]
    NoCommits,
    /// `HEAD` could not be read.
    #[error("resolve HEAD: {0}")]
    ResolveHead(RefError),
    /// The commit-ish names no branch, tag or commit.
    #[error("no such branch, tag, or commit: {spec} ({source})")]
    UnknownCommitish {
        /// The text that the caller gave.
        spec: String,
        /// Why it does not resolve.
        source: revspec::Error,
    },
    /// A sibling tree has the branch checked out.
    #[error("branch '{branch}' is already checked out at '{}'", at.display())]
    CheckedOutElsewhere {
        /// The branch.
        branch: String,
        /// The root of the tree that has it.
        at: PathBuf,
    },
    /// The tree that runs the command has the branch checked out.
    #[error("branch '{0}' is already checked out in this worktree")]
    CheckedOutHere(String),
    /// The start object is not a commit or a remix.
    #[error("{} does not resolve to a commit or remix", &hash::to_hex(.0)[..8])]
    NotACommit(Hash),
    /// The start object cannot be read.
    #[error("read commit: {0}")]
    ReadCommit(StoreError),
    /// The registry id of the new tree cannot come from the path.
    #[error("cannot derive a worktree id from '{}'", .0.display())]
    NoWorktreeId(PathBuf),
    /// The state directory of the new tree cannot be created.
    #[error("create state dir: {0}")]
    CreateStateDir(io::Error),
    /// A file of the state directory cannot be written.
    #[error("write {what}: {source}")]
    WriteState {
        /// The file.
        what: &'static str,
        /// Why the write failed.
        source: io::Error,
    },
    /// The `HEAD` of the new tree cannot be written.
    #[error("write HEAD: {0}")]
    WriteHead(RefError),
    /// The branch of the new tree cannot be created.
    #[error("create branch '{branch}': {source}")]
    CreateBranch {
        /// The branch.
        branch: String,
        /// Why the write failed.
        source: RefError,
    },
    /// The directory of the new tree cannot be created.
    #[error("create '{}': {source}", path.display())]
    CreateTree {
        /// The directory.
        path: PathBuf,
        /// Why it cannot be created.
        source: io::Error,
    },
    /// The pointer file of the new tree cannot be written.
    #[error("write worktree pointer: {0}")]
    WritePointer(io::Error),
    /// The files of the new tree cannot be written.
    #[error("{0}")]
    Restore(String),
    /// The path names the main tree.
    #[error("the main working tree cannot be removed")]
    RemoveMain,
    /// The caller works inside the tree to remove.
    #[error("cannot remove the worktree you are currently inside")]
    RemoveCurrent,
    /// The path names no linked tree of the repository.
    #[error("'{}' is not a linked worktree of this repository", .0.display())]
    NotLinked(PathBuf),
    /// The tree to remove is in the middle of an operation.
    #[error("worktree has a {0} in progress; resolve it or pass --force")]
    OperationInProgress(&'static str),
    /// The tree to remove has work that would be lost.
    #[error("worktree contains {0}; commit, stash, or pass --force")]
    Dirty(String),
    /// The tree to remove cannot be checked for local work. The text names
    /// the failed step.
    #[error("{0}")]
    DirtyCheck(String),
    /// The tree to remove cannot be deleted.
    #[error("remove '{}': {source}", path.display())]
    RemoveTree {
        /// The root of the tree.
        path: PathBuf,
        /// Why the delete failed.
        source: io::Error,
    },
    /// The state directory of the tree to remove cannot be deleted.
    #[error("remove state dir '{}': {source}", path.display())]
    RemoveStateDir {
        /// The state directory.
        path: PathBuf,
        /// Why the delete failed.
        source: io::Error,
    },
    /// A registry entry cannot be pruned. The entries before it are gone.
    #[error("prune worktrees/{id}: {source}")]
    Prune {
        /// The registry id.
        id: String,
        /// Why the delete failed.
        source: io::Error,
        /// The entries that were pruned before the failure.
        pruned: Vec<Pruned>,
    },
    /// The path names the main tree, and the action does not apply to it.
    #[error("the main working tree cannot be {0}")]
    MainTree(&'static str),
    /// The tree is locked.
    #[error("worktree is locked{}; unlock it or pass --force twice", why(.reason))]
    Locked {
        /// The reason that the lock holds. Empty when it has none.
        reason: String,
    },
    /// The tree is already locked.
    #[error("worktree is already locked")]
    AlreadyLocked,
    /// The tree is not locked.
    #[error("worktree is not locked")]
    NotLocked,
    /// The lock file cannot be written or removed, or the reason is not
    /// acceptable.
    #[error("lock: {0}")]
    LockFile(io::Error),
    /// The caller works inside the tree to move.
    #[error("cannot move the worktree you are currently inside")]
    MoveCurrent,
    /// The tree to move is gone, so there is nothing to move.
    #[error("worktree at '{}' is missing; run `worktree repair` or `worktree prune`", .0.display())]
    TreeMissing(PathBuf),
    /// The destination of a move exists.
    #[error("'{}' already exists", .0.display())]
    MoveTargetExists(PathBuf),
    /// The destination of a move is not acceptable. The first field is the
    /// text that the caller gave.
    #[error("invalid destination '{0}': {1}")]
    MoveTargetInvalid(String, &'static str),
    /// The tree cannot be renamed to the destination.
    #[error("move '{}' to '{}': {source}", from.display(), to.display())]
    Move {
        /// The old root.
        from: PathBuf,
        /// The new root.
        to: PathBuf,
        /// Why the rename failed.
        source: io::Error,
    },
    /// The back-pointer cannot be updated. The tree is back at its old root.
    #[error("update back-pointer: {0}")]
    WriteBackPointer(io::Error),
    /// The tree moved, but a file that names its new root was not updated.
    /// `worktree repair <path>` finishes the job.
    #[error("moved to '{}', but updating the pointer failed: {source}; run `worktree repair`", to.display())]
    MoveIncomplete {
        /// The new root.
        to: PathBuf,
        /// Why the update failed.
        source: io::Error,
    },
    /// A path to repair is not a repairable linked tree of this repository.
    #[error("cannot repair '{}': {reason}", path.display())]
    Unrepairable {
        /// The path that the caller gave.
        path: PathBuf,
        /// Why not.
        reason: String,
    },
    /// The trees of the repository cannot be read.
    #[error(transparent)]
    Worktrees(#[from] worktrees::Error),
    /// A lock cannot be taken.
    #[error(transparent)]
    Lock(#[from] lock::Error),
}

fn why(reason: &str) -> String {
    if reason.is_empty() {
        String::new()
    } else {
        format!(" ({reason})")
    }
}

/// What a new tree has checked out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Checkout {
    /// A new branch, made at `HEAD` of the tree that ran the command.
    NewBranch(String),
    /// A branch that exists.
    Branch(String),
    /// A commit, with a detached `HEAD`.
    Detached,
}

/// The result of [`add`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Added {
    /// What the new tree has checked out.
    pub checkout: Checkout,
    /// The commit at the new `HEAD`.
    pub commit: Hash,
    /// The first line of the message of that commit.
    pub subject: String,
}

/// Where the `HEAD` of the new tree points.
enum Plan {
    NewBranch { branch: String, start: Hash },
    ExistingBranch { branch: String, tip: Hash },
    Detached(Hash),
}

impl Plan {
    fn commit(&self) -> Hash {
        match self {
            Self::NewBranch { start, .. } => *start,
            Self::ExistingBranch { tip, .. } => *tip,
            Self::Detached(hash) => *hash,
        }
    }

    fn branch(&self) -> Option<&str> {
        match self {
            Self::NewBranch { branch, .. } | Self::ExistingBranch { branch, .. } => Some(branch),
            Self::Detached(_) => None,
        }
    }
}

/// Make a linked tree at `path`.
///
/// A relative `path` resolves against `cwd`. With no `commit_ish`, the tree
/// gets a new branch that is named after the last component of the path. The
/// operation refuses a name in use. A `commit_ish` that names a branch checks
/// the branch out, and the operation refuses a branch that another tree has.
/// Any other revision gives a detached `HEAD`.
///
/// The operation takes the registry lock after it chose the plan. It checks
/// the branch again under the lock, because a sibling tree may have taken it
/// in between.
///
/// # Errors
/// [`Error`], with one variant for each failed step.
pub fn add(
    layout: &RepoLayout,
    store_config: &StoreConfig<'_>,
    cwd: &Path,
    path: &str,
    commit_ish: Option<&str>,
    observer: &dyn Observer<lock::Event>,
) -> Result<Added, Error> {
    let store = store_config.open(layout).map_err(Error::OpenStore)?;

    // The target does not exist yet, so the check walks up to the deepest
    // directory that does.
    let target = canonical_or_lexical(&absolutize(cwd, Path::new(path)));
    check_add_target(layout, &target)?;
    let plan = plan_head(layout, &store, &target, commit_ish)?;

    let commit = plan.commit();
    let tree_hash = match store.read_object(&commit) {
        Ok(Object::Commit(c)) => c.tree_hash,
        Ok(Object::Remix(r)) => r.tree_hash,
        Ok(_) => return Err(Error::NotACommit(commit)),
        Err(e) => return Err(Error::ReadCommit(e)),
    };
    create_worktree(layout, &store, &plan, &target, tree_hash, observer)?;

    let checkout = match plan {
        Plan::NewBranch { branch, .. } => Checkout::NewBranch(branch),
        Plan::ExistingBranch { branch, .. } => Checkout::Branch(branch),
        Plan::Detached(_) => Checkout::Detached,
    };
    Ok(Added {
        checkout,
        commit,
        subject: log::subject(&store, &commit),
    })
}

/// Refuse a target inside an existing tree.
fn refuse_inside_worktree(layout: &RepoLayout, target: &Path) -> Result<(), Error> {
    for (tree_root, _) in worktrees::all_layouts(layout)? {
        if target.starts_with(canonical_or_lexical(&tree_root)) {
            return Err(Error::InsideWorktree {
                target: target.to_path_buf(),
                at: tree_root,
            });
        }
    }
    Ok(())
}

/// Refuse a target inside an existing tree, or one that is not empty.
fn check_add_target(layout: &RepoLayout, target: &Path) -> Result<(), Error> {
    refuse_inside_worktree(layout, target)?;
    match std::fs::read_dir(target) {
        Ok(mut entries) => {
            if entries.next().is_some() {
                return Err(Error::TargetNotEmpty(target.to_path_buf()));
            }
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) if target.exists() => Err(Error::TargetNotDirectory(target.to_path_buf())),
        Err(source) => Err(Error::InspectTarget {
            path: target.to_path_buf(),
            source,
        }),
    }
}

/// Decide the `HEAD` of the new tree, and enforce one writer for each branch.
fn plan_head(
    layout: &RepoLayout,
    store: &ObjectStore,
    target: &Path,
    commit_ish: Option<&str>,
) -> Result<Plan, Error> {
    let plan = match commit_ish {
        None => {
            let Some(branch) = branch_name_from_path(target) else {
                return Err(Error::NoBranchName(target.to_path_buf()));
            };
            if matches!(refs::read_ref(layout, &branch), Ok(Some(_))) {
                return Err(Error::BranchExists(branch));
            }
            let start = match refs::resolve_head(layout) {
                Ok(Some(head)) => head,
                Ok(None) => return Err(Error::NoCommits),
                Err(e) => return Err(Error::ResolveHead(e)),
            };
            Plan::NewBranch { branch, start }
        }
        Some(spec) => match refs::read_ref(layout, spec) {
            Ok(Some(tip)) => Plan::ExistingBranch {
                branch: spec.to_owned(),
                tip,
            },
            _ => match revspec::resolve_revision(store, layout, spec) {
                Ok(hash) => Plan::Detached(hash),
                Err(source) => {
                    return Err(Error::UnknownCommitish {
                        spec: spec.to_owned(),
                        source,
                    });
                }
            },
        },
    };

    // A branch has one writer at a time, because the ancestry journal assumes
    // it.
    if let Some(branch) = plan.branch() {
        refuse_if_checked_out(layout, branch)?;
        // The helper skips the tree of the caller on purpose.
        if matches!(refs::read_head(layout), Ok(Head::Branch(ref current)) if current == branch) {
            return Err(Error::CheckedOutHere(branch.to_owned()));
        }
    }
    Ok(plan)
}

fn refuse_if_checked_out(layout: &RepoLayout, branch: &str) -> Result<(), Error> {
    match worktrees::checked_out_elsewhere(layout, branch)? {
        Some(at) => Err(Error::CheckedOutElsewhere {
            branch: branch.to_owned(),
            at,
        }),
        None => Ok(()),
    }
}

/// The registry entry, the state directory, the refs, the pointer and the
/// files, in the order of the module documentation.
fn create_worktree(
    layout: &RepoLayout,
    store: &ObjectStore,
    plan: &Plan,
    target: &Path,
    tree_hash: Hash,
    observer: &dyn Observer<lock::Event>,
) -> Result<(), Error> {
    // The lock excludes a sibling `add`, `remove` or `prune`, and `checkout`,
    // which holds it across its own check and `HEAD` write.
    let _registry = lock::acquire_registry(layout, observer)?;

    // The check before the lock raced a sibling `checkout` or `add`. This one
    // cannot, because the registry is frozen.
    if let Some(branch) = plan.branch() {
        refuse_if_checked_out(layout, branch)?;
    }

    let Some(id) = free_worktree_id(layout, target) else {
        return Err(Error::NoWorktreeId(target.to_path_buf()));
    };
    let state_dir = layout.worktree_state_dir_for(&id);
    let linked = RepoLayout::linked(target, &state_dir, layout.common_dir());

    // 1. The state directory is complete before the pointer file exists.
    std::fs::create_dir_all(&state_dir).map_err(Error::CreateStateDir)?;
    let steps: [(&'static str, io::Result<()>); 2] = [
        (
            "commondir",
            std::fs::write(state_dir.join(layout::COMMONDIR_FILE_NAME), b"../..\n"),
        ),
        (
            "back-pointer",
            layout::write_backpointer(&state_dir, target),
        ),
    ];
    for (what, result) in steps {
        result.map_err(|source| Error::WriteState { what, source })?;
    }
    match plan {
        Plan::NewBranch { branch, .. } | Plan::ExistingBranch { branch, .. } => {
            refs::write_head_branch(&linked, branch)
        }
        Plan::Detached(hash) => refs::write_head_detached(&linked, hash),
    }
    .map_err(Error::WriteHead)?;

    // 2. The branch ref, before the tree goes live.
    if let Plan::NewBranch { branch, start } = plan {
        refs::write_ref_recording_history(layout, branch, RefWriteCondition::Missing, start)
            .map_err(|source| Error::CreateBranch {
                branch: branch.clone(),
                source,
            })?;
    }

    // 3. The tree itself: the pointer file, then the files.
    std::fs::create_dir_all(target).map_err(|source| Error::CreateTree {
        path: target.to_path_buf(),
        source,
    })?;
    layout::write_pointer_file(target, &state_dir).map_err(Error::WritePointer)?;
    restore_worktree_and_index(&linked, store, tree_hash).map_err(Error::Restore)
}

/// One tree of the repository, as [`list`] reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The root of the tree. For a broken registry entry, the state
    /// directory when the root is unknown.
    pub path: PathBuf,
    /// The commit at `HEAD`. `None` for a broken entry or an unborn branch.
    pub head: Option<Hash>,
    /// The branch that `HEAD` names. `None` for a detached `HEAD`.
    pub branch: Option<String>,
    /// Why the entry is broken. [`prune`] removes a broken entry.
    pub prunable: Option<String>,
    /// The reason of the lock, empty when it has none. `None` when the tree
    /// is not locked. The main tree is never locked.
    pub locked: Option<String>,
}

/// List the main tree, each healthy linked tree, and each broken registry
/// entry, in that order.
///
/// The hashes come from the refs. The operation opens the object store only to
/// check that `layout` holds a repository.
///
/// # Errors
/// [`Error::OpenStore`] when the store cannot be opened. [`Error::Worktrees`]
/// when the registry cannot be read.
pub fn list(layout: &RepoLayout, store_config: &StoreConfig<'_>) -> Result<Vec<Entry>, Error> {
    store_config.open(layout).map_err(Error::OpenStore)?;
    let mut rows = Vec::new();
    for (path, tree) in worktrees::all_layouts(layout)? {
        rows.push(Entry {
            path,
            head: refs::resolve_head(&tree).ok().flatten(),
            branch: match refs::read_head(&tree) {
                Ok(Head::Branch(name)) => Some(name),
                _ => None,
            },
            prunable: None,
            locked: (!tree.is_single())
                .then(|| layout::lock_reason(tree.worktree_state_dir()))
                .flatten(),
        });
    }
    for entry in registry(layout)? {
        if let Some(reason) = entry.prunable {
            let locked = layout::lock_reason(&entry.state_dir);
            rows.push(Entry {
                path: entry.tree_root.unwrap_or(entry.state_dir),
                head: None,
                branch: None,
                prunable: Some(reason),
                locked,
            });
        }
    }
    Ok(rows)
}

/// Remove the linked tree at `path`, and its state directory.
///
/// A relative `path` resolves against `cwd`. A locked tree needs
/// `force_locked`, which is separate from `force`. Without `force`, the
/// operation refuses a tree that is in the middle of an operation, or that has staged
/// changes, unstaged changes or untracked files. It holds the registry lock
/// and then the lock of the tree to remove, in that order. Another process
/// that works inside the tree could be in the middle of a commit.
///
/// The tree goes first and the registry entry second. A crash in between
/// leaves a registry entry that [`prune`] removes, and never a live tree with
/// no state.
///
/// # Errors
/// [`Error`], with one variant for each failed step.
pub fn remove(
    layout: &RepoLayout,
    store_config: &StoreConfig<'_>,
    cwd: &Path,
    path: &str,
    force: bool,
    force_locked: bool,
    observer: &dyn Observer<lock::Event>,
) -> Result<(), Error> {
    let target = canonical_or_lexical(&absolutize(cwd, Path::new(path)));

    let main_root = layout.common_dir().parent().map(canonical_or_lexical);
    if main_root.as_deref() == Some(target.as_path()) {
        return Err(Error::RemoveMain);
    }
    if canonical_or_lexical(cwd).starts_with(&target) {
        return Err(Error::RemoveCurrent);
    }

    let Some(entry) = registry(layout)?.into_iter().find(|entry| {
        entry
            .tree_root
            .as_deref()
            .is_some_and(|root| canonical_or_lexical(root) == target)
    }) else {
        return Err(Error::NotLinked(target));
    };
    refuse_locked(&entry.state_dir, force_locked)?;

    // Local work counts: an operation in progress, staged and unstaged
    // changes, and untracked files, which exist in that tree only.
    if !force && entry.prunable.is_none() {
        let linked = RepoLayout::linked(&target, &entry.state_dir, layout.common_dir());
        if let Some(op) = conflict_state::in_progress_op_name(&linked) {
            return Err(Error::OperationInProgress(op));
        }
        if let Some(why) = dirty(&linked, store_config)? {
            return Err(Error::Dirty(why));
        }
    }

    let _registry = lock::acquire_registry(layout, observer)?;
    // A sibling `lock` may have run since the first check.
    refuse_locked(&entry.state_dir, force_locked)?;
    // The registry lock comes first, in the global lock order.
    let _tree_lock = if entry.state_dir.is_dir() {
        let tree = RepoLayout::linked(&target, &entry.state_dir, layout.common_dir());
        Some(lock::acquire_worktree(&tree, observer)?)
    } else {
        None
    };
    if target.exists()
        && let Err(source) = std::fs::remove_dir_all(&target)
    {
        return Err(Error::RemoveTree {
            path: target,
            source,
        });
    }
    std::fs::remove_dir_all(&entry.state_dir).map_err(|source| Error::RemoveStateDir {
        path: entry.state_dir,
        source,
    })
}

/// Refuse a locked tree, unless `force_locked`.
fn refuse_locked(state_dir: &Path, force_locked: bool) -> Result<(), Error> {
    match layout::lock_reason(state_dir) {
        Some(reason) if !force_locked => Err(Error::Locked { reason }),
        _ => Ok(()),
    }
}

/// A description of the local work in a tree, relative to its own `HEAD`.
/// `None` when the tree has none.
fn dirty(linked: &RepoLayout, store_config: &StoreConfig<'_>) -> Result<Option<String>, Error> {
    let check = || -> Result<Option<String>, String> {
        let store = store_config
            .open(linked)
            .map_err(|e| format!("open store: {e}"))?;
        let Some(head_tree) = current_head_tree(linked, &store)? else {
            return Ok(None); // unborn HEAD: nothing to lose
        };
        // Untracked files first, for the precise text. The gate below finds
        // them too, but with the wording of a restore.
        let index = read_or_seed_index_from_head(linked, &store)?;
        let mut paths = Vec::new();
        collect_worktree_paths(
            linked.worktree_root(),
            linked.worktree_root(),
            "",
            &mut paths,
        )
        .map_err(|e| format!("scan worktree: {e}"))?;
        for p in paths {
            if linked.worktree_root().join(&p).is_dir() {
                continue;
            }
            if !index_tracks_path_or_descendant(&index, &p) {
                return Ok(Some(format!("untracked file '{p}'")));
            }
        }
        // Staged and unstaged changes, through the gate of a destructive
        // restore. Its refusals about local work start with "restore would".
        // Any other text is a failure of the check, and an unreadable tree
        // must not read as clean.
        match ensure_restore_safe(linked, &store, head_tree) {
            Ok(()) => Ok(None),
            Err(why) if why.starts_with("restore would") => Ok(Some("local changes".to_owned())),
            Err(why) => Err(why),
        }
    };
    check().map_err(Error::DirtyCheck)
}

/// A registry entry that [`prune`] removed, or would remove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pruned {
    /// The registry id.
    pub id: String,
    /// Why the entry was broken.
    pub reason: String,
}

/// Delete the registry entries whose linked tree is gone. Return them. A
/// locked entry stays.
///
/// With `dry_run`, nothing is deleted and no lock is taken. Otherwise the
/// lock comes first and the scan second. A scan before the lock could take an
/// entry of a tree in the middle of [`add`] for a gone tree, and delete the
/// state of a live tree.
///
/// # Errors
/// [`Error::Lock`] or [`Error::Worktrees`] before any change.
/// [`Error::Prune`] when a delete fails. It names the entries that went.
pub fn prune(
    layout: &RepoLayout,
    dry_run: bool,
    observer: &dyn Observer<lock::Event>,
) -> Result<Vec<Pruned>, Error> {
    let _registry = if dry_run {
        None
    } else {
        Some(lock::acquire_registry(layout, observer)?)
    };
    let mut pruned = Vec::new();
    for entry in registry(layout)? {
        let Some(reason) = entry.prunable else {
            continue;
        };
        // A lock protects a tree that is only out of reach, such as one on a
        // disk that is not mounted.
        if layout::lock_reason(&entry.state_dir).is_some() {
            continue;
        }
        if !dry_run && let Err(source) = std::fs::remove_dir_all(&entry.state_dir) {
            return Err(Error::Prune {
                id: entry.id,
                source,
                pruned,
            });
        }
        pruned.push(Pruned {
            id: entry.id,
            reason,
        });
    }
    Ok(pruned)
}

/// The registry entry of the linked tree at `path`, and its canonical root.
/// `action` names what the caller does, for the error of the main tree.
fn find_linked(
    layout: &RepoLayout,
    cwd: &Path,
    path: &str,
    action: &'static str,
) -> Result<(PathBuf, layout::WorktreeEntry), Error> {
    let target = canonical_or_lexical(&absolutize(cwd, Path::new(path)));
    let main_root = layout.common_dir().parent().map(canonical_or_lexical);
    if main_root.as_deref() == Some(target.as_path()) {
        return Err(Error::MainTree(action));
    }
    let entry = registry(layout)?.into_iter().find(|entry| {
        entry
            .tree_root
            .as_deref()
            .is_some_and(|root| canonical_or_lexical(root) == target)
    });
    match entry {
        Some(entry) => Ok((target, entry)),
        None => Err(Error::NotLinked(target)),
    }
}

/// Lock the linked tree at `path`, with `reason`.
///
/// A locked tree survives [`remove`], [`prune`] and [`move_to`] unless the
/// caller forces them. The tree may be gone, such as on a disk that is not
/// mounted.
///
/// # Errors
/// [`Error::MainTree`], [`Error::NotLinked`], [`Error::AlreadyLocked`], or
/// [`Error::LockFile`] for a reason that is too long or has a control
/// character.
pub fn lock(
    layout: &RepoLayout,
    cwd: &Path,
    path: &str,
    reason: &str,
    observer: &dyn Observer<lock::Event>,
) -> Result<(), Error> {
    let _registry = lock::acquire_registry(layout, observer)?;
    let (_, entry) = find_linked(layout, cwd, path, "locked")?;
    layout::write_lock(&entry.state_dir, reason).map_err(|e| {
        if e.kind() == io::ErrorKind::AlreadyExists {
            Error::AlreadyLocked
        } else {
            Error::LockFile(e)
        }
    })
}

/// Unlock the linked tree at `path`.
///
/// # Errors
/// [`Error::MainTree`], [`Error::NotLinked`], [`Error::NotLocked`], or
/// [`Error::LockFile`].
pub fn unlock(
    layout: &RepoLayout,
    cwd: &Path,
    path: &str,
    observer: &dyn Observer<lock::Event>,
) -> Result<(), Error> {
    let _registry = lock::acquire_registry(layout, observer)?;
    let (_, entry) = find_linked(layout, cwd, path, "unlocked")?;
    layout::remove_lock(&entry.state_dir).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            Error::NotLocked
        } else {
            Error::LockFile(e)
        }
    })
}

/// Check the destination of a move and return its canonical form.
///
/// The destination must not exist, even as a dangling link. It has no `..`
/// component, and its parent is an existing directory. It does not sit inside
/// a tree of the repository.
fn check_move_target(layout: &RepoLayout, cwd: &Path, new_path: &str) -> Result<PathBuf, Error> {
    let invalid = |why| Error::MoveTargetInvalid(new_path.to_owned(), why);
    let raw = Path::new(new_path);
    if new_path.is_empty() || new_path.contains('\0') {
        return Err(invalid("the path is empty or has a NUL"));
    }
    if raw
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(invalid("the path has a `..` component"));
    }
    let target = canonical_or_lexical(&absolutize(cwd, raw));
    if target.file_name().is_none() {
        return Err(invalid("the path has no final component"));
    }
    match std::fs::symlink_metadata(&target) {
        Ok(_) => return Err(Error::MoveTargetExists(target)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(Error::InspectTarget {
                path: target,
                source,
            });
        }
    }
    if !target.parent().is_some_and(Path::is_dir) {
        return Err(invalid("the parent directory does not exist"));
    }
    refuse_inside_worktree(layout, &target)?;
    Ok(target)
}

/// Move the linked tree at `path` to `new_path`. Return the new root.
///
/// The destination must not exist, and its parent must. The operation
/// renames the directory, so it stays on one filesystem. Then it rewrites the
/// back-pointer in the state directory and the pointer file in the tree. If
/// the back-pointer write fails, the tree goes back to its old root. A
/// locked tree needs `force_locked`.
///
/// # Errors
/// [`Error`], with one variant for each failed step.
pub fn move_to(
    layout: &RepoLayout,
    cwd: &Path,
    path: &str,
    new_path: &str,
    force_locked: bool,
    observer: &dyn Observer<lock::Event>,
) -> Result<PathBuf, Error> {
    let _registry = lock::acquire_registry(layout, observer)?;
    let (source, entry) = find_linked(layout, cwd, path, "moved")?;
    if canonical_or_lexical(cwd).starts_with(&source) {
        return Err(Error::MoveCurrent);
    }
    refuse_locked(&entry.state_dir, force_locked)?;
    if entry.prunable.is_some() || !source.is_dir() {
        return Err(Error::TreeMissing(source));
    }
    let target = check_move_target(layout, cwd, new_path)?;

    let tree = RepoLayout::linked(&source, &entry.state_dir, layout.common_dir());
    let _tree_lock = lock::acquire_worktree(&tree, observer)?;

    std::fs::rename(&source, &target).map_err(|e| Error::Move {
        from: source.clone(),
        to: target.clone(),
        source: e,
    })?;
    if let Err(e) = layout::write_backpointer(&entry.state_dir, &target) {
        return match std::fs::rename(&target, &source) {
            Ok(()) => Err(Error::WriteBackPointer(e)),
            Err(_) => Err(Error::MoveIncomplete {
                to: target,
                source: e,
            }),
        };
    }
    layout::write_pointer_file(&target, &entry.state_dir).map_err(|e| Error::MoveIncomplete {
        to: target.clone(),
        source: e,
    })?;
    Ok(target)
}

/// What [`repair`] fixed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repaired {
    /// The registry id.
    pub id: String,
    /// The file that was rewritten.
    pub what: &'static str,
}

/// Repair the files that tie linked trees to the registry.
///
/// With `paths`, each path is the root of a linked tree that was moved by
/// hand. The tree names its state directory in its pointer file, so the
/// operation rewrites the back-pointer to name the tree at `path`. With no
/// `paths`, the operation looks at every registry entry that is broken while
/// its tree directory exists, and rewrites a missing or unreadable pointer
/// file. It leaves a tree that points at another live state directory, and a
/// `.kit` that is a directory or a link.
///
/// # Errors
/// [`Error::Unrepairable`] for a path that is not a linked tree of this
/// repository. The fix stops at the first such path.
pub fn repair(
    layout: &RepoLayout,
    cwd: &Path,
    paths: &[String],
    observer: &dyn Observer<lock::Event>,
) -> Result<Vec<Repaired>, Error> {
    let _registry = lock::acquire_registry(layout, observer)?;
    let mut fixed = Vec::new();
    if paths.is_empty() {
        for entry in registry(layout)? {
            let Some(root) = entry.tree_root.as_deref() else {
                continue;
            };
            if entry.prunable.is_none() || !root.is_dir() || !pointer_is_replaceable(root) {
                continue;
            }
            layout::write_pointer_file(root, &entry.state_dir).map_err(|e| {
                Error::Unrepairable {
                    path: root.to_path_buf(),
                    reason: format!("write pointer: {e}"),
                }
            })?;
            fixed.push(Repaired {
                id: entry.id,
                what: "pointer",
            });
        }
        return Ok(fixed);
    }
    for path in paths {
        let root = canonical_or_lexical(&absolutize(cwd, Path::new(path)));
        let unrepairable = |reason: String| Error::Unrepairable {
            path: root.clone(),
            reason,
        };
        let linked = layout::discover(&root).map_err(|e| unrepairable(e.to_string()))?;
        let state = linked.worktree_state_dir();
        // A repository with no linked tree has no registry directory.
        let registry_dir = layout.worktrees_dir().canonicalize().ok();
        let id = state
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|id| layout::validate_worktree_id(id));
        let (false, true, Some(id)) = (
            linked.is_single(),
            registry_dir.is_some() && state.parent() == registry_dir.as_deref(),
            id,
        ) else {
            return Err(unrepairable(
                "not a linked worktree of this repository".to_owned(),
            ));
        };
        let current = kit_core::bounded_read::read_capped_string(
            &state.join(layout::BACKPOINTER_FILE_NAME),
            layout::MAX_POINTER_FILE_BYTES,
        )
        .ok();
        let want = format!("{}\n", root.join(kit_core::KIT_DIR).display());
        if current.as_deref() != Some(want.as_str()) {
            layout::write_backpointer(state, &root)
                .map_err(|e| unrepairable(format!("write back-pointer: {e}")))?;
            fixed.push(Repaired {
                id: id.to_owned(),
                what: "back-pointer",
            });
        }
    }
    Ok(fixed)
}

/// Whether the `.kit` of the tree at `root` may be rewritten. It may when it
/// is absent, or a regular file that names no live state directory.
fn pointer_is_replaceable(root: &Path) -> bool {
    match std::fs::symlink_metadata(root.join(kit_core::KIT_DIR)) {
        Err(e) => e.kind() == io::ErrorKind::NotFound,
        Ok(meta) => {
            meta.file_type().is_file()
                && !matches!(layout::discover(root), Ok(linked) if !linked.is_single())
        }
    }
}

fn registry(layout: &RepoLayout) -> Result<Vec<layout::WorktreeEntry>, Error> {
    layout::worktrees(layout)
        .map_err(|e: DiscoverError| Error::Worktrees(worktrees::Error::Registry(e)))
}

/// Join `path` to `cwd` with no change to its text. The target of [`add`]
/// does not exist yet, so `canonicalize` is not an option.
fn absolutize(cwd: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    }
}

/// Canonicalize `p` when it exists. For a path that does not exist, canonicalize
/// the deepest ancestor that does, and add the rest. A temporary directory on
/// macOS sits behind the `/var` to `/private/var` link, so a text-only
/// fallback would defeat every comparison with a canonical root.
fn canonical_or_lexical(p: &Path) -> PathBuf {
    if let Ok(c) = p.canonicalize() {
        return c;
    }
    let mut missing = Vec::new();
    let mut cur = p;
    while let Some(parent) = cur.parent() {
        if let Some(name) = cur.file_name() {
            missing.push(name.to_owned());
        }
        if let Ok(c) = parent.canonicalize() {
            let mut out = c;
            for name in missing.iter().rev() {
                out.push(name);
            }
            return out;
        }
        cur = parent;
    }
    p.to_path_buf()
}

/// Replace each byte that is not alphanumeric, `.`, `_` or `-` with `-`.
fn sanitize(base: &str) -> String {
    base.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

/// The branch name from the last component of the target. A byte that the ref
/// grammar refuses becomes `-`.
fn branch_name_from_path(target: &Path) -> Option<String> {
    let base = target.file_name()?.to_string_lossy();
    let candidate = sanitize(&base);
    let candidate = candidate.trim_matches(['-', '.']).to_owned();
    refs::validate_ref_name(&candidate).then_some(candidate)
}

/// The first free registry id from the last component of the target:
/// `<name>`, then `<name>-1`, `<name>-2` and on.
fn free_worktree_id(layout: &RepoLayout, target: &Path) -> Option<String> {
    let base = target.file_name()?.to_string_lossy();
    let sanitized = sanitize(&base).trim_matches('-').to_owned();
    if !layout::validate_worktree_id(&sanitized) {
        return None;
    }
    if !layout.worktree_state_dir_for(&sanitized).exists() {
        return Some(sanitized);
    }
    (1..10_000).find_map(|n| {
        let candidate = format!("{sanitized}-{n}");
        (layout::validate_worktree_id(&candidate)
            && !layout.worktree_state_dir_for(&candidate).exists())
        .then_some(candidate)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_branch_name_comes_from_the_last_component() {
        let name = |p: &str| branch_name_from_path(Path::new(p));
        assert_eq!(name("/w/topic").as_deref(), Some("topic"));
        assert_eq!(name("/w/my topic!").as_deref(), Some("my-topic"));
        assert_eq!(name("/w/.hidden.").as_deref(), Some("hidden"));
        assert_eq!(name("/w/---"), None);
        assert_eq!(name("/"), None);
    }

    #[test]
    fn a_relative_path_resolves_against_the_working_directory() {
        assert_eq!(
            absolutize(Path::new("/work"), Path::new("t")),
            PathBuf::from("/work/t")
        );
        assert_eq!(
            absolutize(Path::new("/work"), Path::new("/abs/t")),
            PathBuf::from("/abs/t")
        );
    }

    #[test]
    fn a_missing_path_keeps_its_tail_under_the_deepest_real_directory() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().canonicalize().unwrap();
        assert_eq!(
            canonical_or_lexical(&dir.path().join("a").join("b")),
            real.join("a").join("b")
        );
    }

    #[test]
    fn an_id_in_use_gets_a_number() {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        let target = dir.path().join("topic");
        assert_eq!(free_worktree_id(&layout, &target).as_deref(), Some("topic"));
        std::fs::create_dir_all(layout.worktree_state_dir_for("topic")).unwrap();
        assert_eq!(
            free_worktree_id(&layout, &target).as_deref(),
            Some("topic-1")
        );
        std::fs::create_dir_all(layout.worktree_state_dir_for("topic-1")).unwrap();
        assert_eq!(
            free_worktree_id(&layout, &target).as_deref(),
            Some("topic-2")
        );
    }

    #[test]
    fn an_id_needs_a_usable_name() {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        assert_eq!(free_worktree_id(&layout, Path::new("/w/---")), None);
        assert_eq!(free_worktree_id(&layout, Path::new("/")), None);
    }
}

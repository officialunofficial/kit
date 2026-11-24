//! Pulling: fetch, then fast-forward the local branch, HEAD and worktree.

use std::fs;
use std::path::Path;

use kit_core::hash::Hash;
use kit_core::layout::RepoLayout;
use kit_core::object::Object;
use kit_core::ops::graph::AncestorError;
use kit_core::ops::merge::is_ancestor_strict;
use kit_core::ops::pull_state::PullState;
use kit_core::protocol::escape_terminal_text;
use kit_core::refs::{self, Head};
use kit_core::store::ObjectStore;

use crate::SyncOptions;
use crate::error::SyncError;
use crate::fetch::{FetchReport, fetch_objects};
use crate::lock::{LockWait, acquire_worktree_lock};
use crate::observer::{Observer, SyncEvent};
use crate::source::RemoteSource;
use crate::verify::verify_history_signatures;
use crate::worktree::{
    Expected, Refusals, check_restore_safe, current_head_tree, ensure_restore_safe_from,
    list_remote_refs_parallel, write_ref_recording_history,
};
use kit_core::ops::restore::RestoreOptions;

/// What a pull did to the local branch.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PullOutcome {
    /// The remote advertises no branches, so there was nothing to land.
    NoRemoteBranches,
    /// The local branch already holds the remote tip: it is equal to it or ahead of it.
    UpToDate { branch: String },
    /// The branch, HEAD and worktree moved to the remote tip.
    FastForwarded {
        branch: String,
        /// The previous tip, `None` for a branch that did not exist yet.
        old: Option<Hash>,
        new: Hash,
    },
}

/// What a pull did.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PullReport {
    pub fetch: FetchReport,
    pub outcome: PullOutcome,
    /// Best-effort maintenance after publishing the pull.
    pub maintenance: Option<crate::MaintenanceReport>,
}

/// Open the object store of `layout` with the options' durability schedule.
pub(crate) fn open_store(
    layout: &RepoLayout,
    options: &SyncOptions,
) -> Result<ObjectStore, SyncError> {
    let mut store = ObjectStore::open(layout)?;
    store.set_sync_policy(options.sync_policy);
    Ok(store)
}

/// Verify the signed history of a tip before a pull uses it.
///
/// Checks every commit, remix and tag down to a tip recorded by an earlier
/// verified fetch. A tracking ref alone is not proof of verification: an
/// opt-out fetch may have written it. Uses the same history checker as fetch.
/// This function writes nothing and honors observer cancellation.
///
/// The caller must hold the worktree lock from selecting `tip` through the
/// operation that uses it. The caller must skip this call when signature
/// verification was explicitly disabled.
///
/// # Errors
/// Returns [`SyncError::UnsignedOrInvalidObject`] for an unsigned or invalid
/// signature, [`SyncError::Interrupted`] on cancellation, or an error if the
/// history cannot be read or exceeds the history walk's limit.
pub fn verify_pull_tip(
    layout: &RepoLayout,
    store: &ObjectStore,
    tip: &Hash,
    observer: &dyn Observer<SyncEvent>,
) -> Result<(), SyncError> {
    verify_history_signatures(store, observer, tip, &mut crate::anchor::load_all(layout))
}

/// Fetch the remote's refs, then fast-forward the current local branch from
/// `refs/remotes/<remote>/<branch>`. Fresh repos with no local branch tip
/// initialise from the current branch's remote-tracking ref, or the first
/// advertised remote branch when the current default branch is absent.
/// A branch that already holds the remote tip, equal to it or ahead of it,
/// is up to date and nothing moves. Any other history that is not a
/// fast-forward is refused with [`SyncError::NonFastForwardPull`].
///
/// `options.target_branch`, when `Some`, overrides which remote branch to land
/// on (used by clone `-b <branch>`): it MUST exist among the remote's refs or
/// the call fails with [`SyncError::RemoteBranchMissing`] rather than silently
/// falling back to another branch.
///
/// # Locking
///
/// The fetch phase holds no repo lock while it downloads and applies packs; it
/// takes the lock itself, per branch, around only the remote-ref publish. The
/// fast-forward phase then takes the worktree lock around just the branch ref,
/// HEAD and worktree update. The objects the remote tip points at are already
/// reachable via the remote-tracking ref published during the fetch, so this
/// lock's job is worktree-mutation exclusivity against concurrent commands,
/// not GC protection. The fetch's own protection from gc is a
/// [`kit_core::store::PruneGuard`], released before this phase starts.
pub fn pull(
    dir: &Path,
    source: &dyn RemoteSource,
    remote: &str,
    options: &SyncOptions,
    observer: &dyn Observer<SyncEvent>,
) -> Result<PullReport, SyncError> {
    let layout = kit_core::layout::discover(dir)?;
    if matches!(refs::read_head(&layout), Ok(Head::Detached(_))) {
        return Err(SyncError::DetachedHead);
    }
    let store = open_store(&layout, options)?;
    let lock_wait = LockWait::new(options.lock_wait);
    let fetch = fetch_objects(
        &store, &layout, source, observer, remote, options, &lock_wait,
    )?;
    let mut report = land_pull(
        &layout, &store, remote, options, observer, &lock_wait, fetch,
    )?;
    report.maintenance = maintain(&layout, &store, options, observer, &report.fetch);
    Ok(report)
}

#[allow(clippy::too_many_lines)]
fn land_pull(
    layout: &RepoLayout,
    store: &ObjectStore,
    remote: &str,
    options: &SyncOptions,
    observer: &dyn Observer<SyncEvent>,
    lock_wait: &LockWait,
    fetch: FetchReport,
) -> Result<PullReport, SyncError> {
    let _lock = acquire_worktree_lock(layout, observer, lock_wait)?;
    let remote_refs = list_remote_refs_parallel(layout, remote)?
        .into_iter()
        .filter_map(|r| r.hash.map(|hash| (r.name, hash)))
        .collect::<Vec<_>>();
    let pending = PullState::read(layout)?;
    let original_head = refs::read_head(layout).ok();
    if matches!(original_head, Some(Head::Detached(_))) {
        return Err(SyncError::DetachedHead);
    }
    if remote_refs.is_empty() {
        if pending.is_some() {
            return Err(SyncError::RestoreSafety("unfinished pull cannot recover without a remote branch; restore the remote branch, then pull again".to_owned()));
        }
        return Ok(PullReport {
            fetch,
            maintenance: None,
            outcome: PullOutcome::NoRemoteBranches,
        });
    }

    let (branch, local_tip, remote_tip) = select_branch(
        layout,
        original_head.as_ref(),
        options.target_branch.as_deref(),
        &remote_refs,
    )?;

    // A tracking tip omitted by this fetch may come from an opt-out fetch.
    // Check before recovery or any other worktree, index or HEAD write.
    if options.verify_signatures {
        verify_pull_tip(layout, store, &remote_tip, observer)?;
    }

    let restored = resume_pull(layout, store, &branch, pending, local_tip, observer)?;
    let original_head = refs::read_head(layout).ok();
    let ref_condition = if let Some(local_tip) = local_tip {
        // A missing commit would read as "not a fast-forward" or as "not
        // ahead", so each walk reads every commit and names the one it cannot
        // read. The error keeps the id of the commit it names.
        let ancestor = |ancestor, descendant| {
            is_ancestor_strict(store, ancestor, descendant).map_err(|e| match e {
                AncestorError::Limit(source) => SyncError::Store(source),
                other => SyncError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, other)),
            })
        };
        // A walk runs from the descendant down to the ancestor and ends only
        // when it finds it or runs out of commits. The common pull is a
        // fast-forward, so that walk goes first: it reads only the new commits.
        let holds_remote_tip = if local_tip == remote_tip || ancestor(local_tip, remote_tip)? {
            local_tip == remote_tip
        } else if ancestor(remote_tip, local_tip)? {
            // The branch is ahead of the remote. Nothing moves, as in git.
            true
        } else {
            return Err(SyncError::NonFastForwardPull { branch });
        };
        if holds_remote_tip {
            return Ok(PullReport {
                fetch,
                maintenance: None,
                outcome: if restored {
                    PullOutcome::FastForwarded {
                        branch,
                        old: Some(local_tip),
                        new: local_tip,
                    }
                } else {
                    PullOutcome::UpToDate { branch }
                },
            });
        }
        refs::RefWriteCondition::Match(local_tip)
    } else {
        refs::RefWriteCondition::Missing
    };

    let tree = load_tree_hash(store, remote_tip)?;
    // Recovery may have changed the worktree and index. Read HEAD afterwards.
    let base_tree = current_head_tree(layout, store).map_err(SyncError::RestoreSafety)?;
    ensure_restore_safe_from(layout, store, tree, &RestoreOptions::default(), base_tree)
        .map_err(SyncError::RestoreSafety)?;
    if observer.cancelled() {
        return Err(SyncError::Interrupted);
    }
    write_pull_head(layout, store, remote_tip)?;
    write_ref_recording_history(layout, &branch, ref_condition, &remote_tip)?;
    if let Err(e) = refs::write_head_branch(layout, &branch) {
        rollback_pull_ref(layout, &branch, local_tip, remote_tip)?;
        clear_pull_head(layout)?;
        return Err(e.into());
    }
    if observer.cancelled() {
        // The restore has not begun. A pull that made the branch, as a
        // clone's does, undoes it and HEAD, so the clone can resume: a clone
        // resumes only into a repository with no branch. A pull that moved a
        // branch leaves `PULL_HEAD`, and the next pull finishes the restore.
        // A failed undo still reports the interrupt; `kit pull` then finishes
        // the clone, and the next pull clears a `PULL_HEAD` left behind.
        if local_tip.is_none()
            && rollback_pull_ref_and_head(layout, &branch, None, remote_tip, original_head).is_ok()
        {
            let _ = clear_pull_head(layout);
        }
        return Err(SyncError::Interrupted);
    }
    if let Err(e) = crate::worktree::restore_worktree_and_index_progress(
        layout, store, tree, base_tree, observer,
    ) {
        if let Err(rollback) =
            rollback_pull_ref_and_head(layout, &branch, local_tip, remote_tip, original_head)
        {
            return Err(SyncError::RestoreSafety(format!(
                "{e}; additionally failed to roll back ref: {rollback}"
            )));
        }
        clear_pull_head(layout)?;
        return Err(SyncError::RestoreSafety(e));
    }
    clear_pull_head(layout)?;
    Ok(PullReport {
        fetch,
        maintenance: None,
        outcome: PullOutcome::FastForwarded {
            branch,
            old: local_tip,
            new: remote_tip,
        },
    })
}

/// Fetch every remote branch into its remote-tracking ref, without touching
/// the local branches, HEAD or worktree.
pub fn fetch(
    dir: &Path,
    source: &dyn RemoteSource,
    remote: &str,
    options: &SyncOptions,
    observer: &dyn Observer<SyncEvent>,
) -> Result<FetchReport, SyncError> {
    let layout = kit_core::layout::discover(dir)?;
    // No outer lock: `fetch_objects` takes the repo lock itself, per branch,
    // around only the ref publish.
    let store = open_store(&layout, options)?;
    let lock_wait = LockWait::new(options.lock_wait);
    let mut report = fetch_objects(
        &store, &layout, source, observer, remote, options, &lock_wait,
    )?;
    report.maintenance = maintain(&layout, &store, options, observer, &report);
    Ok(report)
}

fn maintain(
    layout: &RepoLayout,
    store: &ObjectStore,
    options: &SyncOptions,
    observer: &dyn Observer<SyncEvent>,
    fetch: &FetchReport,
) -> Option<crate::MaintenanceReport> {
    if !options.auto_maintenance
        || (fetch.packs_downloaded == 0 && fetch.branches_pruned.is_empty())
        || observer.cancelled()
    {
        return None;
    }
    Some(kit_core::ops::gc::maintain_packs(layout, store, &|| {
        observer.cancelled()
    }))
}

fn rollback_pull_ref_and_head(
    layout: &RepoLayout,
    branch: &str,
    local_tip: Option<Hash>,
    remote_tip: Hash,
    original_head: Option<Head>,
) -> Result<(), String> {
    rollback_pull_ref(layout, branch, local_tip, remote_tip).map_err(|e| e.to_string())?;
    match original_head {
        Some(Head::Branch(name)) => refs::write_head_branch(layout, &name),
        Some(Head::Detached(hash)) => refs::write_head_detached(layout, &hash),
        None => Ok(()),
    }
    .map_err(|e| e.to_string())
}

fn rollback_pull_ref(
    layout: &RepoLayout,
    branch: &str,
    local_tip: Option<Hash>,
    remote_tip: Hash,
) -> Result<(), refs::RefError> {
    if let Some(local_tip) = local_tip {
        write_ref_recording_history(
            layout,
            branch,
            refs::RefWriteCondition::Match(remote_tip),
            &local_tip,
        )
    } else if refs::read_ref(layout, branch)? == Some(remote_tip) {
        refs::delete_ref(layout, branch)
    } else {
        Ok(())
    }
}

fn load_tree_hash(store: &ObjectStore, commit_hash: Hash) -> Result<Hash, SyncError> {
    match store.read_object(&commit_hash)? {
        Object::Commit(c) => Ok(c.tree_hash),
        Object::Remix(r) => Ok(r.tree_hash),
        _ => Err(SyncError::NotCommit),
    }
}

fn select_branch(
    layout: &RepoLayout,
    head: Option<&Head>,
    target_branch: Option<&str>,
    remote_refs: &[(String, Hash)],
) -> Result<(String, Option<Hash>, Hash), SyncError> {
    let selected = match head {
        Some(Head::Branch(head_branch)) => {
            let want = target_branch.unwrap_or(head_branch);
            let local = refs::read_ref(layout, want)?;
            let selected = remote_refs.iter().find(|(name, _)| name == want);
            if local.is_some() || target_branch.is_some() {
                selected.ok_or_else(|| SyncError::RemoteBranchMissing(want.to_owned()))?
            } else {
                selected.unwrap_or(&remote_refs[0])
            }
        }
        Some(Head::Detached(_)) => return Err(SyncError::DetachedHead),
        None => &remote_refs[0],
    };
    // The selected branch may differ from the unborn branch named by HEAD.
    Ok((
        selected.0.clone(),
        refs::read_ref(layout, &selected.0)?,
        selected.1,
    ))
}

fn resume_pull(
    layout: &RepoLayout,
    store: &ObjectStore,
    branch: &str,
    pending: Option<PullState>,
    local_tip: Option<Hash>,
    observer: &dyn Observer<SyncEvent>,
) -> Result<bool, SyncError> {
    let Some(state) = pending else {
        return Ok(false);
    };
    let tip = state.target;
    let head_tip = refs::resolve_head(layout)?;
    if head_tip != Some(tip) && local_tip != Some(tip) {
        clear_pull_head(layout)?;
        return Ok(false);
    }
    let tree = load_tree_hash(store, tip)?;
    ensure_pull_restore_safe(layout, store, tree, state.before_tree)
        .map_err(SyncError::RestoreSafety)?;
    if head_tip != Some(tip) {
        refs::write_head_branch(layout, branch)?;
    }
    crate::worktree::restore_worktree_and_index_progress(layout, store, tree, None, observer)
        .map_err(SyncError::RestoreSafety)?;
    clear_pull_head(layout)?;
    Ok(true)
}

/// The refusals of a pull that resumes an interrupted restore.
const PULL_RECOVERY_REFUSALS: Refusals = Refusals {
    staged: |_| {
        "pull recovery would overwrite staged changes; copy staged work elsewhere before discarding it with `kit checkout -f <branch>`, then pull again".to_owned()
    },
    local: pull_recovery_changes_message,
    overwrite_untracked: pull_recovery_untracked_message,
    remove_untracked: pull_recovery_untracked_message,
};

/// The restore-safety check of a pull that resumes an interrupted restore:
/// each path may hold its entry from before the pull or the target's, and the
/// restore's own temporary files may be swept.
fn ensure_pull_restore_safe(
    layout: &RepoLayout,
    store: &ObjectStore,
    tree: Hash,
    before_tree: Hash,
) -> Result<(), String> {
    // The index as it is, never seeded: HEAD already names the target, so an
    // emptied index seeded from it would pass for the target.
    let index = kit_core::index::read_index(layout).map_err(|e| format!("read index: {e}"))?;
    check_restore_safe(
        layout,
        store,
        &index,
        tree,
        &RestoreOptions::default(),
        &Expected {
            trees: &[Some(before_tree), Some(tree)],
            unchanged_base: None,
            restore_temp_files: true,
            refuse_untracked_dirs: true,
            refusals: &PULL_RECOVERY_REFUSALS,
        },
    )
}

/// The refusal for a path the unfinished pull would overwrite.
fn pull_recovery_changes_message(path: &str) -> String {
    format!(
        "pull recovery would overwrite local changes at '{}'; copy it elsewhere or run `kit restore -f <path>`, then pull again",
        escape_terminal_text(path, false)
    )
}

/// The refusal for an untracked path the unfinished pull would remove.
fn pull_recovery_untracked_message(path: &str) -> String {
    format!(
        "pull recovery would remove untracked path '{}'; move or remove it, then pull again",
        escape_terminal_text(path, false)
    )
}

fn write_pull_head(
    layout: &RepoLayout,
    store: &ObjectStore,
    target: Hash,
) -> Result<(), SyncError> {
    let index = crate::worktree::read_or_seed_index_from_head(layout, store)
        .map_err(SyncError::RestoreSafety)?;
    // The check proved that the index equals HEAD. Unchanged leaves need not
    // exist for the differential restore. Recovery does a full restore and
    // checks all its objects before writing, including these reused leaves.
    let base = current_head_tree(layout, store).map_err(SyncError::RestoreSafety)?;
    let before_tree =
        kit_core::worktree::build_tree_from_index_against(store, store, &index, false, base)
            .map_err(|e| SyncError::RestoreSafety(e.to_string()))?;
    crate::applied_packs::write_atomic(
        &layout.pull_head_file(),
        &PullState {
            target,
            before_tree,
        }
        .encode(),
    )?;
    Ok(())
}

fn clear_pull_head(layout: &RepoLayout) -> Result<(), SyncError> {
    fs::remove_file(layout.pull_head_file())?;
    crate::applied_packs::sync_parent_dir(layout.worktree_state_dir())?;
    Ok(())
}

#[cfg(test)]
mod recovery_message_tests {
    #[test]
    fn the_recovery_refusal_text_is_unchanged() {
        assert_eq!(
            super::pull_recovery_changes_message("a b"),
            "pull recovery would overwrite local changes at 'a b'; copy it elsewhere or run `kit restore -f <path>`, then pull again"
        );
    }

    #[test]
    fn a_control_character_in_a_path_is_escaped() {
        for text in [
            super::pull_recovery_changes_message("a\u{1b}b"),
            super::pull_recovery_untracked_message("a\u{1b}b"),
        ] {
            assert!(text.contains("a\\u{1b}b") && !text.contains('\u{1b}'), "{text:?}");
        }
    }
}

#[cfg(test)]
mod tree_write_tests {
    #[test]
    fn pull_tree_write_reuses_head_but_checks_a_mode_change() {
        use kit_core::{index, layout::RepoLayout, object::*, refs, serialize, store::ObjectStore};
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        let store = ObjectStore::init(&layout).unwrap();
        refs::init(&layout).unwrap();
        let put = |object| {
            store
                .write(&serialize::serialize(&object).unwrap())
                .unwrap()
        };
        let blob = put(Object::Blob(Blob {
            data: b"keep".to_vec(),
        }));
        let tree = put(Object::Tree(Tree {
            entries: vec![TreeEntry {
                name: b"a".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob,
            }],
        }));
        let commit = put(Object::Commit(Commit::new_unannotated(
            tree,
            vec![],
            Identity::ed25519([1; 32]),
            [1; 32],
            b"base".to_vec(),
            1,
            [0; 64],
        )));
        refs::write_ref(&layout, "main", &commit).unwrap();
        refs::write_head_branch(&layout, "main").unwrap();
        let mut idx = index::read_or_seed_from_head(&layout, &store).unwrap();
        std::fs::remove_file({
            let hex = kit_core::hash::to_hex(&blob);
            layout.objects_dir().join(&hex[..2]).join(&hex[2..])
        })
        .unwrap();
        super::write_pull_head(&layout, &store, commit).unwrap();
        let state = kit_core::ops::pull_state::PullState::decode(
            &std::fs::read(layout.pull_head_file()).unwrap(),
        )
        .unwrap();
        assert_eq!(state.before_tree, tree);
        idx.entries[0].status = index::EntryStatus::Executable;
        index::write_index(&layout, &idx).unwrap();
        let error = super::write_pull_head(&layout, &store, commit).unwrap_err();
        assert!(
            matches!(error, crate::error::SyncError::RestoreSafety(ref message) if message.contains("not found")),
            "{error}"
        );
    }
}

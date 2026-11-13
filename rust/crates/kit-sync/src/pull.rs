//! Pulling: fetch, then fast-forward the local branch, HEAD and worktree.

use std::fs;
use std::path::Path;

use kit_core::hash::Hash;
use kit_core::layout::RepoLayout;
use kit_core::object::Object;
use kit_core::ops::graph::AncestorError;
use kit_core::ops::merge::is_ancestor_strict;
use kit_core::ops::pull_state::PullState;
use kit_core::refs::{self, Head};
use kit_core::store::ObjectStore;

use crate::SyncOptions;
use crate::error::SyncError;
use crate::fetch::{FetchReport, fetch_objects};
use crate::lock::{LockWait, acquire_worktree_lock};
use crate::observer::{Observer, SyncEvent};
use crate::source::RemoteSource;
use crate::worktree::{
    current_head_tree, ensure_restore_safe, list_remote_refs_parallel, restore_worktree_and_index,
    restore_worktree_and_index_from, write_ref_recording_history,
};

/// What a pull did to the local branch.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PullOutcome {
    /// The remote advertises no branches, so there was nothing to land.
    NoRemoteBranches,
    /// The local branch already pointed at the remote tip.
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

/// Fetch the remote's refs, then fast-forward the current local branch from
/// `refs/remotes/<remote>/<branch>`. Fresh repos with no local branch tip
/// initialise from the current branch's remote-tracking ref, or the first
/// advertised remote branch when the current default branch is absent.
/// Anything that is not a fast-forward is refused with
/// [`SyncError::NonFastForwardPull`].
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
    let remote_refs = list_remote_refs_parallel(&layout, remote)?
        .into_iter()
        .filter_map(|r| r.hash.map(|hash| (r.name, hash)))
        .collect::<Vec<_>>();
    let _lock = acquire_worktree_lock(&layout, observer, &lock_wait)?;
    let pending = PullState::read(&layout)?;
    let original_head = refs::read_head(&layout).ok();
    if matches!(original_head, Some(Head::Detached(_))) {
        return Err(SyncError::DetachedHead);
    }
    if remote_refs.is_empty() {
        if pending.is_some() {
            return Err(SyncError::RestoreSafety("unfinished pull cannot recover without a remote branch; restore the remote branch, then pull again".to_owned()));
        }
        return Ok(PullReport {
            fetch,
            outcome: PullOutcome::NoRemoteBranches,
        });
    }

    let (branch, local_tip, remote_tip) = select_branch(
        &layout,
        original_head.as_ref(),
        options.target_branch.as_deref(),
        &remote_refs,
    )?;

    let restored = resume_pull(&layout, &store, &branch, pending, local_tip)?;
    let original_head = refs::read_head(&layout).ok();
    let ref_condition = if let Some(local_tip) = local_tip {
        if local_tip == remote_tip {
            return Ok(PullReport {
                fetch,
                outcome: if restored {
                    PullOutcome::FastForwarded {
                        branch,
                        old: Some(local_tip),
                        new: remote_tip,
                    }
                } else {
                    PullOutcome::UpToDate { branch }
                },
            });
        }
        // A missing commit would read as "not a fast-forward", so the walk
        // reads every commit and names the one it cannot read.
        let fast_forward =
            is_ancestor_strict(&store, local_tip, remote_tip).map_err(|e| match e {
                AncestorError::Limit(source) => SyncError::Store(source),
                // The error keeps the id of the commit it names.
                other => SyncError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, other)),
            })?;
        if !fast_forward {
            return Err(SyncError::NonFastForwardPull { branch });
        }
        refs::RefWriteCondition::Match(local_tip)
    } else {
        refs::RefWriteCondition::Missing
    };

    let tree = load_tree_hash(&store, remote_tip)?;
    ensure_restore_safe(&layout, &store, tree).map_err(SyncError::RestoreSafety)?;
    // The check above proved that the worktree and the index equal the tree
    // of HEAD, so the restore only writes what the new tip changed.
    let base_tree = current_head_tree(&layout, &store).map_err(SyncError::RestoreSafety)?;
    if observer.cancelled() {
        return Err(SyncError::Interrupted);
    }
    write_pull_head(&layout, &store, remote_tip)?;
    write_ref_recording_history(&layout, &branch, ref_condition, &remote_tip)?;
    if let Err(e) = refs::write_head_branch(&layout, &branch) {
        rollback_pull_ref(&layout, &branch, local_tip, remote_tip)?;
        clear_pull_head(&layout)?;
        return Err(e.into());
    }
    if observer.cancelled() {
        return Err(SyncError::Interrupted);
    }
    if let Err(e) = restore_worktree_and_index_from(&layout, &store, tree, base_tree) {
        if let Err(rollback) =
            rollback_pull_ref_and_head(&layout, &branch, local_tip, remote_tip, original_head)
        {
            return Err(SyncError::RestoreSafety(format!(
                "{e}; additionally failed to roll back ref: {rollback}"
            )));
        }
        clear_pull_head(&layout)?;
        return Err(SyncError::RestoreSafety(e));
    }
    clear_pull_head(&layout)?;
    Ok(PullReport {
        fetch,
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
    fetch_objects(
        &store, &layout, source, observer, remote, options, &lock_wait,
    )
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
    restore_worktree_and_index(layout, store, tree).map_err(SyncError::RestoreSafety)?;
    clear_pull_head(layout)?;
    Ok(true)
}

// Each path may still contain the old index entry or an already-restored target
// entry. Anything else is local work. The clean restore also requires that no
// untracked, unignored path would be swept away.
fn ensure_pull_restore_safe(
    layout: &RepoLayout,
    store: &ObjectStore,
    tree: Hash,
    before_tree: Hash,
) -> Result<(), String> {
    use crate::worktree::{collect_worktree_paths, is_ignored_worktree_path};
    use kit_core::ops::diff::diff_trees;
    use kit_core::worktree;

    let index = kit_core::index::read_index(layout).map_err(|e| format!("read index: {e}"))?;
    let snapshot = kit_core::store::EphemeralSink::new(store);
    let index_tree = worktree::build_tree_from_index_with(store, &snapshot, &index, false)
        .map_err(|e| format!("index tree: {e}"))?;
    if index_tree != before_tree && index_tree != tree {
        return Err("pull recovery would overwrite staged changes; copy staged work elsewhere before discarding it with `kit checkout -f <branch>`, then pull again".to_owned());
    }
    let old = kit_core::index::from_tree(store, before_tree)
        .map_err(|e| format!("pre-pull index: {e}"))?;
    let target =
        kit_core::index::from_tree(store, tree).map_err(|e| format!("target index: {e}"))?;
    let mut tracked = old.clone();
    for entry in &target.entries {
        tracked.upsert_entry(entry.clone());
    }
    for entry in &mut tracked.entries {
        entry.mtime_ns = 0;
    }
    let root = layout.worktree_root();
    let ignore = kit_core::ignore::load(root).map_err(|e| format!("read ignore file: {e}"))?;
    let mut paths = Vec::new();
    collect_worktree_paths(root, root, "", &mut paths).map_err(|e| format!("check paths: {e}"))?;
    let temporary_paths: std::collections::HashSet<_> = paths
        .iter()
        .filter(|path| is_restore_temp(root, &tracked, path))
        .cloned()
        .collect();
    if let Some(path) = paths.iter().find(|path| {
        !tracked.tracks_path_or_descendant(path)
            && !temporary_paths.contains(*path)
            && Path::new(path)
                .ancestors()
                .filter(|parent| !parent.as_os_str().is_empty())
                .any(|parent| {
                    let name = parent.to_str().expect("collected UTF-8 path");
                    target.has_tracked_file_at(name)
                        || (!target.tracks_path_or_descendant(name)
                            && parent
                                .file_name()
                                .is_none_or(|name| name != ".kitignore" && name != ".gitignore")
                            && !is_ignored_worktree_path(root, &ignore, name))
                })
    }) {
        return Err(format!(
            "pull recovery would remove untracked path '{path}'; move or remove it, then pull again"
        ));
    }
    // The union can contain a former file and a target descendant. Keeping
    // that file in the snapshot index would hide the whole directory.
    let directories: std::collections::HashSet<_> = old
        .entries
        .iter()
        .chain(&target.entries)
        .flat_map(|entry| Path::new(&entry.path).ancestors().skip(1))
        .filter_map(|parent| parent.to_str())
        .filter(|parent| !parent.is_empty())
        .collect();
    tracked.retain_entries(|entry| !directories.contains(entry.path.as_str()));
    let current = worktree::build_tree_filtered_observed_with_source(
        &snapshot,
        &snapshot,
        root,
        Some(&tracked),
        &mut Vec::new(),
    )
    .map_err(|e| format!("working tree: {e}"))?;
    let from_old =
        diff_trees(&snapshot, Some(before_tree), Some(current)).map_err(|e| e.to_string())?;
    let from_target =
        diff_trees(&snapshot, Some(tree), Some(current)).map_err(|e| e.to_string())?;
    let changed: std::collections::HashSet<_> = from_target
        .entries
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();
    if let Some(entry) = from_old.entries.iter().find(|entry| {
        changed.contains(entry.path.as_str())
            && !temporary_paths.contains(&entry.path)
            && !(entry.kind == kit_core::ops::diff::DiffKind::Added
                && (entry.path == ".kitignore" || entry.path == ".gitignore")
                && !target.has_tracked_file_at(&entry.path))
    }) {
        return Err(pull_recovery_changes_message(&entry.path));
    }
    Ok(())
}

/// The refusal for a path the unfinished pull would overwrite.
fn pull_recovery_changes_message(path: &str) -> String {
    format!(
        "pull recovery would overwrite local changes at '{path}'; copy it elsewhere or run `kit restore -f <path>`, then pull again"
    )
}

fn write_pull_head(
    layout: &RepoLayout,
    store: &ObjectStore,
    target: Hash,
) -> Result<(), SyncError> {
    let index = crate::worktree::read_or_seed_index_from_head(layout, store)
        .map_err(SyncError::RestoreSafety)?;
    let before_tree = kit_core::worktree::build_tree_from_index_with(store, store, &index, false)
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

fn is_restore_temp(root: &Path, tracked: &kit_core::index::Index, path: &str) -> bool {
    if tracked.tracks_path_or_descendant(path) {
        return false;
    }
    let path = Path::new(path);
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    kit_core::ops::restore::is_restore_temp_name(name)
        && fs::symlink_metadata(root.join(path)).is_ok_and(|meta| meta.is_file())
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
}

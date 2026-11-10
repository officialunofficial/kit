//! Worktree and ref primitives a pull's fast-forward builds on: restore
//! safety (refuse to overwrite user work), materialising a tree together with
//! the index, and history-aware branch writes.
//!
//! These are also what the `kit` command line's `checkout`, `reset`,
//! `restore` and friends use, so they live in one place. Their error type is a
//! plain message string and their shape follows the command line's needs:
//! treat this module as an unstable convenience, not as the crate's API.

use std::fs;
use std::path::Path;

use kit_core::hash::Hash;
use kit_core::index::Index;
use kit_core::layout::RepoLayout;
use kit_core::object::Object;
use kit_core::ops::diff::{DiffKind, diff_trees};
use kit_core::ops::restore::{RestoreOptions, matches_sparse, restore_tree_to_worktree_observed};
use kit_core::refs::{self, RefError};
use kit_core::store::ObjectStore;
use kit_core::worktree as core_worktree;

/// Rewrite `.kit/index` so it exactly mirrors `tree_hash`.
///
/// `kit commit` now signs the index, so commands that move HEAD and
/// materialize a committed tree must keep the index aligned with that
/// snapshot.
pub fn sync_index_to_tree(
    layout: &RepoLayout,
    store: &ObjectStore,
    tree_hash: Hash,
) -> Result<(), String> {
    sync_index_to_tree_observed(layout, store, tree_hash, &[])
}

/// [`sync_index_to_tree`], recording `observed` as the stat cache of each
/// entry whose path and object hash match an observation. A restore that
/// just wrote those files produces them (see
/// [`kit_core::ops::restore::restore_tree_to_worktree_observed`]), so the
/// next command does not re-hash them.
pub fn sync_index_to_tree_observed(
    layout: &RepoLayout,
    store: &ObjectStore,
    tree_hash: Hash,
    observed: &[core_worktree::StatObservation],
) -> Result<(), String> {
    let mut idx =
        kit_core::index::from_tree(store, tree_hash).map_err(|e| format!("index: {e}"))?;
    // Tree-derived entries carry no stat cache. Carry it over from the
    // outgoing index wherever path AND object hash agree: a later stat
    // match against the old observation still proves the same bytes,
    // so commit/checkout don't wipe the O(stat) fast path.
    if let Ok(old) = kit_core::index::read_index(layout) {
        // O(1) lookups: find_entry is a linear scan and this loop runs
        // once per tree entry (was O(n²) per commit/checkout).
        let by_path: std::collections::HashMap<&str, &kit_core::index::IndexEntry> =
            old.entries.iter().map(|o| (o.path.as_str(), o)).collect();
        for e in &mut idx.entries {
            if let Some(o) = by_path.get(e.path.as_str())
                && o.object_hash == e.object_hash
                && o.status == e.status
            {
                e.mtime_ns = o.mtime_ns;
                e.size = o.size;
                e.ino = o.ino;
                e.ctime_ns = o.ctime_ns;
            }
        }
    }
    if !observed.is_empty() {
        let by_path: std::collections::HashMap<&str, &core_worktree::StatObservation> =
            observed.iter().map(|o| (o.path.as_str(), o)).collect();
        for e in &mut idx.entries {
            if let Some(o) = by_path.get(e.path.as_str())
                && o.object_hash == e.object_hash
            {
                e.mtime_ns = o.mtime_ns;
                e.size = o.size;
                e.ino = o.ino;
                e.ctime_ns = o.ctime_ns;
            }
        }
    }
    kit_core::index::write_index(layout, &idx).map_err(|e| format!("write index: {e}"))
}

/// Materialise `tree_hash` and align the index while preserving `.kitignore` entries.
pub fn restore_worktree_and_index(
    layout: &RepoLayout,
    store: &ObjectStore,
    tree_hash: Hash,
) -> Result<(), String> {
    let mut observed = Vec::new();
    restore_tree_to_worktree_observed(
        store,
        &tree_hash,
        None,
        layout.worktree_root(),
        &RestoreOptions::default(),
        &crate::restore_fanout::read_chunks_fanout,
        Some(&mut observed),
    )
    .map_err(|e| format!("restore worktree: {e}"))?;
    sync_index_to_tree_observed(layout, store, tree_hash, &observed)
}

/// Refuse a destructive restore when the index/worktree contains user work.
pub fn ensure_restore_safe(
    layout: &RepoLayout,
    store: &ObjectStore,
    target_tree: Hash,
) -> Result<(), String> {
    ensure_restore_safe_with_options(layout, store, target_tree, &RestoreOptions::default())
}

/// Refuse a destructive restore when affected index/worktree paths contain user work.
pub fn ensure_restore_safe_with_options(
    layout: &RepoLayout,
    store: &ObjectStore,
    target_tree: Hash,
    options: &RestoreOptions,
) -> Result<(), String> {
    let root = layout.worktree_root();
    let current_tree = current_head_tree(layout, store)?;
    let idx = read_or_seed_index_from_head(layout, store)?;
    // Safety-check snapshot trees are ephemeral — in-memory overlay,
    // no durability cost, no garbage objects in the store.
    let snapshot = kit_core::store::EphemeralSink::new(store);
    let index_tree = core_worktree::build_tree_from_index_with(store, &snapshot, &idx, false)
        .map_err(|e| format!("check index state: {e}"))?;

    let staged = diff_trees(&snapshot, current_tree, Some(index_tree))
        .map_err(|e| format!("check staged changes: {e}"))?;
    if let Some(entry) = staged
        .entries
        .iter()
        .find(|entry| restore_affects_path(options, &entry.path))
    {
        return Err(format!(
            "restore would overwrite staged changes; commit, stash, or reset '{}' first",
            entry.path
        ));
    }

    let worktree_tree = core_worktree::build_tree_filtered_observed_with_source(
        &snapshot,
        &snapshot,
        root,
        Some(&idx),
        &mut Vec::new(),
    )
    .map_err(|e| format!("check working tree changes: {e}"))?;
    let unstaged = diff_trees(&snapshot, Some(index_tree), Some(worktree_tree))
        .map_err(|e| format!("check working tree changes: {e}"))?;
    if let Some(entry) = unstaged
        .entries
        .iter()
        .find(|entry| entry.kind != DiffKind::Added && restore_affects_path(options, &entry.path))
    {
        return Err(format!(
            "restore would overwrite local changes; commit, stash, or reset '{}' first",
            entry.path
        ));
    }

    let target_writes = diff_trees(&snapshot, Some(index_tree), Some(target_tree))
        .map_err(|e| format!("check restore target: {e}"))?
        .entries
        .into_iter()
        .filter(|entry| entry.kind != DiffKind::Removed)
        .filter(|entry| restore_affects_path(options, &entry.path))
        .map(|entry| entry.path)
        .collect::<Vec<_>>();
    if target_writes.is_empty() && !options.clean {
        return Ok(());
    }

    let ignore = kit_core::ignore::load(root).map_err(|e| format!("read ignore file: {e}"))?;
    let mut worktree_paths = Vec::new();
    collect_worktree_paths(root, root, "", &mut worktree_paths)
        .map_err(|e| format!("check untracked paths: {e}"))?;
    if let Some(path) = worktree_paths.iter().find(|path| {
        !index_tracks_path_or_descendant(&idx, path)
            && target_writes
                .iter()
                .any(|target| paths_overlap(path, target))
    }) {
        return Err(format!(
            "restore would overwrite untracked path '{path}'; move or remove it first"
        ));
    }

    if options.clean
        && let Some(path) = worktree_paths.iter().find(|path| {
            !index_tracks_path_or_descendant(&idx, path)
                && restore_affects_path(options, path)
                && *path != ".kitignore"
                && *path != ".gitignore"
                && !is_ignored_worktree_path(root, &ignore, path)
        })
    {
        return Err(format!(
            "restore would remove untracked path '{path}'; move or remove it first"
        ));
    }

    Ok(())
}

#[must_use]
pub fn restore_affects_path(options: &RestoreOptions, path: &str) -> bool {
    options
        .sparse_patterns
        .as_deref()
        .is_none_or(|patterns| matches_sparse(patterns, path, false))
}

pub fn collect_worktree_paths(
    root: &Path,
    dir: &Path,
    prefix: &str,
    out: &mut Vec<String>,
) -> std::io::Result<()> {
    let read = match fs::read_dir(dir) {
        Ok(read) => read,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    for entry in read {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.eq_ignore_ascii_case(".kit") || name.eq_ignore_ascii_case(".git") {
            continue;
        }
        let path = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}/{name}")
        };
        out.push(path.clone());
        let full_path = root.join(&path);
        let meta = fs::symlink_metadata(&full_path)?;
        if meta.is_dir() {
            collect_worktree_paths(root, &full_path, &path, out)?;
        }
    }
    Ok(())
}

#[must_use]
pub fn index_tracks_path_or_descendant(index: &Index, path: &str) -> bool {
    // Delegates to `Index::tracks_path_or_descendant`, which answers via
    // the maintained `path -> position` map in `O(log n + k)` instead of
    // this function's old `O(n)` full scan — `add_tree` calls
    // this once per directory/file it walks.
    index.tracks_path_or_descendant(path)
}

#[must_use]
pub fn paths_overlap(left: &str, right: &str) -> bool {
    index_path_matches_or_descends(left, right) || index_path_descends_from(right, left)
}

pub use kit_core::index::{
    path_descends_from as index_path_descends_from,
    path_matches_or_descends as index_path_matches_or_descends,
};

#[must_use]
pub fn is_ignored_worktree_path(
    root: &Path,
    ignore: &kit_core::ignore::IgnoreList,
    path: &str,
) -> bool {
    let full_path = root.join(path);
    let Ok(meta) = fs::symlink_metadata(&full_path) else {
        return false;
    };
    // Match on the repo-relative path, and treat a path under an ignored
    // directory as ignored too (no top-down walk here to carry that bit).
    ignore.is_ignored_with_ancestors(path, meta.is_dir())
}

pub fn current_head_tree(layout: &RepoLayout, store: &ObjectStore) -> Result<Option<Hash>, String> {
    let Some(head_hash) = refs::resolve_head(layout).map_err(|e| format!("resolve HEAD: {e}"))?
    else {
        return Ok(None);
    };
    match store
        .read_object(&head_hash)
        .map_err(|e| format!("read HEAD: {e}"))?
    {
        Object::Commit(c) => Ok(Some(c.tree_hash)),
        Object::Remix(r) => Ok(Some(r.tree_hash)),
        _ => Err("HEAD does not resolve to a commit or remix".to_string()),
    }
}

pub use kit_core::index::read_or_seed_from_head as read_or_seed_index_from_head;

pub use kit_core::refs::write_ref_recording_history;

/// [`refs::list_remote_refs_with`], with the per-ref read fanned out across
/// rayon's pool once there is enough work to amortise dispatch.
pub fn list_remote_refs_parallel(
    layout: &RepoLayout,
    remote: &str,
) -> Result<Vec<refs::Ref>, RefError> {
    refs::list_remote_refs_with(layout, remote, fanout_read_batch)
}

/// Ref-read fan-out per thread. Ref files are tiny (65 bytes) and the
/// per-entry cost is dominated by syscall overhead, not compute.
const LIST_REFS_FANOUT_ENTRIES_PER_THREAD: usize = 2;

/// The `read_batch` shared by every parallel ref-listing wrapper: fans
/// [`refs::read_ref_candidate`] out across rayon once there is enough work.
#[must_use]
pub fn fanout_read_batch(candidates: &[refs::RefCandidate]) -> Vec<refs::RefReadOutcome> {
    crate::fanout::map_seq_or_par(
        candidates,
        crate::fanout::threshold(LIST_REFS_FANOUT_ENTRIES_PER_THREAD),
        |c, _| refs::read_ref_candidate(c),
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

    use super::*;
    use kit_core::object::{Blob, EntryMode, Tree, TreeEntry};
    use kit_core::serialize;

    fn put(store: &ObjectStore, obj: &Object) -> Hash {
        store.write(&serialize::serialize(obj).unwrap()).unwrap()
    }

    /// An observation becomes the index entry's stat cache only when its
    /// path and object hash both match the tree entry.
    #[test]
    fn sync_index_to_tree_observed_records_matching_observations() {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        let store = ObjectStore::init(&layout).unwrap();
        let blob = |data: &[u8]| {
            put(
                &store,
                &Object::Blob(Blob {
                    data: data.to_vec(),
                }),
            )
        };
        let (a, b) = (blob(b"a"), blob(b"b"));
        let tree = put(
            &store,
            &Object::Tree(Tree {
                entries: vec![
                    TreeEntry {
                        name: b"a".to_vec(),
                        mode: EntryMode::Blob,
                        object_hash: a,
                    },
                    TreeEntry {
                        name: b"b".to_vec(),
                        mode: EntryMode::Blob,
                        object_hash: b,
                    },
                ],
            }),
        );
        // A whole-second mtime far in the past, so the racy-clean rule
        // keeps it on read.
        let seen = |path: &str, object_hash| core_worktree::StatObservation {
            path: path.to_string(),
            object_hash,
            mtime_ns: 1_000_000_000_000_000_000,
            size: 1,
            ino: 7,
            ctime_ns: 1_000_000_000_000_000_001,
        };
        // "b" is observed with the wrong hash, "c" is not in the tree.
        let observed = [seen("a", a), seen("b", a), seen("c", b)];
        sync_index_to_tree_observed(&layout, &store, tree, &observed).unwrap();
        let idx = kit_core::index::read_index(&layout).unwrap();
        assert_eq!(idx.entries.len(), 2);
        let ea = &idx.entries[idx.find_entry("a").unwrap()];
        assert_eq!(
            (ea.mtime_ns, ea.size, ea.ino, ea.ctime_ns),
            (1_000_000_000_000_000_000, 1, 7, 1_000_000_000_000_000_001)
        );
        let eb = &idx.entries[idx.find_entry("b").unwrap()];
        assert_eq!((eb.mtime_ns, eb.size, eb.ino, eb.ctime_ns), (0, 0, 0, 0));
    }
}

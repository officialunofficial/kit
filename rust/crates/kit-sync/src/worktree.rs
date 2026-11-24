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
use kit_core::index::{EntryStatus, Index, IndexEntry};
use kit_core::layout::RepoLayout;
use kit_core::object::{EntryMode, Object};
use kit_core::ops::diff::{DiffEntry, DiffKind, diff_trees};
use kit_core::ops::restore::{RestoreOptions, matches_sparse, nested_repository};
use kit_core::protocol::escape_terminal_text;
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
    write_index_settled(layout, &idx)
}

/// The longest wait for the racy window to pass, in nanoseconds. A recorded
/// mtime so far ahead of the clock that the wait would pass this (about 11 ms
/// ahead: clock skew) is not waited for.
const SETTLE_MAX_WAIT_NS: u64 = 25_000_000;

/// One tick of the kernel's coarse file clock, which a file's mtime follows
/// (4 ms at 250 Hz). A longer tick is absorbed by the rewrite below.
const SETTLE_TICK_NS: u64 = 4_000_000;

/// How many times the index is written again when it is still too close to
/// the newest entry.
const SETTLE_REWRITES: usize = 2;

/// Write the index once the racy window has passed for its newest entry.
///
/// A restore records the stat of each file it writes, then writes the index a
/// few milliseconds later. `read_index` treats an entry within 10 ms of the
/// index file's mtime as racy, so without this wait the next command would
/// hash the newest files again, which for one large file takes minutes. The
/// wait is usually under 15 ms and only happens when an entry was written
/// that recently; a rewrite for a coarse clock adds a few milliseconds, and
/// the call never takes more than about 35 ms of waiting. An entry with a
/// whole-second mtime has a one-second window and is not waited for.
///
/// The file's stat then no longer counts as racy, so an edit made by another
/// process during the restore, inside the same timestamp tick as the restore's
/// own write, is not caught. git has the same blind spot.
/// An edit made after the command returns has a later mtime and is caught.
fn write_index_settled(layout: &RepoLayout, idx: &Index) -> Result<(), String> {
    let write =
        || kit_core::index::write_index(layout, idx).map_err(|e| format!("write index: {e}"));
    let Some(newest) = idx
        .entries
        .iter()
        .map(|e| e.mtime_ns)
        .filter(|m| *m != 0 && !m.is_multiple_of(1_000_000_000))
        .max()
    else {
        return write();
    };
    let window = kit_core::index::PRECISE_RACY_WINDOW_NS;
    // A mtime so far ahead that the wait would pass the longest wait is skew,
    // not a fresh write: do not wait for it.
    let now = now_nanos();
    let ready = newest.saturating_add(window).saturating_add(SETTLE_TICK_NS);
    if ready > now && ready - now > SETTLE_MAX_WAIT_NS {
        return write();
    }
    if ready > now {
        std::thread::sleep(std::time::Duration::from_nanos(ready - now));
    }
    write()?;
    // The index's mtime comes from the kernel's coarse clock, so it can sit
    // up to a tick behind the clock read above. Check the real stamp.
    for _ in 0..SETTLE_REWRITES {
        let Ok(meta) = std::fs::metadata(kit_core::index::index_path(layout)) else {
            break;
        };
        let stamp = core_worktree::mtime_nanos(&meta);
        if stamp == 0
            || stamp.is_multiple_of(1_000_000_000)
            || newest < stamp.saturating_sub(window)
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_nanos(SETTLE_TICK_NS));
        write()?;
    }
    Ok(())
}

fn now_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_nanos()).ok())
        .unwrap_or(0)
}

/// Materialise `tree_hash` and align the index while preserving `.kitignore` entries.
pub fn restore_worktree_and_index(
    layout: &RepoLayout,
    store: &ObjectStore,
    tree_hash: Hash,
) -> Result<(), String> {
    restore_worktree_and_index_from(layout, store, tree_hash, None)
}

/// [`restore_worktree_and_index`] that leaves alone every entry whose mode and
/// object id are the same in `base_tree`, so a file the tip did not change is
/// not read, written or re-stat'ed.
///
/// The caller must have proved that the worktree and the index equal
/// `base_tree` for every tracked path, as [`ensure_restore_safe`] does for the
/// tree of HEAD. Pass `None` when it has not.
pub fn restore_worktree_and_index_from(
    layout: &RepoLayout,
    store: &ObjectStore,
    tree_hash: Hash,
    base_tree: Option<Hash>,
) -> Result<(), String> {
    let mut stats = Vec::new();
    kit_core::ops::restore::restore_tree_to_worktree_observed(
        store,
        &tree_hash,
        base_tree,
        layout.worktree_root(),
        &RestoreOptions::default(),
        &crate::restore_fanout::read_chunks_fanout,
        Some(&mut stats),
    )
    .map_err(|e| format!("restore worktree: {e}"))?;
    sync_index_to_tree_observed(layout, store, tree_hash, &stats)
}

pub(crate) fn restore_worktree_and_index_progress(
    layout: &RepoLayout,
    store: &ObjectStore,
    tree_hash: Hash,
    base_tree: Option<Hash>,
    observer: &dyn crate::Observer<crate::SyncEvent>,
) -> Result<(), String> {
    if observer.concurrent().is_none() {
        return restore_worktree_and_index_from(layout, store, tree_hash, base_tree);
    }
    let mut stats = Vec::new();
    kit_core::ops::restore::restore_tree_to_worktree_progress(
        store,
        &tree_hash,
        base_tree,
        layout.worktree_root(),
        &RestoreOptions::default(),
        &crate::restore_fanout::read_chunks_fanout,
        Some(&mut stats),
        &mut |done, total| observer.event(&crate::SyncEvent::RestoreProgress { done, total }),
    )
    .map_err(|e| format!("restore worktree: {e}"))?;
    sync_index_to_tree_observed(layout, store, tree_hash, &stats)
}

/// Refuse a destructive restore when the index/worktree contains user work.
pub fn ensure_restore_safe(
    layout: &RepoLayout,
    store: &ObjectStore,
    target_tree: Hash,
) -> Result<(), String> {
    ensure_restore_safe_with_options(layout, store, target_tree, &RestoreOptions::default())
}

/// Refuse a restore of `entry` when the store lacks an object it needs (for
/// a chunked file, its manifest). A check with an unchanged base does not
/// open the objects the base names. The old side may be the worktree's only
/// other copy, so a restore must not overwrite or remove it. The new side is
/// read by the restore, which would otherwise fail after HEAD moved, as when
/// the target copies an unchanged file to a new path.
fn ensure_restore_objects_present(store: &ObjectStore, entry: &DiffEntry) -> Result<(), String> {
    if let Some(h) = entry.old_hash
        && !store.contains(&h)
    {
        return Err(format!(
            "restore would lose '{}': its object {} is not found in the store",
            escape_terminal_text(&entry.path, false),
            kit_core::hash::to_hex(&h)
        ));
    }
    if let Some(h) = entry.new_hash
        && !store.contains(&h)
    {
        return Err(format!(
            "restore cannot write '{}': its object {} is not found in the store",
            escape_terminal_text(&entry.path, false),
            kit_core::hash::to_hex(&h)
        ));
    }
    Ok(())
}

/// The refusal for a tracked path that differs from the index.
fn local_changes_message(path: &str) -> String {
    format!(
        "restore would overwrite local changes; commit, stash, or reset '{}' first",
        escape_terminal_text(path, false)
    )
}

fn staged_changes_message(path: &str) -> String {
    format!(
        "restore would overwrite staged changes; commit, stash, or reset '{}' first",
        escape_terminal_text(path, false)
    )
}

fn overwrite_untracked_message(path: &str) -> String {
    format!(
        "restore would overwrite untracked path '{}'; move or remove it first",
        escape_terminal_text(path, false)
    )
}

fn remove_untracked_message(path: &str) -> String {
    format!(
        "restore would remove untracked path '{}'; move or remove it first",
        escape_terminal_text(path, false)
    )
}

/// The texts one caller of [`check_restore_safe`] refuses with, each given
/// the path it refuses for.
pub(crate) struct Refusals {
    /// The index holds work no expected tree has.
    pub(crate) staged: fn(&str) -> String,
    /// A tracked path holds work no expected tree has.
    pub(crate) local: fn(&str) -> String,
    /// An untracked path lies where the restore writes.
    pub(crate) overwrite_untracked: fn(&str) -> String,
    /// A clean restore would sweep an untracked path away.
    pub(crate) remove_untracked: fn(&str) -> String,
}

const RESTORE_REFUSALS: Refusals = Refusals {
    staged: staged_changes_message,
    local: local_changes_message,
    overwrite_untracked: overwrite_untracked_message,
    remove_untracked: remove_untracked_message,
};

/// What a restore may find in the index and the worktree without destroying
/// work: each path as one of `trees` has it.
pub(crate) struct Expected<'a> {
    /// The trees the index and the worktree may match. A destructive restore
    /// expects the tree of HEAD; a pull that resumes an interrupted restore
    /// expects the tree from before the pull or the target. The index must
    /// equal one of them as a whole, the worktree each path one of them.
    pub(crate) trees: &'a [Option<Hash>],
    /// The tree whose unchanged entries the restore leaves alone. The check
    /// opens no object of an index entry equal to it; for each path the
    /// restore changes it checks that the store has the old and the new
    /// object. `None` opens every object.
    pub(crate) unchanged_base: Option<Hash>,
    /// The restore that was interrupted may have left its temporary files,
    /// which the clean restore then sweeps.
    pub(crate) restore_temp_files: bool,
    /// Refuse an untracked directory the ignore rules do not match, whatever
    /// it holds, as a pull recovery always has. Otherwise a directory is
    /// judged by its descendants, as the clean sweep judges it.
    pub(crate) refuse_untracked_dirs: bool,
    pub(crate) refusals: &'a Refusals,
}

/// Refuse a destructive restore when affected index/worktree paths contain user work.
pub fn ensure_restore_safe_with_options(
    layout: &RepoLayout,
    store: &ObjectStore,
    target_tree: Hash,
    options: &RestoreOptions,
) -> Result<(), String> {
    ensure_restore_safe_from(layout, store, target_tree, options, None)
}

/// [`ensure_restore_safe_with_options`] for a restore that leaves alone every
/// entry whose mode and object id are the same in `base_tree`, as
/// [`restore_worktree_and_index_from`] does with the tree of HEAD. The check
/// then opens no object of an index entry equal to `base_tree`; for each
/// path the restore changes, it checks that the store has the old and the
/// new object. Pass `None` when the restore rewrites every entry: the check
/// then opens every object, so a missing one refuses the restore before
/// anything is written.
pub fn ensure_restore_safe_from(
    layout: &RepoLayout,
    store: &ObjectStore,
    target_tree: Hash,
    options: &RestoreOptions,
    base_tree: Option<Hash>,
) -> Result<(), String> {
    let head = current_head_tree(layout, store)?;
    check_restore_safe(
        layout,
        store,
        &read_or_seed_index_from_head(layout, store)?,
        target_tree,
        options,
        &Expected {
            trees: &[head],
            unchanged_base: base_tree,
            restore_temp_files: false,
            refuse_untracked_dirs: false,
            refusals: &RESTORE_REFUSALS,
        },
    )
}

/// The one restore-safety check: refuse a restore of `target_tree` with
/// `options` that would destroy work, which is anything in the index or the
/// worktree that is not as one of `expected.trees` has it, an untracked path
/// the restore would write over, and with `options.clean` an untracked path the
/// sweep would remove. An untracked path is one that neither the index `idx`
/// nor an expected tree tracks. Each refusal names the first path it finds.
pub(crate) fn check_restore_safe(
    layout: &RepoLayout,
    store: &ObjectStore,
    idx: &Index,
    target_tree: Hash,
    options: &RestoreOptions,
    expected: &Expected<'_>,
) -> Result<(), String> {
    let root = layout.worktree_root();
    // Safety-check snapshot trees are ephemeral — in-memory overlay,
    // no durability cost, no garbage objects in the store.
    let snapshot = kit_core::store::EphemeralSink::new(store);
    let index_tree = core_worktree::build_tree_from_index_against(
        store,
        &snapshot,
        idx,
        false,
        expected.unchanged_base,
    )
    .map_err(|e| format!("check index state: {e}"))?;

    let affects = |path: &str| restore_affects_path(options, path);
    let staged = differ_from_every(&snapshot, expected.trees, index_tree, &affects)
        .map_err(|e| format!("check staged changes: {e}"))?;
    if let Some(entry) = &staged.matches_none {
        return Err((expected.refusals.staged)(&entry.path));
    }

    let tracked = tracked_paths(idx, &staged.missing, &affects);
    let worktree_tree = core_worktree::build_tree_filtered_observed_with_source(
        &snapshot,
        &snapshot,
        root,
        Some(&tracked),
        &mut Vec::new(),
    )
    .map_err(|e| format!("check working tree changes: {e}"))?;
    let unstaged = differ_from_every(&snapshot, expected.trees, worktree_tree, &affects)
        .map_err(|e| format!("check working tree changes: {e}"))?;
    // A path every expected tree lacks is untracked: the checks below judge it.
    // With several trees, a file where one of them has a directory is no such
    // path: the checks below count it tracked, by what lies under it, and the
    // restore would remove it. With one tree, the diff names what lies under it
    // instead.
    let several = expected.trees.len() > 1;
    if let Some((entry, _)) = unstaged.differing.iter().find(|(entry, untracked)| {
        (!untracked || (several && index_tracks_path_or_descendant(&tracked, &entry.path)))
            && restore_affects_path(options, &entry.path)
    }) {
        return Err((expected.refusals.local)(&entry.path));
    }

    // What the restore writes over a worktree that holds any expected tree. The
    // index equals one of them on every path the restore affects.
    let mut target_writes = Vec::new();
    for tree in expected.trees {
        let diff = diff_trees(&snapshot, *tree, Some(target_tree))
            .map_err(|e| format!("check restore target: {e}"))?;
        for entry in diff.entries.into_iter().filter(|e| affects(&e.path)) {
            ensure_restore_objects_present(store, &entry)?;
            if entry.kind != DiffKind::Removed {
                target_writes.push(entry.path);
            }
        }
    }
    target_writes.sort_unstable();
    target_writes.dedup();
    if target_writes.is_empty() && !options.clean {
        return Ok(());
    }

    let (ignore, worktree_paths) = restore_paths(root, &target_writes, options.clean)?;
    // A real directory that only holds a target path is no conflict: the
    // restore writes beside its contents. Its descendants are checked as
    // paths of their own.
    let is_real_dir = |path: &str| fs::symlink_metadata(root.join(path)).is_ok_and(|m| m.is_dir());
    if let Some(path) = worktree_paths.iter().find(|path| {
        !index_tracks_path_or_descendant(&tracked, path)
            && target_writes.iter().any(|target| {
                paths_overlap(path, target)
                    && !(is_real_dir(path) && index_path_descends_from(target, path))
            })
    }) {
        return Err((expected.refusals.overwrite_untracked)(path));
    }
    // A target path is a file or a symlink: the diff lists no directories. One
    // written where the worktree has a directory replaces the directory,
    // tracked or not. The walk above leaves out `.kit` and `.git`, so a nested
    // repository in it is refused here. An untracked path, and so a symlink, on
    // the way to a written path was refused above.
    for path in &target_writes {
        let dir = root.join(path);
        if !fs::symlink_metadata(&dir).is_ok_and(|meta| meta.is_dir()) {
            continue;
        }
        if let Some(entry) =
            nested_repository(&dir).map_err(|e| format!("check untracked paths: {e}"))?
        {
            return Err((expected.refusals.overwrite_untracked)(&format!(
                "{path}/{entry}"
            )));
        }
    }

    if options.clean {
        let mut kept = std::collections::HashMap::new();
        let mut ignores = std::collections::HashMap::from([(root.to_path_buf(), ignore.clone())]);
        for path in &worktree_paths {
            let full_path = root.join(path);
            let parent = full_path.parent().unwrap_or(root);
            let ignore = directory_ignore(&mut ignores, &ignore, parent)?;
            if !index_tracks_path_or_descendant(&tracked, path)
                && restore_affects_path(options, path)
                && path != ".kitignore"
                && path != ".gitignore"
                && (expected.refuse_untracked_dirs || !is_real_dir(path))
                && !is_ignored_worktree_path(root, ignore, path)
                && (!expected.restore_temp_files || !is_restore_temp(root, &tracked, path))
                && !sweep_keeps_path(store, target_tree, root, path, &mut kept)
                    .map_err(|e| format!("check untracked repository at '{path}': {e}"))?
            {
                return Err((expected.refusals.remove_untracked)(path));
            }
        }
    }

    Ok(())
}

fn restore_paths(
    root: &Path,
    targets: &[String],
    clean: bool,
) -> Result<(kit_core::ignore::IgnoreList, Vec<String>), String> {
    let ignore = kit_core::ignore::load(root).map_err(|e| format!("read ignore file: {e}"))?;
    let mut paths = Vec::new();
    collect_restore_paths(
        root,
        root,
        "",
        &mut paths,
        clean.then_some((&ignore, targets)),
    )
    .map_err(|e| format!("check untracked paths: {e}"))?;
    Ok((ignore, paths))
}

fn directory_ignore<'a>(
    cache: &'a mut std::collections::HashMap<std::path::PathBuf, kit_core::ignore::IgnoreList>,
    inherited: &kit_core::ignore::IgnoreList,
    parent: &Path,
) -> Result<&'a kit_core::ignore::IgnoreList, String> {
    use std::collections::hash_map::Entry;
    match cache.entry(parent.to_path_buf()) {
        Entry::Occupied(entry) => Ok(entry.into_mut()),
        Entry::Vacant(entry) => Ok(entry.insert(
            inherited
                .load_directory(parent)
                .map_err(|e| format!("read ignore file: {e}"))?,
        )),
    }
}

/// Only an unlisted directory with its own metadata marker is kept whole.
/// A listed directory is swept, even when it has a metadata marker; an
/// ancestor of a nested repository may also have files the sweep removes.
fn sweep_keeps_path(
    store: &ObjectStore,
    target: Hash,
    root: &Path,
    path: &str,
    cache: &mut std::collections::HashMap<String, bool>,
) -> Result<bool, String> {
    let mut path = Some(path);
    while let Some(candidate) = path {
        let kept = if let Some(kept) = cache.get(candidate) {
            *kept
        } else {
            let dir = root.join(candidate);
            let mut holds_repository = false;
            if fs::symlink_metadata(&dir).is_ok_and(|meta| meta.is_dir()) {
                for entry in fs::read_dir(&dir).map_err(|e| e.to_string())? {
                    let name = entry.map_err(|e| e.to_string())?.file_name();
                    if name.to_str().is_some_and(|name| {
                        name.eq_ignore_ascii_case(".kit") || name.eq_ignore_ascii_case(".git")
                    }) {
                        holds_repository = true;
                        break;
                    }
                }
            }
            let kept = holds_repository && !target_lists_directory(store, target, root, candidate)?;
            cache.insert(candidate.to_string(), kept);
            kept
        };
        if kept {
            return Ok(true);
        }
        path = candidate.rsplit_once('/').map(|(parent, _)| parent);
    }
    Ok(false)
}

fn target_lists_directory(
    store: &ObjectStore,
    mut tree: Hash,
    root: &Path,
    path: &str,
) -> Result<bool, String> {
    let mut dir = root.to_path_buf();
    for (depth, name) in path.split('/').enumerate() {
        if depth > kit_core::store::MAX_TREE_DEPTH {
            return Err("tree nesting exceeds the depth limit".into());
        }
        let Object::Tree(entries) = store.read_object(&tree).map_err(|e| e.to_string())? else {
            return Err("restore target is not a tree".into());
        };
        let entry = entries.entries.iter().find(|entry| {
            entry.mode == EntryMode::Tree
                && (entry.name.eq_ignore_ascii_case(name.as_bytes())
                    || std::str::from_utf8(&entry.name).is_ok_and(|target_name| {
                        directory_alias(&dir.join(target_name), &dir.join(name))
                    }))
        });
        let Some(entry) = entry else { return Ok(false) };
        tree = entry.object_hash;
        dir.push(name);
    }
    Ok(true)
}

// Unix file identity handles casefold directories even when realpath preserves
// the spelling supplied by the caller. Other targets also compare names without
// ASCII case above, conservatively refusing more on case-sensitive filesystems.
fn directory_alias(left: &Path, right: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match (fs::symlink_metadata(left), fs::symlink_metadata(right)) {
            (Ok(a), Ok(b)) => a.is_dir() && b.is_dir() && a.dev() == b.dev() && a.ino() == b.ino(),
            _ => false,
        }
    }
    #[cfg(not(unix))]
    {
        match (fs::canonicalize(left), fs::canonicalize(right)) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        }
    }
}

/// How a tree differs from the expected trees.
struct Differences {
    /// The entries of `diff(trees[0], actual)` whose path differs in every
    /// expected tree, each with whether every expected tree lacks the path.
    /// With one tree, that is the whole diff, and the flag marks a
    /// [`DiffKind::Added`] entry.
    differing: Vec<(DiffEntry, bool)>,
    /// The first entry of `diff(trees[0], actual)` on a path the restore
    /// affects, when `actual` differs from every expected tree on such a
    /// path. `None` when it equals one of them on every path the restore
    /// affects.
    matches_none: Option<DiffEntry>,
    /// The paths some expected tree has and `actual` lacks, as that tree has
    /// them, the first such tree's entry for each path.
    missing: Vec<DiffEntry>,
}

fn differ_from_every(
    snapshot: &(dyn kit_core::store::ObjectSource + Sync),
    trees: &[Option<Hash>],
    actual: Hash,
    affects: &dyn Fn(&str) -> bool,
) -> Result<Differences, kit_core::store::StoreError> {
    let mut differing: Option<Vec<(DiffEntry, bool)>> = None;
    let mut matches_none: Option<Option<DiffEntry>> = None;
    let mut missing: Vec<DiffEntry> = Vec::new();
    let mut seen_missing: std::collections::HashSet<String> = std::collections::HashSet::new();
    for tree in trees {
        let entries = diff_trees(snapshot, *tree, Some(actual))?.entries;
        let first_affected = entries.iter().find(|entry| affects(&entry.path));
        matches_none = Some(match matches_none {
            None => first_affected.cloned(),
            Some(first) => first.filter(|_| first_affected.is_some()),
        });
        missing.extend(
            entries
                .iter()
                .filter(|entry| entry.kind == DiffKind::Removed)
                .filter(|entry| seen_missing.insert(entry.path.clone()))
                .cloned(),
        );
        differing = Some(match differing {
            None => entries
                .into_iter()
                .map(|entry| {
                    let added = entry.kind == DiffKind::Added;
                    (entry, added)
                })
                .collect(),
            Some(mut kept) => {
                let kinds: std::collections::HashMap<String, DiffKind> = entries
                    .into_iter()
                    .map(|entry| (entry.path, entry.kind))
                    .collect();
                kept.retain_mut(|(entry, added)| match kinds.get(&entry.path) {
                    Some(kind) => {
                        *added &= *kind == DiffKind::Added;
                        true
                    }
                    None => false,
                });
                kept
            }
        });
    }
    Ok(Differences {
        differing: differing.unwrap_or_default(),
        matches_none: matches_none.flatten(),
        missing,
    })
}

/// The paths the restore treats as its own: the index's, and every path the
/// restore affects that an expected tree has and the index lacks (`missing`).
/// Those entries carry the expected tree's object and no stat cache. A file the union holds where
/// another of its paths needs a directory is left out, so the worktree's
/// directory is read.
fn tracked_paths<'a>(
    idx: &'a Index,
    missing: &[DiffEntry],
    affects: &dyn Fn(&str) -> bool,
) -> std::borrow::Cow<'a, Index> {
    let mut missing = missing
        .iter()
        .filter(|entry| affects(&entry.path))
        .peekable();
    if missing.peek().is_none() {
        return std::borrow::Cow::Borrowed(idx);
    }
    let mut tracked = idx.clone();
    for entry in missing {
        let (Some(object_hash), Some(mode)) = (entry.old_hash, entry.old_mode) else {
            continue;
        };
        let status = match mode {
            EntryMode::Blob => EntryStatus::Blob,
            EntryMode::Executable => EntryStatus::Executable,
            EntryMode::Symlink => EntryStatus::Symlink,
            EntryMode::Tree => continue,
        };
        tracked.upsert_entry(IndexEntry {
            path: entry.path.clone(),
            status,
            object_hash,
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
        });
    }
    let directories: std::collections::HashSet<String> = tracked
        .entries
        .iter()
        .flat_map(|entry| Path::new(&entry.path).ancestors().skip(1))
        .filter_map(|parent| parent.to_str())
        .filter(|parent| !parent.is_empty())
        .map(str::to_owned)
        .collect();
    tracked.retain_entries(|entry| !directories.contains(entry.path.as_str()));
    std::borrow::Cow::Owned(tracked)
}

/// Is `path` a temporary file an interrupted restore left: an untracked
/// regular file with a restore temporary name?
fn is_restore_temp(root: &Path, tracked: &Index, path: &str) -> bool {
    if tracked.tracks_path_or_descendant(path) {
        return false;
    }
    let Some(name) = Path::new(path).file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    kit_core::ops::restore::is_restore_temp_name(name)
        && fs::symlink_metadata(root.join(path)).is_ok_and(|meta| meta.is_file())
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
    collect_restore_paths(root, dir, prefix, out, None)
}

/// An ignored subtree matters only when a target enters it or replaces one
/// of its ancestors. The directory itself stays in the list for the sweep.
fn collect_restore_paths(
    root: &Path,
    dir: &Path,
    prefix: &str,
    out: &mut Vec<String>,
    filter: Option<(&kit_core::ignore::IgnoreList, &[String])>,
) -> std::io::Result<()> {
    let local_ignore = filter
        .map(|(ignore, _)| ignore.load_directory(dir))
        .transpose()
        .map_err(std::io::Error::other)?;
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
        if entry.file_type()?.is_dir() {
            if let (Some(ignore), Some((_, targets))) = (&local_ignore, filter)
                && ignore.is_ignored_with_ancestors(&path, true)
                && !targets.iter().any(|target| paths_overlap(&path, target))
            {
                continue;
            }
            collect_restore_paths(
                root,
                &full_path,
                &path,
                out,
                local_ignore
                    .as_ref()
                    .zip(filter.map(|(_, targets)| targets)),
            )?;
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

    #[test]
    fn the_local_changes_message_is_unchanged() {
        assert_eq!(
            local_changes_message("a b"),
            "restore would overwrite local changes; commit, stash, or reset 'a b' first"
        );
    }

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

    /// A file the restore wrote a moment ago keeps its stat cache: the index
    /// is written after the racy window, so `read_index` does not discard it.
    #[test]
    fn the_index_waits_out_the_racy_window_for_a_just_written_file() {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        let store = ObjectStore::init(&layout).unwrap();
        let a = put(
            &store,
            &Object::Blob(Blob {
                data: b"a".to_vec(),
            }),
        );
        let tree = put(
            &store,
            &Object::Tree(Tree {
                entries: vec![TreeEntry {
                    name: b"a".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: a,
                }],
            }),
        );
        for _ in 0..20 {
            // The file's mtime is now, as the restore just wrote it. Keep it
            // off a whole second, the case with a one-second window.
            let mtime_ns = (now_nanos() | 1) + 1_000;
            let seen = core_worktree::StatObservation {
                path: "a".to_owned(),
                object_hash: a,
                mtime_ns,
                size: 1,
                ino: 7,
                ctime_ns: mtime_ns,
            };
            let started = std::time::Instant::now();
            sync_index_to_tree_observed(&layout, &store, tree, &[seen]).unwrap();
            assert!(
                started.elapsed() < std::time::Duration::from_secs(5),
                "the wait is bounded"
            );
            let idx = kit_core::index::read_index(&layout).unwrap();
            let e = &idx.entries[idx.find_entry("a").unwrap()];
            assert_eq!((e.mtime_ns, e.size, e.ino), (mtime_ns, 1, 7));
        }
    }

    /// A recorded mtime far ahead of the clock is skew: the write does not
    /// wait for it.
    #[test]
    fn a_future_mtime_is_not_waited_for() {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        let store = ObjectStore::init(&layout).unwrap();
        let a = put(
            &store,
            &Object::Blob(Blob {
                data: b"a".to_vec(),
            }),
        );
        let tree = put(
            &store,
            &Object::Tree(Tree {
                entries: vec![TreeEntry {
                    name: b"a".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: a,
                }],
            }),
        );
        let mtime_ns = (now_nanos() | 1) + 3_600_000_000_000;
        let seen = core_worktree::StatObservation {
            path: "a".to_owned(),
            object_hash: a,
            mtime_ns,
            size: 1,
            ino: 7,
            ctime_ns: mtime_ns,
        };
        let started = std::time::Instant::now();
        sync_index_to_tree_observed(&layout, &store, tree, &[seen]).unwrap();
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "a future mtime is not waited for"
        );
    }
}

#[cfg(test)]
mod path_walk_tests {
    #[test]
    fn ignored_subtrees_are_skipped_only_when_no_target_overlaps() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("sub/cache/deep")).unwrap();
        std::fs::write(root.join("sub/.gitignore"), "cache/\n").unwrap();
        std::fs::write(root.join("sub/cache/deep/keep"), "keep").unwrap();
        let ignore = kit_core::ignore::load(root).unwrap();
        for (targets, enters) in [
            (vec!["other".to_owned()], false),
            (vec!["sub/cache/deep/new".to_owned()], true),
            (vec!["sub/cache".to_owned()], true),
        ] {
            let mut paths = Vec::new();
            super::collect_restore_paths(root, root, "", &mut paths, Some((&ignore, &targets)))
                .unwrap();
            assert!(paths.contains(&"sub/cache".to_owned()));
            assert_eq!(paths.contains(&"sub/cache/deep/keep".to_owned()), enters);
        }
        let mut paths = Vec::new();
        super::collect_worktree_paths(root, root, "", &mut paths).unwrap();
        assert!(paths.contains(&"sub/cache/deep/keep".to_owned()));
    }
}

#[cfg(test)]
mod nonclean_walk_tests {
    #[test]
    fn nonclean_walk_does_not_parse_untracked_directory_ignore_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("untracked/.gitignore")).unwrap();
        let (_, paths) = super::restore_paths(dir.path(), &["new".to_owned()], false).unwrap();
        assert!(paths.contains(&"untracked/.gitignore".to_owned()));
    }
}

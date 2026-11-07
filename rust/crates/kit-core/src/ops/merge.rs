//! 3-way tree merge + commit-graph merge-base + ancestry test.
//!
//! `merge_trees` lockstep-walks the three sorted entry arrays
//! (base / ours / theirs) and applies the decision matrix documented
//! above each branch in `merge_entries_recursive`. When all three sides
//! have a path with `EntryMode::Tree`, we recurse into the three
//! subtrees rather than emitting a tree-level conflict; this lets
//! per-file conflicts inside a directory be reported at their full path
//! (`src/main.rs` rather than `src`).
//!
//! `find_merge_base` walks the full DAG on both sides — it is NOT
//! limited to first-parent — so merge bases reachable only through a
//! merge commit's secondary parent are still found. Among multiple
//! common ancestors we pick the one with the smallest total depth:
//! (depth in A's ancestor tree) + (depth in B's BFS).
//!
//! `find_merge_base` and `is_ancestor` end a path at a missing object, for
//! push and its shallow boundaries. `find_merge_base_strict` and
//! `is_ancestor_strict` give the same answers on a healthy store and fail
//! with an error that names the commit where a commit cannot be read.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::hash::Hash;
use crate::object::{EntryMode, Object, Tree, TreeEntry};
use crate::ops::graph::{AncestorError, read_history_commit};
use crate::serialize;
use crate::store::{MAX_TREE_DEPTH, ObjectSink, ObjectSource, StoreError};

/// Distinct conflict kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConflictKind {
    /// Both sides modified the same path to different content.
    ModifyModify,
    /// One side deleted the path while the other modified it.
    DeleteModify,
    /// Both sides created the path with different content.
    AddAdd,
}

/// Single conflict report. `base_hash`, `ours_hash`, `theirs_hash` are
/// `None` whenever the corresponding side does not contain the path
/// (Add/Add has no base; Delete/Modify has no hash on the deleting
/// side).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    pub path: String,
    pub kind: ConflictKind,
    pub base_hash: Option<Hash>,
    pub ours_hash: Option<Hash>,
    pub theirs_hash: Option<Hash>,
    /// Tree mode of the ours-side entry (`None` when ours deleted the
    /// path). Carried so a downstream resolver can stage the ours-side
    /// with its real exec/symlink mode instead of defaulting to a plain
    /// blob.
    pub ours_mode: Option<EntryMode>,
    /// Tree mode of the theirs-side entry (`None` when theirs deleted
    /// the path).
    pub theirs_mode: Option<EntryMode>,
}

/// Result of [`merge_trees`]. The `tree_hash` is always populated —
/// even on conflict — using "ours wins in the merged tree" as the
/// tie-breaker. Callers must check `has_conflicts()` before treating
/// the result as a clean merge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeResult {
    pub tree_hash: Hash,
    pub conflicts: Vec<Conflict>,
}

impl MergeResult {
    #[must_use]
    pub fn has_conflicts(&self) -> bool {
        !self.conflicts.is_empty()
    }
}

/// 3-way merge of three trees identified by their hashes (or `None` to
/// represent the empty tree). Always writes the merged tree to `store`
/// and returns its hash, even when `conflicts` is non-empty (the merged
/// tree contains "ours" at every conflicting path so a downstream
/// resolver can see what we picked).
///
/// `store` must make every successful [`ObjectSink::put`] immediately readable
/// through [`ObjectSource`]. [`crate::store::MemoryOverlay`] supplies this contract
/// with explicit read/output budgets; custom implementations must bound their
/// own memory and work. Tree nesting retains the [`MAX_TREE_DEPTH`] cap.
///
/// # Errors
///
/// Propagates [`StoreError`] from reads and writes, including budget exhaustion.
/// Earlier writes are retained on failure; this operation is not transactional.
pub fn merge_trees<S: ObjectSource + ObjectSink + ?Sized>(
    store: &S,
    base_hash: Option<Hash>,
    ours_hash: Option<Hash>,
    theirs_hash: Option<Hash>,
) -> Result<MergeResult, StoreError> {
    let base_entries = load_entries(store, base_hash)?;
    let ours_entries = load_entries(store, ours_hash)?;
    let theirs_entries = load_entries(store, theirs_hash)?;

    let mut merged: Vec<TreeEntry> = Vec::new();
    let mut conflicts: Vec<Conflict> = Vec::new();
    merge_entries_recursive(
        store,
        &base_entries,
        &ours_entries,
        &theirs_entries,
        "",
        &mut merged,
        &mut conflicts,
        0,
    )?;

    let tree_hash = put_tree(store, merged)?;
    Ok(MergeResult {
        tree_hash,
        conflicts,
    })
}

/// Find the lowest-cost common ancestor of two commits. Returns
/// `Ok(None)` when the histories share no ancestor.
///
/// Definition of "lowest-cost": walk B breadth-first; for every node
/// also reachable from A (taken from a precomputed ancestor-depth map
/// of A), the cost is `depth_in_A + depth_in_B`; take the candidate
/// with smallest total depth, breaking ties by first-seen order in B's
/// BFS. This is NOT necessarily a unique LCA when histories cross
/// multiple times, but it is the behaviour the tests pin.
///
/// This walk is lenient on purpose: a missing object, or an object that
/// is not a commit, ends its path. Push walks histories whose shallow
/// boundaries the caller supplies, and it relies on that. Everywhere else a
/// missing commit is corruption, and the answer would come from part of the
/// history: use [`find_merge_base_strict`], which fails instead.
///
/// # Errors
///
/// Propagates [`StoreError`] from any commit-object read other than
/// `ObjectNotFound`, which is treated as "this branch terminates here".
pub fn find_merge_base<S: ObjectSource + ?Sized>(
    store: &S,
    a: Hash,
    b: Hash,
) -> Result<Option<Hash>, StoreError> {
    if a == b {
        return Ok(Some(a));
    }
    let ancestors_a = collect_ancestors_with_depth(store, a)?;

    // BFS over B.
    let mut queue: Vec<(Hash, usize)> = Vec::new();
    queue.push((b, 0));

    let mut best: Option<(Hash, usize)> = None;
    let mut head = 0usize;
    while head < queue.len() {
        let (node, depth) = queue[head];
        head += 1;
        if let Some((_, best_total)) = best
            && depth > best_total
        {
            break;
        }
        if let Some(&ancestor_depth) = ancestors_a.get(&node) {
            let total = ancestor_depth + depth;
            match best {
                None => best = Some((node, total)),
                Some((_, t)) if total < t => best = Some((node, total)),
                _ => {}
            }
        }
        match store.read_object(&node) {
            Ok(Object::Commit(c)) => {
                for &p in &c.parents {
                    queue.push((p, depth + 1));
                }
            }
            Ok(_) | Err(StoreError::ObjectNotFound(_)) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(best.map(|(h, _)| h))
}

/// Returns `true` when `ancestor` is reachable from `descendant` by
/// walking parent pointers. `ancestor == descendant` returns `true`.
///
/// This walk is lenient on purpose, like [`find_merge_base`]: a missing
/// object, or an object that is not a commit, ends its path, so a missing
/// commit can turn `true` into `false`. Push relies on that for shallow
/// boundaries. Everywhere else use [`is_ancestor_strict`], which fails
/// instead.
///
/// # Errors
///
/// Propagates [`StoreError`] from commit-object reads (other than
/// `ObjectNotFound`, which terminates the local walk silently).
pub fn is_ancestor<S: ObjectSource + ?Sized>(
    store: &S,
    ancestor: Hash,
    descendant: Hash,
) -> Result<bool, StoreError> {
    if ancestor == descendant {
        return Ok(true);
    }
    let mut seen: HashSet<Hash> = HashSet::new();
    let mut stack: Vec<Hash> = Vec::new();
    stack.push(descendant);

    while let Some(current) = stack.pop() {
        if !seen.insert(current) {
            continue;
        }
        if current == ancestor {
            return Ok(true);
        }
        match store.read_object(&current) {
            Ok(Object::Commit(c)) => {
                for &p in &c.parents {
                    stack.push(p);
                }
            }
            Ok(_) | Err(StoreError::ObjectNotFound(_)) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(false)
}

/// The most commits that each side of a strict walk reads. It matches the
/// history walk of `kit log`.
const MAX_STRICT_WALK_COMMITS: usize = 1_000_000;

/// The limit [`find_merge_base_strict`] reports when one of its two walks
/// reaches [`MAX_STRICT_WALK_COMMITS`].
const MERGE_BASE_LIMIT: &str = "1,000,000-commit merge-base walk";

/// The limit [`is_ancestor_strict`] reports when its walk reaches
/// [`MAX_STRICT_WALK_COMMITS`].
const ANCESTRY_LIMIT: &str = "1,000,000-commit ancestry walk";

/// [`find_merge_base`] that reads every commit it walks. On a healthy store
/// it returns the same commit; where a store lacks a commit of the walk it
/// fails instead of answering from part of the history.
///
/// # Errors
///
/// [`AncestorError::Unreadable`] when a commit of either walk is missing or
/// corrupt, and [`AncestorError::NotACommit`] when a parent names another
/// kind of object, a remix included. Both name the object. Fails with
/// [`AncestorError::Limit`] when either walk would read more than
/// 1,000,000 commits; it never answers from part of the history.
pub fn find_merge_base_strict<S: ObjectSource + ?Sized>(
    store: &S,
    a: Hash,
    b: Hash,
) -> Result<Option<Hash>, AncestorError> {
    find_merge_base_strict_with_cap(store, a, b, MAX_STRICT_WALK_COMMITS)
}

/// [`find_merge_base_strict`] with `cap` in place of
/// [`MAX_STRICT_WALK_COMMITS`].
fn find_merge_base_strict_with_cap<S: ObjectSource + ?Sized>(
    store: &S,
    a: Hash,
    b: Hash,
    cap: usize,
) -> Result<Option<Hash>, AncestorError> {
    if a == b {
        return Ok(Some(a));
    }
    // Both walks are breadth-first and mark a commit when they queue it, so
    // each commit is queued once, at its smallest depth. That is the depth
    // the lenient walks keep, and the order in which they first reach it.
    let mut depth_a: HashMap<Hash, usize> = HashMap::new();
    let mut queue: VecDeque<(Hash, usize)> = VecDeque::new();
    depth_a.insert(a, 0);
    queue.push_back((a, 0));
    while let Some((node, depth)) = queue.pop_front() {
        for p in read_history_commit(store, node)?.parents {
            if !depth_a.contains_key(&p) {
                if depth_a.len() >= cap {
                    return Err(strict_limit(MERGE_BASE_LIMIT));
                }
                depth_a.insert(p, depth + 1);
                queue.push_back((p, depth + 1));
            }
        }
    }

    let mut seen_b: HashSet<Hash> = HashSet::new();
    seen_b.insert(b);
    queue.push_back((b, 0));
    let mut best: Option<(Hash, usize)> = None;
    while let Some((node, depth)) = queue.pop_front() {
        if let Some((_, best_total)) = best
            && depth > best_total
        {
            break;
        }
        if let Some(&ancestor_depth) = depth_a.get(&node) {
            let total = ancestor_depth + depth;
            if best.is_none_or(|(_, t)| total < t) {
                best = Some((node, total));
            }
        }
        for p in read_history_commit(store, node)?.parents {
            if !seen_b.contains(&p) {
                if seen_b.len() >= cap {
                    return Err(strict_limit(MERGE_BASE_LIMIT));
                }
                seen_b.insert(p);
                queue.push_back((p, depth + 1));
            }
        }
    }
    Ok(best.map(|(h, _)| h))
}

/// [`is_ancestor`] that reads every commit it walks. On a healthy store it
/// returns the same answer; where a store lacks a commit of the walk it
/// fails instead of answering `false`.
///
/// # Errors
///
/// [`AncestorError::Unreadable`] when a commit of the walk is missing or
/// corrupt, and [`AncestorError::NotACommit`] when a parent names another
/// kind of object, a remix included. Both name the object. Fails with
/// [`AncestorError::Limit`] when the walk would read more than 1,000,000
/// commits.
pub fn is_ancestor_strict<S: ObjectSource + ?Sized>(
    store: &S,
    ancestor: Hash,
    descendant: Hash,
) -> Result<bool, AncestorError> {
    is_ancestor_strict_with_cap(store, ancestor, descendant, MAX_STRICT_WALK_COMMITS)
}

/// [`is_ancestor_strict`] with `cap` in place of
/// [`MAX_STRICT_WALK_COMMITS`].
fn is_ancestor_strict_with_cap<S: ObjectSource + ?Sized>(
    store: &S,
    ancestor: Hash,
    descendant: Hash,
    cap: usize,
) -> Result<bool, AncestorError> {
    let mut seen: HashSet<Hash> = HashSet::new();
    let mut stack: Vec<Hash> = vec![descendant];
    while let Some(current) = stack.pop() {
        if current == ancestor {
            return Ok(true);
        }
        if seen.contains(&current) {
            continue;
        }
        if seen.len() >= cap {
            return Err(strict_limit(ANCESTRY_LIMIT));
        }
        seen.insert(current);
        stack.extend(read_history_commit(store, current)?.parents);
    }
    Ok(false)
}

fn strict_limit(limit: &'static str) -> AncestorError {
    AncestorError::Limit(StoreError::OperationLimitExceeded(limit))
}

// ---------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------

fn load_entries<S: ObjectSource + ?Sized>(
    store: &S,
    hash: Option<Hash>,
) -> Result<Vec<TreeEntry>, StoreError> {
    match hash {
        Some(h) => match store.read_object(&h)? {
            Object::Tree(t) => Ok(t.entries),
            other => Err(StoreError::Decode(
                crate::object::KitError::InvalidObjectType(other.object_type() as u8),
            )),
        },
        None => Ok(Vec::new()),
    }
}

fn put_tree<S: ObjectSink + ?Sized>(
    store: &S,
    entries: Vec<TreeEntry>,
) -> Result<Hash, StoreError> {
    let bytes = serialize::serialize(&Object::Tree(Tree { entries }))?;
    store.put(&bytes)
}

/// The raw bytes of a single-object `Blob`, or `None` for a `ChunkedBlob`
/// (large file) or any non-blob — those skip the line-level merge and fall
/// back to a conflict. Blobs that `add`/`build_tree` produce are single
/// `Blob` objects below the chunk threshold, so this covers the source
/// files a 3-way text merge applies to.
fn single_blob_bytes<S: ObjectSource + ?Sized>(
    store: &S,
    h: Hash,
) -> Result<Option<Vec<u8>>, StoreError> {
    match store.read_object(&h)? {
        Object::Blob(b) => Ok(Some(b.data)),
        _ => Ok(None),
    }
}

/// Attempt a line-level 3-way merge of a both-sides-modified regular-file
/// blob. Returns the hash of the merged blob when ours/theirs
/// changed disjoint regions of base, or `None` to fall back to a
/// modify/modify conflict (overlapping changes, a binary side, or a
/// chunked/large blob). Genuine store I/O errors propagate.
fn try_text_merge<S: ObjectSource + ObjectSink + ?Sized>(
    store: &S,
    base_h: Hash,
    ours_h: Hash,
    theirs_h: Hash,
) -> Result<Option<Hash>, StoreError> {
    let (Some(base), Some(ours), Some(theirs)) = (
        single_blob_bytes(store, base_h)?,
        single_blob_bytes(store, ours_h)?,
        single_blob_bytes(store, theirs_h)?,
    ) else {
        return Ok(None);
    };
    match crate::ops::merge_blob_3way(&base, &ours, &theirs) {
        Some(merged) => {
            // Store as a single Blob — same shape (and hash) `add` produces
            // for sub-threshold content, so the merged object dedups.
            let bytes = serialize::serialize(&Object::Blob(crate::object::Blob { data: merged }))?;
            Ok(Some(store.put(&bytes)?))
        }
        None => Ok(None),
    }
}

fn collect_ancestors_with_depth<S: ObjectSource + ?Sized>(
    store: &S,
    start: Hash,
) -> Result<HashMap<Hash, usize>, StoreError> {
    let mut ancestors: HashMap<Hash, usize> = HashMap::new();
    let mut queue: Vec<(Hash, usize)> = Vec::new();
    queue.push((start, 0));

    let mut head = 0usize;
    while head < queue.len() {
        let (node, depth) = queue[head];
        head += 1;
        // First-write-wins.
        if ancestors.contains_key(&node) {
            continue;
        }
        ancestors.insert(node, depth);
        match store.read_object(&node) {
            Ok(Object::Commit(c)) => {
                for &p in &c.parents {
                    queue.push((p, depth + 1));
                }
            }
            Ok(_) | Err(StoreError::ObjectNotFound(_)) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(ancestors)
}

fn hash_and_mode_eq<S: ObjectSource + ?Sized>(
    store: &S,
    a: &TreeEntry,
    b: &TreeEntry,
) -> Result<bool, StoreError> {
    Ok(a.mode == b.mode
        && (a.object_hash == b.object_hash
            || (a.mode != EntryMode::Tree
                && crate::worktree::content_eq(store, &a.object_hash, &b.object_hash)?)))
}

fn min_of_three<'a>(
    a: Option<&'a [u8]>,
    b: Option<&'a [u8]>,
    c: Option<&'a [u8]>,
) -> Option<&'a [u8]> {
    let mut result: Option<&'a [u8]> = a;
    if let Some(bv) = b {
        result = match result {
            Some(r) if r <= bv => Some(r),
            _ => Some(bv),
        };
    }
    if let Some(cv) = c {
        result = match result {
            Some(r) if r <= cv => Some(r),
            _ => Some(cv),
        };
    }
    result
}

fn join_path(prefix: &str, name: &[u8]) -> String {
    let name_str = String::from_utf8_lossy(name);
    if prefix.is_empty() {
        name_str.into_owned()
    } else {
        let mut s = String::with_capacity(prefix.len() + 1 + name_str.len());
        s.push_str(prefix);
        s.push('/');
        s.push_str(&name_str);
        s
    }
}

fn add_entry(out: &mut Vec<TreeEntry>, name: &[u8], mode: EntryMode, object_hash: Hash) {
    out.push(TreeEntry {
        name: name.to_vec(),
        mode,
        object_hash,
    });
}

#[allow(clippy::too_many_arguments)]
fn recurse_subtree_merge<S: ObjectSource + ObjectSink + ?Sized>(
    store: &S,
    base_sub: Option<Hash>,
    ours_sub: Option<Hash>,
    theirs_sub: Option<Hash>,
    entry_name: &[u8],
    prefix: &str,
    merged: &mut Vec<TreeEntry>,
    conflicts: &mut Vec<Conflict>,
    depth: usize,
) -> Result<(), StoreError> {
    let sub_prefix = join_path(prefix, entry_name);
    let base_entries = load_entries(store, base_sub)?;
    let ours_entries = load_entries(store, ours_sub)?;
    let theirs_entries = load_entries(store, theirs_sub)?;

    let mut sub_merged: Vec<TreeEntry> = Vec::new();
    merge_entries_recursive(
        store,
        &base_entries,
        &ours_entries,
        &theirs_entries,
        &sub_prefix,
        &mut sub_merged,
        conflicts,
        depth + 1,
    )?;

    let sub_hash = put_tree(store, sub_merged)?;
    add_entry(merged, entry_name, EntryMode::Tree, sub_hash);
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn merge_entries_recursive<S: ObjectSource + ObjectSink + ?Sized>(
    store: &S,
    base_entries: &[TreeEntry],
    ours_entries: &[TreeEntry],
    theirs_entries: &[TreeEntry],
    prefix: &str,
    merged: &mut Vec<TreeEntry>,
    conflicts: &mut Vec<Conflict>,
    depth: usize,
) -> Result<(), StoreError> {
    if depth > MAX_TREE_DEPTH {
        return Err(StoreError::TreeTooDeep);
    }
    let mut bi = 0usize;
    let mut oi = 0usize;
    let mut ti = 0usize;

    while bi < base_entries.len() || oi < ours_entries.len() || ti < theirs_entries.len() {
        let b_name: Option<&[u8]> = base_entries.get(bi).map(|e| e.name.as_slice());
        let o_name: Option<&[u8]> = ours_entries.get(oi).map(|e| e.name.as_slice());
        let t_name: Option<&[u8]> = theirs_entries.get(ti).map(|e| e.name.as_slice());

        let Some(min_name) = min_of_three(b_name, o_name, t_name) else {
            break;
        };

        let has_base = b_name.is_some_and(|n| n == min_name);
        let has_ours = o_name.is_some_and(|n| n == min_name);
        let has_theirs = t_name.is_some_and(|n| n == min_name);

        let base_entry = if has_base {
            Some(&base_entries[bi])
        } else {
            None
        };
        let ours_entry = if has_ours {
            Some(&ours_entries[oi])
        } else {
            None
        };
        let theirs_entry = if has_theirs {
            Some(&theirs_entries[ti])
        } else {
            None
        };

        if has_base {
            bi += 1;
        }
        if has_ours {
            oi += 1;
        }
        if has_theirs {
            ti += 1;
        }

        // Match on the captured entries themselves rather than the parallel
        // booleans: the `Some`/`None` shape carries the same information and
        // binds the references directly, so there is nothing to `unwrap`.
        match (base_entry, ours_entry, theirs_entry) {
            (Some(b), Some(o), Some(t)) => {
                let b_eq_o = hash_and_mode_eq(store, b, o)?;
                let b_eq_t = hash_and_mode_eq(store, b, t)?;
                let o_eq_t = hash_and_mode_eq(store, o, t)?;
                if b_eq_o && b_eq_t {
                    add_entry(merged, min_name, b.mode, b.object_hash);
                } else if b_eq_t && !b_eq_o {
                    // Theirs unchanged, ours changed -> take ours.
                    if b.mode == EntryMode::Tree && o.mode == EntryMode::Tree {
                        recurse_subtree_merge(
                            store,
                            Some(b.object_hash),
                            Some(o.object_hash),
                            Some(b.object_hash),
                            min_name,
                            prefix,
                            merged,
                            conflicts,
                            depth,
                        )?;
                    } else {
                        add_entry(merged, min_name, o.mode, o.object_hash);
                    }
                } else if b_eq_o && !b_eq_t {
                    // Ours unchanged, theirs changed -> take theirs.
                    if b.mode == EntryMode::Tree && t.mode == EntryMode::Tree {
                        recurse_subtree_merge(
                            store,
                            Some(b.object_hash),
                            Some(b.object_hash),
                            Some(t.object_hash),
                            min_name,
                            prefix,
                            merged,
                            conflicts,
                            depth,
                        )?;
                    } else {
                        add_entry(merged, min_name, t.mode, t.object_hash);
                    }
                } else if o_eq_t {
                    // Both changed the same way.
                    if b.mode == EntryMode::Tree && o.mode == EntryMode::Tree {
                        recurse_subtree_merge(
                            store,
                            Some(b.object_hash),
                            Some(o.object_hash),
                            Some(t.object_hash),
                            min_name,
                            prefix,
                            merged,
                            conflicts,
                            depth,
                        )?;
                    } else {
                        add_entry(merged, min_name, o.mode, o.object_hash);
                    }
                } else if b.mode == EntryMode::Tree
                    && o.mode == EntryMode::Tree
                    && t.mode == EntryMode::Tree
                {
                    // Three-way subtree change — recurse to find per-file conflicts.
                    recurse_subtree_merge(
                        store,
                        Some(b.object_hash),
                        Some(o.object_hash),
                        Some(t.object_hash),
                        min_name,
                        prefix,
                        merged,
                        conflicts,
                        depth,
                    )?;
                } else if o.mode == t.mode
                    && matches!(o.mode, EntryMode::Blob | EntryMode::Executable)
                    && let Some(merged_hash) =
                        try_text_merge(store, b.object_hash, o.object_hash, t.object_hash)?
                {
                    // Both changed the same regular file, but on disjoint
                    // lines — auto-merge the content. Mode is shared,
                    // so it carries over unambiguously.
                    add_entry(merged, min_name, o.mode, merged_hash);
                } else {
                    // Both changed differently and the content can't be
                    // line-merged (overlap / binary / mode mismatch / chunked)
                    // -> modify/modify conflict.
                    conflicts.push(Conflict {
                        path: join_path(prefix, min_name),
                        kind: ConflictKind::ModifyModify,
                        base_hash: Some(b.object_hash),
                        ours_hash: Some(o.object_hash),
                        theirs_hash: Some(t.object_hash),
                        ours_mode: Some(o.mode),
                        theirs_mode: Some(t.mode),
                    });
                    // Ours wins in the merged tree.
                    add_entry(merged, min_name, o.mode, o.object_hash);
                }
            }
            (None, Some(o), None) => {
                add_entry(merged, min_name, o.mode, o.object_hash);
            }
            (None, None, Some(t)) => {
                add_entry(merged, min_name, t.mode, t.object_hash);
            }
            (None, Some(o), Some(t)) => {
                if hash_and_mode_eq(store, o, t)? {
                    add_entry(merged, min_name, o.mode, o.object_hash);
                } else if o.mode == EntryMode::Tree && t.mode == EntryMode::Tree {
                    recurse_subtree_merge(
                        store,
                        None,
                        Some(o.object_hash),
                        Some(t.object_hash),
                        min_name,
                        prefix,
                        merged,
                        conflicts,
                        depth,
                    )?;
                } else {
                    conflicts.push(Conflict {
                        path: join_path(prefix, min_name),
                        kind: ConflictKind::AddAdd,
                        base_hash: None,
                        ours_hash: Some(o.object_hash),
                        theirs_hash: Some(t.object_hash),
                        ours_mode: Some(o.mode),
                        theirs_mode: Some(t.mode),
                    });
                    add_entry(merged, min_name, o.mode, o.object_hash);
                }
            }
            (Some(b), Some(o), None) => {
                if hash_and_mode_eq(store, b, o)? {
                    // Ours unchanged, theirs deleted -> delete.
                } else {
                    conflicts.push(Conflict {
                        path: join_path(prefix, min_name),
                        kind: ConflictKind::DeleteModify,
                        base_hash: Some(b.object_hash),
                        ours_hash: Some(o.object_hash),
                        theirs_hash: None,
                        ours_mode: Some(o.mode),
                        theirs_mode: None,
                    });
                    add_entry(merged, min_name, o.mode, o.object_hash);
                }
            }
            (Some(b), None, Some(t)) => {
                if hash_and_mode_eq(store, b, t)? {
                    // Theirs unchanged, ours deleted -> delete.
                } else {
                    conflicts.push(Conflict {
                        path: join_path(prefix, min_name),
                        kind: ConflictKind::DeleteModify,
                        base_hash: Some(b.object_hash),
                        ours_hash: None,
                        theirs_hash: Some(t.object_hash),
                        ours_mode: None,
                        theirs_mode: Some(t.mode),
                    });
                    add_entry(merged, min_name, t.mode, t.object_hash);
                }
            }
            (Some(_b), None, None) => {
                // Both deleted -> delete.
            }
            (None, None, None) => {
                // unreachable — `min_of_three` returns None in this case
                // and we'd have broken out of the loop above.
                break;
            }
        }
    }
    Ok(())
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
#[allow(clippy::many_single_char_names)] // single-letter commit names keep the test tables compact
mod tests {
    use super::*;
    use crate::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
    use crate::ops::test_store::CorpusStore;
    use crate::serialize;
    use tempfile::TempDir;

    fn merge_trees(
        s: &CorpusStore,
        base: Option<Hash>,
        ours: Option<Hash>,
        theirs: Option<Hash>,
    ) -> Result<MergeResult, StoreError> {
        s.compare(|backend| super::merge_trees(backend, base, ours, theirs))
    }
    fn find_merge_base(s: &CorpusStore, a: Hash, b: Hash) -> Result<Option<Hash>, StoreError> {
        s.compare(|backend| super::find_merge_base(backend, a, b))
    }
    fn is_ancestor(s: &CorpusStore, a: Hash, b: Hash) -> Result<bool, StoreError> {
        s.compare(|backend| super::is_ancestor(backend, a, b))
    }

    fn store() -> (TempDir, CorpusStore) {
        let d = TempDir::new().unwrap();
        let s = CorpusStore::new(d.path());
        (d, s)
    }
    fn put_blob(s: &CorpusStore, data: &[u8]) -> Hash {
        let bytes = serialize::serialize(&Object::Blob(Blob {
            data: data.to_vec(),
        }))
        .unwrap();
        s.write(&bytes).unwrap()
    }
    fn make_tree(s: &CorpusStore, entries: Vec<TreeEntry>) -> Hash {
        let bytes = serialize::serialize(&Object::Tree(Tree { entries })).unwrap();
        s.write(&bytes).unwrap()
    }
    fn entry(name: &[u8], mode: EntryMode, h: Hash) -> TreeEntry {
        TreeEntry {
            name: name.to_vec(),
            mode,
            object_hash: h,
        }
    }
    fn make_commit(s: &CorpusStore, tree: Hash, parents: &[Hash], message: &str) -> Hash {
        let c = Commit {
            tree_hash: tree,
            parents: parents.to_vec(),
            author: Identity::ed25519([0; 32]),
            signer: [0; 32],
            message: message.as_bytes().to_vec(),
            timestamp: message.len() as u64,
            message_hash: [0; 32],
            content_digest: [0; 32],
            signature: [0; 64],
        };
        let bytes = serialize::serialize(&Object::Commit(c)).unwrap();
        s.write(&bytes).unwrap()
    }
    fn tree_entries(s: &CorpusStore, h: Hash) -> Vec<TreeEntry> {
        match s.read_object(&h).unwrap() {
            Object::Tree(t) => t.entries,
            other => panic!("expected tree, got {other}"),
        }
    }
    fn find_entry<'a>(entries: &'a [TreeEntry], name: &[u8]) -> Option<&'a TreeEntry> {
        entries.iter().find(|e| e.name == name)
    }

    #[test]
    fn merge_identical_trees() {
        let (_d, s) = store();
        let blob_a = put_blob(&s, b"aaa");
        let tree = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, blob_a)]);
        let r = merge_trees(&s, Some(tree), Some(tree), Some(tree)).unwrap();
        assert!(!r.has_conflicts());
        assert_eq!(r.tree_hash, tree);
    }

    #[test]
    fn merge_ours_adds_file() {
        let (_d, s) = store();
        let a = put_blob(&s, b"aaa");
        let b = put_blob(&s, b"bbb");
        let base = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, a)]);
        let ours = make_tree(
            &s,
            vec![
                entry(b"a.txt", EntryMode::Blob, a),
                entry(b"b.txt", EntryMode::Blob, b),
            ],
        );
        let r = merge_trees(&s, Some(base), Some(ours), Some(base)).unwrap();
        assert!(!r.has_conflicts());
        let entries = tree_entries(&s, r.tree_hash);
        assert_eq!(entries.len(), 2);
        assert_eq!(find_entry(&entries, b"a.txt").unwrap().object_hash, a);
        assert_eq!(find_entry(&entries, b"b.txt").unwrap().object_hash, b);
    }

    #[test]
    fn merge_theirs_adds_file() {
        let (_d, s) = store();
        let a = put_blob(&s, b"aaa");
        let c = put_blob(&s, b"ccc");
        let base = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, a)]);
        let theirs = make_tree(
            &s,
            vec![
                entry(b"a.txt", EntryMode::Blob, a),
                entry(b"c.txt", EntryMode::Blob, c),
            ],
        );
        let r = merge_trees(&s, Some(base), Some(base), Some(theirs)).unwrap();
        assert!(!r.has_conflicts());
        let entries = tree_entries(&s, r.tree_hash);
        assert_eq!(entries.len(), 2);
        assert_eq!(find_entry(&entries, b"c.txt").unwrap().object_hash, c);
    }

    #[test]
    fn merge_both_add_different_files() {
        let (_d, s) = store();
        let a = put_blob(&s, b"aaa");
        let b = put_blob(&s, b"bbb");
        let c = put_blob(&s, b"ccc");
        let base = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, a)]);
        let ours = make_tree(
            &s,
            vec![
                entry(b"a.txt", EntryMode::Blob, a),
                entry(b"b.txt", EntryMode::Blob, b),
            ],
        );
        let theirs = make_tree(
            &s,
            vec![
                entry(b"a.txt", EntryMode::Blob, a),
                entry(b"c.txt", EntryMode::Blob, c),
            ],
        );
        let r = merge_trees(&s, Some(base), Some(ours), Some(theirs)).unwrap();
        assert!(!r.has_conflicts());
        assert_eq!(tree_entries(&s, r.tree_hash).len(), 3);
    }

    #[test]
    fn merge_both_add_same_file_same_content() {
        let (_d, s) = store();
        let a = put_blob(&s, b"aaa");
        let b = put_blob(&s, b"bbb");
        let base = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, a)]);
        let twin = make_tree(
            &s,
            vec![
                entry(b"a.txt", EntryMode::Blob, a),
                entry(b"b.txt", EntryMode::Blob, b),
            ],
        );
        let r = merge_trees(&s, Some(base), Some(twin), Some(twin)).unwrap();
        assert!(!r.has_conflicts());
        assert_eq!(
            find_entry(&tree_entries(&s, r.tree_hash), b"b.txt")
                .unwrap()
                .object_hash,
            b
        );
    }

    #[test]
    fn merge_both_add_same_file_different_content() {
        let (_d, s) = store();
        let a = put_blob(&s, b"aaa");
        let b1 = put_blob(&s, b"bbb-ours");
        let b2 = put_blob(&s, b"bbb-theirs");
        let base = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, a)]);
        let ours = make_tree(
            &s,
            vec![
                entry(b"a.txt", EntryMode::Blob, a),
                entry(b"b.txt", EntryMode::Blob, b1),
            ],
        );
        let theirs = make_tree(
            &s,
            vec![
                entry(b"a.txt", EntryMode::Blob, a),
                entry(b"b.txt", EntryMode::Blob, b2),
            ],
        );
        let r = merge_trees(&s, Some(base), Some(ours), Some(theirs)).unwrap();
        assert!(r.has_conflicts());
        assert_eq!(r.conflicts.len(), 1);
        let c = &r.conflicts[0];
        assert_eq!(c.path, "b.txt");
        assert_eq!(c.kind, ConflictKind::AddAdd);
        assert_eq!(c.base_hash, None);
        assert_eq!(c.ours_hash, Some(b1));
        assert_eq!(c.theirs_hash, Some(b2));
    }

    #[test]
    fn merge_ours_modifies() {
        let (_d, s) = store();
        let v1 = put_blob(&s, b"v1");
        let v2 = put_blob(&s, b"v2");
        let base = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, v1)]);
        let ours = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, v2)]);
        let r = merge_trees(&s, Some(base), Some(ours), Some(base)).unwrap();
        assert!(!r.has_conflicts());
        assert_eq!(
            find_entry(&tree_entries(&s, r.tree_hash), b"a.txt")
                .unwrap()
                .object_hash,
            v2
        );
    }

    #[test]
    fn merge_theirs_modifies() {
        let (_d, s) = store();
        let v1 = put_blob(&s, b"v1");
        let v2 = put_blob(&s, b"v2");
        let base = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, v1)]);
        let theirs = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, v2)]);
        let r = merge_trees(&s, Some(base), Some(base), Some(theirs)).unwrap();
        assert!(!r.has_conflicts());
        assert_eq!(
            find_entry(&tree_entries(&s, r.tree_hash), b"a.txt")
                .unwrap()
                .object_hash,
            v2
        );
    }

    #[test]
    fn merge_both_modify_same_way() {
        let (_d, s) = store();
        let v1 = put_blob(&s, b"v1");
        let v2 = put_blob(&s, b"v2");
        let base = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, v1)]);
        let modified = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, v2)]);
        let r = merge_trees(&s, Some(base), Some(modified), Some(modified)).unwrap();
        assert!(!r.has_conflicts());
    }

    #[test]
    fn merge_both_modify_differently() {
        let (_d, s) = store();
        let v1 = put_blob(&s, b"v1");
        let v2 = put_blob(&s, b"v2-ours");
        let v3 = put_blob(&s, b"v3-theirs");
        let base = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, v1)]);
        let ours = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, v2)]);
        let theirs = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, v3)]);
        let r = merge_trees(&s, Some(base), Some(ours), Some(theirs)).unwrap();
        assert!(r.has_conflicts());
        let c = &r.conflicts[0];
        assert_eq!(c.path, "a.txt");
        assert_eq!(c.kind, ConflictKind::ModifyModify);
        assert_eq!(c.base_hash, Some(v1));
        assert_eq!(c.ours_hash, Some(v2));
        assert_eq!(c.theirs_hash, Some(v3));
    }

    #[test]
    fn merge_ours_deletes() {
        let (_d, s) = store();
        let a = put_blob(&s, b"aaa");
        let b = put_blob(&s, b"bbb");
        let base = make_tree(
            &s,
            vec![
                entry(b"a.txt", EntryMode::Blob, a),
                entry(b"b.txt", EntryMode::Blob, b),
            ],
        );
        let ours = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, a)]);
        let r = merge_trees(&s, Some(base), Some(ours), Some(base)).unwrap();
        assert!(!r.has_conflicts());
        assert_eq!(tree_entries(&s, r.tree_hash).len(), 1);
    }

    #[test]
    fn merge_theirs_deletes() {
        let (_d, s) = store();
        let a = put_blob(&s, b"aaa");
        let b = put_blob(&s, b"bbb");
        let base = make_tree(
            &s,
            vec![
                entry(b"a.txt", EntryMode::Blob, a),
                entry(b"b.txt", EntryMode::Blob, b),
            ],
        );
        let theirs = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, a)]);
        let r = merge_trees(&s, Some(base), Some(base), Some(theirs)).unwrap();
        assert!(!r.has_conflicts());
        assert_eq!(tree_entries(&s, r.tree_hash).len(), 1);
    }

    #[test]
    fn merge_both_delete() {
        let (_d, s) = store();
        let a = put_blob(&s, b"aaa");
        let b = put_blob(&s, b"bbb");
        let base = make_tree(
            &s,
            vec![
                entry(b"a.txt", EntryMode::Blob, a),
                entry(b"b.txt", EntryMode::Blob, b),
            ],
        );
        let both = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, a)]);
        let r = merge_trees(&s, Some(base), Some(both), Some(both)).unwrap();
        assert!(!r.has_conflicts());
        assert_eq!(tree_entries(&s, r.tree_hash).len(), 1);
    }

    #[test]
    fn merge_delete_vs_modify() {
        let (_d, s) = store();
        let a = put_blob(&s, b"aaa");
        let b1 = put_blob(&s, b"bbb-v1");
        let b2 = put_blob(&s, b"bbb-v2");
        let base = make_tree(
            &s,
            vec![
                entry(b"a.txt", EntryMode::Blob, a),
                entry(b"b.txt", EntryMode::Blob, b1),
            ],
        );
        let ours = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, a)]);
        let theirs = make_tree(
            &s,
            vec![
                entry(b"a.txt", EntryMode::Blob, a),
                entry(b"b.txt", EntryMode::Blob, b2),
            ],
        );
        let r = merge_trees(&s, Some(base), Some(ours), Some(theirs)).unwrap();
        assert!(r.has_conflicts());
        let c = &r.conflicts[0];
        assert_eq!(c.path, "b.txt");
        assert_eq!(c.kind, ConflictKind::DeleteModify);
        assert_eq!(c.base_hash, Some(b1));
        assert_eq!(c.ours_hash, None);
        assert_eq!(c.theirs_hash, Some(b2));
    }

    #[test]
    fn merge_nested_tree_changes() {
        let (_d, s) = store();
        let main_v1 = put_blob(&s, b"fn main() {}");
        let main_v2 = put_blob(&s, b"fn main() { run(); }");
        let util = put_blob(&s, b"fn util() {}");
        let base_sub = make_tree(&s, vec![entry(b"main.rs", EntryMode::Blob, main_v1)]);
        let base = make_tree(&s, vec![entry(b"src", EntryMode::Tree, base_sub)]);
        let ours_sub = make_tree(&s, vec![entry(b"main.rs", EntryMode::Blob, main_v2)]);
        let ours = make_tree(&s, vec![entry(b"src", EntryMode::Tree, ours_sub)]);
        let theirs_sub = make_tree(
            &s,
            vec![
                entry(b"main.rs", EntryMode::Blob, main_v1),
                entry(b"util.rs", EntryMode::Blob, util),
            ],
        );
        let theirs = make_tree(&s, vec![entry(b"src", EntryMode::Tree, theirs_sub)]);
        let r = merge_trees(&s, Some(base), Some(ours), Some(theirs)).unwrap();
        assert!(!r.has_conflicts());
        let root = tree_entries(&s, r.tree_hash);
        assert_eq!(root.len(), 1);
        let src = tree_entries(&s, root[0].object_hash);
        assert_eq!(src.len(), 2);
        assert_eq!(find_entry(&src, b"main.rs").unwrap().object_hash, main_v2);
        assert_eq!(find_entry(&src, b"util.rs").unwrap().object_hash, util);
    }

    #[test]
    fn merge_nested_conflict_path_is_full() {
        let (_d, s) = store();
        let v1 = put_blob(&s, b"original");
        let v2 = put_blob(&s, b"ours-change");
        let v3 = put_blob(&s, b"theirs-change");
        let base_sub = make_tree(&s, vec![entry(b"main.rs", EntryMode::Blob, v1)]);
        let base = make_tree(&s, vec![entry(b"src", EntryMode::Tree, base_sub)]);
        let ours_sub = make_tree(&s, vec![entry(b"main.rs", EntryMode::Blob, v2)]);
        let ours = make_tree(&s, vec![entry(b"src", EntryMode::Tree, ours_sub)]);
        let theirs_sub = make_tree(&s, vec![entry(b"main.rs", EntryMode::Blob, v3)]);
        let theirs = make_tree(&s, vec![entry(b"src", EntryMode::Tree, theirs_sub)]);
        let r = merge_trees(&s, Some(base), Some(ours), Some(theirs)).unwrap();
        assert!(r.has_conflicts());
        assert_eq!(r.conflicts[0].path, "src/main.rs");
        assert_eq!(r.conflicts[0].kind, ConflictKind::ModifyModify);
        assert_eq!(r.conflicts[0].base_hash, Some(v1));
        assert_eq!(r.conflicts[0].ours_hash, Some(v2));
        assert_eq!(r.conflicts[0].theirs_hash, Some(v3));
    }

    #[test]
    fn merge_empty_base() {
        let (_d, s) = store();
        let a = put_blob(&s, b"aaa");
        let b = put_blob(&s, b"bbb");
        let ours = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, a)]);
        let theirs = make_tree(&s, vec![entry(b"b.txt", EntryMode::Blob, b)]);
        let r = merge_trees(&s, None, Some(ours), Some(theirs)).unwrap();
        assert!(!r.has_conflicts());
        assert_eq!(tree_entries(&s, r.tree_hash).len(), 2);
    }

    // ---- find_merge_base ----

    #[test]
    fn find_merge_base_linear() {
        let (_d, s) = store();
        let empty = make_tree(&s, vec![]);
        let a = make_commit(&s, empty, &[], "A");
        let b = make_commit(&s, empty, &[a], "B");
        let c = make_commit(&s, empty, &[b], "C");
        let d = make_commit(&s, empty, &[b], "D");
        assert_eq!(find_merge_base(&s, c, d).unwrap(), Some(b));
    }

    #[test]
    fn find_merge_base_root() {
        let (_d, s) = store();
        let empty = make_tree(&s, vec![]);
        let a = make_commit(&s, empty, &[], "A");
        let b = make_commit(&s, empty, &[a], "B");
        let c = make_commit(&s, empty, &[a], "C");
        assert_eq!(find_merge_base(&s, b, c).unwrap(), Some(a));
    }

    #[test]
    fn find_merge_base_no_common_ancestor() {
        let (_d, s) = store();
        let empty = make_tree(&s, vec![]);
        let x = make_commit(&s, empty, &[], "X");
        let y = make_commit(&s, empty, &[], "Y");
        assert_eq!(find_merge_base(&s, x, y).unwrap(), None);
    }

    #[test]
    fn find_merge_base_same_commit() {
        let (_d, s) = store();
        let empty = make_tree(&s, vec![]);
        let a = make_commit(&s, empty, &[], "A");
        assert_eq!(find_merge_base(&s, a, a).unwrap(), Some(a));
    }

    #[test]
    fn find_merge_base_walks_non_first_parents() {
        let (_d, s) = store();
        let empty = make_tree(&s, vec![]);
        let root = make_commit(&s, empty, &[], "root");
        let left = make_commit(&s, empty, &[root], "left");
        let right = make_commit(&s, empty, &[root], "right");
        let m = make_commit(&s, empty, &[left, right], "merge");
        let tip = make_commit(&s, empty, &[m], "tip");
        assert_eq!(find_merge_base(&s, tip, right).unwrap(), Some(right));
    }

    #[test]
    fn is_ancestor_walks_merge_parents() {
        let (_d, s) = store();
        let empty = make_tree(&s, vec![]);
        let root = make_commit(&s, empty, &[], "root");
        let left = make_commit(&s, empty, &[root], "left");
        let right = make_commit(&s, empty, &[root], "right");
        let m = make_commit(&s, empty, &[left, right], "merge");

        assert!(is_ancestor(&s, root, m).unwrap());
        assert!(is_ancestor(&s, right, m).unwrap());
        assert!(!is_ancestor(&s, m, right).unwrap());
    }

    #[test]
    fn merge_both_modify_disjoint_lines_auto_merges() {
        let (_d, s) = store();
        let base_b = put_blob(&s, b"a\nb\nc\nd\ne\n");
        let ours_b = put_blob(&s, b"A\nb\nc\nd\ne\n"); // line 1
        let theirs_b = put_blob(&s, b"a\nb\nc\nd\nE\n"); // line 5
        let base = make_tree(&s, vec![entry(b"f.txt", EntryMode::Blob, base_b)]);
        let ours = make_tree(&s, vec![entry(b"f.txt", EntryMode::Blob, ours_b)]);
        let theirs = make_tree(&s, vec![entry(b"f.txt", EntryMode::Blob, theirs_b)]);
        let r = merge_trees(&s, Some(base), Some(ours), Some(theirs)).unwrap();
        assert!(
            !r.has_conflicts(),
            "disjoint line edits should auto-merge, got {:?}",
            r.conflicts
        );
        let f = find_entry(&tree_entries(&s, r.tree_hash), b"f.txt")
            .unwrap()
            .object_hash;
        let merged = match s.read_object(&f).unwrap() {
            Object::Blob(b) => b.data,
            other => panic!("merged f.txt not a blob: {other:?}"),
        };
        assert_eq!(merged, b"A\nb\nc\nd\nE\n");
    }

    #[test]
    fn merge_both_modify_same_line_still_conflicts() {
        let (_d, s) = store();
        let base_b = put_blob(&s, b"a\nb\nc\n");
        let ours_b = put_blob(&s, b"a\nOURS\nc\n"); // line 2
        let theirs_b = put_blob(&s, b"a\nTHEIRS\nc\n"); // line 2 — overlaps
        let base = make_tree(&s, vec![entry(b"f.txt", EntryMode::Blob, base_b)]);
        let ours = make_tree(&s, vec![entry(b"f.txt", EntryMode::Blob, ours_b)]);
        let theirs = make_tree(&s, vec![entry(b"f.txt", EntryMode::Blob, theirs_b)]);
        let r = merge_trees(&s, Some(base), Some(ours), Some(theirs)).unwrap();
        assert!(r.has_conflicts(), "same-line edits must still conflict");
        assert_eq!(r.conflicts[0].kind, ConflictKind::ModifyModify);
    }
}

/// The strict walks on a store with missing, corrupt and odd objects.
#[cfg(test)]
#[allow(clippy::many_single_char_names)] // single-letter commit names follow the fixture diagrams
mod strict_tests {
    use std::fs;
    use std::path::PathBuf;

    use tempfile::TempDir;

    use super::*;
    use crate::hash;
    use crate::layout::RepoLayout;
    use crate::object::{Blob, Commit, Identity, Remix};
    use crate::store::ObjectStore;

    fn fresh_store() -> (TempDir, ObjectStore) {
        let dir = TempDir::new().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
        (dir, store)
    }

    fn put(store: &ObjectStore, object: &Object) -> Hash {
        store.write(&serialize::serialize(object).unwrap()).unwrap()
    }

    fn put_tree(store: &ObjectStore) -> Hash {
        let blob = put(
            store,
            &Object::Blob(Blob {
                data: b"f".to_vec(),
            }),
        );
        put(
            store,
            &Object::Tree(Tree {
                entries: vec![TreeEntry {
                    name: b"f".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: blob,
                }],
            }),
        )
    }

    fn put_commit(store: &ObjectStore, tree: Hash, parents: Vec<Hash>, ts: u64) -> Hash {
        put(
            store,
            &Object::Commit(Commit::new_unannotated(
                tree,
                parents,
                Identity::ed25519([0; 32]),
                [0; 32],
                b"msg".to_vec(),
                ts,
                [0; 64],
            )),
        )
    }

    fn object_path(dir: &TempDir, h: &Hash) -> PathBuf {
        let hex = hash::to_hex(h);
        RepoLayout::single(dir.path())
            .objects_dir()
            .join(&hex[..2])
            .join(&hex[2..])
    }

    fn remove(dir: &TempDir, h: &Hash) {
        fs::remove_file(object_path(dir, h)).unwrap();
    }

    /// Flip the last byte of the object `h`.
    fn corrupt(dir: &TempDir, h: &Hash) {
        let path = object_path(dir, h);
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        fs::write(&path, &bytes).unwrap();
    }

    /// main = r - p - m - g; side = r - p - x - merge(x, g).
    /// Returns the store and [r, p, m, g, x, merge].
    fn fixture() -> (TempDir, ObjectStore, [Hash; 6]) {
        let (dir, store) = fresh_store();
        let tree = put_tree(&store);
        let r = put_commit(&store, tree, vec![], 1);
        let p = put_commit(&store, tree, vec![r], 2);
        let m = put_commit(&store, tree, vec![p], 3);
        let g = put_commit(&store, tree, vec![m], 4);
        let x = put_commit(&store, tree, vec![p], 5);
        let merge = put_commit(&store, tree, vec![x, g], 6);
        (dir, store, [r, p, m, g, x, merge])
    }

    /// Assert that `result` failed and named `culprit`.
    fn assert_names<T: std::fmt::Debug>(result: Result<T, AncestorError>, culprit: &Hash) {
        let err = result.unwrap_err();
        assert!(
            matches!(
                &err,
                AncestorError::Unreadable { hash, .. } | AncestorError::NotACommit(hash)
                    if hash == culprit
            ),
            "{err:?}"
        );
    }

    #[test]
    fn a_healthy_store_gives_the_lenient_answers() {
        let (_d, store, [_, p, _, g, x, merge]) = fixture();
        assert_eq!(find_merge_base_strict(&store, g, p).unwrap(), Some(p));
        assert_eq!(find_merge_base_strict(&store, x, g).unwrap(), Some(p));
        assert_eq!(find_merge_base_strict(&store, merge, g).unwrap(), Some(g));
        assert!(is_ancestor_strict(&store, p, g).unwrap());
        assert!(!is_ancestor_strict(&store, x, g).unwrap());
    }

    #[test]
    fn a_missing_commit_fails_the_walk_on_either_side() {
        let (dir, store, [_, p, m, g, x, merge]) = fixture();
        remove(&dir, &m);
        // The lenient walks answer from the part of the history they can
        // read: no common ancestor, and not an ancestor.
        assert_eq!(find_merge_base(&store, g, p).unwrap(), None);
        assert!(!is_ancestor(&store, p, g).unwrap());
        // The commit is missing from the first side, then from the second.
        assert_names(find_merge_base_strict(&store, g, p), &m);
        assert_names(find_merge_base_strict(&store, p, g), &m);
        assert_names(find_merge_base_strict(&store, x, g), &m);
        assert_names(is_ancestor_strict(&store, p, g), &m);
        assert_names(is_ancestor_strict(&store, p, merge), &m);
    }

    #[test]
    fn a_corrupt_commit_fails_the_walk_on_either_side() {
        let (dir, store, [_, p, m, g, x, _]) = fixture();
        corrupt(&dir, &m);
        assert_names(find_merge_base_strict(&store, g, p), &m);
        assert_names(find_merge_base_strict(&store, x, g), &m);
        assert_names(is_ancestor_strict(&store, p, g), &m);
    }

    #[test]
    fn a_parent_that_is_not_a_commit_fails_the_walk() {
        let (_d, store, [_, p, _, g, _, _]) = fixture();
        let tree = put_tree(&store);
        let odd = put_commit(&store, tree, vec![g, tree], 7);
        assert_names(find_merge_base_strict(&store, odd, p), &tree);
        assert_names(find_merge_base_strict(&store, p, odd), &tree);
        assert_names(is_ancestor_strict(&store, p, odd), &tree);
    }

    /// The walk of the second side stops once no deeper commit can give a
    /// better base. A commit it never reaches cannot change the answer, so
    /// its absence is no error.
    #[test]
    fn a_missing_commit_below_the_answer_is_never_read() {
        let (dir, store) = fresh_store();
        let tree = put_tree(&store);
        let r = put_commit(&store, tree, vec![], 1);
        let q = put_commit(&store, tree, vec![r], 2);
        let z = put_commit(&store, tree, vec![], 3);
        let y = put_commit(&store, tree, vec![z], 4);
        let b = put_commit(&store, tree, vec![q, y], 5);
        remove(&dir, &z);
        assert_eq!(find_merge_base_strict(&store, q, b).unwrap(), Some(q));
    }

    /// r - a1, r - b1; ma = merge(a1, b1) and mb = merge(b1, a1) have two
    /// merge bases, a1 and b1. ta sits on ma. Returns [a1, b1, ma, mb, ta].
    fn criss_cross() -> (TempDir, ObjectStore, [Hash; 5]) {
        let (dir, store) = fresh_store();
        let tree = put_tree(&store);
        let r = put_commit(&store, tree, vec![], 1);
        let a1 = put_commit(&store, tree, vec![r], 2);
        let b1 = put_commit(&store, tree, vec![r], 3);
        let ma = put_commit(&store, tree, vec![a1, b1], 4);
        let mb = put_commit(&store, tree, vec![b1, a1], 5);
        let ta = put_commit(&store, tree, vec![ma], 6);
        (dir, store, [a1, b1, ma, mb, ta])
    }

    #[test]
    fn a_criss_cross_with_a_missing_commit_fails() {
        let (_d, store, [_, b1, _, mb, ta]) = criss_cross();
        let healthy = find_merge_base_strict(&store, ta, mb).unwrap();
        assert_eq!(healthy, find_merge_base(&store, ta, mb).unwrap());
        assert_eq!(healthy, Some(b1));

        // Without ma the first side reaches no merge base.
        let (dir, store, [_, _, ma, mb, ta]) = criss_cross();
        remove(&dir, &ma);
        assert_eq!(find_merge_base(&store, ta, mb).unwrap(), None);
        assert_names(find_merge_base_strict(&store, ta, mb), &ma);

        // Each merge base candidate missing in turn.
        for which in 0..2 {
            let (dir, store, hashes) = criss_cross();
            remove(&dir, &hashes[which]);
            assert_names(
                find_merge_base_strict(&store, hashes[4], hashes[3]),
                &hashes[which],
            );
        }
    }

    /// A remix is not a commit to the strict walks. The lenient walks end
    /// the path at a remix, so they find a merge base where the strict
    /// walks fail.
    #[test]
    fn a_remix_in_the_history_fails_the_strict_walks() {
        let (_d, store) = fresh_store();
        let tree = put_tree(&store);
        let r = put_commit(&store, tree, vec![], 1);
        let remix = put(
            &store,
            &Object::Remix(Remix {
                tree_hash: tree,
                parents: vec![r],
                sources: Vec::new(),
                author: Identity::ed25519([0; 32]),
                signer: [0; 32],
                message: b"remix".to_vec(),
                timestamp: 2,
                signature: [0; 64],
            }),
        );
        let a = put_commit(&store, tree, vec![remix], 3);
        let b = put_commit(&store, tree, vec![remix], 4);
        assert_eq!(find_merge_base(&store, a, b).unwrap(), Some(remix));
        assert!(!is_ancestor(&store, r, a).unwrap());
        assert_names(find_merge_base_strict(&store, a, b), &remix);
        assert_names(is_ancestor_strict(&store, r, a), &remix);
    }

    #[test]
    fn a_walk_over_the_cap_fails_and_names_the_limit() {
        let (_d, store) = fresh_store();
        let tree = put_tree(&store);
        let mut chain = vec![put_commit(&store, tree, vec![], 0)];
        for ts in 1..4 {
            let parent = chain[chain.len() - 1];
            chain.push(put_commit(&store, tree, vec![parent], ts));
        }
        let (root, tip) = (chain[0], chain[3]);
        let limit = |err: AncestorError, name: &str| {
            assert!(
                matches!(&err, AncestorError::Limit(StoreError::OperationLimitExceeded(l)) if *l == name),
                "{err:?}"
            );
        };
        // Four commits on each side fit a cap of four, not of three.
        for (a, b) in [(tip, root), (root, tip)] {
            assert_eq!(
                find_merge_base_strict_with_cap(&store, a, b, 4).unwrap(),
                Some(root)
            );
            limit(
                find_merge_base_strict_with_cap(&store, a, b, 3).unwrap_err(),
                MERGE_BASE_LIMIT,
            );
        }
        let other = put_commit(&store, tree, vec![], 9);
        assert!(!is_ancestor_strict_with_cap(&store, other, tip, 4).unwrap());
        limit(
            is_ancestor_strict_with_cap(&store, other, tip, 3).unwrap_err(),
            ANCESTRY_LIMIT,
        );
    }

    /// On random healthy histories the strict walks give exactly the
    /// answers of the lenient walks: chains, merges of two or three
    /// parents, repeated parents, criss-cross merges, several roots, and
    /// equal or skewed timestamps.
    #[test]
    fn a_healthy_history_gives_the_lenient_answers() {
        for seed in 1..=80u64 {
            let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15);
            let mut below = |n: usize| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                usize::try_from(state >> 33).unwrap() % n
            };
            let (_d, store) = fresh_store();
            let tree = put_tree(&store);
            let n = 1 + below(30);
            let mut hashes: Vec<Hash> = Vec::new();
            for i in 0..n {
                let mut parents = Vec::new();
                if i > 0 && below(15) != 0 {
                    match below(8) {
                        0 | 1 => {
                            for _ in 0..2 + below(2) {
                                parents.push(hashes[below(i)]);
                            }
                        }
                        2 => parents.push(hashes[below(i)]),
                        _ => parents.push(hashes[i - 1]),
                    }
                }
                let ts = match seed % 3 {
                    0 => 7,
                    1 => i as u64,
                    _ => below(5) as u64,
                };
                hashes.push(put_commit(&store, tree, parents, ts));
            }
            for &a in &hashes {
                for &b in &hashes {
                    assert_eq!(
                        find_merge_base_strict(&store, a, b).unwrap(),
                        find_merge_base(&store, a, b).unwrap(),
                        "seed {seed}"
                    );
                    assert_eq!(
                        is_ancestor_strict(&store, a, b).unwrap(),
                        is_ancestor(&store, a, b).unwrap(),
                        "seed {seed}"
                    );
                }
            }
        }
    }
}

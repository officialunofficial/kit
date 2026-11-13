//! Commit-graph traversal helpers.
//!
//! This module exposes [`collect_ancestor_set`]. Higher-level walks
//! (`is_ancestor`, `find_merge_base` and their strict variants) live in
//! [`super::merge`] alongside the merge algorithm that consumes them.
//!
//! Bound: at most [`MAX_ANCESTORS`] (`10_000`) commits are visited per
//! call. A walk that would visit more fails with
//! [`StoreError::OperationLimitExceeded`] and never returns a partial set:
//! a caller that leaves out an incomplete ancestor set would let ancestors
//! through.

use std::collections::{BTreeSet, HashSet, VecDeque};
use std::hash::BuildHasher;

use crate::hash::{self, Hash};
use crate::object::{EntryMode, Object, ObjectType};
use crate::store::{ObjectSource, ObjectStore, StoreError};

/// Hard cap on commits visited per call.
pub const MAX_ANCESTORS: usize = 10_000;

/// The limit [`collect_ancestor_set`] reports when it reaches
/// [`MAX_ANCESTORS`].
pub const ANCESTOR_LIMIT: &str = "10,000-commit ancestor walk";

/// Collect the set of all ancestor commits of `start`, including
/// `start` itself, by DFS over `Commit::parents`. The walk:
///
/// * Adds `start` to `set` even if its object is not in the store
///   (the hash is recorded, then the missing-object error
///   short-circuits the parent walk for that node).
/// * Treats non-commit objects at a hash as terminators (no parents to
///   follow).
/// * Fails with [`StoreError::OperationLimitExceeded`] naming
///   [`ANCESTOR_LIMIT`] when it would insert more than [`MAX_ANCESTORS`]
///   commits. `set` may then hold part of the ancestors; do not use it.
///
/// # Errors
///
/// All source errors, including resource-budget exhaustion, propagate except
/// [`StoreError::ObjectNotFound`]. Reaching the cap is an error.
/// `ObjectNotFound` is *swallowed* — see test
/// `handles_non_existent_parent_gracefully`.
pub fn collect_ancestor_set<S: BuildHasher>(
    store: &(impl ObjectSource + ?Sized),
    start: Hash,
    set: &mut HashSet<Hash, S>,
) -> Result<(), StoreError> {
    collect_ancestor_set_with_cap(store, start, set, MAX_ANCESTORS, ANCESTOR_LIMIT)
}

/// Why a strict ancestor walk failed. A strict walk reads every commit of
/// the history: a walk that ended at a commit it could not read would miss
/// every ancestor behind it.
///
/// New failure kinds can be added without a breaking change, so match with
/// a wildcard arm.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AncestorError {
    /// A commit of the history cannot be read.
    #[error("commit {} cannot be read: {source}", hash::to_hex(.hash))]
    Unreadable {
        /// The commit that cannot be read.
        hash: Hash,
        /// Why the read failed.
        source: StoreError,
    },
    /// A commit names a parent that is not a commit.
    #[error("object {} in the history is not a commit", hash::to_hex(.0))]
    NotACommit(Hash),
    /// The walk reached its cap.
    #[error(transparent)]
    Limit(StoreError),
}

/// Whether `err` names `culprit` as a commit that cannot be read or is not
/// a commit.
#[cfg(test)]
pub(crate) fn names_commit(err: &AncestorError, culprit: &Hash) -> bool {
    matches!(
        err,
        AncestorError::Unreadable { hash, .. } | AncestorError::NotACommit(hash) if hash == culprit
    )
}

/// Whether `err` is a walk that reached the cap named `limit`.
#[cfg(test)]
pub(crate) fn names_limit(err: &AncestorError, limit: &str) -> bool {
    matches!(err, AncestorError::Limit(StoreError::OperationLimitExceeded(l)) if *l == limit)
}

/// Read the commit `hash` of a history.
///
/// # Errors
/// [`AncestorError::Unreadable`] when the object cannot be read, and
/// [`AncestorError::NotACommit`] when it is another kind of object.
pub(crate) fn read_history_commit(
    store: &(impl ObjectSource + ?Sized),
    hash: Hash,
) -> Result<crate::object::Commit, AncestorError> {
    match store.read_object(&hash) {
        Ok(Object::Commit(commit)) => Ok(commit),
        Ok(_) => Err(AncestorError::NotACommit(hash)),
        Err(source) => Err(AncestorError::Unreadable { hash, source }),
    }
}

/// [`collect_ancestor_set`] with a caller-supplied cap and the limit name
/// its error reports.
///
/// # Errors
///
/// As [`collect_ancestor_set`], with `cap` in place of [`MAX_ANCESTORS`].
pub(crate) fn collect_ancestor_set_with_cap<S: BuildHasher>(
    store: &(impl ObjectSource + ?Sized),
    start: Hash,
    set: &mut HashSet<Hash, S>,
    cap: usize,
    limit: &'static str,
) -> Result<(), StoreError> {
    walk_ancestors(start, set, cap, limit, |current| {
        match store.read_object(&current) {
            Ok(Object::Commit(c)) => Ok(c.parents),
            // A non-commit or a missing object ends the path.
            Ok(_) | Err(StoreError::ObjectNotFound(_)) => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    })
}

/// Collect `start` and all of its ancestors into `set`, reading every one
/// of them. A root commit ends a path.
///
/// # Errors
///
/// [`AncestorError::Unreadable`] or [`AncestorError::NotACommit`] when a
/// commit of the history cannot be read or is another kind of object, and
/// [`AncestorError::Limit`] naming `limit` when the walk would insert more
/// than `cap` commits. `set` may then hold part of the ancestors; do not
/// use it.
pub(crate) fn collect_history_with_cap<S: BuildHasher>(
    store: &(impl ObjectSource + ?Sized),
    start: Hash,
    set: &mut HashSet<Hash, S>,
    cap: usize,
    limit: &'static str,
) -> Result<(), AncestorError> {
    walk_ancestors(start, set, cap, limit, |current| {
        read_history_commit(store, current).map(|c| c.parents)
    })
}

/// A depth-first walk from `start` that inserts each hash into `set` and
/// follows the parents that `parents` returns for it.
fn walk_ancestors<S: BuildHasher, E: From<LimitReached>>(
    start: Hash,
    set: &mut HashSet<Hash, S>,
    cap: usize,
    limit: &'static str,
    mut parents: impl FnMut(Hash) -> Result<Vec<Hash>, E>,
) -> Result<(), E> {
    let mut stack: Vec<Hash> = vec![start];
    let mut count: usize = 0;
    while let Some(current) = stack.pop() {
        if set.contains(&current) {
            continue;
        }
        if count >= cap {
            return Err(LimitReached(limit).into());
        }
        set.insert(current);
        count += 1;
        stack.extend(parents(current)?);
    }
    Ok(())
}

/// An ancestor walk reached its cap, named by the limit it reports.
struct LimitReached(&'static str);

impl From<LimitReached> for StoreError {
    fn from(LimitReached(limit): LimitReached) -> Self {
        Self::OperationLimitExceeded(limit)
    }
}

impl From<LimitReached> for AncestorError {
    fn from(LimitReached(limit): LimitReached) -> Self {
        Self::Limit(StoreError::OperationLimitExceeded(limit))
    }
}

/// Hard cap on the object ids a closure walk retains per call. Matches the
/// scale of [`MAX_ANCESTORS`] but applies to the object closure, so it is
/// intentionally larger. The cap bounds the retained id set to about half a
/// GiB. [`reachable_objects`], and so push, count every chunk toward it, so
/// a repository with more chunks than the cap can be fetched or collected
/// but not pushed whole. [`check_closure_present`], the check a fetch runs,
/// and `gc` (see [`super::gc::live_objects`]) count no chunk.
pub const MAX_REACHABLE: usize = 10_000_000;

/// How a closure walk treats commit/remix parents.
///
/// [`ClosureMode::Snapshot`] includes a commit (or remix, or tag) and the tree
/// closure it names — trees, blobs, chunked-blob manifests, chunks —
/// but not parent commits. [`ClosureMode::History`] is today's
/// [`reachable_objects`] semantics: every ancestor, identical to what
/// push/fetch ship. Remix `sources` are never followed in either mode
/// (they are foreign-repo pointers, SPEC-OBJECTS §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClosureMode {
    /// Commit/remix/tag + its tree closure. Parents are referenced
    /// but not included.
    Snapshot,
    /// Full history: commit/remix → tree + every parent, recursively.
    History,
}

/// What an edge of the object graph allows its target to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChildKind {
    /// Any object type.
    Any,
    /// A tree entry: `Tree` mode names a [`ObjectType::Tree`]; every other
    /// mode names a file, a [`ObjectType::Blob`] or a
    /// [`ObjectType::ChunkedBlob`].
    Entry(EntryMode),
    /// A chunk of a [`ObjectType::ChunkedBlob`]: a [`ObjectType::Blob`].
    Chunk,
    /// Exactly this type: the tree of a commit or remix, or the target of a
    /// tag, which records its type.
    Type(ObjectType),
}

/// Bit `1 << ty` in a [`ChildKind::mask`].
pub(crate) fn type_bit(ty: ObjectType) -> u8 {
    1 << ty as u8
}

/// The object types a file entry may name.
const FILE_TYPES: u8 = (1 << ObjectType::Blob as u8) + (1 << ObjectType::ChunkedBlob as u8);

impl ChildKind {
    /// Bit `1 << type` for each object type the edge allows.
    #[must_use]
    pub(crate) fn mask(self) -> u8 {
        match self {
            Self::Any => u8::MAX,
            Self::Entry(EntryMode::Tree) => type_bit(ObjectType::Tree),
            Self::Entry(EntryMode::Blob | EntryMode::Executable | EntryMode::Symlink) => FILE_TYPES,
            Self::Chunk => type_bit(ObjectType::Blob),
            Self::Type(ty) => type_bit(ty),
        }
    }
}

/// The single source of truth for "what does this object reference".
///
/// * [`Object::Commit`]: `tree_hash`, plus `parents` only in
///   [`ClosureMode::History`].
/// * [`Object::Remix`]: `tree_hash`, plus `parents` only in
///   [`ClosureMode::History`]; never `sources`.
/// * [`Object::Tree`]: every entry's `object_hash`.
/// * [`Object::ChunkedBlob`]: every chunk.
/// * [`Object::Tag`][]: `target`.
/// * [`Object::Blob`] / [`Object::Delta`]: none (`Delta.base_hash` is
///   not followed — deltas are pack-only leaves).
#[must_use]
pub fn children(obj: &Object, mode: ClosureMode) -> Vec<Hash> {
    typed_children(obj, mode)
        .into_iter()
        .map(|(id, _)| id)
        .collect()
}

/// [`children`], each with the [`ChildKind`] its edge allows.
#[must_use]
pub(crate) fn typed_children(obj: &Object, mode: ClosureMode) -> Vec<(Hash, ChildKind)> {
    let any = |id: &Hash| (*id, ChildKind::Any);
    let tree = |id: &Hash| (*id, ChildKind::Type(ObjectType::Tree));
    match obj {
        Object::Commit(c) => {
            let mut out = Vec::with_capacity(1 + c.parents.len());
            out.push(tree(&c.tree_hash));
            if mode == ClosureMode::History {
                out.extend(c.parents.iter().map(any));
            }
            out
        }
        Object::Remix(r) => {
            let mut out = Vec::with_capacity(1 + r.parents.len());
            out.push(tree(&r.tree_hash));
            if mode == ClosureMode::History {
                out.extend(r.parents.iter().map(any));
            }
            out
        }
        Object::Tree(t) => t
            .entries
            .iter()
            .map(|e| (e.object_hash, ChildKind::Entry(e.mode)))
            .collect(),
        Object::ChunkedBlob(cb) => cb.chunks.iter().map(|c| (*c, ChildKind::Chunk)).collect(),
        Object::Tag(t) => vec![(t.target, ChildKind::Type(t.target_type))],
        Object::Blob(_) | Object::Delta(_) => Vec::new(),
    }
}

/// Collect every object reachable from commit `root` — the full closure
/// needed to reconstruct the commit on a fresh store. Walks, in order:
///
/// 1. `root` commit → its `tree_hash` + every `parent`.
/// 2. each tree → every entry's `object_hash` (blob / tree / chunked-blob).
/// 3. nested trees → recurse.
/// 4. chunked-blob manifests → every `chunks[i]` hash.
///
/// Deltas are not produced by any path the push code drives, and remix
/// objects are walked like commits (tree + parents) per SPEC-OBJECTS §6.
///
/// Returns a [`BTreeSet`] so iteration order is deterministic — the
/// push code uses that to build reproducible packfiles. Deduplication
/// happens naturally via the set.
///
/// # Errors
///
/// - [`StoreError::ObjectNotFound`] if `root` itself is missing from
///   the store. Missing *referenced* objects (e.g. a tree listing a
///   blob that got pruned) are a harder failure and propagate via the
///   same variant — callers pushing partial repos should fix their
///   store before pushing.
/// - [`StoreError::OperationLimitExceeded`] naming [`REACHABLE_LIMIT`]
///   when the closure reaches [`MAX_REACHABLE`].
/// - Other [`StoreError`] variants propagate as-is.
pub fn reachable_objects(store: &ObjectStore, root: &Hash) -> Result<BTreeSet<Hash>, StoreError> {
    reachable_closure(store, std::iter::once(root))
}

/// Collect every object reachable from **any** of `roots` — the
/// multi-root generalization of [`reachable_objects`]. `kit gc` does not
/// use it: [`super::gc::live_objects`] marks the closure of the roots from
/// [`super::gc::collect_roots`] with the chunks held apart, so that a chunk
/// counts toward no cap.
///
/// Identical walk semantics to [`reachable_objects`] (commits/remixes →
/// tree + parents, trees → entries, chunked-blobs → chunks, tags →
/// target, blobs/deltas are leaves), deduped via the returned
/// [`BTreeSet`], and capped at [`MAX_REACHABLE`] total objects. With a
/// single root the result is byte-identical to [`reachable_objects`].
///
/// # Errors
///
/// Propagates [`StoreError`] as [`reachable_objects`] does — notably
/// [`StoreError::ObjectNotFound`] for a missing root or referenced
/// object, so a caller (gc) fails closed rather than under-counting the
/// live set.
///
/// # Content integrity of leaves
///
/// This walk classifies blob/delta leaves via a cheap type check
/// ([`ObjectStore::object_type`]) instead of a full verified read, so a
/// leaf's BLAKE3 content hash is **not** checked here — only its type.
/// A blob whose stored bytes are corrupted but whose type prologue is
/// intact is still counted as reachable (and, for `gc`, therefore
/// survives). This is a deliberate scope change from the walk's
/// pre-fix behavior, where every leaf's content was verified
/// incidentally as a side effect of the full read the old
/// classification path did. Corruption is still caught — just later,
/// the first time something actually reads the leaf's bytes (pack
/// build, checkout, `cat-file`, ...) via `store.read`/`read_object`,
/// both of which always verify. `gc`'s job is reachability, not
/// content integrity, so this narrowing is intentional; it just means
/// `gc`/push-planning are no longer an incidental corruption-detection
/// pass the way they used to be.
///
/// A walk that reaches [`MAX_REACHABLE`] fails with
/// [`StoreError::OperationLimitExceeded`] naming [`REACHABLE_LIMIT`]: a
/// cut closure would let push send a pack that lacks every object past
/// the cut. A caller that can split its work asks
/// [`reachable_closure_checked`] first.
pub fn reachable_closure<'a, I>(store: &ObjectStore, roots: I) -> Result<BTreeSet<Hash>, StoreError>
where
    I: IntoIterator<Item = &'a Hash>,
{
    complete(reachable_closure_checked(store, roots))
}

/// The limit [`reachable_closure`], [`reachable_objects`] and
/// [`reachable_snapshot`] report when a walk reaches [`MAX_REACHABLE`].
pub const REACHABLE_LIMIT: &str = "10,000,000-object closure walk";

/// The closure of a walk, or [`StoreError::OperationLimitExceeded`] when the
/// cap cut it.
pub(crate) fn complete(
    walk: Result<(BTreeSet<Hash>, bool), StoreError>,
) -> Result<BTreeSet<Hash>, StoreError> {
    match walk? {
        (out, false) => Ok(out),
        (_, true) => Err(StoreError::OperationLimitExceeded(REACHABLE_LIMIT)),
    }
}

/// Like [`reachable_closure`] but also reports whether the
/// [`MAX_REACHABLE`] cap truncated the walk (`true` = incomplete). A
/// caller that would *delete* unreachable objects MUST treat
/// `truncated == true` as fatal: beyond the cap the "unreachable" verdict
/// is unsound, so pruning would drop live data.
///
/// # Errors
///
/// Propagates [`StoreError`] as [`reachable_objects`] does.
pub fn reachable_closure_checked<'a, I>(
    store: &ObjectStore,
    roots: I,
) -> Result<(BTreeSet<Hash>, bool), StoreError>
where
    I: IntoIterator<Item = &'a Hash>,
{
    reachable_closure_checked_with_cap(store, roots, MAX_REACHABLE)
}

/// Collect every object reachable from `root` in [`ClosureMode::Snapshot`]:
/// the commit (or remix, or tag) and its tree closure, but not parent
/// commits. Same walker as [`reachable_objects`], driven by
/// [`children`]`(obj, Snapshot)`.
///
/// # Errors
///
/// Propagates [`StoreError`] as [`reachable_objects`] does, including
/// [`StoreError::OperationLimitExceeded`] when the walk reaches
/// [`MAX_REACHABLE`].
pub fn reachable_snapshot(store: &ObjectStore, root: &Hash) -> Result<BTreeSet<Hash>, StoreError> {
    complete(reachable_with_mode(
        store,
        std::iter::once(root),
        ClosureMode::Snapshot,
        MAX_REACHABLE,
    ))
}

/// Same walk as [`reachable_closure_checked`], but with a caller-supplied
/// cap instead of the hardcoded [`MAX_REACHABLE`] (10 million).
///
/// Injection point for tests and for the push walks: a truncation has
/// no other way to be exercised without actually constructing
/// ten million objects. `pub(crate)`, not part of the public API — real
/// external callers MUST use [`reachable_closure_checked`] (or
/// [`reachable_closure`]) instead.
pub(crate) fn reachable_closure_checked_with_cap<'a, I>(
    store: &ObjectStore,
    roots: I,
    cap: usize,
) -> Result<(BTreeSet<Hash>, bool), StoreError>
where
    I: IntoIterator<Item = &'a Hash>,
{
    reachable_with_mode(store, roots, ClosureMode::History, cap)
}

/// Check that every object reachable from `roots` in
/// [`ClosureMode::History`] is in the store, the walk of
/// [`reachable_closure_checked`]. Returns `true` when the [`MAX_REACHABLE`]
/// cap truncated the walk, so objects past it went unchecked.
///
/// A chunk of a chunked blob needs only its type, so it is checked without
/// being queued, and the cap counts commits, trees, blobs and manifests only.
/// The walk remembers up to [`MAX_CHECKED_CHUNKS`] checked chunk ids, so a
/// chunk that several versions of a file share is read once. Past that bound
/// a chunk is checked again for each manifest that names it, and memory stays
/// fixed. A repository past the cap in chunks still passes this check, and
/// so does `gc`, which counts no chunk toward the cap. Push, which retains
/// every chunk, refuses it.
///
/// # Errors
///
/// [`StoreError::ObjectNotFound`] for a missing root, object or chunk, and
/// every other [`StoreError`] as [`reachable_objects`] reports it.
pub fn check_closure_present<'a, I>(store: &ObjectStore, roots: I) -> Result<bool, StoreError>
where
    I: IntoIterator<Item = &'a Hash>,
{
    check_closure_present_with_cap(store, roots, MAX_REACHABLE, MAX_CHECKED_CHUNKS)
}

/// The most checked chunk ids [`check_closure_present`] remembers, about
/// 100 MiB: the chunks of about 128 GiB of typical content.
pub const MAX_CHECKED_CHUNKS: usize = 2_097_152;

/// [`check_closure_present`] with a caller-supplied cap and chunk memory, so
/// a test can show that chunks do not count toward the cap and that the
/// walk remembers at most `chunk_memory` checked chunks.
pub(crate) fn check_closure_present_with_cap<'a, I>(
    store: &ObjectStore,
    roots: I,
    cap: usize,
    chunk_memory: usize,
) -> Result<bool, StoreError>
where
    I: IntoIterator<Item = &'a Hash>,
{
    walk_closure(
        store,
        roots,
        ClosureMode::History,
        cap,
        Chunks::Check {
            memory: chunk_memory,
        },
    )
    .map(|(_out, truncated)| truncated)
}

/// What a closure walk does with the chunks of a chunked blob.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Chunks {
    /// Retain each chunk id in the returned set.
    Retain,
    /// Check each chunk's type without queueing it, and remember at most
    /// `memory` checked chunk ids.
    Check { memory: usize },
}

fn reachable_with_mode<'a, I>(
    store: &ObjectStore,
    roots: I,
    mode: ClosureMode,
    cap: usize,
) -> Result<(BTreeSet<Hash>, bool), StoreError>
where
    I: IntoIterator<Item = &'a Hash>,
{
    walk_closure(store, roots, mode, cap, Chunks::Retain)
}

fn walk_closure<'a, I>(
    store: &ObjectStore,
    roots: I,
    mode: ClosureMode,
    cap: usize,
    chunks: Chunks,
) -> Result<(BTreeSet<Hash>, bool), StoreError>
where
    I: IntoIterator<Item = &'a Hash>,
{
    let mut out: BTreeSet<Hash> = BTreeSet::new();
    let mut queue: VecDeque<Hash> = VecDeque::new();
    for root in roots {
        queue.push_back(*root);
    }

    let mut checked_chunks: BTreeSet<Hash> = BTreeSet::new();
    let mut truncated = false;
    while let Some(h) = queue.pop_front() {
        if out.len() >= cap {
            // Still had work to do but hit the cap — the closure is
            // incomplete.
            truncated = true;
            break;
        }
        if !out.insert(h) {
            continue;
        }
        // Classify the node via the cheap 6-byte prologue check
        // (`object_type`) instead of a full read+verify+decode
        // (`read_object`) — INV-14. Missing objects bubble up here
        // exactly as `read_object` would: a reachable-set walk for a
        // push must refuse to build a known-broken pack.
        let ty = store.object_type(&h)?;
        if matches!(ty, ObjectType::Blob | ObjectType::Delta) {
            // Leaves — nothing to walk, so there is nothing more to learn
            // about this node than its type. Skip the full read entirely:
            // its content (and therefore its BLAKE3 integrity) is never
            // consulted by reachability. Whoever actually reads this
            // object's bytes later (pack build, checkout, ...) still gets
            // the full verified read via `store.read`/`read_object`.
            continue;
        }

        // Every other kind needs its decoded body to find its children,
        // so this still pays for a full read+verify+decode.
        // [`children`] is the single source of truth for the edges;
        // History mode preserves the pre-existing walk exactly.
        let obj = store.read_object(&h)?;
        let chunk_memory = match (chunks, &obj) {
            (Chunks::Check { memory }, Object::ChunkedBlob(_)) => Some(memory),
            _ => None,
        };
        let edges = children(&obj, mode);
        drop(obj);
        for child in edges {
            // A leaf chunk needs only its type, so it is checked here and
            // never queued. Any other type takes the ordinary path.
            if let Some(memory) = chunk_memory {
                if checked_chunks.contains(&child) {
                    continue;
                }
                #[cfg(test)]
                CHUNK_TYPE_READS.with(|reads| reads.set(reads.get() + 1));
                if matches!(
                    store.object_type(&child)?,
                    ObjectType::Blob | ObjectType::Delta
                ) {
                    if checked_chunks.len() < memory {
                        checked_chunks.insert(child);
                    }
                    continue;
                }
            }
            queue.push_back(child);
        }
    }
    Ok((out, truncated))
}

#[cfg(test)]
std::thread_local! {
    // Chunk type reads in the presence check. Thread-local state keeps
    // concurrently running unit tests independent.
    static CHUNK_TYPE_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
#[allow(clippy::many_single_char_names)] // single-letter commit names keep the test tables compact
mod tests {
    use super::*;
    use crate::hash;
    use crate::object::EntryMode;
    use crate::object::{Blob, Commit, Identity, Object, Tree, TreeEntry};
    use crate::serialize;
    use tempfile::TempDir;

    fn store() -> (TempDir, ObjectStore) {
        let d = TempDir::new().unwrap();
        let s = ObjectStore::init(&crate::layout::RepoLayout::single(d.path())).unwrap();
        (d, s)
    }

    fn put_blob(s: &ObjectStore, data: &[u8]) -> Hash {
        let bytes = serialize::serialize(&Object::Blob(Blob {
            data: data.to_vec(),
        }))
        .unwrap();
        s.write(&bytes).unwrap()
    }

    fn put_tree(s: &ObjectStore, entries: Vec<TreeEntry>) -> Hash {
        let bytes = serialize::serialize(&Object::Tree(Tree { entries })).unwrap();
        s.write(&bytes).unwrap()
    }

    fn make_single_file_tree(s: &ObjectStore, name: &[u8], data: &[u8]) -> Hash {
        let blob = put_blob(s, data);
        put_tree(
            s,
            vec![TreeEntry {
                name: name.to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob,
            }],
        )
    }

    fn make_commit(s: &ObjectStore, tree: Hash, parents: &[Hash], message: &str) -> Hash {
        let c = Commit {
            tree_hash: tree,
            parents: parents.to_vec(),
            author: Identity::ed25519([0; 32]),
            signer: [0; 32],
            message: message.as_bytes().to_vec(),
            timestamp: message.len() as u64, // tiny per-commit divergence avoids store dedup
            message_hash: [0; 32],
            content_digest: [0; 32],
            signature: [0; 64],
        };
        let bytes = serialize::serialize(&Object::Commit(c)).unwrap();
        s.write(&bytes).unwrap()
    }

    #[test]
    fn an_ancestor_walk_over_its_cap_fails_and_never_returns_a_prefix() {
        let (_d, s) = store();
        let tree = make_single_file_tree(&s, b"f", b"data");
        let c1 = make_commit(&s, tree, &[], "c1");
        let c2 = make_commit(&s, tree, &[c1], "c2--");
        let c3 = make_commit(&s, tree, &[c2], "c3----");
        let mut set = HashSet::new();
        let err = collect_ancestor_set_with_cap(&s, c3, &mut set, 2, ANCESTOR_LIMIT).unwrap_err();
        assert!(matches!(
            err,
            StoreError::OperationLimitExceeded(ANCESTOR_LIMIT)
        ));
        let mut set = HashSet::new();
        collect_ancestor_set_with_cap(&s, c3, &mut set, 3, ANCESTOR_LIMIT).unwrap();
        assert_eq!(set.len(), 3);
        // The error names the cap.
        assert!(ANCESTOR_LIMIT.starts_with("10,000-"));
        assert_eq!(MAX_ANCESTORS, 10_000);
    }

    #[test]
    fn linear_chain_3_commits() {
        let (_d, s) = store();
        let tree = make_single_file_tree(&s, b"f", b"data");
        let c1 = make_commit(&s, tree, &[], "c1");
        let c2 = make_commit(&s, tree, &[c1], "c2");
        let c3 = make_commit(&s, tree, &[c2], "c3");

        let mut set = HashSet::new();
        collect_ancestor_set(&s, c3, &mut set).unwrap();
        assert_eq!(set.len(), 3);
        assert!(set.contains(&c1));
        assert!(set.contains(&c2));
        assert!(set.contains(&c3));
    }

    #[test]
    fn diamond_dag() {
        let (_d, s) = store();
        let tree = make_single_file_tree(&s, b"f.txt", b"data");
        let c1 = make_commit(&s, tree, &[], "c1");
        let c2 = make_commit(&s, tree, &[c1], "c2");
        let c3 = make_commit(&s, tree, &[c1], "c3");
        let c4 = make_commit(&s, tree, &[c2, c3], "c4");

        let mut set = HashSet::new();
        collect_ancestor_set(&s, c4, &mut set).unwrap();
        assert_eq!(set.len(), 4);
        assert!(set.contains(&c1));
        assert!(set.contains(&c2));
        assert!(set.contains(&c3));
        assert!(set.contains(&c4));
    }

    #[test]
    fn root_commit_alone() {
        let (_d, s) = store();
        let tree = make_single_file_tree(&s, b"f.txt", b"data");
        let c1 = make_commit(&s, tree, &[], "root");

        let mut set = HashSet::new();
        collect_ancestor_set(&s, c1, &mut set).unwrap();
        assert_eq!(set.len(), 1);
        assert!(set.contains(&c1));
    }

    #[test]
    fn handles_non_existent_parent_gracefully() {
        let (_d, s) = store();
        let tree = make_single_file_tree(&s, b"f.txt", b"data");
        let fake_parent = hash::hash(b"nonexistent-parent");
        let c1 = make_commit(&s, tree, &[fake_parent], "orphan");

        let mut set = HashSet::new();
        collect_ancestor_set(&s, c1, &mut set).unwrap();
        // Both c1 and the fake hash end up in the set; the fake hash
        // doesn't continue the walk because the object lookup fails.
        assert_eq!(set.len(), 2);
        assert!(set.contains(&c1));
        assert!(set.contains(&fake_parent));
    }

    #[test]
    fn empty_store_records_starting_hash() {
        let (_d, s) = store();
        let fake = hash::hash(b"does-not-exist");
        let mut set = HashSet::new();
        collect_ancestor_set(&s, fake, &mut set).unwrap();
        assert_eq!(set.len(), 1);
        assert!(set.contains(&fake));
    }

    // =================================================================
    // reachable_objects — full closure from a commit.
    // =================================================================

    #[test]
    fn reachable_single_commit_includes_tree_and_blob() {
        let (_d, s) = store();
        let blob = put_blob(&s, b"hi");
        let tree = put_tree(
            &s,
            vec![TreeEntry {
                name: b"f".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob,
            }],
        );
        let c1 = make_commit(&s, tree, &[], "c1");
        let reach = reachable_objects(&s, &c1).unwrap();
        assert!(reach.contains(&c1));
        assert!(reach.contains(&tree));
        assert!(reach.contains(&blob));
        assert_eq!(reach.len(), 3);
    }

    #[test]
    fn reachable_walks_parents_and_dedups() {
        let (_d, s) = store();
        let t = make_single_file_tree(&s, b"f", b"x");
        let c1 = make_commit(&s, t, &[], "c1");
        let c2 = make_commit(&s, t, &[c1], "c2");
        let reach = reachable_objects(&s, &c2).unwrap();
        // c1, c2, one shared tree, one shared blob
        assert_eq!(reach.len(), 4);
        assert!(reach.contains(&c1));
        assert!(reach.contains(&c2));
        assert!(reach.contains(&t));
    }

    #[test]
    fn reachable_walks_nested_trees() {
        let (_d, s) = store();
        let leaf = put_blob(&s, b"leaf");
        let inner = put_tree(
            &s,
            vec![TreeEntry {
                name: b"leaf".to_vec(),
                mode: EntryMode::Blob,
                object_hash: leaf,
            }],
        );
        let outer = put_tree(
            &s,
            vec![TreeEntry {
                name: b"sub".to_vec(),
                mode: EntryMode::Tree,
                object_hash: inner,
            }],
        );
        let c1 = make_commit(&s, outer, &[], "c");
        let reach = reachable_objects(&s, &c1).unwrap();
        assert!(reach.contains(&outer));
        assert!(reach.contains(&inner));
        assert!(reach.contains(&leaf));
    }

    #[test]
    fn reachable_walks_chunked_blob_chunks() {
        use crate::object::ChunkedBlob;
        let (_d, s) = store();
        let c0 = put_blob(&s, b"A");
        let c1 = put_blob(&s, b"B");
        let cb_bytes = serialize::serialize(&Object::ChunkedBlob(ChunkedBlob {
            total_size: 2,
            chunk_size: 1,
            chunks: vec![c0, c1],
        }))
        .unwrap();
        let cb = s.write(&cb_bytes).unwrap();
        let tree = put_tree(
            &s,
            vec![TreeEntry {
                name: b"big".to_vec(),
                mode: EntryMode::Blob,
                object_hash: cb,
            }],
        );
        let commit = make_commit(&s, tree, &[], "c");
        let reach = reachable_objects(&s, &commit).unwrap();
        assert!(reach.contains(&cb));
        assert!(reach.contains(&c0));
        assert!(reach.contains(&c1));
    }

    #[test]
    fn reachable_missing_root_errors() {
        let (_d, s) = store();
        let fake = hash::hash(b"nope");
        let err = reachable_objects(&s, &fake).unwrap_err();
        assert!(matches!(err, StoreError::ObjectNotFound(_)));
    }

    // =================================================================
    // object_type() short-circuit (INV-14) — the walk must
    // classify blob/delta leaves via the cheap type-prologue check
    // instead of a full read+verify+decode, without changing the
    // reachable/unreachable classification of any object (INV-3).
    // =================================================================

    /// Flip a byte well past the 6-byte type prologue (offset 0..6, which
    /// `object_type()` reads) so the object's on-disk *content* no longer
    /// matches its BLAKE3 hash, while its type tag stays intact.
    fn corrupt_payload_byte(s: &ObjectStore, h: &Hash) {
        use std::fs::OpenOptions;
        use std::io::{Read, Seek, SeekFrom, Write};
        let path = s.path_for(h);
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        f.seek(SeekFrom::Start(6)).unwrap();
        let mut byte = [0u8; 1];
        f.read_exact(&mut byte).unwrap();
        f.seek(SeekFrom::Start(6)).unwrap();
        f.write_all(&[byte[0] ^ 0xFF]).unwrap();
        f.sync_all().unwrap();
    }

    #[test]
    fn reachable_closure_matches_expected_set_for_mixed_graph() {
        // Correctness proxy for "byte-identical to the old full-read path":
        // a hand-computed expected set over a graph that exercises every
        // node kind the walk handles (commit chain, tree, nested tree,
        // chunked-blob manifest, plain blobs).
        let (_d, s) = store();
        let leaf1 = put_blob(&s, b"leaf-one");
        let inner = put_tree(
            &s,
            vec![TreeEntry {
                name: b"leaf".to_vec(),
                mode: EntryMode::Blob,
                object_hash: leaf1,
            }],
        );
        let chunk_a = put_blob(&s, b"chunk-a");
        let chunk_b = put_blob(&s, b"chunk-b");
        let cb_bytes = serialize::serialize(&Object::ChunkedBlob(crate::object::ChunkedBlob {
            total_size: 14,
            chunk_size: 7,
            chunks: vec![chunk_a, chunk_b],
        }))
        .unwrap();
        let cb = s.write(&cb_bytes).unwrap();
        let outer = put_tree(
            &s,
            vec![
                TreeEntry {
                    name: b"big".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: cb,
                },
                TreeEntry {
                    name: b"sub".to_vec(),
                    mode: EntryMode::Tree,
                    object_hash: inner,
                },
            ],
        );
        let c1 = make_commit(&s, outer, &[], "c1");
        let c2 = make_commit(&s, outer, &[c1], "c2");

        let reach = reachable_objects(&s, &c2).unwrap();
        let expected: BTreeSet<Hash> = [c1, c2, outer, inner, leaf1, cb, chunk_a, chunk_b]
            .into_iter()
            .collect();
        assert_eq!(reach, expected);
    }

    /// A commit whose tree holds one chunked blob of `count` chunks.
    fn chunked_history(s: &ObjectStore, count: usize) -> (Hash, Vec<Hash>) {
        let chunks: Vec<Hash> = (0..count)
            .map(|i| put_blob(s, format!("chunk-{i}").as_bytes()))
            .collect();
        let total_size = (0..count).map(|i| format!("chunk-{i}").len() as u64).sum();
        let manifest = serialize::serialize(&Object::ChunkedBlob(crate::object::ChunkedBlob {
            total_size,
            chunk_size: 0,
            chunks: chunks.clone(),
        }))
        .unwrap();
        let manifest = s.write(&manifest).unwrap();
        let tree = put_tree(
            s,
            vec![TreeEntry {
                name: b"big".to_vec(),
                mode: EntryMode::Blob,
                object_hash: manifest,
            }],
        );
        (make_commit(s, tree, &[], "c1"), chunks)
    }

    #[test]
    fn presence_check_does_not_count_chunks_toward_the_cap() {
        let (_d, s) = store();
        let (c1, _chunks) = chunked_history(&s, 2_000);
        // The commit, its tree and the manifest are the only retained ids.
        assert!(!check_closure_present_with_cap(&s, [&c1], 3, MAX_CHECKED_CHUNKS).unwrap());
        let (_, truncated) = reachable_closure_checked_with_cap(&s, [&c1], 3).unwrap();
        assert!(truncated, "the full walk retains every chunk");
        assert!(check_closure_present_with_cap(&s, [&c1], 2, MAX_CHECKED_CHUNKS).unwrap());
    }

    /// Two versions of an 8-chunk file. The second replaces chunk 0 and
    /// shares chunks 1 to 7. Returns the second commit and the first
    /// version's chunks.
    fn two_versions(s: &ObjectStore) -> (Hash, Vec<Hash>) {
        let (c1, chunks) = chunked_history(s, 8);
        let mut changed = chunks.clone();
        changed[0] = put_blob(s, b"changed-0");
        let manifest = serialize::serialize(&Object::ChunkedBlob(crate::object::ChunkedBlob {
            total_size: 1024,
            chunk_size: 0,
            chunks: changed,
        }))
        .unwrap();
        let manifest = s.write(&manifest).unwrap();
        let tree = put_tree(
            s,
            vec![TreeEntry {
                name: b"big".to_vec(),
                mode: EntryMode::Blob,
                object_hash: manifest,
            }],
        );
        (make_commit(s, tree, &[c1], "c2"), chunks)
    }

    fn chunk_reads(s: &ObjectStore, root: &Hash, memory: usize) -> usize {
        CHUNK_TYPE_READS.with(|reads| reads.set(0));
        assert!(!check_closure_present_with_cap(s, [root], MAX_REACHABLE, memory).unwrap());
        CHUNK_TYPE_READS.with(std::cell::Cell::get)
    }

    #[test]
    fn presence_check_reads_a_remembered_chunk_once() {
        let (_d, s) = store();
        let (c2, _chunks) = two_versions(&s);
        // The second version's 8 chunks, then chunk 0 of the first.
        assert_eq!(chunk_reads(&s, &c2, MAX_CHECKED_CHUNKS), 9);
        // Three remembered: the first version reads chunk 0 and chunks 3 to 7.
        assert_eq!(chunk_reads(&s, &c2, 3), 14);
        // None remembered: every chunk of both versions.
        assert_eq!(chunk_reads(&s, &c2, 0), 16);
    }

    #[test]
    fn presence_check_reports_a_missing_chunk_two_manifests_share() {
        let (_d, s) = store();
        let (c2, chunks) = two_versions(&s);
        assert!(!check_closure_present(&s, [&c2]).unwrap());
        std::fs::remove_file(s.path_for(&chunks[3])).unwrap();
        assert!(matches!(
            check_closure_present(&s, [&c2]),
            Err(StoreError::ObjectNotFound(_))
        ));
    }

    #[test]
    fn a_cut_closure_walk_fails_closed() {
        let (_d, s) = store();
        let (c1, _chunks) = chunked_history(&s, 4);
        let walk = reachable_closure_checked_with_cap(&s, [&c1], 3);
        assert!(matches!(
            complete(walk),
            Err(StoreError::OperationLimitExceeded(REACHABLE_LIMIT))
        ));
        let whole = complete(reachable_closure_checked_with_cap(&s, [&c1], 7)).unwrap();
        assert_eq!(whole, reachable_objects(&s, &c1).unwrap());
        assert_eq!(whole.len(), 7);
    }

    #[test]
    fn presence_check_reports_a_missing_chunk() {
        let (_d, s) = store();
        let (c1, chunks) = chunked_history(&s, 8);
        std::fs::remove_file(s.path_for(&chunks[5])).unwrap();
        let hex = hash::to_hex(&chunks[5]);
        assert!(matches!(
            check_closure_present(&s, [&c1]),
            Err(StoreError::ObjectNotFound(ref missing)) if *missing == hex
        ));
    }

    #[test]
    fn reachable_closure_short_circuits_corrupted_blob_leaf() {
        let (_d, s) = store();
        let blob = put_blob(&s, &vec![0xABu8; 4096]);
        let tree = put_tree(
            &s,
            vec![TreeEntry {
                name: b"f".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob,
            }],
        );
        let c1 = make_commit(&s, tree, &[], "c1");

        corrupt_payload_byte(&s, &blob);

        // Sanity: a full read+verify of this object now fails — proves the
        // corruption is real and would have broken the old `read_object`
        // path had it still been called for this leaf.
        assert!(matches!(
            s.read_object(&blob),
            Err(StoreError::HashMismatch { .. })
        ));

        // The walk must still succeed, and the blob must still be
        // classified reachable: reachability only needs to know this node
        // has no children, and the intact type prologue already answers
        // that. Content integrity is a concern for whoever reads the bytes
        // later, not for this classification.
        let (reach, truncated) = reachable_closure_checked(&s, [c1].iter()).unwrap();
        assert!(!truncated);
        assert!(reach.contains(&c1));
        assert!(reach.contains(&tree));
        assert!(reach.contains(&blob));
        assert_eq!(reach.len(), 3);
    }

    #[test]
    fn reachable_closure_still_fails_closed_on_corrupted_tree() {
        // A non-leaf node (tree) still needs its decoded body to find its
        // children, so corruption there must still surface as an error —
        // proving the short-circuit is targeted at true leaves (blob/
        // delta) only, not a blanket weakening of verification.
        let (_d, s) = store();
        let blob = put_blob(&s, b"hi");
        let tree = put_tree(
            &s,
            vec![TreeEntry {
                name: b"f".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob,
            }],
        );
        let c1 = make_commit(&s, tree, &[], "c1");

        corrupt_payload_byte(&s, &tree);

        let err = reachable_closure_checked(&s, [c1].iter()).unwrap_err();
        assert!(matches!(err, StoreError::HashMismatch { .. }));
    }

    #[test]
    fn children_snapshot_omits_parents_history_includes_them() {
        let t = [1u8; 32];
        let p = [2u8; 32];
        let commit = Object::Commit(Commit {
            tree_hash: t,
            parents: vec![p],
            author: Identity::ed25519([0; 32]),
            signer: [0; 32],
            message: b"m".to_vec(),
            timestamp: 1,
            message_hash: [0; 32],
            content_digest: [0; 32],
            signature: [0; 64],
        });
        assert_eq!(children(&commit, ClosureMode::Snapshot), vec![t]);
        assert_eq!(children(&commit, ClosureMode::History), vec![t, p]);
        let blob = Object::Blob(Blob {
            data: b"x".to_vec(),
        });
        assert!(children(&blob, ClosureMode::History).is_empty());
        assert!(children(&blob, ClosureMode::Snapshot).is_empty());
    }

    #[test]
    fn remix_children_follow_parents_only_in_history() {
        use crate::object::Remix;
        let t = [1u8; 32];
        let p = [2u8; 32];
        let remix = Object::Remix(Remix {
            tree_hash: t,
            parents: vec![p],
            sources: vec![],
            author: Identity::ed25519([0; 32]),
            signer: [0; 32],
            message: b"m".to_vec(),
            timestamp: 1,
            signature: [0; 64],
        });
        assert_eq!(children(&remix, ClosureMode::Snapshot), vec![t]);
        assert_eq!(children(&remix, ClosureMode::History), vec![t, p]);
    }

    #[test]
    fn reachable_snapshot_excludes_parent_commit() {
        let (_d, s) = store();
        let t1 = make_single_file_tree(&s, b"old", b"parent-only");
        let c1 = make_commit(&s, t1, &[], "c1");
        let t2 = make_single_file_tree(&s, b"new", b"child-only");
        let c2 = make_commit(&s, t2, &[c1], "c2");

        let history = reachable_objects(&s, &c2).unwrap();
        let snapshot = reachable_snapshot(&s, &c2).unwrap();

        assert!(history.contains(&c1));
        assert!(history.contains(&t1));
        assert!(!snapshot.contains(&c1), "snapshot must not walk parents");
        assert!(!snapshot.contains(&t1), "parent tree is history-only");
        assert!(snapshot.contains(&c2));
        assert!(snapshot.contains(&t2));
        assert!(history.is_superset(&snapshot));
    }
}

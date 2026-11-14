//! The walk a push plans from.
//!
//! A push needs the objects the remote lacks. The remote holds the history
//! closure of its head, so the walk decides what it holds from the head alone:
//! no negotiation, and no walk of two whole closures.
//!
//! * [`HeldCommits`] is the exact set of commits that are ancestors of the
//!   remote head.
//! * [`PushWalk`] walks the commits the remote lacks, oldest first. For each
//!   one it compares the tree with the trees of the commit's parents, by path,
//!   and keeps the entries that differ from every parent. A chunk of a large
//!   file is never kept in the set that the walk counts: a file lists its
//!   chunks in its manifest, and [`PushWalk::for_each_chunk`] streams them.
//!
//! Why nothing the remote lacks is left out: take an object `x` that the new
//! tip reaches and the remote head does not. It sits in the tree of a commit
//! `C` that is not held, so `C` is a new commit. By induction over the new
//! commits and over the depth of the path, each entry on the path to `x` is
//! either equal to the parent's entry at that path, and that parent covers it,
//! or the walk keeps it. A parent that is held covers its whole closure, and a
//! parent that is new is walked itself. The held filter removes only ids found
//! in the remote head's own snapshot, and a chunk is skipped only when the
//! manifest at the same path in a parent lists it or the plan already sends it.

use std::collections::{BTreeSet, HashSet};

use super::{PUSH_WALK_LIMIT, WalkLimits};
use crate::hash::{Hash, to_hex};
use crate::object::{ChunkedBlob, EntryMode, Object, ObjectType, Tree, TreeEntry};
use crate::ops::graph::{ClosureMode, children};
use crate::store::{ObjectStore, StoreError};

/// Most trees the held filter reads from the remote head's snapshot. Past
/// it the filter stops, which only makes the plan send more.
pub const MAX_HELD_SCAN: usize = 2_097_152;

/// Most chunk ids the plan remembers as already sent. Past it a chunk that
/// several files share may be listed twice, and a pack reader accepts that.
pub const MAX_CHUNK_MEMORY: usize = 2_097_152;

fn limit_error() -> StoreError {
    StoreError::OperationLimitExceeded(PUSH_WALK_LIMIT)
}

#[cfg(test)]
std::thread_local! {
    // Every id that entered a counted set, in order. Thread-local state keeps
    // concurrently running unit tests independent.
    static COUNTED: std::cell::RefCell<Vec<Hash>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// The commits that are ancestors of the remote head, the head included.
///
/// The set counts toward the push walk's cap. A commit this store cannot read
/// ends its path and prunes nothing: the walk only loses the ancestors behind
/// it, and the plan then sends more.
#[derive(Debug, Default)]
pub struct HeldCommits {
    ids: HashSet<Hash>,
    tip: Option<Hash>,
}

impl HeldCommits {
    /// The ancestors of `tip`, or nothing when there is no remote head or this
    /// store lacks it.
    ///
    /// # Errors
    ///
    /// [`StoreError::OperationLimitExceeded`] when the set passes `cap`.
    pub fn collect(store: &ObjectStore, tip: Option<Hash>, cap: usize) -> Result<Self, StoreError> {
        let Some(tip) = tip.filter(|tip| store.contains(tip)) else {
            return Ok(Self::default());
        };
        let mut ids = HashSet::from([tip]);
        if ids.len() > cap {
            return Err(limit_error());
        }
        let mut stack = vec![tip];
        while let Some(id) = stack.pop() {
            let parents = match store.read_object(&id) {
                Ok(Object::Commit(commit)) => commit.parents,
                Ok(Object::Remix(remix)) => remix.parents,
                // A commit that cannot be read, or an object of another kind,
                // ends the path. It is never an error.
                Ok(_) | Err(_) => continue,
            };
            for parent in parents {
                if ids.insert(parent) {
                    if ids.len() > cap {
                        return Err(limit_error());
                    }
                    stack.push(parent);
                }
            }
        }
        Ok(Self {
            ids,
            tip: Some(tip),
        })
    }

    /// The remote head, when this store holds it.
    #[must_use]
    pub fn tip(&self) -> Option<Hash> {
        self.tip
    }

    /// Whether the remote holds `id` as an ancestor of its head.
    #[must_use]
    pub fn contains(&self, id: &Hash) -> bool {
        self.ids.contains(id)
    }

    /// The number of held commits.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ids.len()
    }

    /// `true` when nothing is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }
}

/// A chunked file the walk keeps: its manifest, the commit that brought it,
/// and the manifest it replaces at the same path in a parent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkList {
    /// The commit whose tree brought the manifest.
    pub commit: Hash,
    /// The manifest's id.
    pub id: Hash,
    /// The manifest at the same path in a parent, whose chunks the remote
    /// holds or the plan sends.
    pub old: Option<Hash>,
}

/// The chunk ids a plan has listed, up to a bound.
#[derive(Debug)]
pub struct ChunkMemory {
    seen: HashSet<Hash>,
    limit: usize,
}

impl ChunkMemory {
    /// An empty memory that keeps at most `limit` ids.
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            seen: HashSet::new(),
            limit,
        }
    }

    /// `true` the first time a chunk is seen. Past the bound a chunk is
    /// reported as new again.
    fn first_sight(&mut self, chunk: &Hash) -> bool {
        if self.seen.contains(chunk) {
            return false;
        }
        if self.seen.len() < self.limit {
            self.seen.insert(*chunk);
        }
        true
    }
}

/// What a push has to send, found from the remote head alone.
#[derive(Debug)]
pub struct PushWalk {
    objects: BTreeSet<Hash>,
    manifests: Vec<ChunkList>,
}

/// A new commit, read once.
struct NewCommit {
    id: Hash,
    tree: Hash,
    parents: Vec<Hash>,
}

/// Called for each object the walk keeps: the commit that brought it, and the
/// object.
pub type ObjectSink<'a> = &'a mut dyn FnMut(&Hash, &Hash) -> Result<(), StoreError>;

impl PushWalk {
    /// Walk the commits that `tip` reaches and `held` lacks.
    ///
    /// `shallow` names commits whose parents this store does not hold. The
    /// walk takes them as roots. `sink`, when given, sees each object the walk
    /// keeps, once the held filter has run, with the commit that brought it.
    ///
    /// A tip that is neither a commit nor a remix gets its full closure,
    /// minus held commits.
    ///
    /// # Errors
    ///
    /// [`StoreError::ObjectNotFound`] for a new commit or one of its objects
    /// that this store lacks, and [`StoreError::OperationLimitExceeded`] when
    /// held commits, new commits and kept objects together pass the cap. A
    /// chunk counts toward nothing.
    pub fn run(
        store: &ObjectStore,
        tip: Hash,
        held: &HeldCommits,
        shallow: &HashSet<Hash>,
        limits: WalkLimits,
        sink: Option<ObjectSink<'_>>,
    ) -> Result<Self, StoreError> {
        let (commits, others) = discover(store, tip, held, shallow, limits)?;
        let mut walk = Builder {
            store,
            held,
            limits,
            objects: BTreeSet::new(),
            manifests: Vec::new(),
            non_commit: 0,
            roots: commits
                .iter()
                .map(|commit| commit.id)
                .chain(others.iter().copied())
                .collect(),
            log: sink.is_some().then(Vec::new),
        };
        for (owner, commit) in commits.iter().enumerate() {
            walk.add_commit(owner, commit)?;
        }
        for (offset, root) in others.into_iter().enumerate() {
            walk.add_closure(commits.len() + offset, root)?;
        }
        walk.filter_held();
        if let (Some(sink), Some(log)) = (sink, walk.log.take()) {
            for (owner, id) in log {
                if walk.objects.contains(&id) {
                    sink(&walk.roots[owner], &id)?;
                }
            }
        }
        Ok(Self {
            objects: walk.objects,
            manifests: walk.manifests,
        })
    }

    /// What `id` brings on its own: its tree entries that no parent of it has
    /// at the same name, or the closure of `id` when it is not a commit.
    ///
    /// Nothing another new commit brings is left out, and the remote head's
    /// snapshot is not consulted, so the result is never less than what a plan
    /// that starts at any ancestor of `id` sends for it. A split push sizes
    /// its steps with it.
    ///
    /// # Errors
    ///
    /// As [`PushWalk::run`].
    pub fn run_one(
        store: &ObjectStore,
        id: Hash,
        held: &HeldCommits,
        shallow: &HashSet<Hash>,
        limits: WalkLimits,
    ) -> Result<Self, StoreError> {
        let mut walk = Builder {
            store,
            held,
            limits,
            objects: BTreeSet::new(),
            manifests: Vec::new(),
            non_commit: 0,
            roots: vec![id],
            log: None,
        };
        match read_commit(store, &id)? {
            Some((tree, mut parents)) => {
                if shallow.contains(&id) {
                    parents.clear();
                }
                walk.add_commit(0, &NewCommit { id, tree, parents })?;
            }
            None => walk.add_closure(0, id)?,
        }
        Ok(Self {
            objects: walk.objects,
            manifests: walk.manifests,
        })
    }

    /// The kept objects: new commits, trees, small blobs, manifests and the
    /// rest. Never a chunk of a manifest.
    #[must_use]
    pub fn objects(&self) -> &BTreeSet<Hash> {
        &self.objects
    }

    /// The kept manifests, oldest commit first.
    #[cfg(test)]
    pub(crate) fn manifests(&self) -> &[ChunkList] {
        &self.manifests
    }

    /// Stream the chunks the plan has to send, manifest by manifest.
    ///
    /// A chunk is skipped when the manifest it replaces lists it, when the
    /// walk keeps it as an object, or when `memory` has seen it. The callback
    /// gets the commit that brought the manifest, the manifest, the index of
    /// the chunk in it and the chunk.
    ///
    /// # Errors
    ///
    /// Any [`StoreError`] from reading a manifest, except a missing replaced
    /// manifest, which only means no chunk is skipped for it, and the callback's
    /// own error.
    pub fn for_each_chunk(
        &self,
        store: &ObjectStore,
        memory: &mut ChunkMemory,
        mut f: impl FnMut(&Hash, &ChunkedBlob, u32, Hash) -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        for manifest in &self.manifests {
            let Object::ChunkedBlob(blob) = store.read_object(&manifest.id)? else {
                continue;
            };
            let replaced: HashSet<Hash> = match manifest.old.map(|old| store.read_object(&old)) {
                Some(Ok(Object::ChunkedBlob(old))) => old.into_chunks().into_iter().collect(),
                Some(Ok(_) | Err(StoreError::ObjectNotFound(_))) | None => HashSet::new(),
                Some(Err(error)) => return Err(error),
            };
            for (index, chunk) in (0u32..).zip(blob.chunks().iter().copied()) {
                if replaced.contains(&chunk)
                    || self.objects.contains(&chunk)
                    || !memory.first_sight(&chunk)
                {
                    continue;
                }
                f(&manifest.commit, &blob, index, chunk)?;
            }
        }
        Ok(())
    }
}

fn read_commit(store: &ObjectStore, id: &Hash) -> Result<Option<(Hash, Vec<Hash>)>, StoreError> {
    Ok(match store.read_object(id)? {
        Object::Commit(commit) => Some((commit.tree_hash, commit.parents)),
        Object::Remix(remix) => Some((remix.tree_hash, remix.parents)),
        _ => None,
    })
}

/// The new commits, parents first, and the roots that are not commits.
fn discover(
    store: &ObjectStore,
    tip: Hash,
    held: &HeldCommits,
    shallow: &HashSet<Hash>,
    limits: WalkLimits,
) -> Result<(Vec<NewCommit>, Vec<Hash>), StoreError> {
    let mut seen: HashSet<Hash> = HashSet::new();
    let mut order: Vec<NewCommit> = Vec::new();
    let mut others: Vec<Hash> = Vec::new();
    let mut frames: Vec<(NewCommit, usize)> = Vec::new();
    let mut next = Some(tip);
    loop {
        if let Some(id) = next.take()
            && !held.contains(&id)
            && seen.insert(id)
        {
            if held.len() + seen.len() > limits.objects {
                return Err(limit_error());
            }
            match read_commit(store, &id)? {
                Some((tree, mut parents)) => {
                    if shallow.contains(&id) {
                        parents.clear();
                    }
                    frames.push((NewCommit { id, tree, parents }, 0));
                }
                None => others.push(id),
            }
        }
        let Some((commit, cursor)) = frames.last_mut() else {
            break;
        };
        if let Some(parent) = commit.parents.get(*cursor) {
            next = Some(*parent);
            *cursor += 1;
        } else if let Some((done, _)) = frames.pop() {
            order.push(done);
        }
    }
    Ok((order, others))
}

/// The entry named `name`, if the tree has one. Entries are sorted by name.
fn entry<'a>(tree: &'a Tree, name: &[u8]) -> Option<&'a TreeEntry> {
    tree.entries
        .binary_search_by(|candidate| candidate.name.as_slice().cmp(name))
        .ok()
        .map(|index| &tree.entries[index])
}

struct Builder<'a> {
    store: &'a ObjectStore,
    held: &'a HeldCommits,
    limits: WalkLimits,
    objects: BTreeSet<Hash>,
    manifests: Vec<ChunkList>,
    /// Kept objects that are not commits.
    non_commit: usize,
    /// The new commits, then the other roots. An object is brought by one.
    roots: Vec<Hash>,
    /// Each kept object with the index in `roots` of the root that brought it,
    /// when a caller wants them.
    log: Option<Vec<(usize, Hash)>>,
}

impl Builder<'_> {
    /// Keep `id`, brought by root `owner`. `false` when the walk kept it before.
    fn keep(&mut self, owner: usize, id: Hash, is_commit: bool) -> Result<bool, StoreError> {
        if !self.objects.insert(id) {
            return Ok(false);
        }
        #[cfg(test)]
        COUNTED.with(|counted| counted.borrow_mut().push(id));
        if self.held.len() + self.objects.len() > self.limits.objects {
            return Err(limit_error());
        }
        if !is_commit {
            self.non_commit += 1;
        }
        if let Some(log) = &mut self.log {
            log.push((owner, id));
        }
        Ok(true)
    }

    /// The tree of a parent commit, when this store can read it.
    fn parent_tree(&self, parent: &Hash) -> Option<Hash> {
        match self.store.read_object(parent) {
            Ok(Object::Commit(commit)) => Some(commit.tree_hash),
            Ok(Object::Remix(remix)) => Some(remix.tree_hash),
            Ok(_) | Err(_) => None,
        }
    }

    /// Keep the commit and the entries of its tree that no parent has.
    fn add_commit(&mut self, owner: usize, commit: &NewCommit) -> Result<(), StoreError> {
        self.keep(owner, commit.id, true)?;
        let parents: Vec<Hash> = commit
            .parents
            .iter()
            .filter_map(|parent| self.parent_tree(parent))
            .collect();
        if parents.contains(&commit.tree) {
            return Ok(());
        }
        if self.store.object_type(&commit.tree)? != ObjectType::Tree {
            return self.add_closure(owner, commit.tree);
        }
        if !self.keep(owner, commit.tree, false)? {
            return Ok(());
        }
        let mut stack = vec![(commit.tree, parents)];
        while let Some((tree, parents)) = stack.pop() {
            self.add_tree(owner, tree, &parents, &mut stack)?;
        }
        Ok(())
    }

    /// Keep the entries of `tree` that no tree in `parents` has at the same
    /// name, and queue the subtrees to descend into.
    fn add_tree(
        &mut self,
        owner: usize,
        tree: Hash,
        parents: &[Hash],
        stack: &mut Vec<(Hash, Vec<Hash>)>,
    ) -> Result<(), StoreError> {
        let Object::Tree(tree) = self.store.read_object(&tree)? else {
            return Err(StoreError::ObjectNotFound(to_hex(&tree)));
        };
        // A parent tree this store cannot read prunes nothing.
        let parents: Vec<Tree> = parents
            .iter()
            .filter_map(|parent| match self.store.read_object(parent) {
                Ok(Object::Tree(tree)) => Some(tree),
                Ok(_) | Err(_) => None,
            })
            .collect();
        for new in &tree.entries {
            let beside: Vec<&TreeEntry> = parents
                .iter()
                .filter_map(|parent| entry(parent, &new.name))
                .collect();
            if beside
                .iter()
                .any(|parent| parent.object_hash == new.object_hash)
            {
                continue;
            }
            match self.store.object_type(&new.object_hash)? {
                ObjectType::Tree => {
                    if self.keep(owner, new.object_hash, false)? {
                        let subtrees = beside
                            .iter()
                            .filter(|parent| parent.mode == EntryMode::Tree)
                            .map(|parent| parent.object_hash)
                            .collect();
                        stack.push((new.object_hash, subtrees));
                    }
                }
                ObjectType::Blob | ObjectType::Delta => {
                    self.keep(owner, new.object_hash, false)?;
                }
                ObjectType::ChunkedBlob => {
                    if self.keep(owner, new.object_hash, false)? {
                        let old = beside.iter().map(|parent| parent.object_hash).find(|old| {
                            matches!(self.store.object_type(old), Ok(ObjectType::ChunkedBlob))
                        });
                        self.manifests.push(ChunkList {
                            commit: self.roots[owner],
                            id: new.object_hash,
                            old,
                        });
                    }
                }
                ObjectType::Commit | ObjectType::Remix | ObjectType::Tag => {
                    self.add_closure(owner, new.object_hash)?;
                }
            }
        }
        Ok(())
    }

    /// Keep the whole closure of `root`, except held commits and what they
    /// hold. Serves a tip that is not a commit and the odd entry that names an
    /// object of another kind.
    fn add_closure(&mut self, owner: usize, root: Hash) -> Result<(), StoreError> {
        let mut stack = vec![root];
        while let Some(id) = stack.pop() {
            if self.held.contains(&id) {
                continue;
            }
            let ty = self.store.object_type(&id)?;
            if !self.keep(
                owner,
                id,
                matches!(ty, ObjectType::Commit | ObjectType::Remix),
            )? {
                continue;
            }
            match ty {
                ObjectType::Blob | ObjectType::Delta => {}
                ObjectType::ChunkedBlob => self.manifests.push(ChunkList {
                    commit: self.roots[owner],
                    id,
                    old: None,
                }),
                ObjectType::Tree | ObjectType::Commit | ObjectType::Remix | ObjectType::Tag => {
                    let object = self.store.read_object(&id)?;
                    stack.extend(children(&object, ClosureMode::History));
                }
            }
        }
        Ok(())
    }

    /// Drop what the remote head's own snapshot holds. A renamed file, or one
    /// that returns at another path, is not sent again. The scan stops after
    /// `held_scan` trees, which only leaves more in the plan.
    fn filter_held(&mut self) {
        let Some(remote) = self.held.tip() else {
            return;
        };
        if self.non_commit == 0 {
            return;
        }
        let root = match self.store.read_object(&remote) {
            Ok(Object::Commit(commit)) => commit.tree_hash,
            Ok(Object::Remix(remix)) => remix.tree_hash,
            Ok(_) | Err(_) => return,
        };
        let mut dropped: HashSet<Hash> = HashSet::new();
        let mut visited: HashSet<Hash> = HashSet::new();
        let mut stack = vec![root];
        while let Some(id) = stack.pop() {
            if visited.len() >= self.limits.held_scan {
                break;
            }
            if !visited.insert(id) {
                continue;
            }
            if self.objects.remove(&id) {
                dropped.insert(id);
            }
            let Ok(Object::Tree(tree)) = self.store.read_object(&id) else {
                continue;
            };
            for held in tree.entries {
                if self.objects.remove(&held.object_hash) {
                    dropped.insert(held.object_hash);
                }
                if held.mode == EntryMode::Tree {
                    stack.push(held.object_hash);
                }
            }
        }
        self.manifests
            .retain(|manifest| !dropped.contains(&manifest.id));
    }
}

/// Every id that entered a counted set on this thread since the last call.
#[cfg(test)]
pub(super) fn take_counted() -> Vec<Hash> {
    COUNTED.with(|counted| std::mem::take(&mut *counted.borrow_mut()))
}

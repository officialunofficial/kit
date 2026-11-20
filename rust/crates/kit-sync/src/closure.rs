//! The closure check a fetch runs before it publishes a tracking ref, down to
//! the tips whose closure an earlier check covered.
//!
//! An anchor is a tip whose closure is in the store. There are two kinds:
//!
//! - The tip of a tracking ref of the fetched remote that its record of
//!   verified tips ([`crate::anchor`]) also names, when the store holds it.
//!   Only a fetch that verified signatures writes that record, right after it
//!   published the ref, so the closure of the tip passed this check then. The
//!   ref has named the tip ever since, or the two would differ: a push, a
//!   `git import` or a fetch with the opt-out moves the ref and not the
//!   record. gc keeps all that a ref reaches, and the fetch reads the anchors
//!   only once it holds its [`kit_core::store::PruneGuard`], after which gc
//!   deletes nothing.
//! - A tip this fetch checked and published. The guard keeps its closure.
//!
//! An ancestor of an anchor is in its closure too. The check walks the commit
//! history from the tip and the anchors at once, newest first, until every
//! commit still queued is an ancestor of an anchor ([`split`]). Those
//! ancestors are not checked. Neither is an id that a tree of an anchor's
//! closure lists, found by comparing the tree of each new commit with the
//! trees of its parents, by path, down the paths that differ ([`covered`]).
//! Such an object passed the check when the anchor did: every property the
//! check tests depends on the id alone. Every other object the tip reaches is
//! checked as a full check would. A timestamp out of order, a cap reached, or
//! a new commit or tree that cannot be read only make the check read more.
//!
//! With no anchor the check is the full walk.

use std::collections::{BinaryHeap, HashMap, HashSet};

use kit_core::hash::{Hash, to_hex};
use kit_core::layout::RepoLayout;
use kit_core::object::{EntryMode, KitError, Object, Tree};
use kit_core::ops::{Known, Presence};
use kit_core::refs;
use kit_core::store::{ObjectSource, ObjectStore, StoreError};

use crate::error::SyncError;

/// The most ids [`covered`] collects. Past it, it stops.
const MAX_COVERED: usize = 1_048_576;

/// The most commits [`split`] reads. Past it, it stops.
const MAX_COMMITS: usize = 65_536;

/// The most trees [`covered`] reads.
const MAX_TREE_READS: usize = 262_144;

/// How often [`split`] and [`covered`] poll for cancellation, in objects
/// read.
const POLL_OBJECTS: usize = 4096;

/// The tips whose closure a check of this fetch may stop at.
#[derive(Debug, Default)]
pub(crate) struct Anchors(HashSet<Hash>);

impl Anchors {
    /// The tips of the tracking refs of `remote` that its record of verified
    /// tips names and the store holds. A fetch that does not verify signatures
    /// starts with none. The caller holds the store's prune guard.
    pub(crate) fn load(
        store: &ObjectStore,
        layout: &RepoLayout,
        remote: &str,
        require_signed: bool,
    ) -> Result<Self, SyncError> {
        if !require_signed {
            return Ok(Self::default());
        }
        let mut tips = HashSet::new();
        for r in refs::list_remote_refs(layout, remote)? {
            if let Some(tip) = r.hash
                && crate::anchor::names(layout, remote, &r.name, &tip)
                && store.contains(&tip)
            {
                tips.insert(tip);
            }
        }
        Ok(Self(tips))
    }

    /// Whether no earlier closure is available.
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Add a tip whose closure this fetch checked and published.
    pub(crate) fn insert(&mut self, tip: Hash) {
        self.0.insert(tip);
    }
}

/// Check that the closure of `tip` is in the store, down to `anchors`.
/// Returns how many objects it checked, chunks aside.
///
/// With no anchors this is the full walk. A missing object is
/// [`SyncError::RemoteMissingObject`], a closure past
/// [`kit_core::ops::graph::MAX_REACHABLE`] objects is
/// [`SyncError::ClosureTooLarge`], and `cancelled` turns into
/// [`SyncError::Interrupted`].
#[cfg(test)]
pub(crate) fn check_above(
    store: &ObjectStore,
    tip: &Hash,
    anchors: &Anchors,
    cancelled: &dyn Fn() -> bool,
) -> Result<usize, SyncError> {
    check_above_observed(store, tip, anchors, cancelled, &|_| {})
}

/// A closure check with completed-object counts before each next object.
pub(crate) fn check_above_observed(
    store: &(dyn ObjectSource + Sync),
    tip: &Hash,
    anchors: &Anchors,
    cancelled: &dyn Fn() -> bool,
    progress: &dyn Fn(usize),
) -> Result<usize, SyncError> {
    let mut poll = Poll {
        reads: 0,
        cancelled,
    };
    let split = split(store, tip, &anchors.0, &mut poll)?;
    let covered = covered(store, &split, &mut poll)?;
    let checked = std::cell::Cell::new(0usize);
    let known = |h: &Hash| {
        progress(checked.get());
        if anchors.0.contains(h) || split.old.contains(h) || covered.contains(h) {
            Known::Present
        } else {
            checked.set(checked.get() + 1);
            Known::Unknown
        }
    };
    let cap = kit_core::ops::graph::MAX_REACHABLE;
    match kit_core::ops::check_closure_present_above(store, tip, &known, cap, cancelled) {
        Ok(Presence::Complete(checked)) => Ok(checked.len()),
        Ok(Presence::TooLarge(_)) => Err(SyncError::ClosureTooLarge(cap)),
        Ok(Presence::Missing { object, .. }) => {
            Err(SyncError::RemoteMissingObject(to_hex(&object)))
        }
        Ok(Presence::Stopped(_)) => Err(SyncError::Interrupted),
        Err(e) => Err(closure_error(e)),
    }
}

/// The [`SyncError`] of a store error a closure check met.
pub(crate) fn closure_error(error: StoreError) -> SyncError {
    match error {
        StoreError::ObjectNotFound(hex) => SyncError::RemoteMissingObject(hex),
        StoreError::Decode(
            e @ (KitError::ChunkLengthMismatch { .. } | KitError::ChunkNotBlob { .. }),
        ) => SyncError::RemoteObject(e),
        e => e.into(),
    }
}

/// Counts reads and polls for cancellation every [`POLL_OBJECTS`] of them.
struct Poll<'a> {
    reads: usize,
    cancelled: &'a dyn Fn() -> bool,
}

impl Poll<'_> {
    fn read(&mut self) -> Result<(), SyncError> {
        self.reads += 1;
        if self.reads.is_multiple_of(POLL_OBJECTS) && (self.cancelled)() {
            return Err(SyncError::Interrupted);
        }
        Ok(())
    }
}

/// A commit or remix, as [`split`] read it.
struct Header {
    timestamp: u64,
    tree: Hash,
    parents: Vec<Hash>,
}

/// The commit history between a tip and the anchors.
#[derive(Default)]
struct Split {
    /// Commits reached from an anchor through parents: anchors and their
    /// ancestors.
    old: HashSet<Hash>,
    /// Commits reached from the tip and not from an anchor, newest first.
    new: Vec<Hash>,
    /// Every commit read.
    headers: HashMap<Hash, Header>,
}

/// Painted from the tip.
const NEW: u8 = 1;
/// Painted from an anchor.
const OLD: u8 = 2;

/// Walk the history of `tip` and of the anchors together, newest first,
/// painting each commit with the side it is reached from, until no commit
/// still queued is reached from the tip alone.
///
/// A commit is `old` only when a chain of parents leads to it from an
/// anchor, so it is in that anchor's closure, read or not. A commit that
/// cannot be read ends its chain. Timestamps only order the walk: one out of order, or
/// [`MAX_COMMITS`] reads, stop it early, and a commit then counts as new
/// although it is an ancestor of an anchor.
fn split(
    store: &(dyn ObjectSource + Sync),
    tip: &Hash,
    anchors: &HashSet<Hash>,
    poll: &mut Poll<'_>,
) -> Result<Split, SyncError> {
    let mut split = Split::default();
    if anchors.is_empty() || anchors.contains(tip) {
        return Ok(split);
    }
    let mut walk = Paint {
        store,
        flags: HashMap::new(),
        queue: BinaryHeap::new(),
        queued: HashSet::new(),
        new_only: 0,
        headers: &mut split.headers,
    };
    walk.paint(*tip, NEW, poll)?;
    for anchor in anchors {
        walk.paint(*anchor, OLD, poll)?;
    }
    while walk.new_only > 0 && walk.headers.len() < MAX_COMMITS {
        let Some((_, id)) = walk.queue.pop() else {
            break;
        };
        walk.queued.remove(&id);
        let flags = walk.flags[&id];
        if flags == NEW {
            walk.new_only -= 1;
            split.new.push(id);
        }
        let parents = walk.headers.get(&id).map(|h| h.parents.clone());
        for parent in parents.into_iter().flatten() {
            walk.paint(parent, flags, poll)?;
        }
    }
    // A commit queued when the walk stopped is new unless an anchor reaches it.
    split.new.extend(
        walk.queue
            .iter()
            .map(|(_, id)| *id)
            .filter(|id| walk.flags[id] == NEW),
    );
    split.old = walk
        .flags
        .into_iter()
        .filter(|(_, flags)| flags & OLD != 0)
        .map(|(id, _)| id)
        .collect();
    // A commit popped as new may have been reached from an anchor since.
    split.new.retain(|id| !split.old.contains(id));
    Ok(split)
}

/// The state of [`split`]'s walk.
struct Paint<'a> {
    store: &'a (dyn ObjectSource + Sync),
    flags: HashMap<Hash, u8>,
    /// Commits to visit, by timestamp. Each at most once at a time.
    queue: BinaryHeap<(u64, Hash)>,
    queued: HashSet<Hash>,
    /// Queued commits painted [`NEW`] alone.
    new_only: usize,
    headers: &'a mut HashMap<Hash, Header>,
}

impl Paint<'_> {
    /// Add `side` to the paint of `id`, and queue it if that changed it.
    fn paint(&mut self, id: Hash, side: u8, poll: &mut Poll<'_>) -> Result<(), SyncError> {
        let before = self.flags.get(&id).copied().unwrap_or(0);
        let after = before | side;
        if after == before {
            return Ok(());
        }
        self.flags.insert(id, after);
        if self.queued.contains(&id) {
            if before == NEW {
                self.new_only -= 1;
            }
            return Ok(());
        }
        if !self.headers.contains_key(&id) {
            if self.headers.len() >= MAX_COMMITS {
                return Ok(());
            }
            poll.read()?;
            let header = match self.store.read_object(&id) {
                Ok(Object::Commit(c)) => Header {
                    timestamp: c.timestamp,
                    tree: c.tree_hash,
                    parents: c.parents,
                },
                Ok(Object::Remix(r)) => Header {
                    timestamp: r.timestamp,
                    tree: r.tree_hash,
                    parents: r.parents,
                },
                Ok(_) | Err(_) => return Ok(()),
            };
            self.headers.insert(id, header);
        }
        self.queue.push((self.headers[&id].timestamp, id));
        self.queued.insert(id);
        if after == NEW {
            self.new_only += 1;
        }
        Ok(())
    }
}

/// Ids in the closure of an anchor that the trees of the new commits list,
/// so the check need not read them.
///
/// It compares the tree of each new commit with the tree of each parent it
/// read, about oldest commit first, by path, down the paths that differ. The tree
/// of an old parent is in an anchor's closure, and so is every id that a tree
/// of an anchor's closure lists: such trees' entries are collected. A tree it
/// cannot read only means it learns less, as does reaching [`MAX_COVERED`]
/// or [`MAX_TREE_READS`].
fn covered(
    store: &(dyn ObjectSource + Sync),
    split: &Split,
    poll: &mut Poll<'_>,
) -> Result<HashSet<Hash>, SyncError> {
    let mut covered = HashSet::new();
    if split.old.is_empty() {
        return Ok(covered);
    }
    let mut tree_reads = 0usize;
    for id in split.new.iter().rev() {
        let Some(commit) = split.headers.get(id) else {
            continue;
        };
        for parent in &commit.parents {
            let Some(old) = split.headers.get(parent).map(|h| h.tree) else {
                continue;
            };
            if split.old.contains(parent) {
                covered.insert(old);
            }
            let mut stack = vec![(commit.tree, old)];
            while let Some((new, old)) = stack.pop() {
                if new == old {
                    continue;
                }
                if tree_reads >= MAX_TREE_READS {
                    return Ok(covered);
                }
                tree_reads += 2;
                poll.read()?;
                let (Ok(Object::Tree(old_tree)), Ok(Object::Tree(new_tree))) =
                    (store.read_object(&old), store.read_object(&new))
                else {
                    continue;
                };
                if covered.contains(&old) {
                    if covered.len() + old_tree.entries.len() > MAX_COVERED {
                        return Ok(covered);
                    }
                    covered.extend(old_tree.entries.iter().map(|e| e.object_hash));
                }
                for entry in &new_tree.entries {
                    if entry.mode != EntryMode::Tree || covered.contains(&entry.object_hash) {
                        continue;
                    }
                    if let Some(beside) = named(&old_tree, &entry.name)
                        && beside.mode == EntryMode::Tree
                    {
                        stack.push((entry.object_hash, beside.object_hash));
                    }
                }
            }
        }
    }
    Ok(covered)
}

/// The entry of `tree` named `name`. Entries are sorted by name.
fn named<'a>(tree: &'a Tree, name: &[u8]) -> Option<&'a kit_core::object::TreeEntry> {
    tree.entries
        .binary_search_by(|e| e.name.as_slice().cmp(name))
        .ok()
        .map(|i| &tree.entries[i])
}

#[cfg(test)]
mod tests {
    use super::*;
    use kit_core::object::{Blob, Commit, Identity, TreeEntry};
    use std::collections::BTreeMap;

    /// Paths with `/` separators and their contents.
    type Files = BTreeMap<String, Vec<u8>>;

    struct Repo {
        _dir: tempfile::TempDir,
        store: ObjectStore,
        /// Skip writing these blobs, so a test can leave one missing.
        withheld: HashSet<Vec<u8>>,
        /// The timestamp of the next commit.
        clock: std::cell::Cell<u64>,
    }

    impl Repo {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
            Self {
                _dir: dir,
                store,
                withheld: HashSet::new(),
                clock: std::cell::Cell::new(1_700_000_000),
            }
        }

        fn put(&self, object: &Object) -> Hash {
            self.store
                .write(&kit_core::serialize::serialize(object).unwrap())
                .unwrap()
        }

        fn tree(&self, files: &Files, prefix: &str) -> Hash {
            let mut entries = Vec::new();
            let mut dirs = std::collections::BTreeSet::new();
            for (path, data) in files.range(prefix.to_owned()..) {
                let Some(rest) = path.strip_prefix(prefix) else {
                    break;
                };
                if let Some((dir, _)) = rest.split_once('/') {
                    if dirs.insert(dir.to_owned()) {
                        entries.push(TreeEntry {
                            name: dir.as_bytes().to_vec(),
                            mode: EntryMode::Tree,
                            object_hash: self.tree(files, &format!("{prefix}{dir}/")),
                        });
                    }
                } else {
                    let blob = Object::Blob(Blob { data: data.clone() });
                    let id = if self.withheld.contains(data) {
                        blob.id().unwrap()
                    } else {
                        self.put(&blob)
                    };
                    entries.push(TreeEntry {
                        name: rest.as_bytes().to_vec(),
                        mode: EntryMode::Blob,
                        object_hash: id,
                    });
                }
            }
            entries.sort_by(|a, b| a.name.cmp(&b.name));
            self.put(&Object::Tree(Tree { entries }))
        }

        fn commit(&self, files: &Files, parents: &[Hash]) -> Hash {
            let at = self.clock.replace(self.clock.get() + 1);
            self.commit_at(files, parents, at)
        }

        fn commit_at(&self, files: &Files, parents: &[Hash], timestamp: u64) -> Hash {
            let tree = self.tree(files, "");
            self.put(&Object::Commit(Commit::new_unannotated(
                tree,
                parents.to_vec(),
                Identity::ed25519([7; 32]),
                [7; 32],
                b"c".to_vec(),
                timestamp,
                [0; 64],
            )))
        }

        fn check(&self, tip: Hash, anchors: &[Hash]) -> Result<usize, SyncError> {
            let anchors = Anchors(anchors.iter().copied().collect());
            check_above(&self.store, &tip, &anchors, &|| false)
        }
    }

    /// Ten directories of twenty files.
    fn files() -> Files {
        let mut files = Files::new();
        for d in 0..10 {
            for f in 0..20 {
                files.insert(format!("d{d}/f{f}"), format!("{d} {f}").into_bytes());
            }
        }
        files
    }

    fn with(mut files: Files, path: &str, data: &[u8]) -> Files {
        files.insert(path.to_owned(), data.to_vec());
        files
    }

    #[test]
    fn a_new_commit_is_checked_only_where_it_differs_from_its_anchor() {
        let repo = Repo::new();
        let base = repo.commit(&files(), &[]);
        let tip = repo.commit(&with(files(), "d3/f7", b"new"), &[base]);

        // The commit, the root tree, `d3` and the new file.
        assert_eq!(repo.check(tip, &[base]).unwrap(), 4);
        // No anchor: every object of both commits.
        assert_eq!(repo.check(tip, &[]).unwrap(), 2 + 2 + 11 + 201);
    }

    #[test]
    fn a_tip_that_is_an_anchor_is_not_read() {
        let repo = Repo::new();
        let base = repo.commit(&files(), &[]);
        assert_eq!(repo.check(base, &[base]).unwrap(), 0);
    }

    #[test]
    fn each_commit_between_the_tip_and_the_anchor_is_checked_where_it_differs() {
        let repo = Repo::new();
        let base = repo.commit(&files(), &[]);
        let one = with(files(), "d1/f1", b"one");
        let first = repo.commit(&one, &[base]);
        let two = with(one, "d2/f2", b"two");
        let second = repo.commit(&two, &[first]);
        let three = with(two, "d2/f3", b"three");
        let tip = repo.commit(&three, &[second]);

        // Per commit: the commit and its root tree. `d1` once, `d2` twice,
        // and the three new files.
        assert_eq!(repo.check(tip, &[base]).unwrap(), 6 + 3 + 3);
    }

    #[test]
    fn a_merge_is_checked_against_each_parent() {
        let repo = Repo::new();
        let base = repo.commit(&files(), &[]);
        let side = repo.commit(&with(files(), "d4/f4", b"side"), &[base]);
        let main = repo.commit(&with(files(), "d5/f5", b"main"), &[base]);
        let merged = with(with(files(), "d4/f4", b"side"), "d5/f5", b"main");
        let tip = repo.commit(&merged, &[main, side]);

        // Three commits with their root trees, `d4` and `d5` with their new
        // files.
        assert_eq!(repo.check(tip, &[base]).unwrap(), 6 + 4);
        // With `side` an anchor too, its tree, `d4` and its file are not read.
        assert_eq!(repo.check(tip, &[base, side]).unwrap(), 4 + 2);
    }

    #[test]
    fn history_below_an_anchor_is_not_read_when_a_merge_reaches_it_from_a_fork() {
        let repo = Repo::new();
        let base = repo.commit(&files(), &[]);
        let one = with(files(), "d1/f1", b"one");
        let fork = repo.commit(&one, &[base]);
        let two = with(one.clone(), "d2/f2", b"two");
        let anchor = repo.commit(&two, &[fork]);
        let side = with(one, "d3/f3", b"side");
        let feature = repo.commit(&side, &[fork]);
        let tip = repo.commit(&with(two, "d3/f3", b"side"), &[anchor, feature]);

        // The merge and the feature commit with their root trees, and `d3`
        // with its new file. `fork` and `base` are ancestors of the anchor.
        assert_eq!(repo.check(tip, &[anchor]).unwrap(), 6);
    }

    #[test]
    fn timestamps_out_of_order_cost_reads_and_keep_the_check_whole() {
        let repo = Repo::new();
        let base = repo.commit_at(&files(), &[], 100);
        let anchor = repo.commit_at(&with(files(), "d1/f1", b"one"), &[base], 200);
        // Older than the history it builds on.
        let tip = repo.commit_at(&with(files(), "d3/f3", b"new"), &[base], 50);
        assert_eq!(repo.check(tip, &[anchor]).unwrap(), 4);

        // An anchor from the future, over a tip from the past, whose history
        // the anchor does not reach.
        let lone = repo.commit_at(&with(Files::new(), "x", b"x"), &[], 10);
        let late = repo.commit_at(&with(files(), "d1/f1", b"late"), &[base], u64::MAX);
        let tip = repo.commit_at(&with(Files::new(), "x", b"y"), &[lone], 20);
        assert_eq!(
            repo.check(tip, &[late]).unwrap(),
            repo.check(tip, &[]).unwrap()
        );
    }

    #[test]
    fn a_walk_that_stops_before_it_reaches_the_anchor_checks_everything() {
        let repo = Repo::new();
        let base = repo.commit_at(&files(), &[], 1000);
        let anchor = repo.commit_at(&with(files(), "d1/f1", b"one"), &[base], 10);
        let tip = repo.commit_at(&with(files(), "d3/f3", b"new"), &[base], 500);
        assert_eq!(
            repo.check(tip, &[anchor]).unwrap(),
            repo.check(tip, &[]).unwrap()
        );
    }

    #[test]
    fn a_commit_taken_as_new_that_an_anchor_reaches_later_is_not_checked() {
        let repo = Repo::new();
        let base = repo.commit_at(&files(), &[], 1);
        let old = repo.commit_at(&with(files(), "d1/f1", b"one"), &[base], 1000);
        let lone = repo.commit_at(&with(Files::new(), "y", b"y"), &[], 5);
        let anchor = repo.commit_at(&with(files(), "d2/f2", b"two"), &[old], 10);
        let tip = repo.commit_at(&with(files(), "d1/f1", b"one"), &[old, lone], 2000);

        // The merge, then `lone` with its tree and file. The merge's tree is
        // `old`'s, and `old` is reached from the anchor after it was popped.
        assert_eq!(repo.check(tip, &[anchor]).unwrap(), 4);
    }

    #[test]
    fn a_file_the_anchor_holds_elsewhere_in_a_changed_directory_is_not_read() {
        let repo = Repo::new();
        let base = repo.commit(&files(), &[]);
        let tip = repo.commit(&with(files(), "d3/copy", b"3 1"), &[base]);
        assert_eq!(repo.check(tip, &[base]).unwrap(), 3);
    }

    #[test]
    fn a_directory_that_replaces_a_file_is_walked_in_full() {
        let repo = Repo::new();
        let base = repo.commit(&files(), &[]);
        let mut changed = files();
        changed.remove("d3/f7");
        changed.insert("d3/f7/a".to_owned(), b"0 0".to_vec());
        changed.insert("d3/f7/b".to_owned(), b"b".to_vec());
        let tip = repo.commit(&changed, &[base]);

        // The commit, the root tree, `d3`, `d3/f7`, `a` and `b`. `a` holds
        // what `d0/f0` holds, but no tree the comparison read lists it.
        assert_eq!(repo.check(tip, &[base]).unwrap(), 6);
    }

    #[test]
    fn an_object_missing_above_the_anchor_is_reported() {
        let mut repo = Repo::new();
        let base = repo.commit(&files(), &[]);
        repo.withheld.insert(b"lost".to_vec());
        let tip = repo.commit(&with(files(), "d3/f7", b"lost"), &[base]);
        let lost = Object::Blob(Blob {
            data: b"lost".to_vec(),
        })
        .id()
        .unwrap();

        let error = repo.check(tip, &[base]).unwrap_err();
        assert!(
            matches!(&error, SyncError::RemoteMissingObject(hex) if *hex == to_hex(&lost)),
            "{error:?}"
        );
    }

    #[test]
    fn an_anchor_only_skips_what_its_own_closure_holds() {
        let repo = Repo::new();
        let base = repo.commit(&files(), &[]);
        // An anchor unrelated to the tip covers nothing of it.
        let other = repo.commit(&with(Files::new(), "x", b"x"), &[]);
        let tip = repo.commit(&with(files(), "d3/f7", b"new"), &[base]);
        assert_eq!(
            repo.check(tip, &[other]).unwrap(),
            repo.check(tip, &[]).unwrap()
        );
    }
}

//! The closure check a fetch runs before it publishes a tracking ref, down to
//! the tips whose closure an earlier check covered.
//!
//! An anchor is the tip of a tracking ref of the fetched remote, taken while
//! the fetch holds its [`kit_core::store::PruneGuard`], or a tip this fetch
//! published. Its closure is in the store:
//!
//! - A fetch publishes a tracking ref only after the closure of its tip
//!   passed this check, and a push or `git import` only for a tip whose
//!   objects this store wrote or holds. `update-ref` cannot write one.
//! - gc keeps everything a tracking ref reaches. It holds every worktree lock
//!   while it marks and prunes, and a fetch moves a tracking ref only under
//!   one, so a ref cannot move under a running gc.
//! - From the moment the fetch takes its guard, gc deletes nothing.
//! - A tip the store lacks, as after `.kit/objects` was wiped, is no anchor.
//!
//! The check reads no object at or below an anchor. It also skips each id
//! that a tree of an anchor's closure lists, found by comparing the tree of
//! each new commit with the trees of its parents, by path, down the paths
//! that differ ([`covered`]). Such an id is in that anchor's closure, so its
//! own closure is present and passed the check when the anchor did: every
//! property the check tests depends on the id alone. Every other object the
//! tip reaches is checked as a full check would.
//!
//! With no anchor the check is the full walk.

use std::collections::{HashMap, HashSet};

use kit_core::hash::{Hash, to_hex};
use kit_core::layout::RepoLayout;
use kit_core::object::{EntryMode, KitError, Object, Tree};
use kit_core::ops::{Known, Presence};
use kit_core::refs;
use kit_core::store::{ObjectStore, StoreError};

use crate::error::SyncError;

/// The most ids [`covered`] collects. Past it, it stops, which only makes
/// the check read more.
const MAX_COVERED: usize = 2_097_152;

/// The most new commits [`covered`] reads. Past it, it gives up: a fetch of
/// that much history checks most of its closure anyway.
const MAX_COMMITS: usize = 65_536;

/// The most trees [`covered`] reads.
const MAX_TREE_READS: usize = 262_144;

/// How often [`covered`] polls for cancellation, in objects read.
const POLL_OBJECTS: usize = 4096;

/// The tips whose closure a check of this fetch may stop at.
#[derive(Debug, Default)]
pub(crate) struct Anchors(HashSet<Hash>);

impl Anchors {
    /// The tips of the tracking refs of `remote` that the store holds. The
    /// caller holds the store's prune guard.
    pub(crate) fn load(
        store: &ObjectStore,
        layout: &RepoLayout,
        remote: &str,
    ) -> Result<Self, SyncError> {
        Ok(Self(
            refs::list_remote_refs(layout, remote)?
                .into_iter()
                .filter_map(|r| r.hash)
                .filter(|tip| store.contains(tip))
                .collect(),
        ))
    }

    /// Whether there is no anchor, so a check walks the whole closure.
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
pub(crate) fn check_above(
    store: &ObjectStore,
    tip: &Hash,
    anchors: &Anchors,
    cancelled: &dyn Fn() -> bool,
) -> Result<usize, SyncError> {
    let covered = covered(store, tip, &anchors.0, cancelled)?;
    let known = |h: &Hash| {
        if anchors.0.contains(h) || covered.contains(h) {
            Known::Present
        } else {
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

/// Ids in the closure of an anchor that the tip's new trees list, so the
/// check need not read them.
///
/// It reads the commits `tip` reaches above the anchors, then compares the
/// tree of each one with the tree of each parent, parents first, by path,
/// down the paths that differ. The tree of an anchor parent is in that
/// anchor's closure, and so is every id that a tree in it lists: those trees'
/// entries are collected. A tree or commit it cannot read only means it
/// learns less, as does reaching [`MAX_COMMITS`] or [`MAX_TREE_READS`]: the
/// check that follows reads the same objects and reports them.
fn covered(
    store: &ObjectStore,
    tip: &Hash,
    anchors: &HashSet<Hash>,
    cancelled: &dyn Fn() -> bool,
) -> Result<HashSet<Hash>, SyncError> {
    let mut covered = HashSet::new();
    if anchors.is_empty() || anchors.contains(tip) {
        return Ok(covered);
    }
    let mut reads = 0usize;
    let mut poll = || {
        reads += 1;
        if reads.is_multiple_of(POLL_OBJECTS) && cancelled() {
            return Err(SyncError::Interrupted);
        }
        Ok(reads)
    };
    let Some(commits) = new_commits(store, tip, anchors, &mut poll)? else {
        return Ok(covered);
    };
    let trees: HashMap<Hash, Hash> = commits.iter().map(|c| (c.id, c.tree)).collect();
    let mut tree_reads = 0usize;
    for commit in &commits {
        for parent in &commit.parents {
            let old = match trees.get(parent) {
                Some(tree) => *tree,
                None if anchors.contains(parent) => match store.read_object(parent) {
                    Ok(Object::Commit(c)) => c.tree_hash,
                    Ok(Object::Remix(r)) => r.tree_hash,
                    Ok(_) | Err(_) => continue,
                },
                None => continue,
            };
            if anchors.contains(parent) {
                covered.insert(old);
            }
            let mut stack = vec![(commit.tree, old)];
            while let Some((new, old)) = stack.pop() {
                if new == old {
                    continue;
                }
                if tree_reads >= MAX_TREE_READS || covered.len() >= MAX_COVERED {
                    return Ok(covered);
                }
                tree_reads += 2;
                poll()?;
                let (Ok(Object::Tree(old_tree)), Ok(Object::Tree(new_tree))) =
                    (store.read_object(&old), store.read_object(&new))
                else {
                    continue;
                };
                if covered.contains(&old) {
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

/// A commit above the anchors, read once.
struct NewCommit {
    id: Hash,
    tree: Hash,
    parents: Vec<Hash>,
}

/// The commits and remixes `tip` reaches without passing an anchor, parents
/// first. A commit it cannot read ends its path. `None` past
/// [`MAX_COMMITS`].
fn new_commits(
    store: &ObjectStore,
    tip: &Hash,
    anchors: &HashSet<Hash>,
    poll: &mut dyn FnMut() -> Result<usize, SyncError>,
) -> Result<Option<Vec<NewCommit>>, SyncError> {
    let mut order = Vec::new();
    let mut seen = HashSet::from([*tip]);
    // Each commit with how many of its parents were visited.
    let mut frames: Vec<(NewCommit, usize)> = Vec::new();
    let mut next = Some(*tip);
    loop {
        if let Some(id) = next.take() {
            poll()?;
            if seen.len() > MAX_COMMITS {
                return Ok(None);
            }
            match store.read_object(&id) {
                Ok(Object::Commit(c)) => frames.push((
                    NewCommit {
                        id,
                        tree: c.tree_hash,
                        parents: c.parents,
                    },
                    0,
                )),
                Ok(Object::Remix(r)) => frames.push((
                    NewCommit {
                        id,
                        tree: r.tree_hash,
                        parents: r.parents,
                    },
                    0,
                )),
                Ok(_) | Err(_) => {}
            }
        }
        let Some((commit, cursor)) = frames.last_mut() else {
            return Ok(Some(order));
        };
        if let Some(parent) = commit.parents.get(*cursor) {
            *cursor += 1;
            if !anchors.contains(parent) && seen.insert(*parent) {
                next = Some(*parent);
            }
        } else if let Some((done, _)) = frames.pop() {
            order.push(done);
        }
    }
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
    }

    impl Repo {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
            Self {
                _dir: dir,
                store,
                withheld: HashSet::new(),
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
            let tree = self.tree(files, "");
            self.put(&Object::Commit(Commit::new_unannotated(
                tree,
                parents.to_vec(),
                Identity::ed25519([7; 32]),
                [7; 32],
                b"c".to_vec(),
                1_700_000_000 + parents.len() as u64,
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

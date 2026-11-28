//! The window of a shallow fetch and the objects it sends (SPEC-SHALLOW §2
//! and §8.2).
//!
//! [`window`] is a pure function of the commit graph: the commits at a
//! shortest parent distance of less than `depth` from each tip, and the
//! boundary over their union (SH3). [`window_objects`] is the set a server
//! sends for a window: each window commit with its snapshot closure, less
//! what the client already holds. [`window_packs`] writes that set as packs.

use std::collections::{BTreeMap, BTreeSet, BinaryHeap};

use crate::hash::{Hash, to_hex};
use crate::object::Object;
use crate::ops::graph::reachable_snapshot;
use crate::pack::{self, PackWriter};
use crate::store::{ObjectSource, ObjectStore, StoreError};

use super::Boundary;

/// The most tips one window request names.
pub const MAX_WINDOW_TIPS: usize = 1_000;

/// The greatest depth a window request asks for.
pub const MAX_DEPTH: u32 = (1 << 31) - 1;

/// The most commits a window holds. It matches the history walk of
/// `kit log`.
pub const MAX_WINDOW_COMMITS: usize = 1_000_000;

/// The commits of a window and its boundary.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Window {
    /// Every commit of the window.
    pub commits: BTreeSet<Hash>,
    /// The commits of the window with a parent outside it.
    pub boundary: Boundary,
}

/// Why a window cannot be computed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WindowError {
    /// A depth of 0, which holds no commit.
    #[error("a depth must be at least 1")]
    ZeroDepth,
    /// A depth above [`MAX_DEPTH`].
    #[error("a depth must be at most {MAX_DEPTH}")]
    DepthTooLarge,
    /// No tips, or more than [`MAX_WINDOW_TIPS`].
    #[error("a window names from 1 to {MAX_WINDOW_TIPS} tips")]
    Tips,
    /// A commit the window needs is not in the store.
    #[error("commit {} is missing", to_hex(.0))]
    Missing(Hash),
    /// A tip or parent names an object that is not a commit.
    #[error("object {} is not a commit", to_hex(.0))]
    NotACommit(Hash),
    /// The window would hold more than [`MAX_WINDOW_COMMITS`] commits.
    #[error("the window holds more than {MAX_WINDOW_COMMITS} commits")]
    TooLarge,
    /// The store failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// A pack could not be written.
    #[error(transparent)]
    Pack(#[from] pack::PackError),
}

/// The window of `tips`, each with its depth, over the graph that `parents`
/// describes: `parents` returns the parents of a commit, or `None` for one
/// that is absent. A commit is in the window when its shortest parent
/// distance from some tip is less than that tip's depth, and in the boundary
/// when one of its parents is in no tip's window. Only the parents of
/// window commits are asked for.
///
/// # Errors
/// [`WindowError::ZeroDepth`], [`WindowError::DepthTooLarge`] or
/// [`WindowError::Tips`] for a bad request, [`WindowError::Missing`] when
/// `parents` returns `None` for a commit of the window, and
/// [`WindowError::TooLarge`] past [`MAX_WINDOW_COMMITS`].
pub fn window(
    tips: &[(Hash, u32)],
    mut parents: impl FnMut(&Hash) -> Option<Vec<Hash>>,
) -> Result<Window, WindowError> {
    if tips.is_empty() || tips.len() > MAX_WINDOW_TIPS {
        return Err(WindowError::Tips);
    }
    if tips.iter().any(|(_, d)| *d == 0) {
        return Err(WindowError::ZeroDepth);
    }
    if tips.iter().any(|(_, d)| *d > MAX_DEPTH) {
        return Err(WindowError::DepthTooLarge);
    }
    // A commit is in the union of the windows when the most depth any tip
    // has left at it is at least 1. Walking the greatest remaining depth
    // first settles each commit at that value, as a shortest-path search
    // does, so no commit is expanded with less depth than it has.
    let mut left: BTreeMap<Hash, u32> = BTreeMap::new();
    let mut heap: BinaryHeap<(u32, Hash)> = BinaryHeap::new();
    for (tip, depth) in tips {
        if left.get(tip).is_none_or(|d| d < depth) {
            left.insert(*tip, *depth);
            heap.push((*depth, *tip));
        }
    }
    let mut edges: BTreeMap<Hash, Vec<Hash>> = BTreeMap::new();
    while let Some((depth, commit)) = heap.pop() {
        if left.get(&commit) != Some(&depth) || edges.contains_key(&commit) {
            continue;
        }
        let ps = parents(&commit).ok_or(WindowError::Missing(commit))?;
        if depth > 1 {
            for p in &ps {
                if left.get(p).is_none_or(|d| *d < depth - 1) {
                    if left.len() >= MAX_WINDOW_COMMITS && !left.contains_key(p) {
                        return Err(WindowError::TooLarge);
                    }
                    left.insert(*p, depth - 1);
                    heap.push((depth - 1, *p));
                }
            }
        }
        edges.insert(commit, ps);
    }
    let commits: BTreeSet<Hash> = edges.keys().copied().collect();
    let boundary = Boundary::new(
        edges
            .iter()
            .filter(|(_, ps)| ps.iter().any(|p| !commits.contains(p)))
            .map(|(c, _)| *c),
    );
    Ok(Window { commits, boundary })
}

/// [`window`] over the commits of `store`. A remix counts as a commit with
/// its parents.
///
/// # Errors
/// The errors of [`window`], [`WindowError::NotACommit`] for a tip or parent
/// that is another kind of object, and [`WindowError::Store`] when a read
/// fails for another reason than an absent object.
pub fn window_in(
    store: &(impl ObjectSource + ?Sized),
    tips: &[(Hash, u32)],
) -> Result<Window, WindowError> {
    // The callback cannot fail, so the first error it meets waits here.
    let mut failure: Option<WindowError> = None;
    let result = window(tips, |h| match store.read_object(h) {
        Ok(Object::Commit(c)) => Some(c.parents),
        Ok(Object::Remix(r)) => Some(r.parents),
        Ok(_) => {
            failure.get_or_insert(WindowError::NotACommit(*h));
            None
        }
        Err(StoreError::ObjectNotFound(_)) => None,
        Err(e) => {
            failure.get_or_insert(WindowError::Store(e));
            None
        }
    });
    match (result, failure) {
        (Err(WindowError::Missing(_)), Some(failure)) => Err(failure),
        (result, _) => result,
    }
}

/// The objects a server sends for `window`: each commit of the window and
/// its snapshot closure (its tree, not its parents), less the snapshot
/// closure of each commit in `have`, which the client holds.
///
/// # Errors
/// A [`StoreError`] when an object of a closure is missing or unreadable.
pub fn window_objects(
    store: &ObjectStore,
    window: &Window,
    have: &[Hash],
) -> Result<BTreeSet<Hash>, StoreError> {
    let mut out = BTreeSet::new();
    for commit in &window.commits {
        out.extend(reachable_snapshot(store, commit)?);
    }
    for held in have {
        for id in reachable_snapshot(store, held)? {
            out.remove(&id);
        }
    }
    Ok(out)
}

/// [`window_objects`] written as raw packs, each within the pack limits of
/// the transport.
///
/// # Errors
/// [`WindowError::Store`] for the errors of [`window_objects`] and
/// [`WindowError::Pack`] when a pack cannot be written.
pub fn window_packs(
    store: &ObjectStore,
    window: &Window,
    have: &[Hash],
) -> Result<Vec<Vec<u8>>, WindowError> {
    let mut packs = Vec::new();
    let mut writer = PackWriter::new_raw_only();
    for id in window_objects(store, window, have)? {
        let bytes = store.read(&id)?;
        if pack::PackFill::of(&writer).seals_before(
            pack::Incoming::raw(bytes.len() as u64, 0),
            pack::MAX_TOTAL_PAYLOAD,
            crate::protocol::PACK_BODY_LIMIT,
            pack::MAX_ENTRIES as usize,
        ) {
            packs.push(writer.finish()?);
            writer = PackWriter::new_raw_only();
        }
        writer.push_raw(id, &bytes)?;
    }
    if writer.entry_count() > 0 {
        packs.push(writer.finish()?);
    }
    Ok(packs)
}

/// Why a received window is refused (SPEC-SHALLOW §8.2).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReceivedError {
    /// The window the client computes needs an object it did not receive.
    #[error("the window misses object {}", to_hex(.0))]
    Incomplete(Hash),
    /// The server's boundary list differs from the one the client computes.
    #[error("the server's boundary list differs from the window it sent")]
    BoundaryMismatch,
    /// The window cannot be computed from the received objects.
    #[error(transparent)]
    Window(#[from] WindowError),
}

/// Check a received window before anything names it: compute the window of
/// `tips` at `depth` from the objects in `store`, require the boundary the
/// server `listed` to equal the computed one (SH3), and require the full
/// snapshot closure of each window commit (SH1).
///
/// # Errors
/// [`ReceivedError::Incomplete`] naming an absent object,
/// [`ReceivedError::BoundaryMismatch`], or [`ReceivedError::Window`].
pub fn check_received(
    store: &ObjectStore,
    tips: &[Hash],
    depth: u32,
    listed: &[Hash],
) -> Result<Window, ReceivedError> {
    let tips: Vec<(Hash, u32)> = tips.iter().map(|t| (*t, depth)).collect();
    let window = match window_in(store, &tips) {
        Ok(window) => window,
        Err(WindowError::Missing(id)) => return Err(ReceivedError::Incomplete(id)),
        Err(e) => return Err(e.into()),
    };
    if Boundary::new(listed.iter().copied()) != window.boundary
        || listed.len() != window.boundary.len()
    {
        return Err(ReceivedError::BoundaryMismatch);
    }
    for commit in &window.commits {
        if let Err(missing) = snapshot_present(store, commit) {
            return Err(ReceivedError::Incomplete(missing));
        }
    }
    Ok(window)
}

/// Whether the snapshot closure of `commit` is in `store`: `Err` names the
/// first absent object.
fn snapshot_present(store: &ObjectStore, commit: &Hash) -> Result<(), Hash> {
    match reachable_snapshot(store, commit) {
        Ok(_) => Ok(()),
        Err(StoreError::ObjectNotFound(hex)) => Err(crate::hash::from_hex(&hex).unwrap_or(*commit)),
        Err(_) => Err(*commit),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::shallow::exact_record;
    use proptest::prelude::*;
    use std::collections::{HashMap, VecDeque};

    fn id(n: usize) -> Hash {
        let mut h = [0; 32];
        h[..8].copy_from_slice(&(n as u64).to_be_bytes());
        h
    }

    /// Commits 0..n, each with parents among the lower numbers.
    fn graph() -> impl Strategy<Value = HashMap<Hash, Vec<Hash>>> {
        (1usize..30).prop_flat_map(|n| {
            proptest::collection::vec(
                proptest::collection::vec(any::<prop::sample::Index>(), 0..3),
                n,
            )
            .prop_map(|edges| {
                let mut g = HashMap::new();
                for (i, ps) in edges.iter().enumerate() {
                    let mut parents: Vec<Hash> = if i == 0 {
                        vec![]
                    } else {
                        ps.iter().map(|ix| id(ix.index(i))).collect()
                    };
                    parents.dedup();
                    g.insert(id(i), parents);
                }
                g
            })
        })
    }

    /// The window of one tip, by a breadth-first walk.
    fn reference(g: &HashMap<Hash, Vec<Hash>>, tip: Hash, depth: u32) -> BTreeSet<Hash> {
        let mut dist: HashMap<Hash, u32> = HashMap::from([(tip, 0)]);
        let mut queue = VecDeque::from([tip]);
        while let Some(c) = queue.pop_front() {
            let d = dist[&c];
            if d + 1 >= depth {
                continue;
            }
            for p in &g[&c] {
                if !dist.contains_key(p) {
                    dist.insert(*p, d + 1);
                    queue.push_back(*p);
                }
            }
        }
        dist.into_keys().collect()
    }

    /// The longest parent path from `tip`, counted in commits.
    fn longest(g: &HashMap<Hash, Vec<Hash>>, tip: Hash, memo: &mut HashMap<Hash, u32>) -> u32 {
        if let Some(&n) = memo.get(&tip) {
            return n;
        }
        let n = 1 + g[&tip]
            .iter()
            .map(|p| longest(g, *p, memo))
            .max()
            .unwrap_or(0);
        memo.insert(tip, n);
        n
    }

    fn tips_of(n: usize) -> impl Strategy<Value = Vec<(Hash, u32)>> {
        proptest::collection::vec((0..n, 1u32..8), 1..4)
            .prop_map(|v| v.into_iter().map(|(i, d)| (id(i), d)).collect())
    }

    #[test]
    fn a_bad_request_is_refused() {
        let g = HashMap::from([(id(0), vec![])]);
        let p = |h: &Hash| g.get(h).cloned();
        assert!(matches!(
            window(&[(id(0), 0)], p),
            Err(WindowError::ZeroDepth)
        ));
        assert!(matches!(
            window(&[(id(0), MAX_DEPTH + 1)], p),
            Err(WindowError::DepthTooLarge)
        ));
        assert!(matches!(window(&[], p), Err(WindowError::Tips)));
        let many = vec![(id(0), 1); MAX_WINDOW_TIPS + 1];
        assert!(matches!(window(&many, p), Err(WindowError::Tips)));
    }

    #[test]
    fn depth_one_holds_the_tip_alone() {
        let g = HashMap::from([(id(0), vec![]), (id(1), vec![id(0)])]);
        let w = window(&[(id(1), 1)], |h| g.get(h).cloned()).unwrap();
        assert_eq!(w.commits, BTreeSet::from([id(1)]));
        assert_eq!(w.boundary, Boundary::new([id(1)]));
    }

    #[test]
    fn a_missing_commit_inside_the_window_is_an_error() {
        let g = HashMap::from([(id(1), vec![id(0)])]);
        let got = window(&[(id(1), 2)], |h| g.get(h).cloned());
        assert!(matches!(got, Err(WindowError::Missing(h)) if h == id(0)));
        // The parent of a commit at the last level is never read.
        let w = window(&[(id(1), 1)], |h| g.get(h).cloned()).unwrap();
        assert_eq!(w.boundary, Boundary::new([id(1)]));
    }

    proptest! {
        /// SH3: the window is the union of the breadth-first windows of the
        /// tips, whatever their order, and its boundary is the record SH2
        /// demands for a repository that holds exactly the window.
        #[test]
        fn the_window_is_a_function_of_the_graph(
            (g, tips) in graph().prop_flat_map(|g| { let t = tips_of(g.len()); (Just(g), t) })
        ) {
            let w = window(&tips, |h| g.get(h).cloned()).unwrap();
            let mut union = BTreeSet::new();
            for (tip, depth) in &tips {
                union.extend(reference(&g, *tip, *depth));
            }
            prop_assert_eq!(&w.commits, &union);
            let heads: Vec<Hash> = tips.iter().map(|(t, _)| *t).collect();
            let record = exact_record(&heads, |h| {
                w.commits.contains(h).then(|| g[h].clone())
            });
            prop_assert_eq!(&w.boundary, &record);
            let mut reversed = tips.clone();
            reversed.reverse();
            reversed.extend(tips.iter().copied());
            prop_assert_eq!(window(&reversed, |h| g.get(h).cloned()).unwrap(), w);
        }

        /// SH4: a depth at or above the longest parent path from the tip is
        /// the whole history, with an empty record.
        #[test]
        fn a_full_depth_is_the_whole_history(g in graph()) {
            let tip = id(g.len() - 1);
            let depth = longest(&g, tip, &mut HashMap::new());
            let w = window(&[(tip, depth)], |h| g.get(h).cloned()).unwrap();
            prop_assert_eq!(&w.commits, &reference(&g, tip, u32::MAX));
            prop_assert!(w.boundary.is_empty());
        }
    }

    mod in_store {
        use super::*;
        use crate::layout::RepoLayout;
        use crate::object::{Blob, Commit, EntryMode, Identity, Tree, TreeEntry};
        use crate::ops::graph::reachable_objects;
        use crate::serialize;
        use tempfile::TempDir;

        fn put(store: &ObjectStore, object: &Object) -> Hash {
            store.write(&serialize::serialize(object).unwrap()).unwrap()
        }

        /// A line of `n` commits, each with a file of its own content.
        fn line(store: &ObjectStore, n: usize) -> Vec<Hash> {
            let mut out: Vec<Hash> = Vec::new();
            for i in 0..n {
                let blob = put(
                    store,
                    &Object::Blob(Blob {
                        data: format!("{i}\n").into_bytes(),
                    }),
                );
                let tree = put(
                    store,
                    &Object::Tree(Tree {
                        entries: vec![TreeEntry {
                            name: b"f".to_vec(),
                            mode: EntryMode::Blob,
                            object_hash: blob,
                        }],
                    }),
                );
                out.push(put(
                    store,
                    &Object::Commit(Commit {
                        tree_hash: tree,
                        parents: out.last().copied().into_iter().collect(),
                        author: Identity::ed25519([0; 32]),
                        signer: [0; 32],
                        message: format!("c{i}").into_bytes(),
                        timestamp: i as u64,
                        message_hash: [0; 32],
                        content_digest: [0; 32],
                        signature: [0; 64],
                    }),
                ));
            }
            out
        }

        fn store() -> (TempDir, ObjectStore) {
            let d = TempDir::new().unwrap();
            let s = ObjectStore::init(&RepoLayout::single(d.path())).unwrap();
            (d, s)
        }

        #[test]
        fn a_window_reads_the_commits_of_the_store() {
            let (_d, s) = store();
            let c = line(&s, 5);
            let w = window_in(&s, &[(c[4], 2)]).unwrap();
            assert_eq!(w.commits, BTreeSet::from([c[3], c[4]]));
            assert_eq!(w.boundary, Boundary::new([c[3]]));
            let tree = match s.read_object(&c[0]).unwrap() {
                Object::Commit(commit) => commit.tree_hash,
                _ => unreachable!(),
            };
            assert!(
                matches!(window_in(&s, &[(tree, 1)]), Err(WindowError::NotACommit(h)) if h == tree)
            );
        }

        #[test]
        fn a_full_depth_sends_the_whole_closure() {
            let (_d, s) = store();
            let c = line(&s, 4);
            let w = window_in(&s, &[(c[3], 4)]).unwrap();
            assert_eq!(
                window_objects(&s, &w, &[]).unwrap(),
                reachable_objects(&s, &c[3]).unwrap()
            );
        }

        #[test]
        fn a_window_sends_each_snapshot_less_what_the_client_has() {
            let (_d, s) = store();
            let c = line(&s, 4);
            let w = window_in(&s, &[(c[3], 2)]).unwrap();
            let sent = window_objects(&s, &w, &[]).unwrap();
            let mut want = reachable_snapshot(&s, &c[3]).unwrap();
            want.extend(reachable_snapshot(&s, &c[2]).unwrap());
            assert_eq!(sent, want);
            assert!(!sent.contains(&c[1]));

            let less = window_objects(&s, &w, &[c[2]]).unwrap();
            let held = reachable_snapshot(&s, &c[2]).unwrap();
            assert_eq!(less, sent.difference(&held).copied().collect());

            let packs = window_packs(&s, &w, &[]).unwrap();
            let mut ids = BTreeSet::new();
            for p in &packs {
                for entry in pack::PackEntries::new(p).unwrap() {
                    let pack::PackEntry::Raw { bytes } = entry.unwrap() else {
                        panic!("a window pack is raw");
                    };
                    ids.insert(crate::object::object_id_from_bytes(&bytes));
                }
            }
            assert_eq!(ids, sent);
        }
    }
}

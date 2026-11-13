//! Tests of the two-part mark: a property test against a copy of the old
//! one-set walk, the fail-closed contract, the caps and the boundaries.
//!
//! A bug in the mark deletes data, so each rule has a test that fails when the
//! rule is mutated.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;

use proptest::prelude::*;
use tempfile::TempDir;

use super::*;
use crate::index::{EntryStatus, Index, IndexEntry};
use crate::object::{Blob, ChunkedBlob, Commit, Delta, EntryMode, Identity, Tree, TreeEntry};
use crate::serialize;

/// Run gc at the end of time with no grace, so every unreachable object is old
/// enough to prune.
const NOW: u64 = u64::MAX;

fn limits(cap: usize, chunk_cap: usize, compact_floor: usize) -> MarkLimits {
    MarkLimits {
        cap,
        chunk_cap,
        compact_floor,
    }
}

/// A repository with a store on disk.
struct Fx {
    _dir: TempDir,
    store: ObjectStore,
    layout: RepoLayout,
}

impl Fx {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let layout = RepoLayout::single(dir.path());
        let store = ObjectStore::init(&layout).unwrap();
        refs::init(&layout).unwrap();
        Self {
            _dir: dir,
            store,
            layout,
        }
    }

    fn put(&self, object: &Object) -> Hash {
        self.store
            .write(&serialize::serialize(object).unwrap())
            .unwrap()
    }

    fn blob(&self, data: &str) -> Hash {
        self.put(&Object::Blob(Blob {
            data: data.as_bytes().to_vec(),
        }))
    }

    fn blobs(&self, prefix: &str, n: usize) -> Vec<Hash> {
        (0..n)
            .map(|i| self.blob(&format!("{prefix}-{i}")))
            .collect()
    }

    fn delta(&self, base: Hash) -> Hash {
        self.put(&Object::Delta(Delta {
            base_hash: base,
            result_size: 0,
            instructions: Vec::new(),
        }))
    }

    /// A manifest of the given chunks, in the given order.
    fn manifest(&self, chunks: &[Hash]) -> Hash {
        self.put(&Object::ChunkedBlob(ChunkedBlob {
            total_size: chunks.len() as u64,
            chunk_size: 0,
            chunks: chunks.to_vec(),
        }))
    }

    /// A tree of files and subtrees, named by position so the names sort.
    fn tree(&self, files: &[Hash], subtrees: &[Hash]) -> Hash {
        let entries = files
            .iter()
            .map(|h| (EntryMode::Blob, *h))
            .chain(subtrees.iter().map(|h| (EntryMode::Tree, *h)))
            .enumerate()
            .map(|(i, (mode, object_hash))| TreeEntry {
                name: format!("e{i:05}").into_bytes(),
                mode,
                object_hash,
            })
            .collect();
        self.put(&Object::Tree(Tree { entries }))
    }

    fn commit(&self, tree: Hash, parents: Vec<Hash>, message: &str) -> Hash {
        self.put(&Object::Commit(Commit {
            tree_hash: tree,
            parents,
            author: Identity::opaque(b"t".to_vec()),
            signer: [0u8; 32],
            message: message.as_bytes().to_vec(),
            timestamp: 1,
            message_hash: [0u8; 32],
            content_digest: [0u8; 32],
            signature: [0u8; 64],
        }))
    }

    fn branch(&self, name: &str, commit: &Hash) {
        let path = self.layout.heads_dir().join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, format!("{}\n", hash::to_hex(commit))).unwrap();
    }

    /// `main` points at a commit of a tree that holds one chunked file.
    /// Returns `(commit, tree, manifest)`.
    fn chunked_file_on_main(&self, chunks: &[Hash]) -> (Hash, Hash, Hash) {
        let manifest = self.manifest(chunks);
        let tree = self.tree(&[manifest], &[]);
        let commit = self.commit(tree, vec![], "main");
        self.branch("main", &commit);
        (commit, tree, manifest)
    }

    fn roots(&self) -> BTreeSet<Hash> {
        collect_roots(&self.layout).unwrap()
    }

    fn mark(&self, limits: MarkLimits) -> Result<LiveSet, GcRootsError> {
        mark_live(&self.store, &self.roots(), limits)
    }

    fn gc(&self, limits: MarkLimits, dry_run: bool) -> Result<GcReport, GcRootsError> {
        run_gc_with_hook(&self.store, &self.layout, NOW, 0, dry_run, limits, |_| {})
    }

    fn listing(&self) -> BTreeSet<Hash> {
        self.store
            .iter_object_hashes()
            .unwrap()
            .into_iter()
            .collect()
    }

    /// Every object with its bytes on disk.
    fn snapshot(&self) -> BTreeMap<Hash, Vec<u8>> {
        self.listing()
            .into_iter()
            .map(|h| (h, fs::read(self.store.path_for(&h)).unwrap()))
            .collect()
    }

    /// Read every object of the old walk's closure back through the store.
    fn assert_closure_readable(&self) {
        for h in old_walk(&self.store, &self.roots()).unwrap() {
            self.store
                .read(&h)
                .unwrap_or_else(|e| panic!("live object {} is gone: {e}", hash::to_hex(&h)));
        }
    }
}

/// The one-set walk gc used before chunks were held apart, written with
/// `children` and no cap. It is the reference the new mark must equal.
fn old_walk(store: &ObjectStore, roots: &BTreeSet<Hash>) -> Result<BTreeSet<Hash>, StoreError> {
    let mut live = BTreeSet::new();
    let mut queue: VecDeque<Hash> = roots.iter().copied().collect();
    while let Some(h) = queue.pop_front() {
        if !live.insert(h) {
            continue;
        }
        if matches!(store.object_type(&h)?, ObjectType::Blob | ObjectType::Delta) {
            continue;
        }
        queue.extend(children(&store.read_object(&h)?, ClosureMode::History));
    }
    Ok(live)
}

fn as_set(live: &LiveSet) -> BTreeSet<Hash> {
    live.iter().copied().collect()
}

// ---------------------------------------------------------------------
// The live set
// ---------------------------------------------------------------------

#[test]
fn live_set_holds_objects_and_chunks_apart() {
    let fx = Fx::new();
    let chunks = fx.blobs("c", 3);
    let (commit, tree, manifest) = fx.chunked_file_on_main(&chunks);
    let orphan = fx.blob("orphan");

    let live = fx.mark(MarkLimits::DEFAULT).unwrap();

    let mut sorted = chunks.clone();
    sorted.sort_unstable();
    assert_eq!(live.chunks, sorted);
    assert_eq!(live.objects, BTreeSet::from([commit, tree, manifest]));
    assert_eq!(live.len(), 6);
    assert_eq!(live.chunks_len(), 3);
    assert!(!live.is_empty());
    for h in [commit, tree, manifest].iter().chain(&chunks) {
        assert!(live.contains(h), "{} must be live", hash::to_hex(h));
    }
    assert!(!live.contains(&orphan));
    // `iter` and `IntoIterator` give the objects, then the chunks.
    let expected: Vec<Hash> = live.objects.iter().chain(&sorted).copied().collect();
    assert_eq!(live.iter().copied().collect::<Vec<_>>(), expected);
    assert_eq!((&live).into_iter().copied().collect::<Vec<_>>(), expected);
    assert!(LiveSet::default().is_empty());
}

#[test]
fn contains_needs_either_part() {
    let live = LiveSet {
        objects: BTreeSet::from([[1u8; 32]]),
        chunks: vec![[2u8; 32]],
    };
    assert!(live.contains(&[1u8; 32]));
    assert!(live.contains(&[2u8; 32]));
    assert!(!live.contains(&[3u8; 32]));
    assert!(!live.contains_chunk(&[1u8; 32]));
    assert!(live.contains_chunk(&[2u8; 32]));
}

#[test]
fn chunks_are_sorted_when_one_manifest_lists_them_out_of_order() {
    let fx = Fx::new();
    let mut chunks = fx.blobs("c", 40);
    chunks.sort_unstable();
    chunks.reverse();
    fx.chunked_file_on_main(&chunks);

    // A floor above the 40 ids means no compaction inside the walk, so the
    // final sort is the only one.
    let live = fx.mark(limits(100, 100, 1000)).unwrap();

    assert_eq!(live.chunks.len(), 40);
    assert!(live.chunks.windows(2).all(|w| w[0] < w[1]));
    for c in &chunks {
        assert!(live.contains(c));
    }
}

#[test]
fn chunks_listed_twice_or_by_two_manifests_count_once() {
    let fx = Fx::new();
    let chunks = fx.blobs("c", 6);
    let first = fx.manifest(&[chunks[0], chunks[1], chunks[2], chunks[1]]);
    let second = fx.manifest(&[chunks[2], chunks[3], chunks[0]]);
    let tree = fx.tree(&[first, second], &[]);
    let commit = fx.commit(tree, vec![], "main");
    fx.branch("main", &commit);

    let live = fx.mark(limits(100, 100, 1000)).unwrap();

    assert_eq!(live.chunks_len(), 4, "c0 to c3 once each");
    assert!(!live.contains(&chunks[4]) && !live.contains(&chunks[5]));
}

#[test]
fn a_chunk_that_is_also_an_object_is_an_object_only() {
    let fx = Fx::new();
    let chunks = fx.blobs("c", 3);
    // `chunks[0]` is also a file of the tree, and `chunks[1]` is staged.
    let manifest = fx.manifest(&chunks);
    let tree = fx.tree(&[manifest, chunks[0]], &[]);
    let commit = fx.commit(tree, vec![], "main");
    fx.branch("main", &commit);
    index::write_index(
        &fx.layout,
        &Index::from_entries(vec![index_entry("staged", chunks[1])]),
    )
    .unwrap();

    let live = fx.mark(MarkLimits::DEFAULT).unwrap();

    assert!(live.objects.contains(&chunks[0]) && live.objects.contains(&chunks[1]));
    assert_eq!(live.chunks, vec![chunks[2]]);
    assert_eq!(live.len(), 6, "commit, tree, manifest and three blobs");
    assert!(live.chunks.iter().all(|c| !live.objects.contains(c)));
}

fn index_entry(path: &str, object_hash: Hash) -> IndexEntry {
    IndexEntry {
        path: path.into(),
        status: EntryStatus::Blob,
        object_hash,
        mtime_ns: 0,
        size: 0,
        ino: 0,
        ctime_ns: 0,
    }
}

#[test]
fn a_chunk_that_is_an_index_root_is_kept_when_its_manifest_is_unreachable() {
    let fx = Fx::new();
    let chunks = fx.blobs("c", 3);
    let _unreachable_manifest = fx.manifest(&chunks);
    index::write_index(
        &fx.layout,
        &Index::from_entries(vec![index_entry("staged", chunks[1])]),
    )
    .unwrap();

    let report = fx.gc(MarkLimits::DEFAULT, false).unwrap();

    assert!(fx.store.contains(&chunks[1]), "the staged chunk must stay");
    assert!(!fx.store.contains(&chunks[0]) && !fx.store.contains(&chunks[2]));
    assert_eq!((report.live, report.live_chunks), (1, 0));
    fx.assert_closure_readable();
}

#[test]
fn a_manifest_used_as_a_chunk_and_reached_as_a_file_keeps_its_chunks() {
    let fx = Fx::new();
    let inner_chunks = fx.blobs("inner", 3);
    let inner = fx.manifest(&inner_chunks);
    let outer_chunks = fx.blobs("outer", 2);
    // `outer` lists `inner` as a chunk, and the tree also holds `inner` as a
    // file, so the walk reaches `inner` in full.
    let outer = fx.manifest(&[outer_chunks[0], inner, outer_chunks[1]]);
    let tree = fx.tree(&[inner, outer], &[]);
    let commit = fx.commit(tree, vec![], "main");
    fx.branch("main", &commit);
    let orphan = fx.blob("orphan");

    let live = fx.mark(MarkLimits::DEFAULT).unwrap();

    assert!(live.objects.contains(&inner) && !live.chunks.contains(&inner));
    assert_eq!(live.chunks_len(), 5);
    assert_eq!(as_set(&live), old_walk(&fx.store, &fx.roots()).unwrap());
    fx.gc(MarkLimits::DEFAULT, false).unwrap();
    assert!(!fx.store.contains(&orphan));
    fx.assert_closure_readable();
}

#[test]
fn a_chunk_that_is_a_delta_is_accepted() {
    let fx = Fx::new();
    let base = fx.blob("base");
    let delta = fx.delta(base);
    let plain = fx.blob("plain");
    fx.chunked_file_on_main(&[plain, delta]);

    let live = fx.mark(MarkLimits::DEFAULT).unwrap();

    assert!(live.chunks.contains(&delta) && live.chunks.contains(&plain));
    assert!(!live.contains(&base), "a delta is a leaf");
}

// ---------------------------------------------------------------------
// The walk
// ---------------------------------------------------------------------

#[test]
fn a_leaf_is_not_read_or_verified() {
    let fx = Fx::new();
    let leaf = fx.blob("a file");
    let tree = fx.tree(&[leaf], &[]);
    let commit = fx.commit(tree, vec![], "main");
    fx.branch("main", &commit);
    // Corrupt the file's bytes after the prologue. Reachability reads only
    // the type, as `live_objects` documents.
    let path = fx.store.path_for(&leaf);
    let mut bytes = fs::read(&path).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(&path, bytes).unwrap();

    let live = fx.mark(MarkLimits::DEFAULT).unwrap();

    assert!(live.contains(&leaf));
}

#[test]
fn a_delta_leaf_is_not_read_or_verified() {
    let fx = Fx::new();
    let delta = fx.delta(fx.blob("base"));
    let tree = fx.tree(&[delta], &[]);
    let commit = fx.commit(tree, vec![], "main");
    fx.branch("main", &commit);
    let path = fx.store.path_for(&delta);
    let mut bytes = fs::read(&path).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(&path, bytes).unwrap();

    assert!(fx.mark(MarkLimits::DEFAULT).unwrap().contains(&delta));
}

#[test]
fn history_parents_are_followed() {
    let fx = Fx::new();
    let old_tree = fx.tree(&[fx.blob("old")], &[]);
    let old = fx.commit(old_tree, vec![], "old");
    let new_tree = fx.tree(&[fx.blob("new")], &[]);
    let new = fx.commit(new_tree, vec![old], "new");
    fx.branch("main", &new);

    let live = fx.mark(MarkLimits::DEFAULT).unwrap();

    assert!(live.contains(&old) && live.contains(&old_tree));
}

// ---------------------------------------------------------------------
// Caps
// ---------------------------------------------------------------------

#[test]
fn a_manifest_of_two_thousand_chunks_fits_under_an_object_cap_of_three() {
    let fx = Fx::new();
    let chunks = fx.blobs("c", 2000);
    fx.chunked_file_on_main(&chunks);
    let orphan = fx.blob("orphan");

    let report = fx.gc(limits(3, 10_000, 64), false).unwrap();

    assert_eq!(report.live, 3 + 2000);
    assert_eq!(report.live_chunks, 2000);
    assert!(!fx.store.contains(&orphan));
    for c in &chunks {
        assert!(fx.store.contains(c));
    }
    fx.assert_closure_readable();
}

#[test]
fn three_objects_fail_a_cap_of_two_and_nothing_is_pruned() {
    let fx = Fx::new();
    let file = fx.blob("file");
    let tree = fx.tree(&[file], &[]);
    let commit = fx.commit(tree, vec![], "main");
    fx.branch("main", &commit);
    let orphan = fx.blob("orphan");
    let before = fx.snapshot();

    assert!(matches!(
        fx.mark(limits(2, 100, 64)),
        Err(GcRootsError::Truncated)
    ));
    assert!(matches!(
        fx.gc(limits(2, 100, 64), false),
        Err(GcRootsError::Truncated)
    ));
    assert_eq!(fx.snapshot(), before);
    assert!(fx.store.contains(&orphan));

    // A cap equal to the count passes, and one below fails.
    assert_eq!(fx.mark(limits(3, 100, 64)).unwrap().objects.len(), 3);
    assert!(fx.mark(limits(2, 100, 64)).is_err());
    fx.gc(limits(3, 100, 64), false).unwrap();
    assert!(!fx.store.contains(&orphan));
    fx.assert_closure_readable();
}

#[test]
fn an_object_reached_twice_counts_once_toward_the_cap() {
    let fx = Fx::new();
    let file = fx.blob("file");
    // Two entries name the one blob, so the walk pops it twice.
    let tree = fx.tree(&[file, file], &[]);
    let commit = fx.commit(tree, vec![], "main");
    fx.branch("main", &commit);

    let live = fx.mark(limits(3, 100, 64)).unwrap();

    assert_eq!(live.objects.len(), 3);
}

#[test]
fn a_chunk_cap_below_the_distinct_chunks_fails_closed() {
    let fx = Fx::new();
    let chunks = fx.blobs("c", 5);
    fx.chunked_file_on_main(&chunks);
    let orphan = fx.blob("orphan");
    let before = fx.snapshot();

    for floor in [1, 2, 1000] {
        match fx.mark(limits(100, 4, floor)) {
            Err(GcRootsError::TooManyChunks { count: 5, cap: 4 }) => {}
            other => panic!("floor {floor}: {other:?}"),
        }
        assert!(matches!(
            fx.gc(limits(100, 4, floor), false),
            Err(GcRootsError::TooManyChunks { .. })
        ));
    }
    assert_eq!(fx.snapshot(), before);
    assert!(fx.store.contains(&orphan));
    // The cap itself passes.
    assert_eq!(fx.mark(limits(100, 5, 1)).unwrap().chunks_len(), 5);
}

#[test]
fn the_chunk_cap_counts_distinct_ids_not_listed_ones() {
    let fx = Fx::new();
    let chunks = fx.blobs("c", 3);
    let listed: Vec<Hash> = (0..30).map(|i| chunks[i % 3]).collect();
    fx.chunked_file_on_main(&listed);

    for floor in [1, 4, 1000] {
        let live = fx.mark(limits(100, 3, floor)).unwrap();
        assert_eq!(live.chunks_len(), 3);
    }
}

#[test]
fn the_error_text_says_chunks_are_not_counted() {
    let text = GcRootsError::Truncated.to_string();
    assert!(text.contains("chunks are not counted"), "{text}");
    assert!(text.contains("10000000"), "{text}");
}

// ---------------------------------------------------------------------
// The chunk id buffer
// ---------------------------------------------------------------------

fn id(n: u32) -> Hash {
    hash::hash(&n.to_le_bytes())
}

#[test]
fn the_buffer_compacts_before_it_grows_past_the_threshold() {
    let mut ids = ChunkIds::new(4, usize::MAX);
    let same = [id(1), id(2), id(3)];
    for _ in 0..100 {
        ids.extend(&same).unwrap();
        // Three distinct ids give a threshold of max(2 × 3, 4) = 6.
        assert!(ids.ids.len() <= 6, "grew to {}", ids.ids.len());
    }
    ids.compact().unwrap();
    let mut expected = same.to_vec();
    expected.sort_unstable();
    assert_eq!(ids.ids, expected);
}

#[test]
fn the_buffer_stays_within_the_floor_before_its_first_compaction() {
    let mut ids = ChunkIds::new(8, usize::MAX);
    // Four copies of three ids: 12 ids, over the floor of 8, so one
    // compaction ran.
    for _ in 0..4 {
        ids.extend(&[id(1), id(2), id(3)]).unwrap();
    }
    assert!(ids.ids.len() <= 8);
    assert_eq!(ids.settled, 3, "a compaction ran");
    // Under the floor nothing compacts: two copies fit.
    let mut ids = ChunkIds::new(8, usize::MAX);
    ids.extend(&[id(1), id(2), id(3)]).unwrap();
    ids.extend(&[id(1), id(2), id(3)]).unwrap();
    assert_eq!(ids.ids.len(), 6);
    assert_eq!(ids.settled, 0, "no compaction ran");
}

#[test]
fn distinct_ids_double_the_threshold_instead_of_compacting_every_append() {
    let mut ids = ChunkIds::new(4, usize::MAX);
    let mut compactions = 0;
    let mut settled = 0;
    for n in 0..4096 {
        ids.extend(&[id(n)]).unwrap();
        if ids.settled != settled {
            settled = ids.settled;
            compactions += 1;
        }
    }
    assert!(compactions <= 12, "{compactions} compactions for 4096 ids");
    ids.compact().unwrap();
    assert_eq!(ids.ids.len(), 4096);
    assert!(ids.ids.windows(2).all(|w| w[0] < w[1]));
}

#[test]
fn the_buffer_refuses_past_its_cap_at_a_compaction() {
    let mut ids = ChunkIds::new(1, 2);
    ids.extend(&[id(1), id(2)]).unwrap();
    // The compaction before this append finds two ids, which fit.
    ids.extend(&[id(3), id(4)]).unwrap();
    // The one before this append finds four.
    assert!(matches!(
        ids.extend(&[id(5)]),
        Err(GcRootsError::TooManyChunks { count: 4, cap: 2 })
    ));
    // A compaction of exactly the cap passes.
    let mut ids = ChunkIds::new(1, 2);
    ids.extend(&[id(1), id(2), id(2)]).unwrap();
    ids.compact().unwrap();
    ids.extend(&[id(3)]).unwrap();
    assert!(matches!(
        ids.compact(),
        Err(GcRootsError::TooManyChunks { count: 3, cap: 2 })
    ));
}

#[test]
fn duplicates_that_span_two_compactions_collapse() {
    let fx = Fx::new();
    let chunks = fx.blobs("c", 12);
    // Four manifests with overlapping runs, so ids repeat across the
    // compactions that the floor of 4 forces.
    let runs: [&[usize]; 4] = [
        &[0, 1, 2, 3, 4],
        &[3, 4, 5, 6, 7, 0],
        &[6, 7, 8, 9, 10, 1, 2],
        &[9, 10, 11, 0, 5],
    ];
    let manifests: Vec<Hash> = runs
        .iter()
        .map(|run| fx.manifest(&run.iter().map(|i| chunks[*i]).collect::<Vec<_>>()))
        .collect();
    let tree = fx.tree(&manifests, &[]);
    let commit = fx.commit(tree, vec![], "main");
    fx.branch("main", &commit);

    for floor in [1, 2, 4, 7, 1000] {
        let live = fx.mark(limits(100, 100, floor)).unwrap();
        let mut expected = chunks.clone();
        expected.sort_unstable();
        assert_eq!(live.chunks, expected, "floor {floor}");
        assert_eq!(as_set(&live), old_walk(&fx.store, &fx.roots()).unwrap());
    }
}

// ---------------------------------------------------------------------
// Fail closed
// ---------------------------------------------------------------------

/// gc errors, deletes nothing, and an unreachable orphan survives.
fn assert_gc_refuses(fx: &Fx, orphan: &Hash, expected: impl Fn(&GcRootsError) -> bool) {
    let before = fx.snapshot();
    for dry_run in [false, true] {
        let err = fx.gc(MarkLimits::DEFAULT, dry_run).unwrap_err();
        assert!(expected(&err), "unexpected error: {err:?}");
    }
    assert_eq!(fx.snapshot(), before, "gc changed the store");
    assert!(fx.store.contains(orphan));
}

#[test]
fn a_missing_chunk_aborts_gc_before_any_delete() {
    let fx = Fx::new();
    let chunks = fx.blobs("c", 4);
    fx.chunked_file_on_main(&chunks);
    let orphan = fx.blob("orphan");
    fs::remove_file(fx.store.path_for(&chunks[2])).unwrap();

    assert_gc_refuses(&fx, &orphan, |e| {
        matches!(e, GcRootsError::Store(StoreError::ObjectNotFound(_)))
    });
}

#[test]
fn a_corrupted_manifest_aborts_gc_before_any_delete() {
    let fx = Fx::new();
    let chunks = fx.blobs("c", 4);
    let (_, _, manifest) = fx.chunked_file_on_main(&chunks);
    let orphan = fx.blob("orphan");
    let path = fx.store.path_for(&manifest);
    let mut bytes = fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(&path, bytes).unwrap();

    assert_gc_refuses(&fx, &orphan, |e| matches!(e, GcRootsError::Store(_)));
}

#[test]
fn a_tree_used_as_a_chunk_aborts_gc_and_names_its_manifest() {
    let fx = Fx::new();
    let chunks = fx.blobs("c", 2);
    let not_a_chunk = fx.tree(&[fx.blob("inside")], &[]);
    // Build manifests until one that lists only good chunks has a lower hash
    // than the bad one, so a search by hash order passes it first.
    let bad = fx.manifest(&[chunks[0], not_a_chunk, chunks[1]]);
    let mut good = Vec::new();
    for i in 0.. {
        let g = fx.manifest(&[fx.blob(&format!("good-{i}"))]);
        good.push(g);
        if g < bad {
            break;
        }
    }
    let mut files = good;
    files.push(bad);
    let tree = fx.tree(&files, &[]);
    let commit = fx.commit(tree, vec![], "main");
    fx.branch("main", &commit);
    let orphan = fx.blob("orphan");

    assert_gc_refuses(&fx, &orphan, |e| {
        matches!(e, GcRootsError::ChunkNotBlob { manifest, chunk }
            if *manifest == bad && *chunk == not_a_chunk)
    });
    let text = fx.gc(MarkLimits::DEFAULT, false).unwrap_err().to_string();
    assert!(text.contains(&hash::to_hex(&bad)) && text.contains(&hash::to_hex(&not_a_chunk)));
}

#[test]
fn a_commit_or_a_manifest_used_as_a_chunk_aborts_gc() {
    for kind in ["commit", "manifest"] {
        let fx = Fx::new();
        let plain = fx.blob("plain");
        let other = if kind == "commit" {
            let t = fx.tree(&[], &[]);
            fx.commit(t, vec![], "not a chunk")
        } else {
            fx.manifest(&[plain])
        };
        // `other` is listed as a chunk and reached no other way.
        fx.chunked_file_on_main(&[plain, other]);
        let orphan = fx.blob("orphan");

        assert_gc_refuses(
            &fx,
            &orphan,
            |e| matches!(e, GcRootsError::ChunkNotBlob { chunk, .. } if *chunk == other),
        );
    }
}

#[test]
fn the_type_check_ends_before_the_first_delete() {
    // The bad chunk is found by the last step of the mark. Orphans in many
    // shards stay.
    let fx = Fx::new();
    let tree_chunk = fx.tree(&[], &[]);
    fx.chunked_file_on_main(&[tree_chunk]);
    let orphans = fx.blobs("orphan", 64);
    let before = fx.snapshot();

    assert!(fx.gc(MarkLimits::DEFAULT, false).is_err());

    assert_eq!(fx.snapshot(), before);
    for o in &orphans {
        assert!(fx.store.contains(o));
    }
}

// ---------------------------------------------------------------------
// The sweep
// ---------------------------------------------------------------------

#[test]
fn the_report_counts_live_chunks() {
    let fx = Fx::new();
    let chunks = fx.blobs("c", 7);
    fx.chunked_file_on_main(&chunks);
    let _orphans = fx.blobs("orphan", 5);

    let report = fx.gc(MarkLimits::DEFAULT, false).unwrap();

    assert_eq!(report.live, 3 + 7);
    assert_eq!(report.live_chunks, 7);
    assert_eq!(report.pruned, 5);
    assert_eq!(report.scanned, 3 + 7 + 5);
    fx.assert_closure_readable();
}

#[test]
fn a_dry_run_and_a_real_run_share_their_candidates() {
    // Two stores with the same content, so the same ids.
    let build = || {
        let fx = Fx::new();
        let chunks = fx.blobs("c", 30);
        fx.chunked_file_on_main(&chunks);
        fx.blobs("orphan", 20);
        let m = fx.manifest(&fx.blobs("lost", 4));
        (fx, m)
    };
    let (dry, _) = build();
    let (real, _) = build();
    assert_eq!(dry.listing(), real.listing());
    let listed = real.listing();

    let mut dry_candidates = Vec::new();
    let dry_report = run_gc_with_hook(
        &dry.store,
        &dry.layout,
        NOW,
        0,
        true,
        MarkLimits::DEFAULT,
        |h| dry_candidates.push(*h),
    )
    .unwrap();
    let mut real_candidates = Vec::new();
    let real_report = run_gc_with_hook(
        &real.store,
        &real.layout,
        NOW,
        0,
        false,
        MarkLimits::DEFAULT,
        |h| real_candidates.push(*h),
    )
    .unwrap();

    assert_eq!(dry.listing(), listed, "the dry run deleted something");
    dry_candidates.sort_unstable();
    real_candidates.sort_unstable();
    assert_eq!(dry_candidates, real_candidates);
    let removed: Vec<Hash> = listed.difference(&real.listing()).copied().collect();
    assert_eq!(removed, real_candidates);
    assert_eq!(dry_report.pruned, real_report.pruned);
    assert_eq!(dry_report.bytes_reclaimed, real_report.bytes_reclaimed);
    assert_eq!(real_report.pruned, 20 + 5);
    assert!(dry_report.dry_run && !real_report.dry_run);
    dry.assert_closure_readable();
    real.assert_closure_readable();
}

#[test]
fn the_sweep_visits_every_shard() {
    let fx = Fx::new();
    let (commit, _, _) = fx.chunked_file_on_main(&fx.blobs("c", 3));
    // Enough orphans that most of the 256 shards hold some.
    let orphans = fx.blobs("orphan", 1500);
    let shards: BTreeSet<u8> = orphans.iter().map(|h| h[0]).collect();
    assert!(shards.len() > 200);

    let report = fx.gc(MarkLimits::DEFAULT, false).unwrap();

    assert_eq!(report.pruned, 1500);
    assert!(fx.store.contains(&commit));
    for o in &orphans {
        assert!(!fx.store.contains(o));
    }
    fx.assert_closure_readable();
}

// ---------------------------------------------------------------------
// The oracle
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Spec {
    pool: usize,
    manifests: Vec<Vec<u8>>,
    trees: Vec<Vec<u8>>,
    commits: Vec<(u8, u8)>,
    heads: Vec<u8>,
    index: Vec<u8>,
    stash: Vec<u8>,
    orig_head: Option<u8>,
    /// Let a manifest list any object, so the new mark may refuse a
    /// repository that the old walk accepts.
    weird: bool,
    floor: usize,
}

fn spec() -> impl Strategy<Value = Spec> {
    let selectors = |max_len| prop::collection::vec(any::<u8>(), 0..max_len);
    (
        1usize..=10,
        prop::collection::vec(selectors(8), 0..6),
        prop::collection::vec(selectors(6), 1..6),
        prop::collection::vec((any::<u8>(), any::<u8>()), 0..6),
        selectors(4),
        selectors(4),
        selectors(3),
        prop::option::of(any::<u8>()),
        prop::bool::weighted(0.25),
        1usize..=8,
    )
        .prop_map(
            |(pool, manifests, trees, commits, heads, index, stash, orig_head, weird, floor)| {
                Spec {
                    pool,
                    manifests,
                    trees,
                    commits,
                    heads,
                    index,
                    stash,
                    orig_head,
                    weird,
                    floor,
                }
            },
        )
}

fn pick(items: &[Hash], selector: u8) -> Option<Hash> {
    (!items.is_empty()).then(|| items[usize::from(selector) % items.len()])
}

/// The objects of a built spec, by kind.
struct Graph {
    pool: Vec<Hash>,
    manifests: Vec<Hash>,
    trees: Vec<Hash>,
    commits: Vec<Hash>,
    /// A manifest that may list trees, built only for a weird spec.
    extra: Vec<Hash>,
}

/// Write the objects of a spec. Objects that no root reaches stay in the
/// store as orphans.
fn build_objects(fx: &Fx, spec: &Spec) -> Graph {
    let mut pool = fx.blobs("pool", spec.pool);
    // A delta is a leaf and may be a chunk.
    pool.push(fx.delta(pool[0]));
    let mut manifests: Vec<Hash> = Vec::new();
    for selectors in &spec.manifests {
        // Chunks come from the shared pool. A weird manifest also lists
        // earlier manifests.
        let candidates: Vec<Hash> = if spec.weird {
            pool.iter().chain(&manifests).copied().collect()
        } else {
            pool.clone()
        };
        let chunks: Vec<Hash> = selectors
            .iter()
            .filter_map(|s| pick(&candidates, *s))
            .collect();
        manifests.push(fx.manifest(&chunks));
    }
    let mut trees: Vec<Hash> = Vec::new();
    for selectors in &spec.trees {
        // The pool ids are also files of the trees.
        let files: Vec<Hash> = pool.iter().chain(&manifests).copied().collect();
        let mut chosen_files = Vec::new();
        let mut chosen_trees = Vec::new();
        for s in selectors {
            if s % 4 == 0 {
                chosen_trees.extend(pick(&trees, s / 4));
            } else {
                chosen_files.extend(pick(&files, *s));
            }
        }
        trees.push(fx.tree(&chosen_files, &chosen_trees));
    }
    let mut extra = Vec::new();
    if spec.weird {
        // A manifest that lists trees too, which only an index root or a
        // file can reach.
        let candidates: Vec<Hash> = pool
            .iter()
            .chain(&manifests)
            .chain(&trees)
            .copied()
            .collect();
        let flat: Vec<u8> = spec.manifests.iter().flatten().copied().collect();
        let chunks: Vec<Hash> = flat.iter().filter_map(|s| pick(&candidates, *s)).collect();
        extra.push(fx.manifest(&chunks));
    }
    let mut commits: Vec<Hash> = Vec::new();
    for (i, (parent, tree)) in spec.commits.iter().enumerate() {
        let parents = if parent % 3 == 0 {
            vec![]
        } else {
            pick(&commits, *parent).into_iter().collect()
        };
        let tree = pick(&trees, *tree).expect("a spec has a tree");
        commits.push(fx.commit(tree, parents, &format!("commit-{i}")));
    }
    fx.blobs("orphan", 3);
    Graph {
        pool,
        manifests,
        trees,
        commits,
        extra,
    }
}

/// Write the roots of a spec: branches, the index, the stash and `ORIG_HEAD`.
fn write_roots(fx: &Fx, spec: &Spec, graph: &Graph) {
    for (i, s) in spec.heads.iter().enumerate() {
        if let Some(c) = pick(&graph.commits, *s) {
            fx.branch(&format!("b{i}"), &c);
        }
    }
    let indexable: Vec<Hash> = [&graph.pool, &graph.manifests, &graph.trees, &graph.extra]
        .into_iter()
        .flatten()
        .copied()
        .collect();
    let entries: Vec<IndexEntry> = spec
        .index
        .iter()
        .enumerate()
        .filter_map(|(i, s)| pick(&indexable, *s).map(|h| index_entry(&format!("f{i:03}"), h)))
        .collect();
    index::write_index(&fx.layout, &Index::from_entries(entries)).unwrap();
    let stash_entries: Vec<stash::StashEntry> = spec
        .stash
        .iter()
        .filter_map(|s| pick(&graph.commits, *s))
        .map(|c| stash::StashEntry {
            commit_hash: c,
            parent_hash: c,
            timestamp: 0,
            message: "s".into(),
        })
        .collect();
    stash::write_list_test_only(
        &fx.layout,
        &stash::StashList {
            entries: stash_entries,
        },
    );
    if let Some(c) = spec.orig_head.and_then(|s| pick(&graph.commits, s)) {
        fs::write(
            fx.layout.orig_head_file(),
            format!("{}\n", hash::to_hex(&c)),
        )
        .unwrap();
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// The new live set equals the old one-set walk, or the new mark refuses
    /// and the store stays byte-identical. A gc at grace 0 prunes exactly the
    /// listing minus the old set, and everything the old walk reaches can
    /// still be read afterwards.
    #[test]
    fn the_mark_equals_the_old_walk_or_refuses_and_deletes_nothing(spec in spec()) {
        let fx = Fx::new();
        write_roots(&fx, &spec, &build_objects(&fx, &spec));
        let roots = fx.roots();
        let old = old_walk(&fx.store, &roots).unwrap();
        let before = fx.snapshot();
        let injected = limits(MAX_REACHABLE, MAX_LIVE_CHUNKS, spec.floor);

        let new = mark_live(&fx.store, &roots, injected);
        let swept = fx.gc(injected, false);
        if let Ok(live) = new {
            prop_assert_eq!(as_set(&live), old.clone());
            prop_assert_eq!(live.len(), old.len(), "an id counted twice");
            prop_assert!(live.chunks.windows(2).all(|w| w[0] < w[1]));
            prop_assert!(live.chunks.iter().all(|c| !live.objects.contains(c)));
            let report = swept.unwrap();
            let listed: BTreeSet<Hash> = before.keys().copied().collect();
            let expected: BTreeSet<Hash> = listed.difference(&old).copied().collect();
            let removed: BTreeSet<Hash> = listed.difference(&fx.listing()).copied().collect();
            prop_assert_eq!(removed, expected.clone());
            prop_assert_eq!(report.pruned, expected.len());
            prop_assert_eq!(report.live, old.len());
            prop_assert_eq!(report.live_chunks, live.chunks_len());
            for h in &old {
                prop_assert!(fx.store.read(h).is_ok(), "live object lost");
            }
        } else {
            prop_assert!(spec.weird, "a repository of blob chunks was refused");
            prop_assert!(swept.is_err());
            prop_assert_eq!(fx.snapshot(), before);
        }
    }
}

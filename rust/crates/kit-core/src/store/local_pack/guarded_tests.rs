//! A walk that holds the prune guard checks each local pair once.

use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::hash::Hash;
use crate::layout::RepoLayout;
use crate::object::{Object, ObjectType};
use crate::ops::graph::check_closure_present_observed_from;
use crate::serialize::serialize;
use crate::store::{ClosureSource, ObjectSource, ObjectStore, StoreError, StoreResult};

use super::tests::{blob, cut_pack_short, fresh, publish_objects};
use super::{Locator, Pair, index};

const CHUNK: usize = 4096;

fn chunk(n: usize) -> Vec<u8> {
    let mut data = vec![7; CHUNK];
    data[..8].copy_from_slice(&(n as u64).to_le_bytes());
    blob(&data)
}

/// One pair holding the chunks `range` names.
fn publish_chunks(store: &ObjectStore, range: std::ops::Range<usize>) -> (Pair, Vec<Hash>) {
    let objects: Vec<_> = range.map(chunk).collect();
    let refs: Vec<&[u8]> = objects.iter().map(Vec::as_slice).collect();
    publish_objects(store, &refs)
}

/// A manifest of these chunks, each as long as `CHUNK`.
fn manifest(store: &ObjectStore, chunks: &[Hash]) -> Hash {
    let entries = chunks.iter().map(|&id| (id, CHUNK as u64)).collect();
    let bytes = serialize(&Object::ChunkedBlob(
        crate::object::testing::sized(0, entries).unwrap(),
    ))
    .unwrap();
    store.write(&bytes).unwrap()
}

fn walk(source: &(impl ClosureSource + ?Sized), root: &Hash) -> Result<bool, StoreError> {
    check_closure_present_observed_from(source, root, &|_| {})
}

/// Every locator the store holds, in no order.
fn locators(store: &ObjectStore) -> Vec<Arc<Locator>> {
    let discovery = store.packs.discovery.lock().unwrap();
    let mut all = discovery.catalog.packs.clone();
    all.extend(discovery.latest.clone());
    all
}

fn checks(locator: &Locator) -> usize {
    locator.checks.load(Ordering::Relaxed)
}

/// A store handle whose catalog probes the index files, or holds their rows.
fn reader(layout: &RepoLayout, probing: bool) -> ObjectStore {
    let store = ObjectStore::open(layout).unwrap();
    if !probing {
        store.packs.discovery.lock().unwrap().budgets =
            Some((super::ROW_CACHE_BYTES, super::ROUTE_CACHE_BYTES));
    }
    store
}

/// Three pairs of 40 chunks, and a manifest of the 120.
fn three_pairs() -> (tempfile::TempDir, RepoLayout, Hash, Vec<Pair>, Vec<Hash>) {
    let (dir, layout, store) = fresh();
    let mut pairs = Vec::new();
    let mut chunks = Vec::new();
    for start in [0, 40, 80] {
        let (pair, ids) = publish_chunks(&store, start..start + 40);
        pairs.push(pair);
        chunks.extend(ids);
    }
    let root = manifest(&store, &chunks);
    (dir, layout, root, pairs, chunks)
}

#[test]
fn a_guarded_walk_checks_each_pair_at_most_twice_and_an_unguarded_one_checks_each_read() {
    let (_dir, layout, root, _, chunks) = three_pairs();

    for probing in [true, false] {
        // 120 chunk heads, so the reads run on several threads.
        let guarded = reader(&layout, probing);
        let guard = guarded.prune_guard().unwrap();
        let view = guarded.guarded(&guard).unwrap();
        assert!(!walk(&view, &root).unwrap());
        let counts: Vec<_> = locators(&guarded).iter().map(|l| checks(l)).collect();
        assert_eq!(counts.len(), 3);
        assert!(
            counts.iter().all(|&n| (1..=2).contains(&n)),
            "each pair is checked, and not for each read: {counts:?}"
        );

        let plain = reader(&layout, probing);
        assert!(!walk(&plain, &root).unwrap());
        let counts: Vec<_> = locators(&plain).iter().map(|l| checks(l)).collect();
        assert!(
            counts.iter().all(|&n| n >= 40),
            "an unguarded walk checks at every read: {counts:?} for {} chunks",
            chunks.len()
        );
    }
}

#[test]
fn a_guarded_walk_checks_a_locator_again_after_it_fails_a_read() {
    let (_dir, layout, _, pairs, chunks) = three_pairs();
    let reader = ObjectStore::open(&layout).unwrap();
    let guard = reader.prune_guard().unwrap();
    let view = reader.guarded(&guard).unwrap();
    view.object_head(&chunks[0]).unwrap();
    let serving = locators(&reader)
        .into_iter()
        .find(|l| l.pair.key == pairs[0].key)
        .unwrap();
    view.object_head(&chunks[1]).unwrap();
    assert_eq!(checks(&serving), 1);

    // A frame the pair cannot read. The pair is checked again at once, as
    // every read of it did before.
    let before = checks(&serving);
    super::tests::damage_header(&pairs[0], &chunks[2], 0, |byte| *byte = 9);
    let error = view.object_head(&chunks[2]).unwrap_err();
    assert!(
        matches!(error, StoreError::LocalPackDamaged { .. }),
        "{error:?}"
    );
    let after = checks(&serving);
    assert!(after > before);

    // And at the next read, which a pair that failed no longer vouches for.
    view.object_head(&chunks[3]).unwrap();
    assert!(checks(&serving) > after);
}

#[test]
fn a_pair_retired_or_replaced_before_the_guard_is_caught_at_the_first_use() {
    for (retire, probing) in [(true, true), (false, true), (true, false), (false, false)] {
        let (_dir, layout, root, pairs, _) = three_pairs();
        let reader = reader(&layout, probing);
        // Catalog and handles are warm.
        assert!(!walk(&reader, &root).unwrap());
        let (pack, index) = (
            fs::read(&pairs[1].pack).unwrap(),
            fs::read(&pairs[1].index).unwrap(),
        );
        fs::remove_file(&pairs[1].index).unwrap();
        fs::remove_file(&pairs[1].pack).unwrap();
        if !retire {
            // The same pair, in new files.
            fs::write(&pairs[1].pack, &pack).unwrap();
            fs::write(&pairs[1].index, &index).unwrap();
        }
        let guard = reader.prune_guard().unwrap();
        let view = reader.guarded(&guard).unwrap();
        let guarded = walk(&view, &root).map_err(|e| format!("{e:?}"));
        let plain = walk(&ObjectStore::open(&layout).unwrap(), &root).map_err(|e| format!("{e:?}"));
        assert_eq!(guarded, plain);
        assert_eq!(guarded.is_err(), retire, "{guarded:?}");
    }
}

/// A source that runs `hook` before its `at`th read of a head.
struct Hooked<'a> {
    inner: &'a dyn ClosureSource,
    calls: AtomicUsize,
    at: usize,
    hook: Mutex<Option<Box<dyn FnOnce() + Send + 'a>>>,
}

impl<'a> Hooked<'a> {
    fn new(inner: &'a dyn ClosureSource, at: usize, hook: impl FnOnce() + Send + 'a) -> Self {
        Self {
            inner,
            calls: AtomicUsize::new(0),
            at,
            hook: Mutex::new(Some(Box::new(hook))),
        }
    }

    fn tick(&self) {
        if self.calls.fetch_add(1, Ordering::SeqCst) + 1 == self.at
            && let Some(hook) = self.hook.lock().unwrap().take()
        {
            hook();
        }
    }
}

impl ObjectSource for Hooked<'_> {
    fn read(&self, h: &Hash) -> StoreResult<Vec<u8>> {
        self.inner.read(h)
    }

    fn read_object(&self, h: &Hash) -> StoreResult<Object> {
        self.inner.read_object(h)
    }
}

impl ClosureSource for Hooked<'_> {
    fn object_type(&self, h: &Hash) -> StoreResult<ObjectType> {
        self.tick();
        self.inner.object_type(h)
    }

    fn object_head(&self, h: &Hash) -> StoreResult<(ObjectType, Option<u64>)> {
        self.tick();
        self.inner.object_head(h)
    }
}

/// Damage a pair in place and then publish it again, so the verified copy
/// replaces the damaged one under the same key.
fn damage_then_repair(store: &ObjectStore, pair: &Pair, damage: impl FnOnce(&Pair)) {
    let objects: Vec<_> = (0..8).map(chunk).collect();
    let refs: Vec<&[u8]> = objects.iter().map(Vec::as_slice).collect();
    damage(pair);
    let (published, _) = publish_objects(store, &refs);
    assert_eq!(published.key, pair.key);
}

#[test]
fn a_damaged_pack_or_a_mismatched_index_replaced_in_the_middle_of_a_walk_does_not_fail_it() {
    for damage_pack in [true, false] {
        let (_dir, layout, store) = fresh();
        let (pair, chunks) = publish_chunks(&store, 0..8);
        let root = manifest(&store, &chunks);

        for guarded in [false, true] {
            let reader = ObjectStore::open(&layout).unwrap();
            let guard = reader.prune_guard().unwrap();
            let view = reader.guarded(&guard).unwrap();
            let source: &dyn ClosureSource = if guarded { &view } else { &reader };
            // The third read of a head finds the pair damaged, then replaced.
            let hooked = Hooked::new(source, 3, || {
                damage_then_repair(&store, &pair, |pair| {
                    if damage_pack {
                        super::tests::damage_header(pair, &chunks[5], 0, |byte| *byte = 9);
                    } else {
                        damage_row_len(pair, &chunks, 5);
                    }
                });
                // A directory scan right after the replacement can see the
                // directory unchanged, within one tick of the filesystem clock.
                let dir = fs::symlink_metadata(reader.pack_dir()).unwrap();
                let mut discovery = reader.packs.discovery.lock().unwrap();
                discovery.dir = Some(index::Stamp::get(&dir).unwrap());
                discovery.scanned = true;
            });
            assert!(!walk(&hooked, &root).unwrap(), "guarded: {guarded}");
            if guarded {
                // The refresh gave the pair a new locator, which was checked.
                let held: Vec<_> = locators(&reader)
                    .into_iter()
                    .filter(|l| l.pair.key == pair.key)
                    .collect();
                assert!(!held.is_empty() && held.iter().all(|l| checks(l) >= 1));
            }
        }
    }
}

/// Change the length the index records for chunk `n`.
fn damage_row_len(pair: &Pair, chunks: &[Hash], n: usize) {
    let mut ids = chunks.to_vec();
    ids.sort_unstable();
    let row = ids.iter().position(|id| *id == chunks[n]).unwrap();
    let mut bytes = fs::read(&pair.index).unwrap();
    let at = index::FANOUT_END + ids.len() * 40 + row * 4;
    bytes[at] ^= 1;
    fs::write(&pair.index, bytes).unwrap();
}

#[test]
fn a_catalog_refreshed_in_the_middle_of_a_walk_gives_locators_that_are_checked() {
    let (_dir, layout, store) = fresh();
    let (_, first) = publish_chunks(&store, 0..8);
    let later = publish_chunks(&store, 8..16);
    // The second pair is not there yet when the walk starts.
    let held =
        |path: &std::path::Path| std::path::PathBuf::from(format!("{}.held", path.display()));
    fs::rename(&later.0.pack, held(&later.0.pack)).unwrap();
    fs::rename(&later.0.index, held(&later.0.index)).unwrap();
    let all: Vec<Hash> = first.iter().chain(&later.1).copied().collect();
    let root = manifest(&store, &all);

    let reader = ObjectStore::open(&layout).unwrap();
    let guard = reader.prune_guard().unwrap();
    let view = reader.guarded(&guard).unwrap();
    let hooked = Hooked::new(&view, 9, || {
        fs::rename(held(&later.0.pack), &later.0.pack).unwrap();
        fs::rename(held(&later.0.index), &later.0.index).unwrap();
    });
    assert!(!walk(&hooked, &root).unwrap());
    let fresh_locator = locators(&reader)
        .into_iter()
        .find(|l| l.pair.key == later.0.key)
        .expect("the refresh found the new pair");
    assert!(checks(&fresh_locator) >= 1);
}

#[test]
fn a_pair_replaced_before_a_refresh_gets_a_locator_that_is_checked() {
    let (_dir, layout, store) = fresh();
    let (first, first_ids) = publish_chunks(&store, 0..8);
    let later = publish_chunks(&store, 8..16);
    let held =
        |path: &std::path::Path| std::path::PathBuf::from(format!("{}.held", path.display()));
    fs::rename(&later.0.pack, held(&later.0.pack)).unwrap();
    fs::rename(&later.0.index, held(&later.0.index)).unwrap();
    // Four chunks of the first pair, the second pair, and the first again.
    let order: Vec<Hash> = first_ids[..4]
        .iter()
        .chain(&later.1)
        .chain(&first_ids[4..])
        .copied()
        .collect();
    let root = manifest(&store, &order);

    let reader = reader(&layout, true);
    let guard = reader.prune_guard().unwrap();
    let view = reader.guarded(&guard).unwrap();
    // The first pair is replaced by identical files in new inodes, and the
    // second appears, so the miss that it causes refreshes the catalog.
    let hooked = Hooked::new(&view, 5, || {
        for member in [&first.pack, &first.index] {
            let copy = held(member);
            fs::copy(member, &copy).unwrap();
            fs::rename(&copy, member).unwrap();
        }
        fs::rename(held(&later.0.pack), &later.0.pack).unwrap();
        fs::rename(held(&later.0.index), &later.0.index).unwrap();
    });
    assert!(!walk(&hooked, &root).unwrap());
    let replaced: Vec<_> = locators(&reader)
        .into_iter()
        .filter(|l| l.pair.key == first.key)
        .collect();
    assert_eq!(replaced.len(), 1);
    assert!(
        checks(&replaced[0]) >= 1,
        "the new locator is checked before it is used"
    );
}

/// The two views give the same answer on a damaged store. The test that calls
/// this pins the error each case gives.
fn same_answer(layout: &RepoLayout, root: &Hash) -> String {
    let plain = ObjectStore::open(layout).unwrap();
    let guarded = ObjectStore::open(layout).unwrap();
    let guard = guarded.prune_guard().unwrap();
    let view = guarded.guarded(&guard).unwrap();
    let before = walk(&plain, root).map_err(|e| format!("{e:?}"));
    let after = walk(&view, root).map_err(|e| format!("{e:?}"));
    assert_eq!(before, after);
    format!("{after:?}")
}

#[test]
fn damage_gives_the_same_error_through_a_guarded_walk() {
    // A pack cut short.
    let (_dir, layout, store) = fresh();
    let (pair, chunks) = publish_chunks(&store, 0..8);
    let root = manifest(&store, &chunks);
    cut_pack_short(&pair);
    assert!(same_answer(&layout, &root).contains("invalid index extent"));

    // A frame that is not raw.
    let (_dir, layout, store) = fresh();
    let (pair, chunks) = publish_chunks(&store, 0..8);
    let root = manifest(&store, &chunks);
    super::tests::damage_header(&pair, &chunks[3], 0, |byte| *byte = 9);
    assert!(same_answer(&layout, &root).contains("frame is not raw"));

    // A frame whose length the index and the pack disagree on.
    let (_dir, layout, store) = fresh();
    let (pair, chunks) = publish_chunks(&store, 0..8);
    let root = manifest(&store, &chunks);
    super::tests::damage_header(&pair, &chunks[3], 1, |byte| *byte ^= 1);
    assert!(same_answer(&layout, &root).contains("disagree"));

    // A chunk that is nowhere.
    let (_dir, layout, store) = fresh();
    let (_, mut chunks) = publish_chunks(&store, 0..8);
    chunks.push(*blake3::hash(b"nowhere").as_bytes());
    let root = manifest(&store, &chunks);
    assert!(same_answer(&layout, &root).contains("ObjectNotFound"));

    // A chunk that is not a blob.
    let (_dir, layout, store) = fresh();
    let (_, mut chunks) = publish_chunks(&store, 0..8);
    let tree = serialize(&Object::Tree(crate::object::Tree { entries: vec![] })).unwrap();
    chunks.push(store.write(&tree).unwrap());
    let root = manifest(&store, &chunks);
    assert!(same_answer(&layout, &root).contains("ChunkNotBlob"));

    // A chunk of another length than its span.
    let (_dir, layout, store) = fresh();
    let (_, mut chunks) = publish_chunks(&store, 0..8);
    chunks.push(store.write(&blob(b"short")).unwrap());
    let root = manifest(&store, &chunks);
    assert!(same_answer(&layout, &root).contains("ChunkLengthMismatch"));
}

#[test]
fn gc_and_index_repair_refuse_while_a_guarded_walk_holds_its_guard() {
    use crate::ops::gc::run_gc;

    let (_dir, layout, store) = fresh();
    let (pair, chunks) = publish_chunks(&store, 0..8);
    let root = manifest(&store, &chunks);
    let good = fs::read(&pair.index).unwrap();
    let reader = ObjectStore::open(&layout).unwrap();
    let guard = reader.prune_guard().unwrap();
    let view = reader.guarded(&guard).unwrap();
    assert!(!walk(&view, &root).unwrap());
    run_gc(&store, &layout, u64::MAX, 0, false, &mut |_, _, _| {}).unwrap();
    assert!(pair.pack.exists() && pair.index.exists());
    fs::write(&pair.index, b"damaged").unwrap();
    assert!(store.check_local_packs(true).is_err());
    assert_eq!(fs::read(&pair.index).unwrap(), b"damaged");
    drop(view);
    drop(guard);
    assert_eq!(store.check_local_packs(true).unwrap(), 1);
    assert_eq!(fs::read(&pair.index).unwrap(), good);
}

#[test]
fn a_guard_from_another_store_cannot_make_a_view() {
    let (_dir, _, store) = fresh();
    let (_other_dir, _, other) = fresh();
    let guard = other.prune_guard().unwrap();
    assert!(store.guarded(&guard).is_err());
}

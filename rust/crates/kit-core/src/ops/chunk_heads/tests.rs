//! The parallel walk against a serial loop on random manifests.

use std::collections::BTreeMap;

use proptest::prelude::*;
use tempfile::TempDir;

use super::{LenCache, Tuning, chunk_blob_len, try_each_in_order, walk_chunks};
use crate::hash::{self, Hash};
use crate::object::{Blob, ChunkedBlob, KitError, Object, Tree};
use crate::serialize;
use crate::store::{ObjectStore, StoreError};

/// A length cache with a bound, as the callers have.
#[derive(Debug, Default, PartialEq, Eq)]
struct Cache {
    seen: BTreeMap<Hash, u64>,
    limit: usize,
}

impl LenCache for Cache {
    fn len_of(&self, chunk: &Hash) -> Option<u64> {
        self.seen.get(chunk).copied()
    }

    fn remember(&mut self, chunk: Hash, len: u64) {
        if self.seen.len() < self.limit {
            self.seen.entry(chunk).or_insert(len);
        }
    }
}

/// What the serial loop in the doc comment of `for_each_checked_chunk` does.
fn serial(
    store: &ObjectStore,
    blob: &ChunkedBlob,
    cache: &mut Cache,
    wants_head: impl Fn(u32, &Hash) -> bool,
    mut visit: impl FnMut(&mut Cache, u32, Hash) -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    for (index, chunk) in (0u32..).zip(blob.chunks().iter().copied()) {
        if wants_head(index, &chunk) {
            let len = if let Some(len) = cache.len_of(&chunk) {
                len
            } else {
                let len = chunk_blob_len(store, &chunk, index)?;
                cache.remember(chunk, len);
                len
            };
            blob.check_chunk_length(index, len)?;
        }
        visit(cache, index, chunk)?;
    }
    Ok(())
}

/// Chunks a manifest can list: blobs of known length, a tree (not a blob), and
/// an id the store lacks.
struct Pool {
    _dir: TempDir,
    store: ObjectStore,
    blobs: Vec<(Hash, u64)>,
    tree: Hash,
    missing: Hash,
}

/// The pool the random walks share: 64 blobs, so a round holds many reads.
fn shared_pool() -> &'static Pool {
    static POOL: std::sync::OnceLock<Pool> = std::sync::OnceLock::new();
    POOL.get_or_init(|| pool(64))
}

/// A pool of `count` distinct blobs.
fn pool(count: usize) -> Pool {
    let dir = TempDir::new().unwrap();
    let store = ObjectStore::init(&crate::layout::RepoLayout::single(dir.path())).unwrap();
    let blobs = (0..count)
        .map(|n| {
            let data = format!("chunk-{n}").into_bytes();
            let len = data.len() as u64;
            let bytes = serialize::serialize(&Object::Blob(Blob { data })).unwrap();
            (store.write(&bytes).unwrap(), len)
        })
        .collect();
    let tree = store
        .write(&serialize::serialize(&Object::Tree(Tree { entries: vec![] })).unwrap())
        .unwrap();
    Pool {
        _dir: dir,
        store,
        blobs,
        tree,
        missing: hash::hash(b"no such chunk"),
    }
}

/// One entry of a generated manifest.
#[derive(Debug, Clone, Copy)]
enum Pick {
    /// Blob `n` of the pool, with its real length as the span.
    Good(usize),
    /// Blob `n`, with a span length that is not its length.
    WrongSpan(usize),
    Tree,
    Missing,
}

fn pick() -> impl Strategy<Value = Pick> {
    prop_oneof![
        20 => (0usize..64).prop_map(Pick::Good),
        1 => (0usize..64).prop_map(Pick::WrongSpan),
        1 => Just(Pick::Tree),
        1 => Just(Pick::Missing),
    ]
}

fn manifest(pool: &Pool, picks: &[Pick]) -> ChunkedBlob {
    let count = pool.blobs.len();
    let mut end = 0;
    let entries: Vec<(Hash, u64)> = picks
        .iter()
        .map(|&pick| {
            let (id, len) = match pick {
                Pick::Good(n) => pool.blobs[n % count],
                Pick::WrongSpan(n) => (pool.blobs[n % count].0, pool.blobs[n % count].1 + 1),
                Pick::Tree => (pool.tree, 3),
                Pick::Missing => (pool.missing, 3),
            };
            end += len;
            (id, end)
        })
        .collect();
    ChunkedBlob::new(end, 0, entries).unwrap()
}

/// The outcome of one walk, compared as text: the error, the cache, and the
/// chunks visited.
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    result: String,
    cache: Cache,
    visited: Vec<(u32, Hash)>,
}

fn run(
    walk: impl FnOnce(
        &mut Cache,
        &dyn Fn(u32, &Hash) -> bool,
        &mut Vec<(u32, Hash)>,
    ) -> Result<(), StoreError>,
    limit: usize,
    primed: &[(Hash, u64)],
    skip_every: usize,
) -> Outcome {
    let mut cache = Cache {
        seen: primed.iter().copied().collect(),
        limit,
    };
    let mut visited = Vec::new();
    let wants =
        move |index: u32, _: &Hash| skip_every == 0 || !(index as usize).is_multiple_of(skip_every);
    let result = walk(&mut cache, &wants, &mut visited);
    Outcome {
        result: format!("{result:?}"),
        cache,
        visited,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    /// Whatever the manifest, the window and the cache, the parallel walk
    /// gives the result, the cache and the visits of the serial loop. A bad
    /// chunk sits at a random position, or several do.
    #[test]
    fn parallel_walk_matches_the_serial_loop(
        picks in proptest::collection::vec(pick(), 1..240),
        window in 1usize..90,
        min_parallel_reads in 1usize..6,
        limit in 0usize..40,
        primed in proptest::collection::vec((0usize..64, any::<bool>()), 0..20),
        skip_every in 0usize..4,
        visit_fails_at in proptest::option::of(0u32..240),
    ) {
        let pool = shared_pool();
        let blob = manifest(pool, &picks);
        let primed: Vec<(Hash, u64)> = primed
            .into_iter()
            .map(|(n, honest)| (pool.blobs[n].0, pool.blobs[n].1 + u64::from(!honest)))
            .collect();
        let visit = |visit_fails_at: Option<u32>| {
            move |_: &mut Cache, index: u32, chunk: Hash| {
                if visit_fails_at == Some(index) {
                    return Err(StoreError::ObjectNotFound(hash::to_hex(&chunk)));
                }
                Ok(())
            }
        };
        let expected = run(
            |cache, wants, visited| {
                let fail = visit(visit_fails_at);
                serial(&pool.store, &blob, cache, wants, |c, i, h| {
                    visited.push((i, h));
                    fail(c, i, h)
                })
            },
            limit,
            &primed,
            skip_every,
        );
        let actual = run(
            |cache, wants, visited| {
                let fail = visit(visit_fails_at);
                walk_chunks(
                    &pool.store,
                    &blob,
                    cache,
                    wants,
                    |c, i, h| {
                        visited.push((i, h));
                        fail(c, i, h)
                    },
                    Tuning { window, min_parallel_reads },
                )
            },
            limit,
            &primed,
            skip_every,
        );
        prop_assert_eq!(actual, expected);
    }
}

/// A manifest of 1000 chunks, 300 of them distinct, with one bad chunk at `bad`
/// and a bad chunk of another kind after it, walked in many rounds, each in
/// parallel. The error is the first bad chunk's, whatever the kinds are.
#[test]
fn the_first_bad_chunk_in_manifest_order_is_reported() {
    let pool = pool(300);
    let kinds = [Pick::Missing, Pick::Tree, Pick::WrongSpan(7)];
    for first in kinds {
        for second in kinds {
            for bad in [0usize, 1, 63, 64, 65, 500, 994] {
                let mut picks: Vec<Pick> = (0..1000).map(Pick::Good).collect();
                picks[bad] = first;
                picks[bad + 5] = second;
                let blob = manifest(&pool, &picks);
                let mut cache = Cache {
                    limit: 0,
                    ..Cache::default()
                };
                let error = walk_chunks(
                    &pool.store,
                    &blob,
                    &mut cache,
                    |_, _| true,
                    |_, _, _| Ok(()),
                    Tuning {
                        window: 100,
                        min_parallel_reads: 2,
                    },
                )
                .unwrap_err();
                let right = match first {
                    Pick::Missing => matches!(
                        error,
                        StoreError::ObjectNotFound(ref id) if *id == hash::to_hex(&pool.missing)
                    ),
                    Pick::Tree => matches!(
                        error,
                        StoreError::Decode(KitError::ChunkNotBlob { index }) if index as usize == bad
                    ),
                    _ => matches!(
                        error,
                        StoreError::Decode(KitError::ChunkLengthMismatch { index, .. })
                            if index as usize == bad
                    ),
                };
                assert!(right, "{first:?} at {bad}, then {second:?}: {error:?}");
            }
        }
    }
}

/// The walk reads each distinct chunk of a round once, on the parallel path
/// too, and counts those reads on the calling thread.
#[test]
fn a_round_reads_each_distinct_chunk_once() {
    let pool = pool(300);
    let picks: Vec<Pick> = (0..900).map(|n| Pick::Good(n % 300)).collect();
    let blob = manifest(&pool, &picks);
    let mut cache = Cache {
        limit: 10_000,
        ..Cache::default()
    };
    crate::ops::graph::CHUNK_TYPE_READS.with(|reads| reads.set(0));
    walk_chunks(
        &pool.store,
        &blob,
        &mut cache,
        |_, _| true,
        |_, _, _| Ok(()),
        Tuning {
            window: 450,
            min_parallel_reads: 2,
        },
    )
    .unwrap();
    // 300 distinct chunks, read in the first round and remembered after it.
    assert_eq!(
        crate::ops::graph::CHUNK_TYPE_READS.with(std::cell::Cell::get),
        300
    );
}

/// The checks of `try_each_in_order` run once per item, across windows and on
/// the parallel path, and the error returned is the first in item order.
#[test]
fn try_each_in_order_reports_the_first_error_in_order() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let n = 2 * Tuning::DEFAULT.window + 100;
    let items: Vec<usize> = (0..n).collect();
    let ran = AtomicUsize::new(0);
    try_each_in_order(&items, |_| {
        ran.fetch_add(1, Ordering::Relaxed);
        Ok::<(), usize>(())
    })
    .unwrap();
    assert_eq!(ran.load(Ordering::Relaxed), n);

    let window = Tuning::DEFAULT.window;
    for bad in [0, 1, 63, 64, window - 1, window, n - 1] {
        let error = try_each_in_order(&items, |&i| {
            if i == bad || i == bad + 3 || i == n - 1 {
                Err(i)
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert_eq!(error, bad);
    }
    // A short list runs on the calling thread.
    assert_eq!(
        try_each_in_order(&items[..3], |&i| if i > 0 { Err(i) } else { Ok(()) }),
        Err(1)
    );
}

//! End-to-end restore of one chunked file with every batch read fanned
//! out over rayon. The restore overlaps the write of batch N with the
//! read of batch N+1, so this bench covers the reader-to-writer channel.

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use kit_core::hash::Hash;
use kit_core::layout::RepoLayout;
use kit_core::object::Object;
use kit_core::ops::restore::{RestoreError, RestoreOptions, restore_tree_to_worktree_with};
use kit_core::store::ObjectStore;
use kit_core::worktree;
use rayon::prelude::*;
use tempfile::TempDir;

const FILE_MIB: &[u64] = &[8, 32, 128];

/// Pseudo-random bytes, so FastCDC finds real cut points.
fn fixture(mib: u64) -> Vec<u8> {
    let n = usize::try_from(mib * 1024 * 1024).expect("size fits");
    let mut state: u64 = 0x00C0_FFEE ^ mib;
    (0..n)
        .map(|_| {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            (z & 0xFF) as u8
        })
        .collect()
}

fn build_source(mib: u64) -> (TempDir, ObjectStore, Hash) {
    let src = tempfile::tempdir().expect("tempdir");
    std::fs::write(src.path().join("big.bin"), fixture(mib)).expect("write fixture");
    let store_dir = tempfile::tempdir().expect("tempdir");
    let store = ObjectStore::init(&RepoLayout::single(store_dir.path())).expect("init store");
    let batch = store.batch();
    let tree = worktree::build_tree(&batch, src.path()).expect("build tree");
    batch.commit().expect("commit");
    (store_dir, store, tree)
}

fn bench_restore(c: &mut Criterion) {
    let mut group = c.benchmark_group("restore_chunk_fanout");
    group.sample_size(20);
    for &mib in FILE_MIB {
        let (_keep, store, tree) = build_source(mib);
        group.throughput(Throughput::Bytes(mib * 1024 * 1024));
        group.bench_function(BenchmarkId::new("file", format!("{mib}_mib")), |b| {
            b.iter_batched(
                || tempfile::tempdir().expect("tempdir"),
                |target| {
                    restore_tree_to_worktree_with(
                        &store,
                        &tree,
                        None,
                        target.path(),
                        &RestoreOptions::default(),
                        &|store: &ObjectStore, hashes: &[Hash]| {
                            hashes
                                .par_iter()
                                .map(|h| match store.read_object(h)? {
                                    Object::Blob(blob) => Ok(blob.data),
                                    _ => Err(RestoreError::NotABlob),
                                })
                                .collect()
                        },
                    )
                    .expect("restore");
                    target
                },
                BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, bench_restore);
criterion_main!(benches);

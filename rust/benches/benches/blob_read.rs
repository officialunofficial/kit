//! Blob read path: one verified `read_object` of an inline blob, the
//! reassembly of a chunked blob, and a restore of a tree of many small files.
//! Every row reads objects that are already on disk and in the page cache, so
//! the rows measure allocation, copy, BLAKE3 and decode cost.

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use kit_benches::Xorshift;
use kit_core::hash::Hash;
use kit_core::layout::RepoLayout;
use kit_core::object::{Blob, Object};
use kit_core::ops::restore::{RestoreOptions, restore_tree};
use kit_core::serialize::serialize;
use kit_core::store::ObjectStore;
use kit_core::worktree::{self, LoadedBlob};
use tempfile::TempDir;

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;
const INLINE_SIZES: &[usize] = &[4 * KIB, 64 * KIB, MIB];
const CHUNKED_MIB: usize = 32;
const SMALL_FILES: usize = 2000;
const SMALL_FILE_BYTES: usize = 4 * KIB;

fn random_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut rng = Xorshift::new(seed);
    (0..len).map(|_| rng.next_u64().to_le_bytes()[0]).collect()
}

fn empty_store() -> (TempDir, ObjectStore) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).expect("init store");
    (dir, store)
}

/// Build the tree of `src` into a fresh store.
fn store_tree(src: &TempDir) -> (TempDir, ObjectStore, Hash) {
    let (dir, store) = empty_store();
    let batch = store.batch();
    let tree = worktree::build_tree(&batch, src.path()).expect("build tree");
    batch.commit().expect("commit");
    (dir, store, tree)
}

fn bench_inline(c: &mut Criterion) {
    let mut group = c.benchmark_group("blob_read/read_object");
    let (_keep, store) = empty_store();
    for &len in INLINE_SIZES {
        let bytes = serialize(&Object::Blob(Blob {
            data: random_bytes(len as u64, len),
        }))
        .expect("serialize");
        let h = store.write(&bytes).expect("write");
        group.throughput(Throughput::Bytes(len as u64));
        group.bench_function(
            BenchmarkId::from_parameter(format!("{}_kib", len / KIB)),
            |b| {
                b.iter(|| store.read_object(&h).expect("read"));
            },
        );
    }
    group.finish();
}

fn bench_chunked(c: &mut Criterion) {
    let mut group = c.benchmark_group("blob_read/into_content");
    group.sample_size(20);
    let src = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        src.path().join("big.bin"),
        random_bytes(7, CHUNKED_MIB * MIB),
    )
    .expect("write fixture");
    let (_keep, store, tree) = store_tree(&src);
    let Object::Tree(tree) = store.read_object(&tree).expect("tree") else {
        panic!("root is not a tree");
    };
    let file = tree.entries[0].object_hash;
    group.throughput(Throughput::Bytes((CHUNKED_MIB * MIB) as u64));
    group.bench_function(
        BenchmarkId::from_parameter(format!("{CHUNKED_MIB}_mib")),
        |b| {
            b.iter(|| {
                LoadedBlob::load(&store, &file)
                    .expect("load")
                    .into_content(&store)
                    .expect("content")
            });
        },
    );
    group.finish();
}

fn bench_small_files(c: &mut Criterion) {
    let mut group = c.benchmark_group("blob_read/restore_small_files");
    group.sample_size(20);
    let src = tempfile::tempdir().expect("tempdir");
    for i in 0..SMALL_FILES {
        let path = src.path().join(format!("f{i:05}.bin"));
        std::fs::write(path, random_bytes(i as u64, SMALL_FILE_BYTES)).expect("write fixture");
    }
    let (_keep, store, tree) = store_tree(&src);
    group.throughput(Throughput::Bytes((SMALL_FILES * SMALL_FILE_BYTES) as u64));
    group.bench_function(
        BenchmarkId::from_parameter(format!("{SMALL_FILES}x{}_kib", SMALL_FILE_BYTES / KIB)),
        |b| {
            b.iter_batched(
                || tempfile::tempdir().expect("tempdir"),
                |target| {
                    restore_tree(&store, tree, target.path(), &RestoreOptions::default())
                        .expect("restore");
                    target
                },
                BatchSize::PerIteration,
            );
        },
    );
    group.finish();
}

criterion_group!(benches, bench_inline, bench_chunked, bench_small_files);
criterion_main!(benches);

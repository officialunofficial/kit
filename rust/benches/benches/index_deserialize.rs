//! `index::deserialize` over a 50,000-entry staging index with
//! realistic nested paths.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use kit_core::index::{self, EntryStatus, Index, IndexEntry};
use std::hint::black_box;

const ENTRIES: usize = 50_000;

fn build_index() -> Vec<u8> {
    let entries = (0..ENTRIES)
        .map(|i| IndexEntry {
            path: format!("crates/module{}/src/dir{}/file{i}.rs", i % 40, i % 7),
            status: EntryStatus::Blob,
            object_hash: [(i % 251) as u8; 32],
            mtime_ns: i as u64,
            size: 4096,
            ino: i as u64,
            ctime_ns: i as u64,
        })
        .collect();
    let mut idx = Index::new();
    idx.entries = entries;
    idx.serialize()
}

fn bench_deserialize(c: &mut Criterion) {
    let bytes = build_index();
    let mut group = c.benchmark_group("index_deserialize");
    group.throughput(Throughput::Elements(ENTRIES as u64));
    group.bench_function("50k_entries", |b| {
        b.iter(|| black_box(index::deserialize(black_box(&bytes)).expect("valid index")));
    });
    group.finish();
}

criterion_group!(benches, bench_deserialize);
criterion_main!(benches);

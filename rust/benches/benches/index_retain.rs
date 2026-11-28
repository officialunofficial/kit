//! `Index::retain_entries` cost on a large index. Each iteration drops every
//! tenth entry.

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use kit_core::index::{EntryStatus, Index, IndexEntry};
use std::hint::black_box;

const ENTRIES: usize = 50_000;

fn build() -> Index {
    let mut idx = Index::new();
    for i in 0..ENTRIES {
        idx.upsert_entry(IndexEntry {
            path: format!("crates/module{}/src/file{i:06}.rs", i % 97),
            status: EntryStatus::Blob,
            object_hash: [0; 32],
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
        });
    }
    idx
}

fn bench_retain(c: &mut Criterion) {
    let base = build();
    let mut n = 0usize;
    c.bench_function("index_retain/drop_tenth_of_50k", |b| {
        b.iter_batched(
            || base.clone(),
            |mut idx| {
                n = 0;
                idx.retain_entries(|_| {
                    n += 1;
                    !n.is_multiple_of(10)
                });
                black_box(idx)
            },
            BatchSize::LargeInput,
        );
    });
}

criterion_group!(benches, bench_retain);
criterion_main!(benches);

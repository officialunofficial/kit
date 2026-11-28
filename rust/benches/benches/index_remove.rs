//! `Index::remove_path` cost on a large index. Each iteration unstages a
//! batch of paths one at a time, as `restore --staged` and merge abort do.

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use kit_core::index::{EntryStatus, Index, IndexEntry};
use std::hint::black_box;

const ENTRIES: usize = 20_000;
const REMOVED: usize = 100;

fn entry(path: String) -> IndexEntry {
    IndexEntry {
        path,
        status: EntryStatus::Blob,
        object_hash: [7; 32],
        mtime_ns: 1,
        size: 1,
        ino: 1,
        ctime_ns: 1,
    }
}

fn index() -> Index {
    let mut idx = Index::new();
    for i in 0..ENTRIES {
        idx.upsert_entry(entry(format!("crates/pkg{}/src/file{i:06}.rs", i % 50)));
    }
    idx
}

fn bench(c: &mut Criterion) {
    let base = index();
    let paths: Vec<String> = (0..REMOVED)
        .map(|i| base.entries[i * (ENTRIES / REMOVED)].path.clone())
        .collect();
    c.bench_function("index_remove/remove_path_100_of_20000", |b| {
        b.iter_batched(
            || base.clone(),
            |mut idx| {
                for p in &paths {
                    black_box(idx.remove_path(p));
                }
                idx
            },
            BatchSize::LargeInput,
        );
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);

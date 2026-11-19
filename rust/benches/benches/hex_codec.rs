//! Hex encode and decode of a 32-byte digest and a 62-char object path split.

use criterion::{Criterion, criterion_group, criterion_main};
use kit_core::hash::{from_hex, hash, object_path, to_hex};
use std::hint::black_box;

fn bench_hex(c: &mut Criterion) {
    let digest = hash(b"hex codec bench");
    let text = to_hex(&digest);
    let mut group = c.benchmark_group("hex_codec");
    group.bench_function("to_hex", |b| b.iter(|| to_hex(black_box(&digest))));
    group.bench_function("from_hex", |b| {
        b.iter(|| from_hex(black_box(&text)).unwrap());
    });
    group.bench_function("object_path", |b| {
        b.iter(|| object_path(black_box(&digest)))
    });
    group.finish();
}

criterion_group!(benches, bench_hex);
criterion_main!(benches);

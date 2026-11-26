//! `hash::from_hex` over a 64-digit object id, in lower and upper case.

use criterion::{Criterion, criterion_group, criterion_main};
use kit_core::hash;
use std::hint::black_box;

fn bench_hex_decode(c: &mut Criterion) {
    let lower = hash::to_hex(&hash::hash(b"hex decode bench"));
    let upper = lower.to_ascii_uppercase();
    let mut group = c.benchmark_group("hex_decode");
    group.bench_function("from_hex_lower", |b| {
        b.iter(|| hash::from_hex(black_box(&lower)).expect("valid"));
    });
    group.bench_function("from_hex_upper", |b| {
        b.iter(|| hash::from_hex(black_box(&upper)).expect("valid"));
    });
    group.finish();
}

criterion_group!(benches, bench_hex_decode);
criterion_main!(benches);

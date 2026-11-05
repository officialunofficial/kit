//! `delta::encode` over 64 KiB payloads, from near-identical inputs to
//! inputs with no shared block. The no-match case misses at every byte,
//! so it measures the cost of the literal path.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use kit_core::delta;
use std::hint::black_box;

const SIZE: usize = 64 * 1024;

fn random_bytes(seed: u64, n: usize) -> Vec<u8> {
    let mut state = seed;
    (0..n)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

fn text_base() -> Vec<u8> {
    let mut v = Vec::with_capacity(SIZE);
    while v.len() < SIZE {
        v.extend_from_slice(b"kit delta scan bench line of realistic source text\n");
    }
    v.truncate(SIZE);
    v
}

fn bench_delta_encode(c: &mut Criterion) {
    let base = text_base();
    let mut near = base.clone();
    near.splice(SIZE / 2..SIZE / 2, b"-- edited line --\n".iter().copied());
    let mut half = base[..SIZE / 2].to_vec();
    half.extend(random_bytes(0xC0FF_EE00, SIZE / 2));
    let rand_base = random_bytes(0x1234_5678, SIZE);
    let rand_target = random_bytes(0x8765_4321, SIZE);

    let cases: [(&str, &[u8], &[u8]); 3] = [
        ("near_duplicate", &base, &near),
        ("half_similar", &base, &half),
        ("random_no_match", &rand_base, &rand_target),
    ];
    let mut group = c.benchmark_group("delta_encode_scan");
    for (name, b, t) in cases {
        group.throughput(Throughput::Bytes(t.len() as u64));
        group.bench_function(name, |bench| {
            bench.iter(|| delta::encode(black_box(b), black_box(t)).expect("encode"));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_delta_encode);
criterion_main!(benches);

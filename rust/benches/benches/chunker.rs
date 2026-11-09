//! FastCDC v1 cutting throughput by cutter thread count, through the
//! streaming `ChunkReader` that file ingest uses. Every thread count cuts
//! the same boundaries.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use kit_core::chunker::{ChunkReader, FastCdc};

const FILE_MIB: usize = 64;
const THREADS: &[usize] = &[1, 2, 4, 8];

/// Pseudo-random bytes, so FastCDC finds real cut points.
fn fixture() -> Vec<u8> {
    let mut state: u64 = 0x00C0_FFEE;
    (0..FILE_MIB * 1024 * 1024)
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

fn bench_chunker(c: &mut Criterion) {
    let data = fixture();
    let mut group = c.benchmark_group(format!("chunker/{FILE_MIB} MiB"));
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.sample_size(10);
    for &threads in THREADS {
        group.bench_with_input(BenchmarkId::new("threads", threads), &threads, |b, &t| {
            b.iter(|| {
                let mut reader = ChunkReader::with_threads(FastCdc::v1(), &data[..], t);
                let mut chunks = 0usize;
                while reader.next_chunk_ref().expect("slice read").is_some() {
                    chunks += 1;
                }
                chunks
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_chunker);
criterion_main!(benches);

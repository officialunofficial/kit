//! Ed25519 verification throughput: one signature at a time against the
//! batch check of SPEC-SIGNING §1, with `ed25519-dalek`'s `verify_strict`
//! as the baseline, on one thread and spread across the
//! rayon pool the way fetch spreads them.
//!
//! Each entry signs a distinct 32-byte digest. The "distinct signers" group
//! gives every entry its own key, the shape of a fetch with commits from many
//! people; the "4 signers" group cycles through four keys, the shape of a
//! fetch from a small team, where the batch check shares one term per key.
//! The chart reports signatures verified per second.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use kit_benches::{Sample, Unit, time_one};
use kit_core::sign::{COMMIT_DOMAIN, KeyPair, verify_ed25519, verify_ed25519_batch};
use rayon::prelude::*;

type Entry = ([u8; 32], [u8; 32], [u8; 64]);
/// A named way to verify a set of entries.
type Mode = (&'static str, fn(&[Entry]));

const SIZES: [usize; 5] = [1, 8, 64, 256, 1024];

fn entries(n: usize, signers: usize) -> Vec<Entry> {
    (0..n)
        .map(|i| {
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&((i % signers) as u64).to_le_bytes());
            let kp = KeyPair::from_seed(seed);
            let body = (i as u64).to_le_bytes();
            let digest = kit_core::hash::domain_digest(COMMIT_DOMAIN, &body);
            (kp.public.0, digest, kp.sign(COMMIT_DOMAIN, &body).0)
        })
        .collect()
}

/// `ed25519-dalek`'s `verify_strict`: cofactorless, the baseline the kit
/// checks are measured against.
fn dalek_strict(batch: &[Entry]) {
    use ed25519_dalek::{Signature, VerifyingKey};
    for (public, message, sig) in batch {
        VerifyingKey::from_bytes(public)
            .unwrap()
            .verify_strict(message, &Signature::from_bytes(sig))
            .unwrap();
    }
}

fn single(batch: &[Entry]) {
    for (public, message, sig) in batch {
        verify_ed25519(public, message, sig).unwrap();
    }
}

fn batched(batch: &[Entry]) {
    let refs: Vec<_> = batch.iter().map(|(p, m, s)| (p, &m[..], s)).collect();
    verify_ed25519_batch(&refs).unwrap();
}

fn single_parallel(batch: &[Entry]) {
    batch
        .par_iter()
        .for_each(|(public, message, sig)| verify_ed25519(public, message, sig).unwrap());
}

/// One batch per worker thread, as `kit-sync` does.
fn batched_parallel(batch: &[Entry]) {
    let size = batch.len().div_ceil(rayon::current_num_threads()).max(1);
    batch.par_chunks(size).for_each(batched);
}

fn bench_ed25519_batch(c: &mut Criterion) {
    let modes: [Mode; 5] = [
        ("ed25519-dalek verify_strict", dalek_strict),
        ("single", single),
        ("batch", batched),
        ("single, parallel", single_parallel),
        ("batch, parallel", batched_parallel),
    ];
    let mut samples = Vec::new();
    for (group_name, signers) in [("distinct signers", usize::MAX), ("4 signers", 4)] {
        let mut group = c.benchmark_group(format!("ed25519_batch/{group_name}"));
        for n in SIZES {
            let batch = entries(n, signers.min(n));
            group.throughput(Throughput::Elements(n as u64));
            for (name, f) in modes {
                group.bench_with_input(BenchmarkId::new(name, n), &batch, |b, batch| {
                    b.iter(|| f(batch));
                });
                let iters = (4096 / n).clamp(4, 512) as u32;
                let secs = time_one(iters / 4 + 1, iters, || f(&batch));
                samples.push(Sample {
                    category: format!("ed25519 verify, {group_name}"),
                    axis: format!("{n} signatures"),
                    library: name.into(),
                    value: n as f64 / secs,
                    unit: Unit::OpsPerSec,
                });
            }
        }
        group.finish();
    }
    kit_benches::write_summary("ed25519_batch", &samples);
}

criterion_group!(benches, bench_ed25519_batch);
criterion_main!(benches);

//! Dedup of FastCDC v1 against FastCDC v2 on generated file pairs.
//!
//! Each workload is a pair of versions, A and B, built from a fixed
//! splitmix64 seed, so every run sees the same bytes. For each chunker the
//! bench cuts both versions and reports how many bytes of B are in chunks
//! that A does not have: the bytes a second commit would store. It also
//! reports the chunk count, the mean chunk size and the share of chunks
//! forced at `max_size`. These are counts, not timings, so machine load
//! does not change them.
//!
//! Run: `cargo bench -p kit-benches --bench chunker_dedup`.

use std::collections::HashSet;

use kit_core::chunker::{ChunkIterator, FastCdc};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n + 8);
        while v.len() < n {
            v.extend_from_slice(&self.next().to_le_bytes());
        }
        v.truncate(n);
        v
    }
}

const WORDS: &[&str] = &[
    "the",
    "error",
    "request",
    "user",
    "id",
    "session",
    "connect",
    "timeout",
    "ok",
    "GET",
    "POST",
    "/api/v1/items",
    "cache",
    "miss",
    "hit",
    "db",
    "query",
    "took",
    "ms",
    "retry",
    "worker",
    "started",
    "stopped",
    "config",
    "value",
    "null",
    "true",
    "false",
    "fn",
    "let",
    "mut",
    "return",
    "if",
    "else",
    "for",
    "in",
    "match",
    "struct",
    "impl",
    "pub",
    "use",
    "self",
    "Some",
    "None",
    "Ok",
    "Err",
    "Vec",
    "String",
    "u64",
    "usize",
];

/// One line of a service log (`log`) or of source code (`!log`).
fn line(r: &mut Rng, log: bool) -> String {
    let mut s = if log {
        let ts = 1_700_000_000 + r.below(10_000_000);
        let level = ["INFO", "WARN", "DEBUG", "ERROR"][r.below(4)];
        format!(
            "2026-11-08T{:02}:{:02}:{:02}.{:03}Z {level} [worker-{}] ",
            (ts / 3600) % 24,
            (ts / 60) % 60,
            ts % 60,
            r.below(1000),
            r.below(16)
        )
    } else {
        " ".repeat(4 * r.below(5))
    };
    let words = if log { 3 + r.below(10) } else { 1 + r.below(8) };
    for _ in 0..words {
        s.push_str(WORDS[r.below(WORDS.len())]);
        s.push(if !log && r.below(5) == 0 { '(' } else { ' ' });
    }
    if log {
        s.push_str(&format!(
            "id={} took={}ms\n",
            r.below(1 << 32),
            r.below(5000)
        ));
    } else {
        s.push_str(if r.below(3) == 0 { "{\n" } else { ";\n" });
    }
    s
}

fn lines(r: &mut Rng, total: usize, log: bool) -> Vec<String> {
    let mut v = Vec::new();
    let mut len = 0;
    while len < total {
        let l = line(r, log);
        len += l.len();
        v.push(l);
    }
    v
}

/// A ustar-shaped archive: a 512-byte header per file, the body, zero
/// padding to 512 bytes, and two zero blocks at the end.
fn tar(files: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, body) in files {
        let mut header = [0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..108].copy_from_slice(b"0000644\0");
        header[124..136].copy_from_slice(format!("{:011o}\0", body.len()).as_bytes());
        header[136..148].copy_from_slice(b"14707131000\0");
        header[257..263].copy_from_slice(b"ustar\0");
        out.extend_from_slice(&header);
        out.extend_from_slice(body);
        out.resize(out.len().next_multiple_of(512), 0);
    }
    out.resize(out.len() + 1024, 0);
    out
}

fn workloads() -> Vec<(&'static str, Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();

    // 32 MiB of random bytes; B has 50 single-byte inserts.
    let mut r = Rng(1);
    let a = r.bytes(32 << 20);
    let mut b = a.clone();
    for _ in 0..50 {
        let at = r.below(b.len());
        b.insert(at, r.next().to_le_bytes()[0]);
    }
    out.push(("random, 50 inserts", a, b));

    // 32 MiB of random bytes; B overwrites 4,000 8-byte words in 8 MiB.
    let mut r = Rng(2);
    let a = r.bytes(32 << 20);
    let mut b = a.clone();
    for _ in 0..4000 {
        let at = (8 << 20) + r.below(8 << 20);
        b[at..at + 8].copy_from_slice(&r.next().to_le_bytes());
    }
    out.push(("random, dense edits", a, b));

    // 32 MiB service log; B rewrites 200 lines in the middle half and
    // appends 2 MiB.
    let mut r = Rng(3);
    let mut log = lines(&mut r, 32 << 20, true);
    let a = log.concat().into_bytes();
    let n = log.len();
    for _ in 0..200 {
        let i = n / 4 + r.below(n / 2);
        log[i] = line(&mut r, true);
    }
    log.extend(lines(&mut r, 2 << 20, true));
    out.push(("log, edits + append", a, log.concat().into_bytes()));

    // 32 MiB of source code; B inserts 300 lines.
    let mut r = Rng(4);
    let mut src = lines(&mut r, 32 << 20, false);
    let a = src.concat().into_bytes();
    for _ in 0..300 {
        let i = r.below(src.len());
        let l = line(&mut r, false);
        src.insert(i, l);
    }
    out.push(("source, 300 inserts", a, src.concat().into_bytes()));

    // A 48 MiB tar of log and source files from 200 B to about 220 KB;
    // B inserts one line into 40 files.
    let mut r = Rng(5);
    let mut files = Vec::new();
    let mut total = 0;
    while total < 48 << 20 {
        let size = (200.0 * (r.below(1000) as f64 / 1000.0 * 7.0).exp()) as usize;
        let log = r.below(2) == 0;
        let body = lines(&mut r, size, log).concat().into_bytes();
        total += body.len() + 512;
        let ext = if log { "log" } else { "rs" };
        files.push((format!("pkg/src/file{:05}.{ext}", files.len()), body));
    }
    let a = tar(&files);
    for _ in 0..40 {
        let i = r.below(files.len());
        let l = line(&mut r, false).into_bytes();
        let body = &mut files[i].1;
        let at = r.below(body.len() + 1);
        body.splice(at..at, l);
    }
    out.push(("tar, 40 files edited", a, tar(&files)));

    // A 64 MiB disk image of 4 KiB blocks, 70% zero; B rewrites 1% of
    // the blocks with random bytes.
    let mut r = Rng(6);
    let blocks = (64 << 20) / 4096;
    let mut a = vec![0u8; 64 << 20];
    for block in a.chunks_mut(4096) {
        if r.below(10) < 3 {
            block.copy_from_slice(&r.bytes(4096));
        }
    }
    let mut b = a.clone();
    for _ in 0..blocks / 100 {
        let i = r.below(blocks) * 4096;
        b[i..i + 4096].copy_from_slice(&r.bytes(4096));
    }
    out.push(("sparse image, 1% blocks", a, b));
    out
}

struct Cut {
    ids: Vec<([u8; 32], usize)>,
    forced: usize,
}

fn cut(cdc: FastCdc, data: &[u8]) -> Cut {
    let mut forced = 0;
    let ids = ChunkIterator::new(cdc, data)
        .map(|b| {
            if b.length == cdc.max_size() && b.offset + b.length < data.len() {
                forced += 1;
            }
            (
                kit_core::hash::hash(&data[b.offset..b.offset + b.length]),
                b.length,
            )
        })
        .collect();
    Cut { ids, forced }
}

fn main() {
    // `cargo bench` passes `--bench`; the bench takes no options.
    println!(
        "{:<24} {:<6} {:>11} {:>8} {:>7} {:>9} {:>8}",
        "workload", "cdc", "new bytes", "dedup", "chunks", "mean", "forced"
    );
    for (name, a, b) in workloads() {
        for (label, cdc) in [("v1", FastCdc::v1()), ("v2", FastCdc::v2())] {
            let (ca, cb) = (cut(cdc, &a), cut(cdc, &b));
            let have: HashSet<[u8; 32]> = ca.ids.iter().map(|c| c.0).collect();
            let mut seen = HashSet::new();
            let new: usize = cb
                .ids
                .iter()
                .filter(|c| !have.contains(&c.0) && seen.insert(c.0))
                .map(|c| c.1)
                .sum();
            println!(
                "{name:<24} {label:<6} {new:>11} {:>7.2}% {:>7} {:>9} {:>7.1}%",
                100.0 * (1.0 - new as f64 / b.len() as f64),
                ca.ids.len(),
                a.len() / ca.ids.len(),
                100.0 * ca.forced as f64 / ca.ids.len() as f64,
            );
        }
    }
}

//! `IgnoreList::is_ignored` throughput. Each iteration tests a fixed set of
//! paths of mixed depth against a realistic pattern list.

use criterion::{Criterion, criterion_group, criterion_main};
use kit_core::ignore::parse;
use std::hint::black_box;

const PATTERNS: &str = "\
target/
node_modules/
*.o
*.log
*.tmp
.DS_Store
/build
/dist/
docs/_site/
**/__pycache__/
*.py[cod]
!keep.log
secrets/*.key
vendor/**/testdata
";

fn paths() -> Vec<String> {
    let dirs = [
        "src",
        "crates/kit-core/src",
        "a/b/c/d/e/f",
        "docs/guide/ref",
    ];
    let files = [
        "main.rs",
        "lib.rs",
        "notes.log",
        "mod.o",
        "keep.log",
        "x.pyc",
    ];
    let mut out = Vec::new();
    for d in dirs {
        for f in files {
            out.push(format!("{d}/{f}"));
        }
    }
    out.push("target/debug/deps/libfoo.rlib".into());
    out.push("vendor/a/b/testdata".into());
    out.push("a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/deep.rs".into());
    out
}

fn bench_ignore_match(c: &mut Criterion) {
    let list = parse(PATTERNS);
    let paths = paths();
    c.bench_function("ignore_match/realistic", |b| {
        b.iter(|| {
            let mut hits = 0usize;
            for p in &paths {
                hits += usize::from(list.is_ignored(black_box(p), false));
            }
            hits
        });
    });
}

/// A list the size of a large real `.gitignore`: mostly literal names, with
/// suffix, anchored and negated patterns mixed in.
fn large_patterns() -> String {
    let mut out = String::new();
    for i in 0..300 {
        match i % 10 {
            0..=5 => out.push_str(&format!("generated_{i}\n")),
            6 => out.push_str(&format!("*.ext{i}\n")),
            7 => out.push_str(&format!("/out_{i}/\n")),
            8 => out.push_str(&format!("cache_{i}/\n")),
            _ => out.push_str(&format!("!generated_{i}\n")),
        }
    }
    out.push_str("*.log\nnode_modules/\n");
    out
}

fn bench_ignore_match_large(c: &mut Criterion) {
    let list = parse(&large_patterns());
    let paths = paths();
    c.bench_function("ignore_match/large_list", |b| {
        b.iter(|| {
            let mut hits = 0usize;
            for p in &paths {
                hits += usize::from(list.is_ignored(black_box(p), false));
            }
            hits
        });
    });
}

criterion_group!(benches, bench_ignore_match, bench_ignore_match_large);
criterion_main!(benches);

//! Concurrent-writer rows. See docs/PERFORMANCE.md for how to run them.
//!
//! ```text
//! multiwriter <row> --dir <scratch> [--target file|serve] [--runs R]
//!             [--sizes a,b,..] [--steps S]
//! ```
//!
//! `<row>` is `ref-write`, `push-distinct`, `push-shared`, `fetch-noop` or
//! `fetch-grow`. Every run uses a fresh remote root under `--dir` and removes
//! it afterwards. The `serve` target reaches `kit serve` through
//! `kit+ssh://`, so it needs `KIT_SSH_PROGRAM` pointing at a wrapper that runs
//! `kit serve <path>` locally (`scripts/bench-multiwriter.sh` writes one).
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use kit_benches::multiwriter::{self, Connect, mean_sd};
use kit_core::protocol::Transport;
use kit_transport_file::FileTransport;
use kit_transport_ssh::SshTransport;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    File,
    Serve,
}

#[derive(Debug)]
struct Args {
    row: String,
    dir: PathBuf,
    target: Target,
    runs: usize,
    sizes: Option<Vec<usize>>,
    steps: Option<usize>,
}

const MAX_RUNS: usize = 100;

fn parse_args() -> Result<Args, String> {
    let mut it = std::env::args().skip(1);
    let row = it.next().ok_or("missing row")?;
    let mut args = Args {
        row,
        dir: PathBuf::new(),
        target: Target::File,
        runs: 5,
        sizes: None,
        steps: None,
    };
    while let Some(flag) = it.next() {
        let value = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--dir" => args.dir = PathBuf::from(value),
            "--target" => {
                args.target = match value.as_str() {
                    "file" => Target::File,
                    "serve" => Target::Serve,
                    _ => return Err(format!("unknown target {value}")),
                }
            }
            "--runs" => args.runs = number(&value)?.clamp(1, MAX_RUNS),
            "--steps" => args.steps = Some(number(&value)?),
            "--sizes" => {
                let sizes = value
                    .split(',')
                    .map(number)
                    .collect::<Result<Vec<_>, _>>()?;
                args.sizes = Some(sizes);
            }
            _ => return Err(format!("unknown flag {flag}")),
        }
    }
    if args.dir.as_os_str().is_empty() {
        return Err("--dir is required".to_owned());
    }
    Ok(args)
}

fn number(s: &str) -> Result<usize, String> {
    s.parse().map_err(|_| format!("{s} is not a number"))
}

fn connector(
    target: Target,
    root: &Path,
) -> impl Fn() -> Result<Box<dyn Transport>, String> + Sync {
    let root = root.to_path_buf();
    move || -> Result<Box<dyn Transport>, String> {
        match target {
            Target::File => Ok(Box::new(FileTransport::new(&root))),
            Target::Serve => {
                let url = format!("kit+ssh://bench@localhost{}", root.display());
                Ok(Box::new(
                    SshTransport::connect(&url).map_err(|e| e.to_string())?,
                ))
            }
        }
    }
}

/// A fresh remote root and a local scratch directory for one run.
struct RunDirs {
    base: PathBuf,
    root: PathBuf,
    local: PathBuf,
}

impl RunDirs {
    fn new(dir: &Path, name: &str) -> Result<Self, String> {
        let base = dir.join(name);
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("remote");
        let local = base.join("local");
        for d in [&root, &local] {
            std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
        }
        // `kit serve` serves a root only when it holds a `.kit` directory.
        std::fs::create_dir_all(root.join(".kit")).map_err(|e| e.to_string())?;
        Ok(Self { base, root, local })
    }
}

impl Drop for RunDirs {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

fn ms(d: std::time::Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn report(row: &str, target: Target, n: usize, runs: usize, fields: &[(&str, &[f64])]) {
    let target = match target {
        Target::File => "file",
        Target::Serve => "serve",
    };
    let mut line = format!("{row:<13} target={target:<5} n={n:<5} runs={runs}");
    for (name, xs) in fields {
        let (mean, sd) = mean_sd(xs);
        line.push_str(&format!("  {name}={mean:.1}±{sd:.1}"));
    }
    println!("{line}");
}

fn run(args: &Args) -> Result<(), String> {
    let row = args.row.as_str();
    let default_sizes: &[usize] = match row {
        "ref-write" => &[1, 2, 4, 8, 16, 32],
        "push-distinct" => &[1, 8, 64, 512],
        "push-shared" => &[1, 8, 32],
        "fetch-noop" => &[10, 100, 1_000, 10_000],
        "fetch-grow" => &[10, 100, 1_000],
        _ => return Err(format!("unknown row {row}")),
    };
    let sizes = args.sizes.clone().unwrap_or_else(|| default_sizes.to_vec());
    for &n in &sizes {
        let mut a = Vec::with_capacity(args.runs);
        let mut b = Vec::with_capacity(args.runs);
        let mut c = Vec::with_capacity(args.runs);
        let mut d = Vec::with_capacity(args.runs);
        let mut e = Vec::with_capacity(args.runs);
        let mut f = Vec::with_capacity(args.runs);
        let mut g = Vec::with_capacity(args.runs);
        let mut h = Vec::with_capacity(args.runs);
        for r in 0..args.runs {
            let dirs = RunDirs::new(&args.dir, &format!("{row}-{n}-{r}"))?;
            let connect = connector(args.target, &dirs.root);
            let connect: &Connect = &connect;
            match row {
                "ref-write" => {
                    let run = multiwriter::ref_write(connect, n, args.steps.unwrap_or(150))?;
                    a.push(run.rate());
                }
                "push-distinct" | "push-shared" => {
                    let steps = args.steps.unwrap_or(4);
                    let run = if row == "push-distinct" {
                        multiwriter::push_distinct(connect, &dirs.local, n, steps)?
                    } else {
                        multiwriter::push_shared(connect, &dirs.local, n, steps)?
                    };
                    a.push(run.rate());
                    b.push(ms(run.quantile(0.5)));
                    c.push(ms(run.quantile(0.99)));
                    d.push(run.retries_per_success());
                    if row == "push-shared" {
                        let (slow, _) = run.parts_above(0.99);
                        e.push(slow.attempts as f64);
                        f.push(ms(slow.rejected));
                        g.push(ms(slow.fetch));
                        h.push(ms(slow.commit + slow.landed));
                    }
                }
                "fetch-noop" => {
                    let reader = multiwriter::fetch_noop_setup(connect, &dirs.local, n)?;
                    let fetches = args.steps.unwrap_or(5);
                    for _ in 0..fetches {
                        let run = multiwriter::fetch_noop(connect, &reader)?;
                        a.push(ms(run.elapsed));
                        b.push(run.requests.total() as f64);
                    }
                }
                _ => {
                    let run = multiwriter::fetch_grow(connect, &dirs.local, n)?;
                    a.push(ms(run.incremental.elapsed));
                    b.push(run.incremental.packs_downloaded as f64);
                    c.push(run.incremental.requests.total() as f64);
                    d.push(ms(run.cold.elapsed));
                    e.push(run.cold.packs_downloaded as f64);
                    f.push(run.cold.requests.total() as f64);
                    g.push(run.chain_nodes as f64);
                }
            }
        }
        match row {
            "ref-write" => report(row, args.target, n, args.runs, &[("writes/s", &a)]),
            "push-distinct" => report(
                row,
                args.target,
                n,
                args.runs,
                &[
                    ("pushes/s", &a),
                    ("p50_ms", &b),
                    ("p99_ms", &c),
                    ("retries/success", &d),
                ],
            ),
            // The slowest 1% of landed pushes, split: attempts, time in
            // rejected attempts, in fetches after them, and in local
            // commits plus the attempt that landed.
            "push-shared" => report(
                row,
                args.target,
                n,
                args.runs,
                &[
                    ("pushes/s", &a),
                    ("p50_ms", &b),
                    ("p99_ms", &c),
                    ("retries/success", &d),
                    ("slow_attempts", &e),
                    ("slow_rejected_ms", &f),
                    ("slow_fetch_ms", &g),
                    ("slow_other_ms", &h),
                ],
            ),
            "fetch-noop" => report(
                row,
                args.target,
                n,
                args.runs,
                &[("ms", &a), ("requests", &b)],
            ),
            _ => report(
                row,
                args.target,
                n,
                args.runs,
                &[
                    ("fetch_ms", &a),
                    ("fetch_packs", &b),
                    ("fetch_requests", &c),
                    ("clone_ms", &d),
                    ("clone_packs", &e),
                    ("clone_requests", &f),
                    ("chain_nodes", &g),
                ],
            ),
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match parse_args().and_then(|args| run(&args)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("multiwriter: {e}");
            ExitCode::FAILURE
        }
    }
}

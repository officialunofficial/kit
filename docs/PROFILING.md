# Profiling

Two tools measure performance:

- **Benchmarks** (`rust/benches/`, criterion) show how fast a path runs.
  They also guard against regressions. The script
  [`scripts/bench-vs-git.sh`](../scripts/bench-vs-git.sh) runs the suite that
  compares kit with Git.
- **Sampling profiles** (this document) show where the time goes in a real
  run. They name the functions and source lines that use the CPU, with
  inline stacks.

Profiles use [`samply`](https://github.com/mstange/samply). It runs on
Linux, macOS and Windows. It records to the
[Firefox Profiler](https://profiler.firefox.com/). On macOS it needs no root
access.

## Install

```sh
cargo install samply
```

## The `profiling` cargo profile

A profiler names a function only when the binary has symbols and debug info.
The `release` profile in `rust/Cargo.toml` strips symbols. That is right for
shipping and useless for profiling. The `profiling` profile fixes this:

```toml
[profile.profiling]
inherits = "release"   # codegen-units = 1, lto = "thin"
debug = true           # line tables for inline stacks and the source view
strip = false          # keep symbols
```

Profile with this profile. Do not use `--release`, which has no symbols. Do
not use `dev`, which does not optimize.

### Representative code or readable stacks

The `release` settings `lto = "thin"` and `codegen-units = 1` make the timing
match a shipped binary. They also inline across crates. Inlining collapses
the call stack, so the profiler can assign self-time to the wrong function.
Trust the shape of the hot path. Do not trust exact per-function percentages
in the default profile.

For accurate function-level numbers, build the same profile with LTO off and
more codegen units. The frames stay distinct and the code stays optimized:

```sh
CARGO_PROFILE_PROFILING_LTO=false \
CARGO_PROFILE_PROFILING_CODEGEN_UNITS=16 \
  cargo build --profile profiling -p kit-bin
```

Use both views. The LTO build shows whether the total time is
representative. The non-LTO build shows which function is hot. A difference
between the two is usually an inlining effect, not a regression.

## Profile the CLI

The script builds with `--profile profiling` and records the run:

```sh
# scripts/profile.sh [--features <list>] [-- <kit args>]
scripts/profile.sh -- status
scripts/profile.sh -- log
```

By hand:

```sh
cd rust
cargo build --profile profiling -p kit-bin
samply record ./target/profiling/kit status
```

`samply record` runs the program to the end. It then opens the Firefox
Profiler in your browser with the profile loaded.

## Profile a benchmark

To study one criterion suite, name it. The suites are `hashing`,
`sign_verify`, `object_commit`, `pack_create` and `store_write`. The list is
in `rust/benches/Cargo.toml`.

```sh
scripts/profile.sh --bench pack_create
```

By hand, build the bench with the profiling profile. Cargo puts the binary in
`target/<profile>/deps/` with a hash in its name. Read the path from the JSON
output of cargo. Do not guess it:

```sh
cd rust
cargo build --profile profiling -p kit-benches --bench pack_create \
  --message-format=json \
  | python3 -I -c 'import sys, json; print(next(o["executable"] for l in sys.stdin if (o := json.loads(l)).get("executable") and o.get("target", {}).get("name") == "pack_create"))'
samply record ./target/profiling/deps/pack_create-<hash> --bench
```

The script does the same JSON lookup. It also works with a custom
`CARGO_TARGET_DIR`.

## Read a profile

- The **Call Tree** and **Flame Graph** tabs show where the samples landed.
  Invert the call tree to find the leaf functions with the most self-time.
- Double-click a function to open the source view. It shows the sampled
  lines and how often each one ran.
- samply samples each thread at 1000 Hz (every 1 ms). A short run gives few
  samples. Profile a bench or a large repository, not one small command.

## Platform notes

- **macOS** works without extra setup.
- **Linux** uses `perf_event`. If recording fails with a permission error,
  lower `perf_event_paranoid` for your session. Do not run the profiler as
  root:

  ```sh
  # Temporary, until reboot. samply prints this command when it fails.
  sudo sysctl kernel.perf_event_paranoid=1
  ```

  Do not run `sudo scripts/profile.sh` or `sudo samply record`. That runs
  freshly built local code as root and can leave root-owned files in your
  worktree. Change the sysctl, or give `CAP_PERFMON` to the samply binary,
  and run the profiler as your normal user.

## Why CI does not run profiles

A sampling profile is a tool for investigation. It is not a pass or fail
check. The criterion benches and `scripts/bench-vs-git.sh` track
regressions. Record a profile when a bench changes and you need to know why.

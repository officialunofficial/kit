# Performance

`scripts/bench-vs-git.sh` times kit against git on the same workloads. This
file explains how to run it and how to read the numbers.

## Reproduce the numbers

Install `hyperfine`, `git` and `python3`. The run needs about 3 GiB of free
space under `$TMPDIR`.

```sh
cd rust
cargo build --release --locked -p kit-bin --bin kit
cd ..
scripts/bench-vs-git.sh rust/target/release/kit bench-results
```

The script writes these files to the output directory:

- One `<name>.json` file for each timing row. These are the `hyperfine` exports.
  The mean and the standard deviation of each command are in the `summary`
  object of hyperfine 2 and in the `mean` and `stddev` keys of hyperfine 1.
- `sizes.txt`. It holds the repository sizes in KiB from `du -k`.
- `provenance.txt`. It holds the kit commit, a dirty flag, the machine and the
  tool versions.

The script prints a summary of the mean and standard deviation of each row.
Set `KIT_BENCH_PROVENANCE_ONLY=1` to print the provenance and stop.

## What the script measures

| Row | Workload |
|---|---|
| `init` | Create an empty repository. |
| `small-files` | Add and commit 100 files of 10 KiB. |
| `big-100m` | Add and commit one 100 MiB file. |
| `big-1g` | Add and commit one 1 GiB file. Three runs. |
| `append-1m` | Append 1 MiB to a committed 100 MiB file. Add and commit it. |
| `rehash-unchanged` | Run `touch` on a committed 100 MiB file. Add it again. |
| `status-unchanged` | Run `status` with a committed 100 MiB file and a warm stat cache. |
| `checkout-100m` | Switch to a branch that appends 1 MiB to a 100 MiB file. |

The size rows cover 100 small files, one 100 MiB file, and the growth after a
1 MiB append. Git growth shows both the loose store and the store after
`git gc`.

## Method

- All file content is random bytes. Random bytes do not compress. They stand in
  for media files. Source code can compress well in the git object store, and
  these workloads do not measure that.
- Both tools run as command-line processes with their default configuration.
  The time includes process start.
- `hyperfine` runs a `--prepare` command before each run. The command resets the
  work tree to a known state.
- The script runs in a temporary directory. It sets `HOME` and the `XDG_*`
  variables to that directory. It removes the directory on exit.

## Read the numbers with care

- kit signs each commit with Ed25519. Git does not sign commits by default.
- kit flushes object writes to disk before a command returns. Git does not flush
  loose objects by default.
- Disk speed, file system and CPU change the results. Run the script on your own
  machine before you rely on a ratio.
- A row with a mean below about 5 ms is below the `hyperfine` calibration limit.
  Do not use it to pick a winner.
- Compare the standard deviation with the difference between the means. When the
  ranges overlap, the data does not show a winner.

## Concurrent writers

`scripts/bench-multiwriter.sh` measures many writers against one remote root.
It runs the `multiwriter` binary of the `kit-benches` crate against the file
transport (`kit+file://`) and against `kit serve` (`kit+ssh://`, through a
local stand-in for `ssh` that starts `kit serve <path>` for each connection).

```sh
scripts/bench-multiwriter.sh /path/on/the/disk/to/measure
```

Give it a directory on the disk you want to measure. The script refuses tmpfs,
because tmpfs makes every fsync free and hides the cost of the ref locks. It
builds the release binaries, prints the provenance (commit, dirty flag,
machine, file system, compiler, run count) and one line for each row and size.
Each value is the mean and the sample standard deviation over the runs.

| Variable | Effect |
|---|---|
| `KIT_BENCH_TARGETS` | `file`, `serve`, or both (the default). |
| `KIT_BENCH_RUNS` | Runs per size. The default is 5. |
| `KIT_BENCH_ARGS` | Extra arguments for every row: `--sizes 1,8` overrides the sizes, `--steps N` the operations per writer, `--load W` the writers during `fetch-noop`. |

| Row | Workload | Reports |
|---|---|---|
| `ref-write` | N threads, N in 1, 2, 4, 8, 16, 32. Each makes 150 compare-and-swap writes to its own ref: `Missing`, then `Match` of the previous value. | Writes per second. |
| `ref-commit` | N threads, N in 1, 2, 4, 8, 16, 32. Each makes 150 multi-ref commits of its own branch head, packmap and tag: `Missing`, then `Match` of the previous value. No two threads name a common ref, so no commit may conflict. The `kit serve` target offers no multi-ref commit. | Ref writes and commits per second. |
| `push-distinct` | N pushers, N in 1, 8, 64, 512. Each pushes 4 commits to its own branch. | Pushes per second, p50 and p99 latency. |
| `push-shared` | N pushers, N in 1, 8, 32, each landing 4 commits on one branch. A rejected push fetches, commits again on the new tip and retries. | Pushes per second, latency including retries, rejected attempts per landed push, and for the slowest 1% of landed pushes: attempts, time in rejected attempts, time in fetches after them, and the rest (local commits and the attempt that landed). Pushers retry at once, without a wait. Each landed push can cost up to N - 1 rejected attempts, so large N takes a long time. |
| `fetch-noop` | M branches, M in 10, 100, 1,000, 10,000, and a clone that already holds them. Setup waits 3 s after its last write, because the file transport offers no cursor while a ref directory was modified in the last 2 s. Five fetches per run. With `--load W`, W threads write their own tags on the same root during the fetches. | Fetch time, remote requests, time in repository cursor reads, and cursor reads that returned a cursor. |
| `fetch-grow` | One push, a clone, then K pushes to the branch, K in 10, 100, 1,000. A fetch into the clone, and a fetch into an empty repository. | Time, packs downloaded and remote requests of each fetch, pack list nodes on the chain, and the mean time of the last 10 pushes. |

Every `ref-write` writer opens its own transport, as a separate process
would. Every pusher has its own local repository, and every push and fetch
opens a fresh transport, as one `kit push` or `kit fetch` does. For `kit
serve` that is one server process per push or fetch, and the timed part
includes starting it. Pushes and fetches run the library
code behind `kit push` and `kit fetch`. The workload is deterministic: ref
values, file contents, commit times and the signing key derive from the
writer and step numbers, so every run writes the same bytes.

Each row checks its result before it reports a number. After `ref-write` and
`ref-commit`, each ref must hold its writer's last value. After `push-distinct`, each branch must
hold its pusher's last commit. After `push-shared`, the first-parent history of
the branch must hold exactly the commits the pushers landed. The fetch rows
must end at the pushed tip, and `fetch-noop` must download nothing. A lost
write fails the run. `cargo test -p kit-benches --test multiwriter` runs every
row at tiny sizes and checks that a transport that drops a write fails it.

Each file transport instance has its own in-process locks, so writers in one
process meet only at the OS locks, as separate processes do. Starting the benchmark process is outside the timed part. The rows do not
cover a network: `kit serve` runs on the same machine.

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
scripts/bench-multiwriter.sh /path/on/the/disk/to/measure [row ...]
```

Give it a directory on the disk you want to measure. Name rows after the
directory to run only those; with none it runs all five. The script refuses tmpfs,
because tmpfs makes every fsync free and hides the cost of the ref locks. It
builds the release binaries, prints the provenance (commit, dirty flag,
machine, file system, compiler, run count) and one line for each row and size.
Each value is the mean and the sample standard deviation over the runs.

| Variable | Effect |
|---|---|
| `KIT_BENCH_TARGETS` | `file`, `serve`, or both (the default). |
| `KIT_BENCH_RUNS` | Runs per size. The default is 5. |
| `KIT_BENCH_ARGS` | Extra arguments for every row: `--sizes 1,8` overrides the sizes, `--steps N` the operations per writer (the fetches per run for `fetch-noop`; `fetch-grow` ignores it). |

| Row | Workload | Reports |
|---|---|---|
| `ref-write` | N threads, N in 1, 2, 4, 8, 16, 32. Each makes 150 compare-and-swap writes to its own ref: `Missing`, then `Match` of the previous value. | Writes per second. |
| `push-distinct` | N pushers, N in 1, 8, 64, 512. Each pushes 4 commits to its own branch. | Pushes per second, p50 and p99 latency, rejected attempts per landed push. |
| `push-shared` | N pushers, N in 1, 8, 32, each landing 4 commits on one branch. A rejected push fetches, commits again on the new tip and retries. | Pushes per second, p50, p90, p99 and maximum latency including retries, rejected attempts per landed push, pack list nodes on the branch's chain afterwards (more than the landed pushes means rejected attempts wrote to it), and for the slowest 1% of landed pushes: attempts, time in rejected attempts, time in fetches after them, and the rest (local commits and the attempt that landed). Pushers retry at once, without a wait. Each landed push can cost up to N - 1 rejected attempts, so large N takes a long time. |
| `fetch-noop` | M branches, M in 10, 100, 1,000, 10,000, and a clone that already holds them. Setup waits 3 s after its last write, because the file transport, and `kit serve` with it, offers no cursor while a ref directory was modified in the last 2 s. Five fetches per run. | Fetch time and remote requests. |
| `fetch-grow` | One push, a clone, then K pushes to the branch, K in 10, 100, 1,000. A fetch into the clone, and a fetch into an empty repository. | Time, packs downloaded and remote requests of each fetch, and pack list nodes on the chain. For the K pushes: the mean bytes uploaded, the median and the longest time of the pushes that append to the chain, the count of pushes that re-baseline the chain, and their mean and largest upload and median and longest time. |

Every `ref-write` writer opens its own transport, as a separate process
would. Every pusher has its own local repository, and every push and fetch
opens a fresh transport, as one `kit push` or `kit fetch` does. For `kit
serve` that is one server process per push or fetch, and the timed part
includes starting it. Pushes and fetches run the library
code behind `kit push` and `kit fetch`. The workload is deterministic: ref
values, file contents, commit times and the signing key derive from the
writer and step numbers, so every run writes the same bytes.

Each row checks its result before it reports a number. After `ref-write`, each
ref must hold its writer's last value. After `push-distinct`, each branch must
hold its pusher's last commit. After `push-shared`, the first-parent history of
the branch must hold exactly the commits the pushers landed. The fetch rows
must end at the pushed tip, and `fetch-noop` must download nothing. A lost
write fails the run. `cargo test -p kit-benches --test multiwriter` runs every
row at tiny sizes and checks that a transport that drops a write fails it.

Each file transport instance has its own in-process locks, so writers in one
process meet only at the OS locks, as separate processes do. Starting the benchmark process is outside the timed part. The rows do not
cover a network: `kit serve` runs on the same machine.

### The push cost of a pack chain re-baseline

A push appends one pack list node to the chain of its branch. A push that
would grow the chain past 64 nodes re-baselines it: the push uploads its own
pack and one node that lists every pack of the chain, and the chain restarts
at that node. The first push makes node 1, so every 64th push after it
re-baselines. `fetch-grow` counts the bytes of the packs and pack list nodes
that each push uploads.

Each commit of the workload replaces one 1 KiB file. A push that appends
uploads about 876 bytes. A re-baseline uploads the same pack and 32 bytes for
each pack on the branch, whatever the size of the files. The byte counts are
the same on every run.

| K pushes | Re-baselines | Bytes, append | Bytes, mean re-baseline | Bytes, last re-baseline | Clone, packs | Clone, requests |
|---:|---:|---:|---:|---:|---:|---:|
| 64 | 1 | 875 | 3,446 | 3,446 | 65 | 68 |
| 100 | 1 | 878 | 3,446 | 3,446 | 101 | 140 |
| 128 | 2 | 876 | 4,471 | 5,496 | 129 | 132 |
| 256 | 4 | 876 | 6,520 | 9,592 | 257 | 260 |
| 512 | 8 | 876 | 10,616 | 17,784 | 513 | 516 |
| 1,000 | 15 | 877 | 17,784 | 32,120 | 1,001 | 1,044 |

Over the 1,000 pushes, the 15 re-baselines upload 0.27 MB and the 985 appends
upload 0.86 MB. A fetch into an empty repository downloads one pack for each
push and reads at most 64 nodes. A fetch into a clone taken before the pushes
downloads the K new packs.

A node lists at most 4,096 packs. A branch that holds more appends one node
with each push, and a push and a clone then read one more node each time.

The rows ran once for each size over the file transport, on one 30-CPU arm64
machine under heavy load from other builds, so they report no times.

### The pack size of a push

A push builds packs of at most 256 MiB, so it holds one pack of that size and
one prepared batch in memory. A ticketed advance carries six data packs unless
the server advertises another number, which is about 1.5 GiB of objects. A
push that has a single commit heavier than that raises the pack size for that
push, once, to what the commit needs and no further. It never passes the
format limit of 4 GiB or the largest pack the server accepts. The same objects
spread over several commits keep packs of 256 MiB. A push of one large commit
therefore holds a larger pack in memory than a push of many small ones: one
pack and one prepared batch, each up to the raised size.

### The memory of a proof

Building a proof makes one pass over the leaves. Its memory is one pending
node per level plus the sibling digests of the proof, so it is O(log n) plus
the proof. A manifest of 8,388,608 chunks peaked at 1,050,212 kB to build one
chunk proof, and at 263,980 kB, the size of the manifest alone, after the
change. A multi proof of two positions gave the same two numbers. Each ran
once as a release build on one 32-CPU machine, and each took about 1.9
seconds.

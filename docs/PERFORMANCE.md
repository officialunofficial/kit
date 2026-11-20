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
- `clone-10k.txt`. It holds the median, the range and the raw times of the
  `clone-10k` row.
- `sizes.txt`. It holds the repository sizes in KiB from `du -k`.
- `provenance.txt`. It holds the kit commit, a dirty flag, the machine and the
  tool versions.

The script prints a summary of the mean and standard deviation of each row.
Set `KIT_BENCH_PROVENANCE_ONLY=1` to print the provenance and stop. Set
`KIT_BENCH_CLONE_ONLY=1` to run the `clone-10k` row alone.

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
| `clone-10k` | Clone one commit of 10,000 files of 1 KiB in 100 directories. kit clones over `kit+file://` and git over `file://`. |

The size rows cover 100 small files, one 100 MiB file, and the growth after a
1 MiB append. Git growth shows both the loose store and the store after
`git gc`.

## Clone of 10,000 files

A clone of many small files waits for the disk. `hyperfine` runs one command
many times in a row, so each run pays for the cleanup of the run before it. The
`clone-10k` row does not use `hyperfine`. It alternates kit and git. Before
each run it removes the previous clone, runs `sync` and waits 4 s. One round
that warms the page cache is not counted. The default is 8 runs per tool
(`KIT_BENCH_CLONE_RUNS`). The idle wait is `KIT_BENCH_CLONE_IDLE`. The report
gives the median and the range, and prints the file system of the work
directory.

Measured on a Linux 6.18 aarch64 virtual machine with 9 CPUs, started with
Apple's `container` command on an Apple-silicon Mac Studio with 30 cores. The work
directory is on ext4 on a virtio block device. Three runs of the script, 8
clones of each tool per run, with kit 0.8.0:

| Tool | Median of 24 clones | Range | Medians of the three runs |
|---|---|---|---|
| kit | 4.1 s | 0.9 s to 13.6 s | 3.4 s, 5.9 s, 4.3 s |
| git | 0.41 s | 0.32 s to 1.05 s | 0.43 s, 0.35 s, 0.39 s |

The git time is stable. The kit time is not: the range covers a factor of 14,
and the medians of three runs of the script differ by a factor of 1.7. A kit
clone writes about 10,100 object files and flushes each one. The time to flush
depends on the state of the disk, which this method does not control. Do not
quote a ratio from this row. Quote the range, and run the row on the disk you
care about.

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

A push builds packs of at most 256 MiB. Each pack is written to a spool in
`.kit/tmp/`, so kit-sync holds one prepared batch of about 64 MiB of objects
(or one larger object), not the pack. The file, ssh and S3 transports and
Connect's native channel send the pack from the spool a chunk at a time
(SPEC-TRANSPORT §1.1). A ticketed advance carries six data packs unless
the server advertises another number, which is about 1.5 GiB of objects. A
push that has a single commit heavier than that raises the pack size for that
push, once, to what the commit needs and no further. It never passes the
format limit of 4 GiB or the largest pack the server accepts. The same objects
spread over several commits keep packs of 256 MiB. A raised size makes a
larger spool on disk; kit-sync's batch stays at about 64 MiB, and a transport
that reads the pack into memory holds the raised size.

### The memory of a proof

Building a proof makes one pass over the leaves. Its memory is one pending
node per level plus the positions and the sibling digests of the proof, so it
is O(log n) plus the proof. A manifest of 8,388,608 chunks peaked at 1,050,212 kB to build one
chunk proof, and at 263,980 kB, the size of the manifest alone, after the
change. A multi proof of two positions gave the same two numbers. Each ran
once as a release build on one 32-CPU machine, and each took about 1.9
seconds.

## Pack transfer: memory and time

A push or a clone moves one pack. 0.8.0 held the pack in memory. 0.9 spools it
to a file and streams it on every transport. This section compares the two.

### Method

- 0.8.0 is the `v0.8.0` tag. 0.9 is `main` at commit `58afb7d`. Both are
  release builds from one machine.
- The machine is a shared 32-CPU arm64 Linux VM (Neoverse-V2, 125 GiB, ext4)
  with other jobs on it. The last column of each table is the 1-minute load
  average at the end of each run: the median and the highest.
- Two packs. The small one is 1,024 files of 256 KiB, a 268,509,029-byte pack
  (256 MiB). The large one is 15,360 files of 256 KiB, a 4,027,365,827-byte
  pack (3.75 GiB). The format caps a pack at 4 GiB. The bytes are random, so
  they do not compress.
- `kit+file` and `kit+ssh` run the `kit` command. Each is one new process under
  `/usr/bin/time -v`. A clone includes the checkout of the work tree.
  `kit+ssh` uses `kit serve` behind an `sshd` that the run started on a high
  port on 127.0.0.1. Each build served its own runs.
- Connect runs a test program that calls the push and fetch code of each build
  against the loopback server of the Connect tests. Its clone is a fetch with no
  checkout. That server is the `main` build for both clients, and it does not
  offer a pack location, so a clone streams.
- Each row is four runs of each build. The two builds alternate, and the order
  flips each round, so 0.8.0 goes first in rounds 1 and 3 and last in rounds 2
  and 4. Before every run the script syncs the disk and waits 8 s, and a push
  copies its source repository and syncs before the timer starts. The page
  cache was not dropped. The tables show the median and, in brackets, the range.
  A first pass ran 0.8.0 first every time and did not sync after the copy.
  Its 3.75 GiB push gaps were +18% for `kit+ssh` and +3% for `kit+file`. Later
  passes that synced gave +8% and +9% for `kit+file`. The `kit+ssh` gap moved
  with the order: +24% with 0.8.0 first and -9% with 0.9 first. The tables do
  not use the first pass. The text quotes it where it says so. The two 256 MiB `kit+ssh` rows were run again alone, because in the
  balanced run they overlapped a load spike.
- A push sends one pack. The preferred pack size, 256 MiB, was raised to 4 GiB
  for `kit+file` and `kit+ssh` with a build-time change to
  `DEFAULT_PACK_PAYLOAD_CAP` in both builds. No command-line setting reaches it.
  The Connect program sets the size in code.
- `kit serve` ends a session after 1 GiB of upload or download. A pack larger
  than that cannot cross `kit+ssh` in either version. Both builds were changed
  to allow 8 GiB (`MAX_BYTES_PER_CONN`). Only the large pack needs it.

### 256 MiB pack

| Transfer | 0.8.0 RSS | 0.9 RSS | 0.8.0 time | 0.9 time | Change | Load |
|---|---|---|---|---|---|---|
| push `kit+file` | 332 MiB [330 to 340] | 104 MiB [104 to 104] | 1.02 s [1.02 to 1.02] | 1.06 s [1.06 to 1.06] | +3.9% | 32, 57 |
| push `kit+ssh` | 332 MiB [326 to 336] | 105 MiB [105 to 105] | 1.64 s [1.61 to 1.67] | 1.65 s [1.64 to 1.72] | +0.6% | 9, 15 |
| push Connect | 331 MiB [321 to 345] | 102 MiB [102 to 103] | 1.52 s [1.52 to 1.53] | 1.58 s [1.57 to 1.58] | +3.9% | 80, 155 |
| clone `kit+file` | 285 MiB [285 to 286] | 76 MiB [76 to 76] | 1.38 s [1.37 to 1.91] | 1.16 s [1.14 to 1.23] | -16% | 11, 15 |
| clone `kit+ssh` | 286 MiB [286 to 286] | 78 MiB [76 to 78] | 2.63 s [2.44 to 4.83] | 2.29 s [2.19 to 2.55] | -13% | 26, 33 |
| clone Connect | 284 MiB [284 to 284] | 75 MiB [74 to 75] | 1.21 s [1.19 to 1.68] | 0.90 s [0.89 to 0.90] | -25% | 21, 38 |

No push or clone is more than 5% slower than 0.8.0. The pushes take up to 4%
longer, and the clones take 13 to 25% less. The times are read to 10 ms, so
1.02 s against 1.06 s is between +2.9% and +4.9%. The first pass, at a load
of 3 to 10, gave a similar result: +2.9% for `kit+file`, +1.2% for
`kit+ssh` and +2.6% for Connect.

### 3.75 GiB pack

| Transfer | 0.8.0 RSS | 0.9 RSS | 0.8.0 time | 0.9 time | Change | Load |
|---|---|---|---|---|---|---|
| push `kit+file` | 3,926 MiB [3,910 to 3,937] | 114 MiB [112 to 117] | 16.2 s [15.7 to 16.5] | 17.6 s [17.1 to 20.1] | +9% | 165, 450 |
| push `kit+ssh` | 3,924 MiB [3,906 to 3,930] | 115 MiB [113 to 117] | 23.1 s [21.9 to 25.0] | 24.2 s [23.6 to 32.5] | +5% | 198, 525 |
| push Connect | 3,921 MiB [3,907 to 3,930] | 111 MiB [111 to 118] | 22.8 s [22.5 to 24.0] | 25.9 s [25.7 to 26.7] | +13% | 11, 58 |
| clone `kit+file` | 3,879 MiB [3,879 to 3,880] | 77 MiB [76 to 78] | 18.9 s [18.7 to 26.1] | 17.3 s [16.8 to 25.8] | -8% | 46, 110 |
| clone `kit+ssh` | 3,882 MiB [3,881 to 3,882] | 76 MiB [76 to 77] | 31.3 s [25.9 to 35.3] | 22.1 s [21.4 to 22.3] | -29% | 30, 89 |
| clone Connect | 3,881 MiB [3,880 to 3,881] | 75 MiB [75 to 76] | 19.6 s [17.8 to 39.6] | 15.3 s [13.6 to 24.8] | -22% | 41, 212 |

The machine was busier for these rows, and some runs are much slower than the
rest of their row. The medians are less sensitive to them. The `kit+ssh` clone
gap was -19% in the first pass and -29% here.

A 0.9 clone from a pack location, which the Connect test server can offer, used
73 to 75 MiB at both sizes. Its time was not compared, because the machine was
at a load of 390 to 540 for those runs.

`kit serve` peaked at 7 to 9 MiB in both versions. The Connect test server, the
`main` build in every run, peaked at 8 to 11 MiB, and at 6 MiB when it served a
location.

### Reading the numbers

- The memory of a push or clone no longer follows the pack. It is 74 to 118
  MiB for 256 MiB and for 3.75 GiB. 0.8.0 needed the pack plus 30 to 90 MiB:
  about 3.8 GiB for the 3.75 GiB pack.
- No clone is slower. Clones take 8 to 29% less on 0.9. The likely reason is
  that 0.9 does not hold the pack and hashes it once on a fetch. That was not
  timed.
- At 256 MiB a 0.9 push takes up to 4% longer. At 3.75 GiB it took 5 to 13%
  longer in the balanced run, where the `kit+file` and `kit+ssh` rows ran at a
  median load near 200. `kit+file` gave +8% and +9% in the two synced passes.
  `kit+ssh` ranged from -9% to +24% across passes. Only Connect gave the same
  gap in every pass, 12 to 14%. The cause is
  not measured. 0.8.0 also hashed the whole pack before the upload, twice, in
  memory. What 0.9 adds is writing the pack to a spool file, reading it back
  to hash it, and sending it from that file.

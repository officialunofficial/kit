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

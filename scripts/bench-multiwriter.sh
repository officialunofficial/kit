#!/usr/bin/env bash
# Run the concurrent-writer rows against the file transport and `kit serve`.
#
#   scripts/bench-multiwriter.sh <scratch-dir> [row ...]
#
# <scratch-dir> must be on the disk you want to measure. tmpfs turns every
# fsync into a no-op and hides the cost of the ref locks. The script creates
# its runs under <scratch-dir>/multiwriter and removes them on exit.
#
# Rows default to all five. Set KIT_BENCH_TARGETS to "file", "serve" or
# "file serve" (the default). KIT_BENCH_RUNS sets the run count (default 5).
# Extra arguments for every row go in KIT_BENCH_ARGS, for example
# KIT_BENCH_ARGS="--sizes 1,8 --steps 2".
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRATCH="${1:?usage: bench-multiwriter.sh <scratch-dir> [row ...]}"
shift
ROWS=("$@")
if [ "${#ROWS[@]}" -eq 0 ]; then
  ROWS=(ref-write push-distinct push-shared fetch-noop fetch-grow)
fi
TARGETS="${KIT_BENCH_TARGETS:-file serve}"
RUNS="${KIT_BENCH_RUNS:-5}"

fs_type="$(stat -f -c %T "$SCRATCH" 2>/dev/null || echo unknown)"
if [ "$fs_type" = tmpfs ]; then
  echo "bench-multiwriter: $SCRATCH is on tmpfs; fsync costs vanish there" >&2
  exit 2
fi

(cd "$REPO_ROOT/rust" && cargo build --release --locked -p kit-bin --bin kit \
  -p kit-benches --bin multiwriter)
KIT="$REPO_ROOT/rust/target/release/kit"
BENCH="$REPO_ROOT/rust/target/release/multiwriter"

WORK="$SCRATCH/multiwriter"
mkdir -p "$WORK"
trap 'rm -rf "$WORK"' EXIT

# An ssh stand-in that runs `kit serve <path>` locally. The path is the last
# argument, after the literal `kit serve`.
SSH="$WORK/ssh"
cat >"$SSH" <<'EOF'
#!/bin/sh
set -eu
for a in "$@"; do path="$a"; done
exec "$KIT_SSH_TARGET_BIN" serve "$path"
EOF
chmod +x "$SSH"

echo "== provenance =="
echo "kit commit: $(git -C "$REPO_ROOT" rev-parse HEAD)"
if git -C "$REPO_ROOT" diff --quiet HEAD; then echo "dirty: no"; else echo "dirty: yes"; fi
echo "machine: $(uname -srm), $(nproc) CPUs"
echo "file system: $fs_type at $SCRATCH"
echo "rustc: $(cd "$REPO_ROOT/rust" && rustc --version)"
echo "runs: $RUNS"

echo "== rows =="
for row in "${ROWS[@]}"; do
  for target in $TARGETS; do
    # shellcheck disable=SC2086 # KIT_BENCH_ARGS is a word list by design.
    # A failed row prints its reason and the script goes on with the next.
    KIT_SSH_PROGRAM="$SSH" KIT_SSH_TARGET_BIN="$KIT" \
      "$BENCH" "$row" --dir "$WORK" --target "$target" --runs "$RUNS" ${KIT_BENCH_ARGS:-} ||
      echo "$row target=$target failed"
  done
done

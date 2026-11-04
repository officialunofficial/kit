#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Time kit against git with hyperfine and measure repository sizes.
# docs/PERFORMANCE.md explains the method.
#
# Usage:
#   scripts/bench-vs-git.sh [path-to-kit-binary] [output-dir]
#
# Defaults: binary = rust/target/release/kit, output = ./bench-results.
# Needs: hyperfine, git, python3, and about 3 GiB of free space under $TMPDIR.
#
# The script runs in a throwaway directory under $TMPDIR. It sets HOME and the
# XDG directories to that directory, so the kit keys and the git settings of the
# caller stay untouched. It deletes the directory on exit.
#
# Provenance goes to $OUT/provenance.txt: the commit, a dirty flag, the machine
# and the tool versions. The script refuses to run outside a git checkout, so
# the numbers always name a commit. The dirty flag covers the rust/ directory.
#
# Set KIT_BENCH_PROVENANCE_ONLY=1 to print the provenance and exit before the
# fixtures and the timing runs.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KIT="${1:-$REPO_ROOT/rust/target/release/kit}"
OUT="${2:-$REPO_ROOT/bench-results}"
[ -x "$KIT" ] || { echo "kit binary not found at $KIT (run: cargo build --release --locked -p kit-bin --bin kit)" >&2; exit 1; }
KIT="$(cd "$(dirname "$KIT")" && pwd)/$(basename "$KIT")"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

capture_provenance() {
  local commit dirty="clean"
  commit="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null)" || {
    echo "cannot find the kit commit: $REPO_ROOT is not a git checkout." >&2
    echo "The script does not write unattributed numbers." >&2
    exit 1
  }
  [ -z "$(git -C "$REPO_ROOT" status --porcelain -- rust 2>/dev/null)" ] || dirty="dirty"
  {
    echo "kit binary: $KIT"
    echo "kit version: $("$KIT" --version 2>&1)"
    echo "kit commit: $commit ($dirty)"
    echo "git version: $(git --version)"
    echo "hyperfine version: $(hyperfine --version)"
    echo "machine: $(uname -srm), $(nproc 2>/dev/null || sysctl -n hw.ncpu) CPUs"
    echo "filesystem: $(df -T "${TMPDIR:-/tmp}" 2>/dev/null | awk 'NR==2 {print $2}')"
    echo "measured: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } | tee "$OUT/provenance.txt"
}

command -v hyperfine >/dev/null || { echo "hyperfine not found" >&2; exit 1; }
echo "== provenance =="
capture_provenance
if [ "${KIT_BENCH_PROVENANCE_ONLY:-}" = "1" ]; then
  exit 0
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/kit-bench.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
export HOME="$WORK/home" XDG_CONFIG_HOME="$WORK/home/.config" XDG_DATA_HOME="$WORK/home/.local/share" XDG_CACHE_HOME="$WORK/home/.cache"
mkdir -p "$HOME"
cd "$WORK"

echo "== fixtures (incompressible bytes) =="
mkdir -p fixtures/small100
for i in $(seq 1 100); do head -c 10240 /dev/urandom > "fixtures/small100/f$i.bin"; done
head -c $((100 * 1024 * 1024)) /dev/urandom > fixtures/video100m.bin
head -c $((1024 * 1024 * 1024)) /dev/urandom > fixtures/blob1g.bin
head -c $((1024 * 1024)) /dev/urandom > fixtures/append1m.bin
F="$WORK/fixtures"

# Shell fragments for hyperfine --prepare. $1 is what to copy into the work tree.
kit_fresh() { echo "rm -rf work && mkdir work && cd work && $KIT init >/dev/null 2>&1 && $KIT keygen >/dev/null 2>&1 && cp -R $1 ."; }
git_fresh() { echo "rm -rf work && mkdir work && cd work && git init -q -b main && git config user.email b@b && git config user.name b && cp -R $1 ."; }

run() { # $1 is the name. The other arguments go to hyperfine.
  local name="$1"; shift
  echo "== $name =="
  hyperfine --shell=default --export-json "$OUT/$name.json" "$@"
}

# Every run lists the kit command first and the git command second.
run init --warmup 2 \
  --prepare 'rm -rf work && mkdir work' "cd work && $KIT init" \
  --prepare 'rm -rf work && mkdir work' 'cd work && git init -q'

run small-files --warmup 1 \
  --prepare "$(kit_fresh "$F/small100/")" "cd work && $KIT add . >/dev/null && $KIT commit -m bench >/dev/null 2>&1" \
  --prepare "$(git_fresh "$F/small100/")" 'cd work && git add . && git commit -q -m bench'

run big-100m --warmup 1 \
  --prepare "$(kit_fresh "$F/video100m.bin")" "cd work && $KIT add video100m.bin >/dev/null && $KIT commit -m bench >/dev/null 2>&1" \
  --prepare "$(git_fresh "$F/video100m.bin")" 'cd work && git add video100m.bin && git commit -q -m bench'

run big-1g --runs 3 \
  --prepare "$(kit_fresh "$F/blob1g.bin")" "cd work && $KIT add blob1g.bin >/dev/null && $KIT commit -m bench >/dev/null 2>&1" \
  --prepare "$(git_fresh "$F/blob1g.bin")" 'cd work && git add blob1g.bin && git commit -q -m bench'

# A committed 100 MiB file. Some runs append 1 MiB to it.
kit_v1="$(kit_fresh "$F/video100m.bin") && $KIT add video100m.bin >/dev/null && $KIT commit -m v1 >/dev/null 2>&1"
git_v1="$(git_fresh "$F/video100m.bin") && git add video100m.bin && git commit -q -m v1"

run append-1m --warmup 1 \
  --prepare "$kit_v1 && cat $F/append1m.bin >> video100m.bin" "cd work && $KIT add video100m.bin >/dev/null && $KIT commit -m v2 >/dev/null 2>&1" \
  --prepare "$git_v1 && cat $F/append1m.bin >> video100m.bin" 'cd work && git add video100m.bin && git commit -q -m v2'

# touch changes the modification time only, so both tools hash the file again.
run rehash-unchanged --warmup 1 \
  --prepare "$kit_v1 && touch video100m.bin" "cd work && $KIT add video100m.bin >/dev/null" \
  --prepare "$git_v1 && touch video100m.bin" 'cd work && git add video100m.bin'

# Status with a warm stat cache.
run status-unchanged --warmup 1 \
  --prepare "$kit_v1 && sleep 1.1 && $KIT status >/dev/null 2>&1" "cd work && $KIT status >/dev/null 2>&1" \
  --prepare "$git_v1 && git status >/dev/null" 'cd work && git status >/dev/null'

# Branch main holds v1. Branch v2 holds the file with 1 MiB appended.
run checkout-100m --warmup 1 \
  --prepare "$kit_v1 && $KIT branch v2 >/dev/null 2>&1 && $KIT checkout v2 >/dev/null 2>&1 && cat $F/append1m.bin >> video100m.bin && $KIT add video100m.bin >/dev/null && $KIT commit -m v2 >/dev/null 2>&1 && $KIT checkout main >/dev/null 2>&1" "cd work && $KIT checkout v2 >/dev/null 2>&1" \
  --prepare "$git_v1 && git branch v2 && git checkout -q v2 && cat $F/append1m.bin >> video100m.bin && git add video100m.bin && git commit -q -m v2 && git checkout -q main" 'cd work && git checkout -q v2'

echo "== sizes (du -k) ==" | tee "$OUT/sizes.txt"
size_of() { du -sk "$1" | cut -f1; }
say() { echo "$*" | tee -a "$OUT/sizes.txt"; }
fresh_dir() { cd "$WORK" && rm -rf work && mkdir work && cd work; }
kit_repo() { "$KIT" init >/dev/null 2>&1 && "$KIT" keygen >/dev/null 2>&1; }
git_repo() { git init -q -b main && git config user.email b@b && git config user.name b; }

fresh_dir; kit_repo
cp -R "$F/small100/" . && "$KIT" add . >/dev/null && "$KIT" commit -m bench >/dev/null 2>&1
say "size-small kit KiB: $(size_of .kit)"
fresh_dir; git_repo
cp -R "$F/small100/" . && git add . && git commit -q -m bench
say "size-small git KiB: $(size_of .git)"

fresh_dir; kit_repo
cp "$F/video100m.bin" . && "$KIT" add video100m.bin >/dev/null && "$KIT" commit -m v1 >/dev/null 2>&1
v1=$(size_of .kit)
say "size-big-v1 kit KiB: $v1"
cat "$F/append1m.bin" >> video100m.bin
"$KIT" add video100m.bin >/dev/null && "$KIT" commit -m v2 >/dev/null 2>&1
say "size-big-v2 kit growth KiB: $(( $(size_of .kit) - v1 ))"

fresh_dir; git_repo
cp "$F/video100m.bin" . && git add video100m.bin && git commit -q -m v1
v1=$(size_of .git)
say "size-big-v1 git KiB: $v1"
cat "$F/append1m.bin" >> video100m.bin
git add video100m.bin && git commit -q -m v2
say "size-big-v2 git growth KiB: $(( $(size_of .git) - v1 ))"

# Packed growth uses a separate repository, so git gc does not change the loose figures.
fresh_dir; git_repo
cp "$F/video100m.bin" . && git add video100m.bin && git commit -q -m v1
git gc -q
v1=$(size_of .git)
say "size-big-v1 git packed KiB: $v1"
cat "$F/append1m.bin" >> video100m.bin
git add video100m.bin && git commit -q -m v2
git gc -q
say "size-big-v2 git packed growth KiB: $(( $(size_of .git) - v1 ))"

echo
echo "== provenance =="
cat "$OUT/provenance.txt"
echo
echo "== summary (mean seconds, kit first) =="
python3 - "$OUT" <<'PY'
import glob, json, os, sys

for path in sorted(glob.glob(os.path.join(sys.argv[1], "*.json"))):
    with open(path) as f:
        results = json.load(f)["results"]
    # hyperfine 2 nests the statistics under "summary". hyperfine 1 keeps them flat.
    stats = [r.get("summary", {}).get("time_wall_clock", r) for r in results]
    cells = [
        f'{tool} {s["mean"]:.4f}s +-{s["stddev"] or 0:.4f}'
        for tool, s in zip(("kit", "git"), stats)
    ]
    print(f'{os.path.basename(path)[:-5]:18} ' + "  vs  ".join(cells))
PY
echo "JSON, sizes and provenance are in $OUT"

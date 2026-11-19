#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Compare loose objects with local pack segments for add, clone and gc.
#
# Usage: scripts/bench-local-packs.sh <kit-branch-binary> <kit-main-binary> [rounds]
#
# Runs each workload with three writers, interleaved per round:
#   main   the main build (loose objects only)
#   loose  the branch build with KIT_PROTO_PACKS=0
#   packs  the branch build with pack segments on
# Drops the page cache before every timed run. Prints a Markdown table of
# medians.
set -euo pipefail

BRANCH="$1"
MAIN="$2"
ROUNDS="${3:-5}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export HOME="$WORK/home"
mkdir -p "$HOME"

drop_caches() {
  sync
  if [ "$(uname)" = Darwin ]; then
    sudo purge
  else
    sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches'
  fi
  sleep 1
}

now() { python3 -c 'import time; print(time.monotonic())'; }

cd "$WORK"
python3 - <<'PY'
import os
os.makedirs("fixtures/small", exist_ok=True)
for i in range(20000):
    d = f"fixtures/small/d{i % 100}"
    os.makedirs(d, exist_ok=True)
    with open(f"{d}/f{i}", "wb") as f:
        f.write(os.urandom(4096))
os.makedirs("fixtures/big", exist_ok=True)
for name in ("big1", "big2"):
    with open(f"fixtures/big/{name}", "wb") as f:
        for _ in range(160):
            f.write(os.urandom(1_000_000))
PY

# A remote holding the small files and one big file, for the clone runs.
mkdir src remote
cp -R fixtures/small/. src/
cp fixtures/big/big1 src/
(cd src && KIT_PROTO_PACKS=0 "$BRANCH" init -q && "$BRANCH" keygen >/dev/null \
  && KIT_PROTO_PACKS=0 "$BRANCH" add . && KIT_PROTO_PACKS=0 "$BRANCH" commit -q -m fixture \
  && "$BRANCH" remote add r "kit+file://$WORK/remote" && "$BRANCH" push -q r main)

run_add() { # writer fixture
  local bin env
  case "$1" in
    main) bin="$MAIN"; env="KIT_PROTO_PACKS=0" ;;
    loose) bin="$BRANCH"; env="KIT_PROTO_PACKS=0" ;;
    packs) bin="$BRANCH"; env="KIT_PROTO_PACKS=1" ;;
  esac
  rm -rf r && mkdir r && cp -R "fixtures/$2/." r/
  (cd r && "$bin" init -q)
  drop_caches
  local t0 t1
  t0=$(now)
  (cd r && env $env "$bin" add . >/dev/null)
  t1=$(now)
  python3 -c "print(round($t1 - $t0, 3))"
}

run_clone() { # writer
  local bin env
  case "$1" in
    main) bin="$MAIN"; env="KIT_PROTO_PACKS=0" ;;
    loose) bin="$BRANCH"; env="KIT_PROTO_PACKS=0" ;;
    packs) bin="$BRANCH"; env="KIT_PROTO_PACKS=1" ;;
  esac
  rm -rf c
  drop_caches
  local t0 t1
  t0=$(now)
  env $env "$bin" clone "kit+file://$WORK/remote" c >/dev/null 2>&1
  t1=$(now)
  python3 -c "print(round($t1 - $t0, 3))"
}

run_gc() { # writer
  # Stage the small files, overwrite half of them and stage again, so the
  # first versions of those 10k objects are unreachable, then commit and time
  # a gc that reclaims them.
  local bin env
  case "$1" in
    main) bin="$MAIN"; env="KIT_PROTO_PACKS=0" ;;
    loose) bin="$BRANCH"; env="KIT_PROTO_PACKS=0" ;;
    packs) bin="$BRANCH"; env="KIT_PROTO_PACKS=1" ;;
  esac
  rm -rf g && mkdir g && cp -R fixtures/small/. g/
  (cd g && "$bin" init -q && "$bin" keygen >/dev/null && env $env "$bin" add . >/dev/null \
    && python3 -c "
import glob, os
for p in sorted(glob.glob('d*/f*'))[::2]:
    open(p, 'wb').write(os.urandom(4096))
" && env $env "$bin" add . >/dev/null && env $env "$bin" commit -q -m gc)
  drop_caches
  local t0 t1
  t0=$(now)
  (cd g && env $env "$bin" gc --grace-secs 0 2>gc.log)
  t1=$(now)
  echo "gc $1: $(tail -1 g/gc.log)" >&2
  # A failed gc must fail the job, not report a fast time.
  if ! grep -q '^gc: pruned' g/gc.log; then echo "gc $1 failed" >&2; echo failed; return; fi
  python3 -c "print(round($t1 - $t0, 3))"
}

: > results.txt
for round in $(seq "$ROUNDS"); do
  for w in main loose packs; do
    echo "add-big $w $(run_add "$w" big)" >> results.txt
    echo "add-small $w $(run_add "$w" small)" >> results.txt
    echo "clone $w $(run_clone "$w")" >> results.txt
    echo "gc $w $(run_gc "$w")" >> results.txt
  done
  echo "round $round done" >&2
done

python3 - results.txt <<'PY'
import statistics, sys
rows = {}
for line in open(sys.argv[1]):
    wl, w, t = line.split()
    rows.setdefault(wl, {}).setdefault(w, []).append(float(t))
print("| Workload | main | branch, loose | branch, packs | packs vs main |")
print("| --- | --- | --- | --- | --- |")
for wl, ws in rows.items():
    m = {w: statistics.median(v) for w, v in ws.items()}
    print(f"| {wl} | {m['main']:.3f} s | {m['loose']:.3f} s | {m['packs']:.3f} s | {m['main'] / m['packs']:.2f}x |")
print()
print("Raw seconds per round:")
print()
for wl, ws in rows.items():
    for w, v in ws.items():
        print(f"- {wl} {w}: {', '.join(f'{x:.3f}' for x in v)}")
PY

#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Run every formal/quint/*/check.sh. All of them run, even after a failure,
# and the script then fails if any did.
#
#   formal/scripts/run-quint.sh            each script in its default mode
#   formal/scripts/run-quint.sh --all      also turn on the TLC runs that a
#                                          script leaves off by default
#
# Needs quint 0.32.0 on PATH, Java 21 and the pinned Apalache
# (formal/scripts/setup-apalache.sh).
set -euo pipefail
cd "$(dirname "$0")/../.."

tlc=
case "${1:-}" in
  '') ;;
  --all) tlc=TLC=1 ;;
  *) echo "usage: $0 [--all]" >&2; exit 2 ;;
esac

qv=$(quint --version 2>/dev/null) ||
  { echo "error: quint is not on PATH (npm i -g @informalsystems/quint@0.32.0)" >&2; exit 2; }
[[ $qv == 0.32.0 ]] || { echo "error: quint $qv, the pin is 0.32.0" >&2; exit 2; }

failed=()
log=$(mktemp)
trap 'rm -f "$log"' EXIT

# A check.sh ends with "all checks as expected" or "<n> unexpected". A
# non-zero exit without either line is an abort (for example a failed
# `quint compile`) that the script cannot report itself. Say so.
verdict() {
  if [[ $2 == 0 ]]; then return 0; fi
  if ! tail -n 1 "$log" | grep -Eq '^(all checks as expected|[0-9]+ unexpected)$'; then
    echo "=== $1 aborted (exit $2) before its verdict; last lines above" >&2
  fi
  return 1
}

for s in formal/quint/*/check.sh; do
  echo "=== $s (default mode${tlc:+, $tlc})"
  t0=$SECONDS
  rc=0
  env -u APALACHE -u TLC -u QUINT -u ONLY -u SEL $tlc bash "$s" | tee "$log" || rc=$?
  verdict "$s" "$rc" || failed+=("$s")
  echo "=== $s: $((SECONDS - t0)) s"
done

if ((${#failed[@]})); then
  echo "run-quint: FAILED: ${failed[*]}" >&2
  exit 1
fi

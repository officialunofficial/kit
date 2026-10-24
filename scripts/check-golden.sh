#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Run every independent reference check of the golden vectors in
# rust/tests/golden. The checks are Python scripts in scripts/golden. They
# share no code with the Rust crates. Each one reads only the specs. See
# rust/tests/golden/README.md for the vector set that each script covers.
#
# The script first checks that each MANIFEST.txt holds current digests. Then it
# runs one reference check per vector set.
#
# Setup, once:
#   python3 -m venv .venv && .venv/bin/pip install -r scripts/golden/requirements.txt
# Run from any directory:
#   PYTHON=.venv/bin/python bash scripts/check-golden.sh
#
# Environment:
#   PYTHON     Python with the packages of scripts/golden/requirements.txt.
#              The default is python3.
#   NO_B3SUM   Set to any value to skip the cross-check against the official
#              b3sum tool in the part-upload and grant checks. All other checks
#              use the pure-Python BLAKE3 of scripts/golden/blake3_subtree_ref.py.

set -euo pipefail

cd "$(dirname "$0")/.."

py=${PYTHON:-python3}
golden=rust/tests/golden
fail=0

run() {
    local label=$1
    shift
    if "$@"; then
        printf 'ok: %s\n' "$label"
    else
        printf '::error::golden check failed: %s\n' "$label" >&2
        fail=1
    fi
}

for manifest in "$golden"/*/MANIFEST.txt; do
    dir=$(dirname "$manifest")
    run "manifest $(basename "$dir")" "$py" -I -B scripts/golden/write_manifest.py --check "$dir"
done

b3sum_flag=()
if [ -n "${NO_B3SUM:-}" ]; then
    b3sum_flag=(--no-b3sum)
fi

run 'part uploads' "$py" -I -B scripts/golden/blake3_subtree_ref.py \
    "$golden/uploads/subtree-merge.json" --part-json "$golden/auth-v2/part.json" --jobs 4 \
    ${b3sum_flag[@]+"${b3sum_flag[@]}"}
run 'grants' "$py" -I -B scripts/golden/grants_ref.py "$golden/grants" \
    ${b3sum_flag[@]+"${b3sum_flag[@]}"}
for check in objects closure refs_index pack proofs transport disclosure http_objects git_bridge \
    auth_v2 attest ssh_serve sparse; do
    run "$check" "$py" -I -B "scripts/golden/${check}_ref.py" "$golden"
done
run 'redaction' "$py" -I -B scripts/check-redaction-goldens.py

exit "$fail"

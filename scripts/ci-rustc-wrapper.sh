#!/bin/bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# RUSTC_WRAPPER for the Cloud Build steps that compile Rust (cloudbuild/ci.yaml).
# It runs sccache and keeps the diagnostics of a failed compile visible.
#
# Cargo's JSON renderer drops raw stdout, including the signal messages that
# sccache prints when a compiler dies. On failure this script copies that output
# to stderr and keeps the exit code.
set -euo pipefail

output=$(mktemp)
trap 'rm -f "$output"' EXIT
status=0
sccache "$@" >"$output" || status=$?
cat "$output"
if [ "$status" -ne 0 ]; then
  cat "$output" >&2
fi
exit "$status"

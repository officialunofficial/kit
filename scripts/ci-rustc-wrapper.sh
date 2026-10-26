#!/bin/bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# RUSTC_WRAPPER for the Cloud Build steps that compile Rust (cloudbuild/ci.yaml).
# It runs sccache and keeps the diagnostics of a failed compile visible.
#
# Cargo's JSON renderer drops raw stdout, including the signal messages that
# sccache prints when a compiler dies. On failure this script copies that output
# to stderr instead of stdout and keeps the exit code. It prints the output once.
set -euo pipefail

output=$(mktemp)
trap 'rm -f "$output"' EXIT
status=0
sccache "$@" >"$output" || status=$?
if [ "$status" -eq 0 ]; then
  cat "$output"
else
  cat "$output" >&2
fi
exit "$status"

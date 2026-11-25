#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Isolate scratch files and remove them after tests, including timed-out tests.
# Select a short scratch parent with TMPDIR for path-sensitive heap tests.
set -euo pipefail
# macOS sets TMPDIR with a trailing slash. Strip it so test paths have no empty segment.
parent=${TMPDIR:-/tmp}
scratch=$(mktemp -d "${parent%/}/k.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
export TMPDIR="$scratch"
"$@"

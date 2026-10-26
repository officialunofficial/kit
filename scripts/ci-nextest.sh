#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Run one partition of the workspace tests from the nextest archive.
#
# Usage: scripts/ci-nextest.sh <partition>
#
# The partition is a number from 1 to PARTITIONS. cloudbuild/ci.yaml calls this
# script once for each partition, with the same environment for every call.
set -euo pipefail

PARTITIONS=3
partition="${1:-}"
case "$partition" in
  [1-9]) ;;
  *)
    echo "usage: $0 <partition from 1 to $PARTITIONS>" >&2
    exit 2
    ;;
esac
if [ "$partition" -gt "$PARTITIONS" ]; then
  echo "partition $partition is above $PARTITIONS" >&2
  exit 2
fi

export CARGO_TERM_COLOR=always
export CARGO_INCREMENTAL=0
export RUST_BACKTRACE=short
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export KIT_TEST_STRICT=1
export NEXTEST_TEST_THREADS=9

cd "$(dirname "${BASH_SOURCE[0]}")/../rust"
cargo nextest run --archive-file /workspace/nextest-archive.tar.zst --workspace-remap /workspace/rust \
  --partition "count:${partition}/${PARTITIONS}" --profile ci --no-fail-fast

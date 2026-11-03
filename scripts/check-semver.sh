#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Compare the public API of each published crate with the latest release.
#
# The baseline is the release tag built with its own Cargo.lock. A build of
# the published crate from crates.io resolves its dependencies again, so a
# later dependency release can break that build and hide the comparison.
# The locked build checks the source against the exact dependency versions
# that the release audited.
#
# kit-bin is out of scope. Its library surface is not a public API (see
# docs/RELEASE.md). Crates with `publish = false` have no baseline.
#
# Needs git history with the release tags and cargo-semver-checks on PATH.
# Run from any directory:
#   bash scripts/check-semver.sh [<tag>]

set -euo pipefail

cd "$(dirname "$0")/.."
root=$(pwd)

tag=${1:-$(git describe --tags --abbrev=0 --match 'v[0-9]*')}
base=$(mktemp -d)
trap 'git -C "$root" worktree remove --force "$base/tree" >/dev/null 2>&1 || true; rm -rf "$base"' EXIT
git worktree add --detach --quiet "$base/tree" "$tag"

# rustdoc JSON for one crate: rustdoc_json <workspace> <crate> <out-dir>.
# Both sides use the same toolchain, so the JSON format versions match.
rustdoc_json() {
    (cd "$1" && CARGO_TARGET_DIR="$3" RUSTC_BOOTSTRAP=1 cargo rustdoc --locked --quiet \
        -p "$2" --all-features --lib -- -Z unstable-options --output-format json)
    echo "$3/doc/${2//-/_}.json"
}

status=0
for manifest in rust/crates/*/Cargo.toml; do
    crate=$(basename "$(dirname "$manifest")")
    [[ $crate == kit-bin ]] && continue
    grep -qE '^publish[[:space:]]*=[[:space:]]*false' "$manifest" && continue
    if [[ ! -f $base/tree/$manifest ]]; then
        echo "$crate: new since $tag, no baseline"
        continue
    fi
    echo "=== $crate against $tag"
    old=$(rustdoc_json "$base/tree/rust" "$crate" "$base/target-baseline")
    new=$(rustdoc_json "$root/rust" "$crate" "$base/target-current")
    cargo semver-checks --baseline-rustdoc "$old" --current-rustdoc "$new" || status=1
done
exit "$status"

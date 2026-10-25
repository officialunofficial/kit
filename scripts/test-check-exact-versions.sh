#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Test scripts/check-exact-versions.py on small fixture trees.
#
# Run from any directory:  bash scripts/test-check-exact-versions.sh

set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fails=0
expect() {
    local name=$1 want=$2 root=$3
    local got=pass
    python3 -I -B "$repo_root/scripts/check-exact-versions.py" "$root" >/dev/null 2>"$work/err" || got=fail
    if [ "$got" = "$want" ]; then
        echo "ok: $name"
    else
        echo "FAIL: $name (expected $want)" >&2
        cat "$work/err" >&2
        fails=1
    fi
}

# A fixture has an exact workspace table, one crate with an exact dependency
# and and a path dependency.
fixture() {
    local root="$work/$1"
    mkdir -p "$root/rust/crates/a"
    cat >"$root/rust/Cargo.toml" <<'TOML'
[workspace]
members = ["crates/a"]

[workspace.dependencies]
alpha = { version = "=1.2.3", default-features = false }
TOML
    cat >"$root/rust/crates/a/Cargo.toml" <<'TOML'
[package]
name = "a"

[dependencies]
alpha = { workspace = true }
beta = "=0.4.1"
sibling = { version = "0.5", path = "../sibling" }
TOML
}

fixture clean
expect exact-versions pass "$work/clean"

fixture workspace-range
sed -i.bak 's/"=1.2.3"/"1.2.3"/' "$work/workspace-range/rust/Cargo.toml"
expect workspace-range fail "$work/workspace-range"

fixture crate-range
printf 'gamma = "2"\n' >>"$work/crate-range/rust/crates/a/Cargo.toml"
expect new-crate-range fail "$work/crate-range"

fixture dev-range
printf '\n[dev-dependencies]\ngamma = { version = "^2.1" }\n' >>"$work/dev-range/rust/crates/a/Cargo.toml"
expect new-dev-range fail "$work/dev-range"

exit "$fails"

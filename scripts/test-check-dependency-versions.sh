#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Test scripts/check-dependency-versions.py on small fixture trees.
#
# Run from any directory:  bash scripts/test-check-dependency-versions.sh

set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fails=0
expect() {
    local name=$1 want=$2 root=$3
    local got=pass
    python3 -I -B "$repo_root/scripts/check-dependency-versions.py" "$root" >/dev/null 2>"$work/err" || got=fail
    if [ "$got" = "$want" ]; then
        echo "ok: $name"
    else
        echo "FAIL: $name (expected $want)" >&2
        cat "$work/err" >&2
        fails=1
    fi
}

# A fixture has a workspace version, a lock file, one crate with caret
# requirements, an exact internal dependency and a path-only dev-dependency.
fixture() {
    local root="$work/$1"
    mkdir -p "$root/rust/crates/a" "$root/rust/crates/b"
    cat >"$root/rust/Cargo.toml" <<'TOML'
[workspace]
members = ["crates/a", "crates/b"]

[workspace.package]
version = "0.5.0"

[workspace.dependencies]
alpha = { version = "1.2.3", default-features = false }
TOML
    cat >"$root/rust/crates/a/Cargo.toml" <<'TOML'
[package]
name = "a"
version.workspace = true

[dependencies]
alpha = { workspace = true }
beta = "0.4.1"
sibling = { version = "=0.5.0", path = "../b" }

[dev-dependencies]
helper = { path = "../b" }
TOML
    cat >"$root/rust/crates/b/Cargo.toml" <<'TOML'
[package]
name = "b"
version.workspace = true
TOML
    cat >"$root/rust/Cargo.lock" <<'TOML'
version = 4

[[package]]
name = "alpha"
version = "1.2.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "00"

[[package]]
name = "beta"
version = "0.4.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "01"
TOML
}

fixture clean
expect clean pass "$work/clean"

fixture exact-external
sed -i.bak 's/beta = "0.4.1"/beta = "=0.4.1"/' "$work/exact-external/rust/crates/a/Cargo.toml"
expect exact-external fail "$work/exact-external"

fixture short-bound
sed -i.bak 's/beta = "0.4.1"/beta = "0.4"/' "$work/short-bound/rust/crates/a/Cargo.toml"
expect short-bound fail "$work/short-bound"

fixture star-range
sed -i.bak 's/beta = "0.4.1"/beta = "*"/' "$work/star-range/rust/crates/a/Cargo.toml"
expect star-range fail "$work/star-range"

fixture lower-bound-drift
sed -i.bak 's/beta = "0.4.1"/beta = "0.4.0"/' "$work/lower-bound-drift/rust/crates/a/Cargo.toml"
expect lower-bound-drift fail "$work/lower-bound-drift"

fixture workspace-drift
sed -i.bak 's/"1.2.3"/"1.2.2"/' "$work/workspace-drift/rust/Cargo.toml"
expect workspace-drift fail "$work/workspace-drift"

fixture internal-caret
sed -i.bak 's/"=0.5.0"/"0.5"/' "$work/internal-caret/rust/crates/a/Cargo.toml"
expect internal-caret fail "$work/internal-caret"

fixture internal-stale
sed -i.bak 's/"=0.5.0"/"=0.4.0"/' "$work/internal-stale/rust/crates/a/Cargo.toml"
expect internal-stale fail "$work/internal-stale"

fixture path-only
sed -i.bak 's/^sibling = .*/sibling = { path = "..\/b" }/' "$work/path-only/rust/crates/a/Cargo.toml"
expect path-only-dependency fail "$work/path-only"

fixture path-only-unpublished
sed -i.bak 's/^sibling = .*/sibling = { path = "..\/b" }/' "$work/path-only-unpublished/rust/crates/a/Cargo.toml"
sed -i.bak 's/^version.workspace = true/version.workspace = true\npublish = false/' "$work/path-only-unpublished/rust/crates/a/Cargo.toml"
expect path-only-unpublished pass "$work/path-only-unpublished"

fixture lock-git
printf '\n[[package]]\nname = "gamma"\nversion = "1.0.0"\nsource = "git+https://example.invalid/gamma"\n' >>"$work/lock-git/rust/Cargo.lock"
expect lock-git-source fail "$work/lock-git"

fixture lock-no-checksum
printf '\n[[package]]\nname = "gamma"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n' >>"$work/lock-no-checksum/rust/Cargo.lock"
expect lock-no-checksum fail "$work/lock-no-checksum"

fixture lock-duplicate
printf '\n[[package]]\nname = "beta"\nversion = "0.4.1"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "01"\n' >>"$work/lock-duplicate/rust/Cargo.lock"
expect lock-duplicate fail "$work/lock-duplicate"

exit "$fails"

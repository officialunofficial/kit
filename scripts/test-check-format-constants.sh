#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Test scripts/check-format-constants.py on small fixture trees.
#
# Run from any directory:  bash scripts/test-check-format-constants.sh

set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

check() {
    python3 -I -B "$repo_root/scripts/check-format-constants.py" "$1" >/dev/null 2>"$work/err"
}

fails=0
expect() {
    local name=$1 want=$2 root=$3
    local got=pass
    check "$root" || got=fail
    if [ "$got" = "$want" ]; then
        echo "ok: $name"
    else
        echo "FAIL: $name (expected $want)" >&2
        cat "$work/err" >&2
        fails=1
    fi
}

fixture() {
    local root="$work/$1"
    mkdir -p "$root/rust/crates/a/src" "$root/rust/crates/b/src"
    printf 'pub const ONE_REF: &str = "refs/kit/alpha";\n' >"$root/rust/crates/a/src/lib.rs"
    printf 'pub const OTHER: &str = "other-value";\n' >"$root/rust/crates/b/src/lib.rs"
}

fixture clean
expect one-owner pass "$work/clean"

fixture dup-const
printf 'const AGAIN_REF: &str = "refs/kit/alpha";\n' >>"$work/dup-const/rust/crates/b/src/lib.rs"
expect duplicate-constant fail "$work/dup-const"

fixture dup-literal
printf 'fn f() -> String { format!("refs/kit/alpha/{}", 1) }\n' >>"$work/dup-literal/rust/crates/b/src/lib.rs"
expect repeated-ref-literal fail "$work/dup-literal"

fixture test-only
printf '#[cfg(test)]\nmod tests {\n    const T: &str = "refs/kit/alpha";\n}\n' >>"$work/test-only/rust/crates/b/src/lib.rs"
expect test-module-ignored pass "$work/test-only"

fixture chance
printf 'const HEX: &str = "0123456789abcdef";\n' >>"$work/chance/rust/crates/a/src/lib.rs"
printf 'const HEX: &str = "0123456789abcdef";\n' >>"$work/chance/rust/crates/b/src/lib.rs"
expect allowed-shared-value pass "$work/chance"

exit "$fails"

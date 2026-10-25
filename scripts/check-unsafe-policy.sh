#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Fail when a crate root does not declare an unsafe policy. A crate root is
# a src/lib.rs, a src/main.rs or a file under src/bin/ in a workspace crate.
# The policy is `#![forbid(unsafe_code)]`, or `#![deny(unsafe_code)]` for a
# crate that keeps a small set of justified `#[allow(unsafe_code)]` sites.
# Fuzz targets and integration tests are not crate roots of a shipped
# crate, so the check does not read them.
#
#   bash scripts/check-unsafe-policy.sh

set -euo pipefail

cd "$(dirname "$0")/.."

status=0
total=0
for f in $(git ls-files -- 'rust/**/src/lib.rs' 'rust/**/src/main.rs' 'rust/**/src/bin/*.rs'); do
    total=$((total + 1))
    if ! grep -Eq '^#!\[(forbid|deny)\(unsafe_code\)\]' "$f"; then
        printf '%s: no #![forbid(unsafe_code)] or #![deny(unsafe_code)]\n' "$f" >&2
        status=1
    fi
done

if [ "$total" -eq 0 ]; then
    echo "unsafe policy check: found no crate roots" >&2
    exit 1
fi
if [ "$status" -eq 0 ]; then
    echo "unsafe policy check: ok ($total crate roots)"
fi
exit "$status"

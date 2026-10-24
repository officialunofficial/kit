#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Fail when a doc, comment or workflow cites a repo path that does not exist,
# or names a crate that is not in the workspace. Two checks run:
#   1. Every `scripts/...`, `formal/...`, `docs/...`, `.github/...` and `rust/...` file path
#      in tracked text must exist. A path counts when it ends in a known
#      file extension.
#   2. Every relative Markdown link to a file must resolve.
#
# Run from any directory:  bash scripts/check-doc-paths.sh

set -euo pipefail

cd "$(dirname "$0")/.."

fail=0

# Check 1: cited repo paths. A trailing glob, placeholder or sentence mark is
# cut off before the test.
while IFS=: read -r file line path; do
    path=$(printf '%s' "$path" | sed -E 's/[^A-Za-z0-9_]$//')
    [ -n "$path" ] || continue
        if [ ! -e "$path" ]; then
        printf '::error file=%s,line=%s::cited path does not exist: %s\n' "$file" "$line" "$path" >&2
        fail=1
    fi
done < <(git grep -nIoE '(^|[^A-Za-z0-9_./-])(scripts|formal|docs|\.github|rust/(crates|tests|fuzz))/[A-Za-z0-9_./-]+\.(md|sh|py|rs|yml|yaml|json|toml|proto|txt)([^A-Za-z0-9_*]|$)' -- . \
    ':(exclude)scripts/check-doc-paths.sh' ':(exclude)CHANGELOG.md' ':(exclude)rust/Cargo.lock' |
    sed -E 's/^([^:]*):([0-9]+):[^A-Za-z]?/\1:\2:/')

# Check 2: relative Markdown links. The anchor and any query are dropped.
while IFS=: read -r file line link; do
    target=${link%%#*}
    case $target in '' | http* | mailto*) continue ;; esac
    dir=$(dirname "$file")
    if [ ! -e "$dir/$target" ] && [ ! -e "$target" ]; then
        printf '::error file=%s,line=%s::link target does not exist: %s\n' "$file" "$line" "$target" >&2
        fail=1
    fi
done < <(git grep -nIoE '\]\([^) ]+\.(md|sh|py|json|toml|yml)(#[^) ]*)?\)' -- '*.md' |
    sed -E 's/^([^:]*):([0-9]+):\]\(([^)]*)\)$/\1:\2:\3/')

exit $fail

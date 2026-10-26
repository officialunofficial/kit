#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Test scripts/check-doc-paths.sh. Each case builds a scratch git repository
# with one cited path, link or spec name, and checks that the script passes or
# fails and names the bad citation.
#
# Run from any directory:  bash scripts/test-check-doc-paths.sh

set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

repo=$work/repo
failures=0
cases=0

new_repo() {
    rm -rf "$repo"
    mkdir -p "$repo/scripts" "$repo/docs/specs"
    cp "$root/scripts/check-doc-paths.sh" "$repo/scripts/"
    git -C "$repo" init -q
    printf 'Clean text.\n' >"$repo/README.md"
    printf '# Real spec\n' >"$repo/docs/specs/SPEC-REAL.md"
    printf '# Other spec\n' >"$repo/docs/specs/SPEC-REAL-MORE.md"
}

pass() { cases=$((cases + 1)); }
fail() { cases=$((cases + 1)); failures=$((failures + 1)); printf 'FAIL: %s\n' "$1" >&2; }

# leaks NAME LINE LABEL: the check must fail and print LABEL.
leaks() {
    local name=$1 line=$2 label=$3 out
    new_repo
    printf '%s\n' "$line" >"$repo/NOTES.md"
    git -C "$repo" add -A
    if out=$(bash "$repo/scripts/check-doc-paths.sh" 2>&1); then
        fail "$name: the check passed"
    elif ! grep -qF "$label" <<<"$out"; then
        fail "$name: the output lacks '$label'"
    else
        pass
    fi
}

# clean NAME LINE: the check must pass.
clean() {
    local name=$1 line=$2 out
    new_repo
    printf '%s\n' "$line" >"$repo/NOTES.md"
    git -C "$repo" add -A
    if out=$(bash "$repo/scripts/check-doc-paths.sh" 2>&1); then
        pass
    else
        fail "$name: the check failed: $out"
    fi
}

clean 'no citation' 'Plain text.'
clean 'spec that exists' 'See SPEC-REAL for the rule.'
clean 'spec with a section' 'See SPEC-REAL-MORE §2.'
clean 'spec glob' 'Every docs/specs/SPEC-*.md file has a status.'
clean 'path that exists' 'See docs/specs/SPEC-REAL.md for the rule.'

leaks 'spec that is missing' 'See SPEC-GONE §4 for the rule.' 'cited spec does not exist: SPEC-GONE'
leaks 'hyphenated spec that is missing' 'See SPEC-GONE-AWAY for the rule.' 'cited spec does not exist: SPEC-GONE-AWAY'
leaks 'prefix of an existing spec' 'See SPEC-REAL-MOR for the rule.' 'cited spec does not exist: SPEC-REAL-MOR'
leaks 'spec with a digit' 'See SPEC-V2 for the rule.' 'cited spec does not exist: SPEC-V2'
leaks 'path that is missing' 'See docs/specs/SPEC-REAL-NONE.md for the rule.' 'cited path does not exist'

# A citation in a source file counts as well.
new_repo
mkdir -p "$repo/rust"
printf '// Follows SPEC-GONE.\n' >"$repo/rust/lib.rs"
git -C "$repo" add -A
if bash "$repo/scripts/check-doc-paths.sh" >/dev/null 2>&1; then fail 'source citation'; else pass; fi

# A citation of an existing spec in a source file passes.
new_repo
mkdir -p "$repo/rust"
printf '// Follows SPEC-REAL.\n' >"$repo/rust/lib.rs"
git -C "$repo" add -A
if bash "$repo/scripts/check-doc-paths.sh" >/dev/null 2>&1; then pass; else fail 'source citation of a real spec'; fi

if [ "$failures" -ne 0 ]; then
    printf '%d of %d doc-path cases failed\n' "$failures" "$cases" >&2
    exit 1
fi
printf 'doc-path tests: %d cases ok\n' "$cases"

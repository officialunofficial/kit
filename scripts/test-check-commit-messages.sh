#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Test scripts/check-commit-messages.py. Each case builds a scratch git
# repository, adds one commit and checks the result of the script. The tool
# name is built from fragments at run time. This file then passes the writing
# check that scans it.
#
# Run from any directory:  bash scripts/test-check-commit-messages.sh

set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

w_tool='Cla''ude'

repo=$work/repo
failures=0
cases=0

new_repo() {
    rm -rf "$repo"
    mkdir -p "$repo/scripts"
    cp "$root/scripts/check-commit-messages.py" "$root/scripts/check-writing-patterns.txt" "$repo/scripts/"
    git -C "$repo" init -q
    git -C "$repo" config user.email test@example.invalid
    git -C "$repo" config user.name test
    git -C "$repo" config commit.gpgsign false
    printf 'Clean text.\n' >"$repo/README.md"
    git -C "$repo" add -A
    git -C "$repo" commit -q -m 'chore: add clean text'
}

run_check() { (cd "$repo" && python3 -I -B scripts/check-commit-messages.py "$1" 2>&1); }

pass() { cases=$((cases + 1)); }
fail() { cases=$((cases + 1)); failures=$((failures + 1)); printf 'FAIL: %s\n' "$1" >&2; }

# commit_case NAME EXPECT MESSAGE LABEL: commit MESSAGE, then check the range.
commit_case() {
    local name=$1 expect=$2 message=$3 label=${4:-} out status=0
    new_repo
    printf 'change\n' >>"$repo/README.md"
    git -C "$repo" commit -q -a -m "$message"
    out=$(run_check HEAD~1..HEAD) || status=$?
    if [ "$expect" = fail ]; then
        if [ "$status" -eq 0 ]; then
            fail "$name: the check passed"
        elif ! grep -qF "$label" <<<"$out"; then
            fail "$name: the output lacks '$label'"
        else
            pass
        fi
    elif [ "$status" -ne 0 ]; then
        fail "$name: the check failed: $out"
    else
        pass
    fi
}

commit_case 'plain header' pass 'feat: add the parser'
commit_case 'scoped header' pass 'fix(kit-core): reject trailing bytes'
commit_case 'breaking header' pass 'refactor(kit-core)!: rename the tag type'
commit_case 'breaking header without scope' pass 'perf!: speed up hashing'
commit_case 'last type' pass 'ci: build for wasm32'
commit_case 'body and plain trailer' pass "$(printf 'docs: explain the format\n\nThe text explains why.\n\nReviewed-by: Someone <a@example.invalid>')"
commit_case 'tool name in the body' pass "$(printf 'docs: explain the format\n\nThe note for %s is a body line.' "$w_tool")"
commit_case 'no type' fail 'Add the parser' 'not in the form'
commit_case 'unknown type' fail 'feature: add the parser' "type 'feature'"
commit_case 'uppercase type' fail 'Feat: add the parser' 'not in the form'
commit_case 'missing space' fail 'feat:add the parser' 'not in the form'
commit_case 'empty subject' fail 'feat(kit-core): ' 'not in the form'
commit_case 'empty scope' fail 'feat(): add the parser' 'not in the form'
commit_case 'long header' fail "$(printf 'feat: %0100d' 0)" 'longer than 72'
commit_case 'header of 72 characters' pass "$(printf 'feat: %066d' 0)"
commit_case 'tool trailer' fail "$(printf 'feat: add the parser\n\nWhy.\n\nCo-Authored-By: %s <a@example.invalid>' "$w_tool")" 'trailer names a tool'
commit_case 'tool trailer without body' fail "$(printf 'feat: add the parser\n\nCo-Authored-By: %s <a@example.invalid>' "$w_tool")" 'trailer names a tool'
commit_case 'tool trailer without blank line' fail "$(printf 'feat: add the parser\n\nWhy.\nCo-Authored-By: %s <a@example.invalid>' "$w_tool")" 'trailer names a tool'
commit_case 'session trailer' fail "$(printf 'feat: add the parser\n\nWhy.\n\n%s-Session: https://example.invalid/x' "$w_tool")" 'trailer names a tool'

# A merge commit with a free-form header does not fail.
new_repo
git -C "$repo" checkout -q -b side
printf 'side\n' >"$repo/side.txt"
git -C "$repo" add -A
git -C "$repo" commit -q -m 'feat: add a side file'
git -C "$repo" checkout -q -
printf 'main\n' >"$repo/main.txt"
git -C "$repo" add -A
git -C "$repo" commit -q -m 'feat: add a main file'
git -C "$repo" merge -q --no-ff side -m "Merge branch 'side'"
if run_check HEAD~2..HEAD >/dev/null; then pass; else fail 'merge commit'; fi

# A range checks only its own commits, not the older history.
new_repo
printf 'change\n' >>"$repo/README.md"
git -C "$repo" commit -q -a -m 'bad old header'
printf 'more\n' >>"$repo/README.md"
git -C "$repo" commit -q -a -m 'fix: reject unknown keys'
if run_check HEAD~1..HEAD >/dev/null; then pass; else fail 'range limit'; fi
if run_check HEAD~2..HEAD >/dev/null; then fail 'range includes old commit'; else pass; fi

# An empty range passes.
new_repo
if run_check HEAD..HEAD >/dev/null; then pass; else fail 'empty range'; fi

# A missing argument fails.
if (cd "$repo" && python3 -I -B scripts/check-commit-messages.py) >/dev/null 2>&1; then fail 'missing argument'; else pass; fi

if [ "$failures" -ne 0 ]; then
    printf '%d of %d commit-message-check cases failed\n' "$failures" "$cases" >&2
    exit 1
fi
printf 'commit-message-check tests: %d cases ok\n' "$cases"

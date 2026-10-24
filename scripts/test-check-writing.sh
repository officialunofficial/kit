#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Test scripts/check-writing.sh. Each case builds a scratch git repository,
# adds one kind of leak, and checks that the script fails and names it. The
# banned words are built from fragments at run time. This file then passes
# the same check that it tests.
#
# Run from any directory:  bash scripts/test-check-writing.sh

set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

hash='#'
w_phase='pha''se'
w_ticket='tic''ket'
w_package='work pack''age'
w_milestone='mile''stone'
w_tracker='tra''cker'
w_tool='Cla''ude'
w_old='m''kit'
w_seed='MK''ITFCDC'
w_tracked='tra''cked'
w_follow='fol''low-up'
w_wp='W''P'
w_orig='origin''ating'

repo=$work/repo
failures=0
cases=0

new_repo() {
    rm -rf "$repo"
    mkdir -p "$repo/scripts"
    cp "$root/scripts/check-writing.sh" "$root/scripts/check-writing-patterns.txt" "$repo/scripts/"
    git -C "$repo" init -q
    git -C "$repo" config user.email test@example.invalid
    git -C "$repo" config user.name test
    git -C "$repo" config commit.gpgsign false
    printf 'Clean text.\n' >"$repo/README.md"
    git -C "$repo" add -A
    git -C "$repo" commit -q -m 'Add clean text'
}

pass() { cases=$((cases + 1)); }
fail() { cases=$((cases + 1)); failures=$((failures + 1)); printf 'FAIL: %s\n' "$1" >&2; }

# tree_leaks NAME PATH LINE LABEL: the check must fail and print LABEL.
tree_leaks() {
    local name=$1 path=$2 line=$3 label=$4 out
    new_repo
    mkdir -p "$repo/$(dirname "$path")"
    printf '%s\n' "$line" >"$repo/$path"
    git -C "$repo" add -A
    if out=$(bash "$repo/scripts/check-writing.sh" 2>&1); then
        fail "$name: the check passed"
    elif ! grep -qF "$label" <<<"$out"; then
        fail "$name: the output lacks '$label'"
    else
        pass
    fi
}

# tree_clean NAME PATH LINE: the check must pass.
tree_clean() {
    local name=$1 path=$2 line=$3 out
    new_repo
    mkdir -p "$repo/$(dirname "$path")"
    printf '%s\n' "$line" >"$repo/$path"
    git -C "$repo" add -A
    if out=$(bash "$repo/scripts/check-writing.sh" 2>&1); then
        pass
    else
        fail "$name: the check failed: $out"
    fi
}

# commit_case NAME EXPECT MESSAGE LABEL: commit MESSAGE, then check the range.
commit_case() {
    local name=$1 expect=$2 message=$3 label=${4:-} out status=0
    new_repo
    printf 'change\n' >>"$repo/README.md"
    git -C "$repo" commit -q -a -m "$message"
    out=$(bash "$repo/scripts/check-writing.sh" --commits HEAD~1..HEAD 2>&1) || status=$?
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

tree_clean 'clean text' docs/a.md 'The code rejects unknown keys.'
tree_clean 'anchor link' docs/a.md 'See [the spec](SPEC-A.md'"${hash}"'54-verification).'
tree_clean 'standard name' docs/a.md 'Use PKCS'"${hash}"'11 and C'"${hash}"'.'
tree_clean 'git tracked as a file' src/a.rs '// The path is tracked as a file.'
tree_clean 'old name in the changelog' CHANGELOG.md "Renamed from $w_old."
tree_clean 'old name in the installer' install.sh "# Move the old $w_old directory."
tree_clean 'frozen seed' docs/a.md "The seed is $w_seed."

tree_leaks 'bare issue number' docs/a.md "Fixes ${hash}123." 'issue or pull request number'
tree_leaks 'external issue number' docs/a.md "See org${hash}123 for details." 'external issue number'
tree_leaks 'external repo issue number' docs/a.md "See acme/widget${hash}45." 'external issue number'
tree_leaks 'deferred as' docs/a.md "This is ${w_tracked} as an issue." 'pointer to later work'
tree_leaks 'deferred as later work' docs/a.md "This is ${w_tracked} as ${w_follow}." 'pointer to later work'
tree_leaks 'later issue' docs/a.md "Open a ${w_follow} issue for it." 'pointer to later work'
tree_leaks 'unnamed issue' docs/a.md "The ${w_orig} issue asks for it." 'reference to an issue'
tree_leaks 'work item id' docs/a.md "See ${w_wp}-12." 'work item id'
tree_leaks 'phase label in code' src/a.rs "// ${w_phase} 2 adds the parser." 'plan label'
tree_leaks 'phase label in docs' docs/a.md "The ${w_phase} 3 work." 'plan label'
tree_leaks 'phase label in a workflow' .github/workflows/x.yml "# ${w_phase} 1 job" 'plan label'
tree_leaks 'package label' docs/a.md "This ${w_package} adds it." 'plan label'
tree_leaks 'board word one' docs/a.md "The next ${w_milestone} ships it." 'plan board word'
tree_leaks 'board word two' .github/workflows/x.yml "# Sync with the ${w_tracker}." 'plan board word'
tree_leaks 'tool name' src/a.rs "// Written by ${w_tool}." 'tool or model name'
tree_leaks 'old product name' docs/a.md "The ${w_old} format." 'old product name'
tree_leaks 'old product name in code' src/a.rs "const DIR: &str = \".${w_old}\";" 'old product name'

commit_case 'clean commit' pass 'Reject unknown config keys'
commit_case 'commit issue number' fail "Fix the parser (${hash}12)" 'issue or pull request number'
commit_case 'commit external issue number' fail "Fix the parser, see org${hash}12" 'external issue number'
commit_case 'commit phase word' fail "Add the parser in ${w_phase} two" 'plan label'
commit_case 'commit process word' fail "Add the parser for the ${w_ticket}" 'process word in a commit message'
commit_case 'commit old name' fail "Rename the ${w_old} directory" 'old product name'
commit_case 'commit tool name' fail "Review by ${w_tool}" 'tool or model name'
commit_case 'commit follow-up pointer' fail "Add the parser, ${w_tracked} as ${w_follow} issue" 'pointer to later work'
commit_case 'commit body leak' fail "$(printf 'Add the parser\n\nThis closes the %s.' "$w_ticket")" 'process word in a commit message'
commit_case 'commit trailer' fail "$(printf 'Add the parser\n\nCo-authored-by: Someone <a@example.invalid>')" 'trailer'
commit_case 'commit long subject' fail "$(printf 'Add %0100d' 0)" 'longer than 72'

# A range with an old leaking commit and a clean new commit checks only the new one.
new_repo
printf 'change\n' >>"$repo/README.md"
git -C "$repo" commit -q -a -m "Fix the parser (${hash}12)"
printf 'more\n' >>"$repo/README.md"
git -C "$repo" commit -q -a -m 'Reject unknown config keys'
if bash "$repo/scripts/check-writing.sh" --commits HEAD~1..HEAD >/dev/null 2>&1; then pass; else fail 'range limit'; fi
if bash "$repo/scripts/check-writing.sh" --commits HEAD~2..HEAD >/dev/null 2>&1; then fail 'range includes leak'; else pass; fi

# An empty range passes.
new_repo
if bash "$repo/scripts/check-writing.sh" --commits HEAD..HEAD >/dev/null 2>&1; then pass; else fail 'empty range'; fi

# A bad argument fails.
if bash "$repo/scripts/check-writing.sh" --bogus >/dev/null 2>&1; then fail 'bad argument'; else pass; fi

if [ "$failures" -ne 0 ]; then
    printf '%d of %d writing-check cases failed\n' "$failures" "$cases" >&2
    exit 1
fi
printf 'writing-check tests: %d cases ok\n' "$cases"

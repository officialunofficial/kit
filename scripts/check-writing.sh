#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Fail when text points at an issue system, a plan label, a tool or the old
# product name, as the "Writing" rules in AGENTS.md forbid. The patterns live in
# scripts/check-writing-patterns.txt. This script skips that file.
#
# Two modes:
#   bash scripts/check-writing.sh                   scan every tracked file
#   bash scripts/check-writing.sh --commits RANGE   scan the commit messages
#                                                   in a git revision range
#
# The commit scan skips the hashes in scripts/check-writing-known-commits.txt.
# A commit message also needs a subject of at most 72 characters.
# Needs git built with PCRE support (git grep -P).

set -euo pipefail

cd "$(dirname "$0")/.."

PATTERNS=scripts/check-writing-patterns.txt
KNOWN=scripts/check-writing-known-commits.txt

# Paths that may name the banned words. AGENTS.md and CONTRIBUTING.md state
# the rule itself. .gitignore keeps local tool state out of the tree.
EXCLUDES=(
    ':(exclude)AGENTS.md'
    ':(exclude)CONTRIBUTING.md'
    ":(exclude)$PATTERNS"
    ':(exclude).gitignore'
    ':(exclude)rust/Cargo.lock'
)

fail=0

# patterns SCOPE: print "label@@regex@@extra" for each pattern in SCOPE or both.
patterns() {
    local scope=$1 line s rest
    while IFS= read -r line || [ -n "$line" ]; do
        case $line in '' | '#'*) continue ;; esac
        s=${line%%@@*}
        rest=${line#*@@}
        if [ "$s" = "$scope" ] || [ "$s" = both ]; then
            printf '%s\n' "$rest"
        fi
    done <"$PATTERNS"
}

scan_tree() {
    local entry label regex extra hits spec
    while IFS= read -r entry; do
        label=${entry%%@@*}
        regex=${entry#*@@}
        extra=
        case $regex in *@@*) extra=${regex#*@@}; regex=${regex%%@@*} ;; esac
        spec=("${EXCLUDES[@]}")
        for p in $extra; do spec+=(":(exclude)$p"); done
        hits=$(git grep -nIP -e "$regex" -- . "${spec[@]}" || true)
        if [ -n "$hits" ]; then
            printf '::error::%s\n%s\n\n' "$label" "$hits" >&2
            fail=1
        fi
    done < <(patterns tree)
}

scan_commits() {
    local range=$1 work commit msg subject entry label regex hits
    work=$(mktemp -d)
    # shellcheck disable=SC2064
    trap "rm -rf '$work'" EXIT
    while IFS= read -r commit; do
        [ -n "$commit" ] || continue
        if [ -f "$KNOWN" ] && grep -qxF "$commit" "$KNOWN"; then
            continue
        fi
        msg=$work/message
        git log -1 --format=%B "$commit" >"$msg"
        subject=$(git log -1 --format=%s "$commit")
        if [ "${#subject}" -gt 72 ]; then
            printf '::error::commit %s: subject is longer than 72 characters\n' \
                "$(git rev-parse --short "$commit")" >&2
            fail=1
        fi
        while IFS= read -r entry; do
            label=${entry%%@@*}
            regex=${entry#*@@}
            regex=${regex%%@@*}
            hits=$(cd "$work" && git grep --no-index -nIP -e "$regex" -- message || true)
            if [ -n "$hits" ]; then
                printf '::error::commit %s: %s\n%s\n\n' \
                    "$(git rev-parse --short "$commit")" "$label" "$hits" >&2
                fail=1
            fi
        done < <(patterns commit)
    done < <(git rev-list --reverse "$range")
}

case ${1:-} in
    '') scan_tree ;;
    --commits)
        [ $# -eq 2 ] || { echo 'usage: check-writing.sh [--commits RANGE]' >&2; exit 2; }
        scan_commits "$2"
        ;;
    *) echo 'usage: check-writing.sh [--commits RANGE]' >&2; exit 2 ;;
esac

if [ "$fail" -eq 0 ]; then
    echo 'writing check: ok'
fi
exit "$fail"

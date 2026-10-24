#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Fail when tracked text names a tracker, a plan label or a tool, as the
# "Writing" rules in AGENTS.md forbid. Code, docs, comments, test names and
# fixtures describe what the code does now. They do not point at tickets,
# pull requests, phases, work packages or tools.
#
# Run from any directory:  bash scripts/check-writing.sh
# Needs GNU grep or git built with PCRE support (git grep -P).

set -euo pipefail

cd "$(dirname "$0")/.."

# Paths that may name the banned words. AGENTS.md states the rule itself.
# This script holds the patterns. .gitignore keeps local tool state out of
# the tree.
EXCLUDES=(
    ':(exclude)AGENTS.md'
    ':(exclude)scripts/check-writing.sh'
    ':(exclude).gitignore'
    ':(exclude)rust/Cargo.lock'
)

fail=0

# check LABEL REGEX: print every tracked line that matches REGEX.
check() {
    local label=$1 regex=$2 hits
    hits=$(git grep -nIP -e "$regex" -- . "${EXCLUDES[@]}" || true)
    if [ -n "$hits" ]; then
        printf '::error::%s\n%s\n\n' "$label" "$hits" >&2
        fail=1
    fi
}

check 'issue or pull request number' \
    '(?<![\w&:/])#[0-9]+(?![0-9a-z-])|\b(?i:issues?|prs?|pull requests?) #?[0-9]+\b|\bkit#[0-9]+'
check 'reference to an issue or review that the text does not name' \
    '\b(?i:originating issue|this issue|the issue.s|sibling issues?|the review.s)\b'
check 'tracker id' \
    '\b(?:WP|KIT|LIN|ENG|UNO)-[0-9]|\bWP[0-9]|\bR-[0-9]{2,}\b|\bred-team\b'
check 'phase, stage, part or work package label' \
    '\b[Pp]hase[ -]?-?[0-9]|\bStage [0-9]|\bPart [0-9]|\b[Ww]ork packages?\b|\bM[1-9]\b|\b[Ee]pic\b'
check 'review finding label' \
    '\b[Ff]inding [0-9]|\bReview P[0-9]|\b[Rr]eviewer finding'
check 'tool or model name' \
    '\b(?:Claude|Anthropic|Codex|ChatGPT|OpenAI|Copilot|Gemini|Codecov|LLMs?|GPT)\b|\bclaude\b'

if [ "$fail" -eq 0 ]; then
    echo 'writing check: ok'
fi
exit "$fail"

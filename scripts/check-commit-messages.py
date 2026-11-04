#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Check the commit messages of a revision range against the Commits rules.

Usage:  python3 -I -B scripts/check-commit-messages.py RANGE

The check applies to each non-merge commit in RANGE:
  - the header has the form  type(scope)!: subject  with an optional scope
    and an optional "!";
  - the type is one of feat, fix, docs, refactor, perf, test, build, ci, chore;
  - the header has at most 72 characters;
  - no trailer names a tool or a model.

Whether the subject is in the imperative mood is not machine-checkable, so the
check skips it. Merge commits are skipped. The caller passes the range of one
pull request, so older history never fails the check. The tool and model names
come from scripts/check-writing-patterns.txt.
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TYPES = ("feat", "fix", "docs", "refactor", "perf", "test", "build", "ci", "chore")
MAX_HEADER = 72
HEADER = re.compile(r"^(?P<type>[a-z]+)(?:\((?P<scope>[A-Za-z0-9._/-]+)\))?!?: (?P<subject>\S.*)$")
TRAILER = re.compile(r"^[A-Za-z][A-Za-z0-9-]*:\s")


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True, text=True).stdout


def tool_regex():
    for line in (ROOT / "scripts/check-writing-patterns.txt").read_text().splitlines():
        parts = line.split("@@")
        if len(parts) >= 3 and parts[1] == "tool or model name":
            return re.compile(parts[2])
    sys.exit("check-commit-messages: no tool or model pattern found")


def trailers(body_lines):
    """Return every body line in trailer form. A trailer needs no blank line before it."""
    return [line for line in body_lines if TRAILER.match(line)]


def problems(message, tools):
    lines = message.rstrip("\n").split("\n")
    header = lines[0]
    found = []
    match = HEADER.match(header)
    if not match:
        found.append("header is not in the form type(scope)!: subject")
    elif match["type"] not in TYPES:
        found.append(f"type '{match['type']}' is not one of {', '.join(TYPES)}")
    if len(header) > MAX_HEADER:
        found.append(f"header is longer than {MAX_HEADER} characters")
    for line in trailers(lines[1:]):
        if tools.search(line):
            found.append(f"trailer names a tool or a model: {line}")
    return found


def main(argv):
    if len(argv) != 2:
        print("usage: check-commit-messages.py RANGE", file=sys.stderr)
        return 2
    tools = tool_regex()
    failed = False
    for commit in git("rev-list", "--reverse", "--no-merges", argv[1]).split():
        for text in problems(git("log", "-1", "--format=%B", commit), tools):
            print(f"::error::commit {commit[:12]}: {text}", file=sys.stderr)
            failed = True
    if failed:
        return 1
    print("commit message check: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

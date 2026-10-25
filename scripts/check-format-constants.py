#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Check that each string or byte-string constant value has one owner.

A format constant, such as a ref name or a file name, must be defined once.
Other code imports it. The script reads the production source of every crate
and fails when two `const` or `static` items hold the same literal value. It
also fails when a production file other than the owner repeats the literal of
a constant under the `refs/kit/` namespace. The script needs only the Python
standard library.
"""

import re
import sys
from collections import defaultdict
from pathlib import Path

# An optional first argument names another repository root, for the test.
ROOT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent
SOURCES = ROOT / "rust"
SKIP_DIRS = {"target", "tests", "generated", "fuzz", "benches"}
# `const NAME: &str = "value";` and `const NAME: &[u8; 4] = b"value";`
ITEM = re.compile(
    r'^\s*(?:pub(?:\([a-z]+\))?\s+)?(?:const|static)\s+([A-Z][A-Z0-9_]*)\s*:\s*'
    r'&(?:\'static\s+)?(?:str|\[u8(?:;\s*[A-Za-z0-9_]+)?\])\s*=\s*b?"((?:[^"\\]|\\.)*)"\s*;'
)
KIT_REF_NAMESPACE = "refs/kit/"
MIN_LEN = 4
# Values that two items share by chance. Each names two different purposes.
SHARED_BY_CHANCE = {
    "0123456789abcdef": "the lower-case hex digit table, not a format value",
    "refs": "a directory name in kit-core and a file name in the git bridge",
}


def production_files():
    for path in sorted(SOURCES.rglob("*.rs")):
        parts = set(path.relative_to(SOURCES).parts)
        if parts & SKIP_DIRS or path.name == "tests.rs":
            continue
        yield path


def production_lines(text):
    """Yield (number, line) up to the `#[cfg(test)]` line of a test module."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line == "#[cfg(test)]":
            following = next((l for l in lines[index + 1:] if not l.lstrip().startswith("#[")), "")
            if following.lstrip().startswith("mod "):
                return
        yield index + 1, line


def main():
    owners = defaultdict(list)
    ref_values = {}
    files = {}
    for path in production_files():
        text = path.read_text(encoding="utf-8")
        files[path] = text
        for number, line in production_lines(text):
            match = ITEM.match(line)
            if not match:
                continue
            name, value = match.groups()
            if len(value) < MIN_LEN:
                continue
            owners[value].append(f"{path.relative_to(ROOT)}:{number} {name}")
            if value.startswith(KIT_REF_NAMESPACE):
                ref_values[value] = path
    failures = 0
    for value, places in sorted(owners.items()):
        if len(places) > 1 and value not in SHARED_BY_CHANCE:
            failures += 1
            print(f'constant value "{value}" has {len(places)} owners:', file=sys.stderr)
            for place in places:
                print(f"  {place}", file=sys.stderr)
    for value, owner in sorted(ref_values.items()):
        quoted = f'"{value}'
        for path, text in files.items():
            if path == owner:
                continue
            for number, line in production_lines(text):
                if quoted in line and not line.lstrip().startswith("//"):
                    failures += 1
                    print(
                        f'{path.relative_to(ROOT)}:{number}: repeats "{value}", '
                        f"which {owner.relative_to(ROOT)} owns",
                        file=sys.stderr,
                    )
    if not owners:
        print("check-format-constants: found no constants; the pattern is stale", file=sys.stderr)
        return 1
    if failures:
        return 1
    print(f"check-format-constants: {sum(len(p) for p in owners.values())} constants, each value has one owner")
    return 0


if __name__ == "__main__":
    sys.exit(main())

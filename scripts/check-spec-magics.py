#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Check that each magic in the specs matches the hex bytes written beside it.

A spec line that gives a quoted magic and then hex bytes, such as
`"KIDX" = 0x4B 0x49 0x44 0x58`, must give the bytes of that exact ASCII text.
The text may use the escape \\0 for a zero byte. The script needs only the
Python standard library.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PAIR = re.compile(r'"((?:[^"\\]|\\0)+)"[^\n"]*?((?:\b0x[0-9A-Fa-f]{2}\b[ ,]*){2,})')


def main():
    failures = 0
    checked = 0
    for spec in sorted((ROOT / "docs/specs").glob("SPEC-*.md")):
        for number, line in enumerate(spec.read_text(encoding="utf-8").splitlines(), 1):
            for match in PAIR.finditer(line):
                text, hexes = match.groups()
                expected = text.replace("\\0", "\x00").encode("ascii")
                actual = bytes(int(h, 16) for h in re.findall(r"0x([0-9A-Fa-f]{2})", hexes))
                checked += 1
                if expected != actual:
                    failures += 1
                    print(
                        f"{spec.name}:{number}: magic \"{text}\" is {expected.hex()} "
                        f"but the line gives {actual.hex()}",
                        file=sys.stderr,
                    )
    if checked == 0:
        print("check-spec-magics: found no magic with hex bytes; the pattern is stale", file=sys.stderr)
        return 1
    if failures:
        return 1
    print(f"check-spec-magics: {checked} magics match their hex bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())

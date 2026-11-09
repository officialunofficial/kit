#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Independent reference check of the ref lock stripe vectors:
#   rust/tests/golden/ref-locks/vectors.txt
#
# The check shares no code with the Rust crates. It reads only SPEC-REFS
# section 3 (the ref name grammar) and section 5.1.1 (the stripe of a ref is
# the first byte of the BLAKE3 digest of the full ref name; its lock file is
# `refs-<hh>.lock`, `<hh>` two lowercase hex digits). BLAKE3 comes from the
# pure-Python blake3_subtree_ref.py.
#
# The check:
#   * matches vectors.txt against its MANIFEST.txt digest;
#   * parses every line strictly: `#` comment lines, or exactly three fields
#     `<name> <hh> <lock>` separated by one space, with no blank line, no
#     trailing space, no CR and a final newline;
#   * checks each name against the SPEC-REFS section 3 grammar, including
#     the 512-byte and 32-segment bounds, and rejects a repeated name;
#   * requires `<hh>` to be two lowercase hex digits and `<lock>` to be
#     exactly `refs-<hh>.lock`;
#   * recomputes the stripe of every name and compares it;
#   * checks the coverage the vector set promises: `refs/heads/main` in
#     stripe `ec` (the spec's example), a ref and a ref below it, a name of
#     512 bytes, a name of 32 segments, two names that share a stripe, at
#     least 40 names, and every stripe in 00..0f and f0..ff.
#
# Usage:
#   python3 -I -B scripts/golden/ref_locks_ref.py rust/tests/golden
#
# Exit 0 and print "OK" when every check passes; exit 1 otherwise.

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from blake3_subtree_ref import blake3  # noqa: E402

D = "ref-locks"
FILE = "vectors.txt"
MAX_NAME = 512
MAX_SEGMENTS = 32
MAX_FILE = 1 << 20
SEGMENT = re.compile(r"[0-9A-Za-z._-]+\Z")
HEX2 = re.compile(r"[0-9a-f]{2}\Z")
FAILURES = []


def expect(cond, msg):
    if not cond:
        FAILURES.append(msg)
        print("FAIL:", msg, flush=True)


def valid_ref_name(name):
    """SPEC-REFS section 3."""
    if not name or not name.isascii() or len(name) > MAX_NAME:
        return False
    segments = name.split("/")
    if len(segments) > MAX_SEGMENTS:
        return False
    for seg in segments:
        if not SEGMENT.match(seg) or seg.startswith(".") or seg.endswith(".lock"):
            return False
    return segments[-1] != "HEAD"


def stripe(name):
    """SPEC-REFS section 5.1.1."""
    return blake3(name.encode("ascii"))[0]


def manifest_digest(root):
    with open(os.path.join(root, D, "MANIFEST.txt"), encoding="utf-8") as f:
        for line in f.read().splitlines():
            if line and not line.startswith("#"):
                name, digest = line.split()[:2]
                if name == FILE:
                    return digest
    return None


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: ref_locks_ref.py <rust/tests/golden>")
    root = sys.argv[1]
    path = os.path.join(root, D, FILE)
    if os.path.getsize(path) > MAX_FILE:
        sys.exit("FAIL: vectors.txt is too large")
    with open(path, "rb") as f:
        raw = f.read()
    expect(blake3(raw).hex() == manifest_digest(root), "vectors.txt does not match MANIFEST.txt")
    expect(raw.endswith(b"\n"), "vectors.txt must end with a newline")
    expect(b"\r" not in raw, "vectors.txt holds a CR")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        sys.exit("FAIL: vectors.txt is not ASCII")

    vectors = {}
    by_stripe = {}
    for n, line in enumerate(text.splitlines(), 1):
        if line.startswith("#"):
            continue
        fields = line.split(" ")
        if len(fields) != 3 or any(not f for f in fields):
            expect(False, f"line {n}: want exactly `<name> <hh> <lock>`")
            continue
        name, hh, lock = fields
        expect(valid_ref_name(name), f"line {n}: not a valid ref name")
        expect(name not in vectors, f"line {n}: repeated name")
        expect(bool(HEX2.match(hh)), f"line {n}: stripe {hh!r} is not two lowercase hex digits")
        expect(lock == f"refs-{hh}.lock", f"line {n}: lock file {lock!r} does not name stripe {hh}")
        if HEX2.match(hh):
            got = stripe(name)
            expect(got == int(hh, 16), f"line {n}: stripe of {name[:60]} is {got:02x}, not {hh}")
            by_stripe.setdefault(int(hh, 16), []).append(name)
        vectors[name] = hh

    expect(vectors.get("refs/heads/main") == "ec", "refs/heads/main must be in stripe ec")
    expect(
        any(b.startswith(a + "/") for a in vectors for b in vectors),
        "no ref and ref below it",
    )
    expect(any(len(v) == MAX_NAME for v in vectors), "no name of 512 bytes")
    expect(any(v.count("/") + 1 == MAX_SEGMENTS for v in vectors), "no name of 32 segments")
    expect(any(len(v) > 1 for v in by_stripe.values()), "no two names share a stripe")
    expect(len(vectors) >= 40, f"only {len(vectors)} vectors")
    ends = set(range(0x00, 0x10)) | set(range(0xF0, 0x100))
    missing = sorted(ends - set(by_stripe))
    expect(not missing, f"stripes not covered: {[f'{s:02x}' for s in missing]}")

    if FAILURES:
        sys.exit(1)
    print(f"OK ({len(vectors)} vectors, {len(by_stripe)} stripes)")


if __name__ == "__main__":
    main()

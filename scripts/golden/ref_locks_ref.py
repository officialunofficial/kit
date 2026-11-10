#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Independent reference check of the ref lock stripe vectors and the stripe
# version vectors:
#   rust/tests/golden/ref-locks/vectors.txt
#   rust/tests/golden/ref-locks/versions.txt
#
# The check shares no code with the Rust crates. It reads only SPEC-REFS
# section 3 (the ref name grammar) and section 5.1.1 (the stripe of a ref is
# the first byte of the BLAKE3 digest of the full ref name; its lock file is
# `refs-<hh>.lock`, `<hh>` two lowercase hex digits) and section 5.1.2 (the
# stripe version is the count of writes to refs in the stripe, 8 bytes
# little-endian at the start of the lock file; an empty file holds 0; any
# other length is corrupt; a write adds one, and the version after
# 2^64 - 1 is 0). BLAKE3 comes from the pure-Python blake3_subtree_ref.py.
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
#     least 40 names, and every stripe in 00..0f and f0..ff;
#   * matches versions.txt against its MANIFEST.txt digest and parses it as
#     strictly: `<bytes> <version> <next bytes>` or `<bytes> corrupt`, bytes
#     in lowercase hex and `-` for the empty file;
#   * recomputes each version and the bytes after one more write, and
#     requires `corrupt` for exactly the lengths other than 0 and 8;
#   * checks the coverage: the empty file, version 0 written out, a carry,
#     a version whose 8 bytes all differ, the largest version, and corrupt
#     files shorter than, longer than and twice 8 bytes.
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
VERSIONS = "versions.txt"
VERSION_LEN = 8
MAX_NAME = 512
MAX_SEGMENTS = 32
MAX_FILE = 1 << 20
SEGMENT = re.compile(r"[0-9A-Za-z._-]+\Z")
HEX2 = re.compile(r"[0-9a-f]{2}\Z")
HEX_BYTES = re.compile(r"(?:[0-9a-f]{2})+\Z")
DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)\Z")
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


def manifest_digest(root, file):
    with open(os.path.join(root, D, "MANIFEST.txt"), encoding="utf-8") as f:
        for line in f.read().splitlines():
            if line and not line.startswith("#"):
                name, digest = line.split()[:2]
                if name == file:
                    return digest
    return None


def read_vectors(root, file):
    """The text of a vector file, after the checks every vector file shares."""
    path = os.path.join(root, D, file)
    if os.path.getsize(path) > MAX_FILE:
        sys.exit(f"FAIL: {file} is too large")
    with open(path, "rb") as f:
        raw = f.read()
    expect(blake3(raw).hex() == manifest_digest(root, file), f"{file} does not match MANIFEST.txt")
    expect(raw.endswith(b"\n"), f"{file} must end with a newline")
    expect(b"\r" not in raw, f"{file} holds a CR")
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError:
        sys.exit(f"FAIL: {file} is not ASCII")


def file_bytes(field):
    """The bytes a `<bytes>` field names, or None when it is malformed."""
    if field == "-":
        return b""
    if not HEX_BYTES.match(field):
        return None
    return bytes.fromhex(field)


def check_versions(root):
    """SPEC-REFS section 5.1.2. Returns the number of vectors."""
    text = read_vectors(root, VERSIONS)
    seen = set()
    versions = set()
    corrupt_lengths = set()
    for n, line in enumerate(text.splitlines(), 1):
        if line.startswith("#"):
            continue
        fields = line.split(" ")
        if len(fields) not in (2, 3) or any(not f for f in fields):
            expect(False, f"{VERSIONS} line {n}: want `<bytes> <version> <next>` or `<bytes> corrupt`")
            continue
        data = file_bytes(fields[0])
        if data is None:
            expect(False, f"{VERSIONS} line {n}: {fields[0]!r} is not lowercase hex or `-`")
            continue
        expect(fields[0] not in seen, f"{VERSIONS} line {n}: repeated bytes")
        seen.add(fields[0])
        valid = len(data) in (0, VERSION_LEN)
        if len(fields) == 2:
            expect(fields[1] == "corrupt", f"{VERSIONS} line {n}: two fields must end in `corrupt`")
            expect(not valid, f"{VERSIONS} line {n}: a file of {len(data)} bytes is not corrupt")
            corrupt_lengths.add(len(data))
            continue
        expect(valid, f"{VERSIONS} line {n}: a file of {len(data)} bytes is corrupt")
        if not valid:
            continue
        version = int.from_bytes(data, "little")
        expect(bool(DECIMAL.match(fields[1])), f"{VERSIONS} line {n}: version {fields[1]!r} is not decimal")
        expect(fields[1] == str(version), f"{VERSIONS} line {n}: version is {version}, not {fields[1]}")
        after = ((version + 1) % (1 << 64)).to_bytes(VERSION_LEN, "little").hex()
        expect(fields[2] == after, f"{VERSIONS} line {n}: one more write leaves {after}, not {fields[2]}")
        versions.add((fields[0], version))

    expect(("-", 0) in versions, "no empty lock file")
    expect(("00" * VERSION_LEN, 0) in versions, "no version 0 written out")
    expect(any(v == 255 for _, v in versions), "no carry into the second byte")
    expect(
        any(len(set(bytes.fromhex(b))) == VERSION_LEN for b, _ in versions if b != "-"),
        "no version whose bytes all differ",
    )
    expect(any(v == (1 << 64) - 1 for _, v in versions), "no largest version")
    expect(any(0 < n < VERSION_LEN for n in corrupt_lengths), "no corrupt file shorter than 8 bytes")
    expect(any(n > VERSION_LEN for n in corrupt_lengths), "no corrupt file longer than 8 bytes")
    expect(2 * VERSION_LEN in corrupt_lengths, "no corrupt file of 16 bytes")
    return len(seen)


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: ref_locks_ref.py <rust/tests/golden>")
    root = sys.argv[1]
    text = read_vectors(root, FILE)

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

    version_vectors = check_versions(root)

    if FAILURES:
        sys.exit(1)
    print(f"OK ({len(vectors)} vectors, {len(by_stripe)} stripes, {version_vectors} version vectors)")


if __name__ == "__main__":
    main()

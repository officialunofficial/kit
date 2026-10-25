#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Independent reference check of the refs and index golden vectors:
#   rust/tests/golden/refs-index/
#
# The check shares no code with the Rust crates. It reads only SPEC-INDEX
# section 2 and 3 and SPEC-REFS section 2. BLAKE3 comes from the pure-Python
# transcription in blake3_subtree_ref.py.
#
# For each vector the check:
#   * compares the file with the size and BLAKE3 in its sidecar and in
#     MANIFEST.txt;
#   * parses each index strictly: magic, version 3, entry count bound,
#     status byte, path rules, duplicate paths, checksum and no trailing byte;
#   * rebuilds each index from the pinned inputs and compares the bytes;
#   * checks the detached ref and the symbolic HEAD against their grammar.
#
# The pinned inputs are the ASCII seeds "refs-index-blob", "refs-index-tree",
# "refs-index-exe" and "refs-index-detached-head". Each object hash is the
# BLAKE3 digest of its seed.
#
# Usage:
#   python3 -I -B scripts/golden/refs_index_ref.py rust/tests/golden
#
# Exit 0 and print "OK" when every check passes; exit 1 otherwise.

import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import objects_ref as o  # noqa: E402
from objects_ref import blake3, expect  # noqa: E402

MAGIC = b"KIDX"
VERSION = 3
STATUSES = {0x00, 0x01, 0x02, 0x03, 0x04}
MAX_PATH = 4096
MIN_ENTRY = 67


def check_path(path):
    if not 0 < len(path) <= MAX_PATH:
        raise ValueError("path length")
    text = path.decode("utf-8")
    if text.startswith("/") or "\\" in text or "\x00" in text:
        raise ValueError("forbidden byte or leading slash")
    segments = text.split("/")
    if any(s in ("", ".", "..") for s in segments):
        raise ValueError("bad segment")
    if segments[0] in (".kit", ".git"):
        raise ValueError("reserved path")


def parse_index(data):
    """SPEC-INDEX section 2 and 5. Returns the list of entries."""
    if len(data) < 41:
        raise ValueError("short file")
    body, checksum = data[:-32], data[-32:]
    if blake3(body) != checksum:
        raise ValueError("checksum mismatch")
    r = o.Reader(body)
    if r.take(4) != MAGIC:
        raise ValueError("bad magic")
    if r.u8() != VERSION:
        raise ValueError("unsupported version")
    count = r.u32()
    if count * MIN_ENTRY > len(body) - 9:
        raise ValueError("count exceeds buffer")
    entries, seen = [], set()
    for _ in range(count):
        status = r.u8()
        if status not in STATUSES:
            raise ValueError("bad status")
        object_hash = r.take(32)
        if status == 0 and object_hash != bytes(32):
            raise ValueError("removed entry with a hash")
        stat = struct.unpack("<QQQQ", r.take(32))
        path = r.take(r.u16())
        check_path(path)
        if path in seen:
            raise ValueError("duplicate path")
        seen.add(path)
        entries.append((status, object_hash, stat, path))
    r.end()
    return entries


def build_index(entries):
    body = MAGIC + bytes([VERSION]) + struct.pack("<I", len(entries))
    for status, object_hash, stat, path in entries:
        body += bytes([status]) + object_hash + struct.pack("<QQQQ", *stat)
        body += struct.pack("<H", len(path)) + path
    return body + blake3(body)


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: refs_index_ref.py <rust/tests/golden>")
    root = sys.argv[1]
    files, _ = o.check_files(root, "refs-index")
    zero = (0, 0, 0, 0)

    expect(parse_index(files["index_empty"]) == [], "index_empty has entries")
    expect(len(files["index_empty"]) == 41, "index_empty is not 41 bytes")
    expect(build_index([]) == files["index_empty"], "index_empty rebuild differs")

    want = [
        (0x01, blake3(b"refs-index-blob"), zero, b"README.md"),
        (0x02, blake3(b"refs-index-tree"), zero, b"src"),
        (0x04, blake3(b"refs-index-exe"), zero, b"scripts/build"),
    ]
    try:
        got = parse_index(files["index_3entries"])
    except ValueError as e:
        o.fail(f"index_3entries: {e}")
        got = None
    expect(got == want, "index_3entries entries differ from the pinned inputs")
    expect(build_index(want) == files["index_3entries"], "index_3entries rebuild differs")

    # A bit flip in a staged hash must fail the checksum (SPEC-INDEX section 6).
    flipped = bytearray(files["index_3entries"])
    flipped[12] ^= 1
    try:
        parse_index(bytes(flipped))
        o.fail("a flipped hash bit passed the checksum")
    except ValueError:
        pass

    detached = files["ref_detached"]
    expect(
        re.fullmatch(rb"[0-9a-f]{64}\n", detached) is not None,
        "ref_detached is not 64 lowercase hex digits and a newline",
    )
    expect(
        detached == blake3(b"refs-index-detached-head").hex().encode() + b"\n",
        "ref_detached differs from the pinned input",
    )
    expect(
        re.fullmatch(rb"ref: refs/heads/[0-9A-Za-z._-]+\n", files["head_symbolic"]) is not None,
        "head_symbolic does not match the HEAD grammar",
    )
    if o.FAILURES:
        sys.exit(1)
    print("OK")


if __name__ == "__main__":
    main()

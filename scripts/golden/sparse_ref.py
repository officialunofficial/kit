#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Independent reference check of the sparse checkout golden vector:
#   rust/tests/golden/sparse/response_v2.bin
#
# The check shares no code with the Rust crates. It reads only
# SPEC-SPARSE-CHECKOUT section 2 and 4 and SPEC-OBJECTS / SPEC-MERKLE-OBJECTS.
# BLAKE3 and the strict tree parser come from objects_ref.py.
#
# The check:
#   * parses the envelope: magic KSP1, version 2, the canonical tree id, the
#     filter commitment, an exact serialized tree length and no trailing byte;
#   * parses the tree strictly and compares its bytes with a rebuilt tree;
#   * recomputes the tree id with the merkle rule and compares it;
#   * recomputes the filter commitment for the pinned filter, which is the single
#     path `a`, and compares it;
#   * checks that the commitment of a changed filter differs.
#
# Usage:
#   python3 -I -B scripts/golden/sparse_ref.py rust/tests/golden
#
# Exit 0 and print "OK" when every check passes; exit 1 otherwise.

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import objects_ref as o  # noqa: E402
from objects_ref import blake3, expect  # noqa: E402

MAX_ENVELOPE = 16 << 20


def filter_commitment(paths):
    """SPEC-SPARSE-CHECKOUT section 2."""
    body = b"kit-sparse-filter-v2\x00"
    for path in sorted(set(paths)):
        raw = path.encode("utf-8")
        body += struct.pack("<Q", len(raw)) + raw
    return blake3(body)


def parse_envelope(data):
    if len(data) > MAX_ENVELOPE:
        raise ValueError("envelope too large")
    r = o.Reader(data)
    if r.take(4) != b"KSP1":
        raise ValueError("bad magic")
    if r.u8() != 2:
        raise ValueError("unsupported version")
    tree_id, commitment = r.take(32), r.take(32)
    tree_bytes = r.take(r.u32())
    r.end()
    tree = o.parse_tree(tree_bytes)
    if o.tree_id(tree["entries"]) != tree_id:
        raise ValueError("tree id differs from the witness")
    return tree_id, commitment, tree_bytes, tree["entries"]


def serialize_tree(entries):
    body = b"\x02KOB1\x01" + struct.pack("<I", len(entries))
    for name, mode, h in entries:
        body += struct.pack("<I", len(name)) + name + bytes([mode]) + h
    return body


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: sparse_ref.py <rust/tests/golden>")
    root = sys.argv[1]
    data = o.read(root, "sparse", "response_v2.bin")
    tree_id, commitment, tree_bytes, entries = parse_envelope(data)
    expect(serialize_tree(entries) == tree_bytes, "the witness does not reserialize to its bytes")
    expect(
        entries == [(b"a", 1, b"\x01" * 32), (b"b", 1, b"\x02" * 32)],
        "tree entries differ from the pinned fixture",
    )
    expect(commitment == filter_commitment(["a"]), "filter commitment of the filter [a]")
    expect(commitment not in (filter_commitment([]), filter_commitment(["b"])), "a different filter has the same commitment")
    expect(filter_commitment(["b", "a", "a"]) == filter_commitment(["a", "b"]), "filter sorting and deduplication")
    for bad in (data[:-1], data + b"\x00", b"KSPC" + data[4:], data[:4] + b"\x01" + data[5:]):
        try:
            parse_envelope(bad)
            o.fail("a malformed envelope was accepted")
        except ValueError:
            pass
    if o.FAILURES:
        sys.exit(1)
    print("OK")


if __name__ == "__main__":
    main()

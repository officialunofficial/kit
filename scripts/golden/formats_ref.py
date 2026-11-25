#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Independent reference check of the format vectors:
#   rust/tests/golden/formats/
#
# The check shares no code with the Rust crates. It reads only SPEC-OBJECTS,
# SPEC-MERKLE-OBJECTS, SPEC-TRANSPORT-CONNECT (pack list), SPEC-SPARSE-CHECKOUT
# and SPEC-WORKTREE (stash manifest). BLAKE3 and the strict object parsers come
# from objects_ref.py.
#
# The check:
#   * parses every object vector named in object-ids.txt strictly, derives its
#     id (the BMT root for a tree or a chunked manifest, the BLAKE3 of the
#     bytes for any other type) and compares the id and the type;
#   * parses both pack list nodes (magic KPKL, version 1, an optional previous
#     key, a length-prefixed list of keys, no trailing byte) and compares them
#     with the pinned seeds;
#   * parses the sparse cache envelope (magic KSPC, version 2) and compares it
#     with the sparse wire vector, which differs in the magic only;
#   * parses the stash manifest (magic KSTS, entry count, entries, no trailing
#     byte) and compares it with the pinned entries.
#
# Each pinned input is a seed: its key is the BLAKE3 digest of the ASCII text.
#
# Usage:
#   python3 -I -B scripts/golden/formats_ref.py rust/tests/golden
#
# Exit 0 and print "OK" when every check passes; exit 1 otherwise.

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import objects_ref as o  # noqa: E402
from objects_ref import blake3, expect  # noqa: E402


def seed(text):
    return blake3(text.encode())


def rows(root, name):
    out = []
    for line in o.read(root, "formats", name).decode().splitlines():
        if line and not line.startswith("#"):
            out.append(line.split())
    return out


def varint(r):
    """An unsigned LEB128 length, as the pack list codec writes it."""
    value, shift = 0, 0
    while True:
        byte = r.u8()
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value
        shift += 7


def parse_packlist(data):
    r = o.Reader(data)
    if r.take(4) != b"KPKL":
        raise ValueError("bad magic")
    if r.u8() != 1:
        raise ValueError("unsupported version")
    flag = r.u8()
    if flag not in (0, 1):
        raise ValueError("bad option flag")
    prev = r.take(32) if flag else None
    count = varint(r)
    packs = [r.take(32) for _ in range(count)]
    r.end()
    return prev, packs


def parse_stash(data):
    r = o.Reader(data)
    if r.take(4) != b"KSTS":
        raise ValueError("bad magic")
    count = r.u32()
    entries = []
    for _ in range(count):
        commit = r.take(32)
        parent = r.take(32)
        timestamp = r.u32()
        message = r.take(struct.unpack("<H", r.take(2))[0]).decode("utf-8")
        entries.append((commit, parent, timestamp, message))
    r.end()
    return entries


def check_object_ids(root):
    parsers = {
        "blob": o.parse_blob,
        "commit": o.parse_commit,
        "remix": o.parse_remix,
        "tag": o.parse_tag,
        "tree": o.parse_tree,
        "chunked": o.parse_chunked,
    }
    listed = rows(root, "object-ids.txt")
    expect(len(listed) == 14, "object-ids.txt must list 14 vectors")
    for file, kind, want in listed:
        directory, name = file.split("/")
        data = o.read(root, directory, name)
        try:
            parsed = parsers[kind](data)
        except ValueError as e:
            o.fail(f"{file}: {e}")
            continue
        if kind == "tree":
            got = o.tree_id(parsed["entries"])
        elif kind == "chunked":
            got = o.chunked_id(parsed["total"], parsed["chunk_size"], parsed["chunks"], parsed["ends"])
        else:
            got = blake3(data)
        expect(got.hex() == want, f"{file}: id {got.hex()} differs from {want}")


def check_packlists(root):
    prev, packs = parse_packlist(o.read(root, "formats", "packlist-first.bin"))
    expect(prev is None and packs == [seed("packlist-pack-0")], "packlist-first.bin differs from its seeds")
    prev, packs = parse_packlist(o.read(root, "formats", "packlist-chained.bin"))
    expect(
        prev == seed("packlist-prev") and packs == [seed("packlist-pack-1"), seed("packlist-pack-2")],
        "packlist-chained.bin differs from its seeds",
    )


def check_sparse_cache(root):
    cache = o.read(root, "formats", "sparse-cache.bin")
    wire = o.read(root, "sparse", "response_v2.bin")
    r = o.Reader(cache)
    expect(r.take(4) == b"KSPC", "sparse cache magic")
    expect(r.u8() == 2, "sparse cache version")
    tree_hash = r.take(32)
    r.take(32)  # filter commitment
    tree_bytes = r.take(r.u32())
    r.end()
    tree = o.parse_tree(tree_bytes)
    expect(o.tree_id(tree["entries"]) == tree_hash, "sparse cache tree id differs from the tree")
    expect(cache[4:] == wire[4:], "sparse cache differs from the wire vector beyond the magic")


def check_stash(root):
    entries = parse_stash(o.read(root, "formats", "stash-list.bin"))
    expect(
        entries
        == [
            (seed("stash-commit-1"), seed("stash-parent-1"), 1_700_000_100, "WIP on main: second"),
            (seed("stash-commit-0"), bytes(32), 1_700_000_000, "WIP on a branch: été"),
        ],
        "stash-list.bin differs from its entries",
    )


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: formats_ref.py <rust/tests/golden>")
    root = sys.argv[1]
    try:
        check_object_ids(root)
        check_packlists(root)
        check_sparse_cache(root)
        check_stash(root)
    except ValueError as e:
        o.fail(str(e))
    if o.FAILURES:
        sys.exit(1)
    print("OK")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Check the mixed local pack, including its independently encoded index."""

from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from objects_ref import blake3, chunked_id, parse_blob, parse_chunked, parse_tree, tree_id


def check(directory):
    pack = (directory / "mixed.pack").read_bytes()
    assert (directory / "marker.bin").read_bytes() == b"bmt-v2\nP"
    assert pack[:12] == b"KIT\0" + struct.pack("<II", 1, 4)
    assert pack[-32:] == blake3(pack[:-32])
    key = blake3(pack)
    rows = []
    expected = []
    offset = 12
    for kind in (1, 5, 2, 1):
        tag, size = struct.unpack_from("<BI", pack, offset)
        assert tag == 0
        offset += 5
        obj = pack[offset:offset + size]
        assert len(obj) == size and obj[0] == kind
        if kind == 5:
            meta = parse_chunked(obj)
            identity = chunked_id(meta["total"], meta["chunk_size"], meta["chunks"], meta["ends"])
            assert set(meta["chunks"]) == {rows[0][0]}
        elif kind == 2:
            identity = tree_id(parse_tree(obj)["entries"])
        else:
            parse_blob(obj)
            identity = blake3(obj)
        rows.append((identity, offset, size))
        expected.append(f"{identity.hex()} {size}")
        offset += size
    assert offset == len(pack) - 32
    assert all(row[2] > 16 * 1024 for row in rows[:3])
    assert (directory / "loose.bin").read_bytes() == obj
    assert (directory / "unknown.meta").read_bytes() == b"optional sidecar\n"

    rows.sort()
    assert len({row[0] for row in rows}) == len(rows)
    index = b"KITX" + struct.pack("<II", 1, len(rows))
    index += b"".join(struct.pack("<I", sum(row[0][0] <= i for row in rows)) for i in range(256))
    index += b"".join(row[0] for row in rows)
    index += b"".join(struct.pack("<Q", row[1]) for row in rows)
    index += b"".join(struct.pack("<I", row[2]) for row in rows)
    index += key
    assert (directory / "mixed.idx").read_bytes() == index + blake3(index)
    expected.append(f"pack {key.hex()}")
    assert (directory / "objects.txt").read_text().splitlines() == expected


if __name__ == "__main__":
    check(Path(sys.argv[1]) / "local_pack_mixed")

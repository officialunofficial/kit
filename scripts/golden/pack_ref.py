#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Independent reference check of the pack v2 golden vectors:
#   rust/tests/golden/pack-v2/
#
# The check shares no code with the Rust crates. It reads only SPEC-PACKFILE
# (sections 1 to 4), SPEC-DELTA and SPEC-OBJECTS. BLAKE3 and the strict object
# parsers come from objects_ref.py, which is written from the specs. The zstd
# frames are decoded with the Python standard library (compression.zstd, Python
# 3.14 and later) or with the pinned `zstandard` package.
#
# For each vector the check:
#   * compares the pack with the size and BLAKE3 in its sidecar and in
#     MANIFEST.txt;
#   * checks the magic, the version rule, the trailer and the entry bounds;
#   * rejects entry type 0x01 and rejects 0x03 or 0x04 in a version 1 pack;
#   * decodes each zstd frame, checks the claimed length and the frame offset
#     and length that the sidecar records;
#   * applies each delta stream to its base, which must come earlier in the pack;
#   * derives every object id with the type-dependent rule and compares the
#     id, the length and the digests with the sidecar.
#
# Usage:
#   python3 -I -B scripts/golden/pack_ref.py rust/tests/golden
#
# Exit 0 and print "OK" when every check passes; exit 1 otherwise.

import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import closure_ref as c  # noqa: E402
import objects_ref as o  # noqa: E402
from objects_ref import blake3, expect  # noqa: E402

try:
    from compression import zstd as _zstd

    def zstd_decompress(frame):
        return _zstd.decompress(frame)

except ImportError:
    import zstandard

    def zstd_decompress(frame):
        # The frame header holds the content size, so read one frame whole.
        return zstandard.ZstdDecompressor().decompressobj().decompress(frame)


MAX_RAW_OBJECT_SIZE = 1 << 30


def apply_delta(base, stream):
    """SPEC-DELTA section 4."""
    if len(stream) < 9 or stream[0] != 1:
        raise ValueError("bad delta header")
    base_len, result_len = struct.unpack("<II", stream[1:9])
    if base_len != len(base):
        raise ValueError("base length mismatch")
    pos, out = 9, bytearray()
    while pos < len(stream):
        op = stream[pos]
        pos += 1
        if op & 0x80:
            if op & 0x7F:
                raise ValueError("reserved opcode bits")
            if pos + 6 > len(stream):
                raise ValueError("truncated copy")
            offset, length = struct.unpack("<IH", stream[pos : pos + 6])
            pos += 6
            if length == 0 or offset + length > len(base):
                raise ValueError("bad copy")
            if len(out) + length > result_len:
                raise ValueError("result overrun")
            out += base[offset : offset + length]
        elif op:
            if pos + op > len(stream):
                raise ValueError("truncated insert")
            if len(out) + op > result_len:
                raise ValueError("result overrun")
            out += stream[pos : pos + op]
            pos += op
        else:
            raise ValueError("zero opcode")
    if len(out) != result_len:
        raise ValueError("result underrun")
    return bytes(out)


def inflate(payload):
    """Return (decoded bytes, frame offset in payload) for a 0x03 or 0x04 body."""
    (claimed,) = struct.unpack("<I", payload[:4])
    if claimed > MAX_RAW_OBJECT_SIZE:
        raise ValueError("claimed length over the cap")
    decoded = zstd_decompress(payload[4:])
    if len(decoded) != claimed:
        raise ValueError("decoded length differs from the claim")
    return decoded


def parse_pack(data):
    """SPEC-PACKFILE section 1 to 4. Returns (version, entries).

    Each entry is a dict with the type, the object id, the object bytes and,
    for compressed entries, the decoded stream and the frame position.
    """
    if len(data) < 12 + 32:
        raise ValueError("short pack")
    body, trailer = data[:-32], data[-32:]
    if blake3(body) != trailer:
        raise ValueError("trailer mismatch")
    r = o.Reader(body)
    if r.take(4) != b"KIT\x00":
        raise ValueError("bad magic")
    version = r.u32()
    if version not in (1, 2):
        raise ValueError("unsupported version")
    count = r.u32()
    objects, entries = {}, []
    for _ in range(count):
        kind = r.u8()
        start = r.pos + 4
        payload = r.take(r.u32())
        entry = {"type": kind}
        if kind in (3, 4) and version != 2:
            raise ValueError("compressed entry in a version 1 pack")
        if kind == 0:
            obj = payload
        elif kind == 3:
            obj = inflate(payload)
            entry.update(decoded=obj, frame_offset=start + 4, frame_len=len(payload) - 4)
        elif kind in (2, 4):
            base_hash = payload[:32]
            rest = payload[32:]
            if kind == 4:
                stream = inflate(rest)
                entry.update(decoded=stream, frame_offset=start + 36, frame_len=len(rest) - 4)
            else:
                stream = rest
            if base_hash not in objects:
                raise ValueError("delta base is not earlier in the pack")
            obj = apply_delta(objects[base_hash], stream)
        else:
            raise ValueError(f"invalid entry type {kind:#x}")
        oid = c.object_id(obj)
        objects[oid] = obj
        entry.update(id=oid, obj=obj)
        entries.append(entry)
    r.end()
    # SPEC-PACKFILE section 1: version 2 only when a compressed entry exists.
    has_compressed = any(e["type"] in (3, 4) for e in entries)
    if has_compressed != (version == 2):
        raise ValueError("version does not match the entry types")
    return version, entries


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: pack_ref.py <rust/tests/golden>")
    root = sys.argv[1]
    man = o.manifest(root, "pack-v2")
    names = sorted(f[:-5] for f in os.listdir(os.path.join(root, "pack-v2")) if f.endswith(".json"))
    files = {}
    for name in names:
        sidecar = o.read(root, "pack-v2", name + ".json")
        meta = json.loads(sidecar)
        expect(man.get(name + ".json") == blake3(sidecar).hex(), f"{name}: MANIFEST.txt sidecar entry")
        pack = files[name] = o.read(root, "pack-v2", meta["bin"])
        expect(len(pack) == meta["size"], f"{name}: size")
        expect(blake3(pack).hex() == meta["pack_key"], f"{name}: pack_key")
        expect(man.get(meta["bin"]) == meta["pack_key"], f"{name}: MANIFEST.txt pack entry")
        try:
            version, entries = parse_pack(pack)
        except (ValueError, c.Reject) as e:
            o.fail(f"{name}: {e}")
            continue
        expect(version == meta["version"], f"{name}: version")
        expect(len(entries) == len(meta["entries"]), f"{name}: entry count")
        for i, (got, want) in enumerate(zip(entries, meta["entries"])):
            tag = f"{name} entry {i}"
            expect(got["type"] == want["type"], f"{tag}: type")
            expect(got["id"].hex() == want["id"], f"{tag}: object id")
            expect(len(got["obj"]) == want["len"], f"{tag}: length")
            expect(blake3(got["obj"]).hex() == want["blake3_of_bytes"], f"{tag}: object digest")
            if "decoded" in got:
                expect(blake3(got["decoded"]).hex() == want["decoded_blake3"], f"{tag}: decoded digest")
                expect(len(got["decoded"]) == want["uncompressed_len"], f"{tag}: uncompressed_len")
                expect(got["frame_offset"] == want["frame_offset"], f"{tag}: frame_offset")
                expect(got["frame_len"] == want["frame_len"], f"{tag}: frame_len")
    expect(len(names) >= 4, "fewer than four pack vectors")

    # Negative checks on the pack rules (SPEC-PACKFILE section 3).
    raw = parse_pack(files["tree_and_commit"])[1][0]["obj"]

    def make(version, entries):
        body = b"KIT\x00" + struct.pack("<II", version, len(entries))
        for kind, payload in entries:
            body += bytes([kind]) + struct.pack("<I", len(payload)) + payload
        return body + blake3(body)

    for label, pack in (
        ("reserved type 0x01", make(1, [(1, raw)])),
        ("0x03 in a version 1 pack", make(1, [(3, struct.pack("<I", 0))])),
        ("version 2 without a compressed entry", make(2, [(0, raw)])),
        ("unsupported version", make(3, [(0, raw)])),
        ("trailing byte", make(1, [(0, raw)])[:-32] + b"\x00" + blake3(make(1, [(0, raw)])[:-32] + b"\x00")),
    ):
        try:
            parse_pack(pack)
            o.fail(f"accepted a pack with {label}")
        except (ValueError, c.Reject):
            pass
    good = make(1, [(0, raw)])
    parse_pack(good)
    try:
        parse_pack(good[:-1] + bytes([good[-1] ^ 1]))
        o.fail("accepted a pack with a bad trailer")
    except ValueError:
        pass
    if o.FAILURES:
        sys.exit(1)
    print("OK")


if __name__ == "__main__":
    main()

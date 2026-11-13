#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Independent reference check of the closure-profile golden vectors:
#   rust/tests/golden/closure/
#
# The check shares no code with the Rust crates. It reads only SPEC-DISCLOSURE
# section 7, SPEC-PACKFILE and SPEC-OBJECTS. It reuses the pure-Python BLAKE3
# and the strict object parsers of objects_ref.py, which are themselves
# written from the specs.
#
# For each vector the check:
#   * compares the manifest and pack bytes with the BLAKE3 values in the
#     sidecar and in MANIFEST.txt;
#   * decodes the manifest strictly (magic, version, mode, no trailing byte);
#   * decodes each pack as a raw-only pack and checks its trailer;
#   * derives every object id with the type-dependent rule; bytes that decode
#     to no object are unreferenced, never corrupt;
#   * walks the closure from the trusted root with the mode of the manifest,
#     checks that every entry mode and chunk reference names an object of a
#     fitting type, and that each chunk blob of a chunked blob holds exactly
#     the length of its committed span `end - start` (plan 4.8; one rule for
#     both layouts, each chunk checked on its own);
#   * compares the outcome (accept, incomplete or reject) with the sidecar,
#     including the verified count, the sorted id list and the unreferenced
#     ids.
#
# Usage:
#   python3 -I -B scripts/golden/closure_ref.py rust/tests/golden
#
# Exit 0 and print "OK" when every check passes; exit 1 otherwise.

import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import objects_ref as o  # noqa: E402
from objects_ref import blake3  # noqa: E402

MANIFEST_MAGIC = b"KCLM"
PACK_MAGIC = b"KIT\x00"
SNAPSHOT, HISTORY = 0, 1


class Reject(Exception):
    """The input breaks the closure profile or the manifest format."""


def varint(r):
    """Minimal unsigned LEB128, at most 32 bits."""
    value = 0
    for shift in range(0, 35, 7):
        b = r.u8()
        value |= (b & 0x7F) << shift
        if not b & 0x80:
            if b == 0 and shift > 0:
                raise Reject("non-minimal varint")
            if value >= 1 << 32:
                raise Reject("varint too large")
            return value
    raise Reject("varint too long")


def decode_manifest(data):
    try:
        r = o.Reader(data)
        if r.take(4) != MANIFEST_MAGIC:
            raise Reject("bad manifest magic")
        if r.u8() != 1:
            raise Reject("unsupported version")
        root = r.take(32)
        mode = r.u8()
        if mode not in (SNAPSHOT, HISTORY):
            raise Reject("unknown mode")
        count = varint(r)
        if count > 65_536:
            raise Reject("too many packs")
        packs = [r.take(32) for _ in range(count)]
        r.end()
    except ValueError as e:
        raise Reject(f"manifest: {e}")
    return root, mode, packs


def decode_pack(data):
    """Return the raw object payloads of a raw-only pack (SPEC-PACKFILE)."""
    if len(data) < 12 + 32:
        raise Reject("pack too short")
    body, trailer = data[:-32], data[-32:]
    if blake3(body) != trailer:
        raise Reject("pack trailer mismatch")
    r = o.Reader(body)
    if r.take(4) != PACK_MAGIC:
        raise Reject("bad pack magic")
    version = r.u32()
    if version not in (1, 2):
        raise Reject("unsupported pack version")
    count = r.u32()
    payloads = []
    for i in range(count):
        kind = r.u8()
        n = r.u32()
        payload = r.take(n)
        if kind != 0:
            raise Reject(f"profile violation: entry {i} has type {kind:#04x}")
        payloads.append(payload)
    r.end()
    if version != 1:
        raise Reject("closure pack must declare version 1")
    return payloads


def object_id(data):
    """SPEC-OBJECTS section 10. Raises ValueError when the bytes are not an object."""
    kind = data[0] if data else 0
    if kind == o.TREE:
        return o.tree_id(o.parse_tree(data)["entries"])
    if kind == o.CHUNKED:
        c = o.parse_chunked(data)
        return o.chunked_id(c["total"], c["chunk_size"], c["chunks"], c["ends"])
    parse = {
        o.BLOB: o.parse_blob,
        o.COMMIT: o.parse_commit,
        o.REMIX: o.parse_remix,
        o.TAG: o.parse_tag,
    }.get(kind)
    if parse is None:
        raise ValueError("unknown object type")
    parse(data)
    return blake3(data)


ANY = (o.BLOB, o.TREE, o.COMMIT, o.REMIX, o.CHUNKED, o.DELTA, o.TAG)
TREE_MODE = 2


def children(data, mode):
    """SPEC-DISCLOSURE section 7.1: (id, allowed object types) per reference.

    The tree of a commit or remix is a tree. The target of a tag has the type
    that the tag records. A tree entry of mode Tree names a tree. Any other
    entry names a blob or a chunked blob. A chunk names a blob.
    """
    kind = data[0]
    if kind in (o.COMMIT, o.REMIX):
        r = o.Reader(data)
        r.take(6)
        tree = r.take(32)
        parents = [r.take(32) for _ in range(r.u32())]
        out = [(tree, (o.TREE,))]
        if mode == HISTORY:
            out += [(h, ANY) for h in parents]
        return out
    if kind == o.TREE:
        return [
            (h, (o.TREE,) if m == TREE_MODE else (o.BLOB, o.CHUNKED))
            for _, m, h in o.parse_tree(data)["entries"]
        ]
    if kind == o.CHUNKED:
        return [(h, (o.BLOB,)) for h in o.parse_chunked(data)["chunks"]]
    if kind == o.TAG:
        return [(data[6:38], (data[38],))]
    return []


def walk(root, mode, payloads):
    """Return (verified ids, missing ids, corrupt ids, unreferenced ids)."""
    objects = {}
    unreferenced_junk = set()
    for payload in payloads:
        try:
            objects[object_id(payload)] = payload
        except ValueError:
            # No id derives from bytes that are not an object: never referenced.
            unreferenced_junk.add(blake3(payload))
    allowed = {root: set(ANY)}
    visited, missing, corrupt, queue = [], [], set(), [root]
    seen = {root}
    while queue:
        oid = queue.pop(0)
        data = objects.get(oid)
        if data is None:
            missing.append(oid)
            continue
        if oid == root and data[0] not in (o.COMMIT, o.REMIX, o.TAG):
            raise Reject("root is not a commit, remix or tag")
        if data[0] not in allowed[oid]:
            corrupt.add(oid)
            continue
        visited.append(oid)
        for child, kinds in children(data, mode):
            allowed[child] = allowed.get(child, set(ANY)) & set(kinds)
            if child not in seen:
                seen.add(child)
                queue.append(child)
    # An id named with types that disagree is corrupt, even when no pack
    # supplies it. So is an object whose type an entry forbids.
    for oid, kinds in allowed.items():
        data = objects.get(oid)
        if not kinds or (data is not None and data[0] not in kinds):
            corrupt.add(oid)
    # Plan 4.8, SPEC-DISCLOSURE 7.4 item 10 after the change: each chunk blob
    # that was read holds exactly the length of its span (end - start). One
    # rule for both layouts; each chunk is checked on its own, so a chunk of
    # the wrong length makes the manifest corrupt even when another chunk is
    # missing. A chunk that is absent or not a Blob is not measured here (it
    # is incomplete or corrupt already). The sum needs no check of its own: the
    # decoder made the last end equal total_size and the spans contiguous.
    for oid in visited:
        data = objects[oid]
        if data[0] != o.CHUNKED:
            continue
        manifest = o.parse_chunked(data)
        for chunk, (start, end) in zip(manifest["chunks"], o.spans_of(manifest["ends"])):
            blob = objects.get(chunk)
            if blob is None or blob[0] != o.BLOB:
                continue
            if o.parse_blob(blob)["len"] != end - start:
                corrupt.add(oid)
    unreferenced = sorted((set(objects) - set(seen)) | unreferenced_junk)
    return sorted(set(visited) - corrupt), missing, sorted(corrupt), unreferenced


def check_vector(root_dir, sidecar_name, man):
    d = "closure"
    meta = json.loads(o.read(root_dir, d, sidecar_name))
    name = meta["name"]
    manifest_bytes = o.read(root_dir, d, meta["bin"])
    o.expect(blake3(manifest_bytes).hex() == meta["blake3"], f"{name}: manifest blake3")
    o.expect(len(manifest_bytes) == meta["size"], f"{name}: manifest size")
    o.expect(man.get(name) == meta["blake3"], f"{name}: MANIFEST.txt entry")
    trusted = bytes.fromhex(meta["root_hex"])
    expect = meta["expect"]
    try:
        m_root, mode, pack_keys = decode_manifest(manifest_bytes)
        o.expect(len(pack_keys) == meta["n_packs"], f"{name}: pack count")
        o.expect(mode == (HISTORY if meta["mode"] == "history" else SNAPSHOT), f"{name}: mode")
        if m_root != trusted:
            raise Reject("manifest root differs from the trusted root")
        packs = []
        for i, key in enumerate(pack_keys):
            pack = o.read(root_dir, d, f"{name}.pack{i}.bin")
            if blake3(pack) != key:
                raise Reject("pack-hash mismatch")
            packs.append(pack)
        payloads = [p for pack in packs for p in decode_pack(pack)]
        ids, missing, corrupt, unreferenced = walk(trusted, mode, payloads)
    except Reject as e:
        o.expect(expect == "reject", f"{name}: unexpected reject ({e}); sidecar says {expect}")
        return "reject"
    if missing or corrupt:
        o.expect(expect == "incomplete", f"{name}: incomplete but sidecar says {expect}")
        if meta.get("reason") == "corrupt":
            o.expect(len(corrupt) > 0, f"{name}: expected a corrupt object")
        if meta.get("reason") == "missing":
            o.expect(len(missing) > 0, f"{name}: expected a missing object")
        if meta.get("reason") == "missing root":
            o.expect(missing == [trusted], f"{name}: expected the root to be missing")
        return "incomplete"
    o.expect(expect == "accept", f"{name}: complete but sidecar says {expect}")
    o.expect(len(ids) == meta["verified"], f"{name}: verified {len(ids)} != {meta['verified']}")
    o.expect([i.hex() for i in ids] == meta["ids"], f"{name}: id list")
    o.expect([u.hex() for u in unreferenced] == meta["unreferenced"], f"{name}: unreferenced")
    return "accept"


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: closure_ref.py <rust/tests/golden>")
    root_dir = sys.argv[1]
    man = o.manifest(root_dir, "closure")
    seen = {}
    for fn in sorted(os.listdir(os.path.join(root_dir, "closure"))):
        if fn.endswith(".json"):
            seen[fn] = check_vector(root_dir, fn, man)
    o.expect(len(seen) == len(man), "every MANIFEST.txt entry has a sidecar")
    kinds = set(seen.values())
    o.expect(kinds == {"accept", "incomplete", "reject"}, "vectors cover all three outcomes")
    if o.FAILURES:
        sys.exit(1)
    print("OK")


if __name__ == "__main__":
    main()

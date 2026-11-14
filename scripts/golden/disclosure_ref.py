#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Independent reference check of the disclosure-bundle golden vectors:
#   rust/tests/golden/disclosure/
#
# The check shares no code with the Rust crates. It reads only SPEC-DISCLOSURE
# sections 2 to 6 and 8, SPEC-MERKLE-OBJECTS and SPEC-OBJECTS, with the
# chunk-offsets changes of the kit 0.8.0 plan (section 4.7) applied, and the public
# description of the Bao slice encoding (an 8-byte little-endian content
# length, then the nodes of the BLAKE3 tree in pre-order). BLAKE3 and the
# strict object parsers come from objects_ref.py; the proof folding comes from
# proofs_ref.py. Ed25519 verification is written here from RFC 8032.
#
# For each vector the check:
#   * compares the bundle with the size and BLAKE3 in its sidecar and in
#     MANIFEST.txt;
#   * decodes the bundle strictly: magic, version 3, bounded vectors, minimal
#     varints and no trailing byte;
#   * verifies the commit id, the commit signature, every tree step and the
#     payload, in the order of section 4 and of plan 4.7 (the eight checks of
#     a chunked leaf), including the check that an Object payload has the type
#     that the leaf mode names and that a Chunk or Range payload has a leaf
#     mode that is not Tree;
#   * verifies a KDSP v2 span container (verify_span), which carries no anchor;
#   * compares the result with the `disclosed` summary in the sidecar, or
#     checks that the bundle is rejected when the sidecar says so.
#
# Usage:
#   python3 -I -B scripts/golden/disclosure_ref.py rust/tests/golden
#
# Exit 0 and print "OK" when every check passes; exit 1 otherwise.

import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import closure_ref as c  # noqa: E402
import objects_ref as o  # noqa: E402
import proofs_ref as p  # noqa: E402
from blake3_subtree_ref import CHUNK_LEN, chunk_cv, left_len, parent_cv, to_bytes  # noqa: E402
from objects_ref import blake3, domain_digest, expect  # noqa: E402

MAX_BUNDLE_BYTES = 64 << 20
MAX_COMMIT_BYTES = 4 << 20
MAX_TREE_DEPTH = 128
MAX_OBJECT = o.MAX_RAW_OBJECT_SIZE
BUNDLE_VERSION = 3
SPAN_VERSION = 2
MAX_SPAN_BYTES = 64 << 20
MAX_SPAN_CHUNKS = 1_000_000
TREE_MODE = 2
D = "disclosure"


class Reject(Exception):
    """The bundle does not verify."""


# ----------------------------------------------------------- ed25519


def _recover_x(y, sign):
    x2 = (y * y - 1) * pow(o.D * y * y + 1, o.P - 2, o.P) % o.P
    x = pow(x2, (o.P + 3) // 8, o.P)
    if (x * x - x2) % o.P:
        x = x * pow(2, (o.P - 1) // 4, o.P) % o.P
    if (x * x - x2) % o.P:
        raise ValueError("not a point")
    if x & 1 != sign:
        x = o.P - x
    return x


def _decode_point(b):
    """SPEC-SIGNING §1 check 1: a canonical encoding (y < p, and no sign bit
    on x = 0) of a curve point."""
    n = int.from_bytes(b, "little")
    y, sign = n & ((1 << 255) - 1), n >> 255
    if y >= o.P:
        raise ValueError("bad point")
    x = _recover_x(y, sign)
    if x == 0 and sign:
        raise ValueError("negative zero")
    return x, y


def _small_order(point):
    return o.scalar_mult(8, point) == (0, 1)


def ed25519_verify(public, msg, sig):
    """The SPEC-SIGNING §1 predicate: canonical A and R that are not of small
    order, S < L, and the cofactored equation [8]([S]B - R - [k]A) = 0."""
    import hashlib

    if len(public) != 32 or len(sig) != 64:
        return False
    try:
        a = _decode_point(public)
        r = _decode_point(sig[:32])
    except ValueError:
        return False
    if _small_order(a) or _small_order(r):
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= o.L:
        return False
    k = int.from_bytes(hashlib.sha512(sig[:32] + public + msg).digest(), "little") % o.L
    right = o.point_add(r, o.scalar_mult(k, a))
    diff = o.point_add(o.scalar_mult(s, o.B), ((o.P - right[0]) % o.P, right[1]))
    return o.scalar_mult(8, diff) == (0, 1)


# --------------------------------------------------------------- bao


def bao_slice(slice_bytes, root, start, length):
    """Decode a Bao slice and return the bytes [start, start + length)."""
    if len(slice_bytes) < 8:
        raise Reject("short slice")
    total = struct.unpack("<Q", slice_bytes[:8])[0]
    if start + length > total:
        raise Reject("range beyond the content")
    r = o.Reader(slice_bytes[8:])
    out = bytearray()
    end = start + length

    def walk(expected, lo, n, is_root):
        if n <= CHUNK_LEN:
            data = r.take(n)
            if to_bytes(chunk_cv(data, lo // CHUNK_LEN, is_root)) != expected:
                raise Reject("chunk hash mismatch")
            a, b = max(start, lo), min(end, lo + n)
            if a < b:
                out.extend(data[a - lo : b - lo])
            return
        left, right = r.take(32), r.take(32)
        if to_bytes(parent_cv(struct.unpack("<8I", left), struct.unpack("<8I", right), is_root)) != expected:
            raise Reject("parent hash mismatch")
        split = left_len(n)
        if start < lo + split and end > lo:
            walk(left, lo, split, False)
        if end > lo + split and start < lo + n:
            walk(right, lo + split, n - split, False)

    try:
        walk(root, 0, total, True)
        r.end()
    except ValueError as e:
        raise Reject(f"slice: {e}")
    if len(out) != length:
        raise Reject("slice does not cover the range")
    return bytes(out), total


# ------------------------------------------------------------- codec


class Bundle(o.Reader):
    def varint(self):
        value = 0
        for shift in range(0, 70, 7):
            b = self.u8()
            value |= (b & 0x7F) << shift
            if not b & 0x80:
                if b == 0 and shift > 0:
                    raise Reject("non-minimal varint")
                return value
        raise Reject("varint too long")

    def be32(self):
        return struct.unpack(">I", self.take(4))[0]

    def be64(self):
        return struct.unpack(">Q", self.take(8))[0]

    def vec(self, limit):
        n = self.varint()
        if n > limit:
            raise Reject("vector over the bound")
        return self.take(n)

    def boolean(self):
        b = self.u8()
        if b > 1:
            raise Reject("bad bool")
        return bool(b)

    def proof(self, max_items):
        leaf_count = self.be32()
        n = self.varint()
        if n > max_items * p.MAX_LEVELS:
            raise Reject("sibling count over the bound")
        return leaf_count, [self.take(32) for _ in range(n)]


def decode_bundle(data):
    if len(data) > MAX_BUNDLE_BYTES:
        raise Reject("bundle too large")
    b = Bundle(data)
    try:
        if b.take(4) != b"KDPB":
            raise Reject("bad magic")
        version = b.u8()
        if version != BUNDLE_VERSION:
            raise Reject(f"unsupported bundle version {version}")
        out = {"commit_id": b.take(32), "commit_bytes": b.vec(MAX_COMMIT_BYTES)}
        steps = []
        count = b.varint()
        if count > MAX_TREE_DEPTH:
            raise Reject("too many steps")
        for _ in range(count):
            name = b.vec(255)
            steps.append(
                {
                    "name": name,
                    "mode": b.u8(),
                    "child_id": b.take(32),
                    "inner_root": b.take(32),
                    "position": b.be32(),
                    "proof": b.proof(1),
                }
            )
        out["steps"] = steps
        kind = b.u8()
        out["kind"] = kind
        if kind == 0:
            out["bytes"] = b.vec(MAX_OBJECT)
        elif kind == 1:
            # Plan 4.7: Chunk { total_size, chunk_size, index, start, end,
            # inner_root, proof, bytes }; integers big-endian.
            out["chunk"] = {
                "total_size": b.be64(),
                "chunk_size": b.be32(),
                "index": b.be32(),
                "start": b.be64(),
                "end": b.be64(),
                "inner_root": b.take(32),
                "proof": b.proof(2),
            }
            out["bytes"] = b.vec(MAX_OBJECT)
        elif kind == 2:
            hdr = None
            if b.boolean():
                hdr = {
                    "total_size": b.be64(),
                    "chunk_size": b.be32(),
                    "index": b.be32(),
                    "start": b.be64(),
                    "end": b.be64(),
                    "inner_root": b.take(32),
                    "chunk_id": b.take(32),
                    "proof": b.proof(2),
                }
            out["hdr"] = hdr
            out["offset"] = b.be64()
            out["len"] = b.be64()
            out["slice"] = b.vec(MAX_OBJECT)
        else:
            raise Reject("unknown payload kind")
        b.end()
    except ValueError as e:
        raise Reject(f"decode: {e}")
    return out


# ------------------------------------------------------- verification


def check_layout(hdr):
    """The header-only check that stays (SPEC-OBJECTS section 7,
    `check_chunked_total_size`): total_size must fit the layout. The chunk
    count comes from the proof's leaf count."""
    try:
        o.check_chunked_layout(hdr["total_size"], hdr["chunk_size"], hdr["proof"][0] - 1)
    except ValueError as e:
        raise Reject(str(e))


def check_chunk_header(hdr, chunk_id, leaf_id):
    """Plan 4.7 as ordered by plan section 13, item 2, for a chunked leaf
    (the leaf-type and len == 0 checks come before this): the wrap and
    declared-root check, step 1 (the multi-proof), then the header-only total
    check on (total_size, chunk_size, leaf_count - 1), then steps 2 to 5.
    leaf_count is trusted only once the proof has folded to the id."""
    if domain_digest(o.CHUNKED_DOMAIN, hdr["inner_root"]) != leaf_id:
        raise Reject("chunk inner root does not wrap to the leaf id")
    start, end, index = hdr["start"], hdr["end"], hdr["index"]
    total, size = hdr["total_size"], hdr["chunk_size"]
    leaf_count, siblings = hdr["proof"]
    # 1. The chunk leaf is built from (start, end, chunk id); the meta leaf is
    # computed here from total_size and chunk_size, never supplied.
    leaves = {0: o.meta_leaf(total, size), index + 1: o.chunk_leaf(start, end, chunk_id)}
    try:
        folded = p.fold(leaf_count, siblings, leaves)
    except p.Reject as e:
        raise Reject(str(e))
    if folded != hdr["inner_root"]:
        raise Reject("chunk proof does not fold to the declared inner root")
    check_layout(hdr)
    # 2. start < end <= total_size, and the chunk fits in one object.
    if not start < end <= total:
        raise Reject("span outside the file")
    if end - start > o.MAX_CHUNK_LEN:
        raise Reject("span above the object limit")
    # 3. The first chunk starts at 0, and only the first.
    if (index == 0) != (start == 0):
        raise Reject("index 0 and start 0 disagree")
    # 4. The last chunk ends at total_size, and only the last.
    if (index + 1 == leaf_count - 1) != (end == total):
        raise Reject("last index and end == total_size disagree")
    # 5. A fixed layout has one span for each index.
    if size not in o.CONTENT_DEFINED:
        if start != index * size or end != min(start + size, total):
            raise Reject("a fixed-size chunk has the wrong span")


def verify_bundle(data, trusted_commit_id):
    b = decode_bundle(data)
    if b["commit_id"] != trusted_commit_id:
        raise Reject("commit id differs from the trusted id")
    if blake3(b["commit_bytes"]) != trusted_commit_id:
        raise Reject("commit bytes do not hash to the commit id")
    commit = b["commit_bytes"]
    try:
        if commit[:1] == bytes([o.COMMIT]):
            parsed = o.parse_commit(commit)
        elif commit[:1] == bytes([o.REMIX]):
            parsed = o.parse_remix(commit)
        else:
            raise Reject("commit bytes are not a commit or a remix")
    except ValueError as e:
        raise Reject(f"commit: {e}")
    tree_hash = commit[6:38]
    signer = parsed["signing"][-32:]
    sig_ok = ed25519_verify(signer, domain_digest(parsed["domain"], parsed["signing"]), parsed["signature"])

    expected = tree_hash
    path, step_roots = [], []
    for i, step in enumerate(b["steps"]):
        try:
            o.check_entry_name(step["name"])
        except ValueError as e:
            raise Reject(f"step {i} name: {e}")
        if step["mode"] not in (1, 2, 3, 4):
            raise Reject("unknown mode")
        # The mode test is cheap, so it runs before the proof. The outcome is the same.
        if i != len(b["steps"]) - 1 and step["mode"] != TREE_MODE:
            raise Reject("a non-final step is not a tree")
        if domain_digest(o.TREE_DOMAIN, step["inner_root"]) != expected:
            raise Reject(f"step {i}: inner root does not wrap to the parent id")
        entry_leaf = domain_digest(
            b"kit-tree-entry-v1",
            struct.pack("<I", len(step["name"])) + step["name"] + bytes([step["mode"]]) + step["child_id"],
        )
        leaf_count, siblings = step["proof"]
        try:
            folded = p.fold(leaf_count, siblings, {step["position"]: entry_leaf})
        except p.Reject as e:
            raise Reject(f"step {i}: {e}")
        if folded != step["inner_root"]:
            raise Reject(f"step {i}: proof does not fold to the declared inner root")
        path.append({"mode": step["mode"], "name_hex": step["name"].hex()})
        step_roots.append(step["inner_root"].hex())
        expected = step["child_id"]
    leaf_id = expected

    result = {
        "path": path,
        "leaf_id_hex": leaf_id.hex(),
        "tree_hash_hex": tree_hash.hex(),
        "step_inner_roots_hex": step_roots,
        "chunk_inner_root_hex": None,
        "signer_hex": signer.hex(),
        "signature_valid": sig_ok,
    }
    # The caller may need the decoded bundle and the disclosed bytes.
    result["_bundle"] = b
    result["_content"] = b""
    kind = b["kind"]
    leaf_mode = path[-1]["mode"] if path else TREE_MODE
    if kind != 0 and leaf_mode == TREE_MODE:
        # A Chunk or Range payload is blob data: its leaf is never a tree.
        raise Reject("blob payload under a Tree mode")
    if kind == 0:
        try:
            oid = c.object_id(b["bytes"])
        except ValueError as e:
            raise Reject(f"payload: {e}")
        if oid != leaf_id:
            raise Reject("payload id differs from the leaf id")
        # A Tree mode names a tree; every other mode names a blob or a chunked blob.
        allowed = (o.TREE,) if leaf_mode == TREE_MODE else (o.BLOB, o.CHUNKED)
        if b["bytes"][0] not in allowed:
            raise Reject("payload type does not match the leaf mode")
        result["_content"] = b["bytes"]
        result["payload"] = {"kind": "object", "len": len(b["bytes"]), "bytes_blake3": blake3(b["bytes"]).hex()}
    elif kind == 1:
        hdr = b["chunk"]
        chunk_id = blake3(b["bytes"])
        check_chunk_header(hdr, chunk_id, leaf_id)
        # 6. The bytes are a Blob whose length field equals end - start.
        try:
            blob = o.parse_blob(b["bytes"])
        except ValueError as e:
            raise Reject(f"chunk bytes are not a blob: {e}")
        if blob["len"] != hdr["end"] - hdr["start"]:
            raise Reject("blob length differs from the span")
        result["_content"] = b["bytes"]
        result["chunk_inner_root_hex"] = hdr["inner_root"].hex()
        result["payload"] = {
            "kind": "chunk",
            "total_size": hdr["total_size"],
            "chunk_size": hdr["chunk_size"],
            "index": hdr["index"],
            # Span values are decimal strings in every sidecar (plan section 13).
            "start": str(hdr["start"]),
            "end": str(hdr["end"]),
            "len": len(b["bytes"]),
            "bytes_blake3": blake3(b["bytes"]).hex(),
        }
    else:
        if b["len"] == 0:
            raise Reject("zero-length range")
        hdr = b["hdr"]
        if hdr is None:
            blob_id, start, chunk = leaf_id, 0, None
        else:
            check_chunk_header(hdr, hdr["chunk_id"], leaf_id)
            result["chunk_inner_root_hex"] = hdr["inner_root"].hex()
            blob_id, start = hdr["chunk_id"], hdr["start"]
            chunk = {k: hdr[k] for k in ("total_size", "chunk_size", "index")}
            chunk["start"], chunk["end"] = str(hdr["start"]), str(hdr["end"])
            # 7. The range lies inside the committed span, and only the span: a
            # real chunk longer than its span is not measured (plan section 13,
            # item 3), because bytes past the span cannot be disclosed.
            if b["offset"] + b["len"] > hdr["end"] - hdr["start"]:
                raise Reject("range past the committed span")
        content, _ = bao_slice(b["slice"], blob_id, b["offset"] + 10, b["len"])
        result["_content"] = content
        result["payload"] = {
            "kind": "range",
            "len": b["len"],
            "bytes_blake3": blake3(content).hex(),
            "offset_in_blob": b["offset"],
            # 8. Always present: start + offset_in_blob (start is 0 for a plain blob).
            "absolute_offset": start + b["offset"],
            "blob_id_hex": blob_id.hex(),
            "chunk": chunk,
        }
    return result


class SpanReject(Exception):
    """A KDSP v2 container does not verify. `reason` is the label of the
    SPEC-DISCLOSURE section 8.2 contract, as changed by plan 4.7."""

    def __init__(self, reason, detail=""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


class SpanReader:
    """The KDSP reader: bounded takes, and LEB128 varints that are minimal and
    at most u32 (SPEC-DISCLOSURE section 8.1). Every failure is span_encoding."""

    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, n):
        if n > len(self.data) - self.pos:
            raise SpanReject("span_encoding")
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def varint(self, cap):
        value = 0
        for i in range(5):
            b = self.take(1)[0]
            if (i > 0 and b == 0) or (i == 4 and b > 15):
                raise SpanReject("span_encoding")
            value |= (b & 0x7F) << (7 * i)
            if not b & 0x80:
                if value > cap:
                    raise SpanReject("span_encoding")
                return value
        raise SpanReject("span_encoding")

    def vector(self):
        return self.take(self.varint(min(MAX_SPAN_BYTES, len(self.data) - self.pos)))


def decode_span(data):
    """Plan 4.7: "KDSP", version 2, commit_id, offset, len, then the chunk
    bundles. No anchor. Fixed integers big-endian, lengths as LEB128 varints
    (SPEC-DISCLOSURE sections 3 and 8.1)."""
    if len(data) > MAX_SPAN_BYTES:
        raise SpanReject("span_too_large")
    r = SpanReader(data)
    if r.take(4) != b"KDSP":
        raise SpanReject("span_magic")
    if r.take(1) != bytes([SPAN_VERSION]):
        raise SpanReject("span_version")
    out = {"commit_id": r.take(32)}
    out["offset"] = struct.unpack(">Q", r.take(8))[0]
    out["len"] = struct.unpack(">Q", r.take(8))[0]
    count = r.varint(MAX_SPAN_CHUNKS)
    if count > len(data) - r.pos:
        raise SpanReject("span_encoding")
    out["bundles"] = [r.vector() for _ in range(count)]
    if r.pos != len(data):
        raise SpanReject("span_trailing_bytes")
    return out


def verify_span(data, trusted_commit_id):
    """Plan 4.7, in order: size, magic, version, encoding, trailing bytes,
    commit, range arithmetic, count; each bundle verifies; every payload is a
    Chunk with the same path, leaf, total_size, chunk_size and inner root;
    indices are consecutive; end_i == start_(i+1); start_first <= offset <
    end_first; offset + len <= end_last; offset + len > start_last.
    Returns the decoded container and the per-chunk results."""
    sp = decode_span(data)
    if sp["commit_id"] != trusted_commit_id:
        raise SpanReject("span_commit")
    offset, length = sp["offset"], sp["len"]
    if length == 0 or offset + length >= 1 << 64:
        raise SpanReject("span_range_arithmetic")
    if len(sp["bundles"]) < 2:
        raise SpanReject("span_chunk_count")
    results = []
    for raw in sp["bundles"]:
        try:
            results.append(verify_bundle(raw, trusted_commit_id))
        except Reject as e:
            raise SpanReject("span_inner_invalid", str(e))
    if any(res["_bundle"]["kind"] != 1 for res in results):
        raise SpanReject("span_chunk_selector")
    first = results[0]
    for res in results:
        if res["path"] != first["path"] or res["leaf_id_hex"] != first["leaf_id_hex"]:
            raise SpanReject("span_leaf_context")
    for res in results:
        a, b = first["_bundle"]["chunk"], res["_bundle"]["chunk"]
        if any(a[k] != b[k] for k in ("total_size", "chunk_size", "inner_root")):
            raise SpanReject("span_chunk_context")
    chunks = [res["_bundle"]["chunk"] for res in results]
    for prev, nxt in zip(chunks, chunks[1:]):
        if nxt["index"] != prev["index"] + 1:
            raise SpanReject("span_chunk_order")
    for prev, nxt in zip(chunks, chunks[1:]):
        if prev["end"] != nxt["start"]:
            raise SpanReject("span_chunk_chain")
    if not chunks[0]["start"] <= offset < chunks[0]["end"]:
        raise SpanReject("span_range_outside")
    if offset + length > chunks[-1]["end"]:
        raise SpanReject("span_range_outside")
    if offset + length <= chunks[-1]["start"]:
        raise SpanReject("span_last_unneeded")
    # The disclosed bytes: each Blob's content, in order, sliced to the range.
    content = b"".join(res["_content"][10:] for res in results)
    base = chunks[0]["start"]
    return {
        "span": sp,
        "results": results,
        "path": first["path"],
        "leaf_id_hex": first["leaf_id_hex"],
        "offset": offset,
        "len": length,
        "content": content[offset - base : offset + length - base],
    }


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: disclosure_ref.py <rust/tests/golden>")
    root = sys.argv[1]
    files, man = o.check_files(root, D)
    outcomes = set()
    for name in sorted(files):
        meta = json.loads(o.read(root, D, name + ".json"))
        try:
            got = verify_bundle(files[name], bytes.fromhex(meta["commit_id_hex"]))
            outcome = "accept"
        except Reject as e:
            got, outcome = None, "reject"
            if meta["expect"] == "accept":
                o.fail(f"{name}: unexpected reject ({e})")
        outcomes.add(outcome)
        expect(outcome == meta["expect"], f"{name}: outcome {outcome}, sidecar says {meta['expect']}")
        if got is not None and meta["expect"] == "accept":
            want = meta["disclosed"]
            for key in want:
                expect(got.get(key) == want[key], f"{name}: {key} differs: {got.get(key)} != {want[key]}")
    expect(outcomes == {"accept", "reject"}, "vectors cover both outcomes")
    expect(len(files) == len(man), "every MANIFEST.txt entry has a vector")
    if o.FAILURES:
        sys.exit(1)
    print("OK")


if __name__ == "__main__":
    main()

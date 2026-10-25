#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Independent reference check of the disclosure-bundle golden vectors:
#   rust/tests/golden/disclosure/
#
# The check shares no code with the Rust crates. It reads only SPEC-DISCLOSURE
# sections 2 to 6, SPEC-MERKLE-OBJECTS and SPEC-OBJECTS, and the public
# description of the Bao slice encoding (an 8-byte little-endian content
# length, then the nodes of the BLAKE3 tree in pre-order). BLAKE3 and the
# strict object parsers come from objects_ref.py; the proof folding comes from
# proofs_ref.py. Ed25519 verification is written here from RFC 8032.
#
# For each vector the check:
#   * compares the bundle with the size and BLAKE3 in its sidecar and in
#     MANIFEST.txt;
#   * decodes the bundle strictly: magic, version 2, bounded vectors, minimal
#     varints and no trailing byte;
#   * verifies the commit id, the commit signature, every tree step, the
#     payload and any length proofs, in the order of section 4;
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
MAX_CHUNKS = 1_000_000
MAX_OBJECT = 1 << 30
MAX_LEN_SLICE = 8 << 10
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
    n = int.from_bytes(b, "little")
    y, sign = n & ((1 << 255) - 1), n >> 255
    if y >= o.P:
        raise ValueError("bad point")
    return _recover_x(y, sign), y


def ed25519_verify(public, msg, sig):
    """RFC 8032 section 5.1.7."""
    import hashlib

    try:
        a = _decode_point(public)
        r = _decode_point(sig[:32])
    except ValueError:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= o.L:
        return False
    k = int.from_bytes(hashlib.sha512(sig[:32] + public + msg).digest(), "little") % o.L
    left = o.scalar_mult(s, o.B)
    right = o.point_add(r, o.scalar_mult(k, a))
    return left == right


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


def length_proof(slice_bytes, chunk_id):
    """SPEC-DISCLOSURE section 4.1. Returns the proven content length."""
    if len(slice_bytes) > MAX_LEN_SLICE:
        raise Reject("length slice over the bound")
    head, _ = bao_slice(slice_bytes, chunk_id, 0, 10)
    if head[:6] != bytes([o.BLOB]) + o.PROLOGUE_MAGIC + bytes([o.SCHEMA_VERSION]):
        raise Reject("length slice is not a blob prologue")
    return struct.unpack("<I", head[6:10])[0]


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
        if version != 2:
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
            out["chunk"] = {
                "total_size": b.be64(),
                "chunk_size": b.be32(),
                "index": b.be32(),
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
                    "inner_root": b.take(32),
                    "chunk_id": b.take(32),
                    "proof": b.proof(2),
                }
            out["hdr"] = hdr
            out["offset"] = b.be64()
            out["len"] = b.be64()
            out["slice"] = b.vec(MAX_OBJECT)
            proofs = []
            for _ in range(b.varint()):
                if len(proofs) >= MAX_CHUNKS:
                    raise Reject("too many length proofs")
                proofs.append(
                    {
                        "index": b.be32(),
                        "chunk_id": b.take(32),
                        "proof": b.proof(1),
                        "slice": b.vec(MAX_LEN_SLICE),
                    }
                )
            out["len_proofs"] = proofs
        else:
            raise Reject("unknown payload kind")
        b.end()
    except ValueError as e:
        raise Reject(f"decode: {e}")
    return out


# ------------------------------------------------------- verification


def meta_leaf(total_size, chunk_size):
    return domain_digest(b"kit-cblob-meta-v1", struct.pack("<Q", total_size) + struct.pack("<I", chunk_size))


def check_chunk_proof(hdr, chunk_hash, leaf_id):
    """Wrap check first, then the {0, index + 1} multi-proof (section 4)."""
    if domain_digest(o.CHUNKED_DOMAIN, hdr["inner_root"]) != leaf_id:
        raise Reject("chunk inner root does not wrap to the leaf id")
    leaf_count, siblings = hdr["proof"]
    leaves = {
        0: meta_leaf(hdr["total_size"], hdr["chunk_size"]),
        hdr["index"] + 1: chunk_hash,
    }
    try:
        folded = p.fold(leaf_count, siblings, leaves)
    except p.Reject as e:
        raise Reject(str(e))
    if folded != hdr["inner_root"]:
        raise Reject("chunk proof does not fold to the declared inner root")


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
    if kind == 0:
        try:
            oid = c.object_id(b["bytes"])
        except ValueError as e:
            raise Reject(f"payload: {e}")
        if oid != leaf_id:
            raise Reject("payload id differs from the leaf id")
        result["_content"] = b["bytes"]
        result["payload"] = {"kind": "object", "len": len(b["bytes"]), "bytes_blake3": blake3(b["bytes"]).hex()}
    elif kind == 1:
        hdr = b["chunk"]
        check_chunk_proof(hdr, blake3(b["bytes"]), leaf_id)
        result["_content"] = b["bytes"]
        result["chunk_inner_root_hex"] = hdr["inner_root"].hex()
        result["payload"] = {
            "kind": "chunk",
            "total_size": hdr["total_size"],
            "chunk_size": hdr["chunk_size"],
            "index": hdr["index"],
            "len": len(b["bytes"]),
            "bytes_blake3": blake3(b["bytes"]).hex(),
        }
    else:
        if b["len"] == 0:
            raise Reject("zero-length range")
        hdr = b["hdr"]
        if hdr is None:
            if b["len_proofs"]:
                raise Reject("length proofs on a plain blob")
            blob_id, absolute, chunk = leaf_id, b["offset"], None
        else:
            check_chunk_proof(hdr, hdr["chunk_id"], leaf_id)
            result["chunk_inner_root_hex"] = hdr["inner_root"].hex()
            blob_id = hdr["chunk_id"]
            chunk = {k: hdr[k] for k in ("total_size", "chunk_size", "index")}
            if hdr["index"] == 0:
                if b["len_proofs"]:
                    raise Reject("length proofs on chunk 0")
                absolute = b["offset"]
            elif not b["len_proofs"]:
                absolute = None
            else:
                if sorted(e["index"] for e in b["len_proofs"]) != list(range(hdr["index"])):
                    raise Reject("length proofs do not cover exactly 0..index")
                total = 0
                for e in b["len_proofs"]:
                    leaf_count, siblings = e["proof"]
                    try:
                        folded = p.fold(leaf_count, siblings, {e["index"] + 1: e["chunk_id"]})
                    except p.Reject as err:
                        raise Reject(str(err))
                    if folded != hdr["inner_root"]:
                        raise Reject("length proof does not fold to the inner root")
                    total += length_proof(e["slice"], e["chunk_id"])
                absolute = total + b["offset"]
        content, _ = bao_slice(b["slice"], blob_id, b["offset"] + 10, b["len"])
        result["_content"] = content
        result["payload"] = {
            "kind": "range",
            "len": b["len"],
            "bytes_blake3": blake3(content).hex(),
            "offset_in_blob": b["offset"],
            "absolute_offset": absolute,
            "blob_id_hex": blob_id.hex(),
            "chunk": chunk,
        }
    return result


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

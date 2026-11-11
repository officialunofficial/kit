#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Independent reference check of the inclusion-proof golden vectors:
#   rust/tests/golden/proofs/
#
# The check shares no code with the Rust crates. It reads only
# SPEC-MERKLE-OBJECTS sections 1 to 5. BLAKE3 and the leaf and root rules come
# from objects_ref.py, which is written from the same spec.
#
# For each vector the check:
#   * compares the proof file with the size and BLAKE3 in its sidecar and in
#     MANIFEST.txt;
#   * decodes the proof strictly: big-endian leaf count, minimal varint
#     sibling or step count, the bound on that count and no trailing byte;
#   * for a chunk proof, rebuilds the leaves from the sidecar, folds the
#     proof level by level with the sibling selection of section 5.3, and
#     compares the wrapped result with the object id;
#   * for a tree entry proof, folds the keyed proof of section 5.8, checks
#     the entry name against every separator, and compares the wrapped
#     result with the tree id;
#   * checks that the outcome (accept or reject) matches the sidecar.
#
# Usage:
#   python3 -I -B scripts/golden/proofs_ref.py rust/tests/golden
#
# Exit 0 and print "OK" when every check passes; exit 1 otherwise.

import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import objects_ref as o  # noqa: E402
from objects_ref import blake3, domain_digest, expect  # noqa: E402

MAX_LEVELS = 32


class Reject(Exception):
    """The proof does not verify."""


def decode_proof(data, max_items):
    """SPEC-MERKLE-OBJECTS section 5.2."""
    try:
        r = o.Reader(data)
        leaf_count = struct.unpack(">I", r.take(4))[0]
        count, shift = 0, 0
        while True:
            b = r.u8()
            count |= (b & 0x7F) << shift
            if not b & 0x80:
                if b == 0 and shift > 0:
                    raise Reject("non-minimal varint")
                break
            shift += 7
            if shift > 28:
                raise Reject("varint too long")
        if count > max_items * MAX_LEVELS:
            raise Reject("sibling count over the bound")
        siblings = [r.take(32) for _ in range(count)]
        r.end()
    except ValueError as e:
        raise Reject(f"decode: {e}")
    return leaf_count, siblings


def fold(leaf_count, siblings, leaves):
    """Fold the leaves (dict position -> raw leaf) into the bare root.

    SPEC-MERKLE-OBJECTS sections 5.3 and 5.4. Every sibling must be used.
    """
    if not leaves:
        raise Reject("proof over zero positions")
    if any(p >= leaf_count for p in leaves):
        raise Reject("position out of range")
    nodes = {p: blake3(struct.pack(">I", p) + leaf) for p, leaf in leaves.items()}
    levels = (leaf_count - 1).bit_length() + 1
    size, used = leaf_count, 0
    for _ in range(levels - 1):
        parents = {}
        for p in sorted(nodes):
            sib = (p + 1 if p + 1 < size else p) if p % 2 == 0 else p - 1
            if sib == p:
                parent = blake3(nodes[p] + nodes[p])
            elif sib in nodes:
                if sib < p:
                    continue  # the lower node of the pair builds the parent
                parent = blake3(nodes[p] + nodes[sib])
            else:
                if used >= len(siblings):
                    raise Reject("too few siblings")
                s = siblings[used]
                used += 1
                parent = blake3(nodes[p] + s) if p % 2 == 0 else blake3(s + nodes[p])
            parents[p // 2] = parent
        nodes = parents
        size = (size + 1) // 2
    if used != len(siblings):
        raise Reject("unused siblings")
    return blake3(struct.pack(">I", leaf_count) + nodes[0])


def read_varint(r):
    count, shift = 0, 0
    while True:
        b = r.u8()
        count |= (b & 0x7F) << shift
        if not b & 0x80:
            if b == 0 and shift > 0:
                raise Reject("non-minimal varint")
            return count
        shift += 7
        if shift > 28:
            raise Reject("varint too long")


def read_tree_proof(r):
    """SPEC-MERKLE-OBJECTS section 5.8, from an open reader."""
    leaf_count = struct.unpack(">I", r.take(4))[0]
    count = read_varint(r)
    if count > MAX_LEVELS:
        raise Reject("tree proof step count over the bound")
    steps = []
    for _ in range(count):
        sibling = r.take(32)
        n = r.u8()
        if n == 0:
            raise Reject("empty separator")
        steps.append((sibling, r.take(n)))
    return leaf_count, steps


def decode_tree_proof(data):
    try:
        r = o.Reader(data)
        proof = read_tree_proof(r)
        r.end()
    except ValueError as e:
        raise Reject(f"decode: {e}")
    return proof


def verify_tree_entry(proof, name, mode, object_hash, position, tree_id):
    """SPEC-MERKLE-OBJECTS section 5.8."""
    leaf_count, steps = proof
    if position >= leaf_count:
        raise Reject("position out of range")
    c = blake3(struct.pack(">I", position) + o.tree_entry_leaf(name, mode, object_hash))
    size, used = leaf_count, 0
    while size > 1:
        if position % 2 == 0 and position + 1 >= size:
            c = blake3(c + c)
        else:
            if used >= len(steps):
                raise Reject("too few steps")
            sibling, sep = steps[used]
            used += 1
            try:
                o.check_entry_name(sep)
            except ValueError as e:
                raise Reject(f"separator: {e}")
            if position % 2 == 0:
                if not name < sep:
                    raise Reject("name is not below the separator")
                c = o.tree_parent(c, sibling, sep)
            else:
                if not sep <= name:
                    raise Reject("name is below the separator")
                c = o.tree_parent(sibling, c, sep)
        position //= 2
        size = (size + 1) // 2
    if used != len(steps):
        raise Reject("unused steps")
    root = blake3(struct.pack(">I", leaf_count) + c)
    if domain_digest(o.TREE_DOMAIN, root) != tree_id:
        raise Reject("folded value differs from the tree id")


def verify(leaf_count, siblings, leaves, domain, object_id):
    """Fold the leaves, wrap the result and compare it with the object id."""
    folded = fold(leaf_count, siblings, leaves)
    if domain_digest(domain, folded) != object_id:
        raise Reject("folded value differs from the object id")


def leaves_for(meta):
    """Return (domain, {position: leaf}) built from a chunk sidecar."""
    leaves = [bytes.fromhex(h) for h in meta["chunk_hashes_hex"]]
    domain = o.CHUNKED_DOMAIN
    kind = meta["proof_kind"]
    if kind == "single":
        positions = [meta["position"]]
    elif kind == "range":
        positions = list(range(meta["start"], meta["start"] + len(leaves)))
    else:
        positions = meta["positions"]
        if positions != sorted(set(positions)):
            raise Reject("positions not sorted or not unique")
    if len(positions) != len(leaves):
        raise Reject("position count differs from leaf count")
    if meta["kind"] == "chunk" and 0 in positions:
        raise Reject("position 0 is the metadata leaf")
    return domain, dict(zip(positions, leaves))


def check_vector(root, name):
    meta = json.loads(o.read(root, "proofs", name + ".json"))
    data = o.read(root, "proofs", meta["bin"])
    try:
        if meta["kind"] == "tree_entry":
            e = meta["entries"][0]
            verify_tree_entry(
                decode_tree_proof(data),
                bytes.fromhex(e["name_hex"]),
                e["mode"],
                bytes.fromhex(e["object_hash_hex"]),
                meta["position"],
                bytes.fromhex(meta["object_id_hex"]),
            )
        else:
            leaf_count, siblings = decode_proof(data, meta["max_items"])
            domain, leaves = leaves_for(meta)
            verify(leaf_count, siblings, leaves, domain, bytes.fromhex(meta["object_id_hex"]))
        outcome = "accept"
    except Reject as e:
        outcome = "reject"
        if meta["expect"] == "accept":
            o.fail(f"proofs/{name}: unexpected reject ({e})")
    expect(outcome == meta["expect"], f"proofs/{name}: outcome {outcome}, sidecar says {meta['expect']}")
    return outcome


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: proofs_ref.py <rust/tests/golden>")
    root = sys.argv[1]
    files, man = o.check_files(root, "proofs")
    seen = [check_vector(root, n) for n in sorted(files)]
    expect(set(seen) == {"accept", "reject"}, "vectors cover both outcomes")
    expect(len(seen) == len(man), "every MANIFEST.txt entry has a vector")
    if o.FAILURES:
        sys.exit(1)
    print("OK")


if __name__ == "__main__":
    main()

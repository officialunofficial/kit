#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Independent reference vectors for the chunk-offsets format:
#   scripts/golden/chunk_offsets_expected.json
#
# The chunked-file id commits each chunk's byte span. This script writes the
# expected values for a fixed set of inputs and checks the file against a fresh
# build. It shares no code with the Rust crates. It builds everything from the
# format of the kit 0.8.0 plan (section 4: leaves, manifest bytes, KDPB v3,
# KDSP v2) with the pure-Python helpers of objects_ref.py, proofs_ref.py and
# disclosure_ref.py. Every bundle it builds is also run through the
# verifier of disclosure_ref.py before it is written.
#
# Cases in the file:
#   leaf_digests          the leaf digests with asymmetric maximum values
#   cases                 manifests of 0, 1, 2, 3, 5 and 7 chunks (content
#                         defined and fixed): manifest bytes, chunked id, one
#                         proof of each kind, disclosures, and for some cases
#                         a span (KDSP v2)
#   refusals              manifests that a reader refuses, with the first
#                         failing check
#   overlap               an id built from overlapping spans: no manifest
#                         decodes to it, and two disclosures both verify
#   long_chunk_range      a real chunk longer than its span: a Range inside
#                         the span verifies (plan section 13, item 3)
#   negative_disclosures  bundles and spans that a verifier refuses
#   pins                  the manifest of 1,000,001 and 8,388,608 chunks (only
#                         with --large: about 3 minutes on 10 cores)
#
# Each entry has a one-line "comment" that names the plan line it tests. The
# plan is kit-080-final-plan.md; "plan 13" is its section 13, which overrides
# section 4 where they differ. Span values (start, end) and the total_size of
# the leaf digests are decimal strings in the file, because values near the
# u64 maximum lose precision as JSON numbers.
#
# Usage:
#   python3 -I -B scripts/golden/chunk_offsets_ref.py [--large] [--write]
#
# Without --write the file is checked: exit 0 and print "OK" when it equals a
# fresh build. Without --large the pins are not recomputed and not compared.

import json
import multiprocessing
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import disclosure_ref as d  # noqa: E402
import objects_ref as o  # noqa: E402
import proofs_ref as p  # noqa: E402
from blake3_subtree_ref import CHUNK_LEN, left_len, subtree, to_bytes  # noqa: E402
from objects_ref import blake3, domain_digest  # noqa: E402

OUT = os.path.join(HERE, "chunk_offsets_expected.json")
SIGNER_SEED = bytes([0x2A]) * 32


# ------------------------------------------------------------- encoders


def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def vec(b):
    return varint(len(b)) + b


def be32(n):
    return struct.pack(">I", n)


def be64(n):
    return struct.pack(">Q", n)


def enc_proof(proof):
    leaf_count, siblings = proof
    return be32(leaf_count) + varint(len(siblings)) + b"".join(siblings)


def make_blob(content):
    return bytes([o.BLOB]) + o.PROLOGUE_MAGIC + bytes([o.schema_version(o.BLOB)]) + struct.pack("<I", len(content)) + content


def bao_slice_encode(data, start, length):
    """The Bao slice of data[start, start + length): the 8-byte little-endian
    length, then the tree nodes in pre-order. A parent shows both child
    hashes; a leaf shows its whole chunk; only nodes that overlap the range
    are entered."""
    end = start + length
    out = bytearray(struct.pack("<Q", len(data)))

    def enc(sub, lo):
        n = len(sub)
        if n <= CHUNK_LEN:
            out.extend(sub)
            return
        split = left_len(n)
        out.extend(to_bytes(subtree(sub[:split], lo)))
        out.extend(to_bytes(subtree(sub[split:], lo + split)))
        if start < lo + split and end > lo:
            enc(sub[:split], lo)
        if end > lo + split and start < lo + n:
            enc(sub[split:], lo + split)

    enc(data, 0)
    return bytes(out)


# --------------------------------------------------------------- worlds


class World:
    """One chunked file under a one-entry root tree, signed by one commit.

    `spans` are taken as given, so a world can also hold spans that no
    manifest decodes to (overlap, gaps, bad ends)."""

    def __init__(self, total, chunk_size, blobs, spans):
        self.total, self.chunk_size = total, chunk_size
        self.blobs = blobs
        self.chunk_ids = [blake3(b) for b in blobs]
        self.spans = spans
        self.leaves = o.chunk_leaves(total, chunk_size, spans, self.chunk_ids)
        self.inner_root = o.bmt_root(self.leaves)
        self.chunked_id = domain_digest(o.CHUNKED_DOMAIN, self.inner_root)
        name = b"big.bin"
        entry_leaf = domain_digest(
            b"kit-tree-entry-v1", struct.pack("<I", len(name)) + name + bytes([1]) + self.chunked_id
        )
        self.tree_leaves = [entry_leaf]
        self.tree_inner = o.bmt_root(self.tree_leaves)
        self.tree_id = domain_digest(o.TREE_DOMAIN, self.tree_inner)
        self.name = name
        self.commit_bytes = self._commit()
        self.commit_id = blake3(self.commit_bytes)

    def _commit(self):
        author = b"\x01\x20\x00" + b"\xaa" * 32
        message = b"chunk offsets"
        pub, _ = o.ed25519_sign(SIGNER_SEED, b"")
        head = bytes([o.COMMIT]) + o.PROLOGUE_MAGIC + bytes([o.schema_version(o.COMMIT)])
        signing = (
            head + self.tree_id + struct.pack("<I", 0) + author
            + struct.pack("<I", len(message)) + message + struct.pack("<Q", 1_700_000_000) + pub
        )
        _, sig = o.ed25519_sign(SIGNER_SEED, domain_digest(o.COMMIT_DOMAIN, signing))
        return signing + blake3(message) + bytes(32) + sig

    def _head(self, version):
        step = (
            vec(self.name) + bytes([1]) + self.chunked_id + self.tree_inner + be32(0)
            + enc_proof(p.prove(self.tree_leaves, [0]))
        )
        return (
            b"KDPB" + bytes([version]) + self.commit_id + vec(self.commit_bytes) + varint(1) + step
        )

    def hdr(self, i, with_chunk_id, total_field=None):
        s, e = self.spans[i]
        out = be64(self.total if total_field is None else total_field) + be32(self.chunk_size) + be32(i) + be64(s) + be64(e) + self.inner_root
        if with_chunk_id:
            out += self.chunk_ids[i]
        return out + enc_proof(p.prove(self.leaves, [0, i + 1]))

    def chunk_bundle(self, i, version=3, total_field=None):
        return self._head(version) + bytes([1]) + self.hdr(i, False, total_field) + vec(self.blobs[i])

    def range_bundle(self, i, offset, length, version=3):
        sl = bao_slice_encode(self.blobs[i], offset + 10, length)
        return (
            self._head(version) + bytes([2]) + bytes([1]) + self.hdr(i, True)
            + be64(offset) + be64(length) + vec(sl)
        )

    def span_bundle(self, offset, length, first, last, version=2, inner_version=3):
        bundles = [self.chunk_bundle(i, inner_version) for i in range(first, last + 1)]
        return (
            b"KDSP" + bytes([version]) + self.commit_id + be64(offset) + be64(length)
            + varint(len(bundles)) + b"".join(vec(b) for b in bundles)
        )

    def proofs(self):
        """One proof of each kind (single, range, multi), where the file has
        the chunks for it."""
        n = len(self.blobs)
        out = {}
        if n == 0:
            return out
        mid = (n - 1) // 2
        kinds = {
            "single": [n],  # the last chunk
            "range": list(range(1, min(n, 3) + 1)),  # leaves 1 to min(n, 3)
            "multi": [0, mid + 1],  # the meta leaf and one chunk, as a disclosure uses
        }
        for kind, positions in kinds.items():
            proof = p.prove(self.leaves, positions)
            # Verify it with the folding code before it is written.
            folded = p.fold(proof[0], proof[1], {q: self.leaves[q] for q in positions})
            assert folded == self.inner_root, f"{kind} proof does not fold"
            out[kind] = {
                "positions": positions,
                "leaves_hex": [self.leaves[q].hex() for q in positions],
                "leaf_count": proof[0],
                "proof_hex": enc_proof(proof).hex(),
            }
        return out


def span_raw(commit_id, offset, length, bundles, version=2):
    """A KDSP container around the given bundles, whatever they hold."""
    return (
        b"KDSP" + bytes([version]) + commit_id + be64(offset) + be64(length)
        + varint(len(bundles)) + b"".join(vec(b) for b in bundles)
    )


def contents(seed, lengths):
    return [o.splitmix_bytes(0x4B4F_0000_0000 + seed * 64 + i, n) for i, n in enumerate(lengths)]


def honest_world(seed, chunk_size, lengths, total=None):
    """A world whose manifest decodes: spans follow the chunk lengths."""
    datas = contents(seed, lengths)
    ends, pos = [], 0
    for n in lengths:
        pos += n
        ends.append(pos)
    total = pos if total is None else total
    blobs = [make_blob(c) for c in datas]
    w = World(total, chunk_size, blobs, o.spans_of(ends))
    w.ends = ends
    w.manifest = (
        o.build_manifest(total, chunk_size, list(zip(w.chunk_ids, ends)))
    )
    assert domain_digest(o.CHUNKED_DOMAIN, o.bmt_root(w.leaves)) == w.chunked_id
    parsed = o.parse_chunked(w.manifest)
    assert o.chunked_id(parsed["total"], parsed["chunk_size"], parsed["chunks"], parsed["ends"]) == w.chunked_id
    return w


def summary(res):
    keys = (
        "path", "leaf_id_hex", "tree_hash_hex", "step_inner_roots_hex",
        "chunk_inner_root_hex", "signer_hex", "signature_valid", "payload",
    )
    return {k: res[k] for k in keys}


def disclosure_entry(w, kind, i, comment, **kw):
    if kind == "chunk":
        raw = w.chunk_bundle(i)
    else:
        raw = w.range_bundle(i, kw["offset"], kw["length"])
    res = d.verify_bundle(raw, w.commit_id)
    entry = {
        "comment": comment,
        "kind": kind,
        "index": i,
        "commit_id_hex": w.commit_id.hex(),
        "bundle_hex": raw.hex(),
        "disclosed": summary(res),
    }
    if kind == "range":
        entry["offset_in_blob"], entry["len"] = kw["offset"], kw["length"]
    return entry


def span_entry(w, offset, length, first, last, comment):
    raw = w.span_bundle(offset, length, first, last)
    res = d.verify_span(raw, w.commit_id)
    return {
        "comment": comment,
        "commit_id_hex": w.commit_id.hex(),
        "span_hex": raw.hex(),
        "offset": offset,
        "len": length,
        "first_index": first,
        "last_index": last,
        "content_blake3": blake3(res["content"]).hex(),
    }


def case_entry(name, w, comment, layout_comment):
    first, last = 0, len(w.blobs) - 1
    entry = {
        "name": name,
        "comment": comment,
        "total_size": w.total,
        "chunk_size": w.chunk_size,
        "chunk_count": len(w.blobs),
        "chunks": [
            {"start": str(s), "end": str(e), "chunk_id_hex": h.hex(), "blob_len": len(b) - 10}
            for (s, e), h, b in zip(w.spans, w.chunk_ids, w.blobs)
        ],
        "manifest_len": len(w.manifest),
        "manifest_hex": w.manifest.hex(),
        "leaves_hex": [leaf.hex() for leaf in w.leaves],
        "inner_root_hex": w.inner_root.hex(),
        "chunked_id_hex": w.chunked_id.hex(),
        "proofs": w.proofs(),
        "disclosures": [],
        "spans": [],
    }
    assert len(w.manifest) == o.manifest_len(len(w.blobs))
    n = len(w.blobs)
    if n:
        mid = (n - 1) // 2
        picks = [(first, "first chunk (index 0, start 0)")]
        if mid not in (first, last):
            picks.append((mid, "a middle chunk"))
        if last != first:
            picks.append((last, "last chunk (end == total_size)"))
        if n == 1:
            picks = [(0, "one-chunk file: index 0 is also the last chunk; the multi-proof has no sibling")]
        for i, what in picks:
            entry["disclosures"].append(
                disclosure_entry(w, "chunk", i, f"plan 4.7 steps 1-6, 8: Chunk bundle, {what}")
            )
        # One Range bundle: a range inside the last chunk.
        ln = len(w.blobs[last]) - 10
        entry["disclosures"].append(
            disclosure_entry(
                w, "range", last, "plan 4.7 steps 7-8: Range bundle, absolute_offset = start + offset_in_blob",
                offset=ln // 3, length=max(1, ln // 3),
            )
        )
    return entry


# ---------------------------------------------------------------- cases


def build_cases():
    cases = []

    def add(name, w, comment):
        cases.append(case_entry(name, w, comment, None))
        return w

    # CDC layouts, chunk lengths chosen unequal.
    add("cdc_0_chunks", honest_world(0, 0, []), "plan 4.3/4.4: zero chunks, total_size 0; the meta leaf alone (leaf_count 1) and the v2 meta domain")
    add("cdc_1_chunk", honest_world(1, 0, [300]), "plan 4.7 step 4: one chunk, index 0 is also the last; the proof has no sibling")
    add("cdc_2_chunks", honest_world(2, 0, [700, 1300]), "plan 4.3/4.4: two chunks, spans [0,700) and [700,2000)")
    w3 = add("cdc_3_chunks", honest_world(3, 0, [500, 1200, 80]), "plan 4.3/4.4/4.7: three chunks, content-defined, unequal lengths")
    add("cdc_5_chunks", honest_world(4, 0, [64, 2500, 1, 1023, 1025]), "plan 4.9: five chunks, lengths around the 1024-byte BLAKE3 block")
    w7 = add("cdc_7_chunks", honest_world(5, 0, [100, 200, 300, 400, 500, 600, 700]), "plan 4.9/4.7: seven chunks; an odd leaf count of 8 and a middle chunk")
    add("fastcdc_v2_3_chunks", honest_world(6, 0x8000_0002, [900, 50, 4000]), "plan 4.4: chunk_size 0x8000_0002 is content defined; no fixed formula applies")
    # Fixed layouts.
    add("fixed_1_chunk", honest_world(7, 1000, [400]), "plan 4.4 check 4 / 4.7 step 5: fixed layout, one short chunk")
    add("fixed_2_chunks", honest_world(8, 1000, [1000, 333]), "plan 4.4/4.7 step 5: fixed layout, short last chunk")
    wf = add("fixed_3_chunks", honest_world(9, 1000, [1000, 1000, 500]), "plan 4.4/4.7 step 5: fixed layout, short last chunk")
    add("fixed_5_chunks_exact", honest_world(10, 600, [600] * 5), "plan 4.4/4.7 step 5: fixed layout whose total_size is a multiple of chunk_size")
    # Same chunk id at two indices.
    dup = [o.splitmix_bytes(0x44555000, 400)] * 2
    datas = [dup[0], o.splitmix_bytes(0x44555001, 250), dup[1]]
    blobs = [make_blob(c) for c in datas]
    ends = [400, 650, 1050]
    wd = World(1050, 0, blobs, o.spans_of(ends))
    wd.ends = ends
    wd.manifest = o.build_manifest(1050, 0, list(zip(wd.chunk_ids, ends)))
    assert wd.chunk_ids[0] == wd.chunk_ids[2] and wd.leaves[1] != wd.leaves[3]
    cases.append(case_entry("same_chunk_twice", wd, "plan 4.9: one chunk id at indices 0 and 2; the leaves differ because the spans differ", None))
    # Spans (KDSP v2) on three of the cases.
    by_name = {c["name"]: c for c in cases}
    by_name["cdc_3_chunks"]["spans"].append(
        span_entry(w3, 300, 600, 0, 1, "plan 4.7 KDSP: offset 300 in chunk 0, ends in chunk 1; no anchor")
    )
    by_name["cdc_7_chunks"]["spans"].append(
        span_entry(w7, 450, 900, 2, 4, "plan 4.7 KDSP: a span from the third chunk to the fifth, indices 2..4")
    )
    by_name["fixed_3_chunks"]["spans"].append(
        span_entry(wf, 999, 2, 0, 1, "plan 4.7 KDSP: two bytes across the boundary of two fixed chunks")
    )
    return cases


def build_leaf_digests():
    mx64, mx32 = (1 << 64) - 1, (1 << 32) - 1
    h = bytes(range(32))
    items = []

    def meta(name, total, size, comment):
        body = struct.pack("<Q", total) + struct.pack("<I", size)
        items.append({
            "name": name, "comment": comment, "domain": "kit-cblob-meta-v2",
            "total_size": str(total), "chunk_size": size, "body_hex": body.hex(),
            "digest_hex": o.meta_leaf(total, size).hex(),
        })

    def chunk(name, start, end, cid, comment):
        body = struct.pack("<QQ", start, end) + cid
        items.append({
            "name": name, "comment": comment, "domain": "kit-cblob-chunk-v1",
            "start": str(start), "end": str(end), "chunk_id_hex": cid.hex(), "body_hex": body.hex(),
            "digest_hex": o.chunk_leaf(start, end, cid).hex(),
        })

    meta("meta_asymmetric_max", mx64 - 1, mx32 - 1, "plan 4.3: L[0] with le64(total_size) and le32(chunk_size) at asymmetric maxima; a big-endian or swapped field fails")
    meta("meta_zero", 0, 0, "plan 4.3/4.4: L[0] of the empty file")
    chunk("chunk_asymmetric_max", mx64 - 1, mx64, h, "plan 4.3: L[i + 1] = domain_digest(chunk-v1, le64(start) || le64(end) || id); start and end differ and are near u64::MAX")
    chunk("chunk_start_end_swapped", mx64, mx64 - 1, h, "plan 4.3: the same two values swapped give another digest (start before end in the body)")
    chunk("chunk_small", 1, 2, h, "plan 4.3: low values; every byte of start and end distinct from the high bytes")
    return items


def build_refusals():
    plan = {
        "end does not increase": "plan 4.4 check 4: end_i > end_(i-1)",
        "end_0 is 0": "plan 4.4 check 4: end_0 > 0 (end_(-1) = 0); also a chunk of length 0 at the start",
        "zero-length chunk in the middle": "plan 4.4 check 4: a chunk of length 0 (end_i == end_(i-1)) is refused",
        "ends decrease": "plan 4.4 check 4: ends must increase",
        "last end below total_size": "plan 13 item 1, check 5: the last end is not below total_size",
        "last end above total_size": "plan 13 item 1, check 4: end_i <= total_size is a per-entry check",
        "middle end above total_size": "plan 13 item 1, check 4: end_i <= total_size at an interior entry",
        "end above total_size before the fixed formula": "plan 13 item 1: end <= total_size comes before the fixed formula in check 4",
        "total_size without chunks": "plan 4.4 check 5: with no chunks, total_size == 0",
        "total_size above the limit": "plan 4.4 check 3: total_size <= 128 GiB",
        "chunk above the length cap": "plan 4.4 check 4: end_i - end_(i-1) <= MAX_RAW_OBJECT_SIZE - 10 (a span above 1 GiB less 10)",
        "fixed layout, last end off by one": "plan 4.4 check 4: fixed layout end_i == min((i + 1) * chunk_size, total_size)",
        "fixed layout, first end off by one": "plan 4.4 check 4: fixed layout end_i == min((i + 1) * chunk_size, total_size)",
        "fixed layout, ends too long for the layout": "plan 4.4 check 4: fixed layout end_i == min((i + 1) * chunk_size, total_size)",
        "one byte too long": "plan 4.4 check 2: the object is exactly 22 + 40 * count bytes (+1)",
        "one byte too short": "plan 4.4 check 2: the object is exactly 22 + 40 * count bytes (-1)",
        "type 0x05 with schema 0x01": "plan 4.6: schema_version 0x02 for type 0x05; 0x01 is an unsupported version",
        "type 0x05 with schema 0x03": "plan 4.6: schema_version 0x02 for type 0x05; any other value is refused",
    }
    out = []
    for name, total, size, entries, tweak, want in o.MANIFEST_CASES:
        if want is None:
            continue
        data = o.build_manifest_unchecked(total, size, entries)
        if tweak is not None:
            data = tweak(data)
        out.append({"name": name, "comment": plan[name], "manifest_hex": data.hex(), "refused_by": want})
    # A count above the cap with a short body: check 1 runs before check 2.
    header = bytes([o.CHUNKED]) + o.PROLOGUE_MAGIC + b"\x02" + struct.pack("<QII", o.MAX_TOTAL_SIZE, 0, o.MAX_CHUNKS + 1)
    out.append({"name": "count above the cap, short body", "comment": "plan 4.4 check 1 runs before check 2: chunk_count <= 8,388,608, with a header only", "manifest_hex": header.hex(), "refused_by": "too many chunks"})
    # Another object type with schema 0x02.
    blob2 = bytes([o.BLOB]) + o.PROLOGUE_MAGIC + b"\x02" + struct.pack("<I", 0)
    out.append({"name": "blob with schema 0x02", "comment": "plan 4.6: schema 0x02 is for type 0x05 only", "manifest_hex": blob2.hex(), "refused_by": "unsupported object version", "object_type": o.BLOB})
    for e in out:
        data = bytes.fromhex(e["manifest_hex"])
        try:
            (o.parse_blob if e.get("object_type") == o.BLOB else o.parse_chunked)(data)
        except ValueError as err:
            assert str(err) == e["refused_by"], (e["name"], str(err))
        else:
            raise AssertionError(f"{e['name']} must be refused")
    return out


def build_overlap():
    """Plan 4.2: a dishonest signer commits overlapping spans. The id exists,
    no manifest decodes to it (a manifest holds ends only, so its starts
    follow the previous end), and two disclosures both verify."""
    datas = contents(40, [10, 10])
    blobs = [make_blob(c) for c in datas]
    w = World(15, 0, blobs, [(0, 10), (5, 15)])
    a = disclosure_entry(w, "chunk", 0, "plan 4.2: chunk 0 spans [0,10)")
    b = disclosure_entry(w, "chunk", 1, "plan 4.2: chunk 1 spans [5,15), overlapping chunk 0 on [5,10)")
    ra = disclosure_entry(w, "range", 0, "plan 4.2: bytes [5,10) of the file, as chunk 0 says", offset=5, length=5)
    rb = disclosure_entry(w, "range", 1, "plan 4.2: bytes [5,10) of the file, as chunk 1 says", offset=0, length=5)
    assert ra["disclosed"]["payload"]["absolute_offset"] == 5
    assert rb["disclosed"]["payload"]["absolute_offset"] == 5
    assert ra["disclosed"]["payload"]["bytes_blake3"] != rb["disclosed"]["payload"]["bytes_blake3"]
    # No manifest with these ends decodes to this id.
    cand = o.build_manifest(15, 0, [(w.chunk_ids[0], 10), (w.chunk_ids[1], 15)])
    parsed = o.parse_chunked(cand)
    assert o.chunked_id(parsed["total"], parsed["chunk_size"], parsed["chunks"], parsed["ends"]) != w.chunked_id
    return {
        "comment": "plan 4.2/4.9: overlapping spans under an id with no valid manifest; both disclosures verify and place different bytes at offsets 5..10",
        "total_size": 15,
        "chunk_size": 0,
        "spans": [["0", "10"], ["5", "15"]],
        "chunk_ids_hex": [h.hex() for h in w.chunk_ids],
        "chunked_id_hex": w.chunked_id.hex(),
        "manifest": None,
        "disclosures": [a, b, ra, rb],
    }


def build_long_chunk_range():
    """Plan section 13, item 3: a Range checks the range against the committed
    span only. The real chunk (12 bytes) is longer than its span (5 bytes);
    ranges inside the span verify, and the same chunk as a Chunk payload does
    not (see negative_disclosures)."""
    blobs = [make_blob(contents(55, [10])[0]), make_blob(contents(56, [12])[0])]
    w = World(15, 0, blobs, [(0, 10), (10, 15)])
    a = disclosure_entry(w, "range", 1, "plan 13 item 3: a range inside the span of a real chunk that is longer than its span verifies", offset=1, length=3)
    b = disclosure_entry(w, "range", 1, "plan 13 item 3: the whole committed span (offset 0, len 5) of the longer chunk verifies", offset=0, length=5)
    assert a["disclosed"]["payload"]["absolute_offset"] == 11
    assert b["disclosed"]["payload"]["absolute_offset"] == 10
    return {
        "comment": "plan 13 item 3/4.9: spans [0,10) and [10,15), but chunk 1 holds 12 bytes; a Range inside [10,15) verifies",
        "total_size": 15,
        "chunk_size": 0,
        "spans": [["0", "10"], ["10", "15"]],
        "chunk_blob_lens": [10, 12],
        "chunked_id_hex": w.chunked_id.hex(),
        "manifest": None,
        "disclosures": [a, b],
    }


def neg_entry(name, comment, raw, commit_id, reason):
    return {"name": name, "comment": comment, "commit_id_hex": commit_id.hex(), "bundle_hex": raw.hex(), "refused_by": reason}


def build_negative():
    out = []

    def bad_chunk(name, comment, spans, total, size, lengths, index, why, blobs=None, seed=50):
        datas = contents(seed, lengths)
        bl = blobs if blobs is not None else [make_blob(c) for c in datas]
        w = World(total, size, bl, spans)
        raw = w.chunk_bundle(index)
        try:
            d.verify_bundle(raw, w.commit_id)
        except d.Reject as e:
            assert why in str(e), (name, str(e), why)
        else:
            raise AssertionError(f"{name} must be refused")
        out.append(neg_entry(name, comment, raw, w.commit_id, why))
        return w

    bad_chunk("index_0_start_not_0", "plan 4.7 step 3: index 0 with start != 0", [(1, 10), (10, 15)], 15, 0, [9, 5], 0, "index 0 and start 0 disagree")
    bad_chunk("last_chunk_end_not_total", "plan 4.7 step 4: the last chunk with end != total_size", [(0, 10), (10, 14)], 15, 0, [10, 4], 1, "last index and end == total_size disagree")
    bad_chunk("middle_chunk_ends_at_total", "plan 4.7 step 4: a chunk that is not last with end == total_size", [(0, 15), (15, 15)], 15, 0, [15, 0], 0, "last index and end == total_size disagree")
    bad_chunk("start_equals_end", "plan 4.7 step 2: start < end (a chunk of length 0)", [(0, 10), (10, 10)], 10, 0, [10, 0], 1, "span outside the file")
    bad_chunk("end_above_total_size", "plan 4.7 step 2: end <= total_size", [(0, 10), (10, 16)], 15, 0, [10, 6], 1, "span outside the file")
    bad_chunk("fixed_end_off_by_one", "plan 4.7 step 5: fixed layout, end == min(start + chunk_size, total_size)", [(0, 10), (10, 19), (19, 25)], 25, 10, [10, 9, 6], 1, "wrong span")
    bad_chunk("fixed_start_off_by_one", "plan 4.7 step 5: fixed layout, start == index * chunk_size", [(0, 10), (9, 20), (20, 25)], 25, 10, [10, 11, 5], 1, "wrong span")
    # Honest spans, chunk bytes of another length: a Blob whose length differs from end - start.
    short = [make_blob(contents(51, [10])[0]), make_blob(contents(52, [9])[0])]
    bad_chunk("blob_length_differs_from_span", "plan 4.7 step 6: the Blob length field equals end - start", [(0, 10), (10, 20)], 20, 0, [], 1, "blob length differs from the span", blobs=short)
    longer = [make_blob(contents(57, [10])[0]), make_blob(contents(58, [12])[0])]
    bad_chunk("chunk_longer_than_span", "plan 13 item 3: a Chunk payload holds the bytes, so its Blob length must equal end - start (12 against 5)", [(0, 10), (10, 15)], 15, 0, [], 1, "blob length differs from the span", blobs=longer)
    raw_bytes = [make_blob(contents(53, [10])[0]), contents(54, [10])[0]]
    bad_chunk("bytes_not_a_blob", "plan 4.7 step 6: decode bytes as a Blob", [(0, 10), (10, 20)], 20, 0, [], 1, "not a blob", blobs=raw_bytes)
    # Range past the committed span but inside the real chunk.
    blobs = [make_blob(contents(55, [10])[0]), make_blob(contents(56, [12])[0])]
    w = World(15, 0, blobs, [(0, 10), (10, 15)])
    raw = w.range_bundle(1, 3, 8)
    try:
        d.verify_bundle(raw, w.commit_id)
    except d.Reject as e:
        assert "past the committed span" in str(e), str(e)
    else:
        raise AssertionError("range past the span must be refused")
    out.append(neg_entry("range_past_span_inside_real_chunk", "plan 4.7 step 7: offset_in_blob + len <= end - start, with the real chunk (12 bytes) longer than its span (5)", raw, w.commit_id, "range past the committed span"))
    # Plan section 13, item 2: the multi-proof runs before the header-only total
    # check, so a forged total_size that also breaks the layout is refused by the
    # proof (the meta leaf no longer folds), not by the layout rule.
    w = honest_world(59, 0, [10, 10])
    raw = w.chunk_bundle(0, total_field=1)
    try:
        d.verify_bundle(raw, w.commit_id)
    except d.Reject as e:
        assert "does not fold" in str(e), str(e)
    else:
        raise AssertionError("a forged total_size must be refused")
    out.append(neg_entry("forged_total_size_proof_wins", "plan 13 item 2: with total_size 1 below chunk_count 2 the proof fails first; the header-only total check never runs", raw, w.commit_id, "does not fold"))
    # A v2 bundle: an honest world, version byte 2.
    w = honest_world(60, 0, [30, 40])
    raw = w.chunk_bundle(0, version=2)
    try:
        d.verify_bundle(raw, w.commit_id)
    except d.Reject as e:
        assert "unsupported bundle version 2" in str(e)
    else:
        raise AssertionError("a v2 bundle must be refused")
    out.append(neg_entry("bundle_version_2", "plan 4.6: KDPB version 2 is UnsupportedBundleVersion(2)", raw, w.commit_id, "unsupported bundle version 2"))
    # Spans.
    spans_out = []

    def bad_span(name, comment, raw, commit_id, reason, expand_to=None):
        try:
            d.verify_span(raw if expand_to is None else raw + bytes(expand_to - len(raw)), commit_id)
        except d.SpanReject as e:
            assert e.reason == reason, (name, e.reason, reason)
        else:
            raise AssertionError(f"{name} must be refused")
        entry = {"name": name, "comment": comment, "commit_id_hex": commit_id.hex(), "span_hex": raw.hex(), "refused_by": reason}
        if expand_to is not None:
            entry["expand_to"] = expand_to  # append zero bytes up to this length before verifying
        spans_out.append(entry)

    w = honest_world(61, 0, [100, 100, 100])
    bad_span("span_of_v2_bundles", "plan 4.9: a span of KDPB v2 bundles", w.span_bundle(50, 100, 0, 1, inner_version=2), w.commit_id, "span_inner_invalid")
    bad_span("span_version_1", "plan 4.7: KDSP version 1 is refused", w.span_bundle(50, 100, 0, 1, version=1), w.commit_id, "span_version")
    bad_span("span_offset_in_second_chunk", "plan 4.7: offset < end_first (the range starts after the first chunk)", w.span_bundle(100, 150, 0, 2), w.commit_id, "span_range_outside")
    bad_span("span_range_past_last", "plan 4.7: offset + len <= end_last", w.span_bundle(50, 300, 0, 1), w.commit_id, "span_range_outside")
    bad_span("span_last_chunk_unneeded", "plan 4.7: offset + len > start_last", w.span_bundle(10, 50, 0, 1), w.commit_id, "span_last_unneeded")
    # A chain that breaks: spans (0,10), (11,20) under one id.
    blobs = [make_blob(c) for c in contents(62, [10, 9])]
    wg = World(20, 0, blobs, [(0, 10), (11, 20)])
    bad_span("span_chain_breaks", "plan 4.7: end_i == start_(i+1) (new reason span_chunk_chain)", wg.span_bundle(5, 10, 0, 1), wg.commit_id, "span_chunk_chain")
    # The sixteen reasons of plan section 13, item 6, in order. span_leaf_context
    # needs two files under one commit and span_chunk_context cannot be reached
    # by verified bundles of one leaf; neither has a vector here.
    good = w.span_bundle(50, 100, 0, 1)
    bad_span("span_too_large", "plan 13 item 6: the size check runs first (64 MiB + 1 bytes, zero-filled after a magic)", b"KDSP", w.commit_id, "span_too_large", expand_to=(64 << 20) + 1)
    bad_span("span_magic", "plan 13 item 6: magic", b"KDSX" + good[4:], w.commit_id, "span_magic")
    bad_span("span_encoding_truncated", "plan 13 item 6: a truncated container", good[:-5], w.commit_id, "span_encoding")
    bad_span("span_trailing_bytes", "plan 13 item 6: a byte after the last bundle", good + b"\x00", w.commit_id, "span_trailing_bytes")
    bad_span("span_commit", "plan 13 item 6: the embedded commit differs from the trusted one", good, blake3(b"another commit"), "span_commit")
    bad_span("span_range_arithmetic_len_0", "plan 13 item 6: len == 0", w.span_bundle(50, 0, 0, 1), w.commit_id, "span_range_arithmetic")
    bad_span("span_range_arithmetic_overflow", "plan 13 item 6: offset + len overflows u64", w.span_bundle((1 << 64) - 1, 2, 0, 1), w.commit_id, "span_range_arithmetic")
    bad_span("span_chunk_count_one", "plan 13 item 6: at least two bundles", w.span_bundle(50, 10, 0, 0), w.commit_id, "span_chunk_count")
    b0, b1 = w.chunk_bundle(0), w.range_bundle(1, 0, 10)
    bad_span("span_chunk_selector", "plan 13 item 6: every payload is a Chunk (here the second is a Range)", span_raw(w.commit_id, 50, 100, [b0, b1]), w.commit_id, "span_chunk_selector")
    bad_span("span_chunk_order_reversed", "plan 13 item 6: indices are consecutive and ascending", span_raw(w.commit_id, 50, 100, [w.chunk_bundle(1), b0]), w.commit_id, "span_chunk_order")
    bad_span("span_chunk_order_duplicate", "plan 13 item 6: the same index twice", span_raw(w.commit_id, 50, 100, [b0, b0]), w.commit_id, "span_chunk_order")
    return out, spans_out


# ----------------------------------------------------------------- pins

PIN_CHUNK_SIZE = 16384


def _leaf_block(args):
    lo, hi, total, size = args
    out = []
    for i in range(lo, hi):
        chash = struct.pack("<I", i).ljust(32, b"\0")
        leaf = o.chunk_leaf(i * size, (i + 1) * size, chash)
        out.append(blake3(struct.pack(">I", i + 1) + leaf))
    return out


def _reduce_block(args):
    nodes, = args
    return [blake3(nodes[i] + nodes[i + 1]) for i in range(0, len(nodes), 2)]


def pin_id(count, procs):
    """The id of a fixed-layout file of `count` chunks of 16 KiB, by the level
    build, with the work spread over `procs` processes. The chunk hash of chunk
    i is le32(i) padded to 32 bytes."""
    total = count * PIN_CHUNK_SIZE
    block = 1 << 15
    with multiprocessing.Pool(procs) as pool:
        meta = blake3(struct.pack(">I", 0) + o.meta_leaf(total, PIN_CHUNK_SIZE))
        parts = pool.map(_leaf_block, [(lo, min(lo + block, count), total, PIN_CHUNK_SIZE) for lo in range(0, count, block)])
        level = [meta] + [x for part in parts for x in part]
        leaf_count = len(level)
        while len(level) > 1:
            if len(level) % 2:
                level.append(level[-1])
            step = 1 << 16
            parts = pool.map(_reduce_block, [(level[i : i + step],) for i in range(0, len(level), step)])
            level = [x for part in parts for x in part]
    inner = blake3(struct.pack(">I", leaf_count) + level[0])
    return domain_digest(o.CHUNKED_DOMAIN, inner), inner


def build_pins(procs):
    out = []
    for count in (1_000_001, o.MAX_CHUNKS):
        cid, inner = pin_id(count, procs)
        total = count * PIN_CHUNK_SIZE
        header = bytes([o.CHUNKED]) + o.PROLOGUE_MAGIC + b"\x02" + struct.pack("<QII", total, PIN_CHUNK_SIZE, count)
        out.append({
            "name": f"fixed_16k_{count}_chunks",
            "comment": "plan 4.9: pinned id from the level build; chunk i has hash le32(i) padded to 32 bytes and the span [i * 16384, (i + 1) * 16384)"
            + (" (the largest manifest, plan 4.4: 22 + 40 * 8,388,608 = 335,544,342 bytes)" if count == o.MAX_CHUNKS else ""),
            "total_size": total,
            "chunk_size": PIN_CHUNK_SIZE,
            "chunk_count": count,
            "manifest_len": o.manifest_len(count),
            "manifest_header_hex": header.hex(),
            "inner_root_hex": inner.hex(),
            "chunked_id_hex": cid.hex(),
        })
    return out


# ----------------------------------------------------------------- main


def generate():
    cases = build_cases()
    neg, neg_spans = build_negative()
    return {
        "description": (
            "Expected values for the chunk-offsets format (kit 0.8.0 plan section 4), built by "
            "scripts/golden/chunk_offsets_ref.py from the design alone. Hex strings are lowercase. "
            "Proofs use the wire form of SPEC-MERKLE-OBJECTS 5.2 (big-endian leaf count, minimal "
            "varint count, siblings). Bundles are KDPB version 3 and spans KDSP version 2. "
            "'refused_by' is a label of the check that fails first, not a Rust error name."
        ),
        "signer_seed_hex": SIGNER_SEED.hex(),
        "leaf_digests": build_leaf_digests(),
        "cases": cases,
        "refusals": build_refusals(),
        "overlap": build_overlap(),
        "long_chunk_range": build_long_chunk_range(),
        "negative_disclosures": neg,
        "negative_spans": neg_spans,
    }


def verify_stored(doc):
    """Check the stored hex strings with the decoders and verifiers only, not
    with the builders: a manifest decodes to its id, every proof folds to the
    inner root, every bundle and span verifies (or is refused for the stated
    reason). Returns a list of failure messages."""
    bad = []

    def need(cond, msg):
        if not cond:
            bad.append(msg)

    for item in doc["leaf_digests"]:
        body = bytes.fromhex(item["body_hex"])
        need(domain_digest(item["domain"].encode(), body).hex() == item["digest_hex"], f"leaf {item['name']}")
    for c in doc["cases"]:
        parsed = o.parse_chunked(bytes.fromhex(c["manifest_hex"]))
        cid = o.chunked_id(parsed["total"], parsed["chunk_size"], parsed["chunks"], parsed["ends"])
        need(cid.hex() == c["chunked_id_hex"], f"case {c['name']}: id")
        need(len(bytes.fromhex(c["manifest_hex"])) == 22 + 40 * c["chunk_count"], f"case {c['name']}: length")
        inner = bytes.fromhex(c["inner_root_hex"])
        need(domain_digest(o.CHUNKED_DOMAIN, inner) == cid, f"case {c['name']}: inner root")
        for kind, pr in c["proofs"].items():
            data = bytes.fromhex(pr["proof_hex"])
            leaf_count, sibs = p.decode_proof(data, 2)
            leaves = {q: bytes.fromhex(h) for q, h in zip(pr["positions"], pr["leaves_hex"])}
            need(p.fold(leaf_count, sibs, leaves) == inner, f"case {c['name']}: {kind} proof")
        for e in c["disclosures"]:
            res = d.verify_bundle(bytes.fromhex(e["bundle_hex"]), bytes.fromhex(e["commit_id_hex"]))
            need(summary(res) == e["disclosed"], f"case {c['name']}: disclosure {e['kind']} {e['index']}")
            need(res["leaf_id_hex"] == c["chunked_id_hex"], f"case {c['name']}: disclosure leaf")
        for sp in c["spans"]:
            res = d.verify_span(bytes.fromhex(sp["span_hex"]), bytes.fromhex(sp["commit_id_hex"]))
            need(blake3(res["content"]).hex() == sp["content_blake3"], f"case {c['name']}: span content")
    for r in doc["refusals"]:
        try:
            (o.parse_blob if r.get("object_type") == o.BLOB else o.parse_chunked)(bytes.fromhex(r["manifest_hex"]))
            bad.append(f"refusal {r['name']}: accepted")
        except ValueError as err:
            need(str(err) == r["refused_by"], f"refusal {r['name']}: {err}")
    for e in doc["long_chunk_range"]["disclosures"]:
        res = d.verify_bundle(bytes.fromhex(e["bundle_hex"]), bytes.fromhex(e["commit_id_hex"]))
        need(summary(res) == e["disclosed"], "long_chunk_range: disclosure")
        need(res["leaf_id_hex"] == doc["long_chunk_range"]["chunked_id_hex"], "long_chunk_range: leaf")
    ov = doc["overlap"]
    for e in ov["disclosures"]:
        res = d.verify_bundle(bytes.fromhex(e["bundle_hex"]), bytes.fromhex(e["commit_id_hex"]))
        need(res["leaf_id_hex"] == ov["chunked_id_hex"], "overlap: leaf")
    for e in doc["negative_disclosures"]:
        try:
            d.verify_bundle(bytes.fromhex(e["bundle_hex"]), bytes.fromhex(e["commit_id_hex"]))
            bad.append(f"negative {e['name']}: accepted")
        except d.Reject as err:
            need(e["refused_by"] in str(err), f"negative {e['name']}: {err}")
    for e in doc["negative_spans"]:
        raw = bytes.fromhex(e["span_hex"])
        if "expand_to" in e:
            raw += bytes(e["expand_to"] - len(raw))
        try:
            d.verify_span(raw, bytes.fromhex(e["commit_id_hex"]))
            bad.append(f"negative span {e['name']}: accepted")
        except d.SpanReject as err:
            need(err.reason == e["refused_by"], f"negative span {e['name']}: {err.reason}")
    return bad


def main():
    args = sys.argv[1:]
    large, write = "--large" in args, "--write" in args
    unknown = [a for a in args if a not in ("--large", "--write")]
    if unknown:
        sys.exit("usage: chunk_offsets_ref.py [--large] [--write]")
    fresh = generate()
    existing = json.load(open(OUT)) if os.path.exists(OUT) else {}
    if large:
        fresh["pins"] = build_pins(max(1, (os.cpu_count() or 2) - 1))
    elif "pins" in existing:
        fresh["pins"] = existing["pins"]
    text = json.dumps(fresh, indent=1) + "\n"
    if write:
        with open(OUT, "w") as f:
            f.write(text)
        print(f"wrote {OUT}")
        return
    if not existing:
        sys.exit(f"{OUT} does not exist; run with --write")
    bad = [k for k in fresh if existing.get(k) != fresh[k] and (large or k != "pins")]
    if bad:
        for k in bad:
            print("FAIL: chunk_offsets_expected.json differs in", k)
        sys.exit(1)
    problems = verify_stored(existing)
    if problems:
        for msg in problems:
            print("FAIL:", msg)
        sys.exit(1)
    if "pins" not in existing:
        print("note: no pins in the file; run with --large --write to add them")
    print("OK")


if __name__ == "__main__":
    main()

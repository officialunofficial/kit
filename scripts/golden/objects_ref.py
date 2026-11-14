#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Independent reference check of the object, tag, proof-id and chunker
# golden vectors:
#   rust/tests/golden/objects/
#   rust/tests/golden/tags/
#   rust/tests/golden/proofs/   (object ids only)
#   rust/tests/golden/fastcdc/
#
# The check shares no code with the Rust crates. It reads only the specs:
# SPEC-OBJECTS, SPEC-SIGNING, SPEC-MERKLE-OBJECTS and SPEC-FASTCDC, with the
# chunk-offsets format of the kit 0.8.0 plan (section 4) applied. BLAKE3
# comes from the pure-Python transcription in blake3_subtree_ref.py. Ed25519
# signing and the splitmix64 stream are written here from RFC 8032 and the
# splitmix64 definition.
#
# Checks:
#   * every .bin file against the size and BLAKE3 in its .json sidecar and in
#     MANIFEST.txt;
#   * every object parsed strictly: prologue, field order, sort order, name
#     rules, and no trailing byte;
#   * the entry name rules against a table of accepted and refused names;
#   * the chunked blob header rules against a table of accepted and refused
#     layouts, and the manifest decode rules (40-byte entries with end
#     offsets, schema_version 0x02 for type 0x05 only) against a table of
#     accepted and refused manifests;
#   * the signing bytes of the commit, remix and tag vectors rebuilt from the
#     parsed fields, with the domain string and the u16 length prefix of
#     SPEC-SIGNING;
#   * the tag signing hash and the signed tag signature from seed [0x07; 32];
#   * the ids of the empty tree, the single-file tree and the three-chunk
#     chunked blob, which pin the "kit.tree" and "kit.chunked" domains and
#     the "kit-cblob-meta-v2" and "kit-cblob-chunk-v1" leaf domains;
#   * the FastCDC gear table, the v1 and v2 masks, the v1 and v2 chunk
#     boundaries of the pinned streams, and the v2 manifest bytes and id.
#
# Usage:
#   python3 scripts/golden/objects_ref.py rust/tests/golden
#
# Exit 0 and print "OK" when every check passes; exit 1 otherwise.

import hashlib
import json
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from blake3_subtree_ref import blake3  # noqa: E402

PROLOGUE_MAGIC = b"KOB1"
BLOB, TREE, COMMIT, REMIX, CHUNKED, DELTA, TAG = 1, 2, 3, 4, 5, 6, 7


def schema_version(object_type):
    """Plan 4.6: 0x02 for object type 0x05 only; every other type stays 0x01.
    The commit signing bytes keep 0x01 (the signing bytes copy the prologue of
    a commit, whose type is not 0x05)."""
    return 2 if object_type == CHUNKED else 1


# SPEC-SIGNING section 2 and SPEC-MERKLE-OBJECTS section 2.
COMMIT_DOMAIN = b"kit.commit\x00"
REMIX_DOMAIN = b"kit.remix\x00"
TAG_DOMAIN = b"kit.tag\x00"
TREE_DOMAIN = b"kit.tree\x00"
CHUNKED_DOMAIN = b"kit.chunked\x00"

FAILURES = []


def fail(msg):
    FAILURES.append(msg)
    print("FAIL:", msg, flush=True)


def expect(cond, msg):
    if not cond:
        fail(msg)


def domain_digest(domain, body):
    return blake3(struct.pack("<H", len(domain)) + domain + body)


# ---------------------------------------------------------------- parsing


class Reader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def take(self, n):
        if self.pos + n > len(self.data):
            raise ValueError("truncated")
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def u8(self):
        return self.take(1)[0]

    def u16(self):
        return struct.unpack("<H", self.take(2))[0]

    def u32(self):
        return struct.unpack("<I", self.take(4))[0]

    def u64(self):
        return struct.unpack("<Q", self.take(8))[0]

    def end(self):
        if self.pos != len(self.data):
            raise ValueError("trailing bytes")


def prologue(r, want):
    t = r.u8()
    if t != want:
        raise ValueError(f"object_type {t:#x}, want {want:#x}")
    if r.take(4) != PROLOGUE_MAGIC:
        raise ValueError("bad magic")
    if r.u8() != schema_version(want):
        raise ValueError("unsupported object version")


def identity(r):
    """SPEC-OBJECTS section 9. Returns the raw encoded bytes."""
    start = r.pos
    kind = r.u8()
    n = r.u16()
    if kind not in (1, 2, 3):
        raise ValueError("unknown identity kind")
    if n == 0 or n > 4096:
        raise ValueError("bad identity length")
    if kind == 1 and n != 32:
        raise ValueError("ed25519 identity must be 32 bytes")
    r.take(n)
    return r.data[start : r.pos]


RESERVED = {"CON", "PRN", "AUX", "NUL"} | {f"COM{i}" for i in range(1, 10)} | {
    f"LPT{i}" for i in range(1, 10)
}


def check_entry_name(name):
    if not 1 <= len(name) <= 255:
        raise ValueError("name length")
    if any(b in (0, 0x2F, 0x3A, 0x5C) for b in name):
        raise ValueError("forbidden byte")
    if name in (b".", b".."):
        raise ValueError("dot name")
    if name[-1] in (0x2E, 0x20):
        raise ValueError("trailing dot or space")
    if name.lower() in (b".kit", b".git"):
        raise ValueError("reserved name")
    if re.fullmatch(rb"(kit|git)~[0-9]+", name.lower()):
        raise ValueError("short name of a reserved name")
    stem = name.split(b".", 1)[0].upper()
    if stem.decode("latin-1") in RESERVED:
        raise ValueError("device name")


# SPEC-OBJECTS section 4.1: names that the rules accept and names that they
# refuse, one case for each rule added for NTFS.
ACCEPTED_NAMES = [b"a", b"a.b", b"kit", b"kit~", b"kit~a", b"git.txt", b"~1"]
REFUSED_NAMES = [
    b"a:b",
    b".kit::$INDEX_ALLOCATION",
    b"C:x",
    b"KIT~1",
    b"git~12",
    b"Git~007",
    b".KIT",
    b"a.",
    b"a ",
    b"aux.c",
    b"a\\b",
]


def check_name_rules():
    for name in ACCEPTED_NAMES:
        try:
            check_entry_name(name)
        except ValueError:
            fail(f"entry name {name!r} must be accepted")
    for name in REFUSED_NAMES:
        try:
            check_entry_name(name)
        except ValueError:
            continue
        fail(f"entry name {name!r} must be refused")


def parse_blob(data):
    r = Reader(data)
    prologue(r, BLOB)
    n = r.u32()
    r.take(n)
    r.end()
    return {"len": n}


def parse_tree(data):
    r = Reader(data)
    prologue(r, TREE)
    count = r.u32()
    if count > 1_000_000:
        raise ValueError("too many entries")
    entries = []
    prev = None
    for _ in range(count):
        name = r.take(r.u32())
        check_entry_name(name)
        mode = r.u8()
        if mode not in (1, 2, 3, 4):
            raise ValueError("bad mode")
        h = r.take(32)
        if prev is not None and name <= prev:
            raise ValueError("entries not strictly ascending")
        prev = name
        entries.append((name, mode, h))
    r.end()
    return {"entries": entries}


def parse_commit(data):
    r = Reader(data)
    prologue(r, COMMIT)
    tree = r.take(32)
    parents = [r.take(32) for _ in range(r.u32())]
    if len(parents) > 1000:
        raise ValueError("too many parents")
    author = identity(r)
    message = r.take(r.u32())
    timestamp = r.u64()
    signer = r.take(32)
    r.take(32)  # message_hash
    r.take(32)  # content_digest
    signature = r.take(64)
    r.end()
    # SPEC-SIGNING section 3.
    signing = (
        data[:6]
        + tree
        + struct.pack("<I", len(parents))
        + b"".join(parents)
        + author
        + struct.pack("<I", len(message))
        + message
        + struct.pack("<Q", timestamp)
        + signer
    )
    return {"signing": signing, "domain": COMMIT_DOMAIN, "signature": signature}


def parse_remix(data):
    r = Reader(data)
    prologue(r, REMIX)
    tree = r.take(32)
    parents = [r.take(32) for _ in range(r.u32())]
    if len(parents) > 1000:
        raise ValueError("too many parents")
    nsrc = r.u32()
    if nsrc > 10_000:
        raise ValueError("too many sources")
    sources = [(r.take(32), r.take(32)) for _ in range(nsrc)]
    if sources != sorted(set(sources)):
        raise ValueError("sources not sorted or not unique")
    author = identity(r)
    message = r.take(r.u32())
    timestamp = r.u64()
    signer = r.take(32)
    signature = r.take(64)
    r.end()
    # SPEC-SIGNING section 4.
    signing = (
        data[:6]
        + tree
        + struct.pack("<I", len(parents))
        + b"".join(parents)
        + struct.pack("<I", nsrc)
        + b"".join(u + c for u, c in sources)
        + author
        + struct.pack("<I", len(message))
        + message
        + struct.pack("<Q", timestamp)
        + signer
    )
    return {"signing": signing, "domain": REMIX_DOMAIN, "signature": signature}


def parse_tag(data):
    r = Reader(data)
    prologue(r, TAG)
    target = r.take(32)
    target_type = r.u8()
    if target_type not in (1, 2, 3, 4, 5, 7):
        raise ValueError("bad target type")
    name_len = r.u32()
    if not 1 <= name_len <= 4096:
        raise ValueError("bad tag name length")
    name = r.take(name_len)
    if any(b in (0, 0x2F, 0x5C) for b in name):
        raise ValueError("forbidden byte in tag name")
    tagger = identity(r)
    message = r.take(r.u32())
    timestamp = r.u64()
    signer = r.take(32)
    signature = r.take(64)
    r.end()
    # SPEC-SIGNING section 4a.
    signing = (
        data[:6]
        + target
        + bytes([target_type])
        + struct.pack("<I", name_len)
        + name
        + tagger
        + struct.pack("<I", len(message))
        + message
        + struct.pack("<Q", timestamp)
        + signer
    )
    return {
        "signing": signing,
        "domain": TAG_DOMAIN,
        "signature": signature,
        "signer": signer,
    }


# SPEC-OBJECTS section 7: header layouts as (total_size, chunk_size,
# chunk_count) that the header-only check accepts and refuses. The decoder and
# the disclosure verifier both run it; the entries are checked on top of it by
# the decoder (plan 4.4).
ACCEPTED_CHUNKED = [
    (0, 0, 0),
    (3, 0, 3),
    (196_608, 65_536, 3),
    (131_073, 65_536, 3),
    (1, 65_536, 1),
    (65_536, 65_536, 1),
    (1 << 30, 0, 2),
    ((1 << 30) + 1, 0, 2),
    (128 << 30, 0, 2),
    (0, 0x8000_0002, 0),
    (3, 0x8000_0002, 3),
    (128 << 30, 0x8000_0002, 2),
    (1, 0x8000_0001, 1),
]
REFUSED_CHUNKED = [
    (1, 0, 0),
    (2, 0, 3),
    ((128 << 30) + 1, 0, 2),
    (196_609, 65_536, 3),
    (131_072, 65_536, 3),
    (65_536, 65_536, 2),
    (1, 65_536, 2),
    (0, 65_536, 1),
    (1, 0x8000_0002, 0),
    (2, 0x8000_0002, 3),
    ((128 << 30) + 1, 0x8000_0002, 2),
    (3, 0x8000_0001, 3),
]

# SPEC-OBJECTS section 7 and plan 4.4: the bounds of a manifest. The largest
# chunk_count is the largest total_size cut at the 16 KiB FastCDC minimum chunk
# size.
MAX_TOTAL_SIZE = 128 << 30
MAX_CHUNKS = 8_388_608
MAX_RAW_OBJECT_SIZE = 1 << 30
# A chunk is a Blob: a 10-byte prologue and its content, in one raw object.
MAX_CHUNK_LEN = MAX_RAW_OBJECT_SIZE - 10
# Plan 4.4: the manifest header is the 6-byte prologue, u64, u32, u32; an entry
# is a 32-byte chunk hash and a u64 end offset.
CHUNKED_HEADER_LEN = 22
CHUNK_ENTRY_LEN = 40


def manifest_len(count):
    return CHUNKED_HEADER_LEN + CHUNK_ENTRY_LEN * count


# SPEC-OBJECTS section 7: chunk_size values that name a content-defined
# chunker rather than a fixed size. 0 is FastCDC v1, 0x8000_0002 FastCDC v2.
CONTENT_DEFINED = (0, 0x8000_0002)


def check_chunked_layout(total, size, count):
    """The header-only check (`check_chunked_total_size`), which stays: a
    disclosure verifier runs it on (total_size, chunk_size, leaf_count - 1)."""
    if total > MAX_TOTAL_SIZE:
        raise ValueError("total_size above the file limit")
    if count == 0:
        if total != 0:
            raise ValueError("total_size without chunks")
    elif size in CONTENT_DEFINED:
        if total < count:
            raise ValueError("total_size below chunk_count")
    elif not ((count - 1) * size < total <= count * size):
        raise ValueError("total_size outside the fixed-size layout")


def check_chunk_end(index, size, total, prev_end, end):
    """Plan 4.4 check 4 (as fixed by plan section 13, item 1): the per-entry
    rule that the decoder and the fold share, so both refuse at the same entry
    with the same label. In order: the end increases, the length cap,
    end <= total_size, the fixed formula. Raises ValueError with one label per
    rule."""
    if end <= prev_end:
        raise ValueError("end not increasing")
    if end - prev_end > MAX_CHUNK_LEN:
        raise ValueError("chunk length above the object limit")
    if end > total:
        raise ValueError("end above total_size")
    if size not in CONTENT_DEFINED and end != min((index + 1) * size, total):
        raise ValueError("fixed layout end")


def check_last_end(total, count, last_end):
    """Plan 4.4 check 5. With check 4 done per entry, it catches only a last
    end below total_size and a zero-chunk manifest with a non-zero total_size."""
    if count == 0:
        if total != 0:
            raise ValueError("total_size without chunks")
    elif last_end < total:
        raise ValueError("last end below total_size")


def check_chunked_rules():
    if MAX_CHUNKS != MAX_TOTAL_SIZE // (16 * 1024):
        fail("the chunk cap must be the size bound over the minimum chunk size")
    if manifest_len(MAX_CHUNKS) != 335_544_342:
        fail("largest manifest length (plan 4.4)")
    # Plan 4.4 check 1 runs before check 2: a count above the cap with a short
    # body is "too many chunks", and a count at the cap with a short body is a
    # length error.
    for count, want in ((MAX_CHUNKS, "manifest length"), (MAX_CHUNKS + 1, "too many chunks")):
        header = (
            bytes([CHUNKED]) + PROLOGUE_MAGIC + bytes([schema_version(CHUNKED)])
            + struct.pack("<QII", MAX_TOTAL_SIZE, 0, count)
        )
        try:
            parse_chunked(header)
        except ValueError as err:
            if str(err) != want:
                fail(f"chunk count {count}: refused with {err}, want {want}")
            continue
        fail(f"chunk count {count}: a header without entries must be refused")
    for layout in ACCEPTED_CHUNKED:
        try:
            check_chunked_layout(*layout)
        except ValueError:
            fail(f"chunked layout {layout} must be accepted")
    for layout in REFUSED_CHUNKED:
        try:
            check_chunked_layout(*layout)
        except ValueError:
            continue
        fail(f"chunked layout {layout} must be refused")
    # Plan 4.6: schema 0x02 is for type 0x05 only; every other type stays 0x01.
    for t in (BLOB, TREE, COMMIT, REMIX, TAG):
        for version in (0, 2):
            try:
                prologue(Reader(bytes([t]) + PROLOGUE_MAGIC + bytes([version])), t)
            except ValueError:
                continue
            fail(f"type {t:#x} with schema {version:#x} must be refused")
        prologue(Reader(bytes([t]) + PROLOGUE_MAGIC + b"\x01"), t)
    for name, total, size, entries, tweak, want in MANIFEST_CASES:
        data = build_manifest_unchecked(total, size, entries)
        if tweak is not None:
            data = tweak(data)
        try:
            parse_chunked(data)
        except ValueError as err:
            if want is None:
                fail(f"manifest case {name}: refused with {err}, must be accepted")
            elif str(err) != want:
                fail(f"manifest case {name}: refused with {err!r}, want {want!r}")
            continue
        if want is not None:
            fail(f"manifest case {name}: must be refused with {want!r}")


def build_manifest_unchecked(total, chunk_size, entries, schema=None):
    """Plan 4.4 manifest bytes from (chunk hash, end offset) entries, with no
    validation. `build_manifest` is the checked writer."""
    schema = schema_version(CHUNKED) if schema is None else schema
    return (
        bytes([CHUNKED]) + PROLOGUE_MAGIC + bytes([schema])
        + struct.pack("<QII", total, chunk_size, len(entries))
        + b"".join(h + struct.pack("<Q", e) for h, e in entries)
    )


def build_manifest(total, chunk_size, entries):
    """The checked writer: it refuses what `parse_chunked` refuses (plan 4.4)."""
    data = build_manifest_unchecked(total, chunk_size, entries)
    parse_chunked(data)
    return data


def parse_chunked(data):
    """Plan 4.4: the five decode checks, in order, each with its own label."""
    r = Reader(data)
    prologue(r, CHUNKED)
    total = r.u64()
    chunk_size = r.u32()
    count = r.u32()
    if count > MAX_CHUNKS:  # check 1
        raise ValueError("too many chunks")
    if len(data) != manifest_len(count):  # check 2, before any entry is read
        raise ValueError("manifest length")
    if total > MAX_TOTAL_SIZE:  # check 3
        raise ValueError("total_size above the file limit")
    chunks, ends, prev = [], [], 0
    for i in range(count):  # check 4
        chunks.append(r.take(32))
        end = r.u64()
        check_chunk_end(i, chunk_size, total, prev, end)
        ends.append(end)
        prev = end
    check_last_end(total, count, prev)  # check 5
    r.end()
    return {"total": total, "chunk_size": chunk_size, "chunks": chunks, "ends": ends}


def spans_of(ends):
    """start_0 = 0 and start_i = end_(i-1)."""
    return list(zip([0] + ends[:-1], ends))


def _h(i):
    return bytes([i]) * 32


def _with_schema(version):
    return lambda data: data[:5] + bytes([version]) + data[6:]


# Plan 4.4 and 4.9: (name, total_size, chunk_size, [(hash, end)], tweak of the
# bytes, expected refusal label or None when accepted). Each refused case
# breaks exactly one rule so its label is the first failing check.
MANIFEST_CASES = [
    ("zero chunks", 0, 0, [], None, None),
    ("one chunk", 5, 0, [(_h(1), 5)], None, None),
    ("three chunks", 30, 0, [(_h(1), 10), (_h(2), 25), (_h(3), 30)], None, None),
    ("fixed layout, short last", 2500, 1000, [(_h(1), 1000), (_h(2), 2000), (_h(3), 2500)], None, None),
    ("fixed layout, exact", 2000, 1000, [(_h(1), 1000), (_h(2), 2000)], None, None),
    ("fastcdc v2 layout", 9, 0x8000_0002, [(_h(1), 4), (_h(2), 9)], None, None),
    ("same chunk hash twice", 20, 0, [(_h(1), 10), (_h(1), 20)], None, None),
    ("chunk at the length cap", MAX_CHUNK_LEN, 0, [(_h(1), MAX_CHUNK_LEN)], None, None),
    ("end does not increase", 10, 0, [(_h(1), 10), (_h(2), 10)], None, "end not increasing"),
    ("end_0 is 0", 0, 0, [(_h(1), 0)], None, "end not increasing"),
    ("zero-length chunk in the middle", 9, 0, [(_h(1), 5), (_h(2), 5), (_h(3), 9)], None, "end not increasing"),
    ("ends decrease", 20, 0, [(_h(1), 10), (_h(2), 5), (_h(3), 20)], None, "end not increasing"),
    ("last end below total_size", 25, 0, [(_h(1), 10), (_h(2), 20)], None, "last end below total_size"),
    ("last end above total_size", 15, 0, [(_h(1), 10), (_h(2), 20)], None, "end above total_size"),
    ("middle end above total_size", 15, 0, [(_h(1), 5), (_h(2), 20), (_h(3), 25)], None, "end above total_size"),
    ("end above total_size before the fixed formula", 1500, 1000, [(_h(1), 1000), (_h(2), 2000)], None, "end above total_size"),
    ("total_size without chunks", 1, 0, [], None, "total_size without chunks"),
    ("total_size above the limit", MAX_TOTAL_SIZE + 1, 0, [], None, "total_size above the file limit"),
    ("chunk above the length cap", MAX_CHUNK_LEN + 1, 0, [(_h(1), MAX_CHUNK_LEN + 1)], None, "chunk length above the object limit"),
    ("fixed layout, last end off by one", 2001, 1000, [(_h(1), 1000), (_h(2), 2001)], None, "fixed layout end"),
    ("fixed layout, first end off by one", 2000, 1000, [(_h(1), 999), (_h(2), 2000)], None, "fixed layout end"),
    ("fixed layout, ends too long for the layout", 2000, 1000, [(_h(1), 1500), (_h(2), 2000)], None, "fixed layout end"),
    ("one byte too long", 20, 0, [(_h(1), 10), (_h(2), 20)], lambda d: d + b"\x00", "manifest length"),
    ("one byte too short", 20, 0, [(_h(1), 10), (_h(2), 20)], lambda d: d[:-1], "manifest length"),
    ("type 0x05 with schema 0x01", 5, 0, [(_h(1), 5)], _with_schema(1), "unsupported object version"),
    ("type 0x05 with schema 0x03", 5, 0, [(_h(1), 5)], _with_schema(3), "unsupported object version"),
]


# ----------------------------------------------------------- merkle ids


def bmt_root(leaves):
    """SPEC-MERKLE-OBJECTS section 1.1."""
    if leaves:
        level = [blake3(struct.pack(">I", i) + leaf) for i, leaf in enumerate(leaves)]
    else:
        level = [blake3(b"")]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [blake3(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return blake3(struct.pack(">I", len(leaves)) + level[0])


def tree_id(entries):
    leaves = [
        domain_digest(
            b"kit-tree-entry-v1", struct.pack("<I", len(n)) + n + bytes([m]) + h
        )
        for n, m, h in entries
    ]
    return domain_digest(TREE_DOMAIN, bmt_root(leaves))


def meta_leaf(total, chunk_size):
    """Plan 4.3: L[0]."""
    return domain_digest(b"kit-cblob-meta-v2", struct.pack("<Q", total) + struct.pack("<I", chunk_size))


def chunk_leaf(start, end, chunk_id):
    """Plan 4.3: L[i + 1] commits the span and the chunk id."""
    return domain_digest(b"kit-cblob-chunk-v1", struct.pack("<QQ", start, end) + chunk_id)


def chunk_leaves(total, chunk_size, spans, chunks):
    """All leaves of the BMT: the meta leaf, then one per chunk. `spans` are
    (start, end) pairs, taken as given (no validation)."""
    return [meta_leaf(total, chunk_size)] + [
        chunk_leaf(s, e, h) for (s, e), h in zip(spans, chunks)
    ]


def chunked_id_of_spans(total, chunk_size, spans, chunks):
    """The id of the leaves, whether or not any manifest decodes to them."""
    return domain_digest(CHUNKED_DOMAIN, bmt_root(chunk_leaves(total, chunk_size, spans, chunks)))


def chunked_id(total, chunk_size, chunks, ends):
    return chunked_id_of_spans(total, chunk_size, spans_of(ends), chunks)


# -------------------------------------------------------------- ed25519

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
B = (
    15112221349535400772501151409588531511454012693041857206046113283949847762202,
    46316835694926478169428394003475163141307993866256225615783033603165251855960,
)


def point_add(p, q):
    x1, y1 = p
    x2, y2 = q
    t = D * x1 * x2 * y1 * y2 % P
    x3 = (x1 * y2 + x2 * y1) * pow(1 + t, P - 2, P) % P
    y3 = (y1 * y2 + x1 * x2) * pow(1 - t, P - 2, P) % P
    return x3, y3


def scalar_mult(k, p):
    r = (0, 1)
    while k:
        if k & 1:
            r = point_add(r, p)
        p = point_add(p, p)
        k >>= 1
    return r


def encode_point(p):
    x, y = p
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def ed25519_sign(seed, msg):
    """RFC 8032 section 5.1.6. Returns (public key, signature)."""
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    pub = encode_point(scalar_mult(a, B))
    r = int.from_bytes(hashlib.sha512(h[32:] + msg).digest(), "little") % L
    big_r = encode_point(scalar_mult(r, B))
    k = int.from_bytes(hashlib.sha512(big_r + pub + msg).digest(), "little") % L
    s = (r + k * a) % L
    return pub, big_r + s.to_bytes(32, "little")


# ------------------------------------------------------------- fastcdc

GEAR_SEED = 0x004B495446434443  # ASCII "KITFCDC", big-endian
MASK64 = (1 << 64) - 1


def splitmix_next(state):
    state = (state + 0x9E3779B97F4A7C15) & MASK64
    z = state
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK64
    return state, z ^ (z >> 31)


def gear_table():
    state, out = GEAR_SEED, []
    for _ in range(256):
        state, z = splitmix_next(state)
        out.append(z)
    return out


def splitmix_bytes(seed, total):
    out, state = bytearray(), seed
    while len(out) < total:
        state, z = splitmix_next(state)
        out += z.to_bytes(8, "little")
    return bytes(out[:total])


def v1_masks(avg_size=64 * 1024):
    """SPEC-FASTCDC section 5."""
    bits = avg_size.bit_length() - 1
    mask = (1 << bits) - 1
    return mask | (mask << 1), mask >> 1


def spread_mask(n):
    """SPEC-FASTCDC section 11.1: n one-bits spread over bits 16 to 47."""
    m = 0
    for k in range(n):
        m |= 1 << (16 + (2 * k + 1) * 32 // (2 * n))
    return m


def v2_masks(avg_size=64 * 1024):
    """SPEC-FASTCDC section 11.1."""
    bits = avg_size.bit_length() - 1
    return spread_mask(bits + 2), spread_mask(bits - 2)


def fastcdc_cut(data, gear, masks, min_size=16 * 1024, avg_size=64 * 1024, max_size=256 * 1024):
    """SPEC-FASTCDC section 5, with the masks of section 5 or 11.1."""
    if len(data) <= min_size:
        return len(data)
    mask_s, mask_l = masks
    h = 0
    for i in range(min_size, min(avg_size, len(data))):
        h = ((h << 1) + gear[data[i]]) & MASK64
        if h & mask_s == 0:
            return i
    for i in range(avg_size, min(max_size, len(data))):
        h = ((h << 1) + gear[data[i]]) & MASK64
        if h & mask_l == 0:
            return i
    return min(max_size, len(data))


def boundaries(data, gear, masks=None):
    """Chunk-end offsets; FastCDC v1 unless masks are given."""
    masks = masks or v1_masks()
    ends, pos = [], 0
    while pos < len(data):
        pos += fastcdc_cut(data[pos:], gear, masks)
        ends.append(pos)
    return ends


def runs_stream():
    """SPEC-FASTCDC section 8, vector 11: runs of one byte value between
    splitmix64 stretches, 1 MiB in all."""
    return (
        bytes(393_216)
        + splitmix_bytes(0x0052_554E_5300_0001, 262_144)
        + b"\xa5" * 131_072
        + splitmix_bytes(0x0052_554E_5300_0002, 262_144)
    )


def blob_id(data):
    """SPEC-OBJECTS sections 2 and 3: BLAKE3 of the canonical blob bytes."""
    return blake3(bytes([BLOB]) + PROLOGUE_MAGIC + bytes([schema_version(BLOB)]) + struct.pack("<I", len(data)) + data)


FASTCDC_V2_CHUNK_SIZE = 0x8000_0002  # SPEC-OBJECTS section 7


# ---------------------------------------------------------------- checks


def read(root, d, name):
    with open(os.path.join(root, d, name), "rb") as f:
        return f.read()


def manifest(root, d):
    out = {}
    for line in read(root, d, "MANIFEST.txt").decode().splitlines():
        if line and not line.startswith("#"):
            name, digest = line.split()[:2]
            out[name] = digest
    return out


def check_files(root, d):
    """Check each .bin against its sidecar and the manifest. Returns {name: bytes}."""
    man = manifest(root, d)
    files = {}
    for fn in sorted(os.listdir(os.path.join(root, d))):
        if not fn.endswith(".json"):
            continue
        meta = json.loads(read(root, d, fn))
        if "bin" not in meta:
            continue
        data = read(root, d, meta["bin"])
        digest = blake3(data).hex()
        expect(len(data) == meta["size"], f"{d}/{fn}: size {len(data)} != {meta['size']}")
        expect(digest == meta["blake3"], f"{d}/{fn}: blake3 {digest} != {meta['blake3']}")
        if meta["name"] in man:
            expect(man[meta["name"]] == digest, f"{d}/MANIFEST.txt: {meta['name']} differs")
        files[meta["name"]] = data
    return files, man


PARSERS = {
    "blob": parse_blob,
    "tree": parse_tree,
    "commit": parse_commit,
    "remix": parse_remix,
    "tag": parse_tag,
    "chunked_blob": parse_chunked,
}


def parser_for(name):
    if name.endswith("_signing_bytes") or name.startswith("identity_"):
        return None
    for prefix, fn in PARSERS.items():
        if name.startswith(prefix):
            return fn
    if name.startswith("empty_blob"):
        return parse_blob
    if name.startswith("empty_tree"):
        return parse_tree
    return None


def check_objects(root):
    files, _ = check_files(root, "objects")
    parsed = {}
    for name, data in files.items():
        fn = parser_for(name)
        if fn is None:
            continue
        try:
            parsed[name] = fn(data)
        except ValueError as e:
            fail(f"objects/{name}: {e}")
    # Identity vector: the ed25519 form is 3 + 32 bytes.
    ident = files["identity_ed25519"]
    expect(ident == b"\x01\x20\x00" + b"\xaa" * 32, "identity_ed25519 bytes")
    # Signing bytes of the commit and the remix vectors.
    for name in ("commit_0parent", "remix_2sources"):
        expect(
            name in parsed and parsed[name]["signing"] == files[name + "_signing_bytes"],
            f"objects/{name}: rebuilt signing bytes differ from {name}_signing_bytes.bin",
        )
    # Empty tree and chunked blob ids.
    expect(
        tree_id([]).hex() == "b29117ce9b3d66ba98cd0a57145400f0bf6fff8b5c27c4552d80a38446f27ef7",
        "empty tree id (SPEC-OBJECTS section 13.2)",
    )
    expect(
        files["empty_blob"] == b"\x01KOB1\x01\x00\x00\x00\x00",
        "empty blob bytes",
    )
    cb = parsed.get("chunked_blob_cs0_3chunks")
    expect(
        len(files["chunked_blob_cs0_3chunks"]) == manifest_len(3) == 142,
        "chunked blob length is 22 + 40 * 3 = 142",
    )
    return files, parsed, cb


def check_proof_ids(root, files, parsed, cb):
    proofs = os.path.join(root, "proofs")
    seen = {}
    for fn in os.listdir(proofs):
        if not fn.endswith(".json"):
            continue
        meta = json.load(open(os.path.join(proofs, fn)))
        seen[meta["name"]] = meta
    single = seen["tree_single_file_pos0"]["object_id_hex"]
    expect(
        tree_id(parsed["tree_single_file"]["entries"]).hex() == single,
        "tree_single_file id differs from the proof vector",
    )
    chunk = seen["chunked_blob_cs0_3chunks_pos1"]["object_id_hex"]
    if cb is None:
        return  # the manifest did not decode; that is already a failure
    expect(
        chunked_id(cb["total"], cb["chunk_size"], cb["chunks"], cb["ends"]).hex() == chunk,
        "chunked_blob_cs0_3chunks id differs from the proof vector",
    )


def check_tags(root):
    files, man = check_files(root, "tags")
    for name in ("tag_annotated", "tag_signed"):
        try:
            p = parse_tag(files[name])
        except ValueError as e:
            fail(f"tags/{name}: {e}")
            continue
        if name == "tag_annotated":
            expect(
                p["signing"] == files["tag_annotated_signing_bytes"],
                "tag_annotated: rebuilt signing bytes differ",
            )
            expect(p["signature"] == bytes(64), "tag_annotated signature is not all zero")
            h = domain_digest(TAG_DOMAIN, p["signing"])
            expect(
                h.hex() == man["tag_annotated_signing_hash"],
                "tag_annotated_signing_hash differs from MANIFEST.txt",
            )
        else:
            h = domain_digest(TAG_DOMAIN, p["signing"])
            pub, sig = ed25519_sign(bytes([7]) * 32, h)
            expect(p["signer"] == pub, "tag_signed: signer is not the key of seed [0x07; 32]")
            expect(p["signature"] == sig, "tag_signed: embedded signature differs")
            expect(
                sig.hex() == man["tag_signed_signature"],
                "tag_signed_signature differs from MANIFEST.txt",
            )


def fastcdc_vectors():
    """The boundary vectors of SPEC-FASTCDC section 8: (name, masks, input)."""
    v1, v2 = v1_masks(), v2_masks()
    mib = splitmix_bytes(0xA5A5_F00D_DEAD_BEEF, 1024 * 1024)
    k256 = splitmix_bytes(0xCAFE_BABE_1234_5678, 256 * 1024)
    runs = runs_stream()
    return [
        ("fastcdc_boundaries_1mib", v1, mib),
        ("fastcdc_boundaries_256k", v1, k256),
        ("fastcdc_boundaries_runs", v1, runs),
        ("fastcdc_v2_boundaries_1mib", v2, mib),
        ("fastcdc_v2_boundaries_256k", v2, k256),
        ("fastcdc_v2_boundaries_runs", v2, runs),
    ]


def fastcdc_v2_manifest(gear):
    """SPEC-FASTCDC section 8, vector 14: the v2 manifest of a 2 MiB
    splitmix64 stream, and its object id."""
    data = splitmix_bytes(0x4B49_5446_4344_4332, 2 * 1024 * 1024)
    chunks, ends, start = [], [], 0
    for end in boundaries(data, gear, v2_masks()):
        chunks.append(blob_id(data[start:end]))
        ends.append(end)
        start = end
    body = build_manifest(len(data), FASTCDC_V2_CHUNK_SIZE, list(zip(chunks, ends)))
    return body, chunked_id(len(data), FASTCDC_V2_CHUNK_SIZE, chunks, ends)


def check_fastcdc(root):
    files, man = check_files(root, "fastcdc")
    gear = gear_table()
    expect(len(set(gear)) == 256 and 0 not in gear, "gear table is not unique and non-zero")
    expect(
        blake3(b"".join(g.to_bytes(8, "little") for g in gear)).hex()
        == "2c8b776fb264316106cef8f45ebd30bf6c2cb7a704c095ce9adc4b4b84ab75ff",
        "gear table digest (SPEC-FASTCDC section 8, vector 1)",
    )
    expect(v2_masks() == (0x0000_AB55_AB55_0000, 0x0000_552A_552A_0000), "v2 masks")
    for name, masks, data in fastcdc_vectors():
        want = json.loads(files[name])
        got = boundaries(data, gear, masks)
        expect(got == want, f"{name}: boundaries {got} != {want}")
    expect(
        boundaries(runs_stream(), gear, v1_masks()) != boundaries(runs_stream(), gear, v2_masks()),
        "v1 and v2 must cut the runs stream differently",
    )
    body, oid = fastcdc_v2_manifest(gear)
    expect(files["fastcdc_v2_manifest_2mib"] == body, "fastcdc_v2_manifest_2mib bytes differ")
    expect(parse_chunked(body)["chunk_size"] == FASTCDC_V2_CHUNK_SIZE, "v2 manifest chunk_size")
    expect(
        man.get("fastcdc_v2_manifest_2mib_object_id") == oid.hex(),
        "fastcdc_v2_manifest_2mib object id differs from MANIFEST.txt",
    )


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: objects_ref.py <rust/tests/golden>")
    root = sys.argv[1]
    # Reference BLAKE3 against the published hash of the empty input.
    expect(
        blake3(b"").hex() == "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        "BLAKE3 of the empty input",
    )
    # Domain lengths from SPEC-SIGNING section 2.
    expect(
        (len(COMMIT_DOMAIN), len(REMIX_DOMAIN), len(TAG_DOMAIN)) == (11, 10, 8),
        "signing domain lengths",
    )
    check_name_rules()
    check_chunked_rules()
    files, parsed, cb = check_objects(root)
    check_proof_ids(root, files, parsed, cb)
    check_tags(root)
    check_fastcdc(root)
    if FAILURES:
        sys.exit(1)
    print("OK")


if __name__ == "__main__":
    main()

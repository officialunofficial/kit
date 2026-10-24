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
# SPEC-OBJECTS, SPEC-SIGNING, SPEC-MERKLE-OBJECTS and SPEC-FASTCDC. BLAKE3
# comes from the pure-Python transcription in blake3_subtree_ref.py. Ed25519
# signing and the splitmix64 stream are written here from RFC 8032 and the
# splitmix64 definition.
#
# Checks:
#   * every .bin file against the size and BLAKE3 in its .json sidecar and in
#     MANIFEST.txt;
#   * every object parsed strictly: prologue, field order, sort order, name
#     rules, and no trailing byte;
#   * the signing bytes of the commit, remix and tag vectors rebuilt from the
#     parsed fields, with the domain string and the u16 length prefix of
#     SPEC-SIGNING;
#   * the tag signing hash and the signed tag signature from seed [0x07; 32];
#   * the ids of the empty tree, the single-file tree and the three-chunk
#     chunked blob, which pin the "kit.tree" and "kit.chunked" domains;
#   * the FastCDC gear table and the chunk boundaries of both pinned streams.
#
# Usage:
#   python3 scripts/golden/objects_ref.py rust/tests/golden
#
# Exit 0 and print "OK" when every check passes; exit 1 otherwise.

import hashlib
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from blake3_subtree_ref import blake3  # noqa: E402

PROLOGUE_MAGIC = b"MKT1"
SCHEMA_VERSION = 1
BLOB, TREE, COMMIT, REMIX, CHUNKED, DELTA, TAG = 1, 2, 3, 4, 5, 6, 7

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
    if r.u8() != SCHEMA_VERSION:
        raise ValueError("bad schema version")


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
    if any(b in (0, 0x2F, 0x5C) for b in name):
        raise ValueError("forbidden byte")
    if name in (b".", b".."):
        raise ValueError("dot name")
    if name[-1] in (0x2E, 0x20):
        raise ValueError("trailing dot or space")
    if name.lower() in (b".kit", b".git"):
        raise ValueError("reserved name")
    stem = name.split(b".", 1)[0].upper()
    if stem.decode("latin-1") in RESERVED:
        raise ValueError("device name")


def parse_blob(data):
    r = Reader(data)
    prologue(r, BLOB)
    n = r.u32()
    r.take(n)
    r.end()
    return {}


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


def parse_chunked(data):
    r = Reader(data)
    prologue(r, CHUNKED)
    total = r.u64()
    chunk_size = r.u32()
    count = r.u32()
    if count > 1_000_000:
        raise ValueError("too many chunks")
    chunks = [r.take(32) for _ in range(count)]
    r.end()
    return {"total": total, "chunk_size": chunk_size, "chunks": chunks}


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


def chunked_id(total, chunk_size, chunks):
    meta = domain_digest(
        b"kit-cblob-meta-v1", struct.pack("<Q", total) + struct.pack("<I", chunk_size)
    )
    return domain_digest(CHUNKED_DOMAIN, bmt_root([meta] + list(chunks)))


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


def fastcdc_cut(data, gear, min_size=16 * 1024, avg_size=64 * 1024, max_size=256 * 1024):
    """SPEC-FASTCDC section 5."""
    if len(data) <= min_size:
        return len(data)
    bits = avg_size.bit_length() - 1
    mask = (1 << bits) - 1
    mask_s = mask | (mask << 1)
    mask_l = mask >> 1
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


def boundaries(data, gear):
    ends, pos = [], 0
    while pos < len(data):
        pos += fastcdc_cut(data[pos:], gear)
        ends.append(pos)
    return ends


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
            parsed[name]["signing"] == files[name + "_signing_bytes"],
            f"objects/{name}: rebuilt signing bytes differ from {name}_signing_bytes.bin",
        )
    # Empty tree and chunked blob ids.
    expect(
        tree_id([]).hex() == "b29117ce9b3d66ba98cd0a57145400f0bf6fff8b5c27c4552d80a38446f27ef7",
        "empty tree id (SPEC-OBJECTS section 13.2)",
    )
    expect(
        files["empty_blob"] == b"\x01MKT1\x01\x00\x00\x00\x00",
        "empty blob bytes",
    )
    cb = parsed["chunked_blob_cs0_3chunks"]
    expect(len(files["chunked_blob_cs0_3chunks"]) == 118, "chunked blob length is 118")
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
    expect(
        chunked_id(cb["total"], cb["chunk_size"], cb["chunks"]).hex() == chunk,
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


def check_fastcdc(root):
    files, _ = check_files(root, "fastcdc")
    gear = gear_table()
    expect(len(set(gear)) == 256 and 0 not in gear, "gear table is not unique and non-zero")
    for name, seed, size in (
        ("fastcdc_boundaries_1mib", 0xA5A5_F00D_DEAD_BEEF, 1024 * 1024),
        ("fastcdc_boundaries_256k", 0xCAFE_BABE_1234_5678, 256 * 1024),
    ):
        want = json.loads(files[name])
        got = boundaries(splitmix_bytes(seed, size), gear)
        expect(got == want, f"{name}: boundaries {got} != {want}")


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
    files, parsed, cb = check_objects(root)
    check_proof_ids(root, files, parsed, cb)
    check_tags(root)
    check_fastcdc(root)
    if FAILURES:
        sys.exit(1)
    print("OK")


if __name__ == "__main__":
    main()

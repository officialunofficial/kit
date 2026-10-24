#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Independent reference check of the git bridge golden vectors:
#   rust/tests/golden/git-bridge/   (kit to git export, SPEC-GIT-BRIDGE)
#   rust/tests/golden/git-import/   (git to kit import, SPEC-GIT-IMPORT)
#
# The check shares no code with the Rust crates. It reads only the two specs,
# SPEC-OBJECTS, SPEC-SIGNING and SPEC-FASTCDC. SHA-1 comes from hashlib; BLAKE3,
# the object parsers, Ed25519 signing and FastCDC come from objects_ref.py, and
# Ed25519 verification from disclosure_ref.py.
#
# Export vectors. For each vector the check:
#   * recomputes the git object id from the git bytes and the kit object id
#     from the kit bytes, and compares both with MANIFEST.txt;
#   * rebuilds the git bytes from the kit bytes with the mapping of
#     SPEC-GIT-BRIDGE sections 3 to 7 and compares them;
#   * verifies the carried Ed25519 signature of each commit and tag;
#   * regenerates the 1.2 MB chunked blob from its pinned content, chunks it
#     with FastCDC and compares the manifest bytes and both ids.
#
# Import vectors. For each vector the check:
#   * recomputes the git id from the git bytes and the kit id from the kit bytes;
#   * rebuilds the kit commit or tag from the git bytes with the mapping of
#     SPEC-GIT-IMPORT section 3, signs it with the pinned importer seed
#     [0x42; 32], and compares every byte, including the signature;
#   * regenerates the big blob and compares both ids.
# The translated tree and parent ids come from the vector itself, because the
# vectors do not ship the tree objects. The check compares them with the other
# vectors where it can.
#
# The refusal lines in git-import/REFUSALS.txt name typed errors of one
# implementation and carry no source bytes. They are outside this check.
#
# Usage:
#   python3 -I -B scripts/golden/git_bridge_ref.py rust/tests/golden
#
# Exit 0 and print "OK" when every check passes; exit 1 otherwise.

import base64
import hashlib
import json
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import closure_ref as c  # noqa: E402
import disclosure_ref as d  # noqa: E402
import objects_ref as o  # noqa: E402
from objects_ref import blake3, domain_digest, expect  # noqa: E402

BRIDGE_EMAIL = b"bridge@kit.invalid"
EMPTY_GIT_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
IMPORT_SEED = bytes([0x42]) * 32
GIT_MODE = {1: b"100644", 2: b"40000", 3: b"120000", 4: b"100755"}
KIT_MODE = {b"100644": 1, b"40000": 2, b"120000": 3, b"100755": 4}
BIG = b"".join(struct.pack("<I", i) for i in range(300_000))


def sha1_hex(data):
    return hashlib.sha1(data).hexdigest()


def frame(kind, body):
    return kind + b" " + str(len(body)).encode() + b"\x00" + body


def b64(data):
    return base64.b64encode(data).decode().rstrip("=").encode()


# ------------------------------------------------------------ kit side


def read_identity(r):
    kind = r.u8()
    payload = r.take(r.u16())
    return kind, payload


def identity_bytes(kind, payload):
    return bytes([kind]) + struct.pack("<H", len(payload)) + payload


def read_commit(data):
    r = o.Reader(data)
    r.take(6)
    f = {"tree": r.take(32), "parents": [r.take(32) for _ in range(r.u32())]}
    f["author"] = read_identity(r)
    f["message"] = r.take(r.u32())
    f["timestamp"] = r.u64()
    f["signer"] = r.take(32)
    f["message_hash"] = r.take(32)
    f["content_digest"] = r.take(32)
    f["signature"] = r.take(64)
    r.end()
    return f


def read_tag(data):
    r = o.Reader(data)
    r.take(6)
    f = {"target": r.take(32), "target_type": r.u8()}
    f["name"] = r.take(r.u32())
    f["tagger"] = read_identity(r)
    f["message"] = r.take(r.u32())
    f["timestamp"] = r.u64()
    f["signer"] = r.take(32)
    f["signature"] = r.take(64)
    r.end()
    return f


# ---------------------------------------------------------- export side


def person_name(kind, payload):
    """SPEC-GIT-BRIDGE section 6.2."""
    if kind == 1:
        return b"kit:ed25519:" + payload.hex().encode()
    if kind == 2 and not any(b in payload for b in b"<>\n\x00"):
        return b"did:key:" + payload
    try:
        payload.decode("utf-8")
        plain = not any(b in (0x3C, 0x3E) or b < 0x20 or b == 0x7F for b in payload)
    except UnicodeDecodeError:
        plain = False
    return payload if plain else b"kit:opaque:" + b64(payload)


def person_line(kind, payload, timestamp):
    return person_name(kind, payload) + b" <" + BRIDGE_EMAIL + b"> " + str(timestamp).encode() + b" +0000"


def export_tree(data, shas):
    entries = o.parse_tree(data)["entries"]
    keyed = []
    for name, mode, child in entries:
        git_mode = GIT_MODE[mode]
        key = name + b"/" if mode == 2 else name
        keyed.append((key, git_mode + b" " + name + b"\x00" + bytes.fromhex(shas[child])))
    return b"".join(entry for _, entry in sorted(keyed))


def git_tree_ids(framed):
    """Map entry name to the 40-hex id of a framed git tree."""
    _, body = split_git(framed)
    out, pos = {}, 0
    while pos < len(body):
        end = body.index(b"\x00", pos)
        _, _, entry_name = body[pos:end].partition(b" ")
        out[entry_name] = body[end + 1 : end + 21].hex()
        pos = end + 21
    return out


def export_commit(data, shas):
    f = read_commit(data)
    name_line = person_line(*f["author"], f["timestamp"])
    out = b"tree " + shas[f["tree"]].encode() + b"\n"
    for p in f["parents"]:
        out += b"parent " + shas[p].encode() + b"\n"
    out += b"author " + name_line + b"\ncommitter " + name_line + b"\n"
    out += b"kit-schema 1\n"
    out += b"kit-author %02x:" % f["author"][0] + b64(f["author"][1]) + b"\n"
    out += b"kit-signer " + f["signer"].hex().encode() + b"\n"
    out += b"kit-signature " + f["signature"].hex().encode() + b"\n"
    out += b"kit-tree " + f["tree"].hex().encode() + b"\n"
    for p in f["parents"]:
        out += b"kit-parent " + p.hex().encode() + b"\n"
    if f["message_hash"] != bytes(32):
        out += b"kit-message-hash " + f["message_hash"].hex().encode() + b"\n"
    if f["content_digest"] != bytes(32):
        out += b"kit-content-digest " + f["content_digest"].hex().encode() + b"\n"
    return out + b"\n" + f["message"]


GIT_TYPE = {o.BLOB: b"blob", o.CHUNKED: b"blob", o.TREE: b"tree", o.COMMIT: b"commit", o.TAG: b"tag"}


def export_tag(data, shas):
    f = read_tag(data)
    out = b"object " + shas[f["target"]].encode() + b"\n"
    out += b"type " + GIT_TYPE[f["target_type"]] + b"\ntag " + f["name"] + b"\n"
    out += b"tagger " + person_line(*f["tagger"], f["timestamp"]) + b"\n"
    out += b"kit-schema 1\n"
    out += b"kit-tagger %02x:" % f["tagger"][0] + b64(f["tagger"][1]) + b"\n"
    out += b"kit-signer " + f["signer"].hex().encode() + b"\n"
    out += b"kit-signature " + f["signature"].hex().encode() + b"\n"
    out += b"kit-target " + f["target"].hex().encode() + b"\n"
    out += b"kit-target-type %02x\n" % f["target_type"]
    return out + b"\n" + f["message"]


def signature_ok(data):
    parsed = o.parse_commit(data) if data[0] == o.COMMIT else o.parse_tag(data)
    signing = parsed["signing"]
    # An all-zero signature marks an unsigned object (SPEC-GIT-BRIDGE section 7).
    if parsed["signature"] == bytes(64):
        return None
    return d.ed25519_verify(signing[-32:], domain_digest(parsed["domain"], signing), parsed["signature"])


def read_vectors(root, directory):
    vectors = {}
    for fn in sorted(os.listdir(os.path.join(root, directory))):
        if fn.endswith(".json"):
            meta = json.loads(o.read(root, directory, fn))
            vectors[meta["name"]] = meta
    return vectors


def manifest_ids(root, directory):
    ids = {}
    for line in o.read(root, directory, "MANIFEST.txt").decode().splitlines():
        if line and not line.startswith("#"):
            name, a, b = line.split()
            ids[name] = (a, b)
    return ids


def chunked_manifest():
    """The pinned content, chunked with FastCDC (SPEC-FASTCDC), and its manifest."""
    gear = o.gear_table()
    chunks, pos = [], 0
    for end in o.boundaries(BIG, gear):
        data = BIG[pos:end]
        chunks.append(blake3(b"\x01MKT1\x01" + struct.pack("<I", len(data)) + data))
        pos = end
    body = b"\x05MKT1\x01" + struct.pack("<QII", len(BIG), 0, len(chunks)) + b"".join(chunks)
    return body, o.chunked_id(len(BIG), 0, chunks)


def check_export(root):
    d_name = "git-bridge"
    vectors = read_vectors(root, d_name)
    man = manifest_ids(root, d_name)
    kit, git, shas = {}, {}, {}
    for name, meta in vectors.items():
        kit[name] = o.read(root, d_name, name + ".kit.bin")
        kid = c.object_id(kit[name])
        expect(kid.hex() == meta["kit_id"] == man[name][0], f"export {name}: kit id")
        shas[kid] = meta["git_sha1"]
        expect(man[name][1] == meta["git_sha1"], f"export {name}: MANIFEST.txt git id")
    for name, meta in vectors.items():
        if name == "chunked_blob":
            body, kid = chunked_manifest()
            expect(body == kit[name], "export chunked_blob: manifest bytes")
            expect(kid.hex() == meta["kit_id"], "export chunked_blob: kit id")
            expect(sha1_hex(frame(b"blob", BIG)) == meta["git_sha1"], "export chunked_blob: git id")
            continue
        git[name] = o.read(root, d_name, name + ".git.bin")
        expect(sha1_hex(git[name]) == meta["git_sha1"], f"export {name}: git id")
        kind = kit[name][0]
        want = {
            o.BLOB: lambda: frame(b"blob", kit[name][10:]),
            o.TREE: lambda: frame(b"tree", export_tree(kit[name], shas_text)),
            o.COMMIT: lambda: frame(b"commit", export_commit(kit[name], shas_text)),
            o.TAG: lambda: frame(b"tag", export_tag(kit[name], shas_text)),
        }[kind]
        shas_text = {k: v for k, v in shas.items()}
        if kind == o.TREE:
            # A child that no vector holds keeps the sha1 that the git bytes name.
            named = git_tree_ids(git[name])
            for entry_name, _, child in o.parse_tree(kit[name])["entries"]:
                shas_text.setdefault(child, named[entry_name])
        # A parent that no vector holds keeps the sha1 that the git bytes name.
        for parent in (read_commit(kit[name])["parents"] if kind == o.COMMIT else []):
            if parent not in shas_text:
                line = [l for l in git[name].split(b"\n") if l.startswith(b"parent ")]
                shas_text[parent] = line[read_commit(kit[name])["parents"].index(parent)][7:].decode()
        expect(want() == git[name], f"export {name}: rebuilt git bytes differ")
        if kind in (o.COMMIT, o.TAG):
            ok = signature_ok(kit[name])
            expect(ok in (True, None), f"export {name}: carried signature does not verify")
    # The empty tree has the fixed git id of SPEC-GIT-BRIDGE section 5.
    expect(sha1_hex(frame(b"tree", b"")) == EMPTY_GIT_TREE, "empty git tree id")
    # kit order and git order differ for foo and foo.txt (section 13.4).
    names = [e[0] for e in o.parse_tree(kit["tree_divergent_sort"])["entries"]]
    expect(names == [b"foo", b"foo.txt"], "divergent tree: kit order")
    return len(vectors)


# ---------------------------------------------------------- import side


def split_git(data):
    """Return (kind, body) after checking the frame."""
    head, _, body = data.partition(b"\x00")
    kind, _, size = head.partition(b" ")
    if int(size) != len(body):
        raise ValueError("git frame length")
    return kind, body


def split_headers(body):
    head, sep, message = body.partition(b"\n\n")
    if not sep:
        raise ValueError("no blank line")
    lines = head.split(b"\n")
    headers = []
    for line in lines:
        if line.startswith(b" "):
            headers[-1][1] += b"\n" + line[1:]
        else:
            key, _, value = line.partition(b" ")
            headers.append([key, value])
    return headers, message


def person(line):
    """SPEC-GIT-IMPORT section 3.2. Returns (identity slice, timestamp)."""
    lt = line.find(b"<")
    gt = line.rfind(b">") if lt >= 0 else -1
    if lt >= 0 and gt > lt:
        ident = line[: gt + 1]
        m = re.match(rb" (\d+) [+-]\d{4}$", line[gt + 1 :])
    else:
        m = re.search(rb" (\d+) [+-]\d{4}$", line)
        if not m:
            raise ValueError("no timestamp")
        ident = line[: m.start()]
    if not m:
        raise ValueError("no timestamp")
    return ident, int(m.group(1))


def import_sign(domain, signing_prefix):
    sig = o.ed25519_sign(IMPORT_SEED, domain_digest(domain, signing_prefix))[1]
    return sig


def import_commit(framed, tree_kit, parents_kit):
    kind, body = split_git(framed)
    headers, message = split_headers(body)
    author = next(v for k, v in headers if k == b"author")
    committer = next(v for k, v in headers if k == b"committer")
    ident, _ = person(author)
    _, stamp = person(committer)
    pub = o.ed25519_sign(IMPORT_SEED, b"")[0]
    prefix = (
        b"\x03MKT1\x01"
        + tree_kit
        + struct.pack("<I", len(parents_kit))
        + b"".join(parents_kit)
        + identity_bytes(3, ident)
        + struct.pack("<I", len(message))
        + message
        + struct.pack("<Q", stamp)
        + pub
    )
    sig = import_sign(o.COMMIT_DOMAIN, prefix)
    return prefix + bytes(32) + blake3(framed) + sig


def import_tag(framed, target_kit, target_type):
    kind, body = split_git(framed)
    headers, message = split_headers(body)
    name = next(v for k, v in headers if k == b"tag")
    tagger = [v for k, v in headers if k == b"tagger"]
    if tagger:
        ident, stamp = person(tagger[0])
    else:
        ident, stamp = b"(no tagger)", 0
    pub = o.ed25519_sign(IMPORT_SEED, b"")[0]
    prefix = (
        b"\x07MKT1\x01"
        + target_kit
        + bytes([target_type])
        + struct.pack("<I", len(name))
        + name
        + identity_bytes(3, ident)
        + struct.pack("<I", len(message))
        + message
        + struct.pack("<Q", stamp)
        + pub
    )
    return prefix + import_sign(o.TAG_DOMAIN, prefix)


def check_import(root):
    d_name = "git-import"
    vectors = read_vectors(root, d_name)
    man = manifest_ids(root, d_name)
    kit_by_git = {}
    for name, meta in vectors.items():
        expect(man[name] == (meta["git_sha1"], meta["kit_id"]), f"import {name}: MANIFEST.txt ids")
        if name == "big_blob":
            continue
        kit_by_git[meta["git_sha1"]] = bytes.fromhex(meta["kit_id"])
    for name, meta in vectors.items():
        if name == "big_blob":
            _, kid = chunked_manifest()
            expect(kid.hex() == meta["kit_id"], "import big_blob: kit id")
            expect(sha1_hex(frame(b"blob", BIG)) == meta["git_sha1"], "import big_blob: git id")
            continue
        git_kind = name.split("_")[0].encode()
        framed = frame(git_kind, o.read(root, d_name, name + ".git.bin"))
        kit = o.read(root, d_name, name + ".kit.bin")
        expect(sha1_hex(framed) == meta["git_sha1"], f"import {name}: git id")
        expect(c.object_id(kit).hex() == meta["kit_id"], f"import {name}: kit id")
        kind, body = split_git(framed)
        headers, _ = split_headers(body)
        if kind == b"commit":
            fields = read_commit(kit)
            tree_git = next(v for k, v in headers if k == b"tree").decode()
            if tree_git == EMPTY_GIT_TREE:
                expect(fields["tree"].hex() == "b29117ce9b3d66ba98cd0a57145400f0bf6fff8b5c27c4552d80a38446f27ef7", f"import {name}: empty tree id")
            parents_git = [v.decode() for k, v in headers if k == b"parent"]
            for pg, pk in zip(parents_git, fields["parents"]):
                if pg in kit_by_git:
                    expect(kit_by_git[pg] == pk, f"import {name}: parent id")
            expect(len(parents_git) == len(fields["parents"]), f"import {name}: parent count")
            want = import_commit(framed, fields["tree"], fields["parents"])
        elif kind == b"tag":
            fields = read_tag(kit)
            target_git = next(v for k, v in headers if k == b"object").decode()
            if target_git in kit_by_git:
                expect(kit_by_git[target_git] == fields["target"], f"import {name}: target id")
            want = import_tag(framed, fields["target"], fields["target_type"])
        else:
            o.fail(f"import {name}: unexpected git type {kind!r}")
            continue
        expect(want == kit, f"import {name}: rebuilt kit bytes differ")
    return len(vectors)


def check_tagger_less():
    """The tagger-less tag of golden_import.rs, rebuilt from its git objects."""
    content = b"vector content\n"
    blob_kit = b"\x01MKT1\x01" + struct.pack("<I", len(content)) + content
    blob_sha = hashlib.sha1(frame(b"blob", content)).digest()
    entry = (b"file.txt", 1, blake3(blob_kit))
    tree_id = o.tree_id([entry])
    tree_body = b"100644 file.txt\x00" + blob_sha
    tree_sha = sha1_hex(frame(b"tree", tree_body))
    commit_body = (
        b"tree " + tree_sha.encode() + b"\nauthor A <a@x> 1600000000 +0000\n"
        b"committer A <a@x> 1600000000 +0000\n\ntagged commit\n"
    )
    commit_framed = frame(b"commit", commit_body)
    commit_kit = import_commit(commit_framed, tree_id, [])
    tag_body = (
        b"object " + sha1_hex(commit_framed).encode() + b"\ntype commit\ntag v0.0.1\n\nhistoric tagger-less tag\n"
    )
    tag_kit = import_tag(frame(b"tag", tag_body), blake3(commit_kit), o.COMMIT)
    expect(
        blake3(tag_kit).hex() == "d14450517907902cd49c2cd0ad707178346ae98a0ad7d64d4bfe6a6c88605372",
        "import tagger-less tag id",
    )


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: git_bridge_ref.py <rust/tests/golden>")
    root = sys.argv[1]
    check_export(root)
    check_import(root)
    check_tagger_less()
    if o.FAILURES:
        sys.exit(1)
    print("OK")


if __name__ == "__main__":
    main()

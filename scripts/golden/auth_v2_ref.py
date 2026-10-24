#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Independent reference check of the auth v2 envelope golden vectors:
#   rust/tests/golden/auth-v2/read.json
#   rust/tests/golden/auth-v2/unary.json
# The part-upload vector, part.json, is checked by blake3_subtree_ref.py.
#
# The check shares no code with the Rust crates. It reads only
# SPEC-TRANSPORT-CONNECT section 7.1 ("Auth v2 contract"). BLAKE3 comes from the
# pure-Python transcription in blake3_subtree_ref.py. Ed25519 signing and
# verification come from objects_ref.py and disclosure_ref.py (RFC 8032).
#
# For each vector the check:
#   * rebuilds the eight-field canonical string and compares it;
#   * checks the field rules: ASCII ranges, length limits, lowercase hex widths
#     and decimal spelling;
#   * recomputes the body digest, the commitment and the signing digest;
#   * verifies the Ed25519 signature over the signing digest, and for a vector
#     with a seed also signs the digest and compares the signature;
#   * decodes the signed read bodies by hand from the protobuf and gRPC framing.
#
# Usage:
#   python3 -I -B scripts/golden/auth_v2_ref.py rust/tests/golden
#
# Exit 0 and print "OK" when every check passes; exit 1 otherwise.

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import disclosure_ref as d  # noqa: E402
import objects_ref as o  # noqa: E402
from objects_ref import blake3, expect  # noqa: E402

D = "auth-v2"
DECIMAL = re.compile(r"0|[1-9][0-9]*")
HEX64 = re.compile(r"[0-9a-f]{64}")
HEX128 = re.compile(r"[0-9a-f]{128}")


def printable(text, limit):
    raw = text.encode("ascii")
    return 0 < len(raw) <= limit and all(0x21 <= b <= 0x7E for b in raw)


def canonical(v):
    return "\n".join(
        [
            "kit-write:v2",
            v["audience"],
            v["repository"],
            v["procedure"],
            v["commitment"],
            str(v["created_at"]),
            str(v["expires_at"]),
            v["nonce"],
        ]
    )


def check_vector(name, v, body):
    expect(printable(v["audience"], 512), f"{name}: audience bytes")
    expect(printable(v["repository"], 255), f"{name}: repository bytes")
    expect(printable(v["procedure"], 512) and v["procedure"].startswith("/"), f"{name}: procedure bytes")
    expect(HEX64.fullmatch(v["nonce"]) is not None, f"{name}: nonce width")
    expect(HEX64.fullmatch(v["public_key"]) is not None, f"{name}: public key width")
    expect(HEX128.fullmatch(v["signature"]) is not None, f"{name}: signature width")
    for field in ("created_at", "expires_at"):
        expect(DECIMAL.fullmatch(str(v[field])) is not None and 0 <= v[field] < 1 << 63, f"{name}: {field}")
    digest = blake3(body).hex()
    expect(v["body_digest"] == digest, f"{name}: body digest")
    expect(v["commitment"] == "body:" + digest, f"{name}: commitment")
    text = canonical(v)
    expect(text == v["canonical"], f"{name}: canonical string")
    signing = blake3(text.encode())
    expect(signing.hex() == v["signing_digest"], f"{name}: signing digest")
    public = bytes.fromhex(v["public_key"])
    expect(
        d.ed25519_verify(public, signing, bytes.fromhex(v["signature"])),
        f"{name}: signature does not verify",
    )
    if "seed" in v:
        pub, sig = o.ed25519_sign(bytes.fromhex(v["seed"]), signing)
        expect(pub == public, f"{name}: public key differs from the seed")
        expect(sig.hex() == v["signature"], f"{name}: signature differs from the seed signature")


def read_body_ok(procedure, body):
    """The two signed read bodies of the table (protobuf by hand)."""
    if procedure.endswith("/ReadRef"):
        name = b"refs/heads/main"
        return body == b"\x0a" + bytes([len(name)]) + name
    message = b"\x0a\x20" + b"\xcd" * 32
    return body == b"\x00" + len(message).to_bytes(4, "big") + message


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: auth_v2_ref.py <rust/tests/golden>")
    root = sys.argv[1]
    reads = json.loads(o.read(root, D, "read.json"))
    expect(len(reads) == 2, "read.json holds two vectors")
    for i, v in enumerate(reads):
        body = bytes.fromhex(v["body_hex"])
        expect(read_body_ok(v["procedure"], body), f"read {i}: body bytes")
        check_vector(f"read {i}", v, body)
    unary = json.loads(o.read(root, D, "unary.json"))
    expect(unary["version"] == 2, "unary: version")
    check_vector("unary", unary, unary["body"].encode())
    if o.FAILURES:
        sys.exit(1)
    print("OK")


if __name__ == "__main__":
    main()

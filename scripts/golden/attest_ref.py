#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Independent reference check of the attestation golden vectors:
#   rust/tests/golden/attest/
#
# The check shares no code with the Rust crates. It reads only
# SPEC-ATTESTATIONS (the in-toto Statement v1 shape, the JSON canonical form,
# and the DSSE envelope with its pre-authentication encoding). BLAKE3 comes from
# objects_ref.py; SHA-256 from hashlib; Ed25519 from objects_ref.py and
# disclosure_ref.py (RFC 8032).
#
# The pinned inputs are the ASCII commit bytes
# "pretend-serialised-commit-bytes-for-attest-golden-v1", the predicate type
# "https://example.com/predicate/v1", the empty predicate "{}", and the signing
# seed [0xAB; 32].
#
# The check:
#   * rebuilds the Statement from the inputs with sorted keys and no spacing,
#     and compares the bytes;
#   * decodes the envelope strictly (padded base64, one signature, canonical key
#     order and no spacing) and compares the payload with the Statement;
#   * checks the key id, which is "blake3:" and the BLAKE3 digest of the public
#     key, and verifies the Ed25519 signature over the DSSE pre-authentication
#     encoding;
#   * signs the encoding with the seed and compares the signature.
#
# Usage:
#   python3 -I -B scripts/golden/attest_ref.py rust/tests/golden
#
# Exit 0 and print "OK" when every check passes; exit 1 otherwise.

import base64
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import disclosure_ref as d  # noqa: E402
import objects_ref as o  # noqa: E402
from objects_ref import blake3, expect  # noqa: E402

D = "attest"
COMMIT_BYTES = b"pretend-serialised-commit-bytes-for-attest-golden-v1"
PREDICATE_TYPE = "https://example.com/predicate/v1"
SEED = bytes([0xAB]) * 32
PAYLOAD_TYPE = "application/vnd.in-toto+json"


def canonical(value):
    """JSON with sorted keys and no spacing. The pinned values are ASCII strings."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def pae(payload_type, payload):
    t = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: attest_ref.py <rust/tests/golden>")
    root = sys.argv[1]
    man = o.manifest(root, D)

    statement = canonical(
        {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {
                    "name": "commit",
                    "digest": {"blake3": blake3(COMMIT_BYTES).hex(), "sha256": hashlib.sha256(COMMIT_BYTES).hexdigest()},
                }
            ],
            "predicateType": PREDICATE_TYPE,
            "predicate": {},
        }
    )
    stored = o.read(root, D, "statement_basic.json")
    expect(stored == statement, "statement_basic.json differs from the rebuilt Statement")
    expect(man["statement_basic"] == blake3(stored).hex(), "MANIFEST.txt: statement_basic")

    raw = o.read(root, D, "envelope_basic.json")
    expect(man["envelope_basic"] == blake3(raw).hex(), "MANIFEST.txt: envelope_basic")
    envelope = json.loads(raw)
    expect(canonical(envelope) == raw, "envelope is not in canonical key order")
    expect(sorted(envelope) == ["payload", "payloadType", "signatures"], "envelope keys")
    expect(envelope["payloadType"] == PAYLOAD_TYPE, "payload type")
    payload = base64.b64decode(envelope["payload"], validate=True)
    expect(base64.b64encode(payload).decode() == envelope["payload"], "payload base64 is not padded standard")
    expect(payload == statement, "envelope payload differs from the Statement")
    expect(len(envelope["signatures"]) == 1, "one signature")
    sig_entry = envelope["signatures"][0]
    expect(sorted(sig_entry) == ["keyid", "sig"], "signature keys")
    signature = base64.b64decode(sig_entry["sig"], validate=True)
    expect(len(signature) == 64, "signature length")

    message = pae(PAYLOAD_TYPE, payload)
    public, expected = o.ed25519_sign(SEED, message)
    expect(sig_entry["keyid"] == "blake3:" + blake3(public).hex(), "key id")
    expect(d.ed25519_verify(public, message, signature), "signature does not verify")
    expect(signature == expected, "signature differs from the seed signature")
    if o.FAILURES:
        sys.exit(1)
    print("OK")


if __name__ == "__main__":
    main()

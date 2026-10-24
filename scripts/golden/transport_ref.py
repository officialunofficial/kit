#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Independent reference check of the transport golden vectors:
#   rust/tests/golden/transport/
#
# The check shares no code with the Rust crates. It reads only:
#   * SPEC-TRANSPORT-CONNECT section 5.1 and 7.4 and the message definitions in
#     proto/kit/transport/v1/transport.proto, for the two protobuf details and
#     the repository identity grammar;
#   * the AWS Signature Version 4 algorithm, for the S3 signing vectors. The
#     check uses only hashlib and hmac from the standard library.
#
# For each vector the check:
#   * compares every file with the BLAKE3 digest in MANIFEST.txt;
#   * decodes PendingVerification and AdmissionChallenge by hand from the
#     protobuf wire format and compares them with the JSON form and with the
#     base64 detail in the matching error document;
#   * applies the repository identity grammar to every identity in
#     repository-grammar.json;
#   * rebuilds the SigV4 canonical request, string to sign and signature from
#     the plain inputs and compares them with the recorded values.
#
# Usage:
#   python3 -I -B scripts/golden/transport_ref.py rust/tests/golden
#
# Exit 0 and print "OK" when every check passes; exit 1 otherwise.

import base64
import datetime
import hashlib
import hmac
import json
import os
import re
import sys
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import objects_ref as o  # noqa: E402
from objects_ref import blake3, expect  # noqa: E402

D = "transport"


# ------------------------------------------------------------- protobuf


def read_varint(data, pos):
    value = 0
    for shift in range(0, 70, 7):
        b = data[pos]
        pos += 1
        value |= (b & 0x7F) << shift
        if not b & 0x80:
            return value, pos
    raise ValueError("varint too long")


def fields(data):
    """Yield (number, wire type, value) for a message. Rejects unknown wire types."""
    pos = 0
    while pos < len(data):
        key, pos = read_varint(data, pos)
        number, wire = key >> 3, key & 7
        if wire == 0:
            value, pos = read_varint(data, pos)
        elif wire == 2:
            n, pos = read_varint(data, pos)
            if pos + n > len(data):
                raise ValueError("truncated field")
            value, pos = data[pos : pos + n], pos + n
        else:
            raise ValueError(f"unexpected wire type {wire}")
        yield number, wire, value


def decode_pending(data):
    out = {}
    for number, wire, value in fields(data):
        if number != 1 or wire != 0 or "retryAfterMs" in out:
            raise ValueError("unexpected field")
        out["retryAfterMs"] = value
    return out


def decode_challenge(data):
    out = {}
    for number, wire, value in fields(data):
        name = {1: "scheme", 2: "value"}.get(number)
        if name is None or wire != 2 or name in out:
            raise ValueError("unexpected field")
        out[name] = value.decode("utf-8")
    return out


def decode_admission(data):
    out = {"challenges": []}
    for number, wire, value in fields(data):
        if number == 1 and wire == 2:
            out["challenges"].append(decode_challenge(value))
        elif number == 2 and wire == 2 and "description" not in out:
            out["description"] = value.decode("utf-8")
        else:
            raise ValueError("unexpected field")
    if not 1 <= len(out["challenges"]) <= 8:
        raise ValueError("challenge count")
    return out


def b64(text):
    return base64.b64decode(text + "=" * (-len(text) % 4), validate=True)


def check_details(root):
    pending = o.read(root, D, "pending-verification.bin")
    expect(
        decode_pending(pending) == json.loads(o.read(root, D, "pending-verification.json")),
        "pending-verification.bin differs from its JSON form",
    )
    admission = o.read(root, D, "admission-challenge.bin")
    expect(
        decode_admission(admission) == json.loads(o.read(root, D, "admission-challenge.json")),
        "admission-challenge.bin differs from its JSON form",
    )
    for stem, kind, code, blob in (
        ("pending-verification", "kit.transport.v1.PendingVerification", "unavailable", pending),
        ("admission-challenge", "kit.transport.v1.AdmissionChallenge", "permission_denied", admission),
    ):
        err = json.loads(o.read(root, D, stem + "-error.json"))
        expect(err["code"] == code, f"{stem}-error.json: code")
        expect(len(err["details"]) == 1, f"{stem}-error.json: exactly one detail")
        detail = err["details"][0]
        expect(detail["type"] == kind, f"{stem}-error.json: detail type")
        expect(b64(detail["value"]) == blob, f"{stem}-error.json: detail bytes differ from the .bin file")


# ---------------------------------------------------- repository grammar

NAMESPACE = r"(?:ed25519-[0-9a-f]{64}|0x[0-9a-f]{40})"
NAME = r"[a-z0-9][a-z0-9._-]{0,99}"


def check_grammar(root):
    """SPEC-TRANSPORT-CONNECT section 7.4."""
    for case in json.loads(o.read(root, D, "repository-grammar.json")):
        ident = case["identity"]
        multi = re.fullmatch(NAMESPACE + "/" + NAME, ident, re.ASCII) is not None
        single = multi or re.fullmatch(NAME, ident, re.ASCII) is not None
        expect(single == case["single_ok"], f"grammar: single-repository result for {ident}")
        expect(multi == case["multi_ok"], f"grammar: multi-repository result for {ident}")
        if single:
            expect(len(ident) <= 173, f"grammar: {ident} is longer than 173 bytes")


# ----------------------------------------------------------------- sigv4


def hmac_sha256(key, msg):
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def sigv4(v):
    """AWS Signature Version 4 for a request with the three signed headers."""
    when = datetime.datetime.fromtimestamp(v["timestamp"], datetime.timezone.utc)
    amz_date = when.strftime("%Y%m%dT%H%M%SZ")
    day = when.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(v["payload"].encode()).hexdigest()
    host = urlsplit(v["endpoint"]).netloc
    canonical = "\n".join(
        [
            v["method"],
            v["path"],
            v["query"],
            f"host:{host}",
            f"x-amz-content-sha256:{payload_hash}",
            f"x-amz-date:{amz_date}",
            "",
            "host;x-amz-content-sha256;x-amz-date",
            payload_hash,
        ]
    )
    scope = f"{day}/{v['region']}/s3/aws4_request"
    to_sign = "\n".join(
        ["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical.encode()).hexdigest()]
    )
    key = hmac_sha256(("AWS4" + v["secret_access_key"]).encode(), day)
    for part in (v["region"], "s3", "aws4_request"):
        key = hmac_sha256(key, part)
    return canonical, to_sign, hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()


def check_sigv4(root):
    for stem in ("sigv4_basic", "sigv4_list_query"):
        v = json.loads(o.read(root, D, stem + ".bin"))
        canonical, to_sign, signature = sigv4(v)
        expect(canonical == v["canonical_request"], f"{stem}: canonical request")
        expect(to_sign == v["string_to_sign"], f"{stem}: string to sign")
        expect(signature == v["signature_hex"], f"{stem}: signature")


# ------------------------------------------------------------- manifest


def check_manifest(root):
    man = o.manifest(root, D)
    names = {}
    for fn in os.listdir(os.path.join(root, D)):
        if fn == "MANIFEST.txt":
            continue
        names[fn] = blake3(o.read(root, D, fn)).hex()
    for entry, digest in man.items():
        # A manifest entry is a full file name or the stem of a .bin file.
        fn = entry if entry in names else entry + ".bin"
        expect(names.get(fn) == digest, f"MANIFEST.txt: {entry} does not match {fn}")
    covered = {e if e in names else e + ".bin" for e in man}
    for fn in names:
        # Sidecars of .bin files are described by the `size` and `blake3` they hold.
        if fn not in covered and not fn.endswith(".json"):
            o.fail(f"{fn} is not in MANIFEST.txt")
        if fn.endswith(".json") and fn not in covered:
            meta = json.loads(o.read(root, D, fn))
            if isinstance(meta, dict) and "bin" in meta:
                data = o.read(root, D, meta["bin"])
                expect(
                    meta["size"] == len(data) and meta["blake3"] == blake3(data).hex(),
                    f"{fn}: size or blake3 differs from {meta['bin']}",
                )
            else:
                o.fail(f"{fn} is not in MANIFEST.txt")


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: transport_ref.py <rust/tests/golden>")
    root = sys.argv[1]
    check_manifest(root)
    check_details(root)
    check_grammar(root)
    check_sigv4(root)
    if o.FAILURES:
        sys.exit(1)
    print("OK")


if __name__ == "__main__":
    main()

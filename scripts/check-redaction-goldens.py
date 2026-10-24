#!/usr/bin/env python3
"""Verify SPEC-SERVER §14 fixtures without a server implementation.

The script needs only the Python standard library. BLAKE3 and Ed25519 come from
the reference modules in scripts/golden. The protobuf messages are small, so the
script encodes and decodes them by hand from proto/kit/transport/v1/transport.proto.
"""

import base64
import json
from pathlib import Path
import re
import struct
import sys


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts/golden"))
from blake3_subtree_ref import blake3  # noqa: E402
import disclosure_ref  # noqa: E402
import objects_ref  # noqa: E402
import transport_ref  # noqa: E402
GOLDEN = ROOT / "rust/tests/golden/redaction"
DETAIL_TYPE = "kit.transport.v1.RedactionNotice"
PAYLOAD_TYPE = "application/vnd.kit.redaction-notice.v1+json"


def canonical(value):
    # The pinned fixture uses ASCII keys and values and integer numbers,
    # the subset for which this encoding is JCS byte-for-byte.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


# Messages of proto/kit/transport/v1/transport.proto and proto/kit/common/v1/refs.proto
# that the fixtures use: (field number, JSON name, kind). A kind is "bytes", "string",
# "bool", a message name, or ("repeated", message name).
SCHEMA = {
    "RedactionNotice": [(1, "envelope", "bytes")],
    "RefEntry": [(1, "name", "string"), (2, "objectId", "bytes")],
    "RefRedaction": [(1, "ref", "string"), (2, "notice", "RedactionNotice")],
    "ReadRefResponse": [
        (1, "exists", "bool"),
        (2, "objectId", "bytes"),
        (3, "redactionNotices", ("repeated", "RedactionNotice")),
    ],
    "ListRefsResponse": [
        (1, "refs", ("repeated", "RefEntry")),
        (2, "nextPageToken", "string"),
        (3, "refRedactions", ("repeated", "RefRedaction")),
    ],
}


def proto_to_json(data, type_name):
    """Decode a message to its proto3 JSON form. Default values are omitted."""
    by_number = {number: (name, kind) for number, name, kind in SCHEMA[type_name]}
    out = {}
    for number, wire, value in transport_ref.fields(data):
        name, kind = by_number[number]
        repeated = isinstance(kind, tuple)
        inner = kind[1] if repeated else kind
        if inner == "bool":
            assert wire == 0 and value in (0, 1)
            decoded = bool(value)
        else:
            assert wire == 2
            if inner == "bytes":
                decoded = base64.b64encode(value).decode()
            elif inner == "string":
                decoded = value.decode("utf-8")
            else:
                decoded = proto_to_json(value, inner)
        if repeated:
            out.setdefault(name, []).append(decoded)
        else:
            assert name not in out
            out[name] = decoded
    return {name: out[name] for _, name, _ in SCHEMA[type_name] if name in out}


def json_to_proto(value, type_name):
    """Encode the proto3 JSON form of a message in field-number order."""
    out = b""
    for number, name, kind in SCHEMA[type_name]:
        if name not in value:
            continue
        repeated = isinstance(kind, tuple)
        inner = kind[1] if repeated else kind
        for item in value[name] if repeated else [value[name]]:
            if inner == "bool":
                out += bytes([number << 3 | 0, int(item)])
                continue
            if inner == "bytes":
                payload = base64.b64decode(item, validate=True)
            elif inner == "string":
                payload = item.encode("utf-8")
            else:
                payload = json_to_proto(item, inner)
            assert len(payload) < 1 << 14
            length = bytes([len(payload)]) if len(payload) < 128 else bytes([len(payload) & 127 | 128, len(payload) >> 7])
            out += bytes([number << 3 | 2]) + length + payload
    return out


def read_json(name):
    return json.loads((GOLDEN / name).read_bytes())


def verify_manifest():
    listed = {}
    for line in (GOLDEN / "MANIFEST.txt").read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        name, digest = line.split()
        assert name not in listed
        listed[name] = digest
    actual = {path.name for path in GOLDEN.iterdir() if path.name != "MANIFEST.txt"}
    assert set(listed) == actual, (set(listed) ^ actual)
    for name, digest in listed.items():
        assert blake3((GOLDEN / name).read_bytes()).hex() == digest, name


def verify_signature(payload_bytes, envelope):
    seed = bytes.fromhex((GOLDEN / "test-seed.hex").read_text().strip())
    public = bytes.fromhex((GOLDEN / "test-public-key.hex").read_text().strip())
    assert len(seed) == len(public) == 32
    key_id = blake3(public).hex()
    key_list = read_json("key-list.json")
    assert key_list["version"] == 1 and len(key_list["keys"]) == 1
    listed = key_list["keys"][0]
    assert listed["alg"] == "ed25519"
    assert listed["publicKey"] == public.hex()
    assert listed["keyId"] == key_id
    assert envelope["signatures"][0]["keyid"] == "blake3:" + key_id
    payload = json.loads(payload_bytes)
    assert payload["keyId"] == key_id
    assert int(listed["notBeforeMs"]) <= int(payload["issuedAtMs"]) < int(listed["notAfterMs"])
    assert objects_ref.ed25519_sign(seed, b"")[0] == public
    pae = (b"DSSEv1 " + str(len(PAYLOAD_TYPE)).encode() + b" " + PAYLOAD_TYPE.encode()
           + b" " + str(len(payload_bytes)).encode() + b" " + payload_bytes)
    signature = base64.b64decode(envelope["signatures"][0]["sig"], validate=True)
    assert disclosure_ref.ed25519_verify(public, pae, signature)
    assert objects_ref.ed25519_sign(seed, pae)[1] == signature


def verify_proto(name, type_name):
    json_path = GOLDEN / (name + ".json")
    bin_path = GOLDEN / (name + ".bin")
    expected_json = json.loads(json_path.read_bytes())
    got_json = proto_to_json(bin_path.read_bytes(), type_name)
    assert got_json == expected_json, name
    # The fixture file holds the compact JSON that a canonical encoder prints.
    assert json.dumps(got_json, separators=(",", ":"), ensure_ascii=False).encode() == json_path.read_bytes(), name
    assert json_to_proto(expected_json, type_name) == bin_path.read_bytes(), name


def main():
    verify_manifest()
    for prefix, view in (("notice", "writer"), ("reader", "reader"),
                         ("writer-followup", "writer"),
                         ("reader-followup", "reader"), ("ingest", "writer")):
        payload_bytes = (GOLDEN / (prefix + "-payload.jcs.json")).read_bytes()
        envelope_bytes = (GOLDEN / (prefix + "-envelope.dsse.json")).read_bytes()
        payload = json.loads(payload_bytes)
        envelope = json.loads(envelope_bytes)
        assert canonical(payload) == payload_bytes
        assert canonical(envelope) == envelope_bytes
        assert envelope["payloadType"] == PAYLOAD_TYPE
        assert base64.b64decode(envelope["payload"], validate=True) == payload_bytes
        assert len(envelope["signatures"]) == 1
        assert len(envelope_bytes) <= 262144
        assert payload["view"] == view
        assert re.fullmatch(r"[0-9a-f]{32}", payload["noticeId"])
        assert (re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", payload["takedownId"])
                or (prefix == "ingest" and payload["takedownId"] == ""))
        for field in ("takenDownAtMs", "issuedAtMs"):
            assert isinstance(payload[field], str) and re.fullmatch(r"(0|-?[1-9][0-9]*)", payload[field])
            assert -(1 << 63) <= int(payload[field]) < (1 << 63)
        assert int(payload["takenDownAtMs"]) <= int(payload["issuedAtMs"])
        assert payload["rewrites"] == sorted(payload["rewrites"], key=lambda row: (row["type"], row["old"]))
        verify_signature(payload_bytes, envelope)
        if prefix == "ingest":
            assert payload["repository"] == "" and payload["rewrites"] == []
            assert payload["takedownId"] == ""
        else:
            assert payload["repository"] and payload["rewrites"]
    reader = read_json("reader-payload.jcs.json")
    writer = read_json("notice-payload.jcs.json")
    assert len(reader["objects"]) == 1 and len(writer["objects"]) == 2
    assert len(reader["rewrites"]) == 2 and len(writer["rewrites"]) == 3
    assert set(row["old"] for row in reader["rewrites"]) < set(row["old"] for row in writer["rewrites"])
    for name, type_name in (("detail", "RedactionNotice"), ("reader-detail", "RedactionNotice"),
                            ("writer-followup-detail", "RedactionNotice"),
                            ("reader-followup-detail", "RedactionNotice"),
                            ("ingest-detail", "RedactionNotice"),
                            ("read-ref", "ReadRefResponse"),
                            ("writer-read-ref", "ReadRefResponse"),
                            ("list-refs", "ListRefsResponse"),
                            ("writer-list-refs", "ListRefsResponse")):
        verify_proto(name, type_name)
    for prefix, detail_name in (("notice", "detail"), ("reader", "reader-detail"),
                                ("writer-followup", "writer-followup-detail"),
                                ("reader-followup", "reader-followup-detail"),
                                ("ingest", "ingest-detail")):
        detail_bytes = base64.b64decode(read_json(detail_name + ".json")["envelope"], validate=True)
        assert detail_bytes == (GOLDEN / (prefix + "-envelope.dsse.json")).read_bytes()
    detail = read_json("detail.json")
    reader_detail = read_json("reader-detail.json")
    reader_followup_detail = read_json("reader-followup-detail.json")
    writer_followup_detail = read_json("writer-followup-detail.json")
    assert read_json("read-ref.json")["redactionNotices"] == [reader_detail, reader_followup_detail]
    assert read_json("writer-read-ref.json")["redactionNotices"] == [detail, writer_followup_detail]
    assert read_json("list-refs.json")["refRedactions"] == [
        {"ref": "refs/heads/main", "notice": row}
        for row in (reader_detail, reader_followup_detail)]
    assert read_json("writer-list-refs.json")["refRedactions"] == [
        {"ref": "refs/heads/main", "notice": row}
        for row in (detail, writer_followup_detail)]
    newest = max(("reader", "reader-followup"),
                 key=lambda prefix: (int(read_json(prefix + "-payload.jcs.json")["issuedAtMs"]),
                                     read_json(prefix + "-payload.jcs.json")["noticeId"]))
    assert newest == "reader-followup"
    for name, code, message in (("ingest-blocked", "permission_denied", "object blocked"),
                                ("open-closure", "invalid_argument", "open closure"),
                                ("delta-base", "failed_precondition", "delta base not available in this repository"),
                                ("superseded-pack", "not_found", "pack not found"),
                                ("superseded-pack-reader", "not_found", "pack not found")):
        body = read_json("error-" + name + ".json")
        detail_file = ("ingest-detail.bin" if name == "ingest-blocked" else
                       "reader-detail.bin" if name == "superseded-pack-reader" else "detail.bin")
        detail_b64 = base64.b64encode((GOLDEN / detail_file).read_bytes()).decode().rstrip("=")
        assert body == {"code": code, "message": message,
                        "details": [{"type": DETAIL_TYPE, "value": detail_b64}]}, name
    print("check-redaction-goldens: 36 artifacts, view scopes, signatures, protobuf and Connect bodies verified")


if __name__ == "__main__":
    main()

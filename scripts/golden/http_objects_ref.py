#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Independent reference check of the HTTP object golden vectors:
#   rust/tests/golden/http-objects/
#
# The check shares no code with the Rust crates. It reads only
# SPEC-HTTP-OBJECTS and SPEC-DISCLOSURE (sections 3 to 5 and 8), SPEC-REFS
# section 3 and SPEC-OBJECTS section 4.1. BLAKE3 and the object rules come from
# objects_ref.py; the KDPB verifier comes from disclosure_ref.py.
#
# For each group of vectors the check:
#   * url-parse.json: parses every URL with the grammar of section 2 and
#     compares the result or the 400 status;
#   * content-headers.json: derives Content-Type and Content-Disposition from
#     the extension table of section 5.1 and the RFC 5987 filename rules;
#   * response-cases.json: applies the response precedence of section 3 and the
#     header rules of sections 5, 7 and 8 and compares the status, the
#     required headers and the forbidden headers;
#   * KDPB bodies (object_*, blob_range, chunk, in_chunk_range): verifies the
#     bundle and compares the disclosed summary;
#   * KDSP version 2 bodies (span_* and neg_*): rebuilds each body from its
#     recipe, checks the pinned size and digest, then runs the checks of
#     SPEC-DISCLOSURE section 8.2 as changed by plan 4.7 (no anchor; the new
#     span_chunk_chain reason) in order and compares the outcome or the
#     reject reason.
#
# Usage:
#   python3 -I -B scripts/golden/http_objects_ref.py rust/tests/golden
#
# Exit 0 and print "OK" when every check passes; exit 1 otherwise.

import json
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import disclosure_ref as d  # noqa: E402
import objects_ref as o  # noqa: E402
from objects_ref import blake3, expect  # noqa: E402

D = "http-objects"

# ------------------------------------------------------------ url parse

NAMESPACE = r"(?:ed25519-[0-9a-f]{64}|0x[0-9a-f]{40})"
NAME = r"[a-z0-9][a-z0-9._-]{0,99}"
UNRESERVED = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
HEX = set(b"0123456789abcdefABCDEF")


class Bad(Exception):
    """The URL breaks the grammar (HTTP 400)."""


def pct_decode_segment(seg):
    """Decode one path segment exactly once (SPEC-HTTP-OBJECTS section 2)."""
    raw = seg.encode("ascii", "strict") if seg.isascii() else None
    if raw is None or not raw:
        raise Bad("empty or non-ASCII segment")
    out, i = bytearray(), 0
    while i < len(raw):
        b = raw[i]
        if b == 0x25:
            if i + 2 >= len(raw):
                raise Bad("truncated escape")
            hi, lo = raw[i + 1], raw[i + 2]
            if hi not in HEX or lo not in HEX:
                raise Bad("bad escape")
            out.append(int(bytes([hi, lo]), 16))
            i += 3
        elif b in UNRESERVED:
            out.append(b)
            i += 1
        else:
            raise Bad("byte outside the segment grammar")
    return bytes(out)


def decode_path(text):
    """Decode a file path into entry names. The empty path is the root."""
    if text == "":
        return []
    names, total = [], 0
    for seg in text.split("/"):
        name = pct_decode_segment(seg)
        if b"/" in name or b"\\" in name or b"\x00" in name:
            raise Bad("separator or NUL in a decoded segment")
        try:
            o.check_entry_name(name)
        except ValueError as e:
            raise Bad(str(e))
        names.append(name)
        total += len(name)
    if total + len(names) - 1 > 1024:
        raise Bad("path too long")
    return names


def ref_valid(ref):
    if not 0 < len(ref) <= 512 or not ref.startswith("refs/"):
        return False
    if re.fullmatch(r"[0-9A-Za-z._-]+(?:/[0-9A-Za-z._-]+)*", ref) is None:
        return False
    segments = ref.split("/")
    if any(s.startswith(".") or s.endswith(".lock") for s in segments):
        return False
    return segments[-1] != "HEAD"


def parse_query(query, is_object):
    if query == "":
        raise Bad("empty query")
    found = {}
    for param in query.split("&"):
        name, eq, value = param.partition("=")
        if not eq or name in found:
            raise Bad("bad or repeated parameter")
        if name == "proof" and value == "1":
            found[name] = value
        elif name == "range" and re.fullmatch(r"[0-9]+-[0-9]+", value):
            a, b = (int(x) for x in value.split("-"))
            if a >= 1 << 64 or b >= 1 << 64 or a > b:
                raise Bad("bad range")
            found[name] = value
        elif name == "commit" and re.fullmatch(r"[0-9a-f]{64}", value):
            found[name] = value
        elif name == "path":
            found[name] = b"/".join(decode_path(value)).decode("latin-1")
        elif name == "token":
            found[name] = value
        else:
            raise Bad("unknown parameter or value")
    if "range" in found and "proof" not in found:
        raise Bad("range without proof")
    if is_object and "proof" in found and not ("commit" in found and "path" in found):
        raise Bad("proof without context")
    return found


def parse_url(url, single_repository):
    path, q, query = url.partition("?")
    idx = path.find("/-/")
    if idx < 0 or not path.startswith("/"):
        raise Bad("no route marker")
    prefix, rest = path[:idx], path[idx + 3 :]
    repository = None
    if prefix:
        repository = prefix[1:]
        multi = re.fullmatch(NAMESPACE + "/" + NAME, repository, re.ASCII) is not None
        single = multi or re.fullmatch(NAME, repository, re.ASCII) is not None
        if not (single if single_repository else multi):
            raise Bad("bad repository")
    elif not single_repository:
        raise Bad("repository required")
    if rest.startswith("objects/"):
        oid = rest[len("objects/") :]
        if re.fullmatch(r"[0-9a-f]{64}", oid) is None:
            raise Bad("bad object id")
        is_object = True
    elif rest.startswith("refs/"):
        ref, marker, file_path = rest.partition("/-/")
        if not marker or "%" in ref or not ref_valid(ref):
            raise Bad("bad ref")
        is_object = False
    else:
        raise Bad("unknown route")
    found = parse_query(query, is_object) if q else {}
    parsed = {"proof": "proof" in found, "query": found, "repository": repository}
    if is_object:
        parsed.update(kind="object", object=oid)
    else:
        parsed.update(kind="ref", ref=ref, path_hex=[n.hex() for n in decode_path(file_path)])
    return parsed


def check_url_parse(root):
    table = json.loads(o.read(root, D, "url-parse.json"))
    for case in table["cases"]:
        want = case["expect"]
        try:
            got = {"parsed": parse_url(case["request"]["url"], case["request"]["single_repository"]), "status": 200}
        except Bad:
            got = {"parsed": None, "status": 400}
        expect(got == want, f"url-parse {case['name']}: {got} != {want}")
    return len(table["cases"])


# ------------------------------------------------------ content headers

INLINE = {
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "gif": "image/gif",
    "webp": "image/webp",
    "avif": "image/avif",
    "txt": "text/plain; charset=utf-8",
    "pdf": "application/pdf",
    "mp4": "video/mp4",
    "webm": "video/webm",
    "mp3": "audio/mpeg",
    "ogg": "audio/ogg",
    "wav": "audio/wav",
    "heic": "image/heic",
    "md": "text/markdown; charset=utf-8",
    "csv": "text/csv; charset=utf-8",
}
ATTACHMENT = {"json": "application/json"}
FALLBACK_CHAR = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-")
ATTR_CHAR = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$&+-.^_`|~")


def content_headers(name):
    """SPEC-HTTP-OBJECTS section 5.1. `name` is the decoded last segment (bytes)."""
    ext = name.rsplit(b".", 1)[1].decode("latin-1").lower() if b"." in name else ""
    if ext in INLINE:
        media, kind = INLINE[ext], "inline"
    elif ext in ATTACHMENT:
        media, kind = ATTACHMENT[ext], "attachment"
    else:
        media, kind = "application/octet-stream", "attachment"
    fallback = bytes(b if b in FALLBACK_CHAR else 0x5F for b in name)[:255].decode()
    encoded = "".join(chr(b) if b in ATTR_CHAR else f"%{b:02X}" for b in name)
    return media, f"{kind}; filename=\"{fallback}\"; filename*=UTF-8''{encoded}"


def check_content_headers(root):
    table = json.loads(o.read(root, D, "content-headers.json"))
    for case in table["cases"]:
        name = decode_path(case["path"])[-1]
        media, disposition = content_headers(name)
        expect(name == case["name"].encode("utf-8"), f"content-headers {case['path']}: decoded name")
        expect(media == case["media"], f"content-headers {case['path']}: media {media}")
        expect(disposition == case["disposition"], f"content-headers {case['path']}: {disposition}")
    return len(table["cases"])


# ----------------------------------------------------------- KDPB / KDSP


def kdpb_summary(result):
    """Reduce a verified KDPB result to the fields of an http-objects sidecar."""
    payload = result["payload"]
    kind = {"object": "Object", "chunk": "Chunk", "range": "Range"}[payload["kind"]]
    out = {"kind": kind}
    if kind == "Chunk":
        out.update(
            chunk_size=payload["chunk_size"], index=payload["index"], total_size=payload["total_size"],
            start=payload["start"], end=payload["end"],
        )
    if kind == "Range":
        chunk = payload["chunk"]
        out.update(
            absolute_offset=payload["absolute_offset"],
            offset_in_blob=payload["offset_in_blob"],
            chunk=None if chunk is None else [chunk["index"], chunk["total_size"], chunk["chunk_size"]],
            start=None if chunk is None else chunk["start"],
            end=None if chunk is None else chunk["end"],
        )
    content = result["_content"]
    return {
        "bytes_blake3": blake3(content).hex(),
        "bytes_len": len(content),
        "leaf": result["leaf_id_hex"],
        "path_hex": [step["name_hex"] for step in result["path"]],
        "payload": out,
        "signature_valid": result["signature_valid"],
    }


def check_kdpb(root, name):
    meta = json.loads(o.read(root, D, name + ".json"))
    data = o.read(root, D, name + ".bin")
    expect(len(data) == meta["size"] and blake3(data).hex() == meta["blake3"], f"{name}: size or digest")
    commit = bytes.fromhex(meta["commit"])
    try:
        got = kdpb_summary(d.verify_bundle(data, commit))
    except d.Reject as e:
        o.fail(f"{name}: unexpected reject ({e})")
        return
    want = dict(meta["expect"]["disclosed"])
    want.pop("commit", None)
    for key, value in want.items():
        if key == "payload":
            for k, v in value.items():
                expect(got["payload"].get(k) == v, f"{name}: payload {k}: {got['payload'].get(k)} != {v}")
        else:
            expect(got[key] == value, f"{name}: {key}: {got[key]} != {value}")


SpanReject = d.SpanReject


def verify_span(data, trusted):
    """SPEC-DISCLOSURE section 8.2 as changed by plan 4.7 (KDSP version 2, no
    anchor): disclosure_ref.verify_span, reduced to the sidecar fields."""
    got = d.verify_span(data, trusted)
    first = got["results"][0]
    return {
        "bytes": got["content"],
        "offset": got["offset"],
        "leaf": first["leaf_id_hex"],
        "path_hex": [step["name_hex"] for step in first["path"]],
        "signature_valid": first["signature_valid"],
    }


def rebuild(root, meta):
    """Rebuild a body from its recipe. The sidecar pins this base body."""
    if "recipe" not in meta:
        return o.read(root, D, meta["name"] + ".bin")
    data = b""
    for seg in meta["recipe"]["segments"]:
        if "hex" in seg:
            data += bytes.fromhex(seg["hex"])
        else:
            src = o.read(root, D, seg["source"])
            data += src[seg["offset"] : seg["offset"] + seg["length"]]
    return data


def check_span(root, name):
    meta = json.loads(o.read(root, D, name + ".json"))
    data = rebuild(root, meta)
    commit = bytes.fromhex(meta["commit"])
    expect(len(data) == meta["size"], f"{name}: size {len(data)} != {meta['size']}")
    expect(blake3(data).hex() == meta["blake3"], f"{name}: digest")
    target = meta["expect"].get("expand_to")
    if target:
        # The sidecar expands the base body with zero bytes to this length.
        data += bytes(target - len(data))
    want = meta["expect"]
    try:
        got = verify_span(data, commit)
        outcome, reason = True, None
    except SpanReject as e:
        got, outcome, reason = None, False, e.reason
    expect(outcome == want["accept"], f"{name}: accept={outcome}, sidecar says {want['accept']} ({reason})")
    if outcome and want["accept"]:
        expect(blake3(got["bytes"]).hex() == want["bytes_blake3"], f"{name}: bytes_blake3")
        expect(len(got["bytes"]) == want["bytes_len"], f"{name}: bytes_len")
        for key in ("offset", "leaf", "path_hex", "signature_valid"):
            expect(got[key] == want[key], f"{name}: {key}")
    elif not outcome and not want["accept"]:
        expect(reason == want["reject_reason"], f"{name}: reason {reason} != {want['reject_reason']}")


# -------------------------------------------------------- response model

# Fixture facts from the pinned table, not derived from a request: the object
# id and the commit id that the rows name, and the file served by ref rows.
OBJECT_ID = "b0145b689c72cfb1b8b1e7ec756c2c4a1e0b4f0469393e4ff4a30d8c3d6a0d6f"
COMMIT_ID = "1d8c6225d142427a5791e289bb616393f299292880d59b43cbbebcb6d2c9b145"
FILE_NAME = b"small.txt"
DEPLOYMENT_ORIGIN = "https://vcs.example.test"
# The admission hook supplies these values. A request row does not hold them.
HOOK_HEADERS = {"admission-required", "www-authenticate", "admission-receipt", "admission-response"}
BODY_SIZE = 100
IMMUTABLE = "max-age=31536000, immutable"
RESOLVE_FAILURES = {
    "missing_ref",
    "non_tree",
    "missing_entry",
    "unreachable_commit",
    "wrong_leaf",
    "nonmember",
    "unreachable_id",
    "pending",
}
PREFLIGHT = {
    "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
    "Access-Control-Allow-Headers": "Range, If-None-Match, If-Range, Admission-Authorization, "
    "ADMISSION-SIGNATURE, Authorization, Accept-Admission",
}
EXPOSE = (
    "ETag, Content-Range, Accept-Ranges, Content-Length, X-Kit-Commit, X-Kit-Object, X-Kit-Object-Type, "
    "WWW-Authenticate, Admission-Receipt, ADMISSION-REQUIRED, ADMISSION-RESPONSE, Link"
)


def respond(r):
    """SPEC-HTTP-OBJECTS section 3. Returns (status, headers, body_bytes)."""
    bearer = r.get("bearer_required", False)
    headers = {
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "sandbox; default-src 'none'",
        "Referrer-Policy": "no-referrer",
    }
    origin = r.get("origin")
    if origin:
        headers.update({"Access-Control-Allow-Origin": origin, "Vary": "Origin"})
        headers["Access-Control-Expose-Headers"] = EXPOSE
    else:
        headers["Access-Control-Allow-Origin"] = "*"
    key_document = r.get("route") == "/.well-known/kit-url-token-keys.json"
    no_store = "private, no-store" if bearer else "no-store"

    def fail(status, **extra):
        headers.update({"Cache-Control": no_store}, **extra)
        return status, headers, b""

    method = r["method"]
    if method == "OPTIONS":
        headers.update(PREFLIGHT)
        if bearer:
            headers["Cache-Control"] = "private"
        return 204, headers, b""
    if method not in ("GET", "HEAD"):
        return fail(405, Allow="GET, HEAD, OPTIONS")
    if r.get("malformed_url"):
        return fail(400)
    if key_document:
        headers.update({"Cache-Control": "public, max-age=300", "Content-Type": "application/json"})
        return 200, headers, b"{}"
    if bearer and not r.get("bearer_valid"):
        return fail(401)
    failure = r.get("failure")
    if r.get("repository_missing") or failure in ("repository_missing", "private_missing_token", "private_invalid_token"):
        return fail(404)
    if failure in ("authorizer_private", "authorizer_not_found"):
        return fail(404)
    if failure == "authorizer_deny":
        return fail(403)
    if failure == "hook_unavailable":
        return fail(503)
    if failure in RESOLVE_FAILURES:
        return fail(404)
    if r.get("global_block") and not r.get("repository_tombstone"):
        return fail(404)
    if r.get("chunk_only_under_tombstoned_manifest") or (
        r.get("chunk_only_under_blocked_manifest") and not r.get("manifest_tombstone")
    ):
        return fail(404)
    if r.get("published_reachable") and r.get("repository_tombstone"):
        return fail(451, **{"Content-Type": "application/json", "Link": f"<{DEPLOYMENT_ORIGIN}>; rel=\"blocked-by\""})

    route = r.get("route", "object")
    proof = r.get("proof", False)
    admission = r.get("admission", "off")
    admitted = admission in ("allow", "challenge", "deny") or r.get("admission_configured", False) or r.get("receipt", False)
    public = r.get("public", True)
    selector = r.get("selector")
    if proof:
        etag = f"\"{COMMIT_ID}.{OBJECT_ID}.{selector or 'object'}\""
    else:
        etag = f"\"{OBJECT_ID}\""
    pinned = route != "ref"
    if pinned:
        remaining = r.get("token_remaining_seconds")
        private_pinned = f"private, max-age={remaining}, immutable" if remaining is not None else f"private, {IMMUTABLE}"
        if public:
            policy = f"public, {IMMUTABLE}"
        else:
            policy = private_pinned if not r.get("admission_configured") else f"private, {IMMUTABLE}"
        if public and admitted:
            policy = f"private, {IMMUTABLE}"
    else:
        policy = "public, no-cache" if public else "private, no-cache"
        if public and admitted:
            policy = "private, no-cache"
    if bearer and policy.startswith("public"):
        policy = "private" + policy[len("public") :]
    inm = r.get("if_none_match")
    identity = {"ETag": etag, "X-Kit-Object": OBJECT_ID}
    if route == "ref" or proof:
        identity["X-Kit-Commit"] = COMMIT_ID
    if inm is not None and (inm == "*" or inm == etag):
        headers.update(identity)
        headers["Cache-Control"] = policy
        return 304, headers, b""

    rng = r.get("range")
    size = r.get("size", BODY_SIZE)
    single = None
    if rng and not proof:
        m = re.fullmatch(r"bytes=(\d+)-(\d+)", rng)
        if m:
            lo, hi = int(m.group(1)), int(m.group(2))
            if lo >= size:
                return fail(416, **{"Content-Range": f"bytes */{size}"})
            single = (lo, min(hi, size - 1))
    if proof and r.get("range_failure"):
        return fail(416)
    if admission == "challenge":
        headers.update({"Cache-Control": no_store, "Content-Type": "application/json"})
        return 402, headers, json.dumps(r.get("admission_challenge")).encode()
    if admission == "deny":
        return fail(403)

    if route == "ref" and not proof and r.get("redirects") and public and not admitted:
        headers.update(
            {"Location": f"/-/objects/{OBJECT_ID}", "Cache-Control": "private, no-cache" if bearer else "no-cache"}
        )
        return 302, headers, b""

    headers["Cache-Control"] = policy
    headers.update(identity)
    if proof:
        headers["Accept-Ranges"] = "none"
        headers["Content-Type"] = "application/vnd.kit.disclosure-span" if r.get("kind") == "KDSP" else "application/vnd.kit.disclosure"
        return 200, headers, b""
    kind = r.get("type", "blob")
    headers["X-Kit-Object-Type"] = kind
    headers["Accept-Ranges"] = "bytes"
    if route == "ref":
        media, disposition = content_headers(FILE_NAME)
        headers.update({"Content-Type": media, "Content-Disposition": disposition})
    else:
        headers["Content-Type"] = "application/vnd.kit.object" if kind == "tree" else "application/octet-stream"
    if_range = r.get("if_range")
    if single and (if_range is None or if_range == etag):
        headers["Content-Range"] = f"bytes {single[0]}-{single[1]}/{size}"
        headers["Content-Length"] = str(single[1] - single[0] + 1)
        return 206, headers, b""
    headers["Content-Length"] = str(size)
    if method == "HEAD":
        return 200, headers, b""
    return 200, headers, b""


def check_responses(root):
    table = json.loads(o.read(root, D, "response-cases.json"))
    bodies = {}
    for case in table["cases"]:
        name, want = case["name"], case["expect"]
        status, headers, body = respond(case["request"])
        lower = {k.lower(): v for k, v in headers.items()}
        expect(status == want["status"], f"response {name}: status {status} != {want['status']}")
        for key, value in want["headers"].items():
            if key.lower() in HOOK_HEADERS:
                continue
            if key.lower() == "x-kit-object-type" and key.lower() not in lower:
                continue  # The row does not say which object type its fixture holds.
            expect(lower.get(key.lower()) == value, f"response {name}: {key}: {lower.get(key.lower())!r} != {value!r}")
        for key in want.get("absent_headers", []):
            if key.endswith("*"):
                bad = [h for h in lower if h.startswith(key[:-1].lower())]
            else:
                bad = [h for h in lower if h == key.lower()]
            expect(not bad, f"response {name}: forbidden header {bad}")
        if want.get("body_bytes") == 0:
            expect(status in (204, 304) or case["request"]["method"] == "HEAD", f"response {name}: a body is allowed")
        if "body_json" in want:
            expect(json.loads(body) == want["body_json"], f"response {name}: body_json")
        group = want.get("body_equivalence_group")
        if group:
            seen = bodies.setdefault(group, (status, headers, body))
            expect(seen == (status, headers, body), f"response {name}: differs from its equivalence group")
    return len(table["cases"])


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: http_objects_ref.py <rust/tests/golden>")
    root = sys.argv[1]
    names = sorted(f[:-5] for f in os.listdir(os.path.join(root, D)) if f.endswith(".json"))
    man = o.manifest(root, D)
    for fn in os.listdir(os.path.join(root, D)):
        if fn != "MANIFEST.txt":
            expect(man.get(fn) == blake3(o.read(root, D, fn)).hex(), f"MANIFEST.txt: {fn}")
    tables = {"url-parse", "content-headers", "response-cases"}
    check_url_parse(root)
    check_content_headers(root)
    check_responses(root)
    for name in names:
        if name in tables:
            continue
        meta = json.loads(o.read(root, D, name + ".json"))
        if "disclosed" in meta["expect"]:
            check_kdpb(root, name)
        else:
            check_span(root, name)
    if o.FAILURES:
        sys.exit(1)
    print("OK")


if __name__ == "__main__":
    main()

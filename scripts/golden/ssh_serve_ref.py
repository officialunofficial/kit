#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Independent reference check of the captured ssh sessions:
#   rust/tests/golden/ssh-serve/session-{1,2,3}.in.bin   (client frames)
#   rust/tests/golden/ssh-serve/session-{1,2,3}.bin      (server frames)
#
# The check shares no code with the Rust crates. It reads only SPEC-RPC section 1
# (framing), SPEC-TRANSPORT section 4 (conversation, CAS and caps), SPEC-REFS
# sections 3 and 4 (names and prefix listing) and ssh.proto (the field numbers).
# It decodes the protobuf frames by hand, replays the client script against a
# small model of the server, and compares the model answer with each captured
# frame.
#
# What the model decides, from the specs:
#   * the handshake and the rejection of an empty, repeated or misplaced frame;
#   * ListRefs with the path-component prefix rule, sorted by name;
#   * ReadRef, and UpdateRef with the three CAS expectations, the
#     `details` field that holds the current value, and the refusal of a name
#     that breaks the ref grammar;
#   * PackExists, UploadPack (header, ordered chunks, exact length and BLAKE3
#     of the bytes), and DownloadPack (header, chunks of at most 800 KiB, a
#     single empty last chunk for the empty pack);
#   * the write policy of session 3, which refuses writes and still reads the
#     whole upload stream.
# The check compares frame kinds, payloads and error codes. It does not compare
# the free text of `Error.message`, which SPEC-RPC leaves to the implementation,
# except that the text must be present and valid UTF-8.
#
# The state before each session is a fixture fact, listed in the constants below
# and in the README of the vector directory. The check verifies the BLAKE3
# digest and the length of every pack that the server sends.
#
# Usage:
#   python3 -I -B scripts/golden/ssh_serve_ref.py rust/tests/golden
#
# Exit 0 and print "OK" when every check passes; exit 1 otherwise.

import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import objects_ref as o  # noqa: E402
import transport_ref as t  # noqa: E402
from objects_ref import blake3, expect  # noqa: E402

D = "ssh-serve"
MAX_FRAME = 1 << 20
CHUNK = 800 * 1024
INVALID, NOT_FOUND, INTERNAL = 1, 4, 99
# SPEC-REFS section 3 requires an error for a bad name but names no code.
BAD_NAME = (INVALID, INTERNAL)
SERVER_ID = "kit serve/0.4.2"

TAGS = {
    1: "hello",
    2: "hello_response",
    3: "error",
    4: "close",
    10: "list_refs",
    11: "list_refs_response",
    12: "read_ref",
    13: "read_ref_response",
    14: "update_ref",
    15: "update_ref_response",
    20: "pack_exists",
    21: "pack_exists_response",
    22: "upload_pack",
    23: "upload_pack_response",
    24: "download_pack",
    25: "download_pack_header",
    26: "pack_chunk",
}
EXP_ANY, EXP_MISSING, EXP_MATCH = 1, 2, 3

# Fixture state before each session (the setup is in the Rust test of the same name).
SESSIONS = {
    1: {
        "refs": {"refs/heads/main": b"\x11" * 32, "refs/heads/dev": b"\x22" * 32, "refs/tags/v1": b"\x33" * 32},
        "packs": {"9e488940536ee753d05b6f7f6f40a000d47c9a3fed17f8c241ba1ad5112cbb9a": 1000},
        "writable": True,
    },
    2: {
        "refs": {
            "refs/heads/main": b"\x11" * 32,
            "refs/heads/feat/x": b"\x12" * 32,
            "refs/heads/featx": b"\x13" * 32,
            "refs/tags/v1": b"\x33" * 32,
        },
        "packs": {"63bf7505f11d10754fae1fa0792f74c10d29f45539a8e65add3d5b23fe753170": 800 * 1024 + 1000},
        "writable": True,
    },
    3: {"refs": {"refs/heads/main": b"\x44" * 32}, "packs": {}, "writable": False},
}


def read_frames(data):
    """SPEC-RPC section 1: u32 LE length, then the protobuf body."""
    pos, out = 0, []
    while pos < len(data):
        if pos + 4 > len(data):
            raise ValueError("truncated length prefix")
        (n,) = struct.unpack("<I", data[pos : pos + 4])
        if n > MAX_FRAME or pos + 4 + n > len(data):
            raise ValueError("bad frame length")
        out.append(data[pos + 4 : pos + 4 + n])
        pos += 4 + n
    return out


def decode(body):
    """Return (kind, {field number: value}) for one SshFrame. kind None means empty."""
    entries = list(t.fields(body))
    if not entries:
        return None, {}
    if len(entries) != 1 or entries[0][0] not in TAGS or entries[0][1] != 2:
        raise ValueError("a frame holds exactly one known message")
    number, _, payload = entries[0]
    fields = {}
    for n, _, value in t.fields(payload):
        if TAGS[number] == "list_refs_response":
            fields.setdefault(n, []).append(value)  # `refs` is a repeated field
        elif n in fields:
            raise ValueError("repeated field")
        else:
            fields[n] = value
    return TAGS[number], fields


def pairs(payload):
    return {n: v for n, _, v in t.fields(payload)}


def ref_name_valid(name):
    """SPEC-REFS section 3."""
    if not 0 < len(name) <= 512 or re.fullmatch(r"[0-9A-Za-z._-]+(?:/[0-9A-Za-z._-]+)*", name) is None:
        return False
    segments = name.split("/")
    return not any(s.startswith(".") or s.endswith(".lock") for s in segments) and segments[-1] != "HEAD"


def list_refs(refs, prefix):
    """SPEC-REFS section 4."""
    out = []
    p = prefix.rstrip("/")
    for name, value in refs.items():
        if prefix == "":
            out.append((name, value))
        elif name != p and name.startswith(p + "/"):
            out.append((name[len(p) + 1 :], value))
    return sorted(out)


class Model:
    def __init__(self, state):
        self.refs = dict(state["refs"])
        self.packs = {bytes.fromhex(k): None for k in state["packs"]}
        self.sizes = {bytes.fromhex(k): v for k, v in state["packs"].items()}
        self.writable = state["writable"]
        self.handshake = False

    def error(self, code, details=b""):
        return [("error", code, details)]

    def handle_upload(self, fields, rest):
        """Returns (answer events, number of frames consumed from `rest`)."""
        pack_id, total = fields.get(1, b""), fields.get(2)
        if len(pack_id) != 32:
            return self.error(INVALID), 0
        if total is None:
            return self.error(INVALID), 0
        data, offset, used, failure, done = b"", 0, 0, None, False
        for kind, f in rest:
            used += 1
            if kind != "pack_chunk":
                failure = failure or self.error(INVALID)
                done = True
                break
            if f.get(1, b"") != pack_id or f.get(2, 0) != offset:
                failure = failure or self.error(INVALID)
            else:
                data += f.get(3, b"")
                offset += len(f.get(3, b""))
            if f.get(4, 0):
                done = True
                break
        if failure:
            return failure, used
        if not done:
            return self.error(INVALID), used
        if not self.writable:
            return self.error(INVALID), used
        if len(data) != total or blake3(data) != pack_id:
            return self.error(INVALID), used
        self.packs[pack_id] = data
        self.sizes[pack_id] = len(data)
        return [("upload_pack_response",)], used

    def step(self, kind, f, rest):
        if kind is None:
            return self.error(INVALID), 0
        if kind == "hello":
            if self.handshake:
                return self.error(INVALID), 0
            self.handshake = True
            return [("hello_response", f.get(1))], 0
        if not self.handshake:
            return self.error(INVALID), 0
        if kind == "list_refs":
            prefix = f.get(1, b"").decode()
            if prefix and not (ref_name_valid(prefix.rstrip("/")) or prefix.rstrip("/") == ""):
                return self.error(BAD_NAME), 0
            return [("list", tuple(list_refs(self.refs, prefix)))], 0
        if kind == "read_ref":
            name = f.get(1, b"").decode()
            if not ref_name_valid(name):
                return self.error(BAD_NAME), 0
            return [("read_ref_response", self.refs.get(name, b""))], 0
        if kind == "update_ref":
            return self.update(f), 0
        if kind == "pack_exists":
            pack_id = f.get(1, b"")
            if len(pack_id) != 32:
                return self.error(INVALID), 0
            return [("pack_exists_response", pack_id in self.packs)], 0
        if kind == "upload_pack":
            return self.handle_upload(f, rest)
        if kind == "download_pack":
            pack_id = f.get(1, b"")
            if not pack_id:
                return self.error(INVALID), 0
            if len(pack_id) != 32:
                return self.error(INVALID), 0
            if pack_id not in self.packs:
                return self.error(NOT_FOUND), 0
            return [("download", pack_id, self.sizes[pack_id], self.packs[pack_id])], 0
        if kind == "pack_chunk":
            return self.error(INVALID), 0
        return self.error(INVALID), 0

    def update(self, f):
        name, expected, new = f.get(1, b"").decode(), f.get(2, b""), f.get(3, b"")
        expectation = f.get(4, 0)
        if not self.writable:
            return self.error(INVALID)
        if expectation not in (EXP_ANY, EXP_MISSING, EXP_MATCH):
            return self.error(INVALID)
        if expectation == EXP_MATCH and len(expected) != 32:
            return self.error(INVALID)
        if new and len(new) != 32:
            return self.error(INVALID)
        if not ref_name_valid(name):
            return self.error(BAD_NAME)
        current = self.refs.get(name)
        if expectation == EXP_MISSING and current is not None:
            return self.error(INVALID, current)
        if expectation == EXP_MATCH and current != expected:
            return self.error(INVALID, current or b"")
        if new:
            self.refs[name] = new
        else:
            self.refs.pop(name, None)
        return [("update_ref_response",)]


def normalize(frames):
    """Reduce captured server frames to comparable events."""
    events, i = [], 0
    while i < len(frames):
        kind, f = frames[i]
        i += 1
        if kind == "hello_response":
            events.append(("hello_response", f.get(1)))
            expect(f.get(2, b"").decode() == SERVER_ID, "server_id")
        elif kind == "error":
            code, message, details = f.get(1, 0), f.get(2, b""), f.get(3, b"")
            expect(code != 0 and len(message) > 0, "an Error frame needs a code and a message")
            message.decode("utf-8")
            events.append(("error", code, details))
        elif kind == "list_refs_response":
            refs = tuple((pairs(r)[1].decode(), pairs(r)[2]) for r in f.get(1, []))
            events.append(("list", refs))
        elif kind == "read_ref_response":
            events.append(("read_ref_response", f.get(1, b"")))
        elif kind in ("update_ref_response", "upload_pack_response"):
            events.append((kind,))
        elif kind == "pack_exists_response":
            events.append(("pack_exists_response", bool(f.get(1, 0))))
        elif kind == "download_pack_header":
            total = f.get(1, 0)
            data, offset, pack_id = b"", 0, None
            while True:
                ck, cf = frames[i]
                i += 1
                expect(ck == "pack_chunk", "a download holds only chunks after its header")
                pack_id = pack_id or cf.get(1, b"")
                expect(cf.get(1, b"") == pack_id and cf.get(2, 0) == offset, "download chunk order")
                expect(len(cf.get(3, b"")) <= CHUNK, "download chunk size")
                data += cf.get(3, b"")
                offset += len(cf.get(3, b""))
                if cf.get(4, 0):
                    break
            expect(len(data) == total, "download total_bytes")
            events.append(("download", pack_id, total, data))
        else:
            events.append((kind,))
    return events


def check_session(root, n):
    inputs = [decode(b) for b in read_frames(o.read(root, D, f"session-{n}.in.bin"))]
    outputs = [decode(b) for b in read_frames(o.read(root, D, f"session-{n}.bin"))]
    got = normalize(outputs)
    model = Model(SESSIONS[n])
    want, i = [], 0
    while i < len(inputs):
        kind, f = inputs[i]
        if kind == "close":
            break
        events, used = model.step(kind, f, inputs[i + 1 :])
        want.extend(events)
        i += 1 + used
    expect(len(got) == len(want), f"session {n}: {len(got)} answers, model expects {len(want)}")
    for idx, (g, w) in enumerate(zip(got, want)):
        if w[0] == "hello_response":
            expect(g[0] == "hello_response", f"session {n} answer {idx}")
            expect(g[1] == 1, f"session {n}: handshake version")
            continue
        if w[0] == "download":
            expect(g[0] == "download" and g[1] == w[1] and g[2] == w[2], f"session {n} answer {idx}: download header")
            expect(blake3(g[3]) == w[1], f"session {n} answer {idx}: downloaded bytes do not hash to the pack id")
            if w[3] is not None:
                expect(g[3] == w[3], f"session {n} answer {idx}: downloaded bytes differ from the uploaded pack")
            else:
                model.packs[w[1]] = g[3]
            continue
        if w[0] == "error" and isinstance(w[1], tuple):
            expect(g[0] == "error" and g[1] in w[1] and g[2] == w[2], f"session {n} answer {idx}: {g!r} != {w!r}")
            continue
        expect(g == w, f"session {n} answer {idx}: {g!r} != {w!r}")
    return len(got)


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: ssh_serve_ref.py <rust/tests/golden>")
    root = sys.argv[1]
    for n in (1, 2, 3):
        check_session(root, n)
    if o.FAILURES:
        sys.exit(1)
    print("OK")


if __name__ == "__main__":
    main()

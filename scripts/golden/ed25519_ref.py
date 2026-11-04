#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Independent reference check of the Ed25519 acceptance vectors:
#   rust/tests/golden/ed25519/vectors.json
#
# The check shares no code with the Rust crates. It reads only SPEC-SIGNING
# section 1. Each case runs through two Python transcriptions of the
# predicate: disclosure_ref.ed25519_verify (over objects_ref's curve
# arithmetic) and grants_ref.ed25519_verify (over its own). Both must give
# the case's expected verdict.
#
# Usage:
#   python3 -I -B scripts/golden/ed25519_ref.py rust/tests/golden
#
# Exit 0 and print "OK" when every check passes; exit 1 otherwise.

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import disclosure_ref as d  # noqa: E402
import grants_ref as g  # noqa: E402
from objects_ref import FAILURES, expect, manifest  # noqa: E402

D = "ed25519"
NAMES = {
    "valid", "torsion-r", "torsion-a", "wrong-message", "small-order-a", "small-order-r",
    "torsion-only-r", "s-not-canonical", "r-not-canonical", "a-not-canonical", "a-negative-zero",
}


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: ed25519_ref.py <golden-root>")
    root = sys.argv[1]
    manifest(root, D)
    with open(os.path.join(root, D, "vectors.json"), encoding="utf-8") as f:
        doc = json.load(f)
    seen = set()
    for case in doc["cases"]:
        name = case["name"]
        seen.add(name)
        public = bytes.fromhex(case["public"])
        message = bytes.fromhex(case["message"])
        signature = bytes.fromhex(case["signature"])
        want = case["expect"] == "accept"
        expect(case["expect"] in ("accept", "reject"), f"{name}: bad expect")
        expect(d.ed25519_verify(public, message, signature) == want, f"{name}: disclosure_ref disagrees")
        expect(g.ed25519_verify(public, message, signature) == want, f"{name}: grants_ref disagrees")
    expect(seen == NAMES, f"case names differ: {sorted(seen ^ NAMES)}")
    if FAILURES:
        for msg in FAILURES:
            print("FAIL:", msg)
        sys.exit(1)
    print("OK")


if __name__ == "__main__":
    main()

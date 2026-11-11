#!/usr/bin/env python3
# Decompose the accepting disclosure golden vectors into their parts.
# Usage: python3 -B measure_disclosure.py <kit-repo-root>
import json, os, sys
root = sys.argv[1]
sys.path.insert(0, os.path.join(root, "scripts", "golden"))
import disclosure_ref as d  # noqa: E402

gdir = os.path.join(root, "rust", "tests", "golden", "disclosure")
names = sorted(n[:-5] for n in os.listdir(gdir) if n.endswith(".json"))
print("name total commit steps step_bytes siblings(step) payload_kind payload_bytes chunk_sibs lenproofs lenproof_bytes")
for n in names:
    side = json.load(open(os.path.join(gdir, n + ".json")))
    if side["expect"] != "accept":
        continue
    data = open(os.path.join(gdir, n + ".bin"), "rb").read()
    b = d.decode_bundle(data)
    sibs = [len(s["proof"][1]) for s in b["steps"]]
    leafs = [s["proof"][0] for s in b["steps"]]
    # name vector, mode, child id, position, then the keyed tree proof:
    # leaf count, step count and one (sibling, separator) per step.
    step_bytes = sum(
        1 + len(s["name"]) + 1 + 32 + 4 + 4 + 1
        + sum(33 + len(sep) for _, sep in s["proof"][1])
        for s in b["steps"]
    )
    kind = {0: "object", 1: "chunk", 2: "range"}[b["kind"]]
    chunk_sibs = "-"
    lp = 0; lpb = 0
    if b["kind"] in (0, 1):
        pb = len(b["bytes"])
        if b["kind"] == 1:
            chunk_sibs = "%d(leaves=%d)" % (len(b["chunk"]["proof"][1]), b["chunk"]["proof"][0])
    else:
        pb = len(b["slice"])
        if b["hdr"]:
            chunk_sibs = "%d(leaves=%d)" % (len(b["hdr"]["proof"][1]), b["hdr"]["proof"][0])
        lp = len(b["len_proofs"]); lpb = sum(len(x["slice"]) for x in b["len_proofs"])
    print(n, len(data), len(b["commit_bytes"]), len(b["steps"]), step_bytes,
          "%s/leaves=%s" % (sibs, leafs), kind, pb, chunk_sibs, lp, lpb)

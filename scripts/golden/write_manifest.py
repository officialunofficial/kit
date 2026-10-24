#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Rewrite or check the BLAKE3 digests in the MANIFEST.txt of a golden vector
# directory.
#
# A manifest line has the form `<name> <blake3-hex>`. The name is a file path
# relative to the directory, or the stem of a `.bin`, `.manifest.bin` or `.json` file. The
# script keeps comment lines, blank lines and the order of the entries. It
# changes only the digest of a line that names a file. It leaves every other
# line as it is: a line with more than two fields, and a line that pins a
# derived value such as a signature, names no file.
#
# The digest comes from the pure-Python BLAKE3 in blake3_subtree_ref.py, so
# the script needs no extra tool.
#
# Usage:
#   python3 -I -B scripts/golden/write_manifest.py [--check] [--add NAME]... DIR
#
#   --check   Print each stale entry and exit 1 instead of rewriting the file.
#   --add     Append an entry for NAME when the manifest does not list it.
#
# Exit 0 when the manifest is current (or was rewritten); exit 1 otherwise.

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from blake3_subtree_ref import blake3  # noqa: E402


def resolve(directory, name):
    """Return the path of the file that a manifest name selects, or None."""
    for candidate in (name, name + ".bin", name + ".manifest.bin", name + ".json"):
        path = os.path.join(directory, candidate)
        if os.path.isfile(path):
            return path
    return None


def digest(path):
    with open(path, "rb") as f:
        return blake3(f.read()).hex()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("directory")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--add", action="append", default=[])
    args = ap.parse_args()

    manifest = os.path.join(args.directory, "MANIFEST.txt")
    with open(manifest) as f:
        lines = f.read().splitlines()

    listed = set()
    out, stale = [], []
    for line in lines:
        fields = line.split()
        if line.startswith("#") or len(fields) != 2:
            out.append(line)
            continue
        listed.add(fields[0])
        path = resolve(args.directory, fields[0])
        if path is None:
            out.append(line)
            continue
        want = digest(path)
        if want != fields[1]:
            stale.append(fields[0])
        out.append(f"{fields[0]} {want}")

    missing = []
    for name in args.add:
        if name in listed:
            continue
        path = resolve(args.directory, name)
        if path is None:
            sys.exit(f"FAIL: no file for {name} in {args.directory}")
        missing.append(name)
        out.append(f"{name} {digest(path)}")

    for name in stale:
        print(f"stale: {name}")
    for name in missing:
        print(f"missing: {name}")
    if args.check:
        sys.exit(1 if stale or missing else 0)
    with open(manifest, "w") as f:
        f.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Render the binary formula and commit it through the contents API."""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent
REPO = "officialunofficial/homebrew-tap"
TARGETS = ("aarch64-apple-darwin", "x86_64-apple-darwin",
           "aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu")


def render(version, checksums):
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("the formula needs a stable release version")
    sums = {}
    for line in checksums.splitlines():
        digest, name = line.split()
        if not re.fullmatch(r"[a-f0-9]{64}", digest) or name in sums:
            raise ValueError("invalid or duplicate release checksum")
        sums[name] = digest
    text = (ROOT / "homebrew-kit.rb.in").read_text().replace("@VERSION@", version)
    for target in TARGETS:
        name = f"kit-{version}-{target}.tar.gz"
        if name not in sums:
            raise ValueError(f"missing release checksum: {name}")
        text = text.replace(f"@{target}@", sums[name])
    return text


def api(method, path, body=None):
    token = os.environ.get("HOMEBREW_TAP_TOKEN", "")
    if not token:
        raise ValueError("HOMEBREW_TAP_TOKEN is required and must write tap contents")
    request = urllib.request.Request(
        f"https://api.github.com/repos/{REPO}/{path}",
        data=None if body is None else json.dumps(body).encode(), method=method,
        headers={"Authorization": f"Bearer {token}",
                 "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28",
                 "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        raise ValueError(f"tap API returned HTTP {error.code}; HOMEBREW_TAP_TOKEN must write tap contents") from None
    except urllib.error.URLError:
        raise ValueError("tap API could not be reached") from None


def preflight():
    # Updating the ref to its current value proves write access without a commit.
    ref = api("GET", "git/ref/heads/main")
    api("PATCH", "git/refs/heads/main", {"sha": ref["object"]["sha"], "force": False})


def update(version, checksums):
    formula = render(version, checksums)
    current = api("GET", "contents/Formula/kit.rb?ref=main")
    previous = base64.b64decode(current["content"]).decode()
    if previous == formula:
        return
    versions = set(re.findall(r"/releases/download/v([0-9]+\.[0-9]+\.[0-9]+)/", previous))
    if len(versions) != 1:
        raise ValueError("cannot determine the current tap version")
    current_version = versions.pop()
    if tuple(map(int, version.split("."))) < tuple(map(int, current_version.split("."))):
        raise ValueError("refusing to replace a newer tap version")
    api("PUT", "contents/Formula/kit.rb", {
        "message": f"chore(kit): update to {version}", "branch": "main",
        "sha": current["sha"],
        "content": base64.b64encode(formula.encode()).decode()})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("preflight", "render", "update"))
    parser.add_argument("--version")
    parser.add_argument("--checksums", type=Path)
    args = parser.parse_args()
    if args.command == "preflight":
        preflight()
    else:
        if not args.version or not args.checksums:
            parser.error("--version and --checksums are required")
        checksums = args.checksums.read_text()
        if args.command == "render":
            print(render(args.version, checksums), end="")
        else:
            update(args.version, checksums)


if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        sys.exit(f"ERROR: {error}")

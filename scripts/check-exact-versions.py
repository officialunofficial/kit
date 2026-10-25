#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Check that dependency versions are exact.

AGENTS.md requires exact audited versions. Cargo.lock holds the resolved
versions. A requirement such as "1.2" is a range, and only "=1.2.3" is exact.

* Every entry of `[workspace.dependencies]` must be exact.
* Every dependency of a crate manifest must be exact. There is no baseline.
* Path dependencies on other kit crates are not checked. They carry the
  crate version for publishing.

The script needs only the Python standard library.
"""

import sys
import tomllib
from pathlib import Path

# An optional first argument names another repository root, for the test.
ROOT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent
SECTIONS = ("dependencies", "dev-dependencies", "build-dependencies")


def requirement(spec):
    """The version requirement of a dependency entry, or None if it has none."""
    if isinstance(spec, str):
        return spec
    if spec.get("workspace") or "path" in spec:
        return None
    return spec.get("version")


def tables(manifest):
    for section in SECTIONS:
        if section in manifest:
            yield manifest[section]
    for target in manifest.get("target", {}).values():
        for section in SECTIONS:
            if section in target:
                yield target[section]


def ranges(path):
    """The names of the dependencies of one crate manifest that are ranges."""
    manifest = tomllib.loads(path.read_text(encoding="utf-8"))
    found = set()
    for table in tables(manifest):
        for name, spec in table.items():
            req = requirement(spec)
            if req is not None and not req.startswith("="):
                found.add(name)
    return found


def main():
    failures = 0
    workspace = tomllib.loads((ROOT / "rust/Cargo.toml").read_text(encoding="utf-8"))
    for name, spec in workspace["workspace"]["dependencies"].items():
        req = requirement(spec)
        if req is not None and not req.startswith("="):
            failures += 1
            print(f'rust/Cargo.toml: workspace dependency {name} = "{req}" is not exact', file=sys.stderr)

    for path in sorted((ROOT / "rust").rglob("Cargo.toml")):
        relative = path.relative_to(ROOT)
        if "target" in relative.parts or relative == Path("rust/Cargo.toml"):
            continue
        for name in sorted(ranges(path)):
            failures += 1
            print(f"{relative}: dependency {name} is a range; use an exact version", file=sys.stderr)
    if failures:
        return 1
    print("check-exact-versions: every dependency version is exact")
    return 0


if __name__ == "__main__":
    sys.exit(main())

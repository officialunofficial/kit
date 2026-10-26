#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Check the dependency version policy.

Cargo.lock holds the exact audited version of every external crate. A
manifest holds a compatible range, so a library user can resolve it.

* An external requirement is a caret requirement "X.Y.Z" or "^X.Y.Z". Its
  lower bound is a full version, and that version is in Cargo.lock.
* An internal requirement (a dependency with a `path`) is exactly
  "=<workspace version>". A dependency with no version is allowed only in
  `dev-dependencies` or in a crate that sets `publish = false`.
* Cargo.lock lists no git source and no duplicate entry. Each registry entry
  has a checksum.

The rules cover every manifest under rust/, with no exemption. The script
needs only the Python standard library.
"""

import re
import sys
import tomllib
from pathlib import Path

# An optional first argument names another repository root, for the test.
ROOT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent
SECTIONS = ("dependencies", "dev-dependencies", "build-dependencies")
CARET = re.compile(r"\^?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)")


def load(path):
    return tomllib.loads(path.read_text(encoding="utf-8"))


def tables(manifest):
    """Yield (section, table) for every dependency table of a manifest."""
    for section in SECTIONS:
        if section in manifest:
            yield section, manifest[section]
    for target in manifest.get("target", {}).values():
        for section in SECTIONS:
            if section in target:
                yield section, target[section]


def lock_versions(lock, errors):
    """Map each crate name in Cargo.lock to its set of versions."""
    found = {}
    seen = set()
    for package in lock.get("package", []):
        name, version, source = package["name"], package["version"], package.get("source")
        if (name, version, source) in seen:
            errors.append(f"Cargo.lock: duplicate entry {name} {version}")
        seen.add((name, version, source))
        if source is None:
            continue
        if not source.startswith("registry+"):
            errors.append(f"Cargo.lock: {name} {version} has a source that is not a registry")
        elif "checksum" not in package:
            errors.append(f"Cargo.lock: {name} {version} has no checksum")
        found.setdefault(name, set()).add(version)
    return found


def check_entry(where, section, name, spec, publishes, workspace_version, locked, errors):
    if isinstance(spec, str):
        spec = {"version": spec}
    if spec.get("workspace"):
        return
    req = spec.get("version")
    if "path" in spec:
        if req is None:
            if section != "dev-dependencies" and publishes:
                errors.append(f"{where}: internal dependency {name} has no version")
        elif req != f"={workspace_version}":
            errors.append(f'{where}: internal dependency {name} = "{req}" must be "={workspace_version}"')
        return
    if req is None:
        errors.append(f"{where}: dependency {name} has no version")
        return
    match = CARET.fullmatch(req)
    if match is None:
        errors.append(f'{where}: dependency {name} = "{req}" is not a caret requirement "X.Y.Z"')
        return
    package = spec.get("package", name)
    if match.group(1) not in locked.get(package, ()):
        errors.append(f'{where}: dependency {name} = "{req}" is not the version in Cargo.lock')


def main():
    errors = []
    root = load(ROOT / "rust/Cargo.toml")
    workspace_version = root["workspace"]["package"]["version"]
    locked = lock_versions(load(ROOT / "rust/Cargo.lock"), errors)

    for name, spec in root["workspace"].get("dependencies", {}).items():
        check_entry("rust/Cargo.toml", "dependencies", name, spec, True, workspace_version, locked, errors)

    for path in sorted((ROOT / "rust").rglob("Cargo.toml")):
        relative = path.relative_to(ROOT)
        if "target" in relative.parts or relative == Path("rust/Cargo.toml"):
            continue
        manifest = load(path)
        publishes = manifest.get("package", {}).get("publish", True) is not False
        for section, table in tables(manifest):
            for name, spec in table.items():
                check_entry(str(relative), section, name, spec, publishes, workspace_version, locked, errors)

    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        return 1
    print("check-dependency-versions: every requirement follows the policy")
    return 0


if __name__ == "__main__":
    sys.exit(main())

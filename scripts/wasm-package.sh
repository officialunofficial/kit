#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Build the npm package of kit-wasm into OUT_DIR.
#
#   bash scripts/wasm-package.sh OUT_DIR
#
# The script builds kit-wasm for wasm32, runs wasm-bindgen with the bundler
# target, copies the README and the licenses, and writes package.json. The
# wasm-bindgen tool must match the version in rust/Cargo.lock. OUT_DIR must be
# missing or empty.
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 OUT_DIR" >&2
    exit 2
fi

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
mkdir -p "$1"
out=$(cd "$1" && pwd)
if [ -n "$(ls -A "$out")" ]; then
    echo "$out is not empty" >&2
    exit 1
fi

cd "$root/rust"

want=$(awk '/^name = "wasm-bindgen"$/ { getline; gsub(/[^0-9.]/, "", $0); print; exit }' Cargo.lock)
have=$(wasm-bindgen --version | awk '{ print $2 }')
if [ -z "$want" ] || [ "$have" != "$want" ]; then
    echo "wasm-bindgen is '$have' but Cargo.lock needs '$want'" >&2
    exit 1
fi

cargo build --locked -p kit-wasm --release --target wasm32-unknown-unknown
wasm-bindgen --target bundler --out-dir "$out" \
    "${CARGO_TARGET_DIR:-target}/wasm32-unknown-unknown/release/kit_wasm.wasm"

crate="$root/rust/crates/kit-wasm"
cp "$crate/README.md" "$crate/LICENSE-APACHE" "$crate/LICENSE-MIT" "$out/"

# The package ships these files, and nothing else. npm skips a name that is
# missing from the list, so the loop checks each one.
files=(kit_wasm.js kit_wasm_bg.js kit_wasm_bg.wasm kit_wasm.d.ts kit_wasm_bg.wasm.d.ts LICENSE-APACHE LICENSE-MIT)
for f in "${files[@]}"; do
    [ -f "$out/$f" ] || { echo "missing $f in $out" >&2; exit 1; }
done

cargo metadata --locked --no-deps --format-version 1 | node -e '
const fs = require("fs");
const meta = JSON.parse(fs.readFileSync(0, "utf8"));
const crate = meta.packages.find((p) => p.name === "kit-wasm");
const pkg = {
  name: "@officialunofficial/kit-wasm",
  version: crate.version,
  description: crate.description,
  license: crate.license,
  repository: {
    type: "git",
    url: "git+" + crate.repository + ".git",
    directory: "rust/crates/kit-wasm",
  },
  type: "module",
  main: "kit_wasm.js",
  types: "kit_wasm.d.ts",
  sideEffects: ["./kit_wasm.js"],
  files: process.argv.slice(2),
  keywords: crate.keywords,
};
fs.writeFileSync(process.argv[1], JSON.stringify(pkg, null, 2) + "\n");
' "$out/package.json" "${files[@]}"

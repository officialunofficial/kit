#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Build kit-wasm, generate the Node bindings with wasm-bindgen and call a few
# exports. The wasm-bindgen tool must match the version in rust/Cargo.lock.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root/rust"

want=$(awk '/^name = "wasm-bindgen"$/ { getline; gsub(/[^0-9.]/, "", $0); print; exit }' Cargo.lock)
have=$(wasm-bindgen --version | awk '{ print $2 }')
if [ -z "$want" ] || [ "$have" != "$want" ]; then
    echo "wasm-bindgen is '$have' but Cargo.lock needs '$want'" >&2
    exit 1
fi

cargo build --locked -p kit-wasm --release --target wasm32-unknown-unknown
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
wasm-bindgen --target nodejs --out-dir "$out" \
    "${CARGO_TARGET_DIR:-target}/wasm32-unknown-unknown/release/kit_wasm.wasm"
node "$root/scripts/wasm-smoke.js" "$out/kit_wasm.js"

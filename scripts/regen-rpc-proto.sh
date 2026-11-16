#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Regenerate the vendored buffa codegen output for kit-rpc.
#
# kit-rpc builds from pre-generated sources committed under
# rust/crates/kit-rpc/generated/ so that consumers (and docs.rs) never
# need protoc. After editing any file in rust/crates/kit-rpc/proto/,
# run this script from the repo root and commit the refreshed output.
#
# Requires protoc >= 27 on PATH (protobuf `edition = "2023"` support).

set -euo pipefail

cd "$(dirname "$0")/.."

GEN_DIR=rust/crates/kit-rpc/generated

# Cargo reports the actual OUT_DIR, including configured build directories.
out_dir=$(KIT_RPC_CODEGEN=1 cargo build --manifest-path rust/Cargo.toml -p kit-rpc \
    --message-format=json | python3 scripts/codegen-out-dir.py .kit-rpc-codegen)

rm -f "$GEN_DIR"/*.rs
mkdir -p "$GEN_DIR"
cp "$out_dir"/_includes.rs "$out_dir"/kit.rpc.*.rs \
    "$out_dir"/kit.common.*.rs "$GEN_DIR/"

echo "refreshed $GEN_DIR from $out_dir:"
ls "$GEN_DIR"

if ! git diff --quiet -- "$GEN_DIR"; then
    echo
    echo "generated output changed — review and commit:"
    git status --short -- "$GEN_DIR"
else
    echo "generated output is unchanged."
fi

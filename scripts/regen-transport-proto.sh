#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Regenerate the shared transport and health ConnectRPC bindings owned by
# kit-rpc (feature transport), consumed by the native
# kit-transport-connect client. The canonical protos stay at the repo root;
# ordinary builds use the committed generated/transport/ tree without protoc.
# Requires protoc >= 27 on PATH (or PROTOC).

set -euo pipefail

cd "$(dirname "$0")/.."

# $1 = human label, $2 = generated directory, $3 = Cargo's OUT_DIR.
refresh() {
    local label="$1" gen_dir="$2" out="$3"
    rm -f "$gen_dir"/*.rs
    mkdir -p "$gen_dir"
    # The owning crate also stages RPC schemas at OUT_DIR's root. Select
    # only this Connect generation's transport/health files and wrapper.
    cp "$out"/_connectrpc.rs "$out"/kit.transport.*.rs \
        "$out"/grpc.health.*.rs "$gen_dir/"
    echo "refreshed $gen_dir from $out:"
    ls "$gen_dir"
}

echo ">> kit-rpc transport (wasm32 target)"
out_dir=$(KIT_TRANSPORT_CODEGEN=1 cargo build --manifest-path rust/Cargo.toml -p kit-rpc \
    --features transport --target wasm32-unknown-unknown --message-format=json | \
    python3 scripts/codegen-out-dir.py .kit-rpc-transport-codegen)
refresh "kit-rpc transport" \
    "rust/crates/kit-rpc/generated/transport" \
    "$out_dir"

generated_dirs=(rust/crates/kit-rpc/generated/transport)
# `git status --porcelain`, not only `git diff`: a new module lands untracked.
if ! git diff --quiet -- "${generated_dirs[@]}" \
    || [ -n "$(git status --porcelain -- "${generated_dirs[@]}")" ]; then
    echo
    echo "generated output changed — review and commit:"
    git status --short -- "${generated_dirs[@]}"
else
    echo "generated output is unchanged."
fi

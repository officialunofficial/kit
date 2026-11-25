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

GEN_DIR=rust/crates/kit-rpc/generated/transport

cargo run --quiet --locked --manifest-path rust/Cargo.toml -p kit-rpc-codegen -- transport

echo "refreshed $GEN_DIR:"
ls "$GEN_DIR"

# `git status --porcelain`, not only `git diff`: a new module lands untracked.
if [ -n "$(git status --porcelain -- "$GEN_DIR")" ]; then
    echo
    echo "generated output changed — review and commit:"
    git status --short -- "$GEN_DIR"
else
    echo "generated output is unchanged."
fi

#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Regenerate the checked-in buffa codegen output for kit-rpc.
#
# kit-rpc compiles the generated sources committed under
# rust/crates/kit-rpc/generated/, so that consumers (and docs.rs) never need
# protoc and never build a code generator. After editing any file in
# rust/crates/kit-rpc/proto/ or proto/kit/common/, run this script from the
# repo root and commit the refreshed output.
#
# Requires protoc >= 27 on PATH, or in PROTOC (protobuf `edition = "2023"`
# support).

set -euo pipefail

cd "$(dirname "$0")/.."

GEN_DIR=rust/crates/kit-rpc/generated

cargo run --quiet --locked --manifest-path rust/Cargo.toml -p kit-rpc-codegen -- rpc

echo "refreshed $GEN_DIR:"
ls "$GEN_DIR"

# `git status --porcelain`, not only `git diff`: a new module lands untracked.
# The transport tree below generated/ has its own script.
if [ -n "$(git status --porcelain -- "$GEN_DIR" ":!$GEN_DIR/transport")" ]; then
    echo
    echo "generated output changed — review and commit:"
    git status --short -- "$GEN_DIR" ":!$GEN_DIR/transport"
else
    echo "generated output is unchanged."
fi

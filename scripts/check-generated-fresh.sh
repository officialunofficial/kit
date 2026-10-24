#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Fail when the checked-in protocol code differs from what the .proto files
# produce. The tree under rust/crates/kit-rpc/generated/ is checked in
# because the code generator needs `protoc` and the schemas use protobuf
# edition 2023 (see the README in that directory). This check keeps the copy
# honest: it regenerates the code and compares the result with the checked-in
# files.
#
# Needs `protoc` 27 or newer on PATH (or PROTOC) and the
# wasm32-unknown-unknown target. Run from any directory:
#   bash scripts/check-generated-fresh.sh

set -euo pipefail

cd "$(dirname "$0")/.."

dirs=(rust/crates/kit-rpc/generated)

# Digest of every file under the generated trees. The digest does not use git
# state, so the check also works with uncommitted edits.
digest() {
    find "${dirs[@]}" -type f -name '*.rs' -print0 | LC_ALL=C sort -z |
        xargs -0 shasum -a 256
}

before=$(digest)

bash scripts/regen-rpc-proto.sh >/dev/null
bash scripts/regen-transport-proto.sh >/dev/null

after=$(digest)

if [ "$before" != "$after" ]; then
    printf '::error::the checked-in generated code is stale. Run scripts/regen-rpc-proto.sh and scripts/regen-transport-proto.sh, then commit the result.\n' >&2
    diff <(printf '%s\n' "$before") <(printf '%s\n' "$after") >&2 || true
    exit 1
fi
echo 'generated code is fresh'

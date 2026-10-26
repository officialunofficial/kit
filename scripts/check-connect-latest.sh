#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Probe compatible Connect stack patches in a disposable checkout. Never commit
# the probe's rust/Cargo.lock changes or pin an older release to hide a failure.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root/rust"
export CARGO_BUILD_JOBS=3 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0
cargo_cmd=(cargo)
if [ "${KIT_CARGO_CACHED:-0}" = 1 ]; then
  cargo_cmd=(just --justfile "$root/justfile" --working-directory "$root" cargo-cached)
fi

# Fail early with a clear message when a tool is missing. The CI image has all
# of them. A bare machine needs them installed first. Cargo would otherwise
# exit with code 101 and a message that names no cause.
missing=()
command -v python3 >/dev/null 2>&1 \
  && python3 -c 'import tomllib' 2>/dev/null \
  || missing+=("python3 3.11 or newer")
"${cargo_cmd[@]}" nextest --version >/dev/null 2>&1 \
  || missing+=("cargo-nextest (cargo install cargo-nextest --locked)")
wasm_libdir="$(rustc --print target-libdir --target wasm32-unknown-unknown 2>/dev/null || true)"
[ -n "$wasm_libdir" ] && [ -d "$wasm_libdir" ] \
  || missing+=("the wasm32-unknown-unknown target (rustup target add wasm32-unknown-unknown)")
if [ "${#missing[@]}" -gt 0 ]; then
  echo "check-connect-latest: missing required tools:" >&2
  printf '  %s\n' "${missing[@]}" >&2
  echo "check-connect-latest: this probe also needs network access to the crate registry." >&2
  exit 2
fi

# Stay within the manifests' caret ranges; expose incompatible newer patches.
"${cargo_cmd[@]}" update --ignore-rust-version -p connectrpc -p connectrpc-build -p buffa -p buffa-build
python3 - <<'VERSIONS'
import tomllib
from pathlib import Path
lock = tomllib.loads(Path('Cargo.lock').read_text())
for package in lock['package']:
    if package['name'] in {'connectrpc', 'connectrpc-build', 'buffa', 'buffa-build'}:
        print(f"{package['name']} {package['version']}")
VERSIONS

crates=(-p kit-rpc -p kit-transport-connect -p kit-client)
features='kit-rpc/transport,kit-rpc/transport-messages'
"${cargo_cmd[@]}" build --locked "${crates[@]}" --features "$features"
"${cargo_cmd[@]}" nextest run --locked "${crates[@]}" --features "$features" -j 3
# Mirror both kit-client wasm builds in cloudbuild/ci.yaml.
"${cargo_cmd[@]}" build --locked -p kit-client --target wasm32-unknown-unknown
"${cargo_cmd[@]}" build --locked -p kit-client --no-default-features --target wasm32-unknown-unknown

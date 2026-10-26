#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Regenerate the public TLS test fixtures.
#
# The script makes a self-signed test CA and a localhost-only leaf
# certificate, then copies ca.crt, server.crt and server-pk8.der into the
# fixture directory of each crate that uses them. The CA private key lives in
# a temporary directory. The script deletes it on exit, so it is never
# committed. The leaf key is a test key and never a deployment credential.
#
# Usage:  bash scripts/gen-test-tls-fixtures.sh
# Needs:  openssl 3 or later.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
targets=(
  "${repo_root}/rust/crates/kit-cli/tests/support/fixtures/ca"
  "${repo_root}/rust/crates/kit-transport-connect/tests/fixtures/ca"
)
days=3650

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

openssl genrsa -out "${work}/ca.key" 2048 2>/dev/null
openssl req -x509 -new -key "${work}/ca.key" -sha256 -days "$days" \
  -subj "/CN=kit test CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "${work}/ca.crt"

openssl genrsa -out "${work}/server.key" 2048 2>/dev/null
openssl req -new -key "${work}/server.key" -subj "/CN=localhost" -out "${work}/server.csr"
printf '%s\n' \
  "basicConstraints=critical,CA:FALSE" \
  "keyUsage=critical,digitalSignature,keyEncipherment" \
  "extendedKeyUsage=serverAuth" \
  "subjectAltName=DNS:localhost" >"${work}/server.ext"
openssl x509 -req -in "${work}/server.csr" -CA "${work}/ca.crt" -CAkey "${work}/ca.key" \
  -CAcreateserial -sha256 -days "$days" -extfile "${work}/server.ext" \
  -out "${work}/server.crt" 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -inform PEM -outform DER \
  -in "${work}/server.key" -out "${work}/server-pk8.der"

for dir in "${targets[@]}"; do
  cp "${work}/ca.crt" "${work}/server.crt" "${work}/server-pk8.der" "$dir/"
done

openssl x509 -in "${work}/ca.crt" -noout -startdate -enddate

#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Download the pinned Apalache release into $FV_HOME. The script checks the
# sha256 of the release archive and of the jar, and does nothing when the
# verified jar is already there.
#
#   FV_HOME  install root (default: $HOME/.local/share/mkit-fv)
#
# The check.sh scripts under formal/quint find the jar at this path. TLC is
# the tlc2.TLC class inside the Apalache jar, so every Quint check needs it.
set -euo pipefail

version=0.62.2
tgz_sha256=765f610537281a0f25b8c30f2554f19523e2859c824e80e62276653ee23c10e2
jar_sha256=079b6c2320252469dcf79afec6886b8255d3dd1b34a9484433c88986752efaa8

fv=${FV_HOME:-$HOME/.local/share/mkit-fv}

sha256() {
  if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1
}

jar=$fv/apalache-$version/lib/apalache.jar
if [[ -f $jar && $(sha256 "$jar") == "$jar_sha256" ]]; then
  echo "Apalache $version already at $fv/apalache-$version"
  exit 0
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -sSfL -o "$tmp/a.tgz" \
  "https://github.com/apalache-mc/apalache/releases/download/v$version/apalache-$version.tgz"
[[ $(sha256 "$tmp/a.tgz") == "$tgz_sha256" ]] ||
  { echo "error: apalache-$version.tgz sha256 mismatch" >&2; exit 1; }
tar -xzf "$tmp/a.tgz" -C "$tmp"
[[ $(sha256 "$tmp/apalache-$version/lib/apalache.jar") == "$jar_sha256" ]] ||
  { echo "error: apalache.jar sha256 mismatch" >&2; exit 1; }
mkdir -p "$fv"
rm -rf "$fv/apalache-$version"
mv "$tmp/apalache-$version" "$fv/"
echo "Apalache $version installed at $fv/apalache-$version"

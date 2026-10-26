#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Print the Rust toolchain version that rust/rust-toolchain.toml pins.
#
# That file is the one source of the version. The image build, the setup
# script and the GitHub workflows call this script instead of repeating the
# number.
set -euo pipefail

file="$(dirname "${BASH_SOURCE[0]}")/../rust/rust-toolchain.toml"
version=$(sed -n 's/^channel = "\([0-9][0-9.]*\)"$/\1/p' "$file")
if [ -z "$version" ] || [ "$(printf '%s\n' "$version" | wc -l)" -ne 1 ]; then
  echo "$file does not pin one numeric channel." >&2
  exit 1
fi
printf '%s\n' "$version"

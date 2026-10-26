#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Dry-run the crates.io publish of the whole workspace. This script never
# publishes. The `--dry-run` flag is part of the command, and the script
# stops if it is missing.
#
#   bash scripts/check-publish.sh [--allow-dirty]
#
# `--allow-dirty` is for a local run on a tree with uncommitted changes. CI
# runs on a clean tree and passes no argument.
#
# Why `cargo publish --workspace --dry-run`: the kit crates depend on each
# other, and none of them is on the registry before the first release. A
# per-crate `cargo publish -p <crate> --dry-run` fails for that reason. Since
# Cargo 1.90, `--workspace` packages the crates in dependency order and
# verifies each one against the packaged copies of the others, as if they
# were published. This is the supported way to dry-run a workspace.
#
# The script then packs every crate and fails when one archive is larger than
# 5 MB. crates.io rejects an archive over 10 MB. The margin keeps a stray file
# from reaching that limit.

set -euo pipefail

cd "$(dirname "$0")/../rust"

max_bytes=$((5 * 1024 * 1024))

allow_dirty=()
case "$#:${1-}" in
    0:) ;;
    1:--allow-dirty) allow_dirty=(--allow-dirty) ;;
    *)
        echo "usage: check-publish.sh [--allow-dirty]" >&2
        exit 2
        ;;
esac

# A registry token must not be in reach of this check.
unset CARGO_REGISTRY_TOKEN CARGO_REGISTRIES_CRATES_IO_TOKEN

publish=(cargo publish --workspace --dry-run --locked ${allow_dirty[@]+"${allow_dirty[@]}"})
case " ${publish[*]} " in
    *" --dry-run "*) ;;
    *)
        echo "check-publish: the publish command has no --dry-run. Stop." >&2
        exit 1
        ;;
esac
"${publish[@]}"

# Pack every publishable crate without a build. The publish dry run above
# built them. `cargo package --workspace` also selects the members that have
# `publish = false`, so the script names the crates.
metadata=$(cargo metadata --format-version 1 --no-deps)
target_dir=$(printf '%s' "$metadata" | python3 -I -c \
    'import json, sys; print(json.load(sys.stdin)["target_directory"])')
packages=()
while IFS= read -r name; do
    packages+=(-p "$name")
done < <(printf '%s' "$metadata" | python3 -I -c '
import json, sys
for p in json.load(sys.stdin)["packages"]:
    if p["publish"] != []:
        print(p["name"])
')
if [ "${#packages[@]}" -eq 0 ]; then
    echo "check-publish: found no publishable crate" >&2
    exit 1
fi
rm -rf "$target_dir/package"
cargo package "${packages[@]}" --locked --no-verify ${allow_dirty[@]+"${allow_dirty[@]}"}

status=0
count=0
for archive in "$target_dir"/package/*.crate; do
    count=$((count + 1))
    size=$(wc -c < "$archive")
    printf '%s %s bytes\n' "$(basename "$archive")" "$size"
    if [ "$size" -gt "$max_bytes" ]; then
        printf '%s is larger than %s bytes\n' "$(basename "$archive")" "$max_bytes" >&2
        status=1
    fi
done

if [ "$count" -eq 0 ]; then
    echo "check-publish: found no packed crate" >&2
    exit 1
fi
exit "$status"

#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Record a samply CPU profile of the kit CLI or of a bench binary. The build
# uses the `profiling` cargo profile. The profile opens in the Firefox
# Profiler. The script answers "where does the time go". The criterion
# benches answer "how fast".
#
# Usage:
#   scripts/profile.sh [--features <list>] [-- <kit args>]          # CLI
#   scripts/profile.sh --bench <name> [--features <list>] [-- ...]  # bench
#
# Examples:
#   scripts/profile.sh -- status
#   scripts/profile.sh --bench pack_create
#
# Requires samply (cargo install samply). On Linux, recording needs a
# readable kernel.perf_event_paranoid. samply prints the exact sysctl when it
# is not. Lower that value. Do not run this script under sudo (see
# docs/PROFILING.md).

set -euo pipefail

cd "$(dirname "$0")/../rust"

command -v samply >/dev/null || {
    echo "samply not found. Install it with: cargo install samply" >&2
    exit 1
}

bench=""
features=""
# Script flags end at `--`. The arguments after it go to the profiled program.
while [ $# -gt 0 ]; do
    case "$1" in
        --bench)
            bench="${2:?--bench requires a bench name (for example pack_create)}"
            shift 2
            ;;
        -f | --features)
            features="${2:?--features requires a cargo feature list}"
            shift 2
            ;;
        --)
            shift
            break
            ;;
        *) break ;;
    esac
done

feature_args=()
[ -n "$features" ] && feature_args=(--features "$features")

# Print the path of a built artifact from the JSON output of cargo. The target
# name comes in argv, so it cannot change the Python program. This honors
# CARGO_TARGET_DIR and a configured target-dir.
artifact_path() {
    python3 -I -c '
import json, sys
want = sys.argv[1]
found = ""
for line in sys.stdin:
    try:
        obj = json.loads(line)
    except ValueError:
        continue
    if obj.get("executable") and obj.get("target", {}).get("name") == want:
        found = obj["executable"]
print(found)
' "$1" | tail -1
}

if [ -n "$bench" ]; then
    package=(-p kit-benches --bench "$bench")
    want="$bench"
else
    package=(-p kit-bin --bin kit)
    want="kit"
fi

echo ">> building ${want} (profile=profiling)" >&2
cargo build --locked --profile profiling "${package[@]}" ${feature_args[@]+"${feature_args[@]}"} >&2
# The second build is cached. It only reports the artifact path.
bin="$(cargo build --locked --profile profiling "${package[@]}" ${feature_args[@]+"${feature_args[@]}"} \
    --message-format=json 2>/dev/null | artifact_path "$want")"
if [ -z "$bin" ] || [ ! -x "$bin" ]; then
    echo "could not find the built binary for '${want}'" >&2
    exit 1
fi

if [ -n "$bench" ]; then
    echo ">> samply record $bin --bench $*" >&2
    exec samply record "$bin" --bench "$@"
fi
echo ">> samply record $bin $*" >&2
exec samply record "$bin" "$@"

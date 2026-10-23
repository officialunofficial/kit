#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Assert that the unsafe-expression count of each first-party crate, as
# reported by cargo-geiger, stays at or below a known ceiling. New `unsafe`
# in a crate must be a conscious choice. The change that adds it also
# raises the ceiling here, and the review thread then judges whether the
# `unsafe` is justified. scripts/check-unsafe-safety.sh separately checks
# that every site has a SAFETY comment.
#
# The ceiling counts unsafe EXPRESSIONS, not unsafe BLOCKS. One
# `unsafe { ... }` block usually holds several expressions. A refactor of a
# justified block can move the count a little. Change the ceiling in
# `ceiling_for()` and explain why in the same commit.
#
# Why two first-party crates have a non-zero count:
#   mkit-cli  - `getpwuid_r` in config::home_dir_for_euid. The header of
#               rust/crates/mkit-cli/src/lib.rs documents the exception.
#   mkit-core - two `#[allow(unsafe_code)]` sites, both documented in the
#               header of rust/crates/mkit-core/src/lib.rs: the
#               `libc::geteuid()` call in `sign::effective_uid`, and the
#               `libc::fcntl(.., F_BARRIERFSYNC)` call in
#               `batch::RealSyncer::file_barrier` on macOS and iOS.
#
# All other first-party crates MUST stay at 0.
#
# mkit-transport-memory is NOT in ceiling_for() or EXPECTED_CRATES: it is a
# dev-only dependency of mkit-cli, so geiger never reaches it from the
# normal dependency graph of the binary.
#
# The script is Bash 3.2 compatible, so it runs on macOS without a newer
# Bash.

set -euo pipefail

ceiling_for() {
    case "$1" in
        mkit-cli)               echo 23 ;;
        mkit-client)            echo 0  ;;
        mkit-core)              echo 3  ;;
        mkit-keystore)          echo 0  ;;
        mkit-attest)            echo 0  ;;
        mkit-rpc)               echo 0  ;;
        mkit-transport-file)    echo 0  ;;
        mkit-transport-s3)      echo 0  ;;
        mkit-transport-ssh)     echo 0  ;;
        mkit-transport-connect) echo 0  ;;
        mkit-git-bridge)        echo 0  ;;
        mkit-serve)             echo 0  ;;
        mkit-sync)              echo 0  ;;
        *)                      echo "UNKNOWN" ;;
    esac
}

# Every first-party crate that must appear in the geiger report. The check
# fails when one disappears, for example after a deletion or a change that
# makes it unreachable from mkit-cli.
EXPECTED_CRATES=(
    mkit-cli mkit-client mkit-core mkit-keystore mkit-attest mkit-rpc
    mkit-transport-file mkit-transport-s3 mkit-transport-ssh
    mkit-transport-connect mkit-git-bridge mkit-serve mkit-sync
)

# Features that bring optional first-party crates into the scan. Without
# `s3`, geiger would not see mkit-transport-s3 and the ceiling would be
# skipped. `git-bridge` is a default feature.
SCAN_FEATURES="s3,git-bridge"

# Run from mkit-cli: it depends on every other first-party crate that ships
# in the binary.
#
# The check fails closed. `cargo geiger` exits non-zero on a normal run
# ("error: Found N warnings": build-script outputs and data files it
# cannot scan), so its exit status says nothing alone. The run must print
# the report table with mkit-cli as its root, and every EXPECTED_CRATES
# entry must appear in it. Otherwise the script prints the geiger stderr and
# fails.
#
# cargo-geiger must be installed:
#   cargo install cargo-geiger --locked --version 0.13.0
# MKIT_SKIP_GEIGER=1 skips the check with a visible warning, for a machine
# without it. CI never sets it.
#
# geiger builds the crate graph with its own flags, so it gets its own
# target directory (`<target>/geiger`). Sharing target/debug with a test run
# in flight would rebuild, and could delete, the test binaries of that run.

rust_dir="$(cd "$(dirname "$0")/../rust" && pwd)"

if [ "${MKIT_SKIP_GEIGER:-}" = "1" ]; then
    printf '::warning::MKIT_SKIP_GEIGER=1: the unsafe-code ceiling was NOT checked.\n'
    exit 0
fi
if ! cargo geiger --version >/dev/null 2>&1; then
    printf '::error::cargo-geiger is not installed, so the unsafe-code ceiling cannot be checked.\n' >&2
    printf '   install it: cargo install cargo-geiger --locked --version 0.13.0\n' >&2
    printf '   (or set MKIT_SKIP_GEIGER=1 to skip the check explicitly).\n' >&2
    exit 1
fi

export CARGO_BUILD_TARGET_DIR="${CARGO_TARGET_DIR:-$rust_dir/target}/geiger"
stderr_file="$(mktemp "${TMPDIR:-/tmp}/geiger-stderr.XXXXXX")"
trap 'rm -f "$stderr_file"' EXIT

cd "$rust_dir/crates/mkit-cli"
# geiger 0.13.0 embeds Cargo 0.86. On a cold registry its pre-scan clean can
# request a package twice and panic before it reports any count. Fetch the
# complete locked graph with the workspace Cargo first, so geiger has no
# download to schedule. A fetch or scan failure still fails this gate.
cargo fetch --locked
geiger_status=0
OUTPUT=$(cargo geiger --quiet --color never --features "$SCAN_FEATURES" 2>"$stderr_file") ||
    geiger_status=$?

geiger_failed() {
    printf '::error::cargo geiger produced no usable report (%s; exit %s). Its stderr, without the per-file scan noise:\n' \
        "$1" "$geiger_status" >&2
    grep -v -e '^WARNING: Dependency file was never scanned' -e '^Failed to match' "$stderr_file" |
        tail -n 30 >&2 || true
    exit 1
}

# The header row of the report, and its root row (mkit-cli).
case "$OUTPUT" in
    *Functions*Expressions*) ;;
    *) geiger_failed "no report table" ;;
esac
# A here-string, not a pipe: `grep -q` exits at the first match, and under
# pipefail the SIGPIPE of the writer would fail the pipeline.
if ! grep -qE '^[0-9]+/[0-9]+ +[0-9]+/[0-9]+ .* mkit-cli [0-9]+\.[0-9]+\.[0-9]+' <<<"$OUTPUT"; then
    geiger_failed "no mkit-cli root row"
fi
# The only error a complete run may report is the warning count ("error:
# Found N warnings"). Any other `error:` line (a crate that failed to
# compile, a scan that aborted) fails the check even when a table was
# printed. So does a non-zero exit without the count line.
other_errors=$(grep -E '^error:' "$stderr_file" | grep -vE '^error: Found [0-9]+ warnings$' || true)
if [ -n "$other_errors" ]; then
    geiger_failed "an error other than the warning count"
fi
if [ "$geiger_status" -ne 0 ] && ! grep -qE '^error: Found [0-9]+ warnings$' "$stderr_file"; then
    geiger_failed "non-zero exit"
fi

FAIL=0
SEEN=""

# A cargo-geiger row, after the tree-drawing prefix:
#   used/total functions   used/total expressions   used/total impls   ...
#   used/total methods     STATUS   NAME VERSION
#
# Column 2 is the count of used unsafe expressions. It is compared with the
# ceiling.
while IFS= read -r line; do
    case "$line" in
        *" mkit-"*" "[0-9]*.[0-9]*.[0-9]*)
            name=$(printf '%s\n' "$line" | sed -nE 's/.* (mkit-[a-z0-9-]+) [0-9]+\.[0-9]+\.[0-9]+.*/\1/p')
            if [ -z "$name" ]; then
                continue
            fi
            case " $SEEN " in *" $name "*) continue ;; esac
            SEEN="$SEEN $name"

            counts=$(printf '%s\n' "$line" | awk '{print $2}')
            used="${counts%/*}"
            case "$used" in
                '' | *[!0-9]*)
                    printf '::error::could not read the unsafe-expression count of %s from: %s\n' "$name" "$line"
                    FAIL=1
                    continue
                    ;;
            esac

            ceiling=$(ceiling_for "$name")
            if [ "$ceiling" = "UNKNOWN" ]; then
                printf '::error::Unknown first-party crate %s (count=%s). Add it to ceiling_for and EXPECTED_CRATES in scripts/check-geiger-baseline.sh.\n' "$name" "$used"
                FAIL=1
                continue
            fi

            if [ "$used" -gt "$ceiling" ]; then
                printf '::error::%s has %s unsafe expressions, ceiling is %s\n' "$name" "$used" "$ceiling"
                printf '   review the new unsafe site. If it is justified, raise the ceiling in scripts/check-geiger-baseline.sh in the same commit.\n'
                FAIL=1
            elif [ "$used" -lt "$ceiling" ]; then
                printf '::notice::%s dropped from %s to %s unsafe expressions: lower the ceiling.\n' "$name" "$ceiling" "$used"
            fi
            ;;
    esac
done <<<"$OUTPUT"

# Catch a first-party crate that disappears from the geiger output.
for name in "${EXPECTED_CRATES[@]}"; do
    case " $SEEN " in
        *" $name "*) ;;
        *)
            printf '::error::Expected %s in the geiger output but did not see it. Either the crate left the mkit-cli graph (drop it from EXPECTED_CRATES and ceiling_for) or geiger could not reach it.\n' "$name"
            FAIL=1
            ;;
    esac
done

if [ "$FAIL" -eq 0 ]; then
    printf 'geiger baseline OK:%s\n' "$SEEN"
fi
exit "$FAIL"

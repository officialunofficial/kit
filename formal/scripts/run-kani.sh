#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Run every Kani harness, one at a time (about 1.5 h). The script finds the
# harnesses from the #[kani::proof] items in the files that
# formal/kani/README.md lists, so a new harness in one of them runs
# automatically. The flags follow that README.
#
#   KANI_FILTER=regex  run only the harnesses whose name matches
#   KANI_SKIP_LARGE=1  skip the harnesses in $large
#
# The harnesses run one at a time because each one can use many GB.
# The harnesses in $large need more than 14 GB, so a 16 GB runner cannot
# run them. The nightly job sets KANI_SKIP_LARGE=1. Run them by hand on a
# machine with at least 64 GB.
# Needs Kani 0.68.0: cargo install --locked kani-verifier --version 0.68.0
set -euo pipefail
cd "$(dirname "$0")/../../rust"

kv=$(cargo kani --version 2>/dev/null) ||
  { echo "error: cargo kani is missing (cargo install --locked kani-verifier --version 0.68.0 && cargo kani setup)" >&2; exit 2; }
kv=${kv%%$'\n'*}
[[ $kv == *" 0.68.0 "* ]] || { echo "error: $kv, the pin is Kani 0.68.0" >&2; exit 2; }

files="crates/kit-core/src/delta.rs crates/kit-core/src/merkle.rs crates/kit-core/src/pack.rs
  crates/kit-core/src/serialize.rs crates/kit-keystore/src/encrypted_record.rs crates/kit-rpc/src/framing.rs"

harnesses() {
  awk '/#\[kani::proof\]/{p=1} p && /fn [a-z0-9_]+/{match($0,/fn [a-z0-9_]+/); print substr($0,RSTART+3,RLENGTH-3); p=0}' "$1"
}

large="delta_spec_copy pack_entries_one_frame pack_entries_two_entries pack_writer_roundtrip_raw
  pack_window_cursor_decode pack_window_cursor_flip_rejected pack_window_cursor_canary_flip_accepted"

failed=()
n=0
skipped=0
# run LABEL ARGS...: one cargo kani run with the given arguments.
run() {
  local label=$1 t0=$SECONDS out
  shift
  n=$((n + 1))
  if out=$(cargo kani "$@" 2>&1) && grep -q 'VERIFICATION:- SUCCESSFUL' <<<"$out" &&
    ! grep -q 'VERIFICATION:- FAILED' <<<"$out"; then
    printf '%-64s ok %ss\n' "$label" "$((SECONDS - t0))"
  else
    printf '%-64s UNEXPECTED %ss\n' "$label" "$((SECONDS - t0))"
    tail -n 40 <<<"$out"
    failed+=("$label")
  fi
}

for f in $files; do
  crate=$(cut -d/ -f2 <<<"$f")
  for h in $(harnesses "$f"); do
    [[ -n ${KANI_FILTER:-} && ! $h =~ $KANI_FILTER ]] && continue
    if [[ -n ${KANI_SKIP_LARGE:-} && " $(echo $large) " == *" $h "* ]]; then
      skipped=$((skipped + 1))
      continue
    fi
    case $crate:$h in
      kit-core:merkle_verify_* | kit-core:merkle_roundtrip_* | kit-core:merkle_canary_* | kit-core:pack_*)
        run "$crate::$h" -p "$crate" --no-default-features -Z stubbing --harness "$h" \
          -Z unstable-options --cbmc-args --unwindset memcmp.0:33 ;;
      kit-core:*)
        run "$crate::$h" -p "$crate" --no-default-features -Z stubbing --harness "$h" ;;
      kit-keystore:*)
        run "$crate::$h" -p "$crate" -Z stubbing --harness "$h" ;;
      *)
        run "$crate::$h" -p "$crate" --harness "$h" ;;
    esac
  done
done

echo "run-kani: $n runs, ${#failed[@]} unexpected, $skipped large skipped"
if ((${#failed[@]})); then
  printf '  %s\n' "${failed[@]}" >&2
  exit 1
fi

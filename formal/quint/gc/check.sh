#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
cd "$(dirname "$0")"

quint test maintenance.qnt --main=checked --backend=typescript
quint test maintenance.qnt --main=skipRootCheck --backend=typescript
quint run maintenance.qnt --main=checked --invariant=noLiveObjectLost \
  --max-steps=12 --max-samples=2000 --seed=0x1 --backend=typescript --verbosity=1

# Copy-then-retire: the conforming model keeps both invariants.
for inv in noLiveObjectLost graceKept; do
  quint run copy_retire.qnt --main=copyRetire --invariant="$inv" \
    --max-steps=8 --max-samples=5000 --seed=0x1 --backend=typescript --verbosity=1
done
# Each mutant must violate the invariant it targets.
expect_violation() {
  local main=$1 inv=$2
  if quint run copy_retire.qnt --main="$main" --invariant="$inv" \
    --max-steps=8 --max-samples=5000 --seed=0x1 --backend=typescript --verbosity=1 >/dev/null; then
    echo "mutant $main did not violate $inv" >&2
    exit 1
  fi
}
expect_violation relyOnRetired noLiveObjectLost
expect_violation skipFlush noLiveObjectLost
expect_violation graceByCover graceKept
echo "all checks as expected"

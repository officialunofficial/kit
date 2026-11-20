#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
cd "$(dirname "$0")"

quint test maintenance.qnt --main=checked --backend=typescript
quint test maintenance.qnt --main=skipRootCheck --backend=typescript
quint run maintenance.qnt --main=checked --invariant=noLiveObjectLost \
  --max-steps=12 --max-samples=2000 --seed=0x1 --backend=typescript --verbosity=1
echo "all checks as expected"

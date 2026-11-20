#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
cd "$(dirname "$0")"

quint test maintenance.qnt --main=checked
quint test maintenance.qnt --main=skipRootCheck
quint verify maintenance.qnt --main=checked --step=step --invariant=noLiveObjectLost --max-steps=12
echo "all checks as expected"

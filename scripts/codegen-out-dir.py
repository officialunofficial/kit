#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Find a marked codegen OUT_DIR in Cargo's JSON build messages."""

import json
from pathlib import Path
import sys

out_dir = None
for line in sys.stdin:
    message = json.loads(line)
    if message.get("reason") == "build-script-executed":
        candidate = message["out_dir"]
        if (Path(candidate) / sys.argv[1]).is_file():
            out_dir = candidate
if out_dir is None:
    sys.exit("error: Cargo reported no marked codegen output")
print(out_dir)

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Check Cargo output selection with configured paths and cached messages."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

script = Path(__file__).with_name("codegen-out-dir.py")
with tempfile.TemporaryDirectory() as work:
    root = Path(work)
    out = root / "custom build" / "wasm32-unknown-unknown/debug/build/kit-rpc-hash/out"
    out.mkdir(parents=True)
    (out / ".codegen").touch()
    messages = [
        {"reason": "compiler-artifact", "fresh": True},
        {"reason": "build-script-executed", "out_dir": str(root)},
        {"reason": "build-script-executed", "out_dir": str(out)},
        {"reason": "build-finished", "success": True},
    ]
    result = subprocess.run([sys.executable, str(script), ".codegen"],
        input="".join(json.dumps(message) + "\n" for message in messages),
        text=True, capture_output=True, check=True)
    assert result.stdout.strip() == str(out)
    result = subprocess.run([sys.executable, str(script), ".absent"],
        input=json.dumps(messages[1]) + "\n", text=True, capture_output=True)
    assert result.returncode != 0
print("codegen output selection passed")

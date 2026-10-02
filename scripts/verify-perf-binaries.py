#!/usr/bin/env python3
"""Verify shared performance binaries before any measurement starts."""

import hashlib
import json
import os
from pathlib import Path
import subprocess

manifest = json.loads(Path("target/perf/binaries.json").read_text())
if manifest["commit"] != os.environ["GITHUB_SHA"]:
    raise SystemExit("measurement binary revision mismatch")
if manifest["rustc"] != subprocess.check_output(["rustc", "-Vv"], text=True).strip():
    raise SystemExit("measurement compiler mismatch")
binaries = manifest["binaries"]
if "candidate" not in binaries:
    raise SystemExit("candidate measurement binary is missing")
if manifest["baseline_commit"] and "baseline" not in binaries:
    raise SystemExit("baseline measurement binary is missing")
for binary in binaries.values():
    path = Path(binary["path"])
    if not os.access(path, os.X_OK) or hashlib.sha256(path.read_bytes()).hexdigest() != binary["sha256"]:
        raise SystemExit("measurement binary checksum or executable permission mismatch")
print("sha=" + (manifest["baseline_commit"] or ""))

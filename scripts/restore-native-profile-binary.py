#!/usr/bin/env python3
"""Restore the exact retained native executable for offline CPU report decoding."""

import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile

profile, workspace, source_path = map(Path, sys.argv[1:])
workspace = workspace.resolve()
metadata = json.loads((profile / "binary.json").read_text())
source = json.loads(source_path.read_text())
if (source.get("status") != "completed"
        or re.fullmatch(r"[0-9a-f]{40}", source.get("head_sha", "")) is None):
    raise SystemExit("native profile source requires a completed exact revision")
logs = workspace / "target/perf/streaming-compare-logs"
for role in ("qpxd", "lighttpd"):
    for mode in ("fast", "slow"):
        transfers = 64 if mode == "fast" else 1
        for round_number in range(1, 4):
            path = logs / f"streaming.{role}.{mode}.round-{round_number}.valid-samples.jsonl"
            records = [json.loads(line) for line in path.read_text().splitlines()]
            if (len(records) != 1 or records[0].get("valid") is not True
                    or records[0].get("proxy") != role or records[0].get("read_mode") != mode
                    or records[0].get("transfers") != transfers
                    or records[0].get("bytes") != transfers * 104857600):
                raise SystemExit(f"native source lacks a complete owned workload: {path}")
destination = workspace / "target/callgrind/qpxd"
if (metadata.get("artifact") != "qpxd.elf.gz"
        or metadata.get("format") != "ELF" or metadata.get("compression") != "gzip"
        or metadata.get("source") != str(destination)
        or re.fullmatch(r"[0-9a-f]{64}", metadata.get("sha256", "")) is None
        or not isinstance(metadata.get("uncompressed_bytes"), int)
        or metadata["uncompressed_bytes"] <= 0):
    raise SystemExit("retained native executable metadata is invalid")
destination.parent.mkdir(parents=True, exist_ok=True)
size = 0
checksum = hashlib.sha256()
fd, temporary_name = tempfile.mkstemp(prefix="native-executable-", dir=destination.parent)
temporary = Path(temporary_name)
try:
    with os.fdopen(fd, "wb") as output, gzip.open(profile / metadata["artifact"], "rb") as archive:
        magic = archive.read(4)
        if magic != b"\x7fELF":
            raise SystemExit("retained native executable is not ELF")
        chunk = magic
        while chunk:
            output.write(chunk)
            checksum.update(chunk)
            size += len(chunk)
            if size > metadata["uncompressed_bytes"]:
                raise SystemExit("retained native executable exceeds its recorded size")
            chunk = archive.read(1024 * 1024)
    if size != metadata["uncompressed_bytes"] or checksum.hexdigest() != metadata["sha256"]:
        raise SystemExit("retained native executable identity does not match recording")
    temporary.chmod(0o750)
    temporary.replace(destination)
finally:
    temporary.unlink(missing_ok=True)
(workspace / "target/perf/native-profile-analysis.json").write_text(json.dumps({
    "source_run": source["id"], "source_commit": source["head_sha"],
    "source_conclusion": source["conclusion"], "source_url": source["html_url"],
    "analysis_commit": os.environ["GITHUB_SHA"],
    "analysis_run": os.environ["GITHUB_RUN_ID"],
    "executable_sha256": checksum.hexdigest(),
    "replaces_required_gate": False,
}, indent=2) + "\n")
print("Retained native executable restored with verified SHA-256")

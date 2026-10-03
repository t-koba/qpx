#!/usr/bin/env python3
"""Retain real load-generator CPU reports, including invalid profiles."""

import json
from pathlib import Path
import re
import subprocess
import sys


def main():
    root = Path(sys.argv[1])
    profiler = sys.argv[2]
    profiles = []
    for path in sorted(root.glob("*.lifecycle.json")):
        record = json.loads(path.read_text())
        errors = []
        if (record.get("mode") != "client-cpu"
                or record.get("forced_shutdown") is not False
                or record.get("requested_signal") is not None
                or record.get("exit_status") != 0):
            errors.append("load generator did not complete cleanly")
        data = root / f"{record['role']}.data"
        report = data.with_suffix(".data.report.txt")
        if not data.is_file():
            errors.append("CPU profile is missing")
        else:
            with report.open("w") as output:
                try:
                    result = subprocess.run(
                        [profiler, "report", "--stdio", "--header", "--no-children",
                         "--call-graph", "none", "--sort", "symbol", "--percent-limit", "0.5",
                         "-i", str(data)], stdout=output, stderr=subprocess.STDOUT,
                        timeout=180, check=False,
                    )
                    if result.returncode != 0:
                        errors.append(f"CPU report exited with status {result.returncode}")
                except subprocess.TimeoutExpired:
                    errors.append("CPU report timed out")
            contents = report.read_text()
            lost = re.findall(r"^# Total Lost Samples:\s+(\d+)\s*$", contents, re.MULTILINE)
            if len(lost) != 1 or int(lost[0]) != 0:
                errors.append("CPU profile has missing or lost samples")
            if not re.search(r"^# Samples: [1-9]", contents, re.MULTILINE):
                errors.append("CPU profile contains no samples")
        profiles.append({"lifecycle": record, "report": report.name,
                         "valid": not errors, "errors": errors})
    valid = bool(profiles) and all(row["valid"] for row in profiles)
    summary = {"measurement": "real_http2_client_cpu_profiles_v1",
               "replaces_required_gate": False, "valid": valid, "profiles": profiles}
    (root / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"Real client CPU profiles: count={len(profiles)} valid={valid}")
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())

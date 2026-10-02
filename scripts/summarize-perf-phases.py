#!/usr/bin/env python3
"""Summarize sampled phase durations from real diagnostic server logs."""

import collections
import json
from pathlib import Path
import statistics
import sys

root, output = map(Path, sys.argv[1:])
samples = collections.defaultdict(list)
for path in sorted(root.rglob("*.log")):
    for line in path.open(errors="strict"):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("target") != "qpx_perf_phase":
            continue
        fields = record.get("fields", record)
        if fields.get("message") != "performance phase completed":
            continue
        elapsed = fields["elapsed_ns"]
        if not isinstance(elapsed, int) or elapsed < 0:
            raise SystemExit(f"invalid phase duration in {path}")
        samples[(str(path.relative_to(root)), fields["phase"], fields["sample_interval"])].append(elapsed)
if not samples:
    raise SystemExit("diagnostic server logs contain no sampled phase timings")
records = []
for (source, phase, interval), values in sorted(samples.items()):
    values.sort()
    records.append({
        "source": source, "phase": phase, "sample_interval": interval,
        "samples": len(values), "median_ns": statistics.median(values),
        "p99_ns": values[min(len(values) - 1, (99 * len(values)) // 100)],
        "max_ns": values[-1],
    })
output.write_text(json.dumps(records, indent=2, sort_keys=True) + "\n")
for record in records:
    print(f"{record['source']} {record['phase']}: samples={record['samples']} "
          f"median_us={record['median_ns'] / 1000:.3f} p99_us={record['p99_ns'] / 1000:.3f}")

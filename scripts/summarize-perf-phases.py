#!/usr/bin/env python3
"""Summarize sampled phase durations from real diagnostic server logs."""

import collections
import json
from pathlib import Path
import statistics
import sys

root, output = map(Path, sys.argv[1:])
samples = collections.defaultdict(list)
socket_samples = collections.defaultdict(list)
for path in sorted(root.rglob("*.log")):
    for line in path.open(errors="strict"):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("target") != "qpx_perf_phase":
            continue
        fields = record.get("fields", record)
        message = fields.get("message")
        if message == "file socket queue sampling failed":
            raise SystemExit(f"TCP send queue measurement failed in {path}: {fields.get('error')}")
        if message == "file socket queue sampled":
            queued, unsent = fields["queued_bytes"], fields["unsent_bytes"]
            if not all(isinstance(value, int) and value >= 0 for value in (queued, unsent)) or unsent > queued:
                raise SystemExit(f"invalid TCP send queue measurement in {path}")
            key = (str(path.relative_to(root)), fields["body_bytes"], fields["sample_interval"])
            socket_samples[key].append((queued, unsent))
            continue
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
socket_records = []
for (source, body_bytes, interval), values in sorted(socket_samples.items()):
    record = {"source": source, "body_bytes": body_bytes, "sample_interval": interval, "samples": len(values)}
    for index, metric in enumerate(("queued_bytes", "unsent_bytes")):
        measurements = sorted(value[index] for value in values)
        record[metric] = {"median": statistics.median(measurements),
                          "p99": measurements[min(len(measurements) - 1, (99 * len(measurements)) // 100)],
                          "max": measurements[-1]}
    socket_records.append(record)
output.with_name("socket-queue-summary.json").write_text(json.dumps(socket_records, indent=2, sort_keys=True) + "\n")
for record in records:
    print(f"{record['source']} {record['phase']}: samples={record['samples']} "
          f"median_us={record['median_ns'] / 1000:.3f} p99_us={record['p99_ns'] / 1000:.3f}")

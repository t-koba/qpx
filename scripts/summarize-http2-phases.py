#!/usr/bin/env python3
"""Separate real HTTP/2 phase samples by the recorded workload boundaries."""

import datetime
import json
from pathlib import Path
import re
import statistics
import sys

root, output = map(Path, sys.argv[1:])
phases = {"h2_service_dispatch", "h2_response_queue", "plain_origin_acquire",
          "plain_origin_headers", "plain_origin_materialize"}
clock_tolerance_ns = 1_000_000
samples = []
for line in (root / "qpxd-h2.log").read_text().splitlines():
    record = json.loads(line)
    if record.get("target") != "qpx_perf_phase":
        continue
    fields = record["fields"]
    if fields.get("phase") not in phases:
        continue
    if fields.get("message") != "performance phase completed":
        raise SystemExit("HTTP/2 phase log has an unexpected event")
    if type(fields["elapsed_ns"]) is not int or fields["elapsed_ns"] < 0:
        raise SystemExit("HTTP/2 phase log has an invalid duration")
    stamp = datetime.datetime.fromisoformat(record["timestamp"].replace("Z", "+00:00"))
    if stamp.utcoffset() != datetime.timedelta(0):
        raise SystemExit("HTTP/2 phase timestamp must be UTC")
    delta = stamp - datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
    epoch_ns = (delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000
    samples.append((epoch_ns, fields))

records = []
pattern = re.compile(r"http2\.qpxd\.1024\.m100\.round-(\d+)\.attempt-1\.scheduler-before\.json")
windows = []
for before_path in sorted(root.glob("http2.qpxd.1024.m100.round-*.attempt-1.scheduler-before.json")):
    match = pattern.fullmatch(before_path.name)
    if match is None:
        raise SystemExit("HTTP/2 phase window has an unsupported filename")
    before = json.loads(before_path.read_text())
    after = json.loads(before_path.with_name(before_path.name.replace("scheduler-before", "scheduler-after")).read_text())
    if before["root_pid"] != after["root_pid"]:
        raise SystemExit("HTTP/2 phase window changed process identity")
    offsets = []
    for snapshot in (before, after):
        for edge in ("started", "finished"):
            keys = [f"{edge}_epoch_ns", f"{edge}_monotonic_ns", f"{edge}_clock_end_monotonic_ns"]
            if any(type(snapshot.get(key)) is not int or snapshot[key] <= 0 for key in keys):
                raise SystemExit("HTTP/2 phase window lacks real clock correlation bounds")
            epoch, lower, upper = (snapshot[key] for key in keys)
            if not 0 <= upper - lower <= clock_tolerance_ns:
                raise SystemExit("HTTP/2 phase clock sampling uncertainty exceeds 1 ms")
            offsets.append((epoch - upper, epoch - lower))
    if max(lower for lower, _ in offsets) - min(upper for _, upper in offsets) > clock_tolerance_ns:
        raise SystemExit("HTTP/2 phase wall-clock drift exceeds 1 ms")
    lower, upper = before["finished_epoch_ns"], after["started_epoch_ns"]
    if lower >= upper:
        raise SystemExit("HTTP/2 phase window is empty or reversed")
    windows.append((lower, upper))
    for phase in sorted(phases):
        selected = [fields for epoch, fields in samples if lower <= epoch <= upper and fields["phase"] == phase]
        if len(selected) < 16 or any(fields["sample_interval"] != 1024 for fields in selected):
            raise SystemExit(f"HTTP/2 phase window {match[1]} / {phase} lacks sufficient 1-in-1024 samples")
        values = sorted(fields["elapsed_ns"] for fields in selected)
        records.append({"body_bytes": 1024, "max_concurrent_streams": 100,
                        "round": int(match[1]), "phase": phase, "samples": len(values),
                        "sample_interval": 1024, "median_ns": statistics.median(values),
                        "p99_ns": values[min(len(values) - 1, (99 * len(values)) // 100)],
                        "max_ns": values[-1], "window_start_epoch_ns": lower,
                        "window_end_epoch_ns": upper, "clock_tolerance_ns": clock_tolerance_ns})
if len(windows) != 3 or {record["round"] for record in records} != {1, 2, 3}:
    raise SystemExit("HTTP/2 phase diagnostics require three timed rounds")
windows.sort()
if any(a[1] >= b[0] for a, b in zip(windows, windows[1:])):
    raise SystemExit("HTTP/2 phase measurement windows overlap")
output.write_text(json.dumps(records, indent=2, sort_keys=True) + "\n")
for record in records:
    print(f"HTTP/2 1024-byte m=100 round={record['round']} {record['phase']}: "
          f"samples={record['samples']} median_us={record['median_ns'] / 1000:.3f} "
          f"p99_us={record['p99_ns'] / 1000:.3f}")

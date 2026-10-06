#!/usr/bin/env python3
"""Summarize sampled phase durations from real diagnostic server logs."""

import collections
import json
from pathlib import Path
import statistics
import sys

root, output = map(Path, sys.argv[1:])
samples = collections.defaultdict(list)
poll_samples = collections.defaultdict(list)
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
            pending, yields = fields["io_pending_polls"], fields["explicit_yields"]
            if not all(type(value) is int and value >= 0 for value in (pending, yields)):
                raise SystemExit(f"invalid file-body scheduling measurement in {path}")
            socket_samples[key].append((queued, unsent, pending, yields))
            continue
        if fields.get("message") != "performance phase completed":
            continue
        elapsed = fields["elapsed_ns"]
        if not isinstance(elapsed, int) or elapsed < 0:
            raise SystemExit(f"invalid phase duration in {path}")
        key = (str(path.relative_to(root)), fields["phase"], fields["sample_interval"])
        samples[key].append(elapsed)
        counters = {name: fields[name] for name in (
            "polls", "pending_polls", "active_poll_ns", "max_active_poll_ns",
            "before_notify_ns", "notified_wait_ns", "unnotified_wait_ns",
            "notified_resumptions")}
        if not all(type(value) is int and value >= 0 for value in counters.values()):
            raise SystemExit(f"invalid phase poll counter in {path}")
        if counters["polls"]:
            if (counters["pending_polls"] >= counters["polls"]
                    or counters["notified_resumptions"] > counters["pending_polls"]
                    or counters["max_active_poll_ns"] > counters["active_poll_ns"]
                    or sum(counters[name] for name in (
                        "active_poll_ns", "before_notify_ns", "notified_wait_ns",
                        "unnotified_wait_ns")) > elapsed):
                raise SystemExit(f"inconsistent phase poll accounting in {path}")
            counters["outside_poll_ns"] = elapsed - counters["active_poll_ns"]
            poll_samples[key].append(counters)
        elif fields["phase"] == "file_body_send":
            raise SystemExit(f"file-body phase lacks observed future polls in {path}")
if not samples:
    raise SystemExit("diagnostic server logs contain no sampled phase timings")
records = []
for (source, phase, interval), values in sorted(samples.items()):
    values.sort()
    record = {
        "source": source, "phase": phase, "sample_interval": interval,
        "samples": len(values), "median_ns": statistics.median(values),
        "p99_ns": values[min(len(values) - 1, (99 * len(values)) // 100)],
        "max_ns": values[-1],
    }
    observed = poll_samples[(source, phase, interval)]
    if observed:
        record["observed_future_samples"] = len(observed)
        for metric in observed[0]:
            measurements = sorted(sample[metric] for sample in observed)
            record[metric] = {
                "median": statistics.median(measurements),
                "p99": measurements[min(len(measurements) - 1, (99 * len(measurements)) // 100)],
                "max": measurements[-1],
            }
    records.append(record)
output.write_text(json.dumps(records, indent=2, sort_keys=True) + "\n")
socket_records = []
for (source, body_bytes, interval), values in sorted(socket_samples.items()):
    record = {"source": source, "body_bytes": body_bytes, "sample_interval": interval, "samples": len(values)}
    for index, metric in enumerate(("queued_bytes", "unsent_bytes", "io_pending_polls", "explicit_yields")):
        measurements = sorted(value[index] for value in values)
        record[metric] = {"median": statistics.median(measurements),
                          "p99": measurements[min(len(measurements) - 1, (99 * len(measurements)) // 100)],
                          "max": measurements[-1]}
    socket_records.append(record)
output.with_name("socket-queue-summary.json").write_text(json.dumps(socket_records, indent=2, sort_keys=True) + "\n")
for record in records:
    print(f"{record['source']} {record['phase']}: samples={record['samples']} "
          f"median_us={record['median_ns'] / 1000:.3f} p99_us={record['p99_ns'] / 1000:.3f}")
    if record.get("observed_future_samples"):
        print(f"{record['source']} {record['phase']}: "
              f"active_poll_median_us={record['active_poll_ns']['median'] / 1000:.3f} "
              f"before_notify_median_us={record['before_notify_ns']['median'] / 1000:.3f} "
              f"notified_wait_median_us={record['notified_wait_ns']['median'] / 1000:.3f} "
              f"unnotified_wait_median_us={record['unnotified_wait_ns']['median'] / 1000:.3f}")

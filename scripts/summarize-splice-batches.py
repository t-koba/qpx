#!/usr/bin/env python3
"""Validate and summarize real native streaming splice transfer counters."""

import json
from pathlib import Path
import sys

source, output = map(Path, sys.argv[1:])
records = []
for line in source.read_text().splitlines():
    if not line.startswith("{"):
        continue
    event = json.loads(line)
    if event.get("target") != "qpx_perf_splice":
        continue
    record = event["fields"]
    if record.get("message") != "splice transfer counters completed":
        raise SystemExit("splice counter log has an unexpected event")
    fields = ("planned_bytes", "pipe_capacity", "socket_batch_limit",
              "source_batches", "destination_batches", "source_bytes", "destination_bytes",
              "source_max_batch", "destination_max_batch", "source_batches_over_socket_limit",
              "destination_short_batches", "source_would_block", "destination_would_block")
    if any(type(record.get(field)) is not int or record[field] < 0 for field in fields):
        raise SystemExit("splice counter log has invalid integer counters")
    if record["planned_bytes"] < 104857600 - 65536:
        continue
    if record["planned_bytes"] > 104857600:
        raise SystemExit("splice counters exceed the native streaming transfer size")
    if record.get("completed") is not True or any(
            record[field] != record["planned_bytes"] for field in ("source_bytes", "destination_bytes")):
        raise SystemExit("native streaming splice counters contain an incomplete transfer")
    if (record["source_batches"] == 0 or record["destination_batches"] == 0
            or not 0 < record["source_max_batch"] <= record["pipe_capacity"]
            or not 0 < record["destination_max_batch"] <= record["socket_batch_limit"]
            or record["source_batches_over_socket_limit"] > record["source_batches"]
            or record["destination_short_batches"] > record["destination_batches"]):
        raise SystemExit("native streaming splice counters violate transfer bounds")
    records.append(record)
if len(records) != 195:
    raise SystemExit(f"native streaming splice counters require 192 fast and 3 slow transfers; observed {len(records)}")
source_batches = sum(record["source_batches"] for record in records)
destination_batches = sum(record["destination_batches"] for record in records)
summary = {
    "measurement": "native_streaming_splice_counters_v1",
    "diagnostic_instrumentation": True,
    "completed_transfers": len(records),
    "pipe_capacities": sorted({record["pipe_capacity"] for record in records}),
    "socket_batch_limits": sorted({record["socket_batch_limit"] for record in records}),
    "source_batches": source_batches,
    "destination_batches": destination_batches,
    "mean_source_batch_bytes": sum(record["source_bytes"] for record in records) / source_batches,
    "mean_destination_batch_bytes": sum(record["destination_bytes"] for record in records) / destination_batches,
    "source_batches_over_socket_limit": sum(record["source_batches_over_socket_limit"] for record in records),
    "destination_short_batch_fraction": sum(record["destination_short_batches"] for record in records) / destination_batches,
    "source_would_block": sum(record["source_would_block"] for record in records),
    "destination_would_block": sum(record["destination_would_block"] for record in records),
}
output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
print(json.dumps(summary, sort_keys=True))

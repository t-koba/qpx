#!/usr/bin/env python3
"""Report observed WebDAV TCP segment density from real Linux socket samples."""

import json
from pathlib import Path
import re
import statistics
import sys

root, destination = map(Path, sys.argv[1:])
reports = []
covered = set()
for path in sorted(root.glob("*.threads.csv.sockets.jsonl")):
    lane = re.fullmatch(r"origin_webdav_http1\.(qpxd-webdav|apache-webdav)\.(1024|1048576)\.round-(\d+)\.attempt-\d+\.wrk\.threads\.csv\.sockets\.jsonl", path.name)
    if not lane:
        raise SystemExit(f"unexpected socket diagnostic workload: {path.name}")
    densities, mss_values, queues = [], [], []
    previous = 0
    for line in path.read_text().splitlines():
        sample = json.loads(line)
        if not previous < sample["monotonic_ns"] <= sample["finished_monotonic_ns"]:
            raise SystemExit(f"invalid socket sample timing: {path.name}")
        previous = sample["finished_monotonic_ns"]
        process_ids = set(sample["process_ids"])
        if sample["root_pid"] not in process_ids:
            raise SystemExit(f"socket sample lost its owned process tree: {path.name}")
        owned = False
        for raw in sample["raw"].splitlines():
            if "users:" in raw or re.search(r"\b127\.0\.0\.1:\d+", raw):
                owned = bool(process_ids & {int(pid) for pid in re.findall(r"pid=(\d+)", raw)})
                continue
            if not owned:
                continue
            fields = {key: int(value) for key, value in re.findall(
                r"\b(bytes_sent|data_segs_out|mss|notsent):(\d+)\b", raw)}
            if fields.get("bytes_sent", 0) > 0 and fields.get("data_segs_out", 0) > 0:
                if "mss" not in fields:
                    raise SystemExit(f"socket sample lacks TCP MSS: {path.name}")
                densities.append(fields["bytes_sent"] / fields["data_segs_out"])
                mss_values.append(fields["mss"])
                if "notsent" in fields:
                    queues.append(fields["notsent"])
    if not densities:
        raise SystemExit(f"socket samples lack attributed TCP traffic: {path.name}")
    covered.add((lane[1], int(lane[2]), int(lane[3])))
    reports.append({"source": path.name, "proxy": lane[1], "body_bytes": int(lane[2]),
                    "round": int(lane[3]), "connection_observations": len(densities),
                    "median_bytes_per_data_segment": statistics.median(densities),
                    "minimum_bytes_per_data_segment": min(densities),
                    "maximum_bytes_per_data_segment": max(densities),
                    "median_tcp_mss": statistics.median(mss_values),
                    "socket_queue_observations": len(queues),
                    "maximum_notsent_bytes": max(queues) if queues else None,
                    "scope": "diagnostic_observed_active_connections"})
expected = {(role, size, repetition) for role in ("qpxd-webdav", "apache-webdav")
            for size in (1024, 1048576) for repetition in (1, 2, 3)}
if not expected <= covered:
    raise SystemExit(f"missing socket diagnostic workloads: {sorted(expected - covered)}")
destination.write_text(json.dumps(reports, indent=2, sort_keys=True) + "\n")
for report in reports:
    print(f"{report['source']}: median bytes per data segment "
          f"{report['median_bytes_per_data_segment']:.3f}; "
          f"TCP MSS {report['median_tcp_mss']:.0f}")

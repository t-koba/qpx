#!/usr/bin/env python3
"""Summarize real writeback counters without treating collection as persistence."""

from decimal import Decimal, InvalidOperation
import json
from pathlib import Path
import re
import sys

root, output = map(Path, sys.argv[1:])


def counter(path, name, required):
    matches = re.findall(rf"^{re.escape(name)}\s+([^\s]+)$", path.read_text(), re.MULTILINE)
    if not matches:
        if required:
            raise SystemExit(f"Missing initialized writeback counter {name} in {path}")
        # The recorder creates this counter on its first rejection.
        return 0, False
    if len(matches) != 1:
        raise SystemExit(f"Ambiguous writeback counter {name} in {path}")
    try:
        value = Decimal(matches[0])
    except InvalidOperation as error:
        raise SystemExit(f"Invalid writeback counter {name} in {path}") from error
    if not value.is_finite() or value < 0 or value != value.to_integral_value():
        raise SystemExit(f"Invalid writeback counter {name} in {path}")
    return int(value), True


records = []
miss_samples = 0
before_paths = sorted(root.glob("*.writeback.before.prom"))
if not before_paths:
    raise SystemExit("No real writeback counter snapshots were retained")
if len(list(root.glob("*.writeback.after.prom"))) != len(before_paths):
    raise SystemExit("Writeback counter snapshot pairs are incomplete")
for before in before_paths:
    prefix = before.name.removesuffix(".writeback.before.prom")
    after = root / f"{prefix}.writeback.after.prom"
    wrk = root / f"{prefix}.wrk"
    if not after.is_file() or not wrk.is_file():
        raise SystemExit(f"Incomplete real writeback workload evidence: {prefix}")
    match = re.search(r"^qpx_complete_requests (\d+)$", wrk.read_text(), re.MULTILINE)
    if not match or int(match[1]) == 0:
        raise SystemExit(f"Missing completed frontend requests: {wrk}")
    record = {"sample": prefix, "completed_frontend_requests": int(match[1]),
              "before_capture_finished_unix_ns": before.stat().st_mtime_ns,
              "after_capture_finished_unix_ns": after.stat().st_mtime_ns}
    for metric, required in (("qpx_cache_writeback_body_bytes_total", True),
                             ("qpx_cache_writeback_admission_rejections_total", False)):
        initial, initial_present = counter(before, metric, required)
        final, final_present = counter(after, metric, required)
        if final < initial:
            raise SystemExit(f"Writeback counter decreased during workload: {metric}")
        record[metric] = {"before": initial, "after": final, "delta": final - initial,
                          "initialized_before": initial_present, "initialized_after": final_present}
    records.append(record)
    miss_samples += prefix.startswith("proxy_cache_miss_http1.")
if miss_samples != 3:
    raise SystemExit(f"Writeback diagnostic requires exactly three real miss samples, found {miss_samples}")
report = {
    "diagnostic_instrumentation": True, "replaces_required_gate": False,
    "metrics_recorder_enabled": True, "writeback_load_control": "unchanged_product_default",
    "body_counter_boundary": "body collection completed before metadata encoding and persistence",
    "counter_window": "includes scrapes and in-flight work at workload boundaries",
    "samples": records,
}
output.write_text(json.dumps(report, indent=2) + "\n")
for record in records:
    print(f"{record['sample']}: frontend={record['completed_frontend_requests']}, "
          f"collected_bytes={record['qpx_cache_writeback_body_bytes_total']['delta']}, "
          f"admission_rejections={record['qpx_cache_writeback_admission_rejections_total']['delta']}")

"""Compute comparable resource ratios without numeric failure sentinels."""

import json
import math
import sys


def lower_is_better_ratio(current, reference, record, metric):
    # Equal observed zero costs represent parity, not an unobserved workload.
    if current == 0 and reference == 0:
        return 1.0
    ratio = current / reference if reference else None
    if ratio is not None and math.isfinite(ratio):
        return ratio
    reason = ("resource ratio has a zero reference and a positive measured value"
              if reference == 0 else "resource ratio is not finite")
    failure = {
        "valid": False, "stage": "resource_ratio", "reason": reason,
        "bench": record["bench"], "proxy": record["proxy"], "metric": metric,
        "body_bytes": record["body_bytes"] if "body_bytes" in record else record["stream_bytes"],
        "actual": current, "reference": reference, "ratio": None,
    }
    for field in ("read_mode", "max_concurrent_streams"):
        if field in record:
            failure[field] = record[field]
    print(json.dumps(failure, allow_nan=False, sort_keys=True), flush=True)
    print(f"Invalid measurement: {reason}; metric={metric}; actual={current}; reference={reference}",
          file=sys.stderr)
    raise SystemExit(1)

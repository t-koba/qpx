"""Option-A confirmation for the streaming paired queue-delay objective.

The first report is immutable. Only a complete, same-mode sample of the same
builds and workload may clear its miss; every other outcome retains it.
"""
import json
import math
import os
from pathlib import Path
import re
import sys

import streaming_reference

METRIC = "scheduler_queue_delay_us_per_transfer"


def validate_identity(report, current_sha):
    """Require the report to name the exact current and pinned source pair."""
    if current_sha != report.get("source_sha"):
        raise ValueError("current source_sha identity mismatch")
    for field, env in (("source_sha", "GITHUB_SHA"),
                       ("reference_source_sha", "QPX_PREVIOUS_SOURCE_SHA")):
        identity = report.get(field, "")
        if not re.fullmatch(r"[0-9a-f]{40}", identity):
            raise ValueError(f"missing exact {field}")
        expected = os.environ.get(env)
        if not expected or expected != identity:
            raise ValueError(f"{field} identity mismatch or expected source is missing")
    if (report.get("current_proxy") != "qpxd"
            or report.get("reference_proxy") != "qpxd-previous"):
        raise ValueError("paired lane identity mismatch")


def queue_metric(report, mode):
    if report.get("comparison") != "current_build_versus_pinned_previous_release":
        raise ValueError("unexpected comparison")
    metric = report["read_modes"][mode]["metrics"][METRIC]
    rounds = metric["paired_rounds"]
    median = metric["median_current_over_reference"]
    if type(rounds) is not int or rounds <= 0:
        raise ValueError("no paired rounds")
    if (type(median) not in (int, float) or not math.isfinite(median)
            or median <= 0):
        raise ValueError("invalid paired median")
    return metric


def resolve(first, confirmation, mode, cap, current_sha):
    initial = queue_metric(first, mode)
    result = {"status": "REGRESSED", "mode": mode, "first": initial,
              "source_sha": first.get("source_sha"),
              "reference_source_sha": first.get("reference_source_sha")}
    try:
        validate_identity(first, current_sha)
        validate_identity(confirmation, current_sha)
        for field in ("source_sha", "reference_source_sha"):
            if confirmation.get(field) != first.get(field):
                raise ValueError(f"{field} identity mismatch")
        attempts = first.get("sample_attempts")
        if type(attempts) is not int or attempts <= 0:
            raise ValueError("missing sample attempts")
        if confirmation.get("sample_attempts") != attempts:
            raise ValueError("sample attempts mismatch")
        if not first.get("workload") or confirmation.get("workload") != first["workload"]:
            raise ValueError("workload mismatch")
        confirmed = queue_metric(confirmation, mode)
        # Incomplete pairs and malformed raw measurements cannot turn a miss
        # into a pass, even if their surviving median happens to be low.
        for report in (first, confirmation):
            if (queue_metric(report, mode)["paired_rounds"] != attempts
                    or report.get("complete_modes", {}).get(mode) is not True):
                raise ValueError("inconclusive or invalid paired sample")
        result["confirmation"] = confirmed
        if confirmed["median_current_over_reference"] <= cap + 1e-12:
            result.update(status="PASSED", unconfirmed_misses=[initial])
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        result["reason"] = f"confirmation did not clear first miss: {exc}"
    return result


def missed_modes(report, cap):
    """Return only complete first-pass modes that exceed the fixed objective."""
    attempts = report.get("sample_attempts")
    complete = report.get("complete_modes")
    if type(attempts) is not int or attempts <= 0 or not isinstance(complete, dict):
        return []
    missed = []
    for mode in streaming_reference.READ_MODES:
        try:
            metric = queue_metric(report, mode)
        except (KeyError, TypeError, ValueError, AttributeError):
            continue
        if complete.get(mode) is True and metric["paired_rounds"] == attempts:
            if metric["median_current_over_reference"] > cap + 1e-12:
                missed.append(mode)
    return missed


def write_report(raw, output, source_sha, reference_sha, attempts, workload):
    records = streaming_reference.load_records(raw)
    report = streaming_reference.compare(records)
    report.update(source_sha=source_sha, reference_source_sha=reference_sha,
                  sample_attempts=attempts, workload=workload, complete_modes={})
    for mode in streaming_reference.READ_MODES:
        pairs = [r for r in records if r.get("read_mode") == mode
                 and r.get("proxy") in ("qpxd", "qpxd-previous")]
        expected = {(proxy, n) for proxy in ("qpxd", "qpxd-previous")
                    for n in range(1, attempts + 1)}
        report["complete_modes"][mode] = (
            len(pairs) == len(expected)
            and {(r["proxy"], r.get("sample_round")) for r in pairs} == expected
            and all(r.get("bench") == "proxy_compare_http1_streaming_reverse"
                    and r.get("sample_attempts") == r.get("valid_samples") == 1
                    and r.get("aggregation") == "single_sample"
                    and r.get("commit") == source_sha
                    and r.get("kernel_resource_metrics") is True
                    and type(r.get(METRIC)) in (int, float)
                    and math.isfinite(r[METRIC]) and r[METRIC] > 0
                    and r.get("bytes") == r.get("stream_bytes", 0) * r.get("transfers", 0)
                    and r.get("stream_bytes") == workload["stream_bytes"]
                    and r.get("chunk_bytes") == workload["chunk_bytes"]
                    and r.get("transfers") == (1 if mode == "slow" else workload["fast_transfers"])
                    for r in pairs)
        )
    Path(output).write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(streaming_reference.format_summary(report))


if __name__ == "__main__":
    if sys.argv[1] == "report":
        raw, output, source, reference, attempts, body, chunk, transfers, delay = sys.argv[2:]
        write_report(raw, output, source, reference, int(attempts), {
            "stream_bytes": int(body), "chunk_bytes": int(chunk),
            "fast_transfers": int(transfers), "slow_read_delay_ms": delay,
        })
    elif sys.argv[1] == "misses":
        first = json.loads(Path(sys.argv[2]).read_text())
        cap = json.loads(Path(sys.argv[3]).read_text())["paired"]["max_scheduler_queue_delay_ratio"]
        for mode in missed_modes(first, cap):
            print(mode)

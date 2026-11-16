"""Option-A confirmation for the streaming paired latency and throughput objectives.

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

ENFORCED_METRICS = {
    "total_ms": ("max", "max_total_time_ratio"),
    "requests_per_cpu_second": ("min", "min_throughput_ratio"),
}
DIAGNOSTIC_METRICS = streaming_reference.METRICS[2:]


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


def paired_metric(report, mode, metric):
    if report.get("comparison") != "current_build_versus_pinned_previous_release":
        raise ValueError("unexpected comparison")
    metric = report["read_modes"][mode]["metrics"][metric]
    rounds = metric["paired_rounds"]
    median = metric["median_current_over_reference"]
    if type(rounds) is not int or rounds <= 0:
        raise ValueError("no paired rounds")
    if (type(median) not in (int, float) or not math.isfinite(median)
            or median <= 0):
        raise ValueError("invalid paired median")
    return metric


def violates(metric, direction, cap):
    median = metric["median_current_over_reference"]
    if direction == "max":
        return median > cap + 1e-12
    if direction == "min":
        return median < cap - 1e-12
    raise ValueError("invalid paired objective direction")


def complete_metrics(report, mode):
    attempts = report.get("sample_attempts")
    if type(attempts) is not int or attempts <= 0:
        raise ValueError("missing sample attempts")
    metrics = {name: paired_metric(report, mode, name) for name in ENFORCED_METRICS}
    if (report.get("complete_modes", {}).get(mode) is not True
            or any(metric["paired_rounds"] != attempts for metric in metrics.values())):
        raise ValueError("inconclusive or invalid paired sample")
    return metrics


def resolve(first, confirmation, mode, caps, current_sha):
    result = {"status": "REGRESSED", "mode": mode, "first": {}, "confirmation": {},
              "source_sha": first.get("source_sha"),
              "reference_source_sha": first.get("reference_source_sha")}
    try:
        validate_identity(first, current_sha)
        initial = result["first"] = complete_metrics(first, mode)
        validate_identity(confirmation, current_sha)
        for field in ("source_sha", "reference_source_sha"):
            if confirmation.get(field) != first.get(field):
                raise ValueError(f"{field} identity mismatch")
        if confirmation.get("sample_attempts") != first.get("sample_attempts"):
            raise ValueError("sample attempts mismatch")
        if not first.get("workload") or confirmation.get("workload") != first["workload"]:
            raise ValueError("workload mismatch")
        # Both metrics need every configured pair, even when only one missed.
        confirmed = result["confirmation"] = complete_metrics(confirmation, mode)
        misses = [name for name in ENFORCED_METRICS
                  if violates(confirmed[name], *caps[name])]
        if misses:
            raise ValueError("paired objectives still missed: " + ", ".join(misses))
        result.update(status="PASSED", unconfirmed_misses=[
            initial[name] for name in ENFORCED_METRICS
            if violates(initial[name], *caps[name])
        ])
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        result["reason"] = f"confirmation did not clear first miss: {exc}"
    return result


def missed_modes(report, caps):
    """Return complete first-pass modes missing either paired objective."""
    missed = []
    for mode in streaming_reference.READ_MODES:
        try:
            metrics = complete_metrics(report, mode)
            if any(violates(metrics[name], *caps[name]) for name in ENFORCED_METRICS):
                missed.append(mode)
        except (KeyError, TypeError, ValueError, AttributeError):
            continue
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
                    and all(type(r.get(metric)) in (int, float)
                            and math.isfinite(r[metric]) and r[metric] > 0
                            for metric in ENFORCED_METRICS)
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
        paired = json.loads(Path(sys.argv[3]).read_text())["paired"]
        caps = {name: (direction, paired[key])
                for name, (direction, key) in ENFORCED_METRICS.items()}
        for mode in missed_modes(first, caps):
            print(mode)

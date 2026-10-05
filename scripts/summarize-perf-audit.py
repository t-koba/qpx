#!/usr/bin/env python3
"""Validate required artifacts and aggregate independent performance results."""

import argparse
import json
import math
import os
from pathlib import Path
import re
import statistics
import sys

from lib.perf_audit_catalog import CATEGORIES, evaluation_name


def reject_nonfinite(value):
    raise ValueError(f"nonfinite JSON value: {value}")


def objective_coverage(category, evaluations, scope):
    """Require every workload and criterion, including failed measurements."""
    directory = Path(__file__).resolve().parent.parent / "perf"
    expected = {}
    if category in ("proxy", "http2"):
        filename = "origin-cache" if category == "proxy" else "http2"
        objectives = json.loads((directory / f"{filename}-performance-objectives.json").read_text())
        performance = {key for key in objectives["defaults"]
                       if "sample_spread" not in key and key != "min_aggregate_dominance_score"}
        # HTTP/2 lane entries override defaults; required dimensions define coverage.
        lanes = objectives["lanes"] if category == "proxy" else (
            {"body_bytes": body_bytes, "max_concurrent_streams": max_streams}
            for body_bytes in objectives["required_body_bytes"]
            for max_streams in objectives["required_max_concurrent_streams"]
        )
        for lane in lanes:
            if category == "proxy":
                key = (lane["bench"], lane["body_bytes"], None, None)
                quality = {f"{role}.{metric}" for role in ("qpx", "reference")
                           for metric in ("requests_per_sec_ratio", "requests_per_cpu_second_ratio")}
            else:
                key = ("proxy_compare_http2_reverse", lane["body_bytes"], lane["max_concurrent_streams"], None)
                quality = {f"{role}.{metric}" for role in ("qpxd", "nginx", "direct-backend")
                           for metric in ("throughput_sample_spread", "cpu_sample_spread")}
            expected[key] = quality | (performance if scope == "acceptance" else set())
    else:
        objectives = json.loads((directory / "streaming-performance-objectives.json").read_text())
        fast = {"throughput ratio", "direct efficiency ratio", "total CPU efficiency ratio",
                "first-byte ratio", "p99 gap ratio", "maximum gap ratio", "dominance score",
                "total RSS peak ratio", "total FD peak ratio", "scheduler queue-delay ratio"}
        quality = {f"{role}.total_time_sample_spread" for role in ("qpxd", "direct-backend")}
        for mode in ("fast", "slow"):
            performance = fast if mode == "fast" else set(objectives["slow"])
            expected[("proxy_compare_http1_streaming_reverse", 104857600, None, mode)] = (
                quality | (performance if scope == "acceptance" else set()))
    failures = []
    seen = set()
    for evaluation in evaluations:
        if not isinstance(evaluation, dict):
            failures.append("objective record is not an object")
            continue
        key = tuple(evaluation.get(field) for field in
                    ("bench", "body_bytes", "max_concurrent_streams", "read_mode"))
        if any(value is not None and type(value) not in (str, int) for value in key):
            failures.append("invalid workload identity")
            continue
        if key in seen or key not in expected:
            failures.append(f"duplicate or unexpected workload: {key}")
            continue
        seen.add(key)
        if evaluation.get("scope") != scope:
            failures.append(f"invalid objective scope: {key}")
        checks = evaluation.get("checks")
        if not isinstance(checks, list) or not all(isinstance(check, dict) for check in checks):
            failures.append(f"invalid objective checks: {key}")
            continue
        metrics = [check.get("metric") for check in checks]
        if not all(isinstance(metric, str) for metric in metrics):
            failures.append(f"invalid objective metric: {key}")
            continue
        missing = expected[key] - set(metrics)
        if missing:
            failures.append(f"missing objective checks: {key}: {sorted(missing)}")
        if len(set(metrics)) != len(metrics):
            failures.append(f"duplicate objective checks: {key}")
        if category == "streaming" and not any(
                f"{role}.total_time_sample_spread" in metrics for role in objectives["external_proxies"]):
            failures.append(f"missing reference stability check: {key}")
    for key in expected.keys() - seen:
        failures.append(f"missing required workload: {key}")
    return failures


def summarize(root, destination, commit, repetitions, needs, download_outcome):
    failures = []
    results = []
    observations = {}
    environments = []
    lines = ["## Performance audit", "", f"Commit: `{commit}`; independent runs: {repetitions}.", "",
             "| Category | Result |", "|---|---|"]
    expected_needs = {f"perf_audit_{category}" for category in CATEGORIES}
    if set(needs) != expected_needs:
        failures.append("required category result set is incomplete or unexpected")
    if download_outcome != "success":
        failures.append(f"artifact download failed: {download_outcome}")
    for category, labels in CATEGORIES.items():
        outcome = needs.get(f"perf_audit_{category}", {}).get("result", "missing")
        lines.append(f"| {category} | {outcome} |")
        if outcome != "success":
            failures.append(f"{category}: {outcome}")
        count = repetitions if category in ("proxy", "http2", "streaming") else 1
        for repetition in range(1, count + 1):
            suffix = f"-{repetition}" if category in ("proxy", "http2", "streaming") else ""
            artifact = root / f"qpx-perf-audit-jsonl-{category}{suffix}"
            if not artifact.is_dir():
                failures.append(f"missing artifact: {artifact.name}")
                continue
            runner = artifact / "runner.jsonl"
            if runner.exists():
                try:
                    environments.extend(json.loads(line) for line in runner.read_text().splitlines() if line)
                except (OSError, ValueError) as error:
                    failures.append(f"invalid runner manifest {artifact.name}: {error}")
            required_labels = [(label, commit) for label in labels.values()]
            if count == 3:
                try:
                    manifest = json.loads((artifact / "binaries.json").read_text())
                    baseline_commit = manifest["baseline_commit"]
                    if not isinstance(baseline_commit, str) or not re.fullmatch(r"[0-9a-f]{40}", baseline_commit):
                        raise ValueError("baseline commit is invalid")
                    required_labels.extend([
                        (f"current {category} comparison", commit),
                        (f"baseline {category} comparison", baseline_commit),
                        (f"baseline {category} measurement quality", commit),
                    ])
                except (OSError, ValueError, KeyError, TypeError) as error:
                    failures.append(f"invalid baseline binary manifest {artifact.name}: {error}")
            for label, expected_commit in required_labels:
                path = artifact / "evaluations" / f"{evaluation_name(label)}.json"
                log = path.with_suffix(".log")
                try:
                    result = json.loads(path.read_text(), parse_constant=reject_nonfinite)
                    elapsed = result["elapsed_seconds"]
                    status = result["exit_code"]
                    if (result["label"] != label or result["commit"] != expected_commit
                            or type(status) is not int or not isinstance(elapsed, (int, float))
                            or not math.isfinite(elapsed) or elapsed < 0
                            or result["outcome"] != ("success" if status == 0 else "failure")):
                        raise ValueError("evaluation identity or outcome is invalid")
                    if not isinstance(result.get("evaluations"), list):
                        raise ValueError("structured evaluations are missing")
                    if not isinstance(result.get("measurement_failures"), list) or any(
                            not isinstance(item, dict) for item in result["measurement_failures"]):
                        raise ValueError("measurement validity records are missing or invalid")
                    diagnostics = log.read_text()
                except (OSError, ValueError, KeyError, TypeError) as error:
                    failures.append(f"missing or invalid evaluation {artifact.name}/{label}: {error}")
                    continue
                results.append({"category": category, "repetition": repetition, **result})
                if category in ("proxy", "http2", "streaming") and (
                        label.startswith("enforce ") or label.endswith(" measurement quality")):
                    scope = "measurement-quality" if label.endswith(" measurement quality") else "acceptance"
                    failures.extend(f"{category}, run {repetition}, {label}: {failure}"
                                    for failure in objective_coverage(category, result["evaluations"], scope))
                lines.extend(["", f"### {category}, run {repetition}: {label}", "",
                              f"Result: **{result['outcome']}**; exit code: {status}; elapsed: {elapsed:.3f} s.", ""])
                if status != 0:
                    failures.append(f"{category}, run {repetition}, {label}: exit {status}")
                if result["measurement_failures"]:
                    failures.append(f"{category}, run {repetition}, {label}: invalid measurements")
                    lines.extend(["Measurement invalidity records:", "", "```json",
                                  json.dumps(result["measurement_failures"], indent=2).replace("```", "` ` `"),
                                  "```", ""])
                evaluations = result.get("evaluations", [])
                if evaluations:
                    lines.extend(["| Workload | Metric | Actual | Limit | Violation | Result |",
                                  "|---|---|---:|---:|---:|---|"])
                for evaluation in evaluations:
                    try:
                        workload = "/".join(str(evaluation.get(key, "")) for key in
                                            ("bench", "body_bytes", "max_concurrent_streams", "read_mode"))
                        for check in evaluation["checks"]:
                            actual, limit = check["actual"], check["limit"]
                            tolerance = 1e-12 if category in ("http2", "streaming") else 0.0
                            if (not all(isinstance(value, (int, float)) and math.isfinite(value)
                                        for value in (actual, limit, check["violation_percent"]))
                                    or check["direction"] not in ("min", "max")
                                    or type(check["passed"]) is not bool
                                    or check["passed"] != (actual + tolerance >= limit if check["direction"] == "min" else actual <= limit + tolerance)):
                                raise ValueError("invalid measurement check")
                            relation = ">=" if check["direction"] == "min" else "<="
                            lines.append(f"| {workload} | {check['metric']} | {actual:.6f} | {relation} {limit:.6f} | {check['violation_percent']:.2f}% | {check['passed']} |")
                            if not check["passed"]:
                                failures.append(f"{category}, run {repetition}, {workload}: {check['metric']} failed")
                            revision = "baseline" if label.startswith("baseline ") else "candidate"
                            key = (category, workload, f"{revision} ratio", check["metric"])
                            observations.setdefault(key, []).append({"run": repetition, "value": actual})
                        for role, measurements in evaluation.get("measurements", {}).items():
                            for metric, value in measurements.items():
                                if isinstance(value, (int, float)) and not isinstance(value, bool):
                                    if not math.isfinite(value):
                                        raise ValueError("nonfinite absolute measurement")
                                    revision = "baseline" if label.startswith("baseline ") else "candidate"
                                    key = (category, workload, f"{revision} {role}", metric)
                                    observations.setdefault(key, []).append({"run": repetition, "value": value})
                    except (ValueError, KeyError, TypeError, AttributeError) as error:
                        failures.append(f"{category}, run {repetition}: invalid measurement: {error}")
                tail = re.sub(r"\x1b\[[0-9;]*m", "", diagnostics).splitlines()[-60:]
                tail = [line for line in tail if not line.startswith('{"bench":')]
                lines.extend(["", "```text", "\n".join(tail).replace("```", "` ` `"), "```"])
    aggregates = []
    lines.extend(["", "## Independent measurement variation", "",
                  "Every individual run must pass; averages never override a failed run.", "",
                  "| Category / workload | Role / metric | Count | Minimum | Mean | Maximum | Population SD |",
                  "|---|---|---:|---:|---:|---:|---:|"])
    for (category, workload, role, metric), samples in sorted(observations.items()):
        values = [sample["value"] for sample in samples]
        stats = {"category": category, "workload": workload, "role": role, "metric": metric,
                 "samples": samples, "count": len(values), "minimum": min(values),
                 "mean": statistics.mean(values), "maximum": max(values), "population_sd": statistics.pstdev(values)}
        aggregates.append(stats)
        lines.append(f"| {category}/{workload} | {role}/{metric} | {len(values)} | {stats['minimum']:.6f} | {stats['mean']:.6f} | {stats['maximum']:.6f} | {stats['population_sd']:.6f} |")
    lines.extend(["", "## Measurement and gate failures", ""])
    lines.extend(f"- {failure}" for failure in failures)
    if not failures:
        lines.append("All required categories, artifacts, and evaluations passed.")
    report = {"commit": commit, "repetitions": repetitions, "outcome": "failure" if failures else "success",
              "failures": failures, "evaluations": results, "statistics": aggregates, "environments": environments}
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "summary.json").write_text(json.dumps(report, sort_keys=True, allow_nan=False) + "\n")
    markdown = "\n".join(lines) + "\n"
    (destination / "summary.md").write_text(markdown)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
            summary.write(markdown)
    for failure in failures:
        print(failure, file=sys.stderr)
    return bool(failures)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--repetitions", type=int, choices=(1, 3), required=True)
    arguments = parser.parse_args()
    return summarize(arguments.root, arguments.destination, arguments.commit, arguments.repetitions,
                     json.loads(os.environ["NEEDS_JSON"]), os.environ["DOWNLOAD_OUTCOME"])


if __name__ == "__main__":
    sys.exit(main())

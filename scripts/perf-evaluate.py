#!/usr/bin/env python3
"""Run a performance step and retain its result, timing, and diagnostics."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from lib.perf_audit_catalog import evaluation_name


def main():
    if len(sys.argv) < 4 or sys.argv[2] != "--":
        raise SystemExit("usage: perf-evaluate.py <label> -- <command> [args...]")
    label = sys.argv[1]
    directory = Path(os.environ.get("QPX_PERF_EVALUATION_DIR", "target/perf/evaluations"))
    directory.mkdir(parents=True, exist_ok=True)
    name = evaluation_name(label)
    log_path = directory / f"{name}.log"
    started = time.monotonic()
    evaluations = []
    measurement_failures = []
    with log_path.open("w", encoding="utf-8") as log:
        try:
            process = subprocess.Popen(
                sys.argv[3:], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace",
            )
        except OSError as error:
            log.write(f"failed to start performance step: {error}\n")
            print(f"failed to start performance step: {error}", file=sys.stderr)
            status = 127
        else:
            for line in process.stdout:
                log.write(line)
                print(line, end="", flush=True)
                if line.startswith("Invalid measurement:"):
                    measurement_failures.append({"reason": line.strip()})
                # Merged stderr may follow a complete JSON value on the same line.
                try:
                    record, _ = json.JSONDecoder().raw_decode(line.lstrip())
                except json.JSONDecodeError:
                    continue
                if isinstance(record, dict) and "checks" in record:
                    evaluations.append(record)
                if isinstance(record, dict) and record.get("valid") is False:
                    measurement_failures.append(record)
            status = process.wait()
    result = {
        "label": label,
        "outcome": "success" if status == 0 else "failure",
        "exit_code": status,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "log": str(log_path),
        "commit": os.environ.get("GITHUB_SHA", "unknown"),
        "evaluations": evaluations,
        "measurement_failures": measurement_failures,
    }
    (directory / f"{name}.json").write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        tail = log_path.read_text(encoding="utf-8").splitlines()[-60:]
        diagnostics = re.sub(r"\x1b\[[0-9;]*m", "", "\n".join(tail)).replace("```", "` ` `")
        with open(summary, "a", encoding="utf-8") as report:
            report.write(f"### {label}\n\n")
            report.write(f"Outcome: **{result['outcome']}**; exit code: {status}; elapsed: {result['elapsed_seconds']:.3f} s.\n\n")
            report.write(f"Full log: `{log_path}` (job artifact).\n\n")
            if measurement_failures:
                report.write("Measurement invalidity records:\n\n```json\n")
                report.write(json.dumps(measurement_failures, indent=2).replace("```", "` ` `"))
                report.write("\n```\n\n")
            if evaluations:
                report.write("| Workload | Metric | Actual | Limit | Violation | Result |\n|---|---|---:|---:|---:|---|\n")
                for evaluation in evaluations:
                    workload = f"{evaluation['bench']}/{evaluation['body_bytes']}"
                    if "max_concurrent_streams" in evaluation:
                        workload += f" m={evaluation['max_concurrent_streams']}"
                    if "read_mode" in evaluation:
                        workload += f" {evaluation['read_mode']}"
                    for check in evaluation["checks"]:
                        relation = ">=" if check["direction"] == "min" else "<="
                        outcome = "success" if check["passed"] else "failure"
                        report.write(f"| {workload} | {check['metric']} | {check['actual']:.6f} | {relation} {check['limit']:.6f} | {check['violation_percent']:.2f}% | {outcome} |\n")
                report.write("\n")
                diagnostics = "\n".join(line for line in diagnostics.splitlines() if not line.startswith("{\"bench\":"))
            report.write(f"```text\n{diagnostics}\n```\n\n")
    return status if status >= 0 else 128 - status


if __name__ == "__main__":
    sys.exit(main())

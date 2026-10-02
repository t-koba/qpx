#!/usr/bin/env python3
"""Verify that every performance measurement remains a required CI gate."""

from pathlib import Path
import re


CATEGORIES = {
    "protocol": ("criterion_streaming_throughput_bench", "h3_crate_protocol_perf_benchmarks",
                 "qpx_http3_protocol_perf_benchmarks", "advanced_transport_perf_benchmarks"),
    "proxy": ("external_proxy_comparison_bench", "enforce_cache_origin_feature_rich_performance_objectives",
              "compare_proxy_baseline"),
    "http2": ("external_http2_comparison_bench", "enforce_http2_performance_objectives"),
    "streaming": ("external_long_streaming_comparison_bench", "enforce_streaming_performance_objectives"),
    "allocation": ("allocation_profile", "enforce_allocation_budget"),
    "netem": ("netem_proxy_comparison_bench",),
    "interop": ("http3_interop_matrix",),
    "callgrind": ("callgrind_hot_path_profile",),
}


def require(condition, message):
    if not condition:
        raise SystemExit(f"performance acceptance gate invalid: {message}")


workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
jobs = {}
for match in re.finditer(r"^  ([a-z0-9_]+):\n", workflow, re.MULTILINE):
    next_job = re.search(r"^  [a-z0-9_]+:\n", workflow[match.end():], re.MULTILINE)
    end = match.end() + next_job.start() if next_job else len(workflow)
    jobs[match.group(1)] = workflow[match.start():end]

for category, steps in CATEGORIES.items():
    name = f"perf_audit_{category}"
    require(name in jobs, f"missing category {name}")
    job = jobs[name]
    require("if: always()" in job, f"{name} lacks unconditional evaluation")
    for step in steps:
        require(f"id: {step}\n" in job, f"{name} lacks measurement {step}")
        require(f"steps.{step}.outcome" in job, f"{name} does not enforce {step}")
        require(f'check_step "{step}" "${step.upper()}"' in job,
                f"{name} does not check outcome {step}")
    require('if [ "$2" != "success" ]' in job, f"{name} accepts incomplete steps")
    require("python3 scripts/perf-evaluate.py" in job, f"{name} lacks diagnostic reports")
    require(f"qpx-perf-audit-jsonl-{category}" in job, f"{name} lacks isolated artifacts")
    upload = job[job.index("      - name: upload perf audit artifact"):]
    require("if: always()" in upload, f"{name} does not preserve failure artifacts")
    require("target/perf/evaluations/**" in upload, f"{name} does not retain diagnostics")

require("perf_audit_build" in jobs, "shared measurement build is missing")
for category in ("proxy", "http2", "streaming", "netem"):
    job = jobs[f"perf_audit_{category}"]
    require("needs: perf_audit_build" in job, f"{category} may measure before the shared build")
    require("scripts/verify-perf-binaries.py" in job, f"{category} does not verify binary identity")
    require("cargo build" not in job, f"{category} builds during its measurement job")

for category in ("proxy", "http2", "streaming"):
    job = jobs[f"perf_audit_{category}"]
    require("bash scripts/perf-audit-revision-compare.sh" in job,
            f"{category} does not invoke the revision comparison through bash")
    require(not re.search(r"^\s+scripts/perf-audit-revision-compare\.sh", job, re.MULTILINE),
            f"{category} depends on the revision comparison executable bit")

aggregate = jobs.get("perf_audit", "")
require("if: always()" in aggregate, "aggregate may skip failed categories")
for category in CATEGORIES:
    require(f"      - perf_audit_{category}\n" in aggregate,
            f"aggregate does not require {category}")
require('outcome != "success"' in aggregate, "aggregate accepts missing categories")
require("      - perf_audit\n" in jobs.get("http_rfc_compliance", ""),
        "release gate does not require performance audit")
print("performance acceptance gates complete: 8 categories, 16 evaluations")

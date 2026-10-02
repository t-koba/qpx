#!/usr/bin/env python3
"""Verify that every performance measurement remains a required CI gate."""

from pathlib import Path
import re
from lib.perf_audit_catalog import CATEGORIES


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
        require(f'python3 scripts/perf-evaluate.py "{steps[step]}" --' in job,
                f"{name} does not retain the expected evaluation label for {step}")
    require('if [ "$2" != "success" ]' in job, f"{name} accepts incomplete steps")
    require("python3 scripts/perf-evaluate.py" in job, f"{name} lacks diagnostic reports")
    require(f"qpx-perf-audit-jsonl-{category}" in job, f"{name} lacks isolated artifacts")
    upload = job[job.index("      - name: upload perf audit artifact"):]
    require("if: always()" in upload, f"{name} does not preserve failure artifacts")
    require("target/perf/evaluations/**" in upload, f"{name} does not retain diagnostics")
    require("if-no-files-found: error" in upload, f"{name} accepts missing artifacts")

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
revision_comparison = Path("scripts/perf-audit-revision-compare.sh").read_text(encoding="utf-8")
require('if [ "$revision" = baseline ]; then' in revision_comparison,
        "baseline measurements lack unconditional quality validation")
require('"$ROOT_DIR/perf/$objectives" measurement-quality' in revision_comparison,
        "baseline measurements do not enforce quality objectives")
require('echo "baseline $CATEGORY measurement quality failed"' in revision_comparison,
        "baseline quality failures are not propagated")
require("if: always()" in aggregate, "aggregate may skip failed categories")
for category in CATEGORIES:
    require(f"      - perf_audit_{category}\n" in aggregate,
            f"aggregate does not require {category}")
require("scripts/summarize-perf-audit.py" in aggregate, "aggregate lacks complete measurement reports")
require("actions/download-artifact@" in aggregate, "aggregate does not inspect category artifacts")
require("qpx-perf-audit-jsonl-*" in aggregate, "aggregate does not collect all categories")
require("qpx-perf-audit-summary" in aggregate, "aggregate does not retain its report")
require("      - perf_audit\n" in jobs.get("http_rfc_compliance", ""),
        "release gate does not require performance audit")
for category in ("http2", "streaming"):
    checker = Path(f"scripts/check-{category}-performance.sh").read_text(encoding="utf-8")
    require('record.get("diagnostic_instrumentation") is not False' in checker,
            f"{category} may accept instrumented diagnostic measurements")
require('record.get("cpu_measurement") != "linux_process_cpu_clock_ns_v1"' in checker,
        "streaming may accept coarse CPU tick measurements")
print("performance acceptance gates complete: 8 categories, 16 evaluations")

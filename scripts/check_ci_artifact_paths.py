#!/usr/bin/env python3
"""Require retained measurements in the proxy comparison artifact upload."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


_REQUIRED_PATHS = ("target/perf/*.jsonl", "target/perf/*.json")


def missing_proxy_paths(workflow: str) -> list[str]:
    job_matches = list(
        re.finditer(
            r"^  perf_audit_proxy:\n(.*?)(?=^  [\w-]+:|\Z)",
            workflow,
            re.MULTILINE | re.DOTALL,
        )
    )
    if len(job_matches) != 1:
        raise ValueError(f"expected one perf_audit_proxy job, found {len(job_matches)}")

    steps = list(
        re.finditer(
            r"^      - name: upload perf audit artifact\n(.*?)(?=^      - |\Z)",
            job_matches[0].group(1),
            re.MULTILINE | re.DOTALL,
        )
    )
    if len(steps) != 1:
        raise ValueError(f"expected one proxy artifact upload step, found {len(steps)}")
    step = steps[0].group(1)
    if not re.search(r"^          name: qpx-perf-audit-jsonl-proxy$", step, re.MULTILINE):
        raise ValueError("proxy artifact upload has an unexpected artifact name")

    path = re.search(
        r"^          path: \|\n((?:^            .*\n?)*)",
        step,
        re.MULTILINE,
    )
    if path is None:
        raise ValueError("proxy artifact upload has no block path")
    paths = {line.strip() for line in path.group(1).splitlines() if line.strip()}
    return [item for item in _REQUIRED_PATHS if item not in paths]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("workflow", type=Path)
    args = parser.parse_args()
    try:
        missing = missing_proxy_paths(args.workflow.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        parser.error(str(error))
    if missing:
        parser.error("proxy artifact upload is missing path(s): " + ", ".join(missing))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

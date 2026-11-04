#!/usr/bin/env python3
"""Regression tests for proxy CI artifact retention."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from check_ci_artifact_paths import missing_proxy_paths

ROOT = Path(__file__).resolve().parent.parent
REQUIRED = ("target/perf/*.jsonl", "target/perf/*.json")
WORKFLOW = """jobs:
  perf_audit_qpx:
    steps:
      - name: upload perf audit artifact
        with:
          name: qpx-perf-audit-jsonl-qpx
          path: |
            target/perf/*.jsonl
            target/perf/*.json
  perf_audit_proxy:
    steps:
      - name: upload perf audit artifact
        with:
          name: qpx-perf-audit-jsonl-proxy
          path: |
            target/perf/*.jsonl
            target/perf/*.json
  perf_audit_protocol:
    steps:
      - name: upload perf audit artifact
        with:
          name: qpx-perf-audit-jsonl-protocol
          path: |
            target/perf/*.jsonl
            target/perf/*.json
"""


class ArtifactPathTests(unittest.TestCase):
    def test_current_proxy_upload_contains_required_paths(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertEqual(missing_proxy_paths(workflow), [])
        structure = (ROOT / ".github/workflows/structure.yml").read_text(encoding="utf-8")
        self.assertIn("python3 ./scripts/test-ci-artifact-paths.py", structure)

    def test_removing_proxy_paths_fails_while_other_jobs_keep_them(self):
        without_proxy_paths = WORKFLOW.replace(
            "          name: qpx-perf-audit-jsonl-proxy\n"
            "          path: |\n"
            "            target/perf/*.jsonl\n"
            "            target/perf/*.json\n",
            "          name: qpx-perf-audit-jsonl-proxy\n"
            "          path: |\n",
        )
        self.assertEqual(missing_proxy_paths(without_proxy_paths), list(REQUIRED))
        self.assertEqual(without_proxy_paths.count("target/perf/*.jsonl"), 2)
        self.assertEqual(without_proxy_paths.count("target/perf/*.json\n"), 2)

        with tempfile.TemporaryDirectory() as directory:
            workflow_path = Path(directory) / "ci.yml"
            workflow_path.write_text(without_proxy_paths, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts/check_ci_artifact_paths.py"), str(workflow_path)],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing path(s)", result.stderr)


if __name__ == "__main__":
    unittest.main()

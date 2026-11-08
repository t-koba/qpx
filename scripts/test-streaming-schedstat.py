#!/usr/bin/env python3
"""Small synthetic /proc fixtures and idle-process collector lifecycle check."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import textwrap
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("collector", ROOT / "scripts/trace-streaming-schedstat.py")
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


def stat(start):
    return "1 (name with ) spaces) " + " ".join(["S", "0"] + ["0"] * 17 + [str(start)])


def task(proc, pid, tid, start, delay, children=""):
    process = proc / str(pid)
    process.mkdir(exist_ok=True)
    if not (process / "stat").exists():
        (process / "stat").write_text(stat(start))
    directory = process / "task" / str(tid)
    directory.mkdir(parents=True, exist_ok=True)
    for name, text in dict(stat=stat(start), schedstat=f"123 {delay} 4",
                           children=children, comm="worker").items():
        (directory / name).write_text(text)


class WorkflowRegistrationTest(unittest.TestCase):
    def test_push_registers_workflow_without_running_trace(self):
        workflow = (ROOT / ".github/workflows/streaming-scheduler-trace.yml").read_text()
        self.assertIn("on:\n  workflow_dispatch:\n", workflow)
        self.assertIn(
            "  push:\n    paths:\n      - .github/workflows/streaming-scheduler-trace.yml\n",
            workflow,
        )
        self.assertIn(
            "  trace:\n    if: github.event_name == 'workflow_dispatch'\n", workflow
        )

    def test_pair_only_trace_guard_accepts_both_modes_not_matrix(self):
        source = (ROOT / "scripts/perf-audit-streaming-compare.sh").read_text()
        start = source.index('if [ -n "${QPX_STREAMING_SCHEDSTAT_DIR:-}" ] &&')
        guard = source[start:source.index("require_cmd curl", start)]
        for mode, tracing, expected in (("fast", "trace", 0), ("slow", "trace", 0),
                                        ("", "trace", 1), ("", "", 0)):
            with self.subTest(mode=mode, tracing=tracing):
                result = subprocess.run(["bash", "-eu", "-c", guard], capture_output=True,
                                        env=dict(os.environ, PAIR_ONLY_MODE=mode,
                                                 QPX_STREAMING_SCHEDSTAT_DIR=tracing))
                self.assertEqual(result.returncode, expected, result.stderr)

    def test_same_source_ab_workflow_patch_and_harness_identities(self):
        workflow = (ROOT / ".github/workflows/streaming-scheduler-trace.yml").read_text()
        baseline = "ef8541cc4f9b89e3a89feda8ef4da4c15938cb69"
        self.assertIn(f"CURRENT_SHA: {baseline}", workflow)
        self.assertIn(f"ref: {baseline}", workflow)
        self.assertIn("SOURCE_COMMIT: bead51d033f8dac90a8d3b335565eb1ee4e4dd39", workflow)
        self.assertEqual(workflow.count("runs-on:"), 1)
        self.assertIn("runs-on: ubuntu-24.04", workflow)
        self.assertEqual(workflow.count("cargo +1.99.1 build"), 2)
        self.assertEqual(workflow.count('RUSTFLAGS="-D warnings" cargo'), 2)
        for contract in (
            'worktree add --detach "$EXPERIMENT_DIR" "$CURRENT_SHA"',
            'test "$(git -C .trace-current rev-parse HEAD)" = "$CURRENT_SHA"',
            'test "$(git -C "$EXPERIMENT_DIR" rev-parse HEAD^)" = "$CURRENT_SHA"',
            'diff --name-only)" = qpxd/src/startup.rs',
            'diff > target/scheduler-trace/experiment.patch',
            'harness=%s', 'rustc +1.99.1 -Vv', 'cargo +1.99.1 -V',
            '/proc/sys/kernel/random/boot_id', 'sha256sum',
            'export QPXD_BIN="$RUNNER_TEMP/trace-current/release/qpxd"',
            'export QPX_PREVIOUS_BIN="$RUNNER_TEMP/trace-experiment/release/qpxd"',
            'export QPX_PREVIOUS_SOURCE_SHA="$REFERENCE_SHA"',
            'export GITHUB_SHA="$CURRENT_SHA"',
            'for mode in fast slow; do',
            'export QPX_STREAMING_COMPARE_PAIR_ONLY_MODE="$mode"',
            'export QPX_STREAMING_SCHEDSTAT_DIR="$directory/tasks"',
            'QPX_STREAMING_COMPARE_BYTES: "104857600"',
            'QPX_STREAMING_COMPARE_CHUNK_BYTES: "65536"',
            'QPX_STREAMING_COMPARE_SAMPLE_ATTEMPTS: "3"',
            'QPX_STREAMING_COMPARE_FAST_TRANSFERS: "8"',
            'QPX_STREAMING_COMPARE_SLOW_READ_DELAY_MS: "1"',
            'if: always()', 'path: target/scheduler-trace/',
        ):
            self.assertIn(contract, workflow)
        self.assertEqual(workflow.count("bash scripts/perf-audit-streaming-compare.sh"), 1)
        self.assertNotIn("check-streaming", workflow)
        self.assertNotIn("performance-objectives", workflow)
        # Execute the exact embedded patch against a disposable startup copy.
        patch = textwrap.dedent(workflow.split("python3 - <<'PY'\n", 1)[1].split("          PY\n", 1)[0])
        original = (ROOT / "qpxd/src/startup.rs").read_text()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "qpxd/src/startup.rs"
            path.parent.mkdir(parents=True)
            path.write_text(original)
            env = dict(os.environ, EXPERIMENT_DIR=tmp)
            result = subprocess.run(["python3", "-c", patch], env=env, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            start = original.index("    let mut builder = if worker_threads == 1 {")
            end = original.index("        .max_blocking_threads", start)
            self.assertEqual(path.read_text(), original[:start] +
                             "    let mut builder = tokio::runtime::Builder::new_multi_thread();\n"
                             "    builder\n        .worker_threads(worker_threads)\n" + original[end:])
            # A different runtime builder must fail closed, not silently build a third variant.
            result = subprocess.run(["python3", "-c", patch], env=env, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
        harness = (ROOT / "scripts/perf-audit-streaming-compare.sh").read_text()
        self.assertIn("runtime:\n  worker_threads: 1\n", harness)
        self.assertIn('cp "$TMP_DIR/interleaved-raw.jsonl" "$LOG_ARTIFACT_DIR"/', harness)


class CollectorTest(unittest.TestCase):
    def test_tree_counts_deltas_churn_and_missing_reads(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp)
            task(proc, 10, 10, 100, 1000)
            task(proc, 10, 11, 101, 2000, "20")  # child owned by non-leader
            task(proc, 20, 20, 200, 3000)
            first, previous = collector.snapshot(proc, {"qpxd": 10}, {})
            self.assertEqual(first["errors"], [])
            self.assertEqual(first["counts"]["qpxd"], dict(
                process_count=2, listed_task_count=3, read_task_count=3))
            self.assertTrue(all(t["delta_ns"] is None for t in first["tasks"]))
            task(proc, 10, 10, 100, 1100)
            task(proc, 10, 11, 102, 50, "20")  # same TID, different starttime
            (proc / "20/task/20/schedstat").unlink()
            second, _ = collector.snapshot(proc, {"qpxd": 10}, previous)
            self.assertEqual(second["tasks"][0]["delta_ns"], 100)
            self.assertEqual(second["tasks"][0]["schedstat"], "123 1100 4")
            self.assertIsNone(second["tasks"][1]["delta_ns"])
            self.assertEqual(len(second["vanished"]), 2)
            self.assertEqual(len(second["errors"]), 1)
            task(proc, 10, 10, 100, 999)
            third, _ = collector.snapshot(proc, {"qpxd": 10}, previous)
            self.assertTrue(any("decreased" in e["error"] for e in third["errors"]))

    def test_idle_process_hook_lifecycle_and_disabled_path(self):
        source = (ROOT / "scripts/perf-audit-streaming-compare.sh").read_text()
        hooks = source[source.index("start_schedstat_trace() {"):source.index("start_streaming_backend() {")]
        with tempfile.TemporaryDirectory() as tmp:
            processes = [subprocess.Popen(["sleep", "30"]) for _ in range(2)]
            try:
                env = dict(os.environ, ROOT_DIR=str(ROOT), resource_pid=str(processes[0].pid),
                           BACKEND_PID=str(processes[1].pid), QPX_STREAMING_SCHEDSTAT_DIR=tmp,
                           QPX_STREAMING_SCHEDSTAT_INTERVAL="0.01")
                script = hooks + '''
PIDS=()
register_pid() { PIDS+=("$1"); }
artifact=streaming.qpxd-previous.fast.round-2
attempt=1
proxy=qpxd-previous
CURRENT_SOURCE_SHA=current
QPX_PREVIOUS_SOURCE_SHA=reference
start_schedstat_trace
stop_schedstat_trace
test "${#PIDS[@]}" = 0
unset QPX_STREAMING_SCHEDSTAT_DIR
start_schedstat_trace
stop_schedstat_trace
'''
                result = subprocess.run(["bash", "-eu", "-c", script], env=env,
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                records = [json.loads(line) for line in next(Path(tmp).glob("*.jsonl")).read_text().splitlines()]
                self.assertEqual(records[0]["source_sha"], "reference")
                self.assertIn("round-2.attempt-1", records[0]["sample"])
                self.assertTrue(records[0]["boot_id"])
                self.assertEqual(records[-1]["type"], "end")
                snapshots = [r for r in records if r["type"] == "snapshot"]
                self.assertGreaterEqual(len(snapshots), 2)
                self.assertTrue(all(r["counts"]["backend"]["read_task_count"] == 1 for r in snapshots))
                self.assertTrue(all(t["delta_ns"] is not None for t in snapshots[-1]["tasks"]))
                self.assertFalse(list(Path(tmp).glob("*.ready")) + list(Path(tmp).glob("*.stop")))
            finally:
                for process in processes:
                    process.terminate()
                    process.wait()


if __name__ == "__main__":
    unittest.main()

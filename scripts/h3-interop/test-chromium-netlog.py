#!/usr/bin/env python3
"""Offline summary and shell fixtures; no real Chromium, qpxd, TLS or network."""

import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SUMMARY = runpy.run_path(str(HERE / "chromium-netlog-summary.py"))
SECRET = "private-fixture-value"
DOM_MARKER = "safe-dom-fixture"
SERVER_MARKER = "safe-server-fixture HTTP/3 listener starting"


def netlog(types=None, events=None):
    return {
        "constants": {"logEventTypes": types or {"QUIC_SESSION": 1}},
        "events": events if events is not None else [
            {"type": 1, "params": {"net_error": -118, "url": SECRET}}
        ],
    }


class SummaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "netlog.json"

    def summarize(self, log):
        self.path.write_text(json.dumps(log), encoding="utf-8")
        return SUMMARY["summarize"](self.path)

    def test_only_valid_event_names_and_integer_error_counts(self):
        types = {"QUIC_SESSION": 1, "HTTP_STREAM_JOB": 2, "URL_REQUEST": 3,
                 "OTHER_EVENT": 4, "QUIC_" + SECRET: 5,
                 "QUIC_\nINJECTED": 6, "QUIC_é": 7, "QUIC_" + "A" * 64: 8,
                 "QUIC_\x1b[31m": 9, "QUIC_FAKE_ID": SECRET}
        params = {key: SECRET for key in (
            "url", "hostname", "headers", "cookie", "authorization", "certificates"
        )}
        events = [{"type": n, "params": dict(params, net_error=-118)}
                  for n in range(1, 10)]
        events += [{"type": 1, "params": {"net_error": value}}
                   for value in ("-7", SECRET, True, 1.5, 2**32)]
        lines = self.summarize(netlog(types, events))
        self.assertEqual(lines, [
            "chromium NetLog summary (bounded counts):",
            "event HTTP_STREAM_JOB: 1", "event QUIC_SESSION: 6",
            "event URL_REQUEST: 1", "net_error -118: 9",
        ])
        self.assertNotIn(SECRET, "\n".join(lines))

    def test_output_has_fixed_line_and_name_limits(self):
        types = {f"QUIC_EVENT_{n}": n for n in range(40)}
        events = [{"type": n, "params": {"net_error": -n}} for n in range(40)]
        lines = self.summarize(netlog(types, events))
        self.assertEqual(len(lines), 26)
        self.assertEqual(lines[-1], "chromium NetLog summary truncated")
        self.assertLess(len("\n".join(lines)), 2048)

    def test_unavailable_is_fixed_for_missing_invalid_and_oversized_logs(self):
        unavailable = ["chromium NetLog summary unavailable"]
        self.assertEqual(SUMMARY["summarize"](self.path), unavailable)
        for raw in (b"", b'{"events":[', b"\xff", b"[]", b"{}",
                    b"[" * 2000, b" " * (SUMMARY["MAX_BYTES"] + 1)):
            with self.subTest(size=len(raw)):
                self.path.write_bytes(raw)
                self.assertEqual(SUMMARY["summarize"](self.path), unavailable)
        for log in (netlog(events={}), netlog(events=[None]),
                    netlog(events=[{"params": SECRET}])):
            self.assertEqual(self.summarize(log), unavailable)


class ShellTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.tmp = self.root / "tmp"
        self.tmp.mkdir()
        self.trace = self.root / "invocations.json"
        self.fixture = self.root / "fixture.json"
        self.fixture.write_text(json.dumps(netlog()), encoding="utf-8")
        self.stub("openssl", '#!/bin/sh\ncase "$1" in pkey|dgst|base64) cat >/dev/null;; esac\nprintf stub\n')
        self.stub("qpxd", f"#!{sys.executable}\nimport signal\n"
                  f"print({SERVER_MARKER!r}, flush=True)\nsignal.pause()\n")
        self.stub("chromium", f"#!{sys.executable}\n" + '''
import os
from pathlib import Path
import sys

for arg in sys.argv[1:]:
    if arg.startswith("--log-net-log=") and os.environ.get("OMIT_LOG") != "1":
        Path(arg.split("=", 1)[1]).write_bytes(Path(os.environ["FIXTURE"]).read_bytes())
print("safe-dom-fixture", os.environ.get("PAYLOAD", "qpx-h3-external-interop"))
sys.exit(int(os.environ.get("CLIENT_STATUS", "0")))
''')
        self.stub("timeout", f"#!{sys.executable}\n" + '''
import json
import os
from pathlib import Path
import subprocess
import sys

Path(os.environ["TRACE"]).write_text(json.dumps(sys.argv[1:]))
status = subprocess.run(sys.argv[2:]).returncode
sys.exit(int(os.environ.get("TIMEOUT_STATUS", status)))
''')

    def stub(self, name, source):
        path = self.bin / name
        path.write_text(source, encoding="utf-8")
        path.chmod(0o755)

    def run_client(self, **overrides):
        env = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}",
                   TMPDIR=str(self.tmp), QPXD_BIN=str(self.bin / "qpxd"),
                   CHROMIUM_BIN=str(self.bin / "chromium"),
                   FIXTURE=str(self.fixture), TRACE=str(self.trace))
        # Do not let the calling environment choose a fixture result.
        for key in ("PAYLOAD", "CLIENT_STATUS", "TIMEOUT_STATUS", "OMIT_LOG"):
            env.pop(key, None)
        env.update(overrides)
        result = subprocess.run(
            ["bash", str(HERE / "external-client.sh"), "chromium"],
            env=env, capture_output=True, text=True, timeout=10,
        )
        self.assertTrue(self.trace.exists(), (result.returncode, result.stdout, result.stderr))
        args = json.loads(self.trace.read_text())
        self.assertEqual(args[0], "45")
        self.assertEqual(args[1], str(self.bin / "chromium"))
        self.assertIn("--dump-dom", args)
        self.assertIn("--enable-quic", args)
        self.assertIn("--origin-to-force-quic-on=localhost:18443", args)
        self.assertIn("https://localhost:18443/", args)
        logs = [arg for arg in args if arg.startswith("--log-net-log=")]
        self.assertEqual(len(logs), 1)
        self.assertEqual(Path(logs[0].split("=", 1)[1]).name, "chromium-netlog.json")
        self.assertFalse(any("capture-mode" in arg for arg in args))
        self.assertEqual(list(self.tmp.iterdir()), [])  # raw log cleaned on every path
        self.assertNotIn(SECRET, result.stdout + result.stderr)
        for marker in (DOM_MARKER, SERVER_MARKER):
            if result.returncode:
                self.assertIn(marker, result.stderr)
            else:
                self.assertNotIn(marker, result.stdout + result.stderr)
        self.assertLess(len(result.stderr), 4096)
        return result

    def test_success_has_no_diagnostics(self):
        result = self.run_client()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "chromium HTTP/3 interop passed\n")
        self.assertEqual(result.stderr, "")

    def test_failure_preserves_client_status_and_existing_logs(self):
        result = self.run_client(CLIENT_STATUS="7", PAYLOAD="unexpected-safe-payload")
        self.assertEqual(result.returncode, 7)
        self.assertIn("failed with status 7", result.stderr)
        self.assertIn("event QUIC_SESSION: 1", result.stderr)
        self.assertIn("net_error -118: 1", result.stderr)
        self.assertNotIn("interop passed", result.stdout)

    def test_timeout_preserves_124_with_truncated_log(self):
        self.fixture.write_text('{"events":[', encoding="utf-8")
        result = self.run_client(TIMEOUT_STATUS="124", PAYLOAD="unexpected-safe-payload")
        self.assertEqual(result.returncode, 124)
        self.assertIn("failed with status 124", result.stderr)
        self.assertIn("chromium NetLog summary unavailable", result.stderr)

    def test_payload_mismatch_remains_failure(self):
        result = self.run_client(PAYLOAD="unexpected-safe-payload")
        self.assertEqual(result.returncode, 1)
        self.assertIn("did not receive the expected HTTP/3 response", result.stderr)
        self.assertIn("event QUIC_SESSION: 1", result.stderr)
        self.assertNotIn("interop passed", result.stdout)

    def test_missing_log_is_harmless(self):
        result = self.run_client(CLIENT_STATUS="9", OMIT_LOG="1")
        self.assertEqual(result.returncode, 9)
        self.assertIn("chromium NetLog summary unavailable", result.stderr)

    def test_failed_summarizer_does_not_replace_client_status_or_assertion(self):
        self.stub("python3", "#!/bin/sh\nexit 23\n")
        result = self.run_client(CLIENT_STATUS="8")
        self.assertEqual(result.returncode, 8)
        result = self.run_client(PAYLOAD="unexpected-safe-payload")
        self.assertEqual(result.returncode, 1)
        self.assertIn("did not receive the expected HTTP/3 response", result.stderr)


if __name__ == "__main__":
    unittest.main()

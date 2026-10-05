#!/usr/bin/env python3
"""Verify streaming failure evidence using a real truncated TCP response."""

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading

root = Path(__file__).resolve().parents[1]
source = (root / "scripts/perf-audit-streaming-compare.sh").read_text()
start = source.index("<<'PY'", source.index("run_client() {")) + len("<<'PY'")
end = source.index("\nPY\n}", start)
client = source[start:end]
listener = socket.socket()
listener.bind(("127.0.0.1", 0))
listener.listen(1)
listener.settimeout(5)
failures = []


def serve():
    try:
        with listener.accept()[0] as peer:
            peer.settimeout(5)
            request = b""
            while b"\r\n\r\n" not in request:
                chunk = peer.recv(1024)
                if not chunk:
                    raise RuntimeError("streaming client closed before its request")
                request += chunk
            peer.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 8192\r\nConnection: close\r\n\r\n" + b"x" * 4096)
    except Exception as error:
        failures.append(error)


server = threading.Thread(target=serve)
server.start()
try:
    result = subprocess.run(
        [sys.executable, "-", "real-truncated-server", str(listener.getsockname()[1]),
         "fast", "0", "8192", "4096", "1", str(root / "scripts"), "1"],
        input=client, capture_output=True, text=True, timeout=10,
        env=dict(os.environ, QPX_STREAMING_COMPARE_NATIVE_DIAGNOSTICS="0",
                 PYTHONDONTWRITEBYTECODE="1"),
    )
finally:
    server.join(timeout=6)
    listener.close()
assert not server.is_alive(), "real truncated server failed to finish"
assert not failures, f"real truncated server failed: {failures}"
assert result.returncode != 0, "incomplete real transfer was accepted"
records = [json.loads(line) for line in result.stderr.splitlines() if line.startswith("{")]
assert len(records) == 1, "real transfer failure lacks structured evidence"
record = records[0]
assert record["valid"] is False and record["stage"] == "response_body", record
assert "incomplete streaming transfer" in record["reason"], record
assert record["completed_transfers"] == 0 and record["transfer_received_bytes"] == 4096, record
assert record["expected_transfer_bytes"] == 8192 and record["last_progress_age_ms"] >= 0, record
print("Real streaming client failure evidence check passed")

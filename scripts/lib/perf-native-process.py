#!/usr/bin/env python3
"""Own the native profiler and real server in one isolated process group."""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def main():
    arguments = sys.argv[1:]
    server = os.environ["QPXD_REAL_BIN"]
    if not arguments or arguments[0] != "run":
        os.execv(server, [server, *arguments])
    config_index = arguments.index("--config") + 1
    role = Path(arguments[config_index]).stem
    directory = Path(os.environ["QPX_NATIVE_PROFILE_DIR"])
    directory.mkdir(parents=True, exist_ok=True)
    lifecycle_path = directory / f"{role}.lifecycle.json"
    lifecycle = {"role": role, "started_monotonic_ns": time.monotonic_ns()}
    requested_signal = None

    def request_shutdown(signum, _frame):
        nonlocal requested_signal
        requested_signal = signum

    signal.signal(signal.SIGTERM, request_shutdown)
    signal.signal(signal.SIGINT, request_shutdown)
    process = subprocess.Popen([
        os.environ["QPX_NATIVE_PERF_BIN"], "record", "-e", "cpu-clock", "-F", "199",
        "--clockid", "CLOCK_MONOTONIC", "--call-graph", "dwarf,16384",
        "-o", str(directory / f"{role}.data"), "--", server, *arguments,
    ], start_new_session=True)
    lifecycle.update({"profiler_pid": process.pid, "process_group": process.pid})
    forced = False
    status = None
    try:
        lifecycle_path.write_text(json.dumps(lifecycle) + "\n")
        print(f"Native CPU process started: role={role} group={process.pid}", flush=True)
        while requested_signal is None:
            try:
                status = process.wait(timeout=0.5)
                break
            except subprocess.TimeoutExpired:
                continue
    finally:
        lifecycle["shutdown_monotonic_ns"] = time.monotonic_ns()
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            status = process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            forced = True
            print(f"Native CPU process shutdown timed out: role={role}", file=sys.stderr)
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            status = process.wait()
        lifecycle.update({
            "finished_monotonic_ns": time.monotonic_ns(),
            "requested_signal": requested_signal, "exit_status": status,
            "forced_shutdown": forced,
        })
        lifecycle_path.write_text(json.dumps(lifecycle) + "\n")
        print(f"Native CPU process stopped: role={role} status={status} forced={forced}", flush=True)
    if forced:
        return 1
    if requested_signal is not None:
        return 128 + requested_signal
    return status if status >= 0 else 128 - status


if __name__ == "__main__":
    raise SystemExit(main())

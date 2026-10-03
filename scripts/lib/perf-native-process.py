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
    mode = os.environ.get("QPX_NATIVE_PROFILE_MODE", "cpu")
    if mode not in ("cpu", "syscalls"):
        raise SystemExit("unsupported native profiler mode")
    if not arguments or (mode == "cpu" and arguments[0] != "run") or arguments in (["-v"], ["-V"], ["--version"]):
        os.execv(server, [server, *arguments])
    if "--config" in arguments:
        role = Path(arguments[arguments.index("--config") + 1]).stem
    elif mode == "syscalls" and Path(server).name == "nginx" and "-c" in arguments:
        config = Path(arguments[arguments.index("-c") + 1])
        role = f"{config.parent.name}-{config.stem}"
    elif mode == "syscalls":
        role = f"{Path(server).name}-{os.getpid()}"
    else:
        raise SystemExit("native CPU profiler requires a server config")
    directory = Path(os.environ["QPX_NATIVE_PROFILE_DIR"])
    directory.mkdir(parents=True, exist_ok=True)
    lifecycle_path = directory / f"{role}.lifecycle.json"
    lifecycle = {"role": role, "mode": mode, "executable": server,
                 "started_monotonic_ns": time.monotonic_ns(), "started_unix_ns": time.time_ns()}
    requested_signal = None

    def save_lifecycle():
        temporary = lifecycle_path.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(lifecycle) + "\n")
        temporary.replace(lifecycle_path)

    def request_shutdown(signum, _frame):
        nonlocal requested_signal
        requested_signal = signum

    signal.signal(signal.SIGTERM, request_shutdown)
    signal.signal(signal.SIGINT, request_shutdown)
    observer = os.environ["QPX_NATIVE_PERF_BIN"]
    if mode == "cpu":
        command = [observer, "record", "-e", "cpu-clock", "-F", "199",
                   "--clockid", "CLOCK_MONOTONIC", "--call-graph", "dwarf,16384",
                   "-o", str(directory / f"{role}.data"), "--", server, *arguments]
    else:
        # Observe waits and socket ownership without recording payload buffers.
        syscalls = "epoll_wait,epoll_pwait,epoll_pwait2,epoll_ctl,poll,ppoll,select,pselect6,futex,connect,setsockopt,getsockopt,shutdown,close"
        command = [observer, "--seccomp-bpf", "-ff", "-qq", "-ttt", "-T", "-yy", "-s", "0",
                   "-e", f"trace={syscalls}", "-o", str(directory / f"{role}.syscalls"),
                   "--", server, *arguments]
        lifecycle["syscalls"] = syscalls.split(",")
        lifecycle["seccomp_filter_observed"] = False
    process = subprocess.Popen(command, start_new_session=True)
    lifecycle.update({"profiler_pid": process.pid, "process_group": process.pid})
    forced = False
    status = None
    try:
        save_lifecycle()
        print(f"Native profiler process started: mode={mode} role={role} group={process.pid}", flush=True)
        while requested_signal is None:
            if mode == "syscalls" and not lifecycle["seccomp_filter_observed"]:
                children = Path(f"/proc/{process.pid}/task/{process.pid}/children")
                try:
                    child_ids = children.read_text().split()
                except FileNotFoundError:
                    child_ids = []
                for child_id in child_ids:
                    child_root = Path(f"/proc/{child_id}")
                    try:
                        fields = dict(line.split(":", 1) for line in child_root.joinpath("status").read_text().splitlines() if ":" in line)
                    except FileNotFoundError:
                        continue
                    if fields.get("Name", "").strip() == Path(server).name[:15] and fields.get("Seccomp", "").strip() == "2":
                        lifecycle["seccomp_filter_observed"] = True
                        lifecycle["tracee_pid"] = int(child_id)
                        save_lifecycle()
            try:
                status = process.wait(timeout=0.01 if mode == "syscalls" and not lifecycle["seccomp_filter_observed"] else 0.5)
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
            print(f"Native profiler process shutdown timed out: role={role}", file=sys.stderr)
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
        save_lifecycle()
        print(f"Native profiler process stopped: role={role} status={status} forced={forced}", flush=True)
    if forced:
        return 1
    if requested_signal is not None:
        return 128 + requested_signal
    return status if status >= 0 else 128 - status


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Run one real workload and retain its exact child CPU usage and exit status."""

import json
import os
from pathlib import Path
import subprocess
import sys
import time


def run(output, command):
    started = time.monotonic_ns()
    process = subprocess.Popen(command)
    pid, status, usage = os.wait4(process.pid, 0)
    finished = time.monotonic_ns()
    if pid != process.pid:
        raise RuntimeError('CPU accounting returned a different workload process')
    process.returncode = os.waitstatus_to_exitcode(status)
    Path(output).write_text(json.dumps({
        'measurement': 'owned_client_wait4_cpu_v1',
        'pid': pid, 'command': command,
        'started_monotonic_ns': started, 'finished_monotonic_ns': finished,
        'elapsed_ns': finished - started,
        'user_cpu_seconds': usage.ru_utime, 'system_cpu_seconds': usage.ru_stime,
        'exit_status': process.returncode,
    }, sort_keys=True) + '\n')
    return process.returncode if process.returncode >= 0 else 128 - process.returncode


if __name__ == '__main__':
    if len(sys.argv) < 3:
        raise SystemExit('usage: perf-client-cpu.py OUTPUT COMMAND [ARGUMENT ...]')
    raise SystemExit(run(sys.argv[1], sys.argv[2:]))

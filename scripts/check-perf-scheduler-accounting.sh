#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/lib/perf-process-metrics.sh"
if [ "$(uname -s)" != Linux ]; then
  echo "Scheduler accounting verification requires Linux" >&2
  exit 1
fi
if [ "$(id -u)" -eq 0 ]; then
  sysctl -w kernel.task_delayacct=1
else
  sudo -n sysctl -w kernel.task_delayacct=1
fi
mkdir -p "$ROOT_DIR/target/perf"
# Start a new process after enabling accounting so every measured thread has it.
perf_proc_python - "$ROOT_DIR" <<'PY_PROBE'
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

root = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location('scheduler', root / 'scripts/lib/perf-process-scheduler.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
original_affinity = os.sched_getaffinity(0)
os.sched_setaffinity(0, {min(original_affinity)})
competitor = subprocess.Popen([sys.executable, '-c', 'while True: pass'])
reader = module.Taskstats()
started = threading.Event()
finish = threading.Event()
worker = None
try:
    before = reader.read(os.getpid())
    def compete():
        started.set()
        value = 1
        while not finish.is_set():
            value = (value * 3 + 1) % 1_000_003
    worker = threading.Thread(target=compete)
    worker.start()
    if not started.wait(2):
        raise RuntimeError('scheduler probe worker did not start')
    time.sleep(0.4)
    active_thread = reader.read(worker.native_id, thread=True)
    active = reader.read(os.getpid())
    finish.set()
    worker.join(timeout=2)
    if worker.is_alive():
        raise RuntimeError('scheduler probe worker did not finish')
    retired = reader.read(os.getpid())
    if not (active_thread['cpu_delay_total_ns'] > 0
            and retired['cpu_delay_total_ns'] - before['cpu_delay_total_ns']
            >= active_thread['cpu_delay_total_ns']):
        raise RuntimeError('retired TGID accounting omitted the observed worker delay')
    if not (before['cpu_delay_total_ns'] < active['cpu_delay_total_ns']
            <= retired['cpu_delay_total_ns']):
        raise RuntimeError('completed thread scheduler delay was not retained')
    if not (before['cpu_count'] < active['cpu_count'] <= retired['cpu_count']):
        raise RuntimeError('completed thread scheduler event count was not retained')
    record = module.snapshot(os.getpid())
    record['retired_thread_probe'] = {'before': before, 'active_thread': active_thread,
                                    'active': active, 'retired': retired}
    (root / 'target/perf/scheduler-accounting-probe.json').write_text(
        json.dumps(record, sort_keys=True) + '\n')
    print('Real completed-thread scheduler accounting verified')
finally:
    finish.set()
    if worker is not None:
        worker.join(timeout=2)
    competitor.terminate()
    try:
        competitor.wait(timeout=2)
    except subprocess.TimeoutExpired:
        competitor.kill()
        competitor.wait()
    reader.socket.close()
    os.sched_setaffinity(0, original_affinity)
PY_PROBE

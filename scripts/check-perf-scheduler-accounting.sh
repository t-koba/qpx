#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/lib/perf-process-metrics.sh"
if [ "$(uname -s)" != Linux ]; then
  echo "Scheduler accounting verification requires Linux" >&2
  exit 1
fi
prepare_process_scheduler_accounting
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
competitor = None
reader = None
started = threading.Event()
finish = threading.Event()
worker = None
try:
    os.sched_setaffinity(0, {min(original_affinity)})
    competitor = subprocess.Popen([sys.executable, '-c', 'while True: pass'])
    reader = module.Taskstats()
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
    detailed = module.snapshot(os.getpid(), thread_details=True)
    observed_worker = next((thread for process in detailed['processes']
                           for thread in process['threads']
                           if thread['status'] == 'live' and thread['tid'] == worker.native_id), None)
    if observed_worker is None or observed_worker['cpu_delay_total_ns'] <= 0:
        raise RuntimeError('thread diagnostics omitted the real competing worker')
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
    live = [thread for process in detailed['processes']
            for thread in process['threads'] if thread['status'] == 'live']
    current = next((thread for thread in live if thread['tid'] == threading.get_native_id()), None)
    if (detailed['thread_details'] is not True or current is None
            or current['scheduled_cpu_ns'] <= 0 or not current['allowed_cpus']
            or current['cpu_delay_total_ns'] < 0):
        raise RuntimeError('real thread scheduler diagnostics are incomplete')
    record = module.snapshot(os.getpid())
    if record['thread_details'] is not False or any('threads' in row for row in record['processes']):
        raise RuntimeError('normal scheduler accounting unexpectedly includes thread diagnostics')
    for edge in ('started', 'finished'):
        lower = record[f'{edge}_monotonic_ns']
        upper = record[f'{edge}_clock_end_monotonic_ns']
        if not (lower <= upper and record[f'{edge}_epoch_ns'] > 0):
            raise RuntimeError('scheduler probe has invalid clock correlation bounds')
    record['retired_thread_probe'] = {'before': before, 'active_thread': active_thread,
                                    'active': active, 'retired': retired}
    record['thread_diagnostics_probe'] = detailed
    (root / 'target/perf/scheduler-accounting-probe.json').write_text(
        json.dumps(record, sort_keys=True) + '\n')
    print('Real completed-thread scheduler accounting verified')
finally:
    finish.set()
    if worker is not None:
        worker.join(timeout=2)
    if competitor is not None:
        competitor.terminate()
        try:
            competitor.wait(timeout=2)
        except subprocess.TimeoutExpired:
            competitor.kill()
            competitor.wait()
    if reader is not None:
        reader.socket.close()
    os.sched_setaffinity(0, original_affinity)
PY_PROBE

#!/usr/bin/env python3
"""Summarize real streaming thread counters without substituting the TGID total."""

import importlib.util
import json
from pathlib import Path
import sys

root, output = map(Path, sys.argv[1:])
spec = importlib.util.spec_from_file_location(
    "scheduler", Path(__file__).parent / "lib/perf-process-scheduler.py")
scheduler = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scheduler)
records = []
for role in ("qpxd", "nginx", "apache", "lighttpd", "direct-backend"):
    for mode in ("fast", "slow"):
        for round_number in range(1, 4):
            for family in (("",) if role == "direct-backend" else ("", "backend-")):
                name = f"streaming.{role}.{mode}.round-{round_number}.attempt-1.{family}scheduler-"
                before_path, after_path = root / f"{name}before.json", root / f"{name}after.json"
                before = json.loads(before_path.read_text())
                after = json.loads(after_path.read_text())
                delay = scheduler.delta(before_path, after_path)
                for snapshot in (before, after):
                    if (snapshot["measurement"] != "linux_taskstats_tgid_cpu_delay_ns_v1"
                            or snapshot.get("thread_details") is not True
                            or not snapshot["processes"]):
                        raise SystemExit("Streaming diagnostics lack requested thread evidence")
                    if snapshot["total_cpu_delay_ns"] != sum(
                            row["cpu_delay_total_ns"] for row in snapshot["processes"]):
                        raise SystemExit("Streaming TGID total is inconsistent")
                    for process in snapshot["processes"]:
                        if not any(thread["status"] == "live" and thread["tid"] == process["pid"]
                                   for thread in process.get("threads", [])):
                            raise SystemExit("Streaming diagnostics lack a live process main thread")
                if (before["root_pid"] != after["root_pid"]
                        or before["finished_epoch_ns"] >= after["started_epoch_ns"]):
                    raise SystemExit("Streaming scheduler window has invalid identity or timing")
                old = {(row["pid"], row["start_ticks"]): row for row in before["processes"]}
                new = {(row["pid"], row["start_ticks"]): row for row in after["processes"]}
                threads = []
                for identity in new:
                    previous = old.get(identity)
                    current = new[identity]
                    old_threads = {} if previous is None else {
                        (t["tid"], t["start_ticks"]): t for t in previous["threads"]
                        if t["status"] == "live"}
                    new_threads = {(t["tid"], t["start_ticks"]): t for t in current["threads"]
                                   if t["status"] == "live"}
                    for thread_id in sorted(old_threads.keys() | new_threads.keys()):
                        a, b = old_threads.get(thread_id), new_threads.get(thread_id)
                        row = {"pid": identity[0], "tid": thread_id[0], "start_ticks": thread_id[1],
                               "name": (b or a)["name"],
                               "status": "matched" if a and b else "appeared" if b else "exited"}
                        if a and b:
                            for field in ("cpu_delay_total_ns", "cpu_count", "scheduled_cpu_ns",
                                          "schedstat_wait_ns", "timeslices"):
                                delta = b[field] - a[field]
                                if delta < 0:
                                    raise SystemExit(f"Streaming thread counter regressed: {field}")
                                row[field] = delta
                        threads.append(row)
                records.append({"role": role, "mode": mode, "round": round_number,
                                "family": "origin" if family else "frontend",
                                "appeared_processes": [row for identity, row in new.items()
                                                       if identity not in old],
                                "total_cpu_delay_ns": delay, "threads": threads})
                print(f"Streaming {role} {mode} round={round_number} "
                      f"{records[-1]['family']} delay_us={delay / 1000:.3f}")
output.write_text(json.dumps(records, indent=2, sort_keys=True) + "\n")

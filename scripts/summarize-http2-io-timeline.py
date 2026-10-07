#!/usr/bin/env python3
"""Correlate real TCP receive tracepoints with sampled origin wake notifications."""

import bisect
import collections
import ipaddress
import json
from pathlib import Path
import re
import statistics
import sys


def address(value):
    host, port = value.rsplit(":", 1)
    return str(ipaddress.ip_address(host.strip("[]"))), int(port)


def packets(path):
    pattern = re.compile(
        r"\s(\d+)\.(\d{1,9}):\s+tcp:tcp_probe:.*?\bsrc=(\S+)\s+dest=(\S+)"
        r".*?\bdata_len=(\d+)\b")
    for line in path.open():
        if "PERF_RECORD_LOST" in line or re.search(r"LOST [1-9]", line):
            raise SystemExit("TCP arrival recording lost events")
        if "tcp:tcp_probe:" not in line:
            continue
        match = pattern.search(line)
        if not match:
            raise SystemExit("TCP arrival tracepoint has an unsupported format")
        seconds, fraction, local, peer, length = match.groups()
        if int(length):
            timestamp = int(seconds) * 1_000_000_000 + int(fraction.ljust(9, "0"))
            # tcp_probe describes the receiving socket's local and peer addresses.
            yield address(local) + address(peer), timestamp, int(length)


if len(sys.argv) == 4 and sys.argv[1] == "--probe":
    identity = json.loads(Path(sys.argv[2]).read_text())
    key = address(identity["local"]) + address(identity["peer"])
    observed = [(at, length) for socket, at, length in packets(Path(sys.argv[3]))
                if socket == key]
    if not observed or sum(length for _, length in observed) < identity["payload_bytes"]:
        raise SystemExit("Real TCP probe lacks the owned socket's received payload event")
    print(f"Real TCP receive tracepoint identity verified: packets={len(observed)}")
    raise SystemExit(0)

if len(sys.argv) != 4:
    raise SystemExit("usage: summarize-http2-io-timeline.py LOG_ROOT EVENTS OUTPUT")
root, events, output = map(Path, sys.argv[1:])
windows = []
for round_number in range(1, 4):
    prefix = f"http2.qpxd.1024.m100.round-{round_number}.attempt-1.scheduler-"
    before = json.loads((root / f"{prefix}before.json").read_text())
    after = json.loads((root / f"{prefix}after.json").read_text())
    if (before["root_pid"] != after["root_pid"]
            or before["finished_monotonic_ns"] >= after["started_monotonic_ns"]):
        raise SystemExit("Native I/O timeline lacks a valid real scheduler window")
    windows.append((round_number, before["finished_monotonic_ns"],
                    after["started_monotonic_ns"]))

identities, completed = {}, {}
for line in (root / "qpxd-h2.log").open():
    try:
        record = json.loads(line)
    except json.JSONDecodeError:
        continue
    if record.get("target") != "qpx_perf_phase":
        continue
    fields = record.get("fields", {})
    if fields.get("phase") != "plain_origin_read":
        continue
    sample_id = fields.get("io_sample_id")
    if not sample_id:
        continue
    if type(sample_id) is not int or sample_id < 1:
        raise SystemExit("Native I/O phase has an invalid identity")
    message = fields.get("message")
    destination = identities if message == "native TCP phase identity" else completed
    if message not in ("native TCP phase identity", "performance phase completed"):
        continue
    if sample_id in destination:
        raise SystemExit("Native I/O phase repeats a sample identity")
    destination[sample_id] = fields
if not identities or not completed or not set(completed).issubset(identities):
    raise SystemExit("Native I/O timeline lacks paired real phase identities")

owned = {address(row["local"]) + address(row["peer"]) for row in identities.values()}
arrivals = collections.defaultdict(list)
for socket, at, _ in packets(events):
    if socket in owned:
        arrivals[socket].append(at)
for timestamps in arrivals.values():
    timestamps.sort()

rows, counts, failures = [], collections.Counter(), []
for sample_id, phase in completed.items():
    identity = identities[sample_id]
    required = ("monotonic_before_ns", "monotonic_after_ns", "phase_offset_ns")
    if not all(type(identity[name]) is int and identity[name] >= 0 for name in required):
        raise SystemExit("Native I/O phase has invalid clock calibration")
    if identity["monotonic_after_ns"] < identity["monotonic_before_ns"]:
        raise SystemExit("Native I/O phase clock calibration regressed")
    lower = identity["monotonic_before_ns"] - identity["phase_offset_ns"]
    upper = identity["monotonic_after_ns"] - identity["phase_offset_ns"]
    request_start = identity.get("request_started_monotonic_ns")
    if type(request_start) is not int or not 0 < request_start <= lower:
        raise SystemExit("Native I/O phase lacks a valid request-start boundary")
    round_number = next((number for number, begin, end in windows
                         if request_start >= begin and upper + phase["elapsed_ns"] <= end), None)
    if round_number is None:
        counts["outside_or_crossing_workload_window"] += 1
        continue
    if phase["pending_polls"] == 0:
        counts["completed_without_pending"] += 1
        continue
    if (phase["pending_polls"] != 1 or phase["notified_resumptions"] != 1
            or phase["polls"] != 2):
        counts["multiple_or_unnotified_pending_polls"] += 1
        continue
    notification = phase["first_notification_ns"]
    if type(notification) is not int or not 0 < notification <= phase["elapsed_ns"]:
        raise SystemExit("Native I/O phase has no valid first notification timestamp")
    socket = address(identity["local"]) + address(identity["peer"])
    timestamps = arrivals[socket]
    index = bisect.bisect_left(timestamps, request_start)
    if index == len(timestamps) or timestamps[index] > upper + notification:
        failures.append(f"sample {sample_id} has no TCP receive event before notification")
        continue
    arrival = timestamps[index]
    rows.append({
        "sample_id": sample_id, "round": round_number,
        "local": identity["local"], "peer": identity["peer"],
        "tcp_receive_monotonic_ns": arrival,
        "calibration_span_ns": upper - lower,
        "request_started_monotonic_ns": request_start,
        "received_before_read_phase": arrival < lower,
        "before_receive_lower_ns": max(0, arrival - upper),
        "before_receive_upper_ns": max(0, arrival - lower),
        "receive_to_notification_lower_ns": lower + notification - arrival,
        "receive_to_notification_upper_ns": upper + notification - arrival,
        "notification_to_resume_ns": phase["notified_wait_ns"],
        "elapsed_ns": phase["elapsed_ns"], "active_poll_ns": phase["active_poll_ns"],
    })
counts["matched_single_pending_poll"] = len(rows)
counts["missing_receive_event"] = len(failures)
counts["identities_without_completion"] = len(set(identities) - set(completed))
for round_number, _, _ in windows:
    selected = [row for row in rows if row["round"] == round_number]
    if not selected:
        failures.append(f"round {round_number} lacks correlated real TCP receive samples")
        continue
    print(f"Origin TCP round={round_number} samples={len(selected)} "
          f"receive_to_notification_median_us="
          f"{statistics.median(row['receive_to_notification_lower_ns'] for row in selected) / 1000:.3f}.."
          f"{statistics.median(row['receive_to_notification_upper_ns'] for row in selected) / 1000:.3f} "
          f"notification_to_resume_median_us="
          f"{statistics.median(row['notification_to_resume_ns'] for row in selected) / 1000:.3f}")
output.write_text(json.dumps({
    "measurement": "real_tcp_receive_to_future_notification_v2",
    "clock": "CLOCK_MONOTONIC", "diagnostic_instrumentation": True,
    "replaces_required_gate": False, "counts": dict(counts),
    "failures": failures, "samples": rows,
}, indent=2) + "\n")
if failures:
    raise SystemExit("; ".join(failures))

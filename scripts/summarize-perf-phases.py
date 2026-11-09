#!/usr/bin/env python3
"""Summarize sampled phase durations from real diagnostic server logs."""

import collections
import datetime
import json
from pathlib import Path
import statistics
import sys

args = sys.argv[1:]
owned_cache_misses = args[-1:] == ["--cache-miss-windows"]
if owned_cache_misses:
    args.pop()
root, output = map(Path, args)
windows = []
if owned_cache_misses:
    for before_path in sorted(root.glob("proxy_cache_miss_http1.qpxd-cache.*.round-*.attempt-1.scheduler-before.json")):
        before = json.loads(before_path.read_text())
        after = json.loads(before_path.with_name(before_path.name.replace("before", "after")).read_text())
        if before["root_pid"] != after["root_pid"]:
            raise SystemExit("cache phase window changed process identity")
        offsets = []
        for snapshot in (before, after):
            for edge in ("started", "finished"):
                epoch, lower, upper = (snapshot[f"{edge}_{key}"] for key in (
                    "epoch_ns", "monotonic_ns", "clock_end_monotonic_ns"))
                if (not all(type(value) is int and value > 0 for value in (epoch, lower, upper))
                        or not 0 <= upper - lower <= 1_000_000):
                    raise SystemExit("cache phase clock correlation is invalid")
                offsets.append((epoch - upper, epoch - lower))
        if max(lo for lo, _ in offsets) - min(hi for _, hi in offsets) > 1_000_000:
            raise SystemExit("cache phase wall-clock drift exceeds 1 ms")
        lower, upper = before["finished_epoch_ns"], after["started_epoch_ns"]
        if lower >= upper or any(lower <= end and start <= upper for _, start, end in windows):
            raise SystemExit("cache phase windows overlap or are reversed")
        windows.append((before_path.name.removesuffix(".attempt-1.scheduler-before.json"), lower, upper))
    if len(windows) != 5:
        raise SystemExit("cache phase diagnostics require five owned miss windows")
samples = collections.defaultdict(list)
poll_samples = collections.defaultdict(list)
socket_samples = collections.defaultdict(list)
sync_cpu_samples = collections.defaultdict(list)
for path in sorted(root.rglob("*.log")):
    for line in path.open(errors="strict"):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("target") != "qpx_perf_phase":
            continue
        fields = record.get("fields", record)
        message = fields.get("message")
        if message == "performance phase CPU sampling failed":
            raise SystemExit(f"Thread CPU measurement failed in {path}: {fields.get('error')}")
        if message == "file socket queue sampling failed":
            raise SystemExit(f"TCP send queue measurement failed in {path}: {fields.get('error')}")
        source = str(path.relative_to(root))
        if owned_cache_misses:
            if path.name != "qpxd-cache.log" or message not in {
                    "performance phase completed", "performance phase synchronous CPU sampled"}:
                continue
            elapsed = fields["elapsed_ns"]
            if type(elapsed) is not int or elapsed < 0:
                raise SystemExit(f"invalid phase duration in {path}")
            stamp = datetime.datetime.fromisoformat(record["timestamp"].replace("Z", "+00:00"))
            if stamp.utcoffset() != datetime.timedelta(0):
                raise SystemExit("cache phase timestamp must be UTC")
            delta = stamp - datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
            epoch_ns = (delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000
            selected = [name for name, lower, upper in windows if lower <= epoch_ns - elapsed and epoch_ns <= upper]
            if not selected:
                continue
            source = f"{selected[0]}/{source}"
        if message == "performance phase synchronous CPU sampled":
            wall, cpu = fields["elapsed_ns"], fields["cpu_ns"]
            if not all(type(value) is int and value >= 0 for value in (wall, cpu)) or cpu > wall:
                raise SystemExit(f"invalid synchronous phase CPU measurement in {path}")
            key = (source, fields["phase"], fields["sample_interval"])
            sync_cpu_samples[key].append((wall, cpu, wall - cpu))
            continue
        if message == "file socket queue sampled":
            queued, unsent = fields["queued_bytes"], fields["unsent_bytes"]
            if not all(isinstance(value, int) and value >= 0 for value in (queued, unsent)) or unsent > queued:
                raise SystemExit(f"invalid TCP send queue measurement in {path}")
            key = (str(path.relative_to(root)), fields["body_bytes"], fields["sample_interval"])
            pending, yields = fields["io_pending_polls"], fields["explicit_yields"]
            if not all(type(value) is int and value >= 0 for value in (pending, yields)):
                raise SystemExit(f"invalid file-body scheduling measurement in {path}")
            socket_samples[key].append((queued, unsent, pending, yields))
            continue
        if fields.get("message") != "performance phase completed":
            continue
        elapsed = fields["elapsed_ns"]
        if not isinstance(elapsed, int) or elapsed < 0:
            raise SystemExit(f"invalid phase duration in {path}")
        key = (source, fields["phase"], fields["sample_interval"])
        samples[key].append(elapsed)
        counter_names = (
            "polls", "pending_polls", "active_poll_ns", "max_active_poll_ns",
            "before_notify_ns", "notified_wait_ns", "unnotified_wait_ns",
            "notified_resumptions")
        present = set(counter_names).intersection(fields)
        if not present and fields["phase"] != "file_body_send":
            # Other crates emit duration-only phases using their own timers.
            continue
        if present != set(counter_names):
            raise SystemExit(f"phase lacks complete future poll counters in {path}")
        counters = {name: fields[name] for name in counter_names}
        if not all(type(value) is int and value >= 0 for value in counters.values()):
            raise SystemExit(f"invalid phase poll counter in {path}")
        if counters["polls"]:
            if (counters["pending_polls"] >= counters["polls"]
                    or counters["notified_resumptions"] > counters["pending_polls"]
                    or counters["max_active_poll_ns"] > counters["active_poll_ns"]
                    or sum(counters[name] for name in (
                        "active_poll_ns", "before_notify_ns", "notified_wait_ns",
                        "unnotified_wait_ns")) > elapsed):
                raise SystemExit(f"inconsistent phase poll accounting in {path}")
            counters["outside_poll_ns"] = elapsed - counters["active_poll_ns"]
            if fields["phase"] == "h2_connection_poll":
                cpu_metrics = ("active_poll_cpu_ns", "max_active_poll_cpu_ns", "cpu_at_max_wall_poll_ns")
                if (fields.get("poll_cpu_enabled") is not True
                        or fields.get("poll_cpu_samples") != counters["polls"]
                        or fields.get("poll_cpu_errors") != 0
                        or any(type(fields.get(name)) is not int or fields[name] < 0
                               for name in cpu_metrics)):
                    raise SystemExit(f"HTTP/2 parent poll lacks complete thread CPU measurements in {path}")
                if (fields["active_poll_cpu_ns"] > counters["active_poll_ns"]
                        or fields["max_active_poll_cpu_ns"] > counters["max_active_poll_ns"]
                        or fields["max_active_poll_cpu_ns"] > fields["active_poll_cpu_ns"]
                        or fields["cpu_at_max_wall_poll_ns"] > fields["max_active_poll_cpu_ns"]):
                    raise SystemExit(f"HTTP/2 parent poll thread CPU accounting is inconsistent in {path}")
                counters.update({name: fields[name] for name in cpu_metrics})
                counters["non_cpu_at_max_wall_poll_ns"] = (
                    counters["max_active_poll_ns"] - fields["cpu_at_max_wall_poll_ns"])
            poll_samples[key].append(counters)
        elif fields["phase"] == "file_body_send":
            raise SystemExit(f"file-body phase lacks observed future polls in {path}")
if not samples:
    raise SystemExit("diagnostic server logs contain no sampled phase timings")
records = []
for (source, phase, interval), values in sorted(samples.items()):
    values.sort()
    record = {
        "source": source, "phase": phase, "sample_interval": interval,
        "samples": len(values), "median_ns": statistics.median(values),
        "p99_ns": values[min(len(values) - 1, (99 * len(values)) // 100)],
        "max_ns": values[-1],
    }
    synchronous = sync_cpu_samples[(source, phase, interval)]
    if phase in {"cache_writer_execution", "cache_directory_validation",
                 "cache_object_create", "cache_object_encode_write", "cache_object_commit"} \
            and len(synchronous) != len(values):
        raise SystemExit(f"{phase} lacks complete synchronous CPU coverage in {source}")
    if synchronous:
        record["observed_sync_cpu_samples"] = len(synchronous)
        for index, metric in enumerate(("sync_wall_ns", "sync_cpu_ns", "sync_non_cpu_ns")):
            measurements = sorted(value[index] for value in synchronous)
            record[metric] = {
                "median": statistics.median(measurements),
                "p99": measurements[min(len(measurements) - 1, (99 * len(measurements)) // 100)],
                "max": measurements[-1],
            }
    observed = poll_samples[(source, phase, interval)]
    if observed:
        record["observed_future_samples"] = len(observed)
        for metric in observed[0]:
            measurements = sorted(sample[metric] for sample in observed)
            record[metric] = {
                "median": statistics.median(measurements),
                "p99": measurements[min(len(measurements) - 1, (99 * len(measurements)) // 100)],
                "max": measurements[-1],
            }
    records.append(record)
if owned_cache_misses:
    required = {"cache_writer_execution", "cache_directory_validation",
                "cache_object_create", "cache_object_encode_write", "cache_object_commit"}
    for name, _, _ in windows:
        observed = {record["phase"] for record in records
                    if record["source"] == f"{name}/qpxd-cache.log"
                    and record.get("observed_sync_cpu_samples", 0) > 0}
        if not required <= observed:
            raise SystemExit(f"cache miss window {name} lacks complete writer phase CPU evidence")
output.write_text(json.dumps(records, indent=2, sort_keys=True) + "\n")
socket_records = []
for (source, body_bytes, interval), values in sorted(socket_samples.items()):
    record = {"source": source, "body_bytes": body_bytes, "sample_interval": interval, "samples": len(values)}
    for index, metric in enumerate(("queued_bytes", "unsent_bytes", "io_pending_polls", "explicit_yields")):
        measurements = sorted(value[index] for value in values)
        record[metric] = {"median": statistics.median(measurements),
                          "p99": measurements[min(len(measurements) - 1, (99 * len(measurements)) // 100)],
                          "max": measurements[-1]}
    socket_records.append(record)
output.with_name("socket-queue-summary.json").write_text(json.dumps(socket_records, indent=2, sort_keys=True) + "\n")
for record in records:
    print(f"{record['source']} {record['phase']}: samples={record['samples']} "
          f"median_us={record['median_ns'] / 1000:.3f} p99_us={record['p99_ns'] / 1000:.3f}")
    if record.get("observed_sync_cpu_samples"):
        print(f"{record['source']} {record['phase']}: "
              f"sync_cpu_median_us={record['sync_cpu_ns']['median'] / 1000:.3f} "
              f"sync_cpu_p99_us={record['sync_cpu_ns']['p99'] / 1000:.3f} "
              f"sync_non_cpu_p99_us={record['sync_non_cpu_ns']['p99'] / 1000:.3f}")
    if record.get("observed_future_samples"):
        print(f"{record['source']} {record['phase']}: "
              f"active_poll_median_us={record['active_poll_ns']['median'] / 1000:.3f} "
              f"before_notify_median_us={record['before_notify_ns']['median'] / 1000:.3f} "
              f"notified_wait_median_us={record['notified_wait_ns']['median'] / 1000:.3f} "
              f"unnotified_wait_median_us={record['unnotified_wait_ns']['median'] / 1000:.3f}")
    if record["phase"] == "h2_connection_poll" and record.get("observed_future_samples"):
        print(f"{record['source']} {record['phase']}: "
              f"max_poll_cpu_p99_us={record['max_active_poll_cpu_ns']['p99'] / 1000:.3f} "
              f"cpu_at_max_wall_poll_p99_us={record['cpu_at_max_wall_poll_ns']['p99'] / 1000:.3f} "
              f"non_cpu_at_max_wall_poll_p99_us={record['non_cpu_at_max_wall_poll_ns']['p99'] / 1000:.3f}")

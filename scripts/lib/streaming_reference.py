"""Paired comparison of the current build against a pinned reference build.

The streaming lane measures the current build and the pinned previous release
in the same rounds, against one origin, with the order inside the pair
alternating between rounds. A cross-run ratio compares two noisy statistics
collected in different runs; the paired per-round difference is the
measurement that answers whether the reverse HTTP/1 path changed between the
two builds.

The comparison is a report, never a gate. It names the build each number
belongs to, states how many rounds were paired, and no objective or check
depends on any of its values.
"""

from __future__ import annotations

import json
import math
import statistics

CURRENT_PROXY = "qpxd"
REFERENCE_PROXY = "qpxd-previous"
READ_MODES = ("fast", "slow")
# The wall-clock time, the CPU efficiency and the tail gap are the three
# numbers the reverse HTTP/1 question is about. Every metric name carries its
# own unit, so a difference carries the unit of its metric.
METRICS = ("total_ms", "requests_per_cpu_second", "p99_chunk_gap_ms")


def load_records(path):
    """Reads the valid per-round records of a raw streaming JSONL."""
    records = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            record = json.loads(stripped)
            if record.get("valid") is not True:
                continue
            records.append(record)
    return records


def _rounds_by_number(records, proxy, read_mode):
    grouped = {}
    for record in records:
        if record.get("proxy") != proxy or record.get("read_mode") != read_mode:
            continue
        round_number = record.get("sample_round")
        if type(round_number) is not int:
            continue
        grouped[round_number] = record
    return grouped


def _finite(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return math.isfinite(value)


def compare(records, current_proxy=CURRENT_PROXY, reference_proxy=REFERENCE_PROXY):
    """Builds the paired per-round comparison for both read modes."""
    report = {
        "comparison": "current_build_versus_pinned_previous_release",
        "gate": False,
        "current_proxy": current_proxy,
        "reference_proxy": reference_proxy,
        "read_modes": {},
    }
    for read_mode in READ_MODES:
        current = _rounds_by_number(records, current_proxy, read_mode)
        reference = _rounds_by_number(records, reference_proxy, read_mode)
        paired = sorted(set(current) & set(reference))
        metrics = {}
        for metric in METRICS:
            ratios = []
            differences = []
            for round_number in paired:
                current_value = current[round_number].get(metric)
                reference_value = reference[round_number].get(metric)
                if not _finite(current_value) or not _finite(reference_value):
                    continue
                if reference_value == 0:
                    continue
                ratios.append(current_value / reference_value)
                differences.append(current_value - reference_value)
            if not ratios:
                continue
            metrics[metric] = {
                "paired_rounds": len(ratios),
                "median_current_over_reference": statistics.median(ratios),
                "min_current_over_reference": min(ratios),
                "max_current_over_reference": max(ratios),
                "median_difference": statistics.median(differences),
            }
        report["read_modes"][read_mode] = {
            "paired_rounds": len(paired),
            "metrics": metrics,
        }
    return report


def format_summary(report):
    """One line that states the comparison, its direction and its status."""
    parts = [
        f"streaming reference (report, not a gate): current vs {report['reference_proxy']};"
        " a total_ms ratio above 1 means the current build was slower"
    ]
    for read_mode in READ_MODES:
        mode = report["read_modes"].get(read_mode, {})
        total = mode.get("metrics", {}).get("total_ms")
        if total is None:
            parts.append(f"{read_mode}: no paired rounds")
            continue
        parts.append(
            f"{read_mode}: total_ms current/reference median "
            f"{total['median_current_over_reference']:.3f} over "
            f"{total['paired_rounds']} paired rounds"
        )
    return "; ".join(parts)

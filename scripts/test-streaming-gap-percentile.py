#!/usr/bin/env python3
"""Focused tests for the streaming p99 estimator's effective sample size.

The captured samples are qpxd fast rounds 1-3 of run 46025615821 at source
sha 5e69146651c63cf7d1d4fe1dce4d4f4ba0cbeb13. Their p99 chunk gaps were
0.258675, 0.177012 and 0.543261 ms: a 3.069063x spread against the unchanged
3.0 stability cap, although their p50 gaps stayed near 0.0233 ms.
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "lib"))
import streaming_gap_percentile

OLD_OBSERVATIONS = 12792  # 100 MiB / 64 KiB - 1, times 8 transfers
CAPTURED = (
    # p50, p95, p99, max, all in milliseconds
    (0.02337400019314373, 0.044955000248592114, 0.25867499971354846,
     1.4774629999010358),
    (0.02329400012968108, 0.045495999984268565, 0.17701200022202102,
     2.0453649999581103),
    (0.023754999801894883, 0.04619599985744571, 0.5432610000752902,
     4.774025999722653),
)


def sample_gaps(quantiles):
    """A monotone gap sample hitting every captured quantile at its rank.

    The raw gaps were not retained. This reconstruction makes the fewest
    assumptions possible: it is monotone, puts the captured p99 at the p99
    rank and the captured maximum at the last rank, and interpolates between
    them. The pauses stay confined to the worst gaps, as the stable p50 and
    p95 require.
    """
    p50, p95, p99, maximum = quantiles
    knots = (
        (0, p50),
        (streaming_gap_percentile.rank_index(OLD_OBSERVATIONS, 50), p50),
        (streaming_gap_percentile.rank_index(OLD_OBSERVATIONS, 95), p95),
        # The stable p95 and p50 mean the pauses start at the p99 rank, so
        # the ordinary gaps stay near p95 right up to that rank.
        (streaming_gap_percentile.rank_index(OLD_OBSERVATIONS, 99) - 1, p95),
        (streaming_gap_percentile.rank_index(OLD_OBSERVATIONS, 99), p99),
        (OLD_OBSERVATIONS - 1, maximum),
    )
    gaps = []
    for index in range(OLD_OBSERVATIONS):
        for (left, low), (right, high) in zip(knots, knots[1:]):
            if left <= index <= right:
                gaps.append(low + (high - low) * (index - left) / (right - left))
                break
    return gaps


def finer_sample(gaps, observations):
    """The same sample read at a finer fixed-byte interval.

    Scheduler pauses are events in time: a finer observation interval creates
    more ordinary gaps between them but does not create more pauses. The
    captured pauses therefore stay in place while the p99 rank moves deeper
    into the ordinary gaps.
    """
    baseline_end = streaming_gap_percentile.rank_index(OLD_OBSERVATIONS, 95)
    baseline = gaps[:baseline_end]
    added = observations - len(gaps)
    return gaps + [baseline[index % len(baseline)] for index in range(added)]


def spread(values):
    return max(values) / min(values)


def observation_interval():
    source = (ROOT / "scripts" / "perf-audit-streaming-compare.sh").read_text()
    match = re.search(r'CHUNK_BYTES="\$\{QPX_STREAMING_COMPARE_CHUNK_BYTES:-(\d+)\}"', source)
    if match is None:
        raise AssertionError("the streaming observation interval is not configured")
    return int(match.group(1))


class StreamingGapStatsTest(unittest.TestCase):
    def test_captured_spread_falls_below_the_cap_with_more_observations(self):
        """The captured values fail at 64 KiB and pass at the finer interval."""
        old = []
        new = []
        observations = (104857600 // observation_interval() - 1) * 8
        for quantiles in CAPTURED:
            gaps = sample_gaps(quantiles)
            old.append(streaming_gap_percentile.percentile(gaps, 99))
            new.append(
                streaming_gap_percentile.percentile(finer_sample(gaps, observations), 99)
            )
        for value, (_p50, _p95, p99, _maximum) in zip(old, CAPTURED):
            self.assertAlmostEqual(value, p99, places=9)
        self.assertAlmostEqual(spread(old), 3.069063, places=6)
        self.assertGreater(spread(old), 3.0)
        self.assertLessEqual(spread(new), 3.0)
        print("captured p99 spread:", f"{spread(old):.6f}", "->", f"{spread(new):.6f}")

    def test_the_finer_interval_doubles_the_tail_sample(self):
        """The default interval gives twice the gaps and twice the p99 tail."""
        self.assertEqual(observation_interval(), 32768)
        self.assertEqual((104857600 // 65536 - 1) * 8, OLD_OBSERVATIONS)
        observations = (104857600 // observation_interval() - 1) * 8
        self.assertEqual(observations, 25592)
        old_tail = OLD_OBSERVATIONS - streaming_gap_percentile.rank_index(
            OLD_OBSERVATIONS, 99
        )
        new_tail = observations - streaming_gap_percentile.rank_index(observations, 99)
        self.assertGreaterEqual(new_tail, old_tail * 2)

    def test_the_rank_rule_is_unchanged_for_small_samples(self):
        """The estimator stays the nearest-rank p99, including slow samples."""
        self.assertEqual(streaming_gap_percentile.percentile([], 99), 0.0)
        self.assertEqual(streaming_gap_percentile.percentile([0.25], 99), 0.25)
        gaps = [0.01 + index * 0.001 for index in range(1599)]
        self.assertEqual(
            streaming_gap_percentile.percentile(gaps, 99),
            sorted(gaps)[streaming_gap_percentile.rank_index(len(gaps), 99)],
        )
        self.assertEqual(
            streaming_gap_percentile.percentile_sorted(sorted(gaps), 99),
            streaming_gap_percentile.percentile(gaps, 99),
        )


if __name__ == "__main__":
    unittest.main()

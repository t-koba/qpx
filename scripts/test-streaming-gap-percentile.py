#!/usr/bin/env python3
"""Focused tests for the streaming p99 estimator's effective sample size.

The captured samples are qpxd fast rounds 1-3 of run 46025615821 at source
sha 5e69146651c63cf7d1d4fe1dce4d4f4ba0cbeb13. Their p99 chunk gaps were
0.258675, 0.177012 and 0.543261 ms: a 3.069063x spread against the unchanged
3.0 stability cap, although their p50 gaps stayed near 0.0233 ms. The
reconstruction below is illustrative, not causal: the retained quantiles do
not determine where the pauses began.
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "lib"))
import streaming_gap_percentile

OLD_OBSERVATIONS = 12792  # 100 MiB / 64 KiB - 1, times 8 transfers
# Fixed nearest-rank indices from the independent oracle, never from the
# estimator under test: ceil(P/100 * N) - 1, clamped to [0, N - 1].
OLD_RANK_50 = 6395
OLD_RANK_95 = 12152
OLD_RANK_99 = 12664
NEW_OBSERVATIONS = 25592  # 100 MiB / 32 KiB - 1, times 8 transfers
NEW_RANK_99 = 25336
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

    The raw gaps were not retained. This monotone reconstruction puts the
    captured p99 at the p99 rank and the captured maximum at the last rank,
    then interpolates between them and the captured p50/p95. It is one sample
    consistent with the quantiles, not an identified cause of the spread.
    """
    p50, p95, p99, maximum = quantiles
    knots = (
        (0, p50),
        (OLD_RANK_50, p50),
        (OLD_RANK_95, p95),
        # Illustrative placement: other burst onsets are equally consistent
        # with the captured quantiles.
        (OLD_RANK_99 - 1, p95),
        (OLD_RANK_99, p99),
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

    Illustration only: if pauses are confined to the tail, adding ordinary
    gaps moves the p99 rank deeper into them. The captured quantiles cannot
    establish this placement, so the result is not a causal claim.
    """
    baseline = gaps[:OLD_RANK_95]
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
        for quantiles in CAPTURED:
            gaps = sample_gaps(quantiles)
            old.append(streaming_gap_percentile.percentile(gaps, 99))
            new.append(
                streaming_gap_percentile.percentile(finer_sample(gaps, NEW_OBSERVATIONS), 99)
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
        self.assertEqual((104857600 // 32768 - 1) * 8, NEW_OBSERVATIONS)
        self.assertEqual(OLD_OBSERVATIONS - OLD_RANK_99, 128)
        self.assertEqual(NEW_OBSERVATIONS - NEW_RANK_99, 256)

    def test_the_rank_rule_matches_fixed_oracle_values(self):
        """The estimator uses nearest-rank indices, not a self-derived rule."""
        expected = (
            (0, 99, 0), (1, 99, 0), (1, 50, 0), (2, 99, 1), (3, 99, 2),
            (10, 50, 4), (10, 99, 9), (20, 99, 19), (100, 50, 49),
            (100, 95, 94), (100, 99, 98), (101, 99, 99), (1000, 99, 989),
            (1599, 99, 1583), (OLD_OBSERVATIONS, 99, OLD_RANK_99),
            (NEW_OBSERVATIONS, 99, NEW_RANK_99),
        )
        for count, percentile, index in expected:
            self.assertEqual(
                streaming_gap_percentile.rank_index(count, percentile),
                index,
                f"rank_index({count}, {percentile})",
            )

    def test_percentiles_match_literal_small_sample_values(self):
        """A known sorted sample yields the literal nearest-rank values."""
        ordered = [0.01 + index * 0.001 for index in range(100)]
        self.assertAlmostEqual(
            streaming_gap_percentile.percentile_sorted(ordered, 50), 0.059, places=12
        )
        self.assertAlmostEqual(
            streaming_gap_percentile.percentile_sorted(ordered, 95), 0.104, places=12
        )
        self.assertAlmostEqual(
            streaming_gap_percentile.percentile_sorted(ordered, 99), 0.108, places=12
        )
        self.assertEqual(streaming_gap_percentile.percentile_sorted([], 99), 0.0)


if __name__ == "__main__":
    unittest.main()

"""Nearest-rank percentile of streaming chunk-gap observations.

The streaming harness owns the rank rule in one place so its producer and its
focused test agree on what p99 means. The estimator itself is unchanged: the
stability fix is a finer fixed-byte observation interval, which gives the same
p99 rank many more observations to draw from.
"""


def rank_index(count, percentile):
    """The nearest-rank index of a percentile in ``count`` observations."""
    if count <= 0:
        return 0
    return min(count - 1, max(0, int((count * percentile + 99) // 100) - 1))


def percentile(gaps, percentile_value):
    """The nearest-rank percentile of the gap observations."""
    ordered = sorted(gaps)
    if not ordered:
        return 0.0
    return ordered[rank_index(len(ordered), percentile_value)]

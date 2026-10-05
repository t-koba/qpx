"""Bound complete measurements even when individual I/O keeps progressing."""

from contextlib import contextmanager
import math
import signal


@contextmanager
def measurement_deadline(seconds, label):
    if not math.isfinite(seconds) or seconds <= 0:
        raise ValueError("measurement deadline must be finite and positive")
    if signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
        raise RuntimeError("measurement deadline requires an unused real-time timer")
    previous_handler = signal.getsignal(signal.SIGALRM)

    def expired(_signum, _frame):
        raise TimeoutError(f"{label} completion deadline exceeded after {seconds:.3f} seconds")

    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)

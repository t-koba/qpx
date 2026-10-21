"""The plan of one round's paired streaming measurement.

One round measures the current build and the pinned reference build next to
each other, against the same origin. The order inside the pair alternates
between rounds, so neither build can gain from a fixed position in the
round, and both members carry the round's number, so the report can pair
them afterwards.

This module is the one owner of that round identity: the shell applies the
plan, the per-round record carries the plan's round, and the report pairs on
the round it finds there.
"""

from __future__ import annotations

import sys

CURRENT_PROXY = "qpxd"
REFERENCE_PROXY = "qpxd-previous"


def plan(round_number, reference_available=True):
    """The round's identity and the order in which its members are measured."""
    if type(round_number) is not int or round_number < 1:
        raise ValueError(
            f"the round number must be a positive integer: {round_number!r}"
        )
    members = [CURRENT_PROXY]
    if reference_available:
        members.append(REFERENCE_PROXY)
    if len(members) == 2 and round_number % 2 == 0:
        members.reverse()
    return {"round": round_number, "members": members}


def format_plan(the_plan):
    """One line for the shell: the round, then its members in order."""
    return " ".join([str(the_plan["round"]), *the_plan["members"]])


def reference_available(raw):
    """Reads the caller's yes-or-no answer about the reference build."""
    if raw in ("true", "1", "yes"):
        return True
    if raw in ("false", "0", "no", ""):
        return False
    raise ValueError(f"the reference availability must be true or false: {raw!r}")


def main(argv):
    if len(argv) not in (2, 3):
        print(
            "usage: streaming_pair.py <round> [reference_available]",
            file=sys.stderr,
        )
        return 2
    try:
        the_plan = plan(
            int(argv[1]),
            reference_available(argv[2]) if len(argv) == 3 else True,
        )
    except ValueError as error:
        print(f"streaming_pair.py: {error}", file=sys.stderr)
        return 2
    print(format_plan(the_plan))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

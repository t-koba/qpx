#!/usr/bin/env python3
"""Failure-only NetLog counts: never render parameters or unvalidated strings.

Default Chromium capture mode only; raw logs stay in the interop temporary directory.
Read at most 8 MiB and print at most 26 lines, regardless of log contents.
"""

import collections
import json
import re
import sys

MAX_BYTES = 8 * 1024 * 1024
MAX_ITEMS = 12
UNAVAILABLE = "chromium NetLog summary unavailable"
EVENT_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,63}", re.ASCII)


def summarize(path):
    try:
        with open(path, "rb") as source:
            raw = source.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            return [UNAVAILABLE]
        log = json.loads(raw)
        types = log["constants"]["logEventTypes"]
        events = log["events"]
        if not isinstance(types, dict) or not isinstance(events, list):
            return [UNAVAILABLE]
        # Treat the constants table as untrusted too. Only these short ASCII
        # identifiers may reach output; no parameters or other strings can.
        names = {
            value: name
            for name, value in types.items()
            if type(value) is int
            and EVENT_NAME.fullmatch(name)
            and name.startswith(("QUIC", "HTTP_STREAM", "URL_REQUEST"))
        }
        event_counts = collections.Counter()
        errors = collections.Counter()
        for event in events:
            event_type = event.get("type")
            if type(event_type) is int and event_type in names:
                event_counts[names[event_type]] += 1
            params = event.get("params", {})
            error = params.get("net_error")
            # Chromium net errors are signed integers, not strings or booleans.
            if type(error) is int and -(2**31) <= error < 2**31:
                errors[error] += 1
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
        return [UNAVAILABLE]

    lines = ["chromium NetLog summary (bounded counts):"]
    lines.extend(
        f"event {name}: {count}"
        for name, count in sorted(event_counts.items())[:MAX_ITEMS]
    )
    lines.extend(
        f"net_error {code}: {count}"
        for code, count in sorted(errors.items())[:MAX_ITEMS]
    )
    if len(event_counts) > MAX_ITEMS or len(errors) > MAX_ITEMS:
        lines.append("chromium NetLog summary truncated")
    return lines


if __name__ == "__main__":
    print("\n".join(summarize(sys.argv[1])))

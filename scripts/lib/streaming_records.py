"""The per-round streaming record.

One record describes one proxy's measurement in one round of the streaming
lane. The round number belongs to the record, so the paired report can pair
the current build's record with the reference build's record of the same
round.
"""

from __future__ import annotations

import json
import sys


def write_round_record(
    out_path,
    sample,
    stream_bytes,
    chunk_bytes,
    attempts,
    valid_samples,
    commit,
    sample_round,
):
    """Appends one proxy's measurement of one round to the lane's records."""
    record = json.loads(sample)
    record.update(
        {
            "bench": "proxy_compare_http1_streaming_reverse",
            "stream_bytes": int(stream_bytes),
            "chunk_bytes": int(chunk_bytes),
            "sample_attempts": int(attempts),
            "valid_samples": int(valid_samples),
            "aggregation": "single_sample",
            "sample_round": int(sample_round),
            "commit": commit,
        }
    )
    with open(out_path, "a", encoding="utf-8") as handle:
        handle.write(
            json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        )
    return record


def main(argv):
    if len(argv) != 9:
        print(
            "usage: streaming_records.py <out> <sample> <stream_bytes> <chunk_bytes>"
            " <attempts> <valid_samples> <commit> <sample_round>",
            file=sys.stderr,
        )
        return 2
    write_round_record(*argv[1:])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

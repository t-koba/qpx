#!/usr/bin/env python3
"""Read complete process-tree descriptor data, including non-dumpable servers."""

import json
import os
from pathlib import Path
import sys
import time


def descriptors(root, include_targets=False):
    seen = set()
    pending = [root]
    records = []
    while pending:
        pid = pending.pop()
        if pid in seen:
            continue
        seen.add(pid)
        base = Path('/proc') / pid
        try:
            for task in (base / 'task').iterdir():
                pending.extend((task / 'children').read_text().split())
            for fd in (base / 'fd').iterdir():
                record = {'pid': int(pid), 'fd': int(fd.name)}
                if include_targets:
                    try:
                        record['target'] = os.readlink(fd)
                    except FileNotFoundError:
                        continue
                records.append(record)
        except FileNotFoundError:
            continue
    if not records:
        raise RuntimeError('process descriptor snapshot is empty')
    return records


mode, root = sys.argv[1:3]
if mode == 'count':
    print(len(descriptors(root)))
elif mode == 'snapshot':
    Path(sys.argv[3]).write_text(json.dumps(descriptors(root, True), sort_keys=True) + '\n')
elif mode == 'monitor':
    output, stop = map(Path, sys.argv[3:5])
    peak = int(sys.argv[5])
    try:
        output.write_text(str(peak) + '\n')
        while not stop.exists() and (Path('/proc') / root).exists():
            peak = max(peak, len(descriptors(root)))
            output.write_text(str(peak) + '\n')
            time.sleep(0.05)
    except Exception as error:
        Path(str(output) + '.error').write_text(str(error) + '\n')
        raise
else:
    raise SystemExit('unsupported descriptor measurement mode')

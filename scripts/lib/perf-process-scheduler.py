#!/usr/bin/env python3
"""Read Linux TGID delay accounting, including completed threads."""

import json
import os
from pathlib import Path
import socket
import struct
import sys
import time


def attributes(payload):
    offset = 0
    while offset < len(payload):
        if len(payload) - offset < 4:
            raise RuntimeError('truncated netlink attribute header')
        size, kind = struct.unpack_from('=HH', payload, offset)
        if size < 4 or offset + size > len(payload):
            raise RuntimeError('invalid netlink attribute length')
        yield kind & 0x3fff, payload[offset + 4:offset + size]
        offset += (size + 3) & ~3
    if offset != len(payload):
        raise RuntimeError('truncated netlink attribute padding')


def attribute(kind, payload):
    size = 4 + len(payload)
    return struct.pack('=HH', size, kind) + payload + bytes((-size) % 4)


class Taskstats:
    def __init__(self):
        self.socket = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 16)
        try:
            self.socket.settimeout(2)
            self.socket.bind((0, 0))
            self.sequence = 0
            reply = self.request(16, 3, attribute(2, b'TASKSTATS\0'))
            family = [value for kind, value in attributes(reply[4:]) if kind == 1]
            if len(family) != 1 or len(family[0]) != 2:
                raise RuntimeError('TASKSTATS family resolution failed')
            self.family = struct.unpack('=H', family[0])[0]
        except BaseException:
            self.socket.close()
            raise

    def request(self, family, command, payload):
        self.sequence += 1
        body = struct.pack('=BBH', command, 1, 0) + payload
        header = struct.pack('=IHHII', 16 + len(body), family, 1,
                             self.sequence, self.socket.getsockname()[0])
        self.socket.sendto(header + body, (0, 0))
        while True:
            packet, _, flags, sender = self.socket.recvmsg(65536)
            if flags & socket.MSG_TRUNC or sender[0] != 0:
                raise RuntimeError('invalid or truncated taskstats response')
            offset = 0
            while offset < len(packet):
                if len(packet) - offset < 16:
                    raise RuntimeError('truncated netlink message header')
                size, kind, _, sequence, _ = struct.unpack_from('=IHHII', packet, offset)
                if size < 16 or offset + size > len(packet) or sequence != self.sequence:
                    raise RuntimeError('invalid taskstats message length or sequence')
                result = packet[offset + 16:offset + size]
                if kind == 2:
                    if len(result) < 4:
                        raise RuntimeError('truncated netlink error')
                    error = struct.unpack_from('=i', result)[0]
                    if error:
                        raise OSError(-error, os.strerror(-error))
                elif kind == family:
                    if len(result) < 4:
                        raise RuntimeError('truncated generic netlink response')
                    return result
                else:
                    raise RuntimeError(f'unexpected taskstats message type: {kind}')
                offset += (size + 3) & ~3

    def read(self, pid, *, thread=False):
        identity_kind = 1 if thread else 2
        aggregate_kind = 4 if thread else 5
        reply = self.request(self.family, 1, attribute(identity_kind, struct.pack('=I', pid)))
        if reply[0] != 2:
            raise RuntimeError('unexpected TASKSTATS response command')
        aggregates = [value for kind, value in attributes(reply[4:]) if kind == aggregate_kind]
        if len(aggregates) != 1:
            raise RuntimeError('TASKSTATS TGID aggregate is missing or duplicated')
        fields = list(attributes(aggregates[0]))
        identities = [value for kind, value in fields if kind == identity_kind]
        statistics = [value for kind, value in fields if kind == 3]
        if (len(identities) != 1 or identities[0] != struct.pack('=I', pid)
                or len(statistics) != 1 or len(statistics[0]) < 32):
            raise RuntimeError('invalid TASKSTATS TGID identity or statistics')
        data = statistics[0]
        version = struct.unpack_from('=H', data)[0]
        if version < 12:
            raise RuntimeError(f'unsupported taskstats version: {version}')
        count, delay = struct.unpack_from('=QQ', data, 16)
        return {'pid': pid, 'taskstats_version': version,
                'cpu_count': count, 'cpu_delay_total_ns': delay}


def identity(base):
    fields = (base / 'stat').read_text().rsplit(') ', 1)[1].split()
    if fields[0] in ('Z', 'X'):
        raise RuntimeError(f'measured process has terminated: {base.name}')
    return int(fields[19])


def snapshot(root):
    if Path('/proc/sys/kernel/task_delayacct').read_text().strip() != '1':
        raise RuntimeError('kernel.task_delayacct must be enabled before process startup')
    reader = Taskstats()
    pending = [root]
    seen = set()
    records = []
    started = time.monotonic_ns()
    started_epoch = time.time_ns()
    started_clock_end = time.monotonic_ns()
    try:
        while pending:
            pid = pending.pop()
            if pid in seen:
                continue
            seen.add(pid)
            base = Path('/proc') / str(pid)
            before = identity(base)
            for task in (base / 'task').iterdir():
                try:
                    pending.extend(int(child) for child in (task / 'children').read_text().split())
                except FileNotFoundError:
                    # Completed threads remain included in the TGID aggregate.
                    continue
            record = reader.read(pid)
            if identity(base) != before:
                raise RuntimeError(f'measured process identity changed: {pid}')
            record['start_ticks'] = before
            records.append(record)
    finally:
        reader.socket.close()
    finished = time.monotonic_ns()
    finished_epoch = time.time_ns()
    finished_clock_end = time.monotonic_ns()
    return {'measurement': 'linux_taskstats_tgid_cpu_delay_ns_v1', 'root_pid': root,
            'task_delayacct': True, 'started_monotonic_ns': started,
            'started_epoch_ns': started_epoch, 'started_clock_end_monotonic_ns': started_clock_end,
            'finished_monotonic_ns': finished, 'finished_epoch_ns': finished_epoch,
            'finished_clock_end_monotonic_ns': finished_clock_end, 'processes': records,
            'total_cpu_delay_ns': sum(row['cpu_delay_total_ns'] for row in records)}


def delta(before_path, after_path):
    before = json.loads(Path(before_path).read_text())
    after = json.loads(Path(after_path).read_text())
    if (before['measurement'] != 'linux_taskstats_tgid_cpu_delay_ns_v1'
            or after['measurement'] != before['measurement']
            or before['root_pid'] != after['root_pid']
            or before['finished_monotonic_ns'] > after['started_monotonic_ns']
            or before['task_delayacct'] is not True or after['task_delayacct'] is not True):
        raise RuntimeError('scheduler snapshots do not describe the same measurement')
    previous = {row['pid']: row for row in before['processes']}
    current = {row['pid']: row for row in after['processes']}
    if not previous.keys() <= current.keys():
        raise RuntimeError('measured process exited before its final scheduler snapshot')
    for pid, row in previous.items():
        if (current[pid]['start_ticks'] != row['start_ticks']
                or current[pid]['taskstats_version'] != row['taskstats_version']
                or current[pid]['cpu_delay_total_ns'] < row['cpu_delay_total_ns']
                or current[pid]['cpu_count'] < row['cpu_count']):
            raise RuntimeError(f'measured process identity or scheduler counter changed: {pid}')
    for record in (before, after):
        if record['total_cpu_delay_ns'] != sum(row['cpu_delay_total_ns'] for row in record['processes']):
            raise RuntimeError('scheduler snapshot total is inconsistent')
    return after['total_cpu_delay_ns'] - before['total_cpu_delay_ns']


if __name__ == '__main__':
    try:
        if sys.platform != 'linux':
            raise RuntimeError('process scheduler accounting requires Linux')
        if sys.argv[1] == 'delta':
            print(delta(sys.argv[2], sys.argv[3]))
        else:
            record = snapshot(int(sys.argv[1]))
            if len(sys.argv) > 2:
                Path(sys.argv[2]).write_text(json.dumps(record, sort_keys=True) + '\n')
            print(record['total_cpu_delay_ns'])
    except (OSError, RuntimeError, ValueError) as error:
        raise SystemExit(f'Invalid measurement: {error}') from error

#!/usr/bin/env python3
"""Sample real IPv4 TCP transport state through Linux SOCK_DIAG."""

import argparse
import gzip
import json
import os
from pathlib import Path
import socket
import struct
import sys
import time


def tcp_snapshot(diag, ports, sequence):
    # Linux inet_diag_req_v2 and inet_diag_sockid from the public UAPI.
    request = struct.pack("=BBBBI", socket.AF_INET, socket.IPPROTO_TCP, 2, 0, 2)
    request += bytes(40) + struct.pack("=II", 0xFFFFFFFF, 0xFFFFFFFF)
    header = struct.pack("=IHHII", 16 + len(request), 20, 0x301, sequence, 0)
    diag.send(header + request)
    result = []
    while True:
        data, _, flags, sender = diag.recvmsg(1024 * 1024)
        if flags & socket.MSG_TRUNC or sender[0] != 0:
            raise RuntimeError("TCP diagnostic netlink response was truncated or not from the kernel")
        offset = 0
        while offset < len(data):
            if len(data) - offset < 16:
                raise RuntimeError("TCP diagnostic netlink header is incomplete")
            length, kind, message_flags, seq, _ = struct.unpack_from("=IHHII", data, offset)
            if length < 16 or offset + length > len(data) or seq != sequence:
                raise RuntimeError("TCP diagnostic netlink framing or sequence is invalid")
            payload = data[offset + 16 : offset + length]
            if message_flags & 0x10:
                raise RuntimeError("TCP diagnostic netlink dump was interrupted")
            if kind == 3:
                if len(payload) >= 4 and struct.unpack_from("=i", payload)[0] != 0:
                    raise RuntimeError("TCP diagnostic netlink dump failed")
                return result
            if kind == 2:
                raise RuntimeError("TCP diagnostic kernel rejected the netlink request")
            if kind != 20 or len(payload) < 72 or payload[0] != socket.AF_INET:
                raise RuntimeError("TCP diagnostic socket response is invalid")
            sport, dport = struct.unpack_from("!HH", payload, 4)
            if sport in ports or dport in ports:
                info = None
                attribute_offset = 72
                while attribute_offset < len(payload):
                    if len(payload) - attribute_offset < 4:
                        raise RuntimeError("TCP diagnostic attribute header is incomplete")
                    size, attribute = struct.unpack_from("=HH", payload, attribute_offset)
                    if size < 4 or attribute_offset + size > len(payload):
                        raise RuntimeError("TCP diagnostic attribute framing is invalid")
                    if attribute == 2:
                        info = payload[attribute_offset + 4 : attribute_offset + size]
                    attribute_offset += (size + 3) & ~3
                if info is None or len(info) < 236:
                    raise RuntimeError("TCP diagnostic lacks required Linux TCP_INFO window counters")
                u32 = lambda position: struct.unpack_from("=I", info, position)[0]
                u64 = lambda position: struct.unpack_from("=Q", info, position)[0]
                result.append({
                    "source": socket.inet_ntop(socket.AF_INET, payload[8:12]),
                    "destination": socket.inet_ntop(socket.AF_INET, payload[24:28]),
                    "source_port": sport, "destination_port": dport,
                    "cookie": struct.unpack_from("=Q", payload, 44)[0],
                    "receive_queue": struct.unpack_from("=I", payload, 56)[0],
                    "write_queue": struct.unpack_from("=I", payload, 60)[0],
                    "unacked": u32(24), "rto_us": u32(8), "total_retrans": u32(100),
                    "last_data_sent_ms": u32(44), "last_data_received_ms": u32(52),
                    "last_ack_received_ms": u32(56), "rtt_us": u32(68),
                    "send_window": u32(228), "receive_window": u32(232),
                    "notsent_bytes": u32(144), "bytes_acked": u64(120),
                    "bytes_received": u64(128), "bytes_sent": u64(200),
                    "bytes_retransmitted": u64(208), "rwnd_limited_us": u64(176),
                    "tcp_info_bytes": len(info),
                })
            offset += (length + 3) & ~3


def open_diag():
    if sys.platform != "linux":
        raise RuntimeError("TCP diagnostic requires Linux SOCK_DIAG")
    diag = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 4)
    diag.bind((0, 0))
    diag.settimeout(1)
    return diag


def probe():
    with open_diag() as diag, socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(1)
        port = listener.getsockname()[1]
        with socket.create_connection(listener.getsockname(), timeout=1) as client:
            server, _ = listener.accept()
            with server:
                server.settimeout(1)
                body = b"real-tcp-info-probe"
                client.sendall(body)
                received = b""
                while len(received) < len(body):
                    chunk = server.recv(len(body) - len(received))
                    if not chunk:
                        raise RuntimeError("TCP diagnostic probe ended before the body")
                    received += chunk
                if received != body:
                    raise RuntimeError("TCP diagnostic probe body mismatch")
                rows = tcp_snapshot(diag, {port}, 1)
                incoming = [r for r in rows if r["source_port"] == port]
                if len(rows) != 2 or len(incoming) != 1 or incoming[0]["bytes_received"] < len(body):
                    raise RuntimeError("TCP diagnostic probe did not observe both real transport endpoints")
                if len({r["cookie"] for r in rows}) != 2:
                    raise RuntimeError("TCP diagnostic probe did not distinguish real sockets")
    print("Real TCP_INFO netlink probe passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe-only", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--stop-file", type=Path)
    parser.add_argument("--ports", type=int, nargs="+")
    args = parser.parse_args()
    if args.probe_only:
        probe()
        return
    if not args.output or not args.stop_file or not args.ports:
        parser.error("output, stop-file, and ports are required")
    if any(port < 1 or port > 65535 for port in args.ports):
        parser.error("ports must be between 1 and 65535")
    if args.stop_file.exists():
        raise RuntimeError("TCP diagnostic stop file already exists")
    count = socket_samples = 0
    interval = 0.1
    maximum_gap = 0
    previous = None
    with open_diag() as diag, gzip.open(args.output, "xt", encoding="utf8") as output:
        while not args.stop_file.exists():
            start = time.monotonic_ns()
            if previous is not None:
                maximum_gap = max(maximum_gap, start - previous)
            previous = start
            rows = tcp_snapshot(diag, set(args.ports), count + 1)
            output.write(json.dumps({"monotonic_ns": start, "sockets": rows}) + "\n")
            count += 1
            socket_samples += len(rows)
            time.sleep(max(0, interval - (time.monotonic_ns() - start) / 1e9))
    if not count or not socket_samples:
        raise RuntimeError("TCP diagnostic captured no real benchmark sockets")
    args.output.with_suffix(".sampling.json").write_text(json.dumps({
        "clock": "CLOCK_MONOTONIC", "payload_capture": False, "sampler_pid": os.getpid(),
        "samples": count, "socket_samples": socket_samples,
        "interval_seconds": interval, "maximum_gap_seconds": maximum_gap / 1e9,
        "listener_ports": args.ports,
    }) + "\n")


if __name__ == "__main__":
    main()

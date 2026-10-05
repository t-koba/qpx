#!/usr/bin/env python3
"""Verify whole-transfer deadlines with continuously progressing real TCP I/O."""

import socket
import threading

from lib.perf_deadline import measurement_deadline


def transfer(paced):
    payload = b"x" * 64
    stopped = threading.Event()
    failures = []
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)

    def serve():
        try:
            with listener.accept()[0] as peer:
                if paced:
                    for byte in payload:
                        if stopped.is_set():
                            break
                        peer.sendall(bytes([byte]))
                        if stopped.wait(0.01):
                            break
                else:
                    peer.sendall(payload)
        except OSError as error:
            failures.append(error)

    server = threading.Thread(target=serve)
    server.start()
    received = bytearray()
    expired = False
    try:
        with socket.create_connection(listener.getsockname(), timeout=1) as client:
            received.extend(client.recv(1))
            client.settimeout(0.1)
            try:
                with measurement_deadline(0.08 if paced else 1, "real TCP transfer"):
                    while chunk := client.recv(64):
                        received.extend(chunk)
            except TimeoutError as error:
                if "completion deadline exceeded" not in str(error):
                    raise
                expired = True
            finally:
                stopped.set()
    finally:
        server.join(timeout=2)
        listener.close()
    assert not server.is_alive(), "real TCP server failed to finish"
    assert not failures, f"real TCP server failed: {failures}"
    if paced:
        assert expired and 0 < len(received) < len(payload), "progressing transfer escaped its deadline"
    else:
        assert not expired and received == payload, "complete transfer failed"


transfer(False)
transfer(True)
print("Real TCP completion deadline checks passed")

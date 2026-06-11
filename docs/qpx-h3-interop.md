# qpx-h3 Interop

The qpx-h3 backend is tested against the repository e2e suite for request/response streaming, trailers, extended CONNECT, CONNECT-UDP, and WebTransport behavior. External interop targets should cover curl HTTP/3, Chromium WebTransport, ngtcp2/quiche peers, gRPC over H3, SSE over H3, and MASQUE.

Known backend distinction:

- `http3-backend-h3` uses the upstream `h3` crate stack.
- `http3-backend-qpx` uses the QPX-owned implementation and advanced WebTransport path.

When investigating failures, capture qlog/packet traces and record whether the h3 or qpx-h3 backend was active.

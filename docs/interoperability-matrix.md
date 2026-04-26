# Interoperability Matrix

This file is the protocol and performance baseline for the current non-compatible config redesign.

Acceptance is based on:

- standards-driven interoperability
- use-case preservation
- release benchmark non-regression

Not on internal behavioral equivalence with earlier config shapes.

## Protocol lanes

HTTP substrate:

- HTTP/1.1 proxy semantics, including `CONNECT`
- HTTP/2 downstream proxying, including RFC 8441 extended CONNECT on the supported forward path
- HTTP/3 per RFC 9114
- QPACK per RFC 9204
- HTTP Datagrams / Capsules per RFC 9297
- CONNECT-UDP per RFC 9298
- WebTransport per `draft-ietf-webtrans-http3-15`

QPX product lanes:

- reverse HTTP/3 terminate
- reverse HTTP/3 passthrough
- generic HTTP/3 extended CONNECT
- CONNECT-UDP / MASQUE relay
- WebTransport relay
- forward / reverse / transparent / MITM HTTP response-stage policy

RPC lanes:

- gRPC unary
- gRPC streaming
- Connect unary/streaming
- gRPC-Web unary/streaming

## Release benchmark lanes

The release benchmark gate should continue to measure, at minimum:

- forward CONNECT
- reverse upstream HTTP/1
- reverse local response
- reverse HTTP/3 terminate
- reverse HTTP/3 passthrough
- CONNECT-UDP
- generic HTTP/3 extended CONNECT
- WebTransport relay
- gRPC unary
- gRPC streaming

These are the current throughput / p95 lanes implemented in:

- `qpxd/tests/perf_smoke.rs`
- `qpxd/tests/advanced_transport_perf.rs`

and enforced on the self-hosted reference host in the `release` workflow.

## Release-mode RPC smoke lanes

The release workflow also reruns these higher-value protocol-correctness checks on the same reference host:

- RPC-aware trailer/local-response correctness (`gRPC`, `gRPC-Web`)

## Current always-on smoke coverage

The repo already keeps these lower-cost regression lanes live in CI/local validation:

- `qpxd/tests/perf_smoke.rs`
- `scripts/e2e-control-plane.sh`
- `scripts/e2e-control-plane.ps1`
- `scripts/e2e-control-plane-soak.sh`
- `scripts/check-config-samples.sh`
- `scripts/e2e-config-samples.sh`

These smoke lanes are early warning only in regular CI. Release acceptance is enforced separately on the self-hosted reference host through the `release` workflow's `benchmark_gate` job, which reruns the release-mode benchmark lanes before packaging artifacts.

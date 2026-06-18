# qpx-h3 Interop

The qpx-h3 backend is tested against the repository e2e suite for
request/response streaming, trailers, extended CONNECT, CONNECT-UDP, and
WebTransport behavior. This document is the public interop matrix: record
observed results, not only planned coverage.

Known backend distinction:

- `http3-backend-h3` uses the upstream `h3` crate stack.
- `http3-backend-qpx` uses the QPX-owned implementation and advanced WebTransport path.

When investigating failures, capture qlog/packet traces and record whether the h3 or qpx-h3 backend was active.

## Matrix Format

The table column is shown as `pass/fail`; the JSON field emitted by the runner
is `pass_fail`.

| backend | scenario | peer/client | pass/fail | qlog_available | known_limitation | tested_commit | tested_at | command_or_test |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| h3 | curl HTTP/3 | curl | skipped | no | external tool not present in default CI | pending | pending | `QPX_H3_INTEROP_BACKENDS=h3 scripts/h3-interop/run.sh curl-http3` |
| h3 | Chromium WebTransport | chromium | skipped | no | external browser not present in default CI | pending | pending | `QPX_H3_INTEROP_BACKENDS=h3 scripts/h3-interop/run.sh chromium-webtransport` |
| h3 | ngtcp2 | ngtcp2 | skipped | no | external peer not present in default CI | pending | pending | `QPX_H3_INTEROP_BACKENDS=h3 scripts/h3-interop/run.sh ngtcp2` |
| h3 | quiche | quiche | skipped | no | external peer not present in default CI | pending | pending | `QPX_H3_INTEROP_BACKENDS=h3 scripts/h3-interop/run.sh quiche` |
| h3 | gRPC over H3 | repository e2e | pending | no | needs opt-in interop run | pending | pending | `cargo test -p qpxd --test h3_streaming_e2e --features http3-backend-h3,tls-rustls grpc` |
| h3 | SSE over H3 | repository e2e | pending | no | needs opt-in interop run | pending | pending | `cargo test -p qpxd --test h3_streaming_e2e --features http3-backend-h3,tls-rustls sse` |
| h3 | CONNECT-UDP | repository e2e | pending | no | needs opt-in interop run | pending | pending | `cargo test -p qpxd --test forward_e2e --features http3-backend-h3,tls-rustls connect_udp` |
| h3 | MASQUE | repository e2e | pending | no | URI-template coverage shares CONNECT-UDP path | pending | pending | `cargo test -p qpxd --test forward_e2e --features http3-backend-h3,tls-rustls masque` |
| h3 | generic extended CONNECT | repository e2e | pending | no | needs opt-in interop run | pending | pending | `cargo test -p qpxd --test forward_e2e --features http3-backend-h3,tls-rustls extended` |
| h3 | trailers over H3 | repository e2e | pending | no | needs opt-in interop run | pending | pending | `cargo test -p qpxd --test reverse_h3_e2e --features http3-backend-h3,tls-rustls trailers` |
| qpx_h3 | curl HTTP/3 | curl | skipped | no | external tool not present in default CI | pending | pending | `QPX_H3_INTEROP_BACKENDS=qpx_h3 scripts/h3-interop/run.sh curl-http3` |
| qpx_h3 | Chromium WebTransport | chromium | skipped | no | external browser not present in default CI | pending | pending | `QPX_H3_INTEROP_BACKENDS=qpx_h3 scripts/h3-interop/run.sh chromium-webtransport` |
| qpx_h3 | ngtcp2 | ngtcp2 | skipped | no | external peer not present in default CI | pending | pending | `QPX_H3_INTEROP_BACKENDS=qpx_h3 scripts/h3-interop/run.sh ngtcp2` |
| qpx_h3 | quiche | quiche | skipped | no | external peer not present in default CI | pending | pending | `QPX_H3_INTEROP_BACKENDS=qpx_h3 scripts/h3-interop/run.sh quiche` |
| qpx_h3 | gRPC over H3 | repository e2e | pending | no | needs opt-in interop run | pending | pending | `cargo test -p qpxd --test h3_streaming_e2e --features http3-backend-qpx,tls-rustls grpc` |
| qpx_h3 | SSE over H3 | repository e2e | pending | no | needs opt-in interop run | pending | pending | `cargo test -p qpxd --test h3_streaming_e2e --features http3-backend-qpx,tls-rustls sse` |
| qpx_h3 | CONNECT-UDP | repository e2e | pending | no | needs opt-in interop run | pending | pending | `cargo test -p qpxd --test forward_e2e --features http3-backend-qpx,tls-rustls connect_udp` |
| qpx_h3 | MASQUE | repository e2e | pending | no | URI-template coverage shares CONNECT-UDP path | pending | pending | `cargo test -p qpxd --test forward_e2e --features http3-backend-qpx,tls-rustls masque` |
| qpx_h3 | generic extended CONNECT | repository e2e | pending | no | needs opt-in interop run | pending | pending | `cargo test -p qpxd --test forward_e2e --features http3-backend-qpx,tls-rustls extended` |
| qpx_h3 | trailers over H3 | repository e2e | pending | no | needs opt-in interop run | pending | pending | `cargo test -p qpxd --test reverse_h3_e2e --features http3-backend-qpx,tls-rustls trailers` |

Use `scripts/h3-interop/run.sh` to write `target/interop/qpx-h3-matrix.json`.
External peers are optional; absent tools are recorded as `skipped` so default
CI is not brittle. Set `QPX_H3_INTEROP_BACKENDS` to `h3`, `qpx_h3`, or both to
select backend rows. If `QPX_QLOG_DIR` is set, qlog paths are recorded when the
underlying run produces them.

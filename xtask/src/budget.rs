pub(crate) const LOC_BUDGETS: &[(&str, usize, &str)] = &[
    (
        "qpxd/src/forward/h3/connect/mod.rs",
        600,
        "phase 2 main-file budget",
    ),
    (
        "qpxd/src/reverse/transport/mod.rs",
        600,
        "phase 2 main-file budget",
    ),
    (
        "qpxd/src/forward/connect/mod.rs",
        800,
        "CONNECT entry remains intentionally consolidated; threshold relaxed from 600",
    ),
    (
        "qpxd/src/reverse/router/mod.rs",
        600,
        "phase 2 main-file budget",
    ),
    (
        "qpxd/src/transparent/udp/mod.rs",
        500,
        "transparent UDP session routing budget after dispatch extraction",
    ),
    (
        "qpxd/src/transparent/udp/dispatch.rs",
        450,
        "transparent UDP per-session dispatch and policy budget",
    ),
    (
        "qpxd/src/forward/request/mod.rs",
        600,
        "phase 2 main-file budget",
    ),
    (
        "qpxd/src/forward/request/dispatch.rs",
        1300,
        "forward policy/module dispatch budget after cache/upstream extraction",
    ),
    (
        "qpxd/src/forward/request/dispatch/request_dispatch_cache.rs",
        500,
        "forward cache lookup/collapse dispatch budget",
    ),
    (
        "qpxd/src/forward/request/dispatch/request_dispatch_upstream.rs",
        400,
        "forward upstream dispatch/response-policy budget",
    ),
    (
        "qpx-core/src/config/validate/mod.rs",
        600,
        "phase 3 split budget",
    ),
    (
        "qpx-core/src/config/types/mod.rs",
        600,
        "phase 3 split budget",
    ),
    ("qpxd/src/runtime/mod.rs", 600, "phase 4 split budget"),
    (
        "qpxd/src/upstream/origin/mod.rs",
        600,
        "phase 5 split budget",
    ),
    (
        "qpxd/src/transparent/http/mod.rs",
        250,
        "entrypoint should stay thin",
    ),
    (
        "qpxd/src/http/mitm/mod.rs",
        250,
        "entrypoint should stay thin",
    ),
    (
        "qpxd/src/reverse/transport/dispatch.rs",
        1700,
        "reverse dispatcher budget after HTTP/IPC/cache extraction",
    ),
    (
        "qpxd/src/reverse/transport/dispatch/dispatch_http.rs",
        450,
        "reverse HTTP retry/success dispatch budget",
    ),
    (
        "qpxd/src/reverse/transport/dispatch/dispatch_ipc.rs",
        550,
        "reverse IPC and WebSocket dispatch budget",
    ),
    (
        "qpxd/src/reverse/transport/dispatch/dispatch_cache.rs",
        600,
        "reverse cache lookup/collapse dispatch budget",
    ),
    (
        "qpxd/src/transparent/http/dispatch.rs",
        1200,
        "transparent HTTP dispatch budget after shared dispatch extraction",
    ),
    (
        "qpxd/src/http/mitm/dispatch.rs",
        800,
        "MITM dispatch budget after shared dispatch extraction",
    ),
    (
        "qpxd/src/lib.rs",
        1300,
        "qpxd library entry/control-loop budget after server task extraction",
    ),
    (
        "qpxd/src/server/sets.rs",
        650,
        "listener and sidecar server set orchestration budget",
    ),
    (
        "qpxd/src/server/proxy_tasks.rs",
        650,
        "proxy/admin task lifecycle budget",
    ),
    (
        "qpxd/src/forward/h3/qpx/mod.rs",
        500,
        "qpx-h3 listener and handler entry budget after WebTransport extraction",
    ),
    (
        "qpxd/src/forward/h3/qpx/webtransport.rs",
        650,
        "qpx-h3 WebTransport relay state-machine budget",
    ),
    (
        "qpxd/src/forward/h3/qpx/webtransport_dispatch.rs",
        850,
        "qpx-h3 WebTransport request dispatch budget",
    ),
    (
        "qpxd/src/forward/h3/qpx/response.rs",
        320,
        "qpx-h3 response conversion and policy response budget",
    ),
    (
        "qpxd/src/forward/h3/qpx/connect.rs",
        1000,
        "qpx-h3 CONNECT dispatcher budget after prepare/policy extraction",
    ),
    (
        "qpxd/src/forward/h3/qpx/connect/prepare.rs",
        450,
        "qpx-h3 CONNECT preparation orchestration budget",
    ),
    (
        "qpxd/src/forward/h3/qpx/connect/prepare/policy.rs",
        450,
        "qpx-h3 CONNECT policy/rate-limit preparation budget",
    ),
    (
        "qpxd/src/forward/h3/qpx/connect_upstream.rs",
        320,
        "qpx-h3 CONNECT upstream/opening helper budget",
    ),
    (
        "qpxd/src/forward/h3/qpx/relay.rs",
        400,
        "qpx-h3 CONNECT relay state-machine budget",
    ),
    (
        "qpxd/src/http/modules/mod.rs",
        80,
        "HTTP module facade budget after registry/chain split",
    ),
    (
        "qpxd/src/http/modules/execution.rs",
        650,
        "HTTP module execution/session budget",
    ),
    (
        "qpxd/src/http/modules/response_compression.rs",
        600,
        "response compression module implementation budget",
    ),
    (
        "qpxd/src/http/dispatch/mod.rs",
        90,
        "shared HTTP dispatch facade budget",
    ),
    (
        "qpxd/src/http/dispatch/access.rs",
        80,
        "shared HTTP dispatch access response budget",
    ),
    (
        "qpxd/src/http/dispatch/audit.rs",
        140,
        "shared HTTP dispatch audit budget",
    ),
    (
        "qpxd/src/http/dispatch/guard.rs",
        60,
        "shared HTTP dispatch guard budget",
    ),
    (
        "qpxd/src/http/dispatch/metrics.rs",
        60,
        "shared HTTP dispatch metrics budget",
    ),
    (
        "qpxd/src/http/dispatch/outcome.rs",
        90,
        "shared HTTP dispatch outcome budget",
    ),
    (
        "qpxd/src/http/dispatch/rate_limit.rs",
        45,
        "shared HTTP dispatch rate-limit budget",
    ),
    (
        "qpxd/src/http/dispatch/cache.rs",
        180,
        "shared HTTP dispatch cache flow budget",
    ),
    (
        "qpxd/src/http/dispatch/connect_policy.rs",
        80,
        "shared HTTP dispatch CONNECT policy context budget",
    ),
    (
        "qpxd/src/http/dispatch/prepare.rs",
        120,
        "shared HTTP dispatch request preparation budget",
    ),
    (
        "qpxd/src/http/dispatch/response_policy.rs",
        140,
        "shared HTTP dispatch response policy budget",
    ),
    (
        "qpxd/src/http/dispatch/websocket.rs",
        90,
        "shared HTTP dispatch WebSocket proxy budget",
    ),
    (
        "qpxd/src/http/codec/h1.rs",
        1100,
        "HTTP/1 codec parser/serializer budget after request-body extraction",
    ),
    (
        "qpxd/src/http/codec/h1_request_body.rs",
        300,
        "HTTP/1 request body forwarding budget",
    ),
    (
        "qpxd/src/http/codec/h1_common.rs",
        100,
        "shared HTTP/1 codec helper budget",
    ),
    (
        "qpxd/src/reverse/h3/passthrough.rs",
        1200,
        "reverse HTTP/3 UDP passthrough state-machine budget",
    ),
    (
        "qpxd/src/udp_session_handoff/mod.rs",
        1050,
        "UDP session export/restore handoff budget",
    ),
    (
        "qpxd/src/runtime/plan/mod.rs",
        1050,
        "runtime execution plan compilation budget",
    ),
    (
        "qpxd/src/transparent/tls_path.rs",
        900,
        "transparent TLS decision path budget",
    ),
    (
        "qpxd/src/forward/h3/connect/standard/handlers.rs",
        1050,
        "HTTP/3 CONNECT handler budget",
    ),
    (
        "qpxd/src/upstream/pool/mod.rs",
        850,
        "upstream proxy connection pool budget",
    ),
    ("qpxd/src/ipc_client/mod.rs", 850, "QPX IPC client budget"),
    ("qpxd/src/ftp/mod.rs", 1000, "FTP-over-HTTP gateway budget"),
    ("qpxd/src/rate_limit/mod.rs", 950, "rate limiting budget"),
    (
        "qpxd/src/upstream/origin/http_backend/mod.rs",
        550,
        "origin HTTP backend budget after shared-client extraction",
    ),
    (
        "qpxd/src/upstream/origin/http_backend/shared.rs",
        300,
        "shared reverse HTTP client budget",
    ),
    (
        "qpxd/src/upstream/origin/http_backend/backend_h2.rs",
        400,
        "origin HTTP/2 request/response helper budget",
    ),
    (
        "qpxd/src/upstream/origin/http_backend/pool.rs",
        600,
        "origin HTTP/1/H2 connection acquisition and pool budget",
    ),
    (
        "qpxd/src/destination/mod.rs",
        100,
        "destination classifier facade budget",
    ),
    (
        "qpxd/src/destination/compile.rs",
        300,
        "destination named-set compilation budget",
    ),
    (
        "qpxd/src/destination/resolve.rs",
        650,
        "destination evidence resolution budget",
    ),
    (
        "qpxd/src/upstream/raw_http1/mod.rs",
        950,
        "raw HTTP/1 upstream codec budget",
    ),
    (
        "qpxd/src/forward/h3/connect/standard/udp.rs",
        900,
        "HTTP/3 CONNECT-UDP budget",
    ),
    (
        "qpxd/src/reverse/listener/mod.rs",
        800,
        "reverse TCP/TLS listener budget",
    ),
    (
        "qpx-core/src/config/validate/rules/mod.rs",
        1550,
        "core rule validation budget",
    ),
    (
        "qpx-core/src/config/validate/reverse.rs",
        800,
        "core reverse config validation budget",
    ),
    (
        "qpx-core/src/config/validate/security.rs",
        800,
        "core security config validation budget",
    ),
    (
        "qpx-core/src/config/types/canonical/mod.rs",
        850,
        "canonical config type budget",
    ),
    (
        "qpx-core/src/prefilter/mod.rs",
        900,
        "match prefilter implementation budget",
    ),
    (
        "qpx-core/src/shm_ring.rs",
        900,
        "shared-memory ring implementation budget",
    ),
    (
        "qpx-core/src/config/tests/mod.rs",
        120,
        "core config regression test facade budget",
    ),
    (
        "qpx-h3/src/server/mod.rs",
        1000,
        "qpx-h3 server driver budget",
    ),
    ("qpxf/src/server/mod.rs", 850, "qpxf IPC server budget"),
    ("qpx-acme/src/lib.rs", 800, "ACME integration budget"),
    (
        "qpxd/src/cache/tests/mod.rs",
        350,
        "cache regression shared test helper budget",
    ),
    (
        "qpxd/src/runtime/tests/mod.rs",
        250,
        "runtime regression test facade budget",
    ),
    (
        "qpxd/src/reverse/transport/tests/mod.rs",
        350,
        "reverse transport regression shared test helper budget",
    ),
    (
        "qpxd/src/forward/request/tests/mod.rs",
        120,
        "forward request regression test facade budget",
    ),
    (
        "qpxd/tests/perf_smoke.rs",
        1250,
        "qpxd perf smoke test budget",
    ),
    (
        "qpxd/tests/rfc911x_contract.rs",
        1400,
        "RFC 911x contract test budget",
    ),
    ("qpxd/tests/forward_e2e.rs", 1300, "forward e2e test budget"),
    (
        "qpxd/tests/advanced_transport_perf.rs",
        950,
        "advanced transport perf test budget",
    ),
    ("qpx-h3/tests/e2e.rs", 1200, "qpx-h3 e2e test budget"),
    (
        "qpxd/src/http3/quinn_socket/mod.rs",
        30,
        "QUIC broker facade budget after responsibility split",
    ),
    (
        "qpxd/src/http3/quinn_socket/broker.rs",
        600,
        "QUIC broker socket state budget",
    ),
    (
        "qpxd/src/http3/quinn_socket/endpoint.rs",
        100,
        "QUIC endpoint socket preparation budget",
    ),
    (
        "qpxd/src/http3/quinn_socket/frame.rs",
        260,
        "QUIC broker frame codec budget",
    ),
    (
        "qpxd/src/http3/quinn_socket/handoff.rs",
        400,
        "QUIC broker handoff manifest budget",
    ),
    (
        "qpxd/src/http3/quinn_socket/routing.rs",
        170,
        "QUIC broker CID route state budget",
    ),
    (
        "qpxd/src/http3/quinn_socket/stream.rs",
        230,
        "QUIC broker platform stream adapter budget",
    ),
    (
        "qpxd/src/http3/quinn_socket/tasks.rs",
        160,
        "QUIC broker async task loop budget",
    ),
    (
        "qpx-h3/src/qpack/mod.rs",
        350,
        "qpx-h3 QPACK public facade budget after codec/table split",
    ),
    (
        "qpx-h3/src/response.rs",
        220,
        "qpx-h3 response sanitization module budget",
    ),
    (
        "qpx-h3/src/qpack_fields.rs",
        160,
        "qpx-h3 field validation module budget",
    ),
];

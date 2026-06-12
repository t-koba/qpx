# RFC 911x Compliance Notes

This document tracks HTTP interoperability behavior that is implemented and
covered by the current source layout. It intentionally names module boundaries
rather than obsolete pre-refactor file paths.

## Implemented Points

1. RFC 9110 section 7.6.1: hop-by-hop fields
   - `qpx` strips hop-by-hop fields and fields named by `Connection` tokens on normal proxy paths.
   - WebSocket upgrade paths preserve the required `Connection: upgrade` and `Upgrade` pair.
   - Implemented in `qpx-http/src/protocol/semantics.rs`.
   - Applied from `qpxd/src/http/protocol/l7.rs`, forward dispatch, reverse dispatch, transparent HTTP dispatch, and cache-entry sanitization in `qpxd-cache/src/entry.rs`.

2. RFC 9110 section 7.6.3: `Via`
   - Proxied HTTP messages append version-aware `Via` entries (`1.1`, `2`, `3`) on request and response paths.
   - Implemented in `qpx-http/src/protocol/semantics.rs`.
   - Applied from `qpxd/src/http/protocol/l7.rs`, `qpxd/src/upstream/connect.rs`, and HTTP/3 CONNECT header normalization.

3. RFC 9112 section 3.2.2: request-target and `Host`
   - Forward proxy requests with absolute-form targets synchronize `Host` from the request target before upstream dispatch.
   - HTTP/1 validation rejects missing, duplicate, empty, invalid, or mismatched `Host`/authority values.
   - CONNECT validation requires authority-form targets.
   - Implemented in `qpx-http/src/protocol/semantics.rs`, `qpxd/src/forward/request/mod.rs`, `qpxd/src/forward/request/dispatch/target.rs`, and `qpxd/src/forward/h3/connect/parse.rs`.

4. RFC 9110 section 9.3.6: `CONNECT`
   - The forward proxy establishes CONNECT tunnels and returns `200` only after the tunnel is established.
   - Successful CONNECT responses strip message-body framing headers.
   - Implemented in `qpxd/src/forward/connect/mod.rs`, `qpxd/src/forward/connect/tunnel.rs`, and the HTTP response finalization helpers in `qpx-http/src/protocol/semantics.rs`.

5. RFC 9112 section 7.2: message body length semantics
   - Requests with conflicting `Transfer-Encoding` and `Content-Length` are rejected.
   - Requests with inconsistent duplicate `Content-Length` values are rejected.
   - Unsupported `Expect` values are rejected; `100-continue` remains the accepted expectation.
   - No-body response cases are normalized for `HEAD`, informational (`1xx`), `204`, `205`, `304`, and successful CONNECT.
   - Implemented in `qpx-http/src/protocol/semantics.rs`, `qpxd/src/http/codec/h1_request_body.rs`, `qpxd/src/http/codec/h1/response.rs`, `qpxd/src/http/codec/h2.rs`, and `qpxd/src/http3/codec.rs`.

6. `TRACE`, `OPTIONS`, and `Max-Forwards`
   - `Max-Forwards` is decremented for forwarded `TRACE` and `OPTIONS`.
   - `Max-Forwards: 0` is handled locally.
   - `TRACE` is disabled unless `runtime.trace_enabled` is set.
   - TRACE loop-back bodies are bounded and use `message/http` formatting.
   - Implemented in `qpxd/src/http/protocol/l7.rs` and gated by `qpxd/src/http/protocol/preflight.rs`.

7. RFC 6455 section 4: WebSocket upgrade over HTTP/1.1
   - WebSocket upgrade headers are preserved and upgraded streams are bridged bidirectionally.
   - Implemented in `qpxd/src/http/dispatch/websocket.rs`, `qpxd/src/upstream/http1.rs`, and `qpxd/src/upstream/origin/ws_backend.rs`.

8. RFC 9113: HTTP/2 operational coverage
   - Reverse proxy accepts h2c on cleartext listeners.
   - Reverse TLS listeners advertise ALPN for HTTP/2 and HTTP/1.1.
   - Transparent HTTP accepts HTTP/2 prior knowledge.
   - TLS MITM preserves HTTP/1.1 upstream semantics for intercepted Upgrade/WebSocket flows.
   - Implemented across `qpxd/src/reverse/listener/`, `qpxd/src/reverse/transport/`, `qpxd/src/transparent/http/`, `qpxd/src/http/codec/h2.rs`, `qpxd/src/tls/`, and `qpx-core/src/tls/`.

9. RFC 9114, RFC 9297, and RFC 9298: HTTP/3, HTTP datagrams, CONNECT-UDP
   - Reverse HTTP/3 terminate proxies request/response traffic through route rules.
   - Reverse HTTP/3 passthrough routes raw QUIC/UDP sessions without binding to an HTTP/3 backend.
   - Forward HTTP/3 supports standard request forwarding and CONNECT tunnel proxying.
   - `http3-backend-h3` covers standard HTTP/3 request/response, CONNECT, CONNECT-UDP / MASQUE, chained upstream CONNECT-UDP, and non-WebTransport extended CONNECT.
   - `http3-backend-qpx` covers the QPX-owned HTTP/3 path, including streaming request/response relay, reverse terminate, CONNECT-UDP / MASQUE, generic extended CONNECT, and WebTransport relay.
   - Implemented in `qpxd/src/http3/`, `qpxd/src/forward/h3/`, `qpxd/src/reverse/h3/`, `qpxd/src/upstream/origin/http_backend/h3_pool/`, and `qpx-h3/src/`.

10. PROXY protocol v2 metadata integration
   - `qpxd` consumes PROXY v2 metadata on forward, reverse, and transparent listeners when `xdp.enabled: true` and `xdp.metadata_mode: proxy-v2`.
   - This is an L4 frontend integration point; `qpxd` does not implement AF_XDP packet I/O.
   - Implemented in `qpxd/src/xdp/`, `qpxd/src/forward/mod.rs`, `qpxd/src/reverse/listener/`, `qpxd/src/reverse/transport/`, `qpxd/src/transparent/destination.rs`, and `qpxd/src/transparent/udp/`.

11. Local response policy path
   - `respond` / `local_response` actions can return proxy-local responses without upstream forwarding.
   - RFC message-shape normalization still applies, including no-body response cases, hop-by-hop field handling, `Via`, and default `Date` insertion.
   - Implemented in `qpxd/src/http/local_response.rs`, `qpxd/src/http/protocol/l7.rs`, and the forward, reverse, and transparent dispatch paths.

12. RFC 9111 shared-cache behavior and RFC 5861 extensions
   - Cache lookup/store is implemented for forward-edge and reverse-route cache policies.
   - Request directives include `no-store`, `no-cache`, `max-age`, `max-stale`, `min-fresh`, and `only-if-cached`.
   - Response directives include `no-store`, `private`, `public`, `no-cache`, `must-understand`, `must-revalidate`, `proxy-revalidate`, `s-maxage`, and `max-age`.
   - Freshness uses `s-maxage`, `max-age`, `Expires`, and policy defaults.
   - `Age` is synthesized on cache hits.
   - `Vary` is part of storage and lookup; `Vary: *` is uncacheable.
   - Unsafe successful methods invalidate matching entries.
   - RFC 5861 `stale-while-revalidate` and `stale-if-error` are implemented.
   - Redis and HTTP object-gateway backends live outside `qpxd` in `qpxd-cache`.
   - Implemented in `qpxd-cache/src/`, wired from `qpxd/src/http/dispatch/cache.rs`, forward dispatch, reverse dispatch, and `qpxd/src/runtime/cache_rt.rs`.

13. RFC 9110 section 11.7 and section 7.6.1: proxy credentials
   - Forwarding paths strip `Proxy-Authorization` before origin/upstream dispatch.
   - `407 Proxy Authentication Required` responses preserve proxy challenge headers.
   - Implemented in forward request preparation and HTTP/3 CONNECT header normalization, with response handling in `qpxd/src/forward/request/mod.rs`.

14. Reverse TLS anti-fronting policy
   - Reverse TLS and reverse HTTP/3 terminate enforce SNI and Host/authority consistency by default.
   - Config:
     - `edges[kind=reverse].enforce_sni_host_match` defaults to `true`.
     - `edges[kind=reverse].sni_host_exceptions` provides explicit glob opt-outs.
   - Plain HTTP reverse listeners do not go through this TLS SNI check.
   - Implemented in `qpxd/src/reverse/tls/security.rs`, reverse transport preparation, and reverse HTTP/3 terminate paths.

15. Shared-cache safety for cookie-bearing responses
   - `Set-Cookie` responses are not stored by default.
   - `cache.allow_set_cookie_store: true` still requires `Cache-Control: public` and `Vary: Cookie`.
   - Implemented in `qpxd-cache/src/store.rs` and configured by `qpx-core/src/config/types/cache.rs`.

16. QUIC replay safety defaults
   - Server-side HTTP/3 QUIC configuration disables 0-RTT by default (`max_early_data_size = 0`).
   - Implemented in `qpxd/src/http3/quic.rs`.

17. PROXY metadata trust boundary
   - When XDP metadata mode is enabled, `xdp.trusted_peers` is mandatory.
   - PROXY metadata is accepted only from trusted peer CIDRs.
   - `xdp.require_metadata` defaults to the safe side.
   - Implemented in `qpx-core/src/config/types/listener.rs`, `qpx-core/src/config/validate/`, `qpxd/src/xdp/`, and transparent destination handling.

## Verification

1. Shared protocol unit tests
   - `qpx-http/src/protocol/semantics/tests.rs`
   - `qpxd/src/http/protocol/l7/tests.rs`
   - `qpxd/src/http/codec/h1/tests.rs`
   - `qpxd/src/http/codec/h2/tests.rs`
   - `qpxd/src/http3/codec.rs` tests

2. RFC contract tests
   - `qpxd/tests/rfc911x_contract.rs`
   - Scenario modules under `qpxd/tests/rfc911x/`
   - Run with `cargo test -p qpxd --test rfc911x_contract`

3. Cache tests
   - Cache-library tests live under `qpxd-cache/src/tests/` and `qpxd-cache/src/store/tests.rs`.
   - End-to-end cache behavior is covered by `qpxd/tests/rfc911x/cache.rs`.

4. HTTP/2 and local-response end-to-end scripts
   - `scripts/e2e-http2.sh`
   - `scripts/e2e-local-response.sh`

5. Sample configuration coverage
   - `scripts/e2e-config-samples.sh`
   - `qpx-core/src/config/tests/sample_config_tests.rs`

## Coverage Notes

1. RFC 5861 extensions are implemented as best-effort cache behavior.
   - `stale-while-revalidate` can serve stale immediately and refresh in the background.
   - `stale-if-error` can serve stale when upstream fails within the configured window.

2. Cache keys distinguish method semantics.
   - `HEAD` entries are isolated from `GET`.
   - A stored `GET` representation can satisfy a later `HEAD` without a body.
   - `Range`, `If-Range`, `If-Match`, and `If-Unmodified-Since` influence lookup and revalidation decisions.

3. `TRACE` uses strict loop-back semantics when enabled.
   - Reflected messages are bounded and strip sensitive forwarding/auth/tracing headers unless explicitly configured otherwise.
   - `Max-Forwards: 0` is handled locally for `TRACE` and `OPTIONS`.

4. Interim informational response forwarding is implemented on HTTP proxy paths.
   - Reverse proxy paths forward upstream informational responses on HTTP/1.1, HTTP/2, and HTTP/3.
   - Forward proxy paths forward upstream informational responses on HTTP/1.1, HTTP/2 prior knowledge, and HTTP/3.
   - Transparent cleartext HTTP paths forward upstream informational responses on HTTP/1.1 and HTTP/2 prior knowledge.

5. RFC 9298 / RFC 6570 URI Template handling is implemented for CONNECT-UDP matching and upstream expansion.
   - Listener-side CONNECT-UDP matching is intentionally strict for configured templates.
   - Expansion uses the shared URI-template engine in `qpx-core/src/uri_template.rs`.
   - CONNECT-UDP relay is implemented on both HTTP/3 backends.

6. Generic HTTP/3 extended CONNECT is implemented on both HTTP/3 backends.
   - `http3-backend-h3` preserves non-WebTransport `:protocol`, opens an upstream extended CONNECT request, forwards interim responses, and relays the bidirectional request stream plus per-stream HTTP datagrams.
   - `http3-backend-qpx` handles generic extended CONNECT through the QPX-owned path with bidirectional stream relay, interim responses, and per-stream HTTP datagrams.
   - The QPX backend also relays WebTransport request streams, associated bidirectional streams, associated unidirectional streams, and per-session HTTP datagrams.
   - Implemented in `qpxd/src/forward/h3/connect/standard/`, `qpxd/src/forward/h3/qpx/connect.rs`, `qpxd/src/forward/h3/qpx/webtransport.rs`, and `qpxd/src/forward/h3/qpx/webtransport_dispatch.rs`.

7. RFC 8441 HTTP/2 extended CONNECT is implemented on the forward proxy path.
   - Forward HTTP/2 listeners advertise extended CONNECT support and proxy `:protocol`-based downstream CONNECT streams upstream over HTTP/2.
   - Reverse and transparent HTTP/2 paths do not advertise the generic extended CONNECT protocol.
   - Successful forward-path extended CONNECT responses keep tunnel semantics instead of being normalized as legacy CONNECT no-body responses.
   - Implemented in `qpxd/src/forward/connect/connect_h2.rs`, `qpxd/src/forward/connect/extended.rs`, and `qpxd/src/forward/connect/tunnel.rs`.

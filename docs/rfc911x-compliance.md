# RFC 911x compliance notes

This document tracks concrete interoperability behavior implemented in `qpxd` against HTTP core RFCs and related standards.

## Implemented compliance points

1. RFC 9110 section 7.6.1 (`Connection` and hop-by-hop fields)
   - `qpxd` strips hop-by-hop fields for normal forwarding paths.
   - It also parses `Connection` tokens and removes referenced header fields.
   - For WebSocket upgrade only, it preserves the required `Connection: upgrade` + `Upgrade` pair.
   - Code: `qpxd/src/http/semantics.rs`, applied in:
     - `qpxd/src/forward/request.rs`
     - `qpxd/src/transparent/http_path.rs`
     - `qpxd/src/reverse/transport.rs`

2. RFC 9110 section 7.6.3 (`Via`)
   - Forwarded HTTP messages carry version-aware `Via` entries (`1.1`, `2`, `3`) on request and response paths.
   - Code: `qpxd/src/http/semantics.rs` (`append_via_for_version`) and call sites in forward/reverse/transparent handlers.

3. RFC 9112 section 3.2.2 (request target forms in proxying)
   - For proxy-originated forwarding where absolute target is present, `Host` is synchronized from request authority.
   - For direct forwarding where absolute URI is missing, request target is normalized to an absolute URI before client dispatch.
   - Code:
     - `qpxd/src/http/semantics.rs` (`sync_host_header_from_absolute_target`)
     - `qpxd/src/forward/request.rs` (`handle_request_inner`)

4. RFC 9110 section 9.3.6 (`CONNECT`)
   - Proxy establishes CONNECT tunnels and returns `200` upon tunnel establishment.
   - CONNECT `200` responses strip message-body framing headers (`Content-Length`, `Transfer-Encoding`, `Trailer`).
   - Code: `qpxd/src/forward/connect.rs` (`handle_connect`, `tunnel_connect`)

5. RFC 9112 section 3.2 (`Host`) and section 7.2 (message body length semantics)
   - Incoming requests are validated for:
     - multiple Host header rejection
     - empty/invalid Host syntax rejection (including userinfo form)
     - missing Host/authority rejection
     - CONNECT authority-form requirement
     - CONNECT target strictness (`host:port` only; rejects origin/absolute-form)
     - Host/authority mismatch rejection
     - conflicting framing headers (`Transfer-Encoding` + `Content-Length`) rejection
     - inconsistent multiple `Content-Length` values rejection
     - unsupported `Expect` values (only `100-continue` is accepted; others are rejected with `417 Expectation Failed`)
   - Outbound responses are normalized for no-body cases:
     - `HEAD`
     - informational (`1xx`)
     - `204 No Content`
     - `205 Reset Content`
     - `304 Not Modified`
     - successful `CONNECT`
   - Code:
     - `qpxd/src/http/semantics.rs`
     - integrated in `qpxd/src/forward/request.rs`, `qpxd/src/reverse/transport.rs`, `qpxd/src/transparent/http_path.rs`
   - Operational handling:
     - `Max-Forwards` is decremented for `TRACE`/`OPTIONS` forwarding.
     - `Max-Forwards: 0` is handled locally (no forwarding).
     - `TRACE` is disabled by default to avoid request-header reflection footguns. Set `runtime.trace_enabled: true` to enable it.
     - Code: `qpxd/src/http/l7.rs`

6. RFC 6455 section 4 (WebSocket Upgrade over HTTP/1.1)
   - WebSocket upgrade headers are preserved and upgraded streams are bridged bidirectionally.
   - Code:
     - `qpxd/src/forward/request.rs` (calls `proxy_websocket_http1`)
     - `qpxd/src/reverse/transport.rs` (`proxy_websocket`)
     - `qpxd/src/transparent/http_path.rs` (calls `proxy_websocket_http1`)

7. RFC 9113 (HTTP/2) operational coverage
   - Reverse proxy accepts HTTP/2 prior-knowledge (h2c) on cleartext listeners.
   - Reverse TLS listeners advertise ALPN `h2,http/1.1` and serve both protocols.
   - Transparent mode accepts HTTP/2 prior-knowledge and applies rules/header controls.
   - TLS MITM server supports HTTP/1.1 after interception. Upstream MITM connections are forced to HTTP/1.1 to preserve Upgrade/WebSocket semantics.
   - Code:
     - `qpx-core/src/tls.rs`
     - `qpxd/src/reverse/transport.rs`
     - `qpxd/src/forward/request.rs`
     - `qpxd/src/transparent/http_path.rs`

8. RFC 9114 / RFC 9297 / RFC 9298 (HTTP/3 + HTTP Datagrams + CONNECT-UDP) operational coverage
   - Reverse proxy:
     - QUIC listener supports HTTP/3 terminate path (request/response proxy over route rules).
     - UDP passthrough mode supports configurable upstream sets with round-robin forwarding for `UDP/443` workloads.
   - Forward proxy:
     - HTTP/3 listener supports standard request forwarding and CONNECT tunnel proxying.
     - CONNECT-UDP is handled with MASQUE capsule flow (`Capsule-Protocol: ?1`, DATAGRAM capsule type, context id `0`) for both direct targets and chained upstream HTTP/3 proxies.
   - Code:
     - `qpxd/src/reverse/h3.rs`
     - `qpxd/src/reverse/h3_terminate.rs`
     - `qpxd/src/reverse/h3_passthrough.rs`
     - `qpxd/src/forward/h3.rs`
     - `qpxd/src/forward/h3_connect.rs`
     - `qpxd/src/forward/h3_connect_udp.rs`
     - `qpxd/src/http3/listener.rs`
     - `qpxd/src/http3/server.rs`
     - `qpxd/src/http3/codec.rs`
     - `qpxd/src/http3/capsule.rs`
     - `qpxd/src/http3/quic.rs`
     - `qpx-core/src/tls.rs`
     - `qpxd/src/runtime.rs`

9. PROXY protocol metadata integration (operational extension)
   - `qpxd` can consume PROXY v2 metadata on forward/reverse/transparent listeners when `xdp.enabled: true` and `xdp.metadata_mode: proxy-v2`.
   - This enables XDP/L4 frontends to pass source/destination context into L7 rules.
   - Code:
     - `qpxd/src/xdp/mod.rs`
     - `qpxd/src/forward/mod.rs`
     - `qpxd/src/reverse/transport.rs`
     - `qpxd/src/transparent/destination.rs`

10. Local response policy path (operational extension with RFC semantics retained)
   - `respond/local_response` allows policy-generated responses without upstream forwarding.
   - RFC message-shape rules are still enforced on local responses (`HEAD`, `1xx`, `204`, `304`, successful `CONNECT`).
   - `Connection`-based hop-by-hop field handling and `Via` behavior stay consistent with proxied paths.
   - A `Date` header is added to proxy-generated responses when missing.
   - Code:
     - `qpxd/src/http/local_response.rs`
     - `qpxd/src/forward/request.rs`
     - `qpxd/src/reverse/transport.rs`
     - `qpxd/src/transparent/http_path.rs`

11. RFC 9111 (HTTP caching) baseline behavior
   - Cache lookup/store pipeline is implemented for:
     - forward listeners (`listeners[].cache`)
     - reverse routes (`reverse[].routes[].cache`)
   - Cache-control handling includes:
     - request directives: `no-store`, `no-cache`, `max-age`, `max-stale`, `min-fresh`, `only-if-cached`
     - response directives: `no-store`, `private`, `public`, `no-cache`, `must-revalidate`, `proxy-revalidate`, `s-maxage`, `max-age`
     - freshness lifetime from `s-maxage` / `max-age` / `Expires` / policy default
     - `Age` synthesis on cache hits and stale-warning (`Warning: 110`) when served via `max-stale`
   - Conditional revalidation:
     - stale or `no-cache` entries revalidate via `If-None-Match` / `If-Modified-Since`
     - `304 Not Modified` merges metadata and serves refreshed cached entity
   - Variant handling:
     - `Vary`-aware storage and lookup
     - `Vary: *` is treated as uncacheable
   - Invalidation:
     - unsafe successful methods invalidate target URI cache entries
     - same-authority `Location` / `Content-Location` targets are invalidated as well
   - Cache backend integration supports externalized storage:
     - Redis (`redis://`, `rediss://`, `redis+unix://`)
     - HTTP object gateway (`http://`, `https://`)
   - Code:
     - `qpxd/src/cache/mod.rs`
     - `qpxd/src/cache/backend_redis.rs`
     - `qpxd/src/cache/backend_http.rs`
     - call sites in `qpxd/src/forward/request.rs` and `qpxd/src/reverse/transport.rs`

12. RFC 9110 section 11.7 / section 7.6.1 (proxy credentials not forwarded hop-to-hop)
   - Proxy-specific authentication headers are stripped on forwarding paths:
     - `Proxy-Authorization`
   - `407 Proxy Authentication Required` responses preserve `Proxy-Authenticate` / `Proxy-Authentication-Info` challenges.
   - This prevents proxy credentials from leaking to origin/upstream application servers.
   - Code:
     - `qpxd/src/http/semantics.rs`
     - call sites in forward/reverse/transparent handlers

13. TLS terminate anti-fronting policy (operational security hardening)
   - Reverse TLS and reverse HTTP/3 terminate enforce SNI and Host/authority consistency by default.
   - Config:
     - `reverse[].enforce_sni_host_match` (default `true`)
     - `reverse[].sni_host_exceptions` (explicit opt-out allowlist globs)
   - Plain HTTP reverse listeners are not forced through this check.
   - Code:
     - `qpxd/src/reverse/security.rs`
     - `qpxd/src/reverse/transport.rs`
     - `qpxd/src/reverse/h3_terminate.rs`

14. RFC 9111 shared-cache safety for cookie-bearing responses
   - `Set-Cookie` responses are not storable by default.
   - Optional enablement (`cache.allow_set_cookie_store: true`) still requires:
     - `Cache-Control: public`
     - `Vary: Cookie`
   - Code:
     - `qpxd/src/cache/mod.rs`
     - `qpx-core/src/config/types.rs`

15. QUIC replay safety defaults for HTTP/3 (RFC 9001 context)
   - HTTP/3 server-side QUIC config disables 0-RTT by default (`max_early_data_size = 0`) for both forward and reverse listeners.
   - Code:
     - `qpxd/src/http3/quic.rs`
     - `qpxd/src/forward/h3.rs`
     - `qpxd/src/reverse/h3_terminate.rs`

16. PROXY metadata trust boundary hardening (operational extension)
   - When XDP metadata mode is enabled:
     - `xdp.trusted_peers` is mandatory.
     - PROXY metadata is accepted only from trusted peer CIDRs.
     - Default for `xdp.require_metadata` is safe-side (`true`).
   - Code:
     - `qpx-core/src/config/types.rs`
     - `qpx-core/src/config/validate.rs`
     - `qpxd/src/xdp/mod.rs`
     - `qpxd/src/xdp/remote.rs`
     - `qpxd/src/transparent/destination.rs`

## Verification

1. Unit tests
   - `qpxd/src/http/semantics.rs` tests:
     - connection-token stripping
     - upgrade-preserving sanitation
     - via append behavior
     - Host/authority validation
     - no-body response normalization

2. Contract tests (Rust integration)
   - `qpxd/tests/rfc911x_contract.rs`
   - Runs under `cargo test -p qpxd --test rfc911x_contract`

3. Sample-config end-to-end
   - Script: `scripts/e2e-config-samples.sh`
   - Dependencies: `bash` + common Unix tools, and `cargo`, `curl`, `nc`, `timeout`, `lsof` (no Python).
   - Validates forward/reverse/transparent behavior against real traffic flow.

4. HTTP/2 end-to-end
   - Script: `scripts/e2e-http2.sh`
   - Dependencies: `bash` + common Unix tools, and `cargo`, `curl`, `nc`, `openssl` (no Python).
   - Validates:
     - reverse h2c
     - transparent h2c
     - reverse TLS + ALPN h2

5. Local response end-to-end
   - Script: `scripts/e2e-local-response.sh`
   - Dependencies: `bash` + common Unix tools, and `cargo`, `curl`, `lsof` (no Python).
   - Validates:
     - forward/reverse/transparent local response routing
     - local-response header policy behavior
     - `HEAD` no-body semantics on local responses

6. Cache unit tests
   - `qpxd/src/cache/mod.rs` tests include:
     - `only-if-cached` miss behavior
     - `Vary` variant lookup behavior
     - `no-cache` revalidation path with `304` merge
     - unsafe-method invalidation behavior
     - `Set-Cookie` non-storage by default
     - explicit opt-in storage path (`public` + `Vary: Cookie`)

7. Reverse TLS host security unit tests
   - `qpxd/src/reverse/security.rs` tests include:
     - SNI/Host mismatch rejection on TLS-terminated requests
     - plain HTTP reverse path bypass behavior
     - exception-glob override behavior

## Scope limits

1. RFC 5861 extensions are implemented.
    - Supported: `stale-while-revalidate`, `stale-if-error` (best-effort background revalidation).

2. RFC 9111 cache behavior is intentionally a safe subset (not a full-featured shared-cache).
    - Storage is limited to `GET` responses (no `POST`/`PUT`/etc storage).
    - Storable status codes are an explicit allowlist (see `qpxd/src/cache/store.rs`).
    - Requests with unsupported conditionals (`Range`, `If-Range`, `If-Match`, `If-Unmodified-Since`) bypass cache lookup/store.

3. TRACE is implemented with a security-first local response shape rather than full request loop-back.
    - Default `TRACE` reflection is **headers-only** and uses an allowlist to reduce secret header leakage risk.
    - `runtime.trace_reflect_all_headers: true` can enable full header reflection (DANGEROUS).

# Code Structure

Source-level guide to the qpx workspace.

## Architecture overview

qpx is a Rust workspace with five crates:

```
qpx-core   shared library: config loading, rule engine, auth, TLS, observability
qpxd       daemon:         forward / reverse / transparent HTTP proxy
qpxf       executor:       FastCGI function executor (CGI scripts + WASM modules)
qpxr       reader:         receives traffic events from qpxd, writes PCAPNG
qpxc       client:         streams PCAPNG from qpxr to Wireshark or stdout
```

`qpxd` is the main network proxy. It can forward requests to `qpxf` over the FastCGI protocol using reverse route `fastcgi:` config (recommended) or `fastcgi://` upstream URLs. `qpxr` and `qpxc` are post-capture tooling and never participate in the proxy data path.

### Request flow through qpxd

Every inbound connection follows the same layered pipeline:

```
listener accept (mode-specific: forward/ reverse/ transparent/)
  │
  ├─ XDP / PROXY metadata resolution   (xdp/)
  │
  ├─ TLS peek / SNI extraction          (tls/sniff.rs)
  │   ├─ TLS terminate or passthrough   (tls/client.rs, reverse/listener.rs)
  │   └─ MITM interception              (tls/mitm.rs → http/mitm.rs)
  │
  ├─ HTTP parsing + semantic validation  (http/semantics.rs)
  │
  ├─ Rule/policy evaluation              (forward/policy.rs, http/policy.rs)
  │   ├─ Auth challenge/verify           (qpx-core: auth.rs)
  │   └─ Rule matching                   (qpx-core: rules.rs + prefilter.rs)
  │
  ├─ Action dispatch
  │   ├─ direct / proxy upstream         (upstream/)
  │   ├─ CONNECT tunnel                  (forward/connect.rs)
  │   ├─ cache lookup + store            (cache/, http/cache_flow.rs)
  │   ├─ local response                  (http/local_response.rs)
  │   ├─ FTP gateway                     (ftp.rs)
  │   └─ WebSocket upgrade               (http/websocket.rs)
  │
  ├─ Response finalization               (http/l7.rs: Via, Date, header control)
  │
  └─ Capture export                      (exporter.rs → qpxr)
```

The key boundary rule is: mode directories (`forward/`, `reverse/`, `transparent/`) own **only** mode-specific control flow. Shared protocol mechanics live in `http/`, `http3/`, `upstream/`, `tls/`, and `cache/`. New features must not duplicate parsing, response building, or tunnel logic across modes.

### Capture pipeline boundary

`qpxd` never generates PCAP/PCAPNG. It emits structured capture events via TCP to `qpxr`. `qpxr` is the sole PCAPNG generator. `qpxc` is a passthrough viewer (extcap bridge or simple packet dump).

---

## Core library (`qpx-core`)

Shared building blocks that `qpxd`, `qpxr`, and `qpxc` all depend on. This crate has no network I/O — it provides types, parsing, and evaluation.

- `lib.rs`: crate root, public module re-exports.
- `config.rs`: re-export module root.
- `config/types.rs`: YAML configuration schema (serde structs for all sections).
- `config/load.rs`: config loading, `include` file composition, and environment variable expansion.
- `config/validate.rs`: post-load validation and constraint checking.
- `config/defaults.rs`: default values for optional config fields.
- `config/tests.rs`: config loading and validation tests.
- `envsubst.rs`: `${VAR:-default}` environment variable substitution.
- `rules.rs`: rule engine — compiles listener rules into a matchable form (`CompiledRule`) and evaluates incoming requests against them.
- `prefilter.rs`: bitset/trie-based prefilter index. Narrows candidate rules before full evaluation to avoid O(n) scans on large rulesets.
- `matchers.rs`: low-level match primitives (CIDR, glob, regex, header value matchers) used by the rule engine.
- `auth.rs`: authentication providers (local user file + LDAP), Basic/Digest HTTP auth, and an in-memory auth result cache.
- `tls.rs`: TLS helpers: CA management and MITM certificate generation (feature `tls-rustls`); stub implementation when `tls-rustls` is disabled.
- `observability.rs`: logging initialization (tracing subscriber) and Prometheus metrics endpoint bootstrap.
- `exporter.rs`: capture event schema — shared between `qpxd` (producer) and `qpxr` (consumer) for serialization compatibility.

---

## Proxy daemon (`qpxd`)

### Entry point and runtime

- `main.rs`: CLI (`run`, `check`, and `gen-ca` when built with `tls-rustls`), config loading, listener startup orchestration.
- `runtime.rs`: shared runtime state container — holds the config snapshot, compiled rules, auth providers, TLS state, metrics handles, exporter sessions, and the hot-reload watcher. Passed as `Arc` to all request handlers.

### Forward proxy (`forward/`)

Handles explicit HTTP proxy requests (client sets proxy address).

- `mod.rs`: listener startup, TCP accept loop, HTTP/1.1 and HTTP/2 serve wiring, XDP metadata resolution per connection.
- `request.rs`: request dispatch — evaluates rules, resolves upstream, routes to proxy/direct/FTP/cache/MITM/respond paths. This is the main request handler.
- `connect.rs`: CONNECT method handling — tunnel establishment, bidirectional relay, and TLS interception when policy selects inspect.
- `policy.rs`: forward-mode policy evaluation — auth verification, group-based rule matching, auth cache lookup.
- `h3.rs`: HTTP/3 forward listener — QUIC accept, request/CONNECT/CONNECT-UDP dispatch.
- `h3_connect.rs`: HTTP/3 CONNECT tunnel — policy check + bidirectional stream relay.
- `h3_connect_udp.rs`: HTTP/3 CONNECT-UDP — MASQUE capsule handling, datagram relay, upstream proxy chaining.

### Reverse proxy (`reverse/`)

Routes inbound traffic to backend upstreams based on Host/SNI/path/src_ip matching.

- `mod.rs`: listener startup and mode selection (TLS, plain HTTP, HTTP/3, TLS passthrough).
- `listener.rs`: TCP/TLS accept loops — TLS handshake, SNI peek for passthrough routing, XDP metadata.
- `router.rs`: route compilation and matching — builds a prefilter index over routes, selects upstream set, handles TLS passthrough by SNI.
- `transport.rs`: HTTP request handling after route match — upstream forwarding, WebSocket proxy, retry with body buffering, cache flow, header pipeline.
- `request_template.rs`: request template for retry — buffers the body and checks retryability before re-dispatching.
- `health.rs`: upstream health probes — periodic active checks, health state tracking.
- `security.rs`: TLS host anti-fronting — enforces that TLS SNI matches the HTTP Host/authority header, with configurable exception globs.
- `h3.rs`: HTTP/3 reverse orchestration — selects between terminate and UDP passthrough.
- `h3_terminate.rs`: HTTP/3 terminate runtime — QUIC accept + HTTP/3 request dispatch through route engine.
- `h3_passthrough.rs`: UDP/443 passthrough — round-robin forwarding of raw UDP datagrams to configured upstreams.

### Transparent proxy (`transparent/`)

Intercepts traffic without client configuration (Linux `SO_ORIGINAL_DST` or protocol metadata).

- `mod.rs`: listener startup, TLS/HTTP protocol detection on accepted connections.
- `destination.rs`: original destination recovery — Linux `SO_ORIGINAL_DST`, SNI/Host fallback on non-Linux, PROXY metadata. Also provides target connection helpers.
- `http_path.rs`: plain HTTP handling — rule evaluation, upstream dispatch, header/cache pipeline. Structurally parallel to `forward/request.rs`.
- `tls_path.rs`: TLS connection handling — decides tunnel/block/MITM based on rule outcome and SNI.

### HTTP protocol (`http/`)

Shared HTTP processing used by all three modes. Nothing in this directory is mode-specific.

- `semantics.rs`: RFC 9110/9112 message mechanics — hop-by-hop stripping, Via append, Host/authority validation, no-body response normalization, Transfer-Encoding/Content-Length conflict detection.
- `l7.rs`: request/response finalization pipeline — calls `semantics.rs`, then applies header control, Date, Max-Forwards decrement, TRACE handling.
- `header_control.rs`: request/response header mutation engine — set/add/remove/regex-replace per rule configuration.
- `policy.rs`: shared policy evaluation for transparent and MITM paths — block/respond/proceed decision.
- `mitm.rs`: MITM intercepted request handler — re-evaluates rules after TLS decryption, dispatches to upstream, supports WebSocket upgrade.
- `websocket.rs`: WebSocket upgrade detection and bidirectional upgraded-stream relay.
- `local_response.rs`: policy response builder — constructs status/body/content-type/headers responses without upstream forwarding.
- `common.rs`: canonical error responses (400/403/502/etc.), shared HTTP client, named-upstream resolution.
- `address.rs`: host/port/authority parsing and formatting.
- `cache_flow.rs`: cache orchestration — lookup, conditional revalidation (If-None-Match/If-Modified-Since), response writeback.
- `server.rs`: HTTP/1.1+HTTP/2 serve helper (hyper `serve_connection` with upgrade support).
- `mod.rs`: module re-exports.

### HTTP/3 protocol (`http3/`)

QUIC/HTTP/3 infrastructure shared by forward and reverse H3 listeners.

- `listener.rs`: HTTP/3 connection accept and stream dispatch (mode-independent).
- `codec.rs`: HTTP/3 ↔ hyper type conversion (headers, body, status).
- `server.rs`: stream helpers — body read limits, static responses, error mapping.
- `capsule.rs`: CONNECT-UDP capsule encoding/decoding, QUIC variable-length integer helpers.
- `quic.rs`: QUIC configuration — h3 ALPN, client/server defaults, 0-RTT disabled by default.
- `mod.rs`: module re-exports.

### TLS (`tls/`)

TLS operations for outbound and inspection paths. The active backend is selected by Cargo features (`tls-rustls` vs `tls-native`). TLS MITM inspection requires `mitm` + `tls-rustls`.

- `client.rs`: outbound TLS connectors (rustls/native-tls), ALPN negotiation, shared configs.
- `sniff.rs`: non-destructive TLS ClientHello peek from TCP stream. Extracts SNI without consuming bytes, handles record-layer reassembly across multiple reads.
- `mitm.rs`: MITM TLS accept (impersonated certificate) and upstream TLS connect (feature `mitm`, rustls-only). Forces HTTP/1.1 on MITM upstream to preserve Upgrade semantics.
- `mod.rs`: module re-exports.

### Upstream connections (`upstream/`)

Outbound connection handling — how `qpxd` talks to origins and chained proxies.

- `pool.rs`: pooled connections to upstream proxies for forward-proxy chaining.
- `connect.rs`: CONNECT-to-upstream helper — establishes a CONNECT tunnel through a chained proxy before forwarding.
- `http1.rs`: HTTP/1.1 upstream proxy dispatch — absolute-form URI, WebSocket proxy, upstream endpoint parsing, Proxy-Authorization forwarding.
- `origin.rs`: direct upstream dispatch (reverse/transparent) — plain/TLS/FastCGI, h2-aware sender selection, WebSocket upgrade, request URI rewriting.
- `mod.rs`: module re-exports.

### Cache (`cache/`)

RFC 9111 proxy cache implementation. Used by both forward listeners and reverse routes.

- `mod.rs`: cache orchestration — policy checks (storability, freshness, revalidation), `only-if-cached` handling, `Set-Cookie` safety, entry lifecycle.
- `key.rs`: cache key computation from URI + method + optional namespace.
- `hash.rs`: SHA-256 helper.
- `entry.rs`: cache entry envelope — response headers, body, metadata, age tracking.
- `types.rs`: type definitions — lookup outcome, revalidation state, store decision.
- `backends.rs`: cache backend trait + backend registry (selects implementation by URL scheme).
- `backend_redis.rs`: Redis backend — supports `redis://`, `rediss://`, `redis+unix://`.
- `backend_http.rs`: HTTP object-storage backend — GET/PUT/DELETE against an HTTP gateway.
- `directives.rs`: `Cache-Control` directive parser for request and response.
- `freshness.rs`: freshness lifetime calculation — `s-maxage` > `max-age` > `Expires` > default, Age synthesis.
- `lookup_ops.rs`: cache lookup matching and conditional revalidation (ETag/Last-Modified).
- `store.rs`: storability decision logic — method/status checks, Vary handling, authorization constraints.
- `invalidate.rs`: unsafe-method invalidation — clears target URI and same-authority `Location`/`Content-Location` targets.
- `vary.rs`: `Vary`-aware variant storage and lookup. `Vary: *` treated as uncacheable.
- `util.rs`: utility helpers.
- `tests.rs`: cache unit tests.

### Other daemon modules

- `ftp.rs`: FTP-over-HTTP gateway — translates HTTP GET/PUT/LIST to FTP commands, PASV/PORT fallback, bounded transfer sizes.
- `fastcgi_client.rs`: FastCGI client — encodes HTTP requests as FastCGI records, connects to FastCGI backends (TCP/Unix) with a small connection pool + `FCGI_KEEP_CONN`, decodes CGI-style responses back to HTTP with streaming body support. Used by `upstream/origin.rs` and reverse routes.
- `exporter.rs`: capture event producer — TCP client to `qpxr`, event queue management, request/response body preview serialization.
- `io_copy.rs`: bidirectional stream copy (used for CONNECT tunnels and WebSocket) with optional capture export hooks and idle timeout.
- `io_prefix.rs`: `PrefixedIo` adapter — "unreads" a byte buffer back onto a stream after peeking (used for PROXY v2 metadata and TLS ClientHello inspection) so downstream consumers see the original byte stream from the beginning.
- `net.rs`: socket helpers — `SO_REUSEPORT`, `SO_REUSEADDR`, TCP backlog, multi-socket listener binding.
- `xdp/mod.rs`: PROXY protocol v1/v2 metadata parser.
- `xdp/remote.rs`: resolves effective remote address — uses PROXY metadata when available and trusted, falls back to socket peer address.

---

## Reader (`qpxr`)

Single-file crate. Receives structured capture events from `qpxd` over TCP, generates PCAPNG blocks, manages local file rotation, and serves live/history streams to `qpxc` clients. Security: TLS, bearer token, CIDR allowlists.

- `main.rs`: all logic in one file.

## Client (`qpxc`)

Single-file crate. Connects to `qpxr` and relays the PCAPNG stream to Wireshark (as an extcap plugin) or to stdout for simple packet viewing.

- `main.rs`: supports `live`/`history`/`follow` modes, Wireshark extcap option negotiation, raw passthrough.

---

## Function executor (`qpxf`)

FastCGI server that executes CGI scripts and WASM modules. `qpxd` connects to `qpxf` as a FastCGI client using reverse route `fastcgi:` config or `fastcgi://` upstream URLs.

- `main.rs`: CLI (`--listen`, `--config`, `--workers`), FastCGI connection accept loop, concurrency-limited request dispatch via `tokio::sync::Semaphore`. Safe Unix socket binding (verifies existing path is a socket before unlink).
- `config.rs`: YAML configuration schema with `deny_unknown_fields` — listen address, workers (concurrency limit), request size limits, handler routing rules, CGI/WASM backend settings including per-backend stdout/stderr size limits.
- `server.rs`: FastCGI connection handler — request_id state machine (multiplexing), BEGIN_REQUEST role/flags validation, management records (request_id=0), ABORT_REQUEST, keep-alive (`FCGI_KEEP_CONN`), streaming STDIN→executor and executor stdout/stderr→FastCGI, per-request input idle timeout + connection idle timeout.
- `fastcgi.rs`: FastCGI protocol primitives — record read/write, name-value encoding/decoding, protocol constants, and version validation.
- `router.rs`: path-based request routing — matches incoming requests by `path_prefix`, `path_regex`, and `host` to the appropriate executor. Returns matched prefix for prefix-stripping in executors.
- `executor/mod.rs`: `Executor` trait definition and shared request/response types (`CgiRequest`, `CgiResponse`). `matched_prefix` field enables correct script path resolution.
- `executor/cgi.rs`: RFC 3875 CGI script executor — spawns external processes via `tokio::process::Command`, sets CGI environment variables (including `SERVER_SOFTWARE`), pipes stdin/stdout/stderr. Security: canonicalizes CGI root on startup, rejects `..` paths and symlink escapes, enforces configurable stdout/stderr size limits, reads stdout/stderr concurrently (prevents deadlock), post-timeout `wait()` ensures zombie process cleanup. Hop-by-hop headers are excluded from HTTP_* env.
- `executor/wasm.rs`: WASI-compatible WASM executor (feature `wasm`) — uses `wasmtime::Engine` + `wasmtime::Module` for module loading, `wasmtime_wasi` for WASI context (stdin/stdout/env). Security: `ResourceLimiter` enforces memory limits, a single global epoch ticker (10ms interval) drives all timeout deadlines (no per-request epoch increment side effects), configurable stdout/stderr capture with size limits. Stderr captured and logged instead of inherited. Trap detection uses structural `Trap::Interrupt` check instead of string matching.

---

## Design rules

1. Mode entry files (`forward/mod.rs`, `reverse/mod.rs`, `transparent/mod.rs`) own only mode-specific control flow. They must not contain shared HTTP logic.
2. Shared protocol mechanics live in `http/`, `http3/`, `upstream/`, `xdp/`, or `tls/`.
3. New features must not duplicate parsing, response building, or tunnel logic across mode files.
4. `qpxd` never generates PCAP/PCAPNG. `qpxr` is the sole capture generator. `qpxc` is passthrough only.
5. `qpxf` is the sole CGI/WASM execution environment. `qpxd` communicates with `qpxf` only via the FastCGI protocol.

# Code Structure

Source-level guide to the qpx workspace.

## Architecture overview

qpx is a Rust workspace with ten product/runtime crates plus one developer utility crate (`xtask`):

```
qpx-core   shared library: config loading, rule engine, TLS, exporter schema, IPC/SHM types
qpx-auth   runtime library: proxy auth providers, Basic/Digest auth, LDAP auth, auth cache
qpx-wasm   runtime library: WASI/wasmtime executor used by qpxf's `wasm` feature
qpx-acme   runtime library: ACME HTTP-01 issuance/renewal and in-memory cert stores for qpxd
qpx-h3     runtime library: clean-room HTTP/3 backend crate for qpxd (`http3-backend-qpx`)
qpx-observability runtime library: logging init, metrics endpoint, trace context, access log middleware
qpxd       daemon:         forward / reverse / transparent HTTP proxy
qpxf       executor:       function executor (CGI scripts + WASM modules) over QPX-IPC
qpxr       reader:         reads capture events from qpxd's SHM ring, writes PCAPNG
qpxc       client:         streams PCAPNG from qpxr to Wireshark or stdout
```

`xtask` provides developer automation and is intentionally omitted from the runtime flow diagrams below. `qpxd` is the main network proxy. It forwards requests to `qpxf` over the QPX-IPC protocol using reverse-route `ipc:` targets in the YAML. QPX-IPC uses a shared-memory ring buffer for body transfer when both processes share a host, and falls back to a plain TCP/Unix stream otherwise. `qpxr` and `qpxc` are post-capture tooling and never participate in the proxy data path.

HTTP/3 is now split by build-time backend selection inside `qpxd`. `http3-backend-h3` keeps the upstream-`h3` implementation as the default path. `http3-backend-qpx` switches `qpxd` to the clean-room `qpx-h3` crate and preserves the shared QUIC socket/broker plumbing in `qpxd::http3::quinn_socket`.

Choose the backend by required protocol surface:

- `http3-backend-h3`: baseline upstream-`h3` backend. It carries standard HTTP/3 request/response, forward CONNECT-UDP datagram relay, chained upstream HTTP/3 proxying, and non-WebTransport extended CONNECT.
- `http3-backend-qpx`: clean-room backend. It carries the clean-room terminate/listener path plus the full QPX-owned advanced HTTP/3 surface: CONNECT-UDP / MASQUE datagram relay, generic extended CONNECT, and WebTransport relay over HTTP/3 extended CONNECT.
- Reverse HTTP/3 passthrough is backend-neutral because it stays in `qpxd` as raw UDP/QUIC session routing.

The YAML schema is flat and maps directly to `qpx_core::config::types::*`. Top-level sections such as `system_log`, `metrics`, `auth`, `identity_sources`, and `ext_authz` are deserialized as written; reverse-route targets are expressed directly as `upstreams`, `backends`, `ipc`, or `local_response`.

### Request flow through qpxd

Every inbound connection follows the same layered pipeline:

```
listener accept (mode-specific: forward/ reverse/ transparent/)
  │
  ├─ XDP / PROXY metadata resolution   (xdp/)
  │
  ├─ connection_filter (src_ip/dst_port) (connection_filter.rs)
  │
  ├─ TLS peek / SNI extraction            (tls/sniff.rs)
  │   ├─ connection_filter (SNI/ALPN/JA3/JA4) before handshake
  │   ├─ TLS terminate or passthrough     (tls/client.rs, reverse/listener.rs)
  │   └─ MITM interception                (tls/mitm.rs → http/mitm.rs)
  │
  ├─ HTTP parsing + semantic validation  (http/semantics.rs)
  │
  ├─ Rule/policy evaluation              (forward/policy.rs, http/policy.rs)
  │   ├─ Auth challenge/verify           (qpx-auth)
  │   └─ Rule matching                   (qpx-core: rules.rs + prefilter.rs)
  │
  ├─ Action dispatch
  │   ├─ direct / proxy upstream         (upstream/)
  │   ├─ function executor (IPC)         (ipc_client.rs → qpxf)
  │   ├─ CONNECT tunnel                  (forward/connect.rs)
  │   ├─ cache lookup + store            (cache/, http/cache_flow.rs)
  │   ├─ HTTP modules                    (http/modules.rs)
  │   ├─ local response                  (http/local_response.rs)
  │   ├─ FTP gateway                     (ftp.rs)
  │   └─ WebSocket upgrade               (http/websocket.rs)
  │
  ├─ Response finalization               (http/l7.rs: Via, Date, header control)
  │
  └─ Capture export                      (exporter.rs → SHM ring → qpxr)
```

The key boundary rule is: mode directories (`forward/`, `reverse/`, `transparent/`) own **only** mode-specific control flow. Shared protocol mechanics live in `http/`, `http3/`, `upstream/`, `tls/`, and `cache/`. New features must not duplicate parsing, response building, or tunnel logic across modes.

### Capture pipeline boundary

`qpxd` never generates PCAP/PCAPNG. It emits structured capture events into a shared-memory ring buffer (`exporter.shm_path`), and `qpxr` is the sole PCAPNG generator that consumes that ring. `qpxc` is a passthrough viewer (extcap bridge or simple packet dump).

---

## Core library (`qpx-core`)

Shared building blocks that `qpxd`, `qpxr`, and `qpxc` all depend on. This crate has no network I/O — it provides types, parsing, and evaluation.

- `lib.rs`: crate root, public module re-exports.
- `config.rs`: re-export module root.
- `config/types/`: YAML configuration schema (serde structs for all sections).
- `config/types/http.rs`: open HTTP module schema — shared `type` / `id` / `order` envelope plus raw module settings. Built-ins such as `response_compression`, `subrequest`, and `cache_purge` are parsed by the runtime registry, but third-party module types also load here unchanged.
- `config/load.rs`: config loading, `include` file composition, and environment variable expansion.
- `config/validate.rs`: post-load validation and constraint checking.
- `config/defaults.rs`: default values for optional config fields.
- `config/tests.rs`: config loading and validation tests.
- `envsubst.rs`: `${VAR:-default}` environment variable substitution.
- `rules.rs`: rule engine — compiles listener rules into a matchable form (`CompiledRule`) and evaluates incoming requests against them.
- `prefilter.rs`: bitset/trie-based prefilter index. Narrows candidate rules before full evaluation to avoid O(n) scans on large rulesets.
- `matchers.rs`: low-level match primitives (CIDR, glob, regex, header value matchers) used by the rule engine.
- `tls.rs`: TLS helpers: CA management and MITM certificate generation (feature `tls-rustls`); stub implementation when `tls-rustls` is disabled.
- `exporter.rs`: capture event schema — shared between `qpxd` (producer) and `qpxr` (consumer) for serialization compatibility.
- `shm_ring.rs`: shared-memory ring buffer (`ShmRingBuffer`) backed by a memory-mapped file (`memmap2`). Used by `qpxd` to produce capture events and by `qpxr` to consume them. Also used by QPX-IPC for shared-memory request/response body transfer between `qpxd` and `qpxf` (bodies are copied into/out of the ring).
- `ipc/meta.rs`: QPX-IPC request/response metadata types (`IpcRequestMeta`, `IpcResponseMeta`) — JSON-serialized header frame sent before body data.
- `ipc/protocol.rs`: QPX-IPC framing helpers (`read_frame`, `write_frame`) — length-prefixed JSON frame encoding shared by `qpxd` (client) and `qpxf` (server).

---

## Auth Runtime (`qpx-auth`)

Runtime-only authentication machinery used by `qpxd`. This crate depends on `qpx-core::config` for auth schemas, but keeps LDAP, Basic/Digest parsing, and auth caches out of the shared core crate.

- `lib.rs`: crate root, public auth types, feature gating.
- `auth/authenticator.rs`: `Authenticator` construction, Proxy-Authorization parsing, Basic/Digest verification, challenge generation.
- `auth/ldap.rs`: LDAP bind/search/group resolution and filter escaping.
- `auth/local.rs`: local user materialization from config, including digest HA1 preparation.
- `auth/digest.rs`: Digest auth nonce store, parser, SHA-256 helpers.
- `auth/cache.rs`: LDAP credential/group cache with bounded size and TTL.
- `auth/util.rs`: constant-time compares and header escaping helpers.

---

## Runtime Observability (`qpx-observability`)

Runtime-only logging and tracing machinery used by `qpxd`. This crate depends on `qpx-core::config` for schemas, but it is intentionally separate so executor/capture tooling does not inherit Prometheus/OTel/access-log implementation dependencies.

- `lib.rs`: crate root, public re-exports.
- `logging.rs`: tracing subscriber initialization, system/access/audit log sinks, rotation cleanup, OTEL layer wiring.
- `metrics.rs`: Prometheus scrape endpoint bootstrap and request handling.
- `tracing_support.rs`: OTLP exporter setup plus trace context extract/inject helpers.
- `access_log.rs`: `tower_service` middleware that records access-log fields and attaches trace metadata.

---

## ACME Runtime (`qpx-acme`)

Runtime-only ACME machinery used by `qpxd` when built with feature `acme`. This crate intentionally holds the ACME protocol client, HTTP-01 responder, and certificate stores outside the main daemon crate so the `instant-acme` / newer Hyper stack stays isolated from the hot proxy path.

- `lib.rs`: crate root plus all ACME runtime state.
- `ConfigProvider`: trait implemented by `qpxd::runtime::Runtime`, allowing the ACME manager to read the current hot-reloaded config snapshot without depending on `qpxd` internals.
- `AcmeRuntime`: long-lived ACME state — directory URL, state dir paths, renewal settings, HTTP-01 bind address, and in-memory certificate/token stores.
- `AcmeCertStore` / `AcmeQuicCertStore`: SNI-indexed certificate stores used by reverse TLS termination and HTTP/3 termination when ACME-managed certificates are active.
- `init()`: validates `acme:` config, prepares state directories, preloads certificates from disk, and initializes the process-global runtime handle.
- `run_http01_server()`: lightweight HTTP-01 responder bound to `acme.http01_listen`.
- `run_manager()`: background issuance/renewal loop — loads or creates the ACME account, places orders, satisfies challenges, persists certificates, and refreshes in-memory stores.

---

## HTTP/3 Backend (`qpx-h3`)

Clean-room HTTP/3 backend crate for `qpxd`.

- `lib.rs`: current backend crate root. Holds the clean-room implementation entry surface that `qpxd` can depend on without importing `h3`.
- Current state: `qpx-h3` provides the clean-room buffered HTTP/3 runtime for forward and reverse terminate listeners, plus clean-room CONNECT-UDP / MASQUE relay, generic extended CONNECT, and WebTransport relay.
- Select it when you need WebTransport relay or when you want the full QPX-owned advanced HTTP/3 surface on the clean-room backend.

---

## Proxy daemon (`qpxd`)

### Entry point and runtime

- `main.rs`: CLI (`run`, `check`, `upgrade`, and `gen-ca` when built with `tls-rustls`), merged config loading from one or more `--config` files, listener startup orchestration, config watch setup, and the process supervisor for in-place server-set restarts plus cross-platform binary-upgrade handoff.
- `runtime.rs`: shared runtime state container — holds the config snapshot, compiled rules, auth providers, TLS state, metrics handles, exporter sessions, and the hot-reload watcher. Passed as `Arc` to all request handlers. Also implements `qpx_acme::ConfigProvider` so the isolated ACME runtime can observe the latest config snapshot.
- `sidecar_control.rs`: control-plane enum for UDP/HTTP3 sidecars — distinguishes normal running, graceful stop, and export-for-upgrade shutdown so sidecars can snapshot live session state before exit.
- `tcp_bindings.rs`: process-handoff listener inventory — binds or adopts inherited TCP listeners for forward/transparent listeners, reverse TCP listeners, metrics, and ACME HTTP-01; serializes the inheritance manifest for child startup.
- `udp_bindings.rs`: process-handoff UDP listener inventory — binds or adopts inherited forward HTTP/3, reverse HTTP/3, and transparent UDP/QUIC sockets so the child can resume those listeners without rebinding ports.
- `udp_session_handoff.rs`: UDP session export/restore manifest — serializes transparent UDP and reverse HTTP/3 passthrough session metadata plus inherited connected upstream sockets so a replacement process can resume those flows.
- `http3/quinn_socket.rs`: Quinn upgrade broker — wraps the UDP socket used by forward HTTP/3 and reverse HTTP/3 terminate, tracks active QUIC routing by address/CID, and brokers new handshakes to the replacement process during binary upgrade until the parent drains and exits. Unix uses socketpairs; Windows uses loopback TCP rendezvous.
- `upgrade.rs`: binary-upgrade handoff helpers — installs the platform trigger (`SIGUSR2` on Unix, named event + `upgrade --pid` on Windows), prepares TCP/UDP/session manifests, spawns the replacement process, hands off QUIC broker control streams, and waits for the child readiness handshake before the parent drains its TCP and old-generation QUIC accepts.

### Forward proxy (`forward/`)

Handles explicit HTTP proxy requests (client sets proxy address).

- `mod.rs`: listener startup, TCP accept loop, HTTP/1.1 and HTTP/2 serve wiring, XDP metadata resolution per connection.
- `request.rs`: request dispatch — evaluates rules, resolves upstream, routes to proxy/direct/FTP/cache/MITM/respond paths. This is the main request handler.
- `request_dispatch.rs`: forward HTTP dispatch internals — cache flow, upstream dispatch, and listener-level HTTP module execution.
- `connect.rs`: CONNECT method handling — tunnel establishment, bidirectional relay, and TLS interception when policy selects inspect.
- `policy.rs`: forward-mode policy evaluation — auth verification, group-based rule matching, auth cache lookup.
- `h3.rs` / `h3_qpx.rs`: build-time selected HTTP/3 forward backend entrypoints. `h3.rs` is the upstream-`h3` backend for baseline HTTP/3, MASQUE, and generic extended CONNECT. `h3_qpx.rs` is the clean-room adapter that routes buffered request/response handling, CONNECT-UDP / MASQUE relay, generic extended CONNECT, and WebTransport relay through `qpx-h3`.
- `h3_connect.rs`: default `h3` backend HTTP/3 CONNECT tunnel — policy check + bidirectional stream relay.
- `h3_connect_udp.rs`: default `h3` backend HTTP/3 CONNECT-UDP — MASQUE capsule handling, datagram relay, upstream proxy chaining.

### Reverse proxy (`reverse/`)

Routes inbound traffic to backend upstreams based on Host/SNI/path/src_ip matching.

- `mod.rs`: listener startup and mode selection (TLS, plain HTTP, HTTP/3, TLS passthrough). The reverse HTTP/3 orchestration also lives here: it binds the build-time `h3_terminate` module alias to either `h3_terminate.rs` or `h3_terminate_qpx.rs`, and always exposes backend-neutral UDP passthrough via `h3_passthrough.rs`.
- `listener.rs`: TCP/TLS accept loops — TLS handshake, SNI peek for passthrough routing, XDP metadata.
- `router.rs`: route compilation and matching — builds a prefilter index over routes, selects upstream set, handles TLS passthrough by SNI.
- `transport.rs`: HTTP request handling after route match — upstream forwarding, WebSocket proxy, retry with body buffering, cache flow, header pipeline.
- `transport_dispatch.rs`: reverse HTTP dispatch internals — response rules, retry/failover, cache flow, and route-level HTTP module execution.
- `request_template.rs`: request template for retry — buffers the body and checks retryability before re-dispatching.
- `health.rs`: upstream health probes — periodic active checks, health state tracking.
- `security.rs`: TLS host anti-fronting — enforces that TLS SNI matches the HTTP Host/authority header, with configurable exception globs.
- `h3_terminate.rs` / `h3_terminate_qpx.rs`: build-time selected HTTP/3 terminate backends. `h3_terminate.rs` is the default upstream-`h3` implementation; `h3_terminate_qpx.rs` is the clean-room backend adapter surface.
- `h3_passthrough.rs`: HTTP/3 UDP passthrough runtime — round-robin forwarding of raw UDP datagrams to configured upstreams, with a session index keyed by QUIC connection IDs, amplification guardrails, and the same pre-handshake reverse `connection_filter` before a new UDP/QUIC session is established. This path stays in `qpxd` because it is raw UDP/QUIC session routing rather than HTTP/3 framing logic.

### Transparent proxy (`transparent/`)

Intercepts traffic without client configuration (Linux `SO_ORIGINAL_DST` or protocol metadata).

- `mod.rs`: listener startup, TLS/HTTP protocol detection on accepted connections.
- `destination.rs`: original destination recovery — Linux `SO_ORIGINAL_DST`, SNI/Host fallback on non-Linux, PROXY metadata. Also provides target connection helpers.
- `http_path.rs`: plain HTTP handling — rule evaluation, upstream dispatch, header/cache pipeline. Structurally parallel to `forward/request.rs`.
- `http_dispatch.rs`: transparent HTTP dispatch internals — listener policy, upstream dispatch, response policy, and listener-level HTTP module execution.
- `tls_path.rs`: TLS connection handling — decides tunnel/block/MITM based on rule outcome and SNI.

### HTTP protocol (`http/`)

Shared HTTP processing used by all three modes. Nothing in this directory is mode-specific.

- `semantics.rs`: RFC 9110/9112 message mechanics — hop-by-hop stripping, Via append, Host/authority validation, no-body response normalization, Transfer-Encoding/Content-Length conflict detection.
- `l7.rs`: request/response finalization pipeline — calls `semantics.rs`, then applies header control, Date, Max-Forwards decrement, TRACE handling.
- `header_control.rs`: request/response header mutation engine — set/add/remove/regex-replace per rule configuration.
- `policy.rs`: shared policy evaluation for transparent and MITM paths — block/respond/proceed decision.
- `mitm.rs`: MITM intercepted request handler — re-evaluates rules after TLS decryption, dispatches to upstream, supports WebSocket upgrade.
- `mitm_dispatch.rs`: MITM HTTP dispatch internals — decrypted forward-mode policy, upstream dispatch, and listener-level HTTP module execution.
- `modules.rs`: public in-process HTTP module/filter API — registry/factory surface for external Rust modules, per-request `HttpModuleContext`, borrowed/in-place request hooks, frozen request view for response-phase filters, and the ordered execution chain that runs request-header, cache, upstream, retry, response, error, and logging hooks. Built-ins (`response_compression`, `subrequest`, `cache_purge`) are registered through the same API as third-party modules.
- `websocket.rs`: WebSocket upgrade detection and bidirectional upgraded-stream relay.
- `upgrade.rs`: downstream HTTP/1 upgrade handoff — qpx-native `CONNECT` / `101 Switching Protocols` token that transfers the raw socket to tunnel handlers without routing through hyper's server adapter.
- `local_response.rs`: policy response builder — constructs status/body/content-type/headers responses without upstream forwarding.
- `rpc.rs`: shared RPC protocol inspection and local-response framing — extracts `match.rpc.*` context for `gRPC` / `Connect` / `gRPC-Web` and emits protocol-correct local responses.
- `common.rs`: canonical error responses (400/403/502/etc.), shared HTTP client, named-upstream resolution.
- `address.rs`: host/port/authority parsing and formatting.
- `cache_flow.rs`: cache orchestration — lookup, conditional revalidation (If-None-Match/If-Modified-Since), response writeback.
- `mod.rs`: module re-exports.

### HTTP/3 protocol (`http3/`)

Shared QUIC/HTTP/3 support code used by the backend-selected HTTP/3 runtime.

- `quinn_socket.rs`: backend-neutral QUIC socket wrapper, broker handoff, and endpoint-socket preparation shared by both HTTP/3 backends.
- `capsule.rs`: CONNECT-UDP capsule encoding/decoding and QUIC variable-length integer helpers shared by the HTTP/3 backends; varint decode remains shared with transparent QUIC session code.
- `codec.rs`, `listener.rs`, `server.rs`, `quic.rs`, `datagram.rs`: current `http3-backend-h3` protocol driver surface. These modules are compiled only for the default `h3` backend.
- `mod.rs`: backend-sensitive module exports.

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
- `origin.rs`: direct upstream dispatch (reverse/transparent) — dispatches `http://`, `https://`, `ws://`, and `wss://` upstreams plus the internal IPC URL path used by reverse transport. Routes `ipc`/`ipc+unix` targets to `ipc_client::proxy_ipc()`; selects h2-aware hyper sender for HTTP/HTTPS and the WebSocket upgrade path for WS/WSS; handles request URI rewriting. User-facing YAML expresses the IPC leg as `reverse[].routes[].ipc`.
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
- `ipc_client.rs`: QPX-IPC client used by reverse `ipc:` routes. Sends an `IpcRequestMeta` JSON frame, then transfers request/response bodies: in `shm` mode via per-request `ShmRingBuffer` files (64 KiB chunks, EOF signalled by empty push); in `tcp` mode by streaming bytes directly over the connection. Maintains a small idle-connection pool per backend. Also contains the internal URL-based IPC helper path used by reverse transport. Entry points: `proxy_ipc_upstream()` and `proxy_ipc()`.
- `exporter.rs`: capture event producer — writes serialized capture events to a shared-memory ring buffer (`ShmRingBuffer`), with queue/backpressure behavior controlled by config.
- `io_copy.rs`: bidirectional stream copy (used for CONNECT tunnels and WebSocket) with optional capture export hooks and idle timeout.
- `io_prefix.rs`: `PrefixedIo` adapter — "unreads" a byte buffer back onto a stream after peeking (used for PROXY v2 metadata and TLS ClientHello inspection) so downstream consumers see the original byte stream from the beginning.
- `net.rs`: socket helpers — `SO_REUSEPORT`, `SO_REUSEADDR`, TCP backlog, multi-socket listener binding.
- `xdp/mod.rs`: PROXY protocol v2 metadata parser and trust gate (`xdp.metadata_mode: proxy-v2` only).
- `xdp/remote.rs`: resolves effective remote address — uses PROXY metadata when available and trusted, falls back to socket peer address.

---

## Reader (`qpxr`)

Single-file crate. Consumes structured capture events from the shared-memory ring buffer produced by `qpxd`, generates PCAPNG blocks, manages local file rotation, and serves live/history streams to `qpxc` clients. Security: TLS, bearer token, CIDR allowlists.

- `main.rs`: all logic in one file.

## Client (`qpxc`)

Single-file crate. Connects to `qpxr` and relays the PCAPNG stream to Wireshark (as an extcap plugin) or to stdout for simple packet viewing.

- `main.rs`: supports `live`/`history`/`follow` modes, Wireshark extcap option negotiation, raw passthrough.

## Refactor Baseline

Measured with `scripts/measure-structure.sh`, which strips inline `#[cfg(test)] mod tests` blocks before counting non-comment Rust lines.

| File | Code LOC |
|---|---:|
| `qpxd/src/forward/h3_connect.rs` | 3325 |
| `qpxd/src/reverse/transport.rs` | 1482 |
| `qpx-core/src/config/validate.rs` | 2928 |
| `qpxd/src/forward/connect.rs` | 1835 |
| `qpxd/src/reverse/router.rs` | 1256 |
| `qpxd/src/transparent/udp_path.rs` | 1088 |
| `qpxd/src/forward/request.rs` | 1060 |
| `qpx-core/src/config/types/mod.rs` | 1246 |
| `qpxd/src/runtime.rs` | 940 |
| `qpxd/src/upstream/origin.rs` | 771 |

## Current Structure Budget

Measured on 2026-04-19 with `scripts/measure-structure.sh` after the phase 2-5 splits.

| File | Code LOC | Budget |
|---|---:|---:|
| `qpxd/src/forward/h3_connect.rs` | 160 | 600 |
| `qpxd/src/reverse/transport.rs` | 234 | 600 |
| `qpxd/src/forward/connect.rs` | 608 | 800 |
| `qpxd/src/reverse/router.rs` | 419 | 600 |
| `qpxd/src/transparent/udp_path.rs` | 569 | 600 |
| `qpxd/src/forward/request.rs` | 185 | 600 |
| `qpxd/src/forward/request_dispatch.rs` | 882 | 900 |
| `qpx-core/src/config/validate.rs` | 90 | 600 |
| `qpx-core/src/config/types/mod.rs` | 65 | 600 |
| `qpxd/src/runtime.rs` | 102 | 600 |
| `qpxd/src/upstream/origin.rs` | 173 | 600 |
| `qpxd/src/transparent/http_path.rs` | 118 | 250 |
| `qpxd/src/http/mitm.rs` | 120 | 250 |
| `qpxd/src/reverse/transport_dispatch.rs` | 1276 | 1300 |
| `qpxd/src/transparent/http_dispatch.rs` | 487 | 500 |
| `qpxd/src/http/mitm_dispatch.rs` | 499 | 500 |

`qpxd/src/forward/connect.rs` keeps a relaxed 800 LOC cap because the HTTP/1 CONNECT, HTTP/2 extended CONNECT, and MITM/tunnel entry orchestration still intentionally meet at that boundary. `cargo xtask structure` now enforces both the thin entrypoint modules (`forward/request.rs`, `reverse/transport.rs`, `transparent/http_path.rs`, `http/mitm.rs`) and the moved dispatcher implementation files that hold the hot-path HTTP policy/dispatch logic.

---

## WASM Runtime (`qpx-wasm`)

Reusable WASI executor used by `qpxf` when built with feature `wasm`. This crate intentionally owns the heavy `wasmtime` / `wasmtime-wasi` dependency set so the IPC server crate can stay focused on routing and process management.

- `lib.rs`: crate root plus the full WASM runtime implementation.
- `WasmExecutorConfig`: module path, precompile setting, module/stdin/stdout/stderr size caps, memory/time limits, and environment.
- `WasmRequest`: CGI-shaped request metadata forwarded from `qpxf`.
- `WasmExecution`: live execution handles (`stdin`, `stdout`, `stderr`, `abort`, `done`) returned to the IPC layer.
- `WasmExecutor`: reusable runtime — creates the `wasmtime::Engine`, maintains the global epoch ticker, caches the compiled module / `InstancePre`, builds WASI contexts, enforces module/stdin/memory/time limits, and drives `_start`.
- `WasmResponse`: helper for CGI-compatible output formatting when a WASM result needs to be converted back into a CGI-style response.

---

## Function executor (`qpxf`)

QPX-IPC server that executes CGI scripts and dispatches optional WASM execution through `qpx-wasm` on behalf of `qpxd`. `qpxd` normally connects to `qpxf` using reverse-route `ipc:` config. The protocol sends a JSON metadata frame first, then streams request/response bodies either over the same connection or via shared-memory ring buffers when both processes are on the same host.

- `main.rs`: CLI (`--listen`, `--config`, `--workers`) plus `check --config` for config/backend validation, QPX-IPC connection accept loop, concurrency-limited request dispatch via `tokio::sync::Semaphore`. Listen address accepts TCP (`host:port`) or Unix socket (`unix:///path`). TCP listeners require `allow_insecure_tcp=true`. Safe Unix socket binding verifies an existing path is a socket before unlinking.
- `config.rs`: YAML configuration schema with `deny_unknown_fields` — listen address, workers (concurrency limit), `allow_insecure_tcp`, connection caps (`max_connections`, `max_requests_per_connection`), request and connection idle timeouts, size limits (`max_params_bytes`, `max_stdin_bytes`), handler routing rules, CGI/WASM backend settings including per-backend stdout/stderr size limits.
- `server.rs`: QPX-IPC connection handler — reads `IpcRequestMeta` frame, routes to executor, streams body, writes `IpcResponseMeta` response frame, handles keep-alive, input idle timeout, and connection idle timeout.
- `router.rs`: path-based request routing — matches incoming requests by `path_prefix`, `path_regex`, and `host` to the appropriate executor. Returns matched prefix for prefix-stripping in executors.
- `executor/mod.rs`: `Executor` trait definition and shared request/response types (`CgiRequest`, `CgiResponse`). `matched_prefix` field enables correct script path resolution.
- `executor/cgi.rs`: RFC 3875 CGI script executor — spawns external processes via `tokio::process::Command`, sets CGI environment variables (including `SERVER_SOFTWARE`), pipes stdin/stdout/stderr. Security: canonicalizes CGI root on startup, rejects `..` paths and symlink escapes, enforces configurable stdout/stderr size limits, reads stdout/stderr concurrently (prevents deadlock), post-timeout `wait()` ensures zombie process cleanup. Hop-by-hop headers are excluded from HTTP_* env.
- `executor/wasm.rs`: thin adapter for feature `wasm` — translates `qpxf`'s `CgiRequest` into `qpx_wasm::WasmRequest`, starts `qpx_wasm::WasmExecutor`, and maps the returned execution handles back into the generic `Execution` shape used by the IPC server.

---

## Design rules

1. Mode entry files (`forward/mod.rs`, `reverse/mod.rs`, `transparent/mod.rs`) own only mode-specific control flow. They must not contain shared HTTP logic.
2. Shared protocol mechanics live in `http/`, `http3/`, `upstream/`, `xdp/`, or `tls/`.
3. New features must not duplicate parsing, response building, or tunnel logic across mode files.
4. `qpxd` never generates PCAP/PCAPNG. `qpxr` is the sole capture generator. `qpxc` is passthrough only.
5. `qpxf` is the sole CGI/WASM execution environment. `qpxd` communicates with `qpxf` only via the QPX-IPC protocol (`ipc_client.rs` → `qpxf/server.rs`).
6. `qpx-acme` owns ACME protocol state, renewal logic, and ACME-managed certificate stores. `qpxd` only wires that runtime into listener startup and certificate selection.
7. `qpx-wasm` owns the `wasmtime` / WASI runtime. `qpxf` remains the IPC server, router, and CGI process supervisor.

# Code Structure

Source-level guide to the qpx workspace. Directory granularity is intentional:
per-file inventories go stale quickly, and `cargo xtask structure` /
`xtask/loc-budgets.tsv` are the machine-checked source of truth for file-level
budgets and structural gates.

## Architecture overview

qpx is a Rust workspace with twelve product/runtime crates plus one developer
utility crate (`xtask`):

```
qpx-core          shared library: config loading/validation, rule engine, matchers,
                  prefilter, TLS trust/CA/ClientHello types, exporter schema,
                  IPC/SHM types, redaction, env substitution
qpx-http          shared HTTP runtime primitives lifted out of qpxd (body channels
                  and spooling, protocol helpers, TLS glue, sharding) so sibling
                  crates can reuse them without depending on the daemon
qpx-auth          optional runtime library: built-in Basic/Digest/LDAP proxy auth,
                  auth caches, constant-time helpers
qpx-acme          runtime library: ACME HTTP-01 issuance/renewal and cert stores
qpx-h3            clean-room HTTP/3 backend crate (`http3-backend-qpx`)
qpx-wasm          WASI/wasmtime executor used by qpxf's `wasm` feature
qpx-observability logging init, metrics endpoint, trace context, access log
qpxd-cache        RFC 9111 proxy cache: entries, freshness, Vary, invalidation,
                  in-memory / Redis / HTTP object-storage backends
qpxd              daemon: forward / reverse / transparent HTTP proxy
qpxf              executor: CGI / WASM / FastCGI / SCGI over QPX-IPC
qpxr              reader: consumes capture events from qpxd's SHM ring, writes PCAPNG
qpxc              client: streams PCAPNG from qpxr to Wireshark or stdout
```

`qpxd` is the main network proxy. It forwards requests to `qpxf` over the
QPX-IPC protocol using reverse-route `ipc:` targets. QPX-IPC uses a
shared-memory ring buffer for body transfer when both processes share a Unix
host with owner-only SHM file permissions, and falls back to a plain TCP/Unix
stream otherwise. `qpxr` and `qpxc` are post-capture tooling and never
participate in the proxy data path.

HTTP/3 is split by build-time backend selection inside `qpxd`:
`http3-backend-h3` (default, upstream `h3` crate) and `http3-backend-qpx`
(clean-room `qpx-h3`, full QPX-owned advanced HTTP/3 surface including
WebTransport relay). Reverse HTTP/3 passthrough is backend-neutral raw
UDP/QUIC session routing inside `qpxd`.

The YAML schema is canonical and edge-oriented: `qpx-core` deserializes
canonical input (`telemetry`, `security`, `http`, `traffic`, `caches`,
`edges[]`) and `qpxd` compiles it into the runtime plan.

### Request flow through qpxd

Every inbound connection follows the same layered pipeline:

```
listener accept (mode-specific: forward/ reverse/ transparent/)
  │
  ├─ XDP / PROXY metadata resolution    (xdp/)
  ├─ connection_filter                  (server/, pre-handshake early drop)
  ├─ TLS peek / SNI extraction          (tls/sniff/)
  │   ├─ TLS terminate or passthrough   (reverse/listener/, reverse/tls/)
  │   └─ MITM interception              (tls/mitm.rs → http/mitm/)
  ├─ HTTP parsing + semantic validation (http/protocol/, http/codec/)
  ├─ Rule/policy evaluation             (forward/policy/, http/policy/,
  │                                      qpx-core rules + prefilter + matchers)
  ├─ Shared dispatch stages             (http/dispatch/: audit context, guard,
  │                                      ext_authz, rate limit, cache flow,
  │                                      response policy, websocket setup)
  ├─ Action dispatch (mode dispatchers delegating to shared stages)
  │   ├─ direct / proxy upstream        (upstream/, upstream/origin/)
  │   ├─ function executor (IPC)        (ipc_client/ → qpxf)
  │   ├─ CONNECT / tunnels              (forward/connect/, tunnel/)
  │   ├─ cache lookup + store           (qpxd-cache, http/dispatch/cache.rs)
  │   ├─ HTTP modules                   (http/modules/)
  │   ├─ local response                 (http/local_response.rs, http/rpc/)
  │   ├─ FTP gateway                    (ftp/)
  │   └─ WebSocket upgrade              (http/protocol/, http/dispatch/websocket.rs)
  ├─ Response finalization              (http/protocol/l7: Via, Date, header control)
  └─ Capture export                     (exporter/ → SHM ring → qpxr)
```

The key boundary rules:

- Mode directories (`forward/`, `reverse/`, `transparent/`) own **only**
  mode-specific control flow; each keeps a thin `dispatch` layer (input/outcome
  types plus glue) that delegates to the shared stages in `http/dispatch/`.
- Shared protocol mechanics live in `http/`, `http3/`, `upstream/`, `tls/`,
  and `tunnel/`. `http/dispatch/` must not import mode directories.
- `qpxd` never generates PCAP/PCAPNG. It emits structured capture events into
  a shared-memory ring (`exporter/`), `qpxr` is the sole PCAPNG generator, and
  `qpxc` is a passthrough viewer.

## qpxd source map

Top level: `main.rs` (binary entry), `lib.rs` (library surface + public
module API), `daemon.rs` / `startup.rs` (Daemon builder, CLI event loop),
`cli.rs` (argument parsing), `test_util.rs` (test-only helpers). Shared
primitives (body, protocol leaf helpers, sharding, TLS connectors) are
imported directly from `qpx-http` / `qpx-core` / `qpxd-cache` — there are no
internal compatibility re-exports.

| Directory | Responsibility |
|---|---|
| `server/` | listener startup, accept loops, server-set lifecycle, connection_filter |
| `forward/` | explicit proxy: `request/` dispatch, `connect/` CONNECT + H2 extended CONNECT, `policy/` auth + rule evaluation, `h3/` forward HTTP/3 (`backend_h3.rs` and clean-room `qpx/` with `connect/`, webtransport, relay) |
| `reverse/` | reverse proxy: `listener/` TCP/TLS accept, `router/` route compile + match, `transport/` request handling with `dispatch/` stages and response rules, `health/` active probes, `tls/` termination glue, `h3/` terminate + backend-neutral passthrough |
| `transparent/` | intercepted traffic: `http/` plain-HTTP path with `dispatch/`, `tls_path/` tunnel/block/MITM decisions, `udp/` UDP/QUIC session routing |
| `http/` | shared HTTP mechanics: `protocol/` (RFC 911x semantics, l7 finalize, header control, addresses), `codec/` HTTP/1 codecs, `body/` body channels + observation/spooling, `dispatch/` shared dispatch stages (audit, access, guard, rate limit, ext_authz deny, cache flow, response policy, websocket), `modules/` public in-process module API + built-ins, `mitm/` decrypted-path dispatch, `policy/` shared policy evaluation, `rpc/` gRPC / gRPC-Web / Connect observation + local responses, `capture/`, `pipeline/`, `local_response.rs` |
| `http3/` | QUIC/HTTP/3 support: `listener/`, `server/`, `qpx_stream/` clean-room adapters, `quinn_socket/` upgrade broker, capsules/datagrams, drain limits |
| `upstream/` | outbound connections: `origin/` direct origins (HTTP/1, H2, pooled H3), `pool/` chained-proxy pools, `raw_http1/` |
| `pool/` | generic pool plumbing shared by the concrete pools: `registry.rs`, `evict.rs`, `single_flight.rs` |
| `tunnel/` | unified tunnel runtime (CONNECT, WebSocket, WebTransport relays): metrics, idle/low-speed policy |
| `policy_context/` | trusted identity (`identity/`), `signed_assertion/` JWS/JWT verification, `ext_authz/` external authorization, audit records, crypto helpers |
| `destination/` | destination intelligence: category/reputation/application classification |
| `rate_limit/` | sharded token buckets for requests/traffic/sessions |
| `ipc_client/` | QPX-IPC client for `ipc:` routes (SHM and TCP body transfer, idle pool) |
| `exporter/` | capture event producer + plaintext redaction before enqueue |
| `runtime/` | runtime state container, hot-reload (`config_rt/`), compiled `plan/` (routes, modules, streaming validation) |
| `cli_render/` | `qpxd explain` / `qpxd match` rendering (text + JSON) |
| `tls/` | daemon TLS glue: `sniff/` ClientHello peek, `mitm.rs` impersonation accept. Trust/cert-info types are imported directly from `qpx-core::tls`, and connector/builder helpers directly from `qpx-http::tls` (no compat re-exports) |
| `tcp_bindings/`, `udp_bindings/`, `udp_session_handoff/`, `udp_socket_handoff.rs`, `upgrade/`, `windows_handoff/` | zero-downtime binary upgrade: listener inheritance, UDP session export/restore, QUIC broker handoff (Unix fd passing, Windows `WSADuplicateSocketW`) |
| `config_reload/` | config watch + in-place reload / server-set restart decisions |
| `ftp/` | FTP-over-HTTP gateway |
| `xdp/` | PROXY protocol v2 metadata parsing and trust gate |

## Shared library crates

- `qpx-core`: no network I/O. `config/` (types, load/include/env expansion,
  validate), `rules/` + `prefilter/` + `matchers/` policy engine, `tls/`
  (trust compilation, CA management, ClientHello types, cert info, resolver),
  `shm_ring.rs` shared-memory ring, `ipc/` QPX-IPC framing + metadata,
  `exporter.rs` capture schema, `redaction.rs`, `envsubst.rs`,
  `uri_template.rs`, `secure_file.rs` permission-safe file handling.
- `qpx-http`: body channel/spool primitives with cancellation
  (`tokio_util::sync::CancellationToken`), protocol helpers, sharding, TLS
  glue. Grown incrementally as self-contained modules are lifted out of
  `qpxd`; `qpxd` imports them directly from this crate (no compat re-exports).
- `qpxd-cache`: RFC 9111 + RFC 5861 cache: `entry.rs`, `freshness.rs`,
  `vary.rs`, `store/`, `lookup_ops.rs`, `invalidate.rs`, `directives.rs`,
  backends (`backend_redis/`, `backend_http/`), `metrics.rs`.
- `qpx-auth`: `authenticator.rs`, `digest.rs` nonce store, `ldap.rs` with
  RFC 4515 escaping, `local.rs` (zeroized credentials), bounded `cache.rs`,
  `util.rs` constant-time compares.
- `qpx-acme`: ACME account/order state, HTTP-01 responder, SNI-indexed cert
  stores, fd-validated key/cert persistence.
- `qpx-observability`: tracing init, access log middleware with query-key
  redaction, Prometheus endpoint with render cache, OTLP wiring, log-sink
  security checks (`logging/security.rs`).
- `qpx-h3`: clean-room HTTP/3 protocol runtime: QPACK, control streams,
  request/response streaming, CONNECT-UDP / MASQUE, extended CONNECT,
  WebTransport.
- `qpx-wasm`: wasmtime engine wrapper with module/stdin/memory/time limits.

## Executor and capture tooling

- `qpxf`: QPX-IPC server (`server/` connection + protocol handling,
  `ipc_request.rs` transport-independent planning, `router.rs` path routing,
  `executor/` CGI / WASM / FastCGI / SCGI backends with path containment,
  size limits, and pooled FastCGI connections, `qpxf/src/config.rs` schema).
- `qpxr`: SHM ring consumer, PCAPNG generation, rotation, live/history
  streams with TLS / token / CIDR controls.
- `qpxc`: extcap bridge / packet viewer over qpxr streams.

## Structure rules

`cargo xtask structure` is the enforcement gate; the rules below are the
intent behind it.

- File-level Code LOC budgets live in `xtask/loc-budgets.tsv` and are
  reported as advisory trend signals. New large modules must be visible in
  review, but code is not split solely to satisfy a line count.
- Production proxy code must not use `panic!`, `todo!`, `unimplemented!`, or
  unchecked `unwrap()`/`expect()` on request paths; `unsafe` blocks require
  `// SAFETY:` comments (denied via workspace lints).
- Library crates expose typed errors at their public boundaries; `anyhow` is
  reserved for the application layer.
- `http/dispatch/` must not import mode directories; mode dispatch files stay
  within counted baselines (`access.rs`, `prepare.rs`, `policy.rs`,
  `types.rs`, `outcome.rs`) so parallel dispatch surfaces cannot silently
  multiply.
- Connection-pool struct count, qpx-core TLS type budget, dependency
  duplicate-name count, raw `counter!`/`gauge!` macro usage, duplicate test
  helpers, and ext_authz response buffering shape are all baseline-checked.
- Security-critical parsers (policy-context identity, signed assertions,
  PROXY v2, TLS ClientHello sniff, QPACK, SHM ring, IPC meta frames, FTP
  responses) keep boundary-focused tests and fuzz targets (`fuzz/fuzz_targets/`).
- Operational dispatch failures use typed errors (`DispatchError`) at mode
  boundaries instead of stringly-typed routing.

Run `scripts/measure-structure.sh` for the current measured LOC table and
`cargo xtask budget` for workspace-level production/test/docs LOC baselines.

# qpx

Quick HTTP proxy and server in Rust. Supports forward, reverse, and transparent proxy modes with HTTP/1.1, HTTP/2, HTTP/3, TLS inspection (MITM), and a function executor for CGI scripts and WASM modules.

## Features

- **Forward proxy** — HTTP/HTTPS with rules, auth (Basic/Digest/LDAP), upstream chaining, FTP-over-HTTP gateway, WebSocket upgrade.
- **Reverse proxy** — route by Host/SNI/path/src_ip, TLS termination, TLS passthrough by SNI, retry, health checks, header rewrite, path rewrite (strip/add/regex), canary traffic splitting, request mirroring, HTTP/3 termination, function executor forwarding (`ipc:` routes).
- **Enterprise policy inputs** — trusted headers, mTLS subject mapping, signed JWS/JWT assertion verification, `ext_authz`, named sets/external feeds, and destination intelligence (`category` / `reputation` / `application`).
- **HTTP modules** — public in-process request/response module API for `listeners[].http_modules` and `reverse[].routes[].http_modules`, with built-in `response_compression` (`gzip` / `br` / `zstd`), internal subrequests, and first-class cache purge.
- **ACME / Let's Encrypt** — automatic certificate issuance/renewal (HTTP-01) for reverse TLS termination (`qpxd` feature `acme`, enabled by default; requires `tls-rustls`).
- **Function executor** — `qpxf` is a hardened executor for CGI scripts (path containment, concurrent I/O, size limits) and optional WASM modules via `qpx-wasm` (`wasmtime` with memory limits, epoch-based timeout). `qpxd` communicates with `qpxf` over the QPX-IPC protocol via reverse-route `ipc:` targets.
- **Transparent proxy** — Linux `SO_ORIGINAL_DST` or protocol metadata routing (SNI, Host), with optional TLS MITM inspection.
- **TLS inspection (MITM)** — dynamic per-connection certificate impersonation via built-in CA (requires `tls-rustls` build).
- **HTTP/3 (QUIC)** — build-time backend split. `http3-backend-h3` is the default upstream-`h3` backend for standard HTTP/3, CONNECT-UDP / MASQUE, and generic extended CONNECT. `http3-backend-qpx` enables the clean-room `qpx-h3` backend for the full QPX-owned advanced HTTP/3 surface, including CONNECT-UDP / MASQUE, generic extended CONNECT, and WebTransport relay (requires `tls-rustls`).
- **Caching** — RFC 9111 + RFC 5861 (`stale-while-revalidate`, `stale-if-error`) proxy cache with in-memory, Redis, and HTTP object-storage backends.
- **PCAPNG capture pipeline** — `qpxd` emits decrypted traffic events; `qpxr` writes PCAPNG; `qpxc` streams to Wireshark.
- **XDP / PROXY protocol** — PROXY v2 metadata for forwarding original client addresses from L4 frontends.
- **Observability** — structured logging, Prometheus metrics endpoint, optional OpenTelemetry tracing (OTLP/Jaeger).

## Build

qpx supports two TLS backends, selectable at build time:

- `tls-rustls` (default backend): required for HTTP/3 (`http3`) and TLS inspection (`mitm`).
- `tls-native`: uses `native-tls`/`tokio-native-tls` (HTTP/3 and TLS inspection are unavailable).

`qpxd` default features are `tls-rustls`, `http3-backend-h3`, `mitm`, `acme`, `digest-auth`, and `sha2-hash`. `http3` is now an internal umbrella feature that must be activated by exactly one backend selector: `http3-backend-h3` (default) or `http3-backend-qpx`. `acme` is isolated in `qpx-acme`, can be disabled independently, and still requires `tls-rustls` when enabled.

Choose the HTTP/3 backend by required behavior, not by listener YAML. Backend choice is build-time only.

- `http3-backend-h3`: choose this for standard HTTP/3 request/response, CONNECT-UDP / MASQUE datagram relay, chained upstream HTTP/3 proxying, and non-WebTransport extended CONNECT.
- `http3-backend-qpx`: choose this when you need the clean-room backend or the full QPX-owned advanced HTTP/3 surface. It covers buffered HTTP/3 request/response handling, reverse HTTP/3 terminate, CONNECT-UDP / MASQUE datagram relay, generic extended CONNECT, and WebTransport relay.
- Reverse HTTP/3 passthrough is backend-neutral. It stays in `qpxd` as raw UDP/QUIC session routing and works with either backend.

```bash
# Default workspace build. qpxd includes tls-rustls + http3-backend-h3 + mitm + acme.
cargo build --release

# Clean-room HTTP/3 backend with full advanced HTTP/3 coverage
cargo build --release -p qpxd --no-default-features --features tls-rustls,http3-backend-qpx

# Native TLS backend
cargo build --release -p qpxd --no-default-features --features tls-native
cargo build --release -p qpxr --no-default-features --features tls-native
cargo build --release -p qpxc --no-default-features --features tls-native

# Minimal build (no TLS backends)
cargo build --release -p qpxd --no-default-features
cargo build --release -p qpxr --no-default-features
cargo build --release -p qpxc --no-default-features
```

Current HTTP/3 backend split:

- `http3-backend-h3`: standard request/response, CONNECT, CONNECT-UDP / MASQUE datagram relay, chained upstream CONNECT-UDP, and non-WebTransport extended CONNECT.
- `http3-backend-qpx`: standard request/response, reverse terminate, CONNECT-UDP / MASQUE datagram relay, generic extended CONNECT, and WebTransport relay over extended CONNECT.
- `http3-backend-qpx` is the only backend that provides the full QPX-owned advanced HTTP/3 surface without relying on upstream `h3` behavior beyond its public API.

## Platform support

CI runs native build/test coverage on Linux, Windows, macOS Intel, and macOS Apple Silicon, and also preflights the release-target build matrix for Linux musl `x86_64` / `aarch64`, macOS `x86_64` / `aarch64`, and Windows `x86_64`. Release binaries are published for:

| Target | Notes |
|---|---|
| `x86_64-unknown-linux-musl` | Static musl binary |
| `aarch64-unknown-linux-musl` | Static musl binary |
| `x86_64-apple-darwin` | macOS Intel |
| `aarch64-apple-darwin` | macOS Apple Silicon |
| `x86_64-pc-windows-msvc` | Windows |

Other Unix systems (FreeBSD, etc.) are not tested and not guaranteed to work.

**Platform-specific behavior:**

- Transparent original-destination recovery uses Linux `SO_ORIGINAL_DST`; on non-Linux it falls back to TLS SNI / HTTP `Host` / PROXY metadata.
- Transparent proxy mode is practical only on Linux, where iptables/nftables can redirect traffic to the listener. macOS and Windows lack an equivalent redirection mechanism.
- `tls-native` builds depend on the platform TLS stack. Linux requires OpenSSL development headers (`libssl-dev` on Debian/Ubuntu, `openssl-devel` on RHEL/Fedora). The default `tls-rustls` build has no system dependencies.
- Redis cache `redis+unix://` endpoints require Unix domain sockets; on Windows use `redis://` or `rediss://`.

## CLI

```bash
# Run the proxy daemon
cargo run -p qpxd -- run --config config/qpx.example.yaml

# Validate config without starting listeners
cargo run -p qpxd -- check --config config/qpx.example.yaml

# Generate a CA key pair for TLS inspection
# Writes ca.crt and ca.key into the specified directory.
# (rustls backend only)
cargo run -p qpxd -- gen-ca --state-dir ~/.local/share/qpx
```

`run` and `check` accept one or more `--config` arguments. When multiple files are provided, they are merged in order and later files override earlier ones.

`check` loads and validates the merged config, including `include` resolution, environment expansion, unknown-key rejection, and reverse runtime compilation. Use it in CI or pre-deploy hooks.

## Capture pipeline

The capture pipeline consists of three components:

| Binary | Role |
|--------|------|
| `qpxd` (daemon) | Traffic processing and TLS termination/decryption; writes capture events to a shared-memory ring |
| `qpxr` (reader) | Reads the shared-memory ring written by `qpxd`, generates PCAPNG files, and serves live/history streams |
| `qpxc` (client) | Connects to `qpxr` and relays PCAPNG to Wireshark (extcap) or a simple packet viewer |

**Recommended topology:** `qpxd` and `qpxr` run on the same host; remote analysis machines connect via `qpxc` only.

```bash
# 1) Start the reader (reads the shared-memory capture ring, serves PCAPNG streams)
#    --shm-path and --shm-size-mb must match exporter.shm_path / exporter.shm_size_mb in qpxd config.
#    When omitted, both sides use the same platform-private default path
#    (for example $XDG_RUNTIME_DIR/qpx/capture.shm or ~/.qpx/run/capture.shm).
export QPX_EXPORTER_TOKEN='local-dev-token'
cargo run -p qpxr -- \
  --stream-listen 127.0.0.1:19101 \
  --token-env QPX_EXPORTER_TOKEN \
  --save-dir /tmp/qpx-pcapng

# 2) Start the daemon (writes capture events to the SHM ring)
cargo run -p qpxd -- run --config config/usecases/07-observability-debug/observability-high-detail.yaml

# 3) Stream via client (also usable as a Wireshark extcap FIFO)
cargo run -p qpxc -- \
  --endpoint 127.0.0.1:19101 --mode live \
  --token-env QPX_EXPORTER_TOKEN \
  > /tmp/qpx-live.pcapng
```

### Capture security profiles

- **Local debug:** Loopback bind with `--token-env` (as shown above).
- **Low-security lab use:** Loopback bind without auth only when `--unsafe-allow-insecure` is explicitly passed.
- **Production (recommended):** Start `qpxr` with TLS + token (optionally mTLS + allowlist); connect `qpxc` with the same credentials.
  - `qpxr` **refuses** unauthenticated loopback listeners and **refuses** non-loopback listeners without TLS unless `--unsafe-allow-insecure` is explicitly passed.

**Example (TLS + token + allowlist):**

```bash
export QPX_EXPORTER_TOKEN='...'

# Reader (server)
cargo run -p qpxr -- \
  --stream-listen 0.0.0.0:19101 \
  --tls-cert /etc/qpxr/tls/server.crt --tls-key /etc/qpxr/tls/server.key \
  --token-env QPX_EXPORTER_TOKEN \
  --stream-allow 10.0.0.0/8

# Client
cargo run -p qpxc -- \
  --endpoint qpxr.example.internal:19101 --mode follow \
  --tls --tls-server-name qpxr.example.internal \
  --token-env QPX_EXPORTER_TOKEN \
  > /tmp/qpx-live.pcapng
```

For `tls-native` builds, use `qpxr --tls-pkcs12` and `qpxc --tls-client-pkcs12` instead of PEM `--tls-cert/--tls-key` and `--tls-client-cert/--tls-client-key`.

**`qpxd` exporter config (`exporter:`):**

```yaml
exporter:
  enabled: true
  shm_path: ""        # SHM file path. Empty = platform-private default path.
  shm_size_mb: 16     # Must match qpxr --shm-size-mb (default: 16).
  lossy: false        # true = drop events when ring is full; false = block with backpressure.
  max_queue_events: 4096
  capture:
    plaintext: true
    encrypted: true
    max_chunk_bytes: 16384
```

`qpxr` reads the same ring using `--shm-path` / `--shm-size-mb` (both default to the same values). When running `qpxd` and `qpxr` on the same host with default paths, no explicit path configuration is needed.

## Function executor (`qpxf`)

`qpxf` is a hardened function executor that runs alongside `qpxd`. `qpxd` routes requests to `qpxf` over the QPX-IPC protocol with reverse routes that set `ipc:`. `qpxf` owns the IPC server, routing, and CGI process management; its optional WASM runtime lives in the separate `qpx-wasm` crate behind the `wasm` feature.

For local deployments, `qpxf` defaults to a user-scoped `unix://` socket. Any TCP listener, including loopback, requires `allow_insecure_tcp=true`.

`qpxf` supports two execution backends:

| Backend | Description |
|---------|-------------|
| CGI scripts | Spawns external processes (RFC 3875). Path containment, symlink-escape prevention, concurrent I/O with deadlock prevention, configurable size limits. |
| WASM modules | Executes WASI-compatible modules via `qpx-wasm` (`wasmtime` + `wasmtime-wasi`). Module/stdin/stdout/stderr size caps, memory limits via `ResourceLimiter`, request wall-clock timeout, and stderr capture. |

The default `qpxf` build enables the `wasm` feature, which pulls in `qpx-wasm`. Use `cargo build -p qpxf --no-default-features` for a CGI-only build.

For `ipc:` routes, `ipc.mode` controls how request/response bodies are transferred:

| `ipc.mode` | Body transfer | When to use |
|--------------------|--------------|-------------|
| `shm` (default) | shared-memory ring buffer | `qpxd` and `qpxf` on the same host |
| `tcp` | streamed over the connection | cross-host or non-Unix deployments |

```yaml
# reverse route config in qpxd
routes:
  - match: { path: ["/cgi-bin/*"] }
    ipc:
      mode: shm          # "shm" (default) or "tcp"
      address: "${QPXF_UNIX_LISTEN}"
      timeout_ms: 30000
```

```bash
# Validate the paired qpxf sample, including CGI/WASM handler initialization
cargo run -p qpxf -- check --config config/usecases/12-ipc-gateway/qpxf.yaml

# Start the executor (Unix sockets are the default and recommended transport)
qpxf_runtime="${XDG_RUNTIME_DIR:-$HOME/.qpx/run}"
install -d -m 700 "$qpxf_runtime"
export QPXF_UNIX_LISTEN="unix://$qpxf_runtime/qpxf.sock"
cargo run -p qpxf -- --listen "$QPXF_UNIX_LISTEN" --config config/usecases/12-ipc-gateway/qpxf.yaml

# Start qpxd routed to it
cargo run -p qpxd -- run --config config/usecases/12-ipc-gateway/qpx.yaml
```

The `12-ipc-gateway` sample pair ships with repo-local CGI/WASM fixture handlers so the sample can be checked and smoke-tested as-is. Override `QPXF_SAMPLE_CGI_ROOT` / `QPXF_SAMPLE_WASM_MODULE` to point at your own handlers.

See `config/usecases/12-ipc-gateway/` for sample configs.

## Configuration

- **Canonical samples** (use-case oriented): `config/usecases/`
- **Shared fragments** for include composition: `config/fragments/`
- **Full index and usage guidance**: [`config/README.md`](config/README.md)
- **Full example config**: [`config/qpx.example.yaml`](config/qpx.example.yaml)

The YAML schema is flat and matches `qpx_core::config::types::*` directly. Write top-level sections such as `system_log`, `access_log`, `audit_log`, `metrics`, `otel`, `auth`, `identity_sources`, `ext_authz`, and `named_sets` directly, and express reverse-route targets as `upstreams`, `backends`, `ipc`, or `local_response`.

Two control-plane surfaces matter for the current schema:

- Transport-aware shaping uses `rate_limit` / `rate_limit_profiles` with `apply_to`, `requests`, `traffic`, and `sessions`. This is the canonical surface for request, CONNECT, UDP, HTTP/3 datagram, and WebTransport shaping; WebTransport can be scoped at `webtransport`, `webtransport_bidi`, `webtransport_uni`, `webtransport_datagram`, or the `*_downstream` / `*_upstream` variants for direction-specific traffic/quota control.
- Response-stage HTTP policy uses `listeners[].http.response_rules` and `reverse[].routes[].http.response_rules`. Reverse route retry/ejection/concurrency policy is expressed with `reverse[].routes[].resilience`.
- RPC-aware policy is part of the same rule surface. `match.rpc.*` and `action.local_response.rpc` cover `gRPC`, `Connect`, and `gRPC-Web` without a separate protocol-specific config tree.

> **Security note:** Forward and transparent samples default to `default_action: block` to prevent accidental open-proxy deployments. Explicit exceptions are `*-local-dev-direct.yaml` and `config/usecases/99-test-fixtures/*` (loopback-only dev/test profiles).

### Include composition

Configs can compose shared fragments via `include`:

```yaml
include:
  - config/fragments/base-observability.yaml
  - config/fragments/forward-listener.yaml
```

Included files are merged depth-first. The main config's values take precedence over included values.
When multiple top-level `--config` files are passed to `qpxd`, they are merged in the same way and later files win.

### Reverse route target forms

Reverse routes use exactly one of these shapes:

- `upstreams` / `backends[].upstreams` with literal `http://` / `https://` / `ws://` / `wss://` URLs
- `upstreams` / `backends[].upstreams` with names from top-level `upstreams`
- `ipc` for QPX-IPC forwarding to `qpxf`
- route-level `local_response`

### Connection filters

`connection_filter` is a separate early-drop surface on both `listeners[]` and `reverse[]`.

- It runs before full HTTP parsing and can reject unwanted traffic at accept time or, when TLS/QUIC metadata is available, at ClientHello time.
- `connection_filter` requires `match:` and only accepts `action.type: block`.
- It is intentionally limited to low-cost transport/TLS inputs such as `src_ip`, `dst_port`, `sni`, `alpn`, `tls_version`, and `tls_fingerprint.ja3` / `tls_fingerprint.ja4`.
- It does not accept higher-level HTTP matchers such as `host`, `method`, `path`, `headers`, `identity`, request/response sizes, or destination-intelligence fields.
- Drops emit audit event `connection_filter_drop`.

See [`config/usecases/08-performance-and-xdp/connection-filter-early-drop.yaml`](config/usecases/08-performance-and-xdp/connection-filter-early-drop.yaml) and [`config/qpx.example.yaml`](config/qpx.example.yaml).

### Destination resolution

Destination intelligence arbitration is configured once and then optionally overridden by scope:

- `destination_resolution.defaults`
- `listeners[].destination_resolution`
- `reverse[].destination_resolution`
- `reverse[].routes[].destination_resolution`

Use it to define evidence precedence (`cert` / `sni` / `host` / `ip` / `tls_fingerprint` / `heuristic`), conflict handling, merge mode, and minimum confidence thresholds for category / reputation / application classification.

See [`config/usecases/02-secure-egress/forward-destination-intelligence-and-trust.yaml`](config/usecases/02-secure-egress/forward-destination-intelligence-and-trust.yaml).

### HTTP guard profiles

`http_guard_profiles` is the lightweight request-hardening surface for bounded parser work and protocol safety.

- Define reusable profiles at top level.
- Attach them with `listeners[].http_guard_profile` or `reverse[].routes[].http_guard_profile`.
- The current runtime enforces path/query/header/body limits, JSON depth / field count, multipart part/name/file limits, and basic smuggling / invalid-framing checks.

See [`config/usecases/03-service-publishing/reverse-http-guard-lite.yaml`](config/usecases/03-service-publishing/reverse-http-guard-lite.yaml) and [`config/qpx.example.yaml`](config/qpx.example.yaml).

### RPC-aware policy

`gRPC`, `Connect`, and `gRPC-Web` are matched through the shared `match.rpc.*` surface on request rules and `http.response_rules`.

- `match.rpc.protocol` selects `grpc`, `connect`, or `grpc_web`.
- `match.rpc.service` / `match.rpc.method` use the canonical `/Service/Method` path split.
- `match.rpc.status`, `match.rpc.message`, `match.rpc.message_size`, and `match.rpc.trailers` apply on the response stage.
- `action.local_response.rpc` emits protocol-correct local replies for the same three protocols.

See [`config/usecases/03-service-publishing/reverse-rpc-aware-policy.yaml`](config/usecases/03-service-publishing/reverse-rpc-aware-policy.yaml).

### HTTP modules

HTTP request/response modules are configured directly in YAML:

- `listeners[].http_modules` applies to forward, transparent HTTP, and MITM HTTP paths.
- `reverse[].routes[].http_modules` applies per reverse route.

Built-in modules:

- `response_compression`: downstream response compression for `gzip`, `br`, and `zstd`. Use `min_body_bytes`, `max_body_bytes`, `content_types`, and per-algorithm levels (`gzip_level`, `brotli_level`, `zstd_level`) to tune when and how compression runs. Compression happens after cache writeback, so cached objects remain identity-encoded while clients receive compressed responses when `Accept-Encoding` allows it.
- `subrequest`: internal absolute-URL subrequest at `request_headers` or `response_headers` phase. Use `pass_headers`, `request_headers`, `copy_response_headers_to_request`, `copy_response_headers_to_response`, and `response_mode` to shape what the sidecar call sees and how its result feeds back into the main transaction.
- `cache_purge`: first-class HTTP purge endpoint for the configured cache key. Use `methods`, `response_status`, `response_body`, and `response_headers` to tailor the purge endpoint response. Requires `cache.enabled: true` on the listener or reverse route where it is used.

Every module spec also accepts:

- `id`: stable operator label for logs and debugging.
- `order`: execution order; lower numbers run earlier.

Custom in-process modules:

- `qpxd` is now a library as well as a daemon binary. External Rust binaries can register custom module factories and then run the normal CLI/event loop.
- Config is open by `type:`. `qpx-core` loads unknown module types without rejecting them, and `qpxd` resolves them against the runtime registry.
- Public API surface is `qpxd::Daemon::builder()` plus `qpxd::module_api::{HttpModuleFactory, HttpModule, HttpModuleContext, HttpModuleRequestView, Body}`.
- Request hooks are borrowed/in-place: `on_request_headers(&mut Request<Body>)` and `on_upstream_request(&mut Request<Body>)`. Response-phase hooks can read the frozen request view from `HttpModuleContext::frozen_request()`.

Minimal example:

```rust
use anyhow::Result;
use async_trait::async_trait;
use qpxd::module_api::{Body, HttpModule, HttpModuleContext, HttpModuleFactory};
use qpxd::{Daemon, HttpModuleConfig};
use hyper::Response;
use std::sync::Arc;

#[derive(serde::Deserialize)]
struct AddHeaderConfig {
    header_name: String,
    header_value: String,
}

struct AddHeaderFactory;
struct AddHeader {
    name: http::HeaderName,
    value: http::HeaderValue,
}

impl HttpModuleFactory for AddHeaderFactory {
    fn build(&self, spec: &HttpModuleConfig) -> Result<Arc<dyn HttpModule>> {
        let cfg: AddHeaderConfig = spec.parse_settings()?;
        Ok(Arc::new(AddHeader {
            name: cfg.header_name.parse()?,
            value: cfg.header_value.parse()?,
        }))
    }
}

#[async_trait]
impl HttpModule for AddHeader {
    async fn on_downstream_response(
        &self,
        _ctx: &mut HttpModuleContext,
        mut response: Response<Body>,
    ) -> Result<Response<Body>> {
        response.headers_mut().insert(self.name.clone(), self.value.clone());
        Ok(response)
    }
}

fn main() -> Result<()> {
    Daemon::builder()
        .register_http_module("add_header", AddHeaderFactory)?
        .build()
        .run_cli()
}
```

Example:

```yaml
listeners:
  - name: forward
    mode: forward
    listen: 127.0.0.1:18080
    default_action: { type: direct }
    cache:
      enabled: true
      backend: edge-cache
    http_modules:
      - type: cache_purge
      - type: response_compression
        min_body_bytes: 512
        gzip: true
        brotli: true
        zstd: true

reverse:
  - name: api
    listen: 127.0.0.1:18443
    routes:
      - match:
          host: [api.example.com]
        upstreams:
          - https://127.0.0.1:9443
        http_modules:
          - type: subrequest
            name: authz
            phase: request_headers
            url: http://127.0.0.1:19091/check?path={request.path}
            response_mode: return_on_error
```

See [`config/usecases/07-observability-debug/http-modules-advanced.yaml`](config/usecases/07-observability-debug/http-modules-advanced.yaml) and [`config/qpx.example.yaml`](config/qpx.example.yaml) for a fuller built-in-module sample with `id`, `order`, compression tuning, subrequest header capture, and cache purge response customization.

### Environment variable substitution

All string values support `${VAR}` and `${VAR:-default}` expansion at load time. Use this for credentials, hostnames, and environment-specific paths:

```yaml
state_dir: "${QPX_STATE_DIR:-/var/lib/qpx}"

metrics:
  listen: "${QPX_METRICS_LISTEN:-127.0.0.1:9901}"

reverse:
  - name: edge
    listen: "${QPX_REVERSE_LISTEN:-127.0.0.1:8443}"
    tls:
      certificates:
        - sni: "app.example.com"
          cert: "${QPX_TLS_CERT:-/etc/qpx/tls/server.crt}"
          key: "${QPX_TLS_KEY:-/etc/qpx/tls/server.key}"
```

### Hot reload

`qpxd` watches every configured `--config` file, all resolved `include` targets, and any `named_sets[].file` inputs. On compatible changes it rebuilds the in-memory runtime state in place. When listener/reverse bind shape or acceptor startup settings change, it gracefully stops the old accept loops and restarts the listener/reverse server set in-process instead of requiring a full daemon restart.

The repo keeps both hot-reload paths under CI:

- `scripts/e2e-control-plane.sh` exercises in-place reload and listener/reverse server-set restart on Linux CI.
- `scripts/e2e-control-plane.ps1` exercises the same reload behavior on Windows CI.
- `scripts/e2e-control-plane-soak.sh` keeps loopback traffic flowing while reload, restart-required reload, and binary upgrade happen on Linux CI.

Reload constraints:
- Restart is required for `state_dir`, `system_log`, `access_log`, `audit_log`, `acme`, `otel`, `metrics`, or `identity.metrics_prefix` changes.
- Process runtime sizing still requires restart: `worker_threads` and `max_blocking_threads`.
- Listener/reverse startup changes trigger an in-process server-set restart: `acceptor_tasks_per_listener`, `reuse_port`, `tcp_backlog`, listener names/listen addresses/mode/XDP/HTTP3 settings, and reverse names/listen addresses/TLS or HTTP/3 startup settings.
- Existing accepted TCP connections continue draining on the old runtime generation while the replacement listener/reverse set starts with the new config.

### Binary upgrade

`qpxd` supports zero-downtime binary replacement for the listener socket layer.

- On Unix, send `SIGUSR2` to the parent process.
- On Windows, run `qpxd upgrade --pid <parent-pid>`.

The parent process will:

- hand the active TCP listening sockets for forward listeners, transparent listeners, reverse TCP listeners, `metrics.listen`, and ACME `http01_listen` to the child
- hand the active UDP listening sockets for forward HTTP/3, reverse HTTP/3, and transparent UDP/QUIC listeners to the child
- spawn the same executable with the same CLI args and wait until the child signals readiness
- stop accepting new TCP connections in the parent and drain already accepted TCP sessions before exit

Notes:
- This is a binary handoff path, not a config reload path. Use normal file-watching reload for compatible config edits.
- Existing TCP sessions stay on the old generation; new TCP accepts move to the child after readiness.
- UDP/QUIC listener sockets are inherited by the child as well, so binary replacement no longer depends on rebinding those ports.
- Existing transparent UDP sessions and reverse HTTP/3 passthrough sessions are exported to the child together with their connected upstream UDP sockets, so those flows continue on the replacement process without reopening the upstream path.
- Forward HTTP/3 sessions and reverse HTTP/3 terminate sessions stay on the parent generation behind a parent-child QUIC broker. The child receives new QUIC handshakes immediately after readiness, while established QUIC sessions continue draining on the old generation until it exits.
- To keep broker routing deterministic during the handoff window, server-side QUIC active migration is disabled on HTTP/3 listeners.
- Unix uses inherited file descriptors for TCP/UDP listeners and QUIC broker control sockets.
- Windows uses `WSADuplicateSocketW` manifests for TCP/UDP listener and live UDP session handoff, plus loopback TCP rendezvous for readiness and QUIC broker control.
- `scripts/e2e-control-plane.sh` exercises the Unix `qpxd upgrade --pid <parent-pid>` handoff path end-to-end on CI Linux.
- `scripts/e2e-control-plane.ps1` exercises the Windows `qpxd upgrade --pid <parent-pid>` handoff path end-to-end on CI.
- `scripts/e2e-control-plane-soak.sh` verifies that live loopback traffic survives reload/restart/upgrade sequencing without failed requests.

### Continuous Security QA

The repo's CI keeps several security-focused gates beyond normal unit/integration testing:

- CodeQL analyzes both GitHub Actions and Rust sources.
- `security-qa.yml` runs AddressSanitizer smoke on shared-memory ring and upgrade readiness code paths.
- `security-qa.yml` also runs short `cargo-fuzz` jobs for shared-memory ring operations, PROXY v2 parsing, HTTP/1 request-head parsing, QPACK decoding, and TLS ClientHello sniffing.

### Trusted Identity And External Authz

Enterprise deployments can bind trusted identity sources and external authorization through `policy_context` on listeners, reverse proxies, and reverse routes:

```yaml
policy_context:
  identity_sources: ["corp-access-proxy"]
  ext_authz: central-policy
```

See [`config/usecases/02-secure-egress/forward-trusted-identity-ext-authz.yaml`](config/usecases/02-secure-egress/forward-trusted-identity-ext-authz.yaml), [`config/qpx.example.yaml`](config/qpx.example.yaml), and [`docs/enterprise-edge-scope.md`](docs/enterprise-edge-scope.md) for the full model.

`identity_sources[].type: signed_assertion` verifies JWS/JWT style assertions locally with `assertion.secret_env` or `assertion.public_key_env` and maps claims into `user`, `groups`, `device_id`, `tenant`, `auth_strength`, and `idp`. `ext_authz` allow responses share the same decision surface across forward, reverse, transparent, and MITM paths, including `override_upstream`, `timeout_override_ms`, `cache_bypass`, `mirror_upstreams`, `rate_limit_profile`, `force_inspect`, `force_tunnel`, and `policy_tags`; `timeout_ms` covers both response headers and body, and `max_response_bytes` caps the authorization response body before JSON parsing.

Built-in auth and identity mapping also expose a few advanced knobs that are easy to miss:

- `auth.users[].ha1` accepts a precomputed SHA-256 Digest HA1, so you can enable Digest auth without storing a cleartext password.
- `auth.ldap` supports `user_filter`, `group_filter`, and `group_attr` when you need to align LDAP lookup shape with your directory schema.
- `identity_sources[].type: mtls_subject` can derive the user from `map.user_from_san_uri_prefix` and/or `map.user_from_subject_cn`.
- `identity_sources[].type: signed_assertion` can derive the user from `sub` with `assertion.claims.user_from_sub`, and can split packed group claims with `assertion.claims.groups_separator`.

Destination intelligence is driven by `named_sets` plus host, destination IP, SNI, ALPN, TLS fingerprint, and upstream certificate metadata. Prefix set names with `category:`, `reputation:`, or `application:` and match them later with `destination.category`, `destination.reputation`, or `destination.application`, using each dimension's `value`, `source`, and `confidence` fields when you need to distinguish host-driven vs heuristic-derived classifications.

Advanced rule matchers also include `http_version`, `tls_version`, `tls_fingerprint`, `request_size`, `response_size`, `upstream_cert`, and, on reverse TLS-terminated requests, `client_cert`.

Upstream trust is configurable per chained upstream, reverse route, and transparent TLS inspection path with `tls_trust` / `upstream_trust`. Policy supports pinning (`pin_sha256`), issuer and SAN constraints, and per-upstream mTLS client certificate selection via `client_cert` / `client_key`.

See [`config/usecases/02-secure-egress/forward-local-auth-basic-digest.yaml`](config/usecases/02-secure-egress/forward-local-auth-basic-digest.yaml), [`config/usecases/02-secure-egress/forward-ldap-group-policy.yaml`](config/usecases/02-secure-egress/forward-ldap-group-policy.yaml), [`config/usecases/02-secure-egress/forward-signed-assertion-policy.yaml`](config/usecases/02-secure-egress/forward-signed-assertion-policy.yaml), [`config/usecases/02-secure-egress/forward-destination-intelligence-and-trust.yaml`](config/usecases/02-secure-egress/forward-destination-intelligence-and-trust.yaml), [`config/usecases/03-service-publishing/reverse-mtls-identity-routing.yaml`](config/usecases/03-service-publishing/reverse-mtls-identity-routing.yaml), and [`config/qpx.example.yaml`](config/qpx.example.yaml).

### Local response policy

```yaml
listeners:
  - name: forward
    mode: forward
    listen: "127.0.0.1:8080"
    default_action: { type: direct }
    rules:
      - name: block-ads
        match:
          host: ["*.doubleclick.net", "*.googlesyndication.com"]
        action:
          type: respond
          local_response:
            status: 403
            content_type: "text/plain; charset=utf-8"
            body: "blocked by policy"
```

See also: `config/usecases/06-local-response/`

## End-to-end tests

```bash
cargo build -p qpxd
./scripts/e2e-config-samples.sh
./scripts/e2e-http2.sh
./scripts/e2e-local-response.sh
```

**Operational helper:**

- `scripts/irq-affinity-plan.sh` — Linux IRQ/CPU affinity planner for NIC queue distribution (see [`docs/multicore-xdp-scaling.md`](docs/multicore-xdp-scaling.md))

## Documentation

- [`config/README.md`](config/README.md) — configuration sample index and usage guide
- [`docs/code-structure.md`](docs/code-structure.md) — source-level module index
- [`docs/enterprise-edge-scope.md`](docs/enterprise-edge-scope.md) — product boundary and enterprise cloud edge positioning
- [`docs/interoperability-matrix.md`](docs/interoperability-matrix.md) — protocol interoperability and release benchmark lanes
- [`docs/rfc911x-compliance.md`](docs/rfc911x-compliance.md) — RFC compliance notes and verification
- [`docs/local-response-and-routing.md`](docs/local-response-and-routing.md) — local response and routing guide
- [`docs/multicore-xdp-scaling.md`](docs/multicore-xdp-scaling.md) — multicore and XDP scaling guide
- [`docs/usecase-inventory.md`](docs/usecase-inventory.md) — `config/usecases/` capability inventory

## Operational notes

<details>
<summary>Transparent mode</summary>

- Linux uses `SO_ORIGINAL_DST`; macOS/Windows fall back to protocol metadata routing (TLS SNI for HTTPS, `Host` header for HTTP).
- The transparent path applies L7 rules for HTTP and supports opt-in TLS MITM for HTTPS flows.
- `xdp.metadata_mode: proxy-v2` allows transparent destination recovery from PROXY metadata (useful with XDP/L4 frontends).

</details>

<details>
<summary>RFC alignment hardening</summary>

- Host/authority validation enforced (duplicate/missing/mismatch rejected with `400`).
- No-body response rules enforced for `HEAD`, `1xx`, `204`, `304`, and successful `CONNECT`.
- `Via` is version-aware (`1.1`, `2`, `3`) per proxied hop.
- Reverse TLS enforces SNI vs Host/authority match by default (`enforce_sni_host_match: true`).
- `Proxy-Authorization`, `Proxy-Authenticate`, and `Proxy-Authentication-Info` are stripped from forwarded hops.
- QUIC 0-RTT is disabled by default in HTTP/3 listeners.

</details>

<details>
<summary>XDP metadata integration</summary>

- Forward/reverse/transparent listeners can consume PROXY v2 metadata (`xdp.enabled: true`, `metadata_mode: proxy-v2`).
- Source address metadata is used for rule evaluation (`src_ip`) on forward listeners.
- Reverse route matcher supports `src_ip` / `dst_port` / `host` / `sni` / `method` / `path` / `headers`.
- When `xdp.enabled: true`, `trusted_peers` is required and metadata is accepted only from trusted peer CIDRs.

</details>

<details>
<summary>Runtime multicore scaling</summary>

- `runtime.worker_threads` and `runtime.max_blocking_threads` tune Tokio parallelism.
- `runtime.max_ftp_concurrency` caps concurrent FTP-over-HTTP operations.
- `runtime.acceptor_tasks_per_listener` + `runtime.reuse_port` enable multi-socket accept fan-out.
- `runtime.tcp_backlog` controls listen queue depth.
- `runtime.max_h3_streams_per_connection` caps concurrent HTTP/3 streams and associated WebTransport sessions per QUIC connection.
- `runtime.upstream_http_timeout_ms` is the default dial/request timeout for upstream HTTP and reverse route proxying.
- `runtime.max_h3_request_body_bytes` / `runtime.max_h3_response_body_bytes` bound HTTP/3 body buffering.
- `runtime.max_observed_request_body_bytes` / `runtime.max_observed_response_body_bytes` are hard caps for policy, guard, RPC, and response-rule body observation before buffering.
- `runtime.trace_enabled` controls whether local `TRACE` loop-back handling is available at all.
- `runtime.trace_reflect_all_headers` controls whether `TRACE` loop-back reflects every request header or uses the safer default that strips hop-by-hop, auth, forwarding, and tracing headers.

</details>

<details>
<summary>Metrics, identity, and messages</summary>

- **Metrics:** `metrics.listen` and `metrics.path` configure the Prometheus scrape endpoint. Non-loopback binding requires explicit `metrics.allow` CIDR allowlist.
- **Identity:** `identity.proxy_name` (Via hop entries), `identity.auth_realm` (auth challenges), `identity.metrics_prefix` (metric name prefix), `identity.generated_user_agent` (User-Agent for proxy-originated requests).
- **Messages:** `messages.*` controls fixed response bodies for policy/error paths (e.g., `blocked`, `forbidden`, proxy errors, cache miss, FTP method errors).

</details>

<details>
<summary>WebSocket and header control</summary>

- Forward proxy and transparent HTTP path support WebSocket upgrade proxying (`101` + upgraded stream tunnel).
- Header control applies to both request and response headers in forward and transparent modes.
- Request headers (including `User-Agent`) can be explicitly set/add/remove/regex-rewritten via rule `headers`.
- `respond` + `local_response` can return policy pages directly without forwarding upstream.

</details>

## License

[MIT](LICENSE)

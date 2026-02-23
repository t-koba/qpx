# qpx

Quick HTTP proxy and server in Rust. Supports forward, reverse, and transparent proxy modes with HTTP/1.1, HTTP/2, HTTP/3, TLS inspection (MITM), and a function executor for CGI scripts and WASM modules.

## Features

- **Forward proxy** — HTTP/HTTPS with rules, auth (Basic/Digest/LDAP), upstream chaining, FTP-over-HTTP gateway, WebSocket upgrade.
- **Reverse proxy** — route by Host/SNI/path/src_ip, TLS termination, TLS passthrough by SNI, retry, health checks, header rewrite, path rewrite (strip/add/regex), canary traffic splitting, request mirroring, HTTP/3 termination, function executor forwarding (`ipc:` routes).
- **ACME / Let's Encrypt** — automatic certificate issuance/renewal (HTTP-01) for reverse TLS termination (requires `tls-rustls` build).
- **Function executor** — `qpxf` is a hardened executor for CGI scripts (path containment, concurrent I/O, size limits) and WASM modules (via `wasmtime` with memory limits, epoch-based timeout). `qpxd` communicates with `qpxf` over the QPX-IPC protocol via `ipc:` reverse route config (recommended) or `ipc://` upstream URLs (TCP/Unix).
- **Transparent proxy** — Linux `SO_ORIGINAL_DST` or protocol metadata routing (SNI, Host), with optional TLS MITM inspection.
- **TLS inspection (MITM)** — dynamic per-connection certificate impersonation via built-in CA (requires `tls-rustls` build).
- **HTTP/3 (QUIC)** — forward and reverse listeners. CONNECT-UDP / MASQUE support (requires `tls-rustls` build).
- **Caching** — RFC 9111 (safe subset) + RFC 5861 (`stale-while-revalidate`, `stale-if-error`) proxy cache with in-memory, Redis, and HTTP object-storage backends.
- **PCAPNG capture pipeline** — `qpxd` emits decrypted traffic events; `qpxr` writes PCAPNG; `qpxc` streams to Wireshark.
- **XDP / PROXY protocol** — PROXY v2 metadata for forwarding original client addresses from L4 frontends.
- **Observability** — structured logging, Prometheus metrics endpoint, optional OpenTelemetry tracing (OTLP/Jaeger).

## Build

qpx supports two TLS backends, selectable at build time:

- `tls-rustls` (default backend): required for HTTP/3 (`http3`) and TLS inspection (`mitm`).
- `tls-native`: uses `native-tls`/`tokio-native-tls` (HTTP/3 and TLS inspection are unavailable).

```bash
# Default (rustls backend)
cargo build --release

# Native TLS backend
cargo build --release -p qpxd --no-default-features --features tls-native
cargo build --release -p qpxr --no-default-features --features tls-native
cargo build --release -p qpxc --no-default-features --features tls-native

# Minimal build (no TLS backends)
cargo build --release -p qpxd --no-default-features
cargo build --release -p qpxr --no-default-features
cargo build --release -p qpxc --no-default-features
```

## Platform support

CI builds and tests run on Linux, macOS, and Windows (x86_64 and aarch64). Release binaries are published for:

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

`check` loads and validates the config (including `include` resolution and `envsubst` expansion) and exits. Use it in CI or pre-deploy hooks.

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
#    When omitted, both sides use the same platform default path (temp_dir/qpx/capture.shm).
cargo run -p qpxr -- \
  --stream-listen 127.0.0.1:19101 \
  --save-dir /tmp/qpx-pcapng

# 2) Start the daemon (writes capture events to the SHM ring)
cargo run -p qpxd -- run --config config/usecases/07-observability-debug/observability-high-detail.yaml

# 3) Stream via client (also usable as a Wireshark extcap FIFO)
cargo run -p qpxc -- \
  --endpoint 127.0.0.1:19101 --mode live > /tmp/qpx-live.pcapng
```

### Capture security profiles

- **Local debug (low security):** Loopback bind, no TLS, no token (as shown above).
- **Production (recommended):** Start `qpxr` with TLS + token (optionally mTLS + allowlist); connect `qpxc` with the same credentials.
  - `qpxr` **refuses** non-loopback listeners without TLS unless `--unsafe-allow-insecure` is explicitly passed.

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
  shm_path: ""        # SHM file path. Empty = platform default (temp_dir/qpx/capture.shm).
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

`qpxf` is a hardened function executor that runs alongside `qpxd`. `qpxd` routes requests to `qpxf` over the QPX-IPC protocol — a lightweight JSON-framed protocol. Route to `qpxf` using an `ipc:` reverse route config (recommended) or an `ipc://` upstream URL.

`qpxf` supports two execution backends:

| Backend | Description |
|---------|-------------|
| CGI scripts | Spawns external processes (RFC 3875). Path containment, symlink-escape prevention, concurrent I/O with deadlock prevention, configurable size limits. |
| WASM modules | Executes WASI-compatible modules via `wasmtime`. Memory limits via `ResourceLimiter`, epoch-based timeout, stderr captured and logged. |

The `ipc.mode` field controls how request/response bodies are transferred:

| `ipc.mode` | Body transfer | When to use |
|------------|--------------|-------------|
| `shm` (default) | shared-memory ring buffer | `qpxd` and `qpxf` on the same host |
| `tcp` | streamed over the connection | cross-host or non-Unix deployments |

```yaml
# reverse route config in qpxd
routes:
  - match: { path: ["/cgi-bin/*"] }
    ipc:
      mode: shm          # "shm" (default) or "tcp"
      address: "127.0.0.1:9000"
      timeout_ms: 30000
```

```bash
# Start the executor (Unix socket, or a plain TCP address like "127.0.0.1:9000")
cargo run -p qpxf -- --listen unix:///run/qpxf/qpxf.sock --config config/usecases/12-ipc-gateway/qpxf.yaml

# Start qpxd routed to it
cargo run -p qpxd -- run --config config/usecases/12-ipc-gateway/qpx.yaml
```

See `config/usecases/12-ipc-gateway/` for sample configs.

## Configuration

- **Canonical samples** (use-case oriented): `config/usecases/`
- **Shared fragments** for include composition: `config/fragments/`
- **Full index and usage guidance**: [`config/README.md`](config/README.md)
- **Full example config**: [`config/qpx.example.yaml`](config/qpx.example.yaml)

> **Security note:** Forward and transparent samples default to `default_action: block` to prevent accidental open-proxy deployments. Explicit exceptions are `*-local-dev-direct.yaml` and `config/usecases/99-test-fixtures/*` (loopback-only dev/test profiles).

### Include composition

Configs can compose shared fragments via `include`:

```yaml
include:
  - config/fragments/base-observability.yaml
  - config/fragments/forward-listener.yaml
```

Included files are merged depth-first. The main config's values take precedence over included values.

### Environment variable substitution

All string values support `${VAR}` and `${VAR:-default}` expansion at load time. Use this for credentials, hostnames, and environment-specific paths:

```yaml
auth:
  token_env: "${QPX_EXPORTER_TOKEN}"
tls:
  ca_cert: "${TLS_CA_PATH:-/etc/qpxr/tls/ca.crt}"
```

### Hot reload

`qpxd` watches the config file and all `include` targets for changes. On modification it reloads rules, auth, cache (including RFC 5861 behavior), identity/messages, exporter, and reverse routing/LB/health/security settings without restarting.

Reload constraints:
- Listener and reverse section **topology** (names, modes, listen addresses) must not change — topology changes are rejected and the old config is kept.
- Runtime thread pool settings (`worker_threads`, `max_blocking_threads`, etc.) are not reloaded.
- Observability outputs (logging/metrics/OTel) are not reloaded.

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
- [`docs/rfc911x-compliance.md`](docs/rfc911x-compliance.md) — RFC compliance notes and verification
- [`docs/local-response-and-routing.md`](docs/local-response-and-routing.md) — local response and routing guide
- [`docs/multicore-xdp-scaling.md`](docs/multicore-xdp-scaling.md) — multicore and XDP scaling guide

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
- `runtime.max_h3_request_body_bytes` / `runtime.max_h3_response_body_bytes` bound HTTP/3 body buffering.

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

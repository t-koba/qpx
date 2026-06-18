# qpx

Quick HTTP proxy and server in Rust. qpx supports forward, reverse, and
transparent proxy modes with HTTP/1.1, HTTP/2, HTTP/3, TLS inspection, caching,
policy enforcement, observability, PCAPNG capture, and a separate function
executor for CGI / WASM / FastCGI / SCGI workloads.

qpx is a traffic-processing edge and policy enforcement point. In production,
identity should normally arrive from an external IdP, mTLS gateway, signed
assertion, or `ext_authz`; qpx enforces policy from that trusted context.
Built-in Basic/Digest/LDAP auth is kept for labs, small deployments, and local
edge use.

qpx is a policy enforcement point, protocol gateway, and observability edge. It is not intended to be the primary enterprise authentication authority: production identity should normally come from an external IdP, mTLS gateway, signed assertion, or `ext_authz`, with qpx enforcing policy from that trusted context. Built-in auth is primarily for lab, small deployment, and local edge use cases.

qpx uses bounded, backpressure-aware body streams for HTTP/3 request and response relay. Streaming-aware policies cover gRPC, gRPC-Web, Connect, and SSE without requiring qpx to become an application authentication authority. Buffering modules must opt in explicitly and can be rejected by route-level streaming requirements.

qpx treats `text/event-stream` as latency-sensitive streaming traffic: response buffering and compression are disabled by default, and SSE streams get dedicated idle timeout and observability.

qpx runs continuous performance regression tests. These CI results are used to detect large regressions, not to claim absolute throughput. Release-grade comparative benchmarks require dedicated hardware.

## Features

- **Forward proxy**: HTTP/HTTPS, CONNECT, rules, optional built-in auth,
  upstream proxy chaining, FTP-over-HTTP, WebSocket upgrade, HTTP/3
  CONNECT-UDP / MASQUE, and generic extended CONNECT.
- **Reverse proxy**: Host/SNI/path/src_ip routing, TLS termination, TLS
  passthrough, retry, health checks, header/path rewrite, canary splitting,
  mirroring, HTTP/3 termination, HTTP/3 passthrough, and `qpxf` IPC targets.
- **Transparent proxy**: Linux `SO_ORIGINAL_DST` plus metadata fallback
  routing, with optional TLS MITM inspection.
- **Policy inputs**: trusted headers, mTLS subject mapping, signed JWS/JWT
  assertions, external authorization, named sets/external feeds, destination
  intelligence, and advanced HTTP/TLS/certificate/RPC matchers.
- **Streaming-aware HTTP policy**: bounded body streams, explicit buffering
  opt-in, gRPC / gRPC-Web / Connect observation, SSE low-latency defaults, and
  `qpxd explain` visibility into buffering cost.
- **HTTP modules**: built-in response compression, internal subrequests, cache
  purge endpoints, and a public in-process module API.
- **Caching**: RFC 9111 + RFC 5861 proxy cache with in-memory, Redis, and HTTP
  object-storage backends.
- **Capture and observability**: structured logs, Prometheus metrics, optional
  OpenTelemetry, shared-memory capture export from `qpxd`, PCAPNG generation by
  `qpxr`, and client streaming by `qpxc`.
- **ACME**: HTTP-01 certificate issuance/renewal for reverse TLS termination
  when `qpxd` is built with `acme` and `tls-rustls`.

## Quick Start

```bash
# Build the workspace. qpxd defaults to tls-rustls + http3-backend-h3 + mitm
# + acme + auth-digest + auth-ldap.
cargo build --release

# Run the daemon.
cargo run -p qpxd -- run --config config/qpx.example.yaml

# Validate config without starting listeners.
cargo run -p qpxd -- check --config config/qpx.example.yaml

# Print the machine-readable current config schema.
cargo run -p qpxd -- schema --format json

# Render the compiled runtime plan.
cargo run -p qpxd -- explain --config config/qpx.example.yaml
```

Start with [`config/usecases/01-getting-started`](config/usecases/01-getting-started)
for small runnable profiles. The full sample index is
[`config/README.md`](config/README.md).

<details>
<summary>Build features</summary>

`qpxd` default features are `tls-rustls`, `http3-backend-h3`, `mitm`, `acme`,
`auth-digest`, and `auth-ldap`.

- `tls-rustls` is the default TLS backend and is required by HTTP/3, MITM, and
  ACME.
- `tls-native` uses `native-tls` / `tokio-native-tls`; HTTP/3 and MITM are not
  available with this backend.
- `http3-backend-h3` is the default upstream-`h3` backend for standard HTTP/3,
  CONNECT, CONNECT-UDP / MASQUE, upstream HTTP/3 proxying, and non-WebTransport
  extended CONNECT.
- `http3-backend-qpx` enables the clean-room `qpx-h3` backend and the full
  QPX-owned advanced HTTP/3 surface, including WebTransport relay.
- Reverse HTTP/3 passthrough is backend-neutral because it is raw UDP/QUIC
  session routing inside `qpxd`.

```bash
# Clean-room HTTP/3 backend.
cargo build --release -p qpxd --no-default-features --features tls-rustls,http3-backend-qpx

# Native TLS backend.
cargo build --release -p qpxd --no-default-features --features tls-native
cargo build --release -p qpxr --no-default-features --features tls-native
cargo build --release -p qpxc --no-default-features --features tls-native

# Minimal qpxd build with no TLS backend.
cargo build --release -p qpxd --no-default-features
```

</details>

<details>
<summary>CLI surface</summary>

`qpxd` subcommands:

- `run --config <file>...`
- `check --config <file>...`
- `init <reverse-basic|forward-egress|transparent-linux|ipc-gateway|trusted-identity-ext-authz>`
- `schema --format <json|yaml>`
- `explain --config <file>... [--format <text|json>] [--edge <name>] [--route <name>]`
- `match --config <file>... --edge <name> [--src-ip <ip>] [--dst-port <port>] [--sni <name>] [--host <name>] [--method <method>] [--path <path>]`
- `gen-ca --state-dir <dir>` when built with `tls-rustls`
- `upgrade --pid <pid>`

`run`, `check`, `explain`, and `match` accept repeated `--config` arguments.
Files are merged in order; later files override earlier scalar/object values,
while named collections append and are then checked for duplicate names.

</details>

## Configuration

qpx uses one current canonical YAML schema. Unknown keys are rejected so typos do
not silently become defaults. Use `qpxd schema` for the machine-readable schema
and `qpxd check` for deployment validation.

The schema is edge-oriented:

- `runtime`: process and protocol limits
- `telemetry`: logs, metrics, OpenTelemetry, ACME, capture exporter
- `security`: auth, identity sources, named sets, destination intelligence,
  trust profiles, and external authorization decisions
- `http`: reusable HTTP policy, guard profiles, and module chains
- `traffic`: reusable rate-limit profiles
- `caches`: cache backend definitions
- `edges[]`: forward, reverse, and transparent entry points

Reverse routes use one typed `target`: `upstream`, `weighted`, `ipc`,
`local_response`, or `tls_passthrough`.

<details>
<summary>Important config notes</summary>

- Forward and transparent samples default to `default_action: block` except for
  loopback-only local-dev and test-fixture profiles.
- Include composition uses `include:`; included files are merged depth-first and
  the including file wins.
- Transport-aware shaping uses `rate_limit` / `rate_limit_profiles` with
  `apply_to`, `requests`, `traffic`, and `sessions`.
- Response-stage policy lives under `edges[].http.response_rules` and reverse
  route `http.response_rules`.
- `connection_filter` is a low-cost early-drop DSL on `edges[]`. It requires
  `match:` and only supports `action.type: block`.
- Streaming behavior can be tuned under `runtime`, `edges[].streaming` /
  `grpc` / `sse`, and reverse route `streaming` / `grpc` / `sse`.
- `streaming_requirement: required` rejects buffering features; `preferred`
  makes buffering an explicit opt-in.
- Exact size matching for unknown-length bodies additionally requires
  `runtime.unknown_length_exact_size: buffer`.

See [`docs/config-schema.md`](docs/config-schema.md),
[`docs/streaming-config.md`](docs/streaming-config.md), and
[`config/README.md`](config/README.md).

</details>

## Components

| Binary | Role |
|---|---|
| `qpxd` | Proxy daemon and policy runtime |
| `qpxf` | QPX-IPC function executor for CGI / WASM / FastCGI / SCGI |
| `qpxr` | Shared-memory capture reader and PCAPNG stream/server |
| `qpxc` | PCAPNG stream client and Wireshark/extcap bridge |

Detailed component guides:

- [`docs/function-executor.md`](docs/function-executor.md)
- [`docs/capture-pipeline.md`](docs/capture-pipeline.md)
- [`docs/http-modules.md`](docs/http-modules.md)
- [`docs/operations.md`](docs/operations.md)

## Platform Support

CI runs native build/test coverage on Linux, Windows, macOS Intel, and macOS
Apple Silicon, and preflights the release-target matrix for Linux musl
`x86_64` / `aarch64`, macOS `x86_64` / `aarch64`, and Windows `x86_64`.

Release binaries are published for:

| Target | Notes |
|---|---|
| `x86_64-unknown-linux-musl` | Static musl binary |
| `aarch64-unknown-linux-musl` | Static musl binary |
| `x86_64-apple-darwin` | macOS Intel |
| `aarch64-apple-darwin` | macOS Apple Silicon |
| `x86_64-pc-windows-msvc` | Windows |

<details>
<summary>Platform-specific behavior</summary>

- Transparent original-destination recovery uses Linux `SO_ORIGINAL_DST`; on
  non-Linux it falls back to TLS SNI, HTTP `Host`, or PROXY metadata.
- Practical transparent interception requires Linux packet redirection through
  iptables/nftables or an L4 frontend.
- `tls-native` builds depend on the platform TLS stack. Linux requires OpenSSL
  development headers.
- Redis cache `redis+unix://` endpoints require Unix domain sockets; on Windows
  use `redis://` or `rediss://`.

</details>

## Tests

```bash
cargo build -p qpxd -p qpxf
./scripts/check-config-samples.sh
./scripts/e2e-config-samples.sh
./scripts/e2e-http2.sh
./scripts/e2e-local-response.sh
```

CI also gates formatting, documentation warnings, unused dependency checks,
feature-matrix clippy, RustSec audit, CodeQL, AddressSanitizer smoke tests, fuzz
smoke tests, multi-platform builds, and end-to-end reload/upgrade paths.

## Documentation

- [`config/README.md`](config/README.md): configuration sample index and usage
  guide
- [`docs/config-schema.md`](docs/config-schema.md): schema rules and validation
  workflow
- [`docs/code-structure.md`](docs/code-structure.md): source-level module index
- [`docs/operations.md`](docs/operations.md): reload, binary upgrade, runtime
  tuning, and operational safeguards
- [`docs/function-executor.md`](docs/function-executor.md): `qpxf` and QPX-IPC
  guide
- [`docs/capture-pipeline.md`](docs/capture-pipeline.md): capture exporter,
  `qpxr`, and `qpxc`
- [`docs/http-modules.md`](docs/http-modules.md): built-in and custom HTTP
  modules
- [`docs/enterprise-edge-scope.md`](docs/enterprise-edge-scope.md): enterprise
  cloud-edge positioning
- [`docs/rfc911x-compliance.md`](docs/rfc911x-compliance.md): RFC compliance
  notes and verification
- [`docs/interoperability-matrix.md`](docs/interoperability-matrix.md):
  protocol interoperability lanes
- [`docs/usecase-inventory.md`](docs/usecase-inventory.md): `config/usecases/`
  capability inventory

## License

[MIT](LICENSE)

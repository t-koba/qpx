# qpx config samples

`qpxd` configuration samples organized by **use case**.

## How to use this folder

- Start from `config/usecases/01-getting-started/`.
- Move to a use-case directory that matches your operation goal.
- Copy one sample and adjust listen addresses, hostnames, credentials, and cert paths.
- Shared include fragments are in `config/fragments/`.
- `qpxd run` / `qpxd check` can layer multiple files with repeated `--config`; later files override earlier ones.

The YAML schema is flat and matches the serde structs in `qpx_core::config::types::*`. Write top-level sections such as `system_log`, `metrics`, `auth`, `identity_sources`, and `ext_authz` directly, and express reverse-route targets as `upstreams`, `backends`, `ipc`, or `local_response`.

Reverse route targets are:

- `upstreams` / `backends[].upstreams` with literal `http://` / `https://` / `ws://` / `wss://` upstream URLs.
- `upstreams` / `backends[].upstreams` with names declared in top-level `upstreams`.
- `ipc` for QPX-IPC forwarding to `qpxf`.
- `local_response` for route-local responses without upstream forwarding.

## TLS backend notes

Most samples assume the default `qpxd` build (`tls-rustls`).

- HTTP/3 (`http3:` sections) and TLS inspection (`tls_inspection:` sections) require a `tls-rustls` build.
- For `tls-native` builds, reverse TLS termination uses PKCS#12 (`reverse[].tls.certificates[].pkcs12`) instead of PEM `cert`/`key`.

Example for `tls-native` reverse termination:

```yaml
reverse:
  - name: edge
    listen: "0.0.0.0:443"
    tls:
      certificates:
        - sni: "app.example.com"
          pkcs12: "/etc/qpx/tls/app.example.com.p12"
          pkcs12_password_env: QPX_TLS_PKCS12_PASSWORD
```

## HTTP/3 backend choice

HTTP/3 backend selection is a build-time `qpxd` feature choice. YAML does not select the backend.

- `http3-backend-h3` is the default upstream-`h3` backend. Use it for standard HTTP/3, CONNECT-UDP / MASQUE datagram relay, upstream HTTP/3 chaining, and non-WebTransport extended CONNECT.
- `http3-backend-qpx` is the clean-room backend. Use it when you need WebTransport relay, or when you want the clean-room backend to carry the full QPX-owned advanced HTTP/3 surface: CONNECT-UDP / MASQUE, generic extended CONNECT, and reverse terminate.
- Reverse HTTP/3 passthrough is backend-neutral and works with either backend because it is raw UDP/QUIC routing rather than HTTP/3 framing.

## Security defaults (important)

- Forward-proxy samples default to `default_action: block` and only allow traffic via explicit allow rules (typically `src_ip` allowlists and/or `auth`). This prevents accidental open-proxy deployments.
- Transparent-mode samples also default to `default_action: block` and require explicit allow rules (typically `src_ip` allowlists) because a transparent listener can be abused as a generic proxy if exposed.
- When changing a sample from loopback-only (`127.0.0.1`) to `0.0.0.0`, review the allow rules first and add an explicit client allowlist or authentication.
- Metrics endpoint defaults to loopback-only; to bind `metrics.listen` to non-loopback, configure `metrics.allow` (CIDR allowlist).
- `forward-local-dev-direct.yaml` and `forward-http3-connect-udp-local-dev-direct.yaml` are exceptions: they intentionally use `default_action: direct` for local development and are bound to loopback.
- `99-test-fixtures/` samples are for automated tests only and may use `default_action: direct` on loopback listeners.

## Use-case index

### 01-getting-started (`config/usecases/01-getting-started`)
- `forward-minimal.yaml`: smallest forward proxy (safe default deny).
- `forward-local-dev-direct.yaml`: development-only allow-by-default forward proxy (loopback only).
- `reverse-basic-http.yaml`: smallest reverse proxy.
- `transparent-linux-original-dst.yaml`: Linux transparent interception baseline (`SO_ORIGINAL_DST`).

### 02-secure-egress (`config/usecases/02-secure-egress`)
- `forward-upstream-chain.yaml`: forward proxy chained to upstream proxy.
- `forward-local-auth-basic-digest.yaml`: built-in multi-user local auth (Basic/Digest) baseline for tests, local development, or small deployments; shows both cleartext `password` and precomputed Digest `ha1`.
- `forward-ldap-group-policy.yaml`: direct LDAP bind/group policy when `qpx` itself terminates the auth hop; includes `user_filter`, `group_filter`, and `group_attr` overrides for non-default directory schemas.
- `forward-trusted-identity-ext-authz.yaml`: trusted identity ingestion + external authz policy callout.
- `forward-signed-assertion-policy.yaml`: locally verified signed identity assertions (`signed_assertion`) + external authz, including `user_from_sub`.
- `forward-tls-inspection-selective.yaml`: selective TLS inspection/tunnel/block.
- `forward-adblock-privacy.yaml`: ad/tracker blocking profile.
- `forward-firewall-style-policy.yaml`: firewall-style multi-condition rules.
- `forward-authenticated-upstream.yaml`: authenticated users + upstream egress chaining.
- `forward-rate-limit-profiles.yaml`: transport-aware inline throttling plus reusable `rate_limit_profiles` (`requests` / `traffic` / `sessions`) for ext_authz-driven enforcement.
- `forward-destination-intelligence-and-trust.yaml`: named destination sets, file-backed feeds, destination-resolution precedence/confidence policy, upstream discovery, and trust profiles.

### 03-service-publishing (`config/usecases/03-service-publishing`)
- `reverse-load-balance-retry.yaml`: load balancing, route `resilience`, and health-check policy.
- `reverse-path-rewrite.yaml`: reverse route path rewrite (strip/add prefix).
- `reverse-advanced-routing.yaml`: reverse route header rewrite + canary + mirroring + regex rewrite.
- `reverse-affinity-response-policy.yaml`: stickiness, response-aware local fallback, mirroring, and cache bypass policy.
- `reverse-cert-and-size-aware-policy.yaml`: advanced reverse matchers for downstream `client_cert`, `request_size`, and response-side `response_size` / `upstream_cert`.
- `reverse-discovery-srv.yaml`: SRV-backed upstream discovery with active/passive health and lifecycle controls.
- `reverse-mtls-identity-routing.yaml`: inbound client-cert auth, `mtls_subject` identity extraction (`user_from_san_uri_prefix` plus `user_from_subject_cn`), and identity-aware routing.
- `reverse-sni-host-exceptions.yaml`: shared-edge publish profile that intentionally allows Host/SNI mismatch within an explicit wildcard allowlist.
- `reverse-tls-termination.yaml`: HTTPS terminate and route to HTTP upstreams.
- `reverse-tls-termination-native-pkcs12.yaml`: `tls-native`-only reverse TLS termination sample using PKCS#12 and `pkcs12_password_env`.
- `reverse-tls-acme-letsencrypt.yaml`: reverse TLS termination with ACME / Let's Encrypt (HTTP-01), including `directory_url` override for staging/private ACME endpoints.
- `reverse-tls-passthrough-sni.yaml`: SNI-based TLS passthrough split.
- `reverse-http2-tls.yaml`: reverse TLS with HTTP/2 downstream.
- `reverse-http3-terminate.yaml`: reverse HTTP/3 terminate mode. Works with either backend.
- `reverse-http3-passthrough.yaml`: reverse HTTP/3 UDP passthrough mode. Backend-neutral.
- `reverse-websocket-upstream.yaml`: reverse publish profile for `ws://` and `wss://` upstream backends, including health checks.
- `reverse-http-guard-lite.yaml`: lightweight reverse-edge request hardening via reusable `http_guard_profiles`.
- `reverse-rpc-aware-policy.yaml`: response-stage RPC-aware policy for `gRPC`, `Connect`, and `gRPC-Web`, including protocol-correct local responses.

### 04-http3-and-masque (`config/usecases/04-http3-and-masque`)
- `forward-http3-connect-udp.yaml`: forward HTTP/3 + CONNECT-UDP (MASQUE) sample (safe default deny). Works with either backend; choose `http3-backend-qpx` if the same build also needs WebTransport relay.
- `forward-http3-connect-udp-local-dev-direct.yaml`: development-only allow-by-default HTTP/3 + CONNECT-UDP (loopback only). Works with either backend.
- `forward-http3-connect-udp-uri-template.yaml`: CONNECT-UDP URI template enforcement sample. Works with either backend.
- `forward-http3-extended-connect.yaml`: generic non-WebTransport HTTP/3 extended CONNECT sample, covering both direct relay and chained upstream proxying. Works with either backend.
- `forward-http3-webtransport.yaml`: forward HTTP/3 WebTransport relay sample. Use `http3-backend-qpx`.

### 05-caching (`config/usecases/05-caching`)
- `forward-redis.yaml`: forward cache with Redis (`redis://`).
- `forward-redis-unix.yaml`: forward cache with Redis UNIX socket (`redis+unix://`).
- `forward-redis-public-cookie.yaml`: shared-cache profile that explicitly allows public cookie-bearing objects.
- `reverse-http-backend.yaml`: reverse cache with HTTP object gateway backend.
- `reverse-rediss-remote.yaml`: reverse cache with remote Redis TLS (`rediss://`).

### 06-local-response (`config/usecases/06-local-response`)
- `all-modes-policy.yaml`: local response examples for forward/transparent/reverse.
- `forward-debug.yaml`: forward local health/policy responses.
- `reverse-maintenance.yaml`: reverse maintenance/status local responses.
- `transparent-captive-portal.yaml`: captive-portal style transparent responses.

### 07-observability-debug (`config/usecases/07-observability-debug`)
- `observability-high-detail.yaml`: detailed logging + metrics + capture exporter (writes to shared-memory ring for `qpxr`).
- `observability-otel-rich-audit.yaml`: non-loopback metrics allowlist + OTLP + richer audit field coverage.
- `forward-trace-debug.yaml`: loopback-only TRACE/OPTIONS diagnostic profile with `trace_enabled` and the safer default `trace_reflect_all_headers: false`.
- `http-modules-advanced.yaml`: canonical built-in HTTP module sample with `id` / `order`, cache purge response tuning, subrequest header capture, and compression tuning.
- `forward-header-rewrite.yaml`: request/response header rewrite testing.
- `forward-websocket-debug.yaml`: WebSocket-oriented routing/debug profile.
- `forward-ftp-over-http.yaml`: FTP-over-HTTP debug profile.

### 08-performance-and-xdp (`config/usecases/08-performance-and-xdp`)
- `runtime-multicore-scaling.yaml`: runtime thread/backlog/reuse-port tuning, HTTP/3 stream caps, and default upstream HTTP timeout tuning.
- `connection-filter-early-drop.yaml`: early-drop `connection_filter` examples for listener accept and reverse TLS ClientHello stages.
- `xdp-forward-reverse-proxy-metadata.yaml`: PROXY v2 metadata integration (trusted peers).
- `xdp-transparent-proxy-metadata.yaml`: transparent listener consuming PROXY v2 metadata.

### 09-composition (`config/usecases/09-composition`)
- `multi-mode-office-gateway.yaml`: forward + transparent + reverse in one config.
- `include-forward.yaml`: include-composed forward profile.
- `include-transparent-reverse.yaml`: include-composed transparent + reverse profile.

### 10-operator-customization (`config/usecases/10-operator-customization`)
- `operator-tuning.yaml`: identity/messages customization and low-information generated `User-Agent` tuning.

### 11-transparent-intercept (`config/usecases/11-transparent-intercept`)
- `transparent-macos-windows-fallback.yaml`: transparent mode fallback path for non-Linux hosts.
- `transparent-mitm-selective.yaml`: transparent mode with selective TLS MITM.

### 12-ipc-gateway (`config/usecases/12-ipc-gateway`)
- `qpx.yaml`: `qpxd` reverse proxy sample routing to a `qpxf` function executor via QPX-IPC (`ipc:` route). `listen` is overridable with `QPX_IPC_GATEWAY_LISTEN`.
- `qpxf.yaml`: `qpxf` executor sample (CGI/WASM handlers) backed by repo-local fixture handlers so `qpxf check` and sample e2e work out of the box; override `QPXF_SAMPLE_CGI_ROOT` / `QPXF_SAMPLE_WASM_MODULE` for your own handlers.
- `qpx-tcp.yaml`: `qpxd` reverse proxy sample using `ipc.mode: tcp`. `listen` is overridable with `QPX_IPC_GATEWAY_TCP_LISTEN`.
- `qpxf-tcp.yaml`: `qpxf` TCP listener sample (`allow_insecure_tcp: true`) aligned with `qpx-tcp.yaml` for loopback smoke tests; tighten `host:` / `path_regex:` after validation if needed.

### 99-test-fixtures (`config/usecases/99-test-fixtures`)
- `e2e-forward.yaml`
- `e2e-reverse.yaml`
- `e2e-transparent.yaml`

## Shared fragments (`config/fragments`)

- `base-observability.yaml`
- `forward-listener.yaml`
- `transparent-reverse.yaml`

Use these only through `include` composition samples.

## Validation

`qpxd` and `qpxf` use different config schemas. The default sample check validates all `tls-rustls` samples plus the repo-local `qpxf` examples. `*-native-*` samples are for manual `tls-native` validation.

```bash
cargo build -p qpxd -p qpxf --locked
./scripts/check-config-samples.sh
```

Manual check for the `tls-native` PKCS#12 sample:

```bash
export QPX_TLS_PKCS12=/path/to/server.p12
export QPX_TLS_PKCS12_PASSWORD='change-me'
cargo run -p qpxd --no-default-features --features tls-native -- \
  check --config config/usecases/03-service-publishing/reverse-tls-termination-native-pkcs12.yaml
```

`qpxf` now supports `check`:

```bash
cargo run -p qpxf -- check --config config/usecases/12-ipc-gateway/qpxf.yaml
cargo run -p qpxf -- check --config config/usecases/12-ipc-gateway/qpxf-tcp.yaml
```

The sample `qpxf` configs default to repo-local fixture handlers and still allow `${VAR}` / `${VAR:-default}` overrides. Any TCP `listen` value requires `allow_insecure_tcp: true`.

## End-to-end checks

```bash
cargo build -p qpxd -p qpxf
./scripts/e2e-config-samples.sh
./scripts/e2e-http2.sh
./scripts/e2e-local-response.sh
```

## Notes

- `listeners[].default_action.type: respond` and `listeners[].rules[].action.type: respond` both require `local_response`.
- Reverse routes use exactly one target surface: `upstreams`, `backends`, `ipc`, or `local_response`.
- `upstreams` / `backends[].upstreams` accept either literal `http://` / `https://` / `ws://` / `wss://` URLs or names from top-level `upstreams`.
- `connection_filter` is a separate early-drop DSL on `listeners[]` and `reverse[]`. It requires `match:` plus `action.type: block`, is limited to transport/TLS metadata such as `src_ip`, `dst_port`, `sni`, `alpn`, `tls_version`, and `tls_fingerprint`, and emits `connection_filter_drop` audit entries when it blocks a connection.
- `destination_resolution.defaults` is the shared destination-intelligence arbitration policy. Override it on `listeners[]`, `reverse[]`, and `reverse[].routes[]` when a scope needs different evidence precedence, conflict handling, or minimum confidence thresholds.
- `http_guard_profiles` is the reusable lightweight HTTP guard surface. Attach a profile with `listeners[].http_guard_profile` or `reverse[].routes[].http_guard_profile` to enable smuggling/framing checks and bounded path/query/header/body parsing.
- Runtime knobs worth calling out explicitly: `runtime.max_h3_streams_per_connection`, `runtime.upstream_http_timeout_ms`, `runtime.max_observed_request_body_bytes`, `runtime.max_observed_response_body_bytes`, `runtime.trace_enabled`, and `runtime.trace_reflect_all_headers`. See `runtime-multicore-scaling.yaml` and `config/qpx.example.yaml`.
- `forward-trace-debug.yaml` is the dedicated loopback-only sample for TRACE diagnostics. Keep `trace_reflect_all_headers: false` unless you explicitly need full header echo for local troubleshooting.
- Built-in auth supports `auth.users[].ha1` for Digest HA1 preload, and LDAP supports `user_filter`, `group_filter`, and `group_attr`. See `forward-local-auth-basic-digest.yaml` and `forward-ldap-group-policy.yaml`.
- Trusted identity mapping supports `map.user_from_subject_cn` for mTLS subjects and `assertion.claims.user_from_sub` / `groups_separator` for signed assertions. See `reverse-mtls-identity-routing.yaml` and `forward-signed-assertion-policy.yaml`.
- Advanced rule matchers include `http_version`, `tls_version`, `tls_fingerprint`, `request_size`, `response_size`, destination `destination.<dimension>.source` / `destination.<dimension>.confidence`, `upstream_cert`, and reverse-TLS `client_cert`. See `forward-destination-intelligence-and-trust.yaml` and `config/qpx.example.yaml`.
- `match.rpc.*` is the shared RPC-aware matcher family on HTTP rules and response rules. Use `protocol`, `service`, `method`, `status`, `message_size`, `message`, and `trailers` to write `gRPC` / `Connect` / `gRPC-Web` policy without a separate gateway DSL. See `reverse-rpc-aware-policy.yaml`.
- `action.local_response.rpc` emits protocol-correct local responses for `grpc`, `connect`, and `grpc_web` on request rules. Response-stage policy uses the same payload shape under `http.response_rules[].effects.local_response.rpc`.
- HTTP modules are configured with `type`, optional `id`, and optional `order`. Built-ins expose field-level knobs such as compression `max_body_bytes` / `content_types`, subrequest `pass_headers` / header capture, and cache purge `methods` / `response_*`. See `http-modules-advanced.yaml`.
- On `ipc` routes, `ipc.mode: shm` (default) uses a shared-memory ring for body transfer and requires `qpxd` and `qpxf` on the same host. Use `ipc.mode: tcp` for cross-host deployments.
- `identity_sources[].type: signed_assertion` locally verifies JWS/JWT assertions. Use `assertion.secret_env` for HS* algorithms or `assertion.public_key_env` for RS*/ES* algorithms, then map claims into subject fields.
- `named_sets` can be backed by inline `values` or `file`. For destination intelligence, use `type: domain|cidr|string|regex` and prefix the set name with `category:`, `reputation:`, or `application:`. `qpxd` also watches `named_sets[].file` targets during hot reload.
- `tls_trust` / `upstream_trust` are available on named upstreams, reverse routes, and TLS inspection. They enforce upstream pinning, issuer/SAN constraints, and optional per-upstream mTLS client cert selection via `client_cert` / `client_key`.
- `reverse[].sni_host_exceptions` is the explicit allowlist for host/SNI mismatch exceptions when `enforce_sni_host_match: true` is enabled.
- `resilience.outlier_detection.consecutive_failures.resets` counts transport resets alongside 5xx/timeouts for ejection decisions on named upstreams.
- `reverse-tls-acme-letsencrypt.yaml` now also shows `acme.directory_url` for staging/private ACME endpoints.
- Transport-aware shaping uses one canonical surface: `rate_limit` / `rate_limit_profiles` with `apply_to`, `requests`, `traffic`, and `sessions`. WebTransport supports session-wide `webtransport` plus `webtransport_bidi`, `webtransport_uni`, `webtransport_datagram`, and direction-specific `*_downstream` / `*_upstream` scopes.
- Reverse-route retry/ejection/concurrency policy is expressed with `resilience`; named upstreams use the same `resilience` surface.
- Response-stage rules live under `listeners[].http.response_rules` and `reverse[].routes[].http.response_rules`, and the same response-aware policy surface is enforced in forward, MITM, transparent HTTP, and reverse HTTP paths.

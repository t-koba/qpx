# qpx config samples

`qpxd` configuration samples organized by **use case**.

## How to use this folder

- Start from `config/usecases/01-getting-started/`.
- Move to a use-case directory that matches your operation goal.
- Copy one sample and adjust listen addresses, hostnames, credentials, and cert paths.
- Shared include fragments are in `config/fragments/`.

## TLS backend notes

Most samples assume the default `qpxd` build (`tls-rustls`).

- HTTP/3 (`http3:` sections) and TLS inspection (`tls_inspection:` sections) require a `tls-rustls` build.
- For `tls-native` builds, reverse TLS termination uses PKCS#12 (`reverse[].tls.certificates[].pkcs12`) instead of PEM `cert`/`key`.
- If you enable exporter TLS client authentication, `exporter.tls.client_cert/client_key` is rustls-only; `exporter.tls.client_pkcs12` is native-tls-only.

## Security defaults (important)

- Forward-proxy samples default to `default_action: block` and only allow traffic via explicit allow rules (typically `src_ip` allowlists and/or `auth`). This prevents accidental open-proxy deployments.
- Transparent-mode samples also default to `default_action: block` and require explicit allow rules (typically `src_ip` allowlists) because a transparent listener can be abused as a generic proxy if exposed.
- When changing a sample from loopback-only (`127.0.0.1`) to `0.0.0.0`, review the allow rules first and add an explicit client allowlist or authentication.
- Metrics endpoint defaults to loopback-only; to bind `metrics.listen` to non-loopback, configure `metrics.allow` (CIDR allowlist).
- `forward-local-dev-direct.yaml` is the exception: it intentionally uses `default_action: direct` for local development and is bound to loopback.

## Use-case index

### 01-getting-started (`config/usecases/01-getting-started`)
- `forward-minimal.yaml`: smallest forward proxy (safe default deny).
- `forward-local-dev-direct.yaml`: development-only allow-by-default forward proxy (loopback only).
- `reverse-basic-http.yaml`: smallest reverse proxy.
- `transparent-linux-original-dst.yaml`: Linux transparent interception baseline (`SO_ORIGINAL_DST`).

### 02-secure-egress (`config/usecases/02-secure-egress`)
- `forward-upstream-chain.yaml`: forward proxy chained to upstream proxy.
- `forward-local-auth-basic-digest.yaml`: local user auth (Basic/Digest) baseline.
- `forward-ldap-group-policy.yaml`: LDAP auth with group-based policy.
- `forward-tls-inspection-selective.yaml`: selective TLS inspection/tunnel/block.
- `forward-adblock-privacy.yaml`: ad/tracker blocking profile.
- `forward-firewall-style-policy.yaml`: firewall-style multi-condition rules.
- `forward-authenticated-upstream.yaml`: **new common pattern** for authenticated users + upstream egress chaining.

### 03-service-publishing (`config/usecases/03-service-publishing`)
- `reverse-load-balance-retry.yaml`: load balancing, retry, health-check policy.
- `reverse-path-rewrite.yaml`: reverse route path rewrite (strip/add prefix).
- `reverse-advanced-routing.yaml`: reverse route header rewrite + canary + mirroring + regex rewrite.
- `reverse-tls-termination.yaml`: HTTPS terminate and route to HTTP upstreams.
- `reverse-tls-passthrough-sni.yaml`: SNI-based TLS passthrough split.
- `reverse-http2-tls.yaml`: reverse TLS with HTTP/2 downstream.
- `reverse-http3-terminate.yaml`: reverse HTTP/3 terminate mode.
- `reverse-http3-passthrough.yaml`: reverse HTTP/3 UDP passthrough mode.

### 04-http3-and-masque (`config/usecases/04-http3-and-masque`)
- `forward-http3-connect-udp.yaml`: forward HTTP/3 + CONNECT-UDP (MASQUE) sample (safe default deny).
- `forward-http3-connect-udp-local-dev-direct.yaml`: development-only allow-by-default HTTP/3 + CONNECT-UDP (loopback only).

### 05-caching (`config/usecases/05-caching`)
- `forward-redis.yaml`: forward cache with Redis (`redis://`).
- `forward-redis-unix.yaml`: forward cache with Redis UNIX socket (`redis+unix://`).
- `reverse-http-backend.yaml`: reverse cache with HTTP object gateway backend.
- `reverse-rediss-remote.yaml`: reverse cache with remote Redis TLS (`rediss://`).

### 06-local-response (`config/usecases/06-local-response`)
- `all-modes-policy.yaml`: local response examples for forward/transparent/reverse.
- `forward-debug.yaml`: forward local health/policy responses.
- `reverse-maintenance.yaml`: reverse maintenance/status local responses.
- `transparent-captive-portal.yaml`: captive-portal style transparent responses.

### 07-observability-debug (`config/usecases/07-observability-debug`)
- `observability-high-detail.yaml`: detailed logging + metrics + exporter feed (for `qpxr` integration).
- `forward-header-rewrite.yaml`: request/response header rewrite testing.
- `forward-websocket-debug.yaml`: WebSocket-oriented routing/debug profile.
- `forward-ftp-over-http.yaml`: FTP-over-HTTP debug profile.

### 08-performance-and-xdp (`config/usecases/08-performance-and-xdp`)
- `runtime-multicore-scaling.yaml`: runtime thread/backlog/reuse-port tuning.
- `xdp-forward-reverse-proxy-metadata.yaml`: PROXY v1/v2 metadata integration (trusted peers).

### 09-composition (`config/usecases/09-composition`)
- `multi-mode-office-gateway.yaml`: forward + transparent + reverse in one config.
- `include-forward.yaml`: include-composed forward profile.
- `include-transparent-reverse.yaml`: include-composed transparent + reverse profile.

### 10-operator-customization (`config/usecases/10-operator-customization`)
- `operator-tuning.yaml`: identity/messages customization and generated `User-Agent` tuning.

### 11-transparent-intercept (`config/usecases/11-transparent-intercept`)
- `transparent-macos-windows-fallback.yaml`: transparent mode fallback path for non-Linux hosts.
- `transparent-mitm-selective.yaml`: transparent mode with selective TLS MITM.

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

```bash
cargo build -p qpxd
find config/usecases -name '*.yaml' -print | sort | while read -r f; do
  echo "==> $f"
  target/debug/qpxd check --config "$f"
done
```

## End-to-end checks

```bash
cargo build -p qpxd
./scripts/e2e-config-samples.sh
./scripts/e2e-http2.sh
./scripts/e2e-local-response.sh
```

## Notes

- `listeners.rules[].action.type: respond` requires `action.local_response`.
- Reverse route local response uses route-level `local_response` (omit `upstreams` / `backends`).
- `reverse.routes[]` must set exactly one of `upstreams`, `backends`, or `local_response`.

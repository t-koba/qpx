# Use Case Inventory

This file is the stage-0 capability baseline for the current non-compatible config redesign.

The acceptance rule is not “old YAML still parses”. The rule is:

- every capability represented under `config/usecases/`
- remains representable on the current public surface
- and remains covered by `check-config-samples.sh` plus the relevant e2e/smoke lanes

## 01-getting-started

- `forward-minimal.yaml`: smallest safe-default forward proxy.
- `forward-local-dev-direct.yaml`: loopback-only allow-by-default forward proxy for local development.
- `reverse-basic-http.yaml`: smallest reverse HTTP publish path.
- `transparent-linux-original-dst.yaml`: Linux transparent interception baseline.

## 02-secure-egress

- `forward-upstream-chain.yaml`: chained upstream proxying.
- `forward-local-auth-basic-digest.yaml`: built-in Basic/Digest auth, including HA1 preload.
- `forward-ldap-group-policy.yaml`: direct LDAP auth/group policy.
- `forward-trusted-identity-ext-authz.yaml`: trusted identity ingestion plus external authorization.
- `forward-signed-assertion-policy.yaml`: signed assertion identity plus external authorization.
- `forward-tls-inspection-selective.yaml`: selective inspect/tunnel/block.
- `forward-adblock-privacy.yaml`: ad/tracker filtering.
- `forward-firewall-style-policy.yaml`: multi-condition firewall-style rules.
- `forward-authenticated-upstream.yaml`: identity-aware upstream chaining.
- `forward-rate-limit-profiles.yaml`: transport-aware shaping profiles and inline rule shaping.
- `forward-destination-intelligence-and-trust.yaml`: destination intelligence plus upstream trust.

## 03-service-publishing

- `reverse-load-balance-retry.yaml`: reverse publish with load balancing, health checks, and route resilience.
- `reverse-path-rewrite.yaml`: reverse path rewrite.
- `reverse-advanced-routing.yaml`: canary, mirroring, affinity, resilience, and response-stage rules.
- `reverse-affinity-response-policy.yaml`: affinity, cache, mirroring, and response-stage local fallback.
- `reverse-cert-and-size-aware-policy.yaml`: downstream client cert and response/upstream-cert aware policy.
- `reverse-discovery-srv.yaml`: SRV discovery with active/passive health.
- `reverse-mtls-identity-routing.yaml`: downstream mTLS identity extraction and identity-aware routing.
- `reverse-sni-host-exceptions.yaml`: explicit Host/SNI exception allowlist.
- `reverse-tls-termination.yaml`: HTTPS termination to HTTP upstreams.
- `reverse-tls-termination-native-pkcs12.yaml`: `tls-native` PKCS#12 termination.
- `reverse-tls-acme-letsencrypt.yaml`: ACME-managed reverse termination.
- `reverse-tls-passthrough-sni.yaml`: TLS passthrough split by SNI.
- `reverse-http2-tls.yaml`: HTTP/2 downstream reverse publish.
- `reverse-http3-terminate.yaml`: HTTP/3 terminate mode.
- `reverse-http3-passthrough.yaml`: backend-neutral HTTP/3 UDP passthrough.
- `reverse-websocket-upstream.yaml`: reverse publish to `ws://` and `wss://` upstreams.
- `reverse-http-guard-lite.yaml`: reusable reverse-edge HTTP guard profile.
- `reverse-rpc-aware-policy.yaml`: response-stage RPC-aware policy for gRPC, Connect, and gRPC-Web.

## 04-http3-and-masque

- `forward-http3-connect-udp.yaml`: safe-default HTTP/3 CONNECT-UDP / MASQUE.
- `forward-http3-connect-udp-local-dev-direct.yaml`: loopback-only local-dev MASQUE.
- `forward-http3-connect-udp-uri-template.yaml`: strict URI-template-controlled CONNECT-UDP.
- `forward-http3-extended-connect.yaml`: generic non-WebTransport extended CONNECT.
- `forward-http3-webtransport.yaml`: WebTransport relay.

## 05-caching

- `forward-redis.yaml`: Redis-backed forward cache.
- `forward-redis-unix.yaml`: Redis UNIX-socket forward cache.
- `forward-redis-public-cookie.yaml`: public cookie-bearing shared-cache policy.
- `reverse-http-backend.yaml`: HTTP object-store reverse cache backend.
- `reverse-rediss-remote.yaml`: TLS Redis reverse cache backend.

## 06-local-response

- `all-modes-policy.yaml`: local responses across forward, transparent, and reverse.
- `forward-debug.yaml`: forward health/debug local responses.
- `reverse-maintenance.yaml`: reverse maintenance/status responses.
- `transparent-captive-portal.yaml`: transparent captive-portal response flow.

## 07-observability-debug

- `observability-high-detail.yaml`: detailed observability and capture exporter.
- `observability-otel-rich-audit.yaml`: OTLP, metrics allowlist, and rich audit fields.
- `forward-trace-debug.yaml`: loopback TRACE diagnostics.
- `http-modules-advanced.yaml`: canonical HTTP module configuration.
- `forward-header-rewrite.yaml`: request/response header mutation.
- `forward-websocket-debug.yaml`: WebSocket debugging/routing.
- `forward-ftp-over-http.yaml`: FTP-over-HTTP diagnostics.

## 08-performance-and-xdp

- `runtime-multicore-scaling.yaml`: runtime scaling knobs and HTTP/3 concurrency caps.
- `connection-filter-early-drop.yaml`: listener/reverse connection filters.
- `xdp-forward-reverse-proxy-metadata.yaml`: PROXY v2 metadata on forward/reverse.
- `xdp-transparent-proxy-metadata.yaml`: PROXY v2 metadata on transparent path.

## 09-composition

- `multi-mode-office-gateway.yaml`: one config spanning forward, transparent, and reverse.
- `include-forward.yaml`: include-composed forward profile.
- `include-transparent-reverse.yaml`: include-composed transparent plus reverse profile.

## 10-operator-customization

- `operator-tuning.yaml`: identity/messages/operator-facing tuning.

## 11-transparent-intercept

- `transparent-macos-windows-fallback.yaml`: non-Linux transparent fallback routing.
- `transparent-mitm-selective.yaml`: transparent TLS MITM selection.

## 12-ipc-gateway

- `qpx.yaml`: reverse to `qpxf` over shared-memory IPC.
- `qpxf.yaml`: `qpxf` executor with repo-local fixture handlers.
- `qpx-tcp.yaml`: reverse to `qpxf` over TCP IPC.
- `qpxf-tcp.yaml`: TCP `qpxf` executor paired with `qpx-tcp.yaml`.

## 99-test-fixtures

- `e2e-forward.yaml`: forward test fixture.
- `e2e-reverse.yaml`: reverse test fixture.
- `e2e-transparent.yaml`: transparent test fixture.

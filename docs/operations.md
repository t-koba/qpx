# Operations

This page collects operational details that are useful after the first local
run: reload behavior, binary upgrade, runtime tuning, capture safety, and
security QA coverage.

## Hot Reload

`qpxd` watches every configured `--config` file, all resolved `include` targets,
and any `named_sets[].file` inputs. Compatible changes rebuild the in-memory
runtime state in place. Listener/reverse bind-shape or acceptor startup changes
trigger an in-process restart of the listener/reverse server set rather than a
full daemon restart.

Restart is required for:

- `state_dir`
- `system_log`, `access_log`, `audit_log`
- `acme`, `otel`, `metrics`
- `identity.metrics_prefix`
- `runtime.worker_threads`
- `runtime.max_blocking_threads`

In-process listener/server-set restart is used for:

- `runtime.acceptor_tasks_per_listener`
- `runtime.reuse_port`
- `runtime.tcp_backlog`
- listener names, listen addresses, mode, XDP, and HTTP/3 startup settings
- reverse names, listen addresses, TLS, and HTTP/3 startup settings

Existing accepted TCP connections continue draining on the old runtime
generation while replacement listeners start with the new config.

## Binary Upgrade

`qpxd` supports zero-downtime binary replacement for the listener socket layer.

- Unix: send `SIGUSR2` to the parent process.
- Windows: run `qpxd upgrade --pid <parent-pid>`.

The parent process hands active TCP listening sockets, UDP listening sockets,
metrics and ACME listeners, and QUIC broker control sockets to the child. New
TCP accepts move to the child after readiness; existing TCP sessions continue on
the old generation until drained.

Existing transparent UDP sessions and reverse HTTP/3 passthrough sessions are
exported to the child with their connected upstream UDP sockets. Forward HTTP/3
sessions and reverse HTTP/3 terminate sessions remain on the parent generation
behind a parent-child QUIC broker while the child accepts new handshakes.

This is a binary handoff path, not a config reload path. Use normal file-watch
reload for compatible config edits.

## Runtime Notes

<details>
<summary>Transparent mode</summary>

- Linux uses `SO_ORIGINAL_DST`; macOS/Windows fall back to protocol metadata
  routing through TLS SNI, HTTP `Host`, or PROXY metadata.
- The transparent path applies L7 rules for HTTP and supports opt-in TLS MITM
  for HTTPS flows.
- `xdp.metadata_mode: proxy-v2` allows transparent destination recovery from
  PROXY metadata, useful with XDP/L4 frontends.

</details>

<details>
<summary>RFC alignment hardening</summary>

- Host/authority validation rejects duplicate, missing, and mismatched values.
- No-body response rules are enforced for `HEAD`, `1xx`, `204`, `304`, and
  successful `CONNECT`.
- `Via` is version-aware per proxied hop.
- Reverse TLS enforces SNI vs Host/authority matching by default through
  `enforce_sni_host_match: true`.
- Proxy authentication headers are stripped from forwarded hops.
- QUIC 0-RTT is disabled by default in HTTP/3 listeners.

</details>

<details>
<summary>XDP metadata integration</summary>

- Forward, reverse, and transparent listeners can consume PROXY v2 metadata via
  `xdp.enabled: true` and `metadata_mode: proxy-v2`.
- Source address metadata is used for `src_ip` rule evaluation.
- When `xdp.enabled: true`, `trusted_peers` is required and metadata is accepted
  only from trusted peer CIDRs.

</details>

<details>
<summary>Runtime multicore scaling</summary>

- `runtime.worker_threads` and `runtime.max_blocking_threads` tune Tokio
  parallelism.
- `runtime.acceptor_tasks_per_listener` plus `runtime.reuse_port` enable
  multi-socket accept fan-out.
- `runtime.tcp_backlog` controls listen queue depth.
- `runtime.max_h3_streams_per_connection` caps concurrent HTTP/3 streams and
  associated WebTransport sessions per QUIC connection.
- `runtime.upstream_http_timeout_ms` is the default dial/request timeout for
  upstream HTTP and reverse route proxying.
- `runtime.max_observed_request_body_bytes` and
  `runtime.max_observed_response_body_bytes` are hard caps for policy, guard,
  RPC, and response-rule body observation.
- `runtime.trace_enabled` controls local `TRACE` loop-back availability.
- `runtime.trace_reflect_all_headers` controls whether `TRACE` reflects every
  request header or strips sensitive/hop-by-hop fields.

</details>

<details>
<summary>Metrics, identity, and messages</summary>

- `metrics.listen` and `metrics.path` configure the Prometheus endpoint.
  Non-loopback binding requires an explicit `metrics.allow` CIDR allowlist.
- `identity.proxy_name` controls Via hop entries.
- `identity.auth_realm` controls auth challenges.
- `identity.metrics_prefix` controls metric names.
- `identity.generated_user_agent` controls proxy-originated request
  `User-Agent`; keep it low-information.
- `messages.*` controls fixed response bodies for policy/error paths.

</details>

## Security QA

qpx treats parser, TLS sniffing, shared-memory capture, and policy matching code
as security-sensitive. CI gates formatting, typos, sensitive artifact checks,
documentation warnings, unused dependency checks, sample config validation,
end-to-end tests, multi-platform builds, feature-matrix clippy, RustSec audit,
CodeQL, AddressSanitizer smoke tests, and fuzz smoke tests.

Security-focused CI includes:

- CodeQL analysis for GitHub Actions and Rust sources.
- AddressSanitizer smoke tests for shared-memory ring and upgrade readiness
  code paths.
- Short `cargo-fuzz` jobs for shared-memory ring operations, PROXY v2 parsing,
  HTTP/1 request-head parsing, QPACK decoding, and TLS ClientHello sniffing.

## Helper Scripts

- `scripts/check-config-samples.sh`: validates sample configs.
- `scripts/e2e-control-plane.sh`: exercises Linux reload and upgrade handoff.
- `scripts/e2e-control-plane.ps1`: exercises Windows reload and upgrade
  handoff.
- `scripts/e2e-control-plane-soak.sh`: keeps loopback traffic flowing across
  reload, restart-required reload, and binary upgrade.
- `scripts/irq-affinity-plan.sh`: Linux IRQ/CPU affinity planner for NIC queue
  distribution. See [`docs/multicore-xdp-scaling.md`](multicore-xdp-scaling.md).

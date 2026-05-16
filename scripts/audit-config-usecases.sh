#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

failures=0

assert_contains() {
  local file="$1"
  local description="$2"
  local pattern="$3"

  if ! grep -Eq "$pattern" "$ROOT_DIR/$file"; then
    printf 'config semantic audit failed: %s: missing %s (%s)\n' "$file" "$description" "$pattern" >&2
    failures=$((failures + 1))
  fi
}

assert_all() {
  local file="$1"
  shift
  while [ "$#" -gt 0 ]; do
    assert_contains "$file" "$1" "$2"
    shift 2
  done
}

assert_all config/qpx.example.yaml \
  "forward edge" 'kind:[[:space:]]*forward' \
  "transparent edge" 'kind:[[:space:]]*transparent' \
  "reverse edge" 'kind:[[:space:]]*reverse' \
  "default deny" 'default_action:[[:space:]]*$' \
  "TLS inspection" 'tls_inspection:' \
  "HTTP/3 CONNECT-UDP" 'connect_udp:' \
  "capture exporter" 'exporter:' \
  "cache backend" 'kind:[[:space:]]*redis' \
  "HTTP modules" 'http_modules:' \
  "response rules" 'response_rules:'

assert_all config/fragments/base-observability.yaml \
  "base telemetry" 'telemetry:' \
  "metrics listener" 'metrics:' \
  "exporter defaults" 'exporter:'
assert_all config/fragments/forward-listener.yaml \
  "forward listener fragment" 'kind:[[:space:]]*forward' \
  "default deny" 'default_action:[[:space:]]*$' \
  "direct internal bypass" 'type:[[:space:]]*direct' \
  "shared upstream proxy" 'upstream:[[:space:]]*shared-egress'
assert_all config/fragments/transparent-reverse.yaml \
  "transparent listener fragment" 'kind:[[:space:]]*transparent' \
  "reverse listener fragment" 'kind:[[:space:]]*reverse' \
  "default deny" 'default_action:[[:space:]]*$' \
  "reverse upstream target" 'type:[[:space:]]*upstream'

assert_all config/usecases/01-getting-started/forward-minimal.yaml \
  "forward listener" 'kind:[[:space:]]*forward' \
  "default deny" 'default_action:[[:space:]]*$' \
  "explicit direct allow" 'type:[[:space:]]*direct'
assert_all config/usecases/01-getting-started/forward-local-dev-direct.yaml \
  "loopback listen" 'listen:[[:space:]]*"?127\.0\.0\.1:' \
  "development direct default" 'type:[[:space:]]*direct'
assert_all config/usecases/01-getting-started/reverse-basic-http.yaml \
  "reverse listener" 'kind:[[:space:]]*reverse' \
  "upstream target" 'type:[[:space:]]*upstream'
assert_all config/usecases/01-getting-started/transparent-linux-original-dst.yaml \
  "transparent listener" 'kind:[[:space:]]*transparent' \
  "original destination flow" 'original_dst|transparent'

assert_all config/usecases/02-secure-egress/forward-upstream-chain.yaml \
  "named upstream" '^upstreams:' \
  "proxy action" 'type:[[:space:]]*proxy' \
  "upstream reference" 'upstream:'
assert_all config/usecases/02-secure-egress/forward-local-auth-basic-digest.yaml \
  "local auth users" 'auth:' \
  "cleartext password sample" 'password:' \
  "digest HA1 sample" 'ha1:'
assert_all config/usecases/02-secure-egress/forward-ldap-group-policy.yaml \
  "LDAP source" 'ldap:' \
  "LDAP user filter" 'user_filter:' \
  "LDAP group filter" 'group_filter:' \
  "LDAP group attribute" 'group_attr:'
assert_all config/usecases/02-secure-egress/forward-trusted-identity-ext-authz.yaml \
  "trusted identity source" 'trusted_headers|trusted_header' \
  "external authorization" 'ext_authz'
assert_all config/usecases/02-secure-egress/forward-signed-assertion-policy.yaml \
  "signed assertion source" 'signed_assertion' \
  "subject mapping from sub" 'user_from_sub' \
  "external authorization" 'ext_authz'
assert_all config/usecases/02-secure-egress/forward-tls-inspection-selective.yaml \
  "TLS inspection" 'tls_inspection:' \
  "inspect action" 'type:[[:space:]]*inspect' \
  "direct bypass action" 'type:[[:space:]]*direct' \
  "block action" 'type:[[:space:]]*block'
assert_all config/usecases/02-secure-egress/forward-adblock-privacy.yaml \
  "ad/tracker matchers" 'doubleclick|googlesyndication|adservice' \
  "local block response" 'local_response|type:[[:space:]]*respond'
assert_all config/usecases/02-secure-egress/forward-firewall-style-policy.yaml \
  "source IP policy" 'src_ip:' \
  "destination port policy" 'dst_port:' \
  "header policy" 'headers:' \
  "controlled egress action" 'type:[[:space:]]*(proxy|inspect)'
assert_all config/usecases/02-secure-egress/forward-authenticated-upstream.yaml \
  "authentication" 'auth:' \
  "upstream proxy action" 'type:[[:space:]]*proxy' \
  "upstream reference" 'upstream:'
assert_all config/usecases/02-secure-egress/forward-rate-limit-profiles.yaml \
  "reusable rate limit profiles" 'rate_limit_profiles:' \
  "request limits" 'requests:' \
  "traffic limits" 'traffic:' \
  "session limits" 'sessions:' \
  "external authz enforcement" 'ext_authz'
assert_all config/usecases/02-secure-egress/forward-destination-intelligence-and-trust.yaml \
  "named destination sets" 'named_sets:' \
  "file-backed feed" 'file:' \
  "destination policy" 'destination' \
  "upstream trust" 'tls_trust|upstream_trust|trust_profiles' \
  "discovery policy" 'discovery|resolve|resolver'

assert_all config/usecases/03-service-publishing/reverse-load-balance-retry.yaml \
  "load balancing" 'lb:' \
  "route resilience" 'resilience:' \
  "health check" 'health_check:'
assert_all config/usecases/03-service-publishing/reverse-path-rewrite.yaml \
  "path rewrite" 'path_rewrite|strip_prefix|add_prefix'
assert_all config/usecases/03-service-publishing/reverse-advanced-routing.yaml \
  "header rewrite" 'headers:' \
  "weighted backend target" 'type:[[:space:]]*weighted' \
  "mirroring" 'mirrors?:' \
  "regex rewrite" 'regex:'
assert_all config/usecases/03-service-publishing/reverse-affinity-response-policy.yaml \
  "affinity" 'affinity|stickiness' \
  "response rules" 'response_rules:' \
  "local fallback" 'local_response:' \
  "mirroring" 'mirror' \
  "cache policy" 'cache:'
assert_all config/usecases/03-service-publishing/reverse-cert-and-size-aware-policy.yaml \
  "client certificate matcher" 'client_cert' \
  "request size matcher" 'request_size' \
  "response size matcher" 'response_size' \
  "upstream certificate matcher" 'upstream_cert'
assert_all config/usecases/03-service-publishing/reverse-discovery-srv.yaml \
  "SRV discovery" 'srv|SRV|dns' \
  "health check" 'health_check:' \
  "resilience" 'resilience:'
assert_all config/usecases/03-service-publishing/reverse-mtls-identity-routing.yaml \
  "client certificate TLS" 'client_ca|client_cert' \
  "mTLS identity source" 'mtls_subject' \
  "SAN URI mapping" 'user_from_san_uri_prefix' \
  "subject CN mapping" 'user_from_subject_cn'
assert_all config/usecases/03-service-publishing/reverse-sni-host-exceptions.yaml \
  "SNI/Host exceptions" 'sni_host_exceptions:' \
  "SNI/Host enforcement" 'enforce_sni_host_match:'
assert_all config/usecases/03-service-publishing/reverse-tls-termination.yaml \
  "TLS termination" '^  tls:' \
  "certificate path" 'cert:' \
  "key path" 'key:' \
  "HTTP upstream" 'http://'
assert_all config/usecases/03-service-publishing/reverse-tls-termination-native-pkcs12.yaml \
  "PKCS#12 identity" 'pkcs12:' \
  "PKCS#12 password env" 'pkcs12_password_env:'
assert_all config/usecases/03-service-publishing/reverse-tls-acme-letsencrypt.yaml \
  "ACME config" 'acme:' \
  "ACME directory override" 'directory_url:'
assert_all config/usecases/03-service-publishing/reverse-tls-passthrough-sni.yaml \
  "TLS passthrough routes" 'tls_passthrough_routes:' \
  "SNI matching" 'sni:'
assert_all config/usecases/03-service-publishing/reverse-http2-tls.yaml \
  "HTTP/2 signal" 'http2|h2|alpn' \
  "TLS config" '^  tls:'
assert_all config/usecases/03-service-publishing/reverse-http3-terminate.yaml \
  "HTTP/3 config" 'http3:' \
  "TLS config" '^  tls:' \
  "upstream target" 'target:'
assert_all config/usecases/03-service-publishing/reverse-http3-passthrough.yaml \
  "HTTP/3 config" 'http3:' \
  "passthrough upstreams" 'passthrough_upstreams:'
assert_all config/usecases/03-service-publishing/reverse-websocket-upstream.yaml \
  "WebSocket upstream" 'ws://|wss://' \
  "health check" 'health_check:'
assert_all config/usecases/03-service-publishing/reverse-http-guard-lite.yaml \
  "guard profile definition" 'guard_profiles:' \
  "guard profile attachment" 'http_guard_profile:'
assert_all config/usecases/03-service-publishing/reverse-rpc-aware-policy.yaml \
  "RPC matcher" 'rpc:' \
  "RPC protocol" 'grpc|connect' \
  "protocol-correct local response" 'local_response'

assert_all config/usecases/04-http3-and-masque/forward-http3-connect-udp.yaml \
  "HTTP/3 config" 'http3:' \
  "CONNECT-UDP config" 'connect_udp:' \
  "upstream MASQUE chaining" 'type:[[:space:]]*proxy'
assert_all config/usecases/04-http3-and-masque/forward-http3-connect-udp-local-dev-direct.yaml \
  "HTTP/3 config" 'http3:' \
  "CONNECT-UDP config" 'connect_udp:' \
  "direct local development action" 'type:[[:space:]]*direct'
assert_all config/usecases/04-http3-and-masque/forward-http3-connect-udp-uri-template.yaml \
  "CONNECT-UDP config" 'connect_udp:' \
  "URI template enforcement" 'uri_template:'
assert_all config/usecases/04-http3-and-masque/forward-http3-extended-connect.yaml \
  "extended CONNECT rules" 'extended_connect|CONNECT' \
  "direct relay action" 'type:[[:space:]]*direct' \
  "upstream chained action" 'type:[[:space:]]*proxy'
assert_all config/usecases/04-http3-and-masque/forward-http3-webtransport.yaml \
  "WebTransport surface" 'webtransport' \
  "transport-aware shaping" 'rate_limit:'

assert_all config/usecases/05-caching/forward-redis.yaml \
  "Redis backend" 'redis://' \
  "cache policy" 'cache:'
assert_all config/usecases/05-caching/forward-redis-unix.yaml \
  "Redis UNIX backend" 'redis\+unix://' \
  "cache policy" 'cache:'
assert_all config/usecases/05-caching/forward-redis-public-cookie.yaml \
  "Redis backend" 'redis://' \
  "public cookie behavior" 'public|cookie|Cookie' \
  "response cache policy" 'response_rules:'
assert_all config/usecases/05-caching/reverse-http-backend.yaml \
  "HTTP cache backend" 'kind:[[:space:]]*http' \
  "cache policy" 'cache:'
assert_all config/usecases/05-caching/reverse-rediss-remote.yaml \
  "Redis TLS backend" 'rediss://' \
  "cache policy" 'cache:'

assert_all config/usecases/06-local-response/all-modes-policy.yaml \
  "forward edge" 'kind:[[:space:]]*forward' \
  "transparent edge" 'kind:[[:space:]]*transparent' \
  "reverse edge" 'kind:[[:space:]]*reverse' \
  "local responses" 'local_response|type:[[:space:]]*respond'
assert_all config/usecases/06-local-response/forward-debug.yaml \
  "forward edge" 'kind:[[:space:]]*forward' \
  "local responses" 'local_response|type:[[:space:]]*respond'
assert_all config/usecases/06-local-response/reverse-maintenance.yaml \
  "reverse edge" 'kind:[[:space:]]*reverse' \
  "maintenance local response" 'type:[[:space:]]*local_response'
assert_all config/usecases/06-local-response/transparent-captive-portal.yaml \
  "transparent edge" 'kind:[[:space:]]*transparent' \
  "captive local response" 'local_response|type:[[:space:]]*respond'

assert_all config/usecases/07-observability-debug/observability-high-detail.yaml \
  "system log" 'system_log:' \
  "access log" 'access_log:' \
  "audit log" 'audit_log:' \
  "metrics" 'metrics:' \
  "exporter" 'exporter:' \
  "capture" 'capture:'
assert_all config/usecases/07-observability-debug/observability-otel-rich-audit.yaml \
  "OTel config" 'otel:' \
  "metrics allowlist" 'allow:' \
  "audit field coverage" 'audit_log:' \
  "external authz" 'ext_authz'
assert_all config/usecases/07-observability-debug/forward-trace-debug.yaml \
  "TRACE runtime enabled" 'trace_enabled:[[:space:]]*true' \
  "TRACE header safety" 'trace_reflect_all_headers:[[:space:]]*false'
assert_all config/usecases/07-observability-debug/http-modules-advanced.yaml \
  "HTTP modules" 'http_modules:' \
  "cache purge module" 'type:[[:space:]]*cache_purge' \
  "subrequest module" 'type:[[:space:]]*subrequest' \
  "compression module" 'type:[[:space:]]*response_compression' \
  "module ordering" 'order:'
assert_all config/usecases/07-observability-debug/forward-header-rewrite.yaml \
  "request header rewrite" 'request_(set|add|remove)' \
  "response header rewrite" 'response_(set|add|remove)'
assert_all config/usecases/07-observability-debug/forward-websocket-debug.yaml \
  "WebSocket match" 'websocket|Upgrade|upgrade' \
  "direct WebSocket action" 'type:[[:space:]]*direct'
assert_all config/usecases/07-observability-debug/forward-ftp-over-http.yaml \
  "FTP method allowlist" 'ftp-method|FTP|CONNECT' \
  "method blocking" 'block'

assert_all config/usecases/08-performance-and-xdp/runtime-multicore-scaling.yaml \
  "runtime thread tuning" 'worker_threads|max_blocking_threads|reuse_port|tcp_backlog' \
  "HTTP/3 stream cap" 'max_h3_streams_per_connection' \
  "upstream timeout" 'upstream_http_timeout_ms'
assert_all config/usecases/08-performance-and-xdp/connection-filter-early-drop.yaml \
  "connection filter" 'connection_filter:' \
  "early drop action" 'action:[[:space:]]*$'
assert_all config/usecases/08-performance-and-xdp/xdp-forward-reverse-proxy-metadata.yaml \
  "XDP metadata" 'xdp:' \
  "PROXY v2 metadata mode" 'metadata_mode:[[:space:]]*proxy-v2' \
  "trusted peers" 'trusted_peers:'
assert_all config/usecases/08-performance-and-xdp/xdp-transparent-proxy-metadata.yaml \
  "XDP metadata" 'xdp:' \
  "PROXY v2 metadata mode" 'metadata_mode:[[:space:]]*proxy-v2' \
  "trusted peers" 'trusted_peers:'

assert_all config/usecases/09-composition/include-forward.yaml \
  "include composition" '^include:'
assert_all config/usecases/09-composition/include-transparent-reverse.yaml \
  "include composition" '^include:'
assert_all config/usecases/09-composition/multi-mode-office-gateway.yaml \
  "forward edge" 'kind:[[:space:]]*forward' \
  "transparent edge" 'kind:[[:space:]]*transparent' \
  "reverse edge" 'kind:[[:space:]]*reverse'

assert_all config/usecases/10-operator-customization/operator-tuning.yaml \
  "identity customization" 'identity:' \
  "message customization" 'messages:' \
  "User-Agent customization" 'user_agent'

assert_all config/usecases/11-transparent-intercept/transparent-macos-windows-fallback.yaml \
  "transparent edge" 'kind:[[:space:]]*transparent' \
  "safe default deny" 'default_action:[[:space:]]*$'
assert_all config/usecases/11-transparent-intercept/transparent-mitm-selective.yaml \
  "TLS inspection" 'tls_inspection:' \
  "selective inspect action" 'type:[[:space:]]*inspect'

assert_all config/usecases/12-ipc-gateway/qpx.yaml \
  "IPC target" 'type:[[:space:]]*ipc' \
  "shared-memory IPC mode" 'mode:[[:space:]]*shm'
assert_all config/usecases/12-ipc-gateway/qpx-tcp.yaml \
  "IPC target" 'type:[[:space:]]*ipc' \
  "TCP IPC mode" 'mode:[[:space:]]*tcp'
assert_all config/usecases/12-ipc-gateway/qpxf.yaml \
  "CGI handler" 'type:[[:space:]]*cgi' \
  "WASM handler" 'type:[[:space:]]*wasm'
assert_all config/usecases/12-ipc-gateway/qpxf-tcp.yaml \
  "explicit insecure TCP opt-in" 'allow_insecure_tcp:[[:space:]]*true' \
  "CGI handler" 'type:[[:space:]]*cgi' \
  "WASM handler" 'type:[[:space:]]*wasm'
assert_all config/usecases/12-ipc-gateway/qpxf-fastcgi.yaml \
  "FastCGI backend" 'type:[[:space:]]*fastcgi' \
  "SCGI backend" 'type:[[:space:]]*scgi'

assert_all config/usecases/99-test-fixtures/e2e-forward.yaml \
  "forward fixture" 'kind:[[:space:]]*forward'
assert_all config/usecases/99-test-fixtures/e2e-reverse.yaml \
  "reverse fixture" 'kind:[[:space:]]*reverse'
assert_all config/usecases/99-test-fixtures/e2e-transparent.yaml \
  "transparent fixture" 'kind:[[:space:]]*transparent'

if [ "$failures" -ne 0 ]; then
  exit 1
fi

echo "[CONFIG] use-case semantic audit passed"

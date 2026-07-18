#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

while IFS= read -r script; do
  bash -n "$script"
done < <(find scripts -type f -name '*.sh' -print)

require() {
  local file="$1"
  local needle="$2"
  if ! grep -Fq -- "$needle" "$file"; then
    echo "ci acceptance gate missing in ${file}: ${needle}" >&2
    exit 1
  fi
}

reject_step_value() {
  local file="$1"
  local step_name="$2"
  local needle="$3"
  python3 - "$file" "$step_name" "$needle" <<'PY'
import sys

path, step_name, needle = sys.argv[1:4]
lines = open(path, "r", encoding="utf-8").readlines()
marker = f"- name: {step_name}"
for index, line in enumerate(lines):
    if line.strip() != marker:
        continue
    indent = len(line) - len(line.lstrip())
    end = index + 1
    while end < len(lines):
        candidate = lines[end]
        candidate_indent = len(candidate) - len(candidate.lstrip())
        if candidate_indent == indent and candidate.strip().startswith("- name:"):
            break
        end += 1
    if any(needle in candidate for candidate in lines[index:end]):
        raise SystemExit(
            f"{path}: step {step_name!r} contains forbidden value {needle!r}"
        )
    break
else:
    raise SystemExit(f"{path}: workflow step not found: {step_name}")
PY
}

require_json_number_at_least() {
  local file="$1"
  local path="$2"
  local minimum="$3"
  python3 - "$file" "$path" "$minimum" <<'PY'
import json
import math
import sys

file_name, dotted_path, minimum_raw = sys.argv[1:4]
with open(file_name, "r", encoding="utf-8") as handle:
    value = json.load(handle)
for component in dotted_path.split("."):
    if not isinstance(value, dict) or component not in value:
        raise SystemExit(f"{file_name}: missing numeric objective {dotted_path}")
    value = value[component]
try:
    number = float(value)
    minimum = float(minimum_raw)
except (TypeError, ValueError):
    raise SystemExit(f"{file_name}: objective {dotted_path} is not numeric")
if not math.isfinite(number) or number < minimum:
    raise SystemExit(
        f"{file_name}: objective {dotted_path}={number} is below required {minimum}"
    )
PY
}

require_json_number_at_most() {
  local file="$1"
  local path="$2"
  local maximum="$3"
  python3 - "$file" "$path" "$maximum" <<'PY'
import json
import math
import sys

file_name, dotted_path, maximum_raw = sys.argv[1:4]
with open(file_name, "r", encoding="utf-8") as handle:
    value = json.load(handle)
for component in dotted_path.split("."):
    if not isinstance(value, dict) or component not in value:
        raise SystemExit(f"{file_name}: missing numeric objective {dotted_path}")
    value = value[component]
try:
    number = float(value)
    maximum = float(maximum_raw)
except (TypeError, ValueError):
    raise SystemExit(f"{file_name}: objective {dotted_path} is not numeric")
if not math.isfinite(number) or number > maximum:
    raise SystemExit(
        f"{file_name}: objective {dotted_path}={number} exceeds allowed {maximum}"
    )
PY
}

check_deprecated_node_actions() {
  local deprecated
  deprecated="$(grep -REn \
    -e 'actions/(upload|download)-artifact@v([1-5])([^0-9]|$)' \
    -e 'actions-rs/' \
    -e 'bnjbvr/cargo-machete@' \
    .github/workflows || true)"
  if [ -n "$deprecated" ]; then
    echo "workflow contains an action with a deprecated Node.js runtime:" >&2
    echo "$deprecated" >&2
    exit 1
  fi
}

require docs/http-rfc-compliance.md '# qpx HTTP RFC compliance matrix'
require docs/http-rfc-compliance.md '## Complete RFC inventory'
require docs/http-rfc-compliance.md '## Product-role applicability'
require docs/http-rfc-compliance.md 'native'
require docs/http-rfc-compliance.md 'external-authority'
require docs/http-rfc-compliance.md 'transport-library-with-contract'

check_deny_skip_baseline() {
  local max_entries=53
  local entries
  entries="$(awk '
    $0 ~ /^skip = \[/ { in_skip = 1; next }
    in_skip && $0 ~ /^\]/ { in_skip = 0; next }
    in_skip && $0 ~ /^  \{ crate = / {
      entries += 1
      if ($0 !~ /reason = /) missing_reason += 1
    }
    END { printf "%d %d\n", entries, missing_reason }
  ' deny.toml)"
  local count missing_reason
  count="${entries%% *}"
  missing_reason="${entries##* }"
  if [ "$count" -gt "$max_entries" ]; then
    echo "deny.toml skip baseline exceeded: ${count} > ${max_entries}" >&2
    exit 1
  fi
  if [ "$missing_reason" -ne 0 ]; then
    echo "deny.toml skip entries missing reason: ${missing_reason}" >&2
    exit 1
  fi
}

require Cargo.toml 'rust-version = "1.96"'
require Cargo.toml 'dead_code = "deny"'
require Cargo.toml 'unused = "deny"'
require Cargo.toml 'unsafe_op_in_unsafe_fn = "deny"'
require Cargo.toml 'undocumented_unsafe_blocks = "deny"'
require qpx-acme/src/lib.rs '#![warn(missing_docs)]'
require qpx-auth/src/lib.rs '#![warn(missing_docs)]'
require qpx-auth/src/lib.rs '#![forbid(unsafe_code)]'
require qpx-h3/src/lib.rs '#![warn(missing_docs)]'
require qpx-h3/src/lib.rs '#![forbid(unsafe_code)]'
require qpx-h3/src/lib.rs 'pub enum H3Error'
require xtask/src/checks.rs 'pub trait method'
require xtask/src/checks.rs 'type_path_is_anyhow_result'
require xtask/src/checks.rs 'type_contains_anyhow_error'
require xtask/src/checks.rs 'pub struct field'
require xtask/src/checks.rs 'pub enum variant'
require xtask/src/checks.rs 'pub trait associated type'
require xtask/src/checks.rs 'collect_public_anyhow_items'
require xtask/src/checks.rs 'pub use'
require xtask/src/checks.rs 'pub async fn'
require xtask/src/checks.rs 'pub(crate) async fn'
require xtask/src/checks.rs 'check_workspace_lint_posture'
require xtask/src/checks.rs 'workspace lint posture violations'
require xtask/src/checks.rs 'check_dependency_policy_config'
require xtask/src/checks.rs 'dependency policy config violations'
require xtask/src/checks.rs 'DENY_SKIP_ENTRY_MAX'
require xtask/src/checks.rs 'RawMetricMacroVisitor'
require xtask/src/checks.rs 'join("tests")'
require xtask/src/checks.rs 'scan_duplicate_helpers_in_src'
require xtask/src/checks.rs 'DuplicateHelperScope::CfgTestOnly'
require xtask/src/checks.rs 'check_architecture_baselines'
require xtask/src/checks.rs 'DISPATCH_PARALLEL_FILE_BASELINES'
require xtask/src/checks.rs 'check_dispatch_access_commonality_baseline'
require xtask/src/checks.rs 'dispatch access commonality baseline exceeded'
require xtask/src/checks.rs 'check_dispatch_audit_builder_commonality'
require xtask/src/checks.rs 'dispatch audit builder commonality violations'
require xtask/src/checks.rs 'check_dispatch_cache_collapse_commonality'
require xtask/src/checks.rs 'dispatch cache collapse commonality baseline exceeded'
require xtask/src/checks.rs 'check_dispatch_limit_response_commonality'
require xtask/src/checks.rs 'dispatch limit response commonality baseline exceeded'
require xtask/src/checks.rs 'check_dispatch_annotated_local_response_commonality'
require xtask/src/checks.rs 'dispatch annotated local response commonality baseline exceeded'
require xtask/src/checks.rs 'check_dispatch_max_forwards_response_commonality'
require xtask/src/checks.rs 'dispatch max-forwards response commonality baseline exceeded'
require xtask/src/checks.rs 'check_dispatch_body_too_large_response_commonality'
require xtask/src/checks.rs 'dispatch body-too-large response commonality baseline exceeded'
require xtask/src/checks.rs 'check_response_capture_after_finalize'
require xtask/src/checks.rs 'response capture after-finalization violations'
require xtask/src/checks.rs 'check_proxy_authorization_header_boundary'
require xtask/src/checks.rs 'proxy authorization header boundary violations'
require xtask/src/checks.rs 'check_reverse_response_rules_dispatch_boundary'
require xtask/src/checks.rs 'reverse response rules dispatch boundary violations'
require xtask/src/checks.rs 'check_h3_origin_pool_load_semantics'
require xtask/src/checks.rs 'effective load must not double count open queue depth'
require xtask/src/checks.rs 'POOL_STRUCT_BASELINE_MAX'
require xtask/src/checks.rs 'QPXD_TLS_TYPE_BASELINE_MAX'
require xtask/src/checks.rs 'DIRECT_HEADER_MUTATION_BASELINE_MAX'
require xtask/src/checks.rs 'DIRECT_RESPONSE_POLICY_ENGINE_BASELINE_MAX'
require xtask/src/checks.rs 'count_direct_response_transform_files'
require xtask/src/checks.rs 'apply_response_headers('
require xtask/src/checks.rs 'check_canonical_config_loader_baseline'
require xtask/src/checks.rs 'canonical config loader baseline violations'
require xtask/src/checks.rs 'sample config guard must load qpx.example and qpxd usecases through the real loader'
require xtask/src/checks.rs 'check_manual_session_shard_modulo_baseline'
require xtask/src/checks.rs 'manual session shard modulo baseline exceeded'
require xtask/src/checks.rs 'check_shard_initialization_helper_baseline'
require xtask/src/checks.rs 'shard initialization helper baseline exceeded'
require xtask/src/checks.rs 'check_h3_open_queue_backpressure_baseline'
require xtask/src/checks.rs 'H3 origin open queue backpressure baseline exceeded'
require xtask/src/checks.rs 'request open uses sender mutex'
require xtask/src/checks.rs 'check_reverse_mirror_spawn_backpressure'
require xtask/src/checks.rs 'reverse mirror spawn backpressure baseline exceeded'
require xtask/src/checks.rs 'check_decision_service_response_buffering'
require xtask/src/checks.rs 'decision_service response buffering baseline exceeded'
require xtask/src/checks.rs 'missing cancellable bounded decision_service response collector'
require xtask/src/checks.rs 'decision_service response collector uses non-cancellable blocking parser'
require xtask/src/checks.rs 'check_reverse_retry_template_bounded_body'
require xtask/src/checks.rs 'reverse retry template bounded-body baseline exceeded'
require xtask/src/checks.rs 'check_qpxr_capture_publish_order'
require xtask/src/checks.rs 'qpxr capture publish order violations'
require xtask/src/checks.rs 'check_qpxf_ipc_cleanup_backpressure'
require xtask/src/checks.rs 'qpxf IPC cleanup/backpressure violations'
require xtask/src/checks.rs 'check_secure_file_write_boundaries'
require xtask/src/checks.rs 'secure file write boundary violations'
require xtask/src/checks.rs 'check_ci_acceptance_gates'
require xtask/src/checks.rs 'CI acceptance gate violations'
require xtask/src/checks.rs 'check_public_api_snapshot_script'
require xtask/src/checks.rs 'public API snapshot script violations'
require xtask/src/checks.rs 'check_security_qa_fuzz_targets'
require xtask/src/checks.rs 'security QA fuzz target violations'
require xtask/src/checks.rs 'check_metric_cardinality_policy'
require xtask/src/checks.rs 'metrics cardinality policy violations'
require xtask/src/checks.rs 'PLAN_P3_FUZZ_TARGETS'
require xtask/src/checks.rs 'advisory structure LOC budget notices'
require xtask/src/checks.rs 'advisory workspace total LOC budget notices'
require qpx-observability/src/lib.rs '#![warn(missing_docs)]'
require qpx-wasm/src/lib.rs '#![warn(missing_docs)]'
require qpx-wasm/src/lib.rs '#![forbid(unsafe_code)]'
require qpxc/src/main.rs '#![forbid(unsafe_code)]'
require qpxd/src/policy_context/decision_service/mod.rs 'fn policy_id(&self) -> Option<&str>'
require qpxd/src/policy_context/decision_service/mod.rs 'fn policy_tags(&self) -> &[String]'
require qpxd/src/http/dispatch/audit_builder.rs 'build_dispatch_audit_context'
require qpxd/src/forward/request/dispatch.rs 'build_dispatch_audit_context'
require qpxd/src/forward/request/dispatch/policy.rs 'build_dispatch_audit_context'
require qpxd/src/http/mitm/dispatch.rs 'build_dispatch_audit_context'
require qpxd/src/transparent/http/dispatch/prepare_helpers.rs 'build_dispatch_audit_context'
require qpxd/src/http/dispatch/decision_service_access.rs 'apply_decision_service_http_access'
require qpxd/src/http/dispatch/access.rs 'apply_decision_service_http_access'
require qpxd/src/reverse/transport/dispatch/access.rs 'apply_decision_service_http_access'
require qpxd/src/reverse/transport/dispatch.rs 'annotated_max_forwards_response'
require qpxd/src/http/dispatch/prepare/response.rs 'request_body_too_large_response'
require qpxd/src/upstream/origin/http_backend/pool.rs 'typed_pool_slot'
require qpxd/src/upstream/origin/http_backend/pool.rs 'H2ConnectionReservation'
require qpxd/src/upstream/origin/http_backend/h3_pool.rs 'spawn_h3_request_open_actor'
require qpxd/src/upstream/origin/http_backend/h3_pool.rs 'send_h3_open_request'
require qpxd/src/upstream/origin/http_backend/h3_pool.rs 'open_queue_capacity'
require qpxd/src/upstream/origin/http_backend/h3_pool/pool.rs 'h3_connection_stream_capacity_for_limits'
require qpxd/src/upstream/origin/http_backend/h3_pool/pool.rs 'h3_connection_effective_load'
require qpxd/src/upstream/origin/http_backend/h3_pool/pool.rs 'h3_origin_saturated_wait_uses_effective_stream_capacity'
require qpxd/src/upstream/pool/mod.rs 'trait ConnectionPool<T>'
require qpxd/src/upstream/pool/cluster.rs 'impl ConnectionPool<ResolvedUpstreamProxy> for Arc<UpstreamProxyCluster>'
require qpxd/src/forward/h3/qpx/connect_upstream/pool.rs 'wait_for_inflight_below'
require qpxd/src/forward/h3/qpx/connect_upstream/pool.rs 'max_inflight_streams_per_session'
require qpxd/src/reverse/transport/mirrors.rs 'MIRROR_MAX_INFLIGHT_PER_ENDPOINT'
require qpxd/src/reverse/transport/mirrors.rs 'try_acquire_mirror_permit'
require qpxd/src/policy_context/decision_service/mod.rs 'collect_decision_service_response_body'
require qpxd/src/policy_context/decision_service/mod.rs 'checked_add(data.len())'
require qpxd/src/reverse/transport/request_template.rs 'content_length(req).is_some_and(|len| len <= body_threshold_bytes as u64)'
require qpx-core/src/config/validate/reverse.rs 'retry_body_threshold_bytes must be <= runtime.max_reverse_retry_template_body_bytes'
require qpxf/Cargo.toml 'memchr.workspace = true'
require qpxf/src/server/protocol.rs 'memchr::memmem'
require xtask/src/checks.rs 'check_qpxf_cgi_header_parser_zero_copy'
require qpxd/src/reverse/h3/streaming.rs 'request_side_fail_closed'
require qpxd/src/forward/h3/streaming.rs 'request_side_fail_closed'
require qpx-h3/src/transport/datagram.rs 'send_prefixed_datagram'
require qpx-h3/src/transport/datagram.rs 'send_unprefixed_datagram_with_scratch'
require qpx-h3/src/transport/datagram.rs 'ArcSwap<HashMap<u64, DatagramRoute>>'
require xtask/src/checks.rs 'qpx-h3 datagram send boundary violations'
require xtask/src/checks.rs 'ambiguous unprefixed send_datagram API'
require qpx-h3/src/sharding.rs 'modulo_u64'
require qpx-h3/src/client/registry.rs 'crate::sharding::modulo_u64'
require qpx-h3/src/server/registry.rs 'crate::sharding::modulo_u64'
require qpx-h3/src/transport/datagram.rs 'crate::sharding::modulo_u64'
require qpx-http/src/sharding.rs 'pub fn modulo_u64'
require qpx-http/src/sharding.rs 'pub fn sync_mutex_shards'
require qpx-http/src/sharding.rs 'pub fn async_mutex_shards'
require qpx-http/src/sharding.rs 'pub struct AsyncShardMap'
require qpxd/src/upstream/pool/sender_pool.rs 'AsyncShardMap'
require qpxd/src/ipc_client/pool.rs 'AsyncShardMap'
require qpxd/src/upstream/origin/http_backend/h3_pool/alt_svc.rs 'AsyncShardMap'
require qpxd/src/reverse/h3/passthrough/index/shared.rs 'qpx_http::sharding::modulo_u64'
require qpxd/src/transparent/udp/session/index.rs 'qpx_http::sharding::modulo_u64'
require qpxd/src/http/modules/response_compression/streaming.rs 'qpx_http::sharding::modulo_u64'
require qpx-core/src/secure_file.rs 'HardLinked'
require qpx-core/src/secure_file.rs 'validate_secure_file_handle'
require qpx-core/src/secure_file.rs 'file.set_permissions'
require qpx-core/src/tls/ca.rs 'validate_secure_file_handle'
require qpx-core/src/tls/ca.rs 'file.set_permissions'
require qpx-acme/src/provisioner.rs 'open_secure_output_file'
require qpx-acme/src/provisioner.rs 'file.set_permissions'
require qpx-core/src/shm_ring.rs 'validate_secure_shm_file(&file, path)?'
require qpx-core/src/shm_ring.rs 'file.set_permissions'
require qpxr/src/hub.rs 'qpx_core::secure_file::open_secure_output_file(path)'
require qpxr/src/hub.rs 'self.live_tx.send(encoded.clone())'
require qpxr/src/hub.rs 'tx.try_send(encoded)'
require qpxr/src/hub.rs 'fn duration_as_saturating_nanos'
require qpxr/src/hub.rs 'fn should_rotate_capture_file'
require qpxr/src/hub.rs 'checked_add(block_len)'
require qpx-core/src/tls/mod.rs 'pub use ca::{CaStore, load_or_generate_ca, write_ca_files}'
require qpx-core/src/tls/mod.rs 'pub use config::{build_client_config, build_server_config, load_cert_chain, load_private_key}'
require qpx-core/src/tls/mod.rs 'pub use resolver::{DynamicCertResolver, MitmConfig}'
require qpx-core/src/config/tests/sample_config_tests.rs 'fn sample_qpxd_configs_load'
require qpx-core/src/config/tests/sample_config_tests.rs 'expand_sample_env'
require docs/refactor-fwd-rev.md 'should not be fully merged'
require docs/refactor-fwd-rev.md 'the full forward/reverse request state machine'
require docs/refactor-crate-boundaries.md 'do not split qpxd solely to move LOC'
require docs/refactor-crate-boundaries.md 'no feature loss'
require docs/refactor-crate-boundaries.md 'Cargo-enforced dependency direction'
require xtask/src/checks.rs 'crate-boundary refactor documentation violations'
require qpx-core/src/tls/mod.rs 'mod trust'
require qpx-http/src/tls/mod.rs 'pub mod builder'
require qpx-http/src/tls/builder.rs 'pub async fn connect_client_http1'
require qpx-http/src/tls/builder.rs 'pub async fn connect_client_h2_h1'
require qpx-http/src/tls/builder.rs 'pub async fn preview_client_certificate'
require qpx-http/src/tls/builder.rs 'qpx_core::tls::build_client_config'
require qpx-http/src/tls/builder.rs 'CompiledUpstreamTlsTrust::client_auth'
require qpxd/src/http/dispatch/response_policy.rs 'apply_dispatch_response_policy'
require qpxd/src/http/dispatch/response_policy.rs 'trait ResponseTransform'
require qpxd/src/http/dispatch/cache.rs 'dispatch_cache_collapse_continue'
require qpxd/src/http/dispatch/cache_decision.rs 'finalize_dispatch_collapsed_cache_decision'
require qpxd/src/reverse/transport/response_rules.rs 'fn response_policy_parts'
require qpxd/src/forward/h3/qpx/response.rs 'fn qpx_static_response'
require xtask/src/checks.rs 'check_qpx_h3_static_response_boundary'
require xtask/src/checks.rs 'check_rpc_frame_boundary_tests'
require qpxd/src/http/protocol/l7.rs 'finalize_response_headers_common'
require qpxd/src/http/protocol/l7.rs 'finalize_response_with_headers_in_place'
require qpxd/src/http/protocol/header_control.rs 'trait HeaderTransform'
require qpxd/src/http/protocol/header_control.rs 'set_proxy_authorization_header'
require deny.toml 'multiple-versions = "deny"'
require deny.toml 'wildcards = "allow"'
require xtask/src/checks.rs 'external_wildcard_dependency_violations'
require xtask/src/checks.rs 'must use workspace, path, or an explicit version'
require deny.toml 'skip-tree = []'
require deny.toml 'unknown-registry = "deny"'
require deny.toml 'unknown-git = "deny"'
require .github/workflows/ci.yml 'workflow_dispatch:'
require .github/workflows/ci.yml 'release:'
require .github/workflows/ci.yml 'types: [published]'
require .github/workflows/ci.yml 'tags:'
require .github/workflows/ci.yml '"v*"'
require .github/workflows/ci.yml 'dtolnay/rust-toolchain@1.96'
require .github/workflows/ci.yml 'cargo fmt --all -- --check'
require .github/workflows/ci.yml 'cargo check --workspace --locked'
require .github/workflows/ci.yml 'cargo build --workspace --all-targets --locked'
require .github/workflows/ci.yml 'cargo test --workspace --locked -- --test-threads=1'
require .github/workflows/ci.yml 'cargo doc --workspace --locked --no-deps --document-private-items'
require .github/workflows/ci.yml 'cargo llvm-cov --workspace --locked --fail-under-lines 20'
require .github/workflows/ci.yml 'bash ./scripts/check-public-api.sh'
require .github/workflows/ci.yml 'dtolnay/rust-toolchain@nightly'
require .github/workflows/ci.yml 'toolchain: nightly-2026-07-15'
require .github/workflows/ci.yml 'cargo install cargo-public-api --version 0.52.0 --locked'
require .github/workflows/ci.yml 'cargo clippy --workspace --all-targets --locked -- -D warnings'
require .github/workflows/ci.yml 'cargo clippy -p "${pkg}" --locked --all-targets --no-default-features --features "${features}" -- -D warnings'
require .github/workflows/ci.yml '"http3-backend-qpx"'
require .github/workflows/ci.yml '"http3-backend-h3,http3-backend-qpx,mitm,acme"'
require .github/workflows/ci.yml 'cargo install cargo-machete --version 0.6.0 --locked'
require .github/workflows/ci.yml 'cargo machete'
require .github/workflows/ci.yml 'cargo audit'
require .github/workflows/ci.yml 'cargo deny check'
require .github/workflows/ci.yml 'bash ./scripts/e2e-control-plane.sh'
require .github/workflows/ci.yml 'bash ./scripts/e2e-control-plane-soak.sh'
require .github/workflows/ci.yml 'bash ./scripts/e2e-config-samples.sh'
require .github/workflows/ci.yml 'bash ./scripts/e2e-local-response.sh'
require .github/workflows/ci.yml 'bash ./scripts/e2e-http2.sh'
require .github/workflows/ci.yml './scripts/e2e-control-plane.ps1'
require .github/workflows/ci.yml 'bash ./scripts/check-config-samples.sh'
require .github/workflows/ci.yml 'bash ./scripts/audit-config-usecases.sh'
require .github/workflows/ci.yml 'bash ./scripts/audit-config-behavior.sh'
require .github/workflows/ci.yml 'QPX_PERF_SMOKE_JSON: ${{ github.workspace }}/target/perf/perf-smoke.jsonl'
require .github/workflows/ci.yml 'QPX_PERF_SMOKE_JSON: ${{ github.workspace }}/target/perf/advanced-transport-perf.jsonl'
require .github/workflows/ci.yml 'cargo test -p qpxd --release --test perf_smoke --locked -- --nocapture --test-threads=1'
require .github/workflows/ci.yml 'cargo test -p qpxd --release --test advanced_transport_perf --locked --features http3-backend-qpx,mitm -- --nocapture --test-threads=1'
require .github/workflows/ci.yml 'id: perf_smoke_release'
require .github/workflows/ci.yml 'id: advanced_transport_perf_release'
require .github/workflows/ci.yml 'continue-on-error: true'
require .github/workflows/ci.yml 'fail if any perf smoke evaluation failed'
require .github/workflows/ci.yml 'actions/upload-artifact@v7'
check_deprecated_node_actions
require .github/workflows/ci.yml 'qpx-perf-smoke-jsonl'
require .github/workflows/ci.yml 'target/perf/perf-audit-criterion.jsonl'
require .github/workflows/ci.yml 'cargo bench -p qpxd --bench streaming_throughput --locked -- --sample-size 10'
require .github/workflows/ci.yml 'target/perf/perf-audit-protocol-h3-crate-perf.jsonl'
require .github/workflows/ci.yml 'target/perf/perf-audit-protocol-qpx-h3-perf.jsonl'
require .github/workflows/ci.yml 'target/perf/perf-audit-advanced-transport-perf.jsonl'
require .github/workflows/ci.yml 'cargo test -p qpxd --release --test perf_smoke --locked --features http3-backend-h3 -- --nocapture --test-threads=1'
require .github/workflows/ci.yml 'cargo test -p qpxd --release --test perf_smoke --locked --features http3-backend-qpx -- --nocapture --test-threads=1'
require .github/workflows/ci.yml 'runs-on: ubuntu-latest'
require .github/workflows/ci.yml 'scripts/check-perf-runner.sh'
require .github/workflows/ci.yml 'QPX_PERF_RUNNER_JSON: ${{ github.workspace }}/target/perf/runner.jsonl'
require .github/workflows/ci.yml 'sudo apt-get install -y apache2 apache2-utils iproute2 lighttpd nginx nghttp2-client openssl squid valgrind wrk'
require .github/workflows/ci.yml 'cargo build -p qpxd --release --locked --features http3-backend-qpx'
reject_step_value .github/workflows/ci.yml 'external proxy comparison bench' 'CARGO_PROFILE_RELEASE_'
require .github/workflows/ci.yml 'QPX_PROXY_COMPARE_JSON: ${{ github.workspace }}/target/perf/perf-audit-proxy-compare.jsonl'
require .github/workflows/ci.yml 'CARGO_PROFILE_RELEASE_DEBUG: "1"'
require .github/workflows/ci.yml 'CARGO_PROFILE_RELEASE_STRIP: "none"'
require .github/workflows/ci.yml 'scripts/perf-audit-proxy-matrix.sh "$QPX_PROXY_COMPARE_JSON"'
require .github/workflows/ci.yml 'scripts/check-origin-cache-performance.sh target/perf/perf-audit-proxy-compare.jsonl perf/origin-cache-performance-objectives.json'
require .github/workflows/ci.yml 'QPX_HTTP2_COMPARE_JSON: ${{ github.workspace }}/target/perf/perf-audit-http2-compare.jsonl'
require .github/workflows/ci.yml 'scripts/perf-audit-http2-compare.sh "$QPX_HTTP2_COMPARE_JSON"'
require .github/workflows/ci.yml 'scripts/check-http2-performance.sh target/perf/perf-audit-http2-compare.jsonl perf/http2-performance-objectives.json'
require .github/workflows/ci.yml 'QPX_STREAMING_COMPARE_JSON: ${{ github.workspace }}/target/perf/perf-audit-streaming-compare.jsonl'
require .github/workflows/ci.yml 'scripts/perf-audit-streaming-compare.sh "$QPX_STREAMING_COMPARE_JSON"'
require .github/workflows/ci.yml 'scripts/check-streaming-performance.sh target/perf/perf-audit-streaming-compare.jsonl perf/streaming-performance-objectives.json'
require .github/workflows/ci.yml 'QPX_ALLOCATION_PROFILE_JSON: ${{ github.workspace }}/target/perf/perf-audit-allocation-profile.jsonl'
require .github/workflows/ci.yml 'scripts/perf-audit-allocation-profile.sh'
require .github/workflows/ci.yml 'scripts/compare-proxy-baseline.sh target/perf/perf-audit-proxy-compare.jsonl perf/baseline-proxy-compare.json perf/proxy-performance-objectives.json'
require .github/workflows/ci.yml 'QPX_NETEM_COMPARE_JSON: ${{ github.workspace }}/target/perf/perf-audit-netem-proxy-compare.jsonl'
require .github/workflows/ci.yml 'scripts/perf-audit-netem-compare.sh "$QPX_NETEM_COMPARE_JSON"'
require .github/workflows/ci.yml 'target/perf/netem-proxy-compare-logs/**'
require .github/workflows/ci.yml 'QPX_H3_INTEROP_JSON: ${{ github.workspace }}/target/perf/qpx-h3-interop-matrix.json'
require .github/workflows/ci.yml 'scripts/h3-interop/run.sh all'
require .github/workflows/ci.yml 'scripts/perf-audit-profile.sh'
require .github/workflows/ci.yml 'QPX_PERF_PROFILE_JSON: ${{ github.workspace }}/target/perf/perf-audit-profile-summary.jsonl'
require .github/workflows/ci.yml 'QPX_PERF_PROFILE_EVENTS: ${{ github.workspace }}/target/perf/perf-audit-profile-events.jsonl'
reject_step_value .github/workflows/ci.yml 'callgrind hot path profile' 'CARGO_PROFILE_RELEASE_'
require .github/workflows/ci.yml 'id: criterion_streaming_throughput_bench'
require .github/workflows/ci.yml 'id: h3_crate_protocol_perf_benchmarks'
require .github/workflows/ci.yml 'id: qpx_http3_protocol_perf_benchmarks'
require .github/workflows/ci.yml 'id: advanced_transport_perf_benchmarks'
require .github/workflows/ci.yml 'id: external_proxy_comparison_bench'
require .github/workflows/ci.yml 'id: enforce_cache_origin_feature_rich_performance_objectives'
require .github/workflows/ci.yml 'id: external_http2_comparison_bench'
require .github/workflows/ci.yml 'id: enforce_http2_performance_objectives'
require .github/workflows/ci.yml 'id: external_long_streaming_comparison_bench'
require .github/workflows/ci.yml 'id: enforce_streaming_performance_objectives'
require .github/workflows/ci.yml 'id: allocation_profile'
require .github/workflows/ci.yml 'id: compare_proxy_baseline'
require .github/workflows/ci.yml 'id: netem_proxy_comparison_bench'
require .github/workflows/ci.yml 'id: http3_interop_matrix'
require .github/workflows/ci.yml 'id: callgrind_hot_path_profile'
require .github/workflows/ci.yml 'fail if any perf audit evaluation failed'
require .github/workflows/ci.yml 'steps.external_proxy_comparison_bench.outcome'
require .github/workflows/ci.yml 'steps.enforce_cache_origin_feature_rich_performance_objectives.outcome'
require .github/workflows/ci.yml 'steps.callgrind_hot_path_profile.outcome'
require scripts/perf-audit-proxy-compare.sh '"proxy_compare_http1_reverse"'
require scripts/perf-audit-proxy-compare.sh '"proxy_cache_hit_http1"'
require scripts/perf-audit-proxy-compare.sh '"origin_local_http1"'
require scripts/perf-audit-proxy-compare.sh '"origin_webdav_http1"'
require scripts/perf-audit-proxy-compare.sh '"feature_rich_cache_hit_http1"'
require scripts/perf-audit-proxy-compare.sh 'expect_cache_hit'
require scripts/perf-audit-profile.sh 'run_profile http1 "$QPX_HTTP1_PORT"'
require scripts/perf-audit-profile.sh 'run_profile http2 "$QPX_HTTP2_PORT"'
require scripts/perf-audit-profile.sh '--instr-atstart=no'
require scripts/perf-audit-profile.sh 'callgrind_control -i on "$pid"'
require scripts/perf-audit-profile.sh 'callgrind_control -i off "$pid"'
require scripts/perf-audit-profile.sh 'callgrind output does not profile qpxd directly'
require scripts/perf-audit-profile.sh 'callgrind output has too few instructions'
require scripts/perf-audit-profile.sh 'callgrind_hot_path_profile'
require scripts/perf-audit-profile.sh 'target/callgrind/qpxd'
require scripts/perf-audit-profile.sh 'cargo build -p qpxd --profile callgrind'
require scripts/perf-audit-profile.sh 'select_profile_dump "$output"'
require scripts/perf-audit-proxy-compare.sh 'require_cmd nginx'
require scripts/perf-audit-proxy-compare.sh 'APACHE_BIN="${QPX_PROXY_COMPARE_APACHE_BIN:-}"'
require scripts/perf-audit-proxy-compare.sh 'command -v apache2'
require scripts/perf-audit-proxy-compare.sh 'command -v httpd'
require scripts/perf-audit-proxy-compare.sh 'missing required command: apache2 or httpd'
require scripts/perf-audit-proxy-compare.sh 'require_cmd lighttpd'
require scripts/perf-audit-proxy-compare.sh 'require_cmd wrk'
require scripts/perf-audit-proxy-compare.sh 'require_cmd squid'
require scripts/perf-audit-proxy-compare.sh 'cache_effective_user'
require scripts/perf-audit-proxy-compare.sh 'squid-cache.log'
require scripts/perf-audit-proxy-compare.sh 'squid -N -n "$service_name"'
require scripts/perf-audit-proxy-compare.sh '"proxy_compare_http1_forward"'
require scripts/perf-audit-proxy-compare.sh '"proxy_scale_http1_reverse"'
require scripts/perf-audit-proxy-compare.sh 'BODY_SIZES="${QPX_PROXY_COMPARE_BODY_SIZES:-1024 1048576}"'
require scripts/perf-audit-proxy-compare.sh 'LOCAL_ORIGIN_WORKERS="${QPX_PROXY_COMPARE_LOCAL_ORIGIN_WORKERS:-3}"'
require scripts/perf-audit-proxy-compare.sh 'CACHE_WORKERS="${QPX_PROXY_COMPARE_CACHE_WORKERS:-4}"'
require scripts/perf-audit-proxy-compare.sh 'FEATURE_RICH_WORKERS="${QPX_PROXY_COMPARE_FEATURE_RICH_WORKERS:-4}"'
require scripts/perf-audit-proxy-compare.sh 'WEBDAV_WORKERS="${QPX_PROXY_COMPARE_WEBDAV_WORKERS:-2}"'
require scripts/perf-audit-proxy-compare.sh 'WEBDAV_BLOCKING_THREADS="${QPX_PROXY_COMPARE_WEBDAV_BLOCKING_THREADS:-16}"'
require scripts/perf-audit-proxy-compare.sh 'max_blocking_threads: ${WEBDAV_BLOCKING_THREADS}'
require scripts/perf-audit-proxy-compare.sh 'APACHE_START_SERVERS="${QPX_PROXY_COMPARE_APACHE_START_SERVERS:-3}"'
require scripts/perf-audit-proxy-compare.sh 'APACHE_THREADS_PER_CHILD="${QPX_PROXY_COMPARE_APACHE_THREADS_PER_CHILD:-25}"'
require scripts/perf-audit-proxy-compare.sh 'APACHE_REQUEST_WORKERS="${QPX_PROXY_COMPARE_APACHE_REQUEST_WORKERS:-400}"'
require scripts/perf-audit-proxy-compare.sh 'echo "ThreadsPerChild ${APACHE_THREADS_PER_CHILD}"'
require scripts/perf-audit-proxy-compare.sh 'echo "MaxRequestWorkers ${APACHE_REQUEST_WORKERS}"'
require scripts/perf-audit-proxy-compare.sh 'Apache initial event workers must not exceed MaxRequestWorkers'
require scripts/perf-audit-proxy-compare.sh 'start_qpxd_webdav'
require scripts/perf-audit-proxy-compare.sh 'validate_prefixed_environment'
require scripts/perf-audit-proxy-compare.sh 'SAMPLE_ATTEMPTS="${QPX_PROXY_COMPARE_SAMPLE_ATTEMPTS:-3}"'
require scripts/perf-audit-proxy-compare.sh 'MIN_VALID_SAMPLES="${QPX_PROXY_COMPARE_MIN_VALID_SAMPLES:-}"'
require scripts/perf-audit-proxy-compare.sh 'conservative_median_per_metric'
require scripts/perf-audit-proxy-compare.sh 'def lower_median:'
require scripts/perf-audit-proxy-compare.sh 'def upper_median:'
require scripts/perf-audit-proxy-compare.sh '.sample_spread = {'
require scripts/perf-audit-proxy-compare.sh 'tightest_valid_majority'
require scripts/perf-audit-proxy-compare.sh '*.valid-samples.tsv'
require scripts/perf-audit-proxy-compare.sh 'MAX_READ_ERROR_RATE_PPM="${QPX_PROXY_COMPARE_MAX_READ_ERROR_RATE_PPM:-1000}"'
require scripts/perf-audit-proxy-compare.sh 'MAX_SCALE_WORKERS="${QPX_PROXY_COMPARE_MAX_SCALE_WORKERS:-4}"'
require scripts/perf-audit-proxy-compare.sh 'WRK_TIMEOUT="${QPX_PROXY_COMPARE_WRK_TIMEOUT:-30s}"'
require scripts/perf-audit-proxy-compare.sh 'max_response_body_bytes: 134217728'
require scripts/perf-audit-proxy-compare.sh 'SCALE_WORKERS="$(default_scale_workers)"'
require scripts/perf-audit-proxy-compare.sh '"body_profile"'
require scripts/perf-audit-proxy-compare.sh 'wrk warmup failed for ${proxy}'
require scripts/perf-audit-proxy-compare.sh 'wrk -t"$THREADS" -c"$CONCURRENCY" -d"${DURATION_SECONDS}s" --timeout "$WRK_TIMEOUT"'
require scripts/perf-audit-proxy-compare.sh 'non_2xx_responses'
require scripts/perf-audit-proxy-compare.sh 'bad_length_responses'
require scripts/perf-audit-proxy-compare.sh 'failed_requests'
require scripts/perf-audit-proxy-compare.sh 'read_errors'
require scripts/perf-audit-proxy-compare.sh 'max_read_error_rate_ppm'
require scripts/perf-audit-proxy-compare.sh 'status_before'
require scripts/perf-audit-proxy-compare.sh 'latency_p99_ms'
require scripts/perf-audit-proxy-compare.sh 'requests_per_cpu_second'
require scripts/perf-audit-proxy-compare.sh 'process_tree_cpu_ms'
require scripts/perf-audit-proxy-compare.sh 'endswith("feature-rich")) then $feature_rich_workers'
require scripts/perf-audit-proxy-compare.sh '"thread-per-request" else "async-io"'
require scripts/perf-audit-proxy-compare.sh '.blocking_workers = (if .proxy == "qpxd-webdav" then $webdav_blocking_threads else null end)'
require scripts/perf-audit-proxy-compare.sh 'source "$ROOT_DIR/scripts/lib/perf-process-metrics.sh"'
require scripts/perf-audit-proxy-compare.sh 'rss_peak_kb'
require scripts/perf-audit-proxy-compare.sh 'dump_benchmark_logs'
require scripts/perf-audit-proxy-compare.sh 'proxy-compare-logs'
require scripts/perf-audit-proxy-compare.sh 'copy_bounded_log_artifact'
require scripts/perf-audit-proxy-compare.sh 'expect_rich_access_log_output'
require scripts/perf-audit-proxy-compare.sh 'ARTIFACT_LOG_TAIL_LINES="${QPX_PROXY_COMPARE_ARTIFACT_LOG_TAIL_LINES:-100}"'
require scripts/perf-audit-proxy-compare.sh 'ACCESS_LOG_DRAIN_SECONDS="${QPX_PROXY_COMPARE_ACCESS_LOG_DRAIN_SECONDS:-1.25}"'
require scripts/perf-audit-proxy-compare.sh 'LOG_COMPACTION_SETTLE_SECONDS="${QPX_PROXY_COMPARE_LOG_COMPACTION_SETTLE_SECONDS:-0.75}"'
require scripts/perf-audit-proxy-compare.sh 'drain_feature_rich_access_log "$proxy"'
require scripts/perf-audit-proxy-compare.sh 'settle_feature_rich_log_compaction "$proxy"'
require scripts/perf-audit-proxy-compare.sh 'REPEATED_PROXY_SETTLE_SECONDS="${QPX_PROXY_COMPARE_REPEATED_PROXY_SETTLE_SECONDS:-2}"'
require scripts/perf-audit-proxy-compare.sh 'proxy_selected()'
require scripts/perf-audit-proxy-matrix.sh 'run_group origin "1024" "qpxd-local,nginx-static" ""'
require scripts/perf-audit-proxy-matrix.sh 'run_group webdav "1024 1048576" "qpxd-webdav,apache-webdav" ""'
require scripts/perf-audit-proxy-matrix.sh 'run_group cache "1024 1048576" "qpxd-cache,nginx-cache" ""'
require scripts/perf-audit-proxy-matrix.sh 'run_group feature-rich "1024 1048576" "qpxd-feature-rich,nginx-feature-rich" ""'
require scripts/perf-audit-proxy-matrix.sh 'isolated proxy performance matrix is incomplete or invalid'
require scripts/compare-proxy-baseline.sh 'valid_samples < sample_attempts // 2 + 1'
require scripts/compare-proxy-baseline.sh 'record.get("aggregation") != "conservative_median_per_metric"'
require scripts/compare-proxy-baseline.sh 'proxy-performance-objectives.json'
require_json_number_at_least perf/proxy-performance-objectives.json defaults.min_throughput_ratio 1.25
require_json_number_at_least perf/proxy-performance-objectives.json defaults.min_cpu_efficiency_ratio 1.25
require_json_number_at_least perf/proxy-performance-objectives.json defaults.min_dominance_score 1.25
require_json_number_at_most perf/proxy-performance-objectives.json defaults.max_p99_latency_ratio 0.8
require scripts/check-origin-cache-performance.sh 'multi_axis_origin_cache_dominance'
require scripts/check-origin-cache-performance.sh 'round_robin_interleaved'
require scripts/check-origin-cache-performance.sh 'does not use majority spread'
require scripts/check-origin-cache-performance.sh 'record, "role_workers", context'
require scripts/check-origin-cache-performance.sh 'compares incompatible execution models'
require scripts/check-origin-cache-performance.sh 'qpx_blocking_workers'
require scripts/check-origin-cache-performance.sh 'is missing workload_profile'
require scripts/check-origin-cache-performance.sh 'objective {bench}/{body_bytes} weakens'
require_json_number_at_least perf/origin-cache-performance-objectives.json defaults.min_throughput_ratio 1.25
require_json_number_at_least perf/origin-cache-performance-objectives.json defaults.min_cpu_efficiency_ratio 1.25
require_json_number_at_least perf/origin-cache-performance-objectives.json defaults.min_dominance_score 1.25
require_json_number_at_most perf/origin-cache-performance-objectives.json defaults.max_p99_latency_ratio 0.8
require scripts/perf-audit-http2-compare.sh 'MAX_CONCURRENT_STREAMS_VALUES="${QPX_HTTP2_COMPARE_MAX_CONCURRENT_STREAMS_VALUES:-1 100}"'
require scripts/perf-audit-http2-compare.sh 'BODY_SIZES="${QPX_HTTP2_COMPARE_BODY_SIZES:-1024 1048576}"'
require scripts/perf-audit-http2-compare.sh 'CLIENT_THREADS="${QPX_HTTP2_COMPARE_CLIENT_THREADS:-4}"'
require scripts/perf-audit-http2-compare.sh '--log-file="$latency_file"'
require scripts/perf-audit-http2-compare.sh "-name '*.latency.tsv'"
require scripts/perf-audit-http2-compare.sh 'nearest_rank(latencies_us, 0.99)'
require scripts/perf-audit-http2-compare.sh 'does not match completed requests'
require scripts/perf-audit-http2-compare.sh 'latency_summary = timing_row("request")'
require scripts/perf-audit-http2-compare.sh 'SAMPLE_ATTEMPTS="${QPX_HTTP2_COMPARE_SAMPLE_ATTEMPTS:-3}"'
require scripts/perf-audit-http2-compare.sh 'MIN_VALID_SAMPLES="${QPX_HTTP2_COMPARE_MIN_VALID_SAMPLES:-}"'
require scripts/perf-audit-http2-compare.sh '"aggregation": "conservative_median_per_metric"'
require scripts/perf-audit-http2-compare.sh '"direct-backend"'
require scripts/perf-audit-http2-compare.sh '"sampling_order": "round_robin_interleaved"'
require scripts/perf-audit-http2-compare.sh '*.valid-samples.jsonl'
require scripts/perf-audit-http2-compare.sh 'TLS_HOST="${QPX_HTTP2_COMPARE_TLS_HOST:-localhost}"'
require scripts/perf-audit-http2-compare.sh 'max_response_body_bytes: 134217728'
require scripts/perf-audit-http2-compare.sh 'sni: ${TLS_HOST}'
require scripts/perf-audit-http2-compare.sh 'https://${TLS_HOST}:${port}'
require scripts/perf-audit-http2-compare.sh '--connect-to "127.0.0.1:${port}"'
require scripts/perf-audit-http2-compare.sh 'h2load warmup failed for ${proxy}'
require scripts/perf-audit-http2-compare.sh '"proxy_compare_http2_reverse"'
require scripts/perf-audit-http2-compare.sh '"qpxd"'
require scripts/perf-audit-http2-compare.sh '"nginx"'
require scripts/perf-audit-http2-compare.sh 'requests_per_cpu_second'
require scripts/perf-audit-http2-compare.sh 'requests_per_total_cpu_second'
require scripts/perf-audit-http2-compare.sh 'backend_cpu_ms'
require scripts/perf-audit-http2-compare.sh '"benchmark_schema_version": 5'
require scripts/perf-audit-http2-compare.sh 'rss_peak_kb'
require scripts/perf-audit-http2-compare.sh 'latency_max_ms'
require scripts/perf-audit-http2-compare.sh 'first_byte_mean_ms'
require scripts/perf-audit-http2-compare.sh 'source "$ROOT_DIR/scripts/lib/perf-process-metrics.sh"'
require scripts/check-http2-performance.sh 'multi_axis_total_system_http2_dominance'
require scripts/check-http2-performance.sh 'client_threads'
require scripts/check-http2-performance.sh 'started_requests'
require scripts/check-http2-performance.sh 'server_workers'
require scripts/check-http2-performance.sh 'min_lane_throughput_ratio'
require scripts/check-http2-performance.sh 'min_lane_total_cpu_efficiency_ratio'
require scripts/check-http2-performance.sh 'max_lane_p99_latency_ratio'
require scripts/check-http2-performance.sh 'min_aggregate_dominance_score'
require_json_number_at_least perf/http2-performance-objectives.json defaults.min_lane_dominance_score 1.25
require_json_number_at_least perf/http2-performance-objectives.json defaults.min_aggregate_dominance_score 1.5
require scripts/perf-audit-streaming-compare.sh '"proxy_compare_http1_streaming_reverse"'
require scripts/perf-audit-streaming-compare.sh 'STREAM_BYTES="${QPX_STREAMING_COMPARE_BYTES:-104857600}"'
require scripts/perf-audit-streaming-compare.sh 'FAST_TRANSFERS="${QPX_STREAMING_COMPARE_FAST_TRANSFERS:-8}"'
require scripts/perf-audit-streaming-compare.sh 'SAMPLE_ATTEMPTS="${QPX_STREAMING_COMPARE_SAMPLE_ATTEMPTS:-3}"'
require scripts/perf-audit-streaming-compare.sh 'MIN_VALID_SAMPLES="${QPX_STREAMING_COMPARE_MIN_VALID_SAMPLES:-}"'
require scripts/perf-audit-streaming-compare.sh '"aggregation": "conservative_median_per_metric"'
require scripts/perf-audit-streaming-compare.sh '"sampling_order": "round_robin_interleaved"'
require scripts/perf-audit-streaming-compare.sh '*.valid-samples.jsonl'
require scripts/perf-audit-streaming-compare.sh 'max_response_body_bytes: ${STREAM_BYTES}'
require scripts/perf-audit-streaming-compare.sh 'first_byte_ms'
require scripts/perf-audit-streaming-compare.sh 'p95_chunk_gap_ms'
require scripts/perf-audit-streaming-compare.sh 'read_mode'
require scripts/perf-audit-streaming-compare.sh 'requests_per_cpu_second'
require scripts/perf-audit-streaming-compare.sh 'requests_per_total_cpu_second'
require scripts/perf-audit-streaming-compare.sh 'backend_cpu_ms'
require scripts/perf-audit-streaming-compare.sh '"benchmark_schema_version": 3'
require scripts/perf-audit-streaming-compare.sh 'gap_observation_bytes'
require scripts/perf-audit-streaming-compare.sh 'source "$ROOT_DIR/scripts/lib/perf-process-metrics.sh"'
require scripts/lib/perf-process-metrics.sh 'process_tree_cpu_ms()'
require scripts/lib/perf-process-metrics.sh 'process_cpu_ms_portable()'
require scripts/lib/perf-process-metrics.sh 'ps -o time='
require scripts/check-streaming-performance.sh 'multi_axis_total_system_streaming_dominance'
require scripts/check-streaming-performance.sh 'min_throughput_ratio'
require scripts/check-streaming-performance.sh 'min_total_cpu_efficiency_ratio'
require scripts/check-streaming-performance.sh 'max_p99_gap_ratio'
require scripts/check-streaming-performance.sh 'max_total_time_ratio'
require scripts/check-streaming-performance.sh 'competitive_frontier_total_ratio'
require_json_number_at_least perf/streaming-performance-objectives.json fast.min_throughput_ratio 1.5
require_json_number_at_least perf/streaming-performance-objectives.json fast.min_dominance_score 1.25
require scripts/perf-audit-allocation-profile.sh '"qpxd_allocation_profile_http1_reverse"'
require scripts/perf-audit-allocation-profile.sh '--tool=dhat'
require scripts/perf-audit-allocation-profile.sh 'while [ "$tries" -lt 600 ]'
require scripts/perf-audit-allocation-profile.sh 'alloc_bytes'
require scripts/perf-audit-allocation-profile.sh 'alloc_count'
require scripts/perf-audit-profile.sh 'if [ ! -s "$file" ] || ! grep -q'
require scripts/perf-audit-profile.sh 'callgrind_annotate --threshold=99'
require scripts/perf-audit-netem-compare.sh 'tc qdisc add dev lo root netem'
require scripts/perf-audit-netem-compare.sh '"network_condition_profile"'
require scripts/perf-audit-netem-compare.sh 'QPX_PROXY_COMPARE_LOG_DIR="${QPX_NETEM_PROXY_COMPARE_LOG_DIR:-$ROOT_DIR/target/perf/netem-proxy-compare-logs}"'
require scripts/perf-audit-netem-compare.sh 'QPX_PROXY_COMPARE_MAX_READ_ERROR_RATE_PPM="$MAX_READ_ERROR_RATE_PPM"'
require scripts/h3-interop/run.sh 'all(.[]; .pass_fail == "pass")'
require scripts/h3-interop/external-client.sh 'QUICHE_CLIENT_BIN is required'
require scripts/h3-interop/external-client.sh 'NGTCP2_CLIENT_BIN is required'
require scripts/h3-interop/external-client.sh 'CURL_HTTP3_BIN is required'
require scripts/h3-interop/external-client.sh 'AIOQUIC_DIR is required'
require scripts/h3-interop/external-client.sh 'CHROMIUM_BIN is required'
require qpxd/tests/perf_smoke/mod.rs 'resource_snapshot'
require qpxd/tests/perf_smoke/mod.rs 'live_qpxd_resource_snapshot'
require qpxd/tests/perf_smoke/mod.rs 'live_qpxd_pids'
require qpxd/tests/perf_smoke/mod.rs 'RUSAGE_SELF'
require qpxd/tests/advanced_transport_perf.rs 'resource_snapshot'
require qpxd/tests/advanced_transport_perf.rs 'live_qpxd_resource_snapshot'
require qpxd/tests/advanced_transport_perf.rs 'live_qpxd_pids'
require qpxd/tests/advanced_transport_perf.rs 'RUSAGE_SELF'
require scripts/check-perf-runner.sh '"perf_runner_capacity"'
require scripts/check-perf-runner.sh 'MIN_CORES="${QPX_PERF_MIN_CORES:-4}"'
require scripts/check-perf-runner.sh 'MIN_MEM_MB="${QPX_PERF_MIN_MEM_MB:-16384}"'
require scripts/check-perf-runner.sh 'REQUIRE_CAPACITY="${QPX_PERF_REQUIRE_CAPACITY:-0}"'
require scripts/compare-proxy-baseline.sh 'multi_axis_proxy_dominance'
require scripts/compare-proxy-baseline.sh 'external_best_rps = max'
require scripts/compare-proxy-baseline.sh 'external_best_p99_ms = min'
require scripts/compare-proxy-baseline.sh 'dominance_score'
require scripts/compare-proxy-baseline.sh 'min_cpu_efficiency_ratio'
require scripts/compare-proxy-baseline.sh 'max_p99_latency_ratio'
require scripts/compare-proxy-baseline.sh 'min_dominance_score'
require scripts/compare-proxy-baseline.sh 'external_proxy_requests_per_sec'
require scripts/compare-proxy-baseline.sh 'generate-baseline'
require scripts/compare-proxy-baseline.sh 'require_valid_sample'
require perf/baseline-proxy-compare.json '"degradation_threshold": 0.05'
require perf/baseline-proxy-compare.json '"schema_version": 3'
require perf/baseline-proxy-compare.json '"throughput_ratio"'
require perf/baseline-proxy-compare.json '"dominance_score"'
require perf/proxy-performance-objectives.json '"min_throughput_ratio"'
require perf/proxy-performance-objectives.json '"min_cpu_efficiency_ratio"'
require perf/proxy-performance-objectives.json '"max_p99_latency_ratio"'
require perf/proxy-performance-objectives.json '"min_dominance_score"'
require perf/proxy-performance-objectives.json '"min_direct_headroom_ratio"'
require perf/proxy-performance-objectives.json '"max_throughput_sample_spread_ratio"'
require perf/proxy-performance-objectives.json '"max_cpu_sample_spread_ratio"'
require perf/baseline-proxy-compare.json '"duration_seconds": 10'
require perf/baseline-proxy-compare.json '"external_proxy_best_requests_per_sec"'
require perf/baseline-proxy-compare.json '"external_proxy_best_latency_p99_ms"'
require perf/baseline-proxy-compare.json '"source_commit"'
require scripts/check-allocation-budget.sh 'alloc_bytes_per_request'
require scripts/check-allocation-budget.sh 'alloc_count_per_request'
require perf/allocation-budget.json '"max_alloc_bytes_per_request": 1800'
require perf/allocation-budget.json '"max_alloc_count_per_request": 55'
require .github/workflows/ci.yml 'enforce allocation budget'
require .github/workflows/ci.yml 'target/perf/proxy-compare-logs/**'
require .github/workflows/ci.yml 'target/perf/profiles/**'
require .github/workflows/ci.yml 'qpx-perf-audit-jsonl'
require .github/workflows/ci.yml 'provider-neutral matrix (qid, Keycloak, Cerbos)'
require .github/workflows/ci.yml 'bash ./scripts/e2e-provider-matrix.sh'
require .github/workflows/ci.yml 'WebDAV litmus and CalDAV tester'
require .github/workflows/ci.yml 'bash ./scripts/e2e-webdav-compliance.sh'
require .github/workflows/ci.yml 'cargo test --workspace --all-features --locked -- --test-threads=1'
require .github/workflows/ci.yml 'compile and test Windows Wintun CONNECT-IP path'
require .github/workflows/ci.yml 'external H3 (${{ matrix.backend }}, ${{ matrix.client }})'
require .github/workflows/ci.yml 'client: [aioquic, curl, ngtcp2, quiche, chromium]'
require .github/workflows/ci.yml 'libssl-dev'
require .github/workflows/ci.yml 'HTTP RFC compliance release gate'
require .github/workflows/ci.yml 'RESULTS:'
require .github/workflows/ci.yml 'join(needs.*.result'
require scripts/e2e-provider-matrix.sh 'keycloak/keycloak@sha256:'
require scripts/e2e-provider-matrix.sh 'cerbos/cerbos@sha256:'
require scripts/e2e-provider-matrix.sh 'SISTER_QID_REPO_DIR is required'
require scripts/e2e-webdav-compliance.sh 'LITMUS_BIN is required'
require scripts/e2e-webdav-compliance.sh 'CALDAV_TESTER_BIN is required'
require scripts/e2e-webdav-compliance.sh '--run-feature create-calendar'
require scripts/e2e-webdav-compliance.sh '--run-feature search.time-range.event'
require scripts/e2e-webdav-compliance.sh '--run-feature freebusy-query'
require .github/workflows/ci.yml '8d2fc13636abf82c82436771990e8e65a28c7cb4'
require .github/workflows/release.yml 'workflow_dispatch:'
require .github/workflows/release.yml 'tags:'
require .github/workflows/release.yml 'v*'
require .github/workflows/release.yml 'dtolnay/rust-toolchain@1.96'
require .github/workflows/release.yml 'tool: cargo-about'
require .github/workflows/release.yml 'cross build --workspace --release --locked --target ${{ matrix.target }} --features "${QPXD_SAMPLE_RUSTLS_FEATURES}"'
require .github/workflows/release.yml 'cargo build --workspace --release --locked --target ${{ matrix.target }} --features "${QPXD_SAMPLE_RUSTLS_FEATURES}"'
require .github/workflows/release.yml 'cargo about generate --fail --config about.toml --workspace --locked licenses/about.hbs > THIRDPARTY.md'
require .github/workflows/release.yml 'softprops/action-gh-release@v3'
require .github/workflows/release.yml 'id-token: write'
require .github/workflows/release.yml 'attestations: write'
require .github/workflows/release.yml 'actions/attest-build-provenance@v4.1.1'
require .github/workflows/release.yml 'subject-path: ${{ env.ASSET }}'
require .github/workflows/release.yml 'ASSET_SHA256='
require .github/workflows/release.yml 'files: |'
require .github/workflows/release.yml '${{ env.ASSET_SHA256 }}'
require about.toml '"MIT-0"'
require .github/workflows/security-qa.yml 'RUSTFLAGS: -Zsanitizer=address'
require .github/workflows/security-qa.yml 'cargo test -Zbuild-std --target x86_64-unknown-linux-gnu -p qpx-core --lib shm_ring --no-default-features --features ipc-support -- --nocapture'
require .github/workflows/security-qa.yml 'cargo test -Zbuild-std --target x86_64-unknown-linux-gnu -p qpxd ready_notifier_from_env_writes_readiness_byte -- --nocapture'
require .github/workflows/security-qa.yml 'cargo fuzz run "${target}"'
require .github/workflows/security-qa.yml 'config_canonical_loader'
require .github/workflows/security-qa.yml 'connect_frame_observer'
require .github/workflows/security-qa.yml 'datagram_capsule_parser'
require .github/workflows/security-qa.yml 'grpc_frame_observer'
require .github/workflows/security-qa.yml 'grpc_web_binary_frame_observer'
require .github/workflows/security-qa.yml 'grpc_web_text_base64_observer'
require .github/workflows/security-qa.yml 'h3_content_length_state'
require .github/workflows/security-qa.yml 'h3_trailer_sanitizer'
require .github/workflows/security-qa.yml 'reverse_target_input_deserializer'
require .github/workflows/security-qa.yml 'sse_event_observer'
require .github/workflows/security-qa.yml 'streaming_requirement_config_validator'
require .github/workflows/codeql.yml 'github/codeql-action/init@v4'
require .github/workflows/codeql.yml 'github/codeql-action/analyze@v4'
require .github/workflows/structure.yml 'bash ./scripts/check-ci-acceptance-gates.sh'
require .github/workflows/structure.yml 'cargo xtask structure'
require .github/workflows/structure.yml 'cargo xtask budget'
require scripts/check-public-api.sh 'check_crate qpx-core'
require scripts/check-public-api.sh 'check_crate qpx-auth'
require scripts/check-public-api.sh 'check_crate qpx-h3'
require scripts/check-public-api.sh 'check_crate qpx-acme'
require scripts/check-public-api.sh 'check_crate qpx-observability'
check_deny_skip_baseline

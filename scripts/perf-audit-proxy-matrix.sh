#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/lib/temp-dir.sh"
OUT_JSON="${1:-${QPX_PROXY_COMPARE_JSON:-$ROOT_DIR/target/perf/perf-audit-proxy-compare.jsonl}}"
LOG_ROOT="${QPX_PROXY_MATRIX_LOG_DIR:-$ROOT_DIR/target/perf/proxy-compare-logs}"
TMP_DIR="$(make_temp_dir qpx-proxy-matrix)"
CANDIDATE="${OUT_JSON}.tmp.$$"
INVALID_JSON="${OUT_JSON}.invalid"

cleanup() {
  local exit_status=$?
  rm -rf "$TMP_DIR"
  if [ -n "$CANDIDATE" ]; then
    rm -f "$CANDIDATE"
  fi
  return "$exit_status"
}
trap cleanup EXIT

run_group() {
  local name="$1"
  local body_sizes="$2"
  local proxies="$3"
  local scale_workers="$4"
  QPX_PROXY_COMPARE_BODY_SIZES="$body_sizes" \
  QPX_PROXY_COMPARE_PROXY_FILTER="$proxies" \
  QPX_PROXY_COMPARE_SCALE_WORKERS="$scale_workers" \
  QPX_PROXY_COMPARE_LOG_DIR="$LOG_ROOT/$name" \
    "$ROOT_DIR/scripts/perf-audit-proxy-compare.sh" "$TMP_DIR/$name.jsonl"
}

rm -rf "$LOG_ROOT"
rm -f "$INVALID_JSON"
mkdir -p "$LOG_ROOT" "$(dirname "$OUT_JSON")"

run_group \
  proxy \
  "1024 1048576" \
  "direct-backend,qpxd,nginx,apache,lighttpd,qpxd-forward,squid,qpxd-workers-1,qpxd-workers-2,qpxd-workers-4" \
  "1 2 4"
run_group origin "1024" "qpxd-local,nginx-static" ""
run_group webdav "1024 1048576" "qpxd-webdav,apache-webdav" ""
# The unique-URL miss workload pays for origin fetches plus disk writeback on
# every request, so its per-sample spread is much wider than the hit path;
# five samples keep the majority-median stable across runs.
QPX_PROXY_COMPARE_MISS_SAMPLE_ATTEMPTS=5 \
  run_group cache "1024 1048576" "qpxd-cache,nginx-cache" ""
run_group feature-rich "1024 1048576" "qpxd-feature-rich,nginx-feature-rich" ""

: >"$CANDIDATE"
for group in proxy origin webdav cache feature-rich; do
  cat "$TMP_DIR/$group.jsonl" >>"$CANDIDATE"
done

if ! jq -e -s '
  def matrix($bench; $sizes; $proxies):
    [$sizes[] as $size | $proxies[] as $proxy | "\($bench)/\($size)/\($proxy)"];
  (matrix("proxy_compare_http1_reverse"; [1024, 1048576];
      ["direct-backend", "qpxd", "nginx", "apache", "lighttpd"])
    + matrix("proxy_compare_http1_forward"; [1024, 1048576];
      ["qpxd-forward", "squid"])
    + matrix("proxy_scale_http1_reverse"; [1024, 1048576];
      ["qpxd-workers-1", "qpxd-workers-2", "qpxd-workers-4"])
    + matrix("origin_local_http1"; [1024]; ["qpxd-local", "nginx-static"])
    + matrix("origin_webdav_http1"; [1024, 1048576];
      ["qpxd-webdav", "apache-webdav"])
    + matrix("proxy_cache_hit_http1"; [1024, 1048576];
      ["qpxd-cache", "nginx-cache"])
    + matrix("proxy_cache_miss_http1"; [1024];
      ["qpxd-cache", "nginx-cache"])
    + matrix("feature_rich_cache_hit_http1"; [1024, 1048576];
      ["qpxd-feature-rich", "nginx-feature-rich"])
    | sort) as $expected
  | ([.[] | "\(.bench)/\(.body_bytes)/\(.proxy)"] | sort) as $actual
  | ($actual == $expected)
    and all(.[];
      .valid == true
      and .status_before == "200"
      and .status_after == "200"
      and .connect_errors == 0
      and .write_errors == 0
      and .timeout_errors == 0
      and (.failed_requests == .read_errors)
      and (.read_errors * 1000000 <= .complete_requests * .max_read_error_rate_ppm)
      and .non_2xx_responses == 0
      and .bad_length_responses == 0
      and .cache_result_errors == 0
      and (if .bench == "proxy_cache_miss_http1" then .cache_writeback_verified == true else true end))
' "$CANDIDATE" >/dev/null; then
  echo "isolated proxy performance matrix is incomplete or invalid" >&2
  jq -r '[.bench, .body_bytes, .proxy, .valid] | @tsv' "$CANDIDATE" >&2 || true
  mv "$CANDIDATE" "$INVALID_JSON"
  CANDIDATE=""
  exit 1
fi

mv "$CANDIDATE" "$OUT_JSON"

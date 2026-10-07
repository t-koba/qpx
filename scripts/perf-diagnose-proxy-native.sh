#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workload="${QPX_NATIVE_WORKLOAD:-proxy}"
export QPXD_REAL_BIN="${QPXD_BIN:-$ROOT_DIR/target/callgrind/qpxd}"
mkdir -p "$ROOT_DIR/target/perf/profiles"
export QPX_NATIVE_PROFILE_DIR
QPX_NATIVE_PROFILE_DIR="$(mktemp -d "$ROOT_DIR/target/perf/profiles/native.XXXXXX")"
export QPX_NATIVE_PERF_BIN="${QPX_NATIVE_PERF_BIN:?native perf executable is required}"
export QPX_NATIVE_WRAPPER_SOURCE="$ROOT_DIR/scripts/lib/perf-native-process.py"
[ -x "$QPXD_REAL_BIN" ]
[ -x "$QPX_NATIVE_PERF_BIN" ]
mkdir -p "$QPX_NATIVE_PROFILE_DIR"
"$QPX_NATIVE_PERF_BIN" --version
# Preserve the exact ELF image needed to resolve raw profile addresses offline.
python3 - "$QPXD_REAL_BIN" "$QPX_NATIVE_PROFILE_DIR" <<'PY_BINARY'
import gzip
import hashlib
import json
from pathlib import Path
import sys
binary, destination = map(Path, sys.argv[1:])
def identity_of(path):
    stat = path.stat()
    return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)
identity = identity_of(binary)
digest = hashlib.sha256()
size = 0
with binary.open("rb") as source, (destination / "qpxd.elf.gz").open("xb") as archive:
    if source.read(4) != b"\x7fELF":
        raise SystemExit("native CPU profiling requires an ELF executable")
    source.seek(0)
    with gzip.GzipFile(filename="", fileobj=archive, mode="wb", mtime=0) as output:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
            output.write(chunk)
if identity_of(binary) != identity or size != identity[2]:
    raise SystemExit("native CPU executable changed while preserving profile evidence")
(destination / "binary.json").write_text(json.dumps({
    "artifact": "qpxd.elf.gz", "sha256": digest.hexdigest(), "uncompressed_bytes": size,
    "source": str(binary.resolve()), "format": "ELF", "compression": "gzip",
}, indent=2) + "\n")
print("Native CPU executable preserved with SHA-256")
PY_BINARY
wrapper="$QPX_NATIVE_PROFILE_DIR/qpxd-perf"
cat >"$wrapper" <<'WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
exec python3 "$QPX_NATIVE_WRAPPER_SOURCE" "$@"
WRAPPER
chmod 755 "$wrapper"
bash "$ROOT_DIR/scripts/check-perf-native-process.sh" "$wrapper"
echo "Native CPU workload started: $workload"
workload_status=0
case "$workload" in
  http1)
    QPXD_BIN="$wrapper" QPX_PROXY_COMPARE_THREAD_DIAGNOSTICS=1 \
      QPX_PROXY_COMPARE_DEPENDENCY_CPU_DIAGNOSTICS=1 \
      QPX_PROXY_COMPARE_PROXY_FILTER=direct-backend,qpxd,nginx,apache,lighttpd \
      QPX_PROXY_COMPARE_BODY_SIZES="1024 1048576" \
      bash "$ROOT_DIR/scripts/perf-audit-proxy-compare.sh"
    log_directory="$ROOT_DIR/target/perf/proxy-compare-logs"
    ;;
  proxy|feature-large)
    log_directory="$QPX_NATIVE_PROFILE_DIR/workloads"
    roles=(qpxd-cache qpxd-feature-rich)
    body_sizes=1024
    if [ "$workload" = feature-large ]; then
      roles=(qpxd-feature-rich)
      body_sizes=1048576
    fi
    # Keep unrelated cache loaders out of each pair's measurement lifetime,
    # matching the normal matrix and same-runner revision comparisons.
    for role in "${roles[@]}"; do
      case "$role" in
        qpxd-cache) proxies=qpxd-cache,nginx-cache ;;
        qpxd-feature-rich) proxies=qpxd-feature-rich,nginx-feature-rich ;;
      esac
      QPXD_BIN="$wrapper" QPX_PROXY_COMPARE_THREAD_DIAGNOSTICS=1 \
        QPX_PROXY_COMPARE_MISS_SAMPLE_ATTEMPTS=5 \
        QPX_PROXY_COMPARE_PROXY_FILTER="$proxies" \
        QPX_PROXY_COMPARE_BODY_SIZES="$body_sizes" \
        QPX_PROXY_COMPARE_LOG_DIR="$log_directory/$role" \
        bash "$ROOT_DIR/scripts/perf-audit-proxy-compare.sh" "$QPX_NATIVE_PROFILE_DIR/$role.jsonl"
    done
    ;;
  webdav)
    export QPX_NATIVE_APACHE_REAL_BIN
    QPX_NATIVE_APACHE_REAL_BIN="$(command -v apache2)"
    apache_wrapper="$QPX_NATIVE_PROFILE_DIR/apache-perf"
    cat >"$apache_wrapper" <<'APACHE_WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
export QPXD_REAL_BIN="$QPX_NATIVE_APACHE_REAL_BIN"
export QPX_NATIVE_REFERENCE_ROLE=apache-webdav
exec python3 "$QPX_NATIVE_WRAPPER_SOURCE" "$@"
APACHE_WRAPPER
    chmod 755 "$apache_wrapper"
    QPXD_BIN="$wrapper" QPX_PROXY_COMPARE_THREAD_DIAGNOSTICS=1 \
      QPX_PROXY_COMPARE_APACHE_BIN="$apache_wrapper" \
      QPX_PROXY_COMPARE_PROXY_FILTER=qpxd-webdav,apache-webdav \
      QPX_PROXY_COMPARE_BODY_SIZES="1024 1048576" \
      QPX_PROXY_COMPARE_WEBDAV_QPXD_ENV="MALLOC_ARENA_MAX=2 MALLOC_TRIM_THRESHOLD_=134217728" \
      bash "$ROOT_DIR/scripts/perf-audit-proxy-compare.sh"
    log_directory="$ROOT_DIR/target/perf/proxy-compare-logs"
    ;;
  http2)
    QPXD_BIN="$wrapper" bash "$ROOT_DIR/scripts/perf-audit-http2-isolated.sh" \
      --native "$ROOT_DIR/target/perf/perf-audit-http2-compare.jsonl"
    log_directory="$ROOT_DIR/target/perf/http2-compare-logs"
    ;;
  streaming)
    export QPX_NATIVE_BACKEND_REAL_BIN
    QPX_NATIVE_BACKEND_REAL_BIN="$(command -v python3)"
    backend_wrapper="$QPX_NATIVE_PROFILE_DIR/backend-perf"
    cat >"$backend_wrapper" <<'BACKEND_WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
export QPXD_REAL_BIN="$QPX_NATIVE_BACKEND_REAL_BIN"
export QPX_NATIVE_REFERENCE_ROLE=streaming-backend
exec python3 "$QPX_NATIVE_WRAPPER_SOURCE" "$@"
BACKEND_WRAPPER
    chmod 755 "$backend_wrapper"
    "$QPX_NATIVE_BACKEND_REAL_BIN" --version
    if QPXD_BIN="$wrapper" QPX_STREAMING_COMPARE_NATIVE_DIAGNOSTICS=1 \
      QPX_STREAMING_COMPARE_BACKEND_BIN="$backend_wrapper" \
      QPX_STREAMING_COMPARE_FAST_TRANSFERS=64 \
      bash "$ROOT_DIR/scripts/perf-audit-streaming-compare.sh"; then
      workload_status=0
    else
      workload_status=$?
      echo "Native streaming workload failed; retaining completed CPU windows" >&2
    fi
    log_directory="$ROOT_DIR/target/perf/streaming-compare-logs"
    ;;
  *) echo "unsupported native CPU workload: $workload" >&2; exit 2 ;;
esac

# A failed reference workload must not discard completed owned CPU windows.
# Reporting and workload failures remain explicit failures of this diagnostic.
bash "$ROOT_DIR/scripts/perf-report-proxy-native.sh" \
  "$workload" "$QPX_NATIVE_PROFILE_DIR" "$log_directory"
exit "$workload_status"

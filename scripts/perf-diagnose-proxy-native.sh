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
case "$workload" in
  http1)
    QPXD_BIN="$wrapper" QPX_PROXY_COMPARE_THREAD_DIAGNOSTICS=1 \
      QPX_PROXY_COMPARE_PROXY_FILTER=direct-backend,qpxd,nginx,apache,lighttpd \
      QPX_PROXY_COMPARE_BODY_SIZES="1024 1048576" \
      bash "$ROOT_DIR/scripts/perf-audit-proxy-compare.sh"
    roles="qpxd"
    log_directory="$ROOT_DIR/target/perf/proxy-compare-logs"
    expected_profiles=1
    minimum_reports=6
    ;;
  proxy)
    roles="qpxd-cache qpxd-feature-rich"
    log_directory="$QPX_NATIVE_PROFILE_DIR/workloads"
    # Keep unrelated cache loaders out of each pair's measurement lifetime,
    # matching the normal matrix and same-runner revision comparisons.
    for role in $roles; do
      case "$role" in
        qpxd-cache) proxies=qpxd-cache,nginx-cache ;;
        qpxd-feature-rich) proxies=qpxd-feature-rich,nginx-feature-rich ;;
      esac
      QPXD_BIN="$wrapper" QPX_PROXY_COMPARE_THREAD_DIAGNOSTICS=1 \
        QPX_PROXY_COMPARE_MISS_SAMPLE_ATTEMPTS=5 \
        QPX_PROXY_COMPARE_PROXY_FILTER="$proxies" \
        QPX_PROXY_COMPARE_BODY_SIZES=1024 \
        QPX_PROXY_COMPARE_LOG_DIR="$log_directory/$role" \
        bash "$ROOT_DIR/scripts/perf-audit-proxy-compare.sh" "$QPX_NATIVE_PROFILE_DIR/$role.jsonl"
    done
    expected_profiles=2
    minimum_reports=11
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
    roles="qpxd-webdav apache-webdav"
    log_directory="$ROOT_DIR/target/perf/proxy-compare-logs"
    expected_profiles=2
    minimum_reports=12
    ;;
  http2)
    QPXD_BIN="$wrapper" bash "$ROOT_DIR/scripts/perf-audit-http2-isolated.sh" \
      --native "$ROOT_DIR/target/perf/perf-audit-http2-compare.jsonl"
    roles="qpxd-h2"
    log_directory="$ROOT_DIR/target/perf/http2-compare-logs"
    expected_profiles=1
    minimum_reports=12
    ;;
  streaming)
    QPXD_BIN="$wrapper" QPX_STREAMING_COMPARE_NATIVE_DIAGNOSTICS=1 \
      QPX_STREAMING_COMPARE_FAST_TRANSFERS=64 \
      bash "$ROOT_DIR/scripts/perf-audit-streaming-compare.sh"
    roles="qpxd-streaming"
    log_directory="$ROOT_DIR/target/perf/streaming-compare-logs"
    expected_profiles=1
    minimum_reports=6
    ;;
  *) echo "unsupported native CPU workload: $workload" >&2; exit 2 ;;
esac

# Harness shutdown also closes perf's output before report generation.
echo "Native CPU workload finished: $workload"
python3 - "$QPX_NATIVE_PROFILE_DIR" "$roles" <<'PY'
import json
from pathlib import Path
import sys
paths = list(Path(sys.argv[1]).glob("*.lifecycle.json"))
expected = set(sys.argv[2].split())
if {path.name.removesuffix(".lifecycle.json") for path in paths} != expected:
    raise SystemExit("native profiler lifecycle records are incomplete")
for path in paths:
    record = json.load(path.open())
    if (record.get("forced_shutdown") is not False or record.get("requested_signal") != 15
            or record.get("exit_status") not in (0, -15, 143)):
        raise SystemExit(f"native profiler shutdown was not complete: {path}")
PY
profiles=0
for profile in "$QPX_NATIVE_PROFILE_DIR"/*.data; do
  [ -f "$profile" ] || continue
  echo "Native CPU report started: $profile"
  timeout --signal=TERM --kill-after=10s 180s "$QPX_NATIVE_PERF_BIN" report --stdio --header --no-children --call-graph none \
    --sort symbol --percent-limit 0.5 -i "$profile" >"$profile.report.txt"
  if ! rg -q '^# Samples: [1-9]' "$profile.report.txt"; then
    echo "native CPU profile contains no samples: $profile" >&2
    exit 1
  fi
  profiles=$((profiles + 1))
done
if [ "$profiles" -ne "$expected_profiles" ]; then
  echo "native CPU profiling lacks required roles: observed $profiles; expected $expected_profiles" >&2
  exit 1
fi
reports=0
for role in $roles; do
  sample_role="$role"
  role_log_directory="$log_directory"
  if [ "$workload" = proxy ]; then
    role_log_directory="$log_directory/$role"
  fi
  if [ "$workload" = http2 ] || [ "$workload" = streaming ]; then
    sample_role=qpxd
  fi
  for sample in "$role_log_directory"/*."$sample_role".*.rss-peak.samples.csv; do
    [ -f "$sample" ] || continue
    window="$(python3 - "$sample" <<'PY'
import csv
import sys
rows = list(csv.DictReader(open(sys.argv[1])))
if len(rows) < 2:
    raise SystemExit("native profile window requires at least two real workload samples")
first, last = int(rows[0]["monotonic_ns"]), int(rows[-1]["monotonic_ns"])
if first >= last:
    raise SystemExit("native profile workload sample times are not increasing")
def timestamp(value):
    return f"{value // 1_000_000_000}.{value % 1_000_000_000:09d}"
print(f"{timestamp(first)},{timestamp(last)}")
PY
)"
    echo "Native CPU workload report started: $sample"
    timeout --signal=TERM --kill-after=10s 180s "$QPX_NATIVE_PERF_BIN" report --stdio --header --no-children --call-graph none \
      --sort symbol --percent-limit 0.5 --time "$window" \
      -i "$QPX_NATIVE_PROFILE_DIR/$role.data" >"$sample.cpu-report.txt"
    if ! rg -q '^# Samples: [1-9]' "$sample.cpu-report.txt"; then
      echo "native workload CPU profile contains no samples: $sample" >&2
      exit 1
    fi
    if [ "$workload" = proxy ] && [[ "$sample" = *.round-2.* ]]; then
      echo "Native memory-copy caller report started: $sample"
      timeout --signal=TERM --kill-after=10s 180s "$QPX_NATIVE_PERF_BIN" report --stdio --header --no-children \
        --no-inline --call-graph flat,0.5,32,caller --symbol-filter memmove --percentage absolute \
        --sort symbol --show-nr-samples --time "$window" \
        -i "$QPX_NATIVE_PROFILE_DIR/$role.data" >"$sample.memmove-callers.txt"
    fi
    if [[ "$sample" = *.round-2.* ]]; then
      echo "Native workload callsite decoding started: $sample"
      timeout --signal=TERM --kill-after=10s 180s "$QPX_NATIVE_PERF_BIN" script --no-inline \
        --fields comm,pid,tid,time,ip,sym,symoff,dso --time "$window" \
        -i "$QPX_NATIVE_PROFILE_DIR/$role.data" >"$sample.callchains.txt"
      if [ ! -s "$sample.callchains.txt" ]; then
        echo "native workload callsite decoding contains no samples: $sample" >&2
        exit 1
      fi
    fi
    reports=$((reports + 1))
  done
done
if [ "$reports" -lt "$minimum_reports" ]; then
  echo "native CPU profiling lacks complete workload windows: observed $reports" >&2
  exit 1
fi
# Retain every report before rejecting incomplete sampling evidence.
python3 - "$QPX_NATIVE_PROFILE_DIR" <<'PY_QUALITY'
import json
from pathlib import Path
import re
import sys
root = Path(sys.argv[1])
profiles = []
for report in sorted(root.glob("*.data.report.txt")):
    counts = re.findall(r"^# Total Lost Samples:\s+(\d+)\s*$", report.read_text(), re.MULTILINE)
    if len(counts) != 1:
        raise SystemExit(f"native CPU report lacks an unambiguous lost-sample count: {report}")
    profiles.append({"report": report.name, "lost_samples": int(counts[0])})
if not profiles:
    raise SystemExit("native CPU sampling quality lacks real profile reports")
valid = all(profile["lost_samples"] == 0 for profile in profiles)
(root / "sampling-quality.json").write_text(json.dumps({
    "measurement": "native_cpu_sampling_quality_v1", "valid": valid,
    "maximum_lost_samples": 0, "profiles": profiles,
    "reason": None if valid else "native CPU recording lost samples",
}, indent=2) + "\n")
if not valid:
    print("Invalid measurement: native CPU recording lost samples", file=sys.stderr)
    raise SystemExit(1)
print("Native CPU sampling quality passed without lost samples")
PY_QUALITY
echo "Native CPU profiles: $profiles"
echo "Native workload CPU reports: $reports"

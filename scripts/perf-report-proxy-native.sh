#!/usr/bin/env bash
set -euo pipefail
workload="${1:?native workload is required}"
export QPX_NATIVE_PROFILE_DIR="${2:?native profile directory is required}"
log_directory="${3:?native workload log directory is required}"
QPX_NATIVE_PERF_BIN="${QPX_NATIVE_PERF_BIN:?native perf executable is required}"
case "$workload" in
  http1) roles=qpxd; expected_profiles=1; minimum_reports=6 ;;
  proxy) roles="qpxd-cache qpxd-feature-rich"; expected_profiles=2; minimum_reports=11 ;;
  feature-large) roles=qpxd-feature-rich; expected_profiles=1; minimum_reports=3 ;;
  webdav) roles="qpxd-webdav apache-webdav"; expected_profiles=2; minimum_reports=12 ;;
  http2) roles=qpxd-h2; expected_profiles=1; minimum_reports=12 ;;
  streaming) roles="qpxd-streaming streaming-backend"; expected_profiles=2; minimum_reports=18 ;;
  *) echo "unsupported native report workload: $workload" >&2; exit 2 ;;
esac

# Harness shutdown also closes perf's output before report generation.
echo "Native CPU report generation started: $workload"
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
  if [ "$workload" = proxy ] || [ "$workload" = feature-large ]; then
    role_log_directory="$log_directory/$role"
  fi
  if [ "$workload" = http2 ] || [ "$workload" = streaming ]; then
    sample_role=qpxd
  fi
  report_suffix=cpu-report
  callchain_suffix=callchains
  if [ "$role" = streaming-backend ]; then
    samples=("$role_log_directory"/streaming.qpxd.*.backend-rss-peak.samples.csv
             "$role_log_directory"/streaming.lighttpd.*.backend-rss-peak.samples.csv)
    report_suffix=backend-cpu-report
    callchain_suffix=backend-callchains
  else
    samples=("$role_log_directory"/*."$sample_role".*.rss-peak.samples.csv)
  fi
  for sample in "${samples[@]}"; do
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
      -i "$QPX_NATIVE_PROFILE_DIR/$role.data" >"$sample.$report_suffix.txt"
    if ! rg -q '^# Samples: [1-9]' "$sample.$report_suffix.txt"; then
      echo "native workload CPU profile contains no samples: $sample" >&2
      exit 1
    fi
    if { [ "$workload" = proxy ] || [ "$workload" = feature-large ]; } && [[ "$sample" = *.round-2.* ]]; then
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
        -i "$QPX_NATIVE_PROFILE_DIR/$role.data" >"$sample.$callchain_suffix.txt"
      if [ ! -s "$sample.$callchain_suffix.txt" ]; then
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

if [ "$workload" = http2 ]; then
  python3 - "$log_directory" "$QPX_NATIVE_PROFILE_DIR/tls-vectored-writes.json" <<'PY_TLS'
import json
from pathlib import Path
import sys
root, output = map(Path, sys.argv[1:])
started = 0
samples = []
for path in sorted(root.rglob("*.log")):
    for line in path.read_text().splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("target") != "qpx_perf_tls":
            continue
        fields = record.get("fields", record)
        if fields.get("message") == "coalesced vectored write diagnostics enabled":
            started += 1
            continue
        if fields.get("message") != "coalesced pending vectored write sampled":
            continue
        names = ("pending_bytes", "first_slice_bytes", "offered_bytes", "offered_slices",
                 "consumed_bytes", "omitted_slice_bytes", "sample_interval")
        if not all(type(fields.get(name)) is int and fields[name] >= 0 for name in names):
            raise SystemExit("TLS vectored-write diagnostic has invalid counters")
        if (fields["sample_interval"] != 1024 or fields["offered_slices"] == 0
                or fields["consumed_bytes"] > fields["first_slice_bytes"]
                or fields["offered_bytes"] < fields["first_slice_bytes"]
                or fields["omitted_slice_bytes"] != fields["offered_bytes"] - fields["first_slice_bytes"]):
            raise SystemExit("TLS vectored-write diagnostic counters are inconsistent")
        samples.append({name: fields[name] for name in names})
if started == 0:
    raise SystemExit("TLS vectored-write diagnostic did not start on a real connection")
output.write_text(json.dumps({
    "measurement": "native_tls_pending_vectored_write_samples_v1",
    "scope": "complete_profile_including_calibration_and_all_lanes",
    "started_connections": started, "sample_interval": 1024,
    "sampled_events": len(samples), "samples": samples,
}, indent=2) + "\n")
print(f"TLS pending vectored-write samples retained: {len(samples)}")
PY_TLS
fi

if [ "$workload" = streaming ]; then
  python3 - "$log_directory/backend-tcp.jsonl" <<'PY'
import json
from pathlib import Path
import sys
records = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines()]
# Five real servers, three interleaved rounds, 64 fast and one slow transfer.
if len(records) < 5 * 3 * (64 + 1):
    raise SystemExit("backend TCP diagnostics lack completed transfer records")
for record in records:
    if record.get("status") != "ok" or record.get("stream_bytes", 0) <= 0:
        raise SystemExit("backend TCP diagnostics contain a failed transfer snapshot")
    before, after = record["before"], record["after"]
    if after["monotonic_ns"] <= before["monotonic_ns"]:
        raise SystemExit("backend TCP diagnostic timestamps are not ordered")
    for snapshot in (before, after):
        if (len(bytes.fromhex(snapshot["tcp_info_hex"])) < 104
                or snapshot["send_buffer_bytes"] <= 0
                or snapshot["receive_buffer_bytes"] <= 0):
            raise SystemExit("backend TCP diagnostics contain an incomplete snapshot")
print(f"Backend TCP diagnostics validated: {len(records)} transfers")
PY
fi

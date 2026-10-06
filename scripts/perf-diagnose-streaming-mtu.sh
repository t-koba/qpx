#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ "$(uname -s)" != Linux ]; then
  echo "streaming MTU diagnostics require Linux" >&2
  exit 1
fi
if [ "$#" -eq 0 ]; then
  exec sudo --preserve-env=QPXD_BIN,GITHUB_SHA unshare --net bash "$0" --inside
fi
if [ "$#" -eq 1 ] && [ "$1" = --normal ]; then
  exec sudo --preserve-env=QPXD_BIN,GITHUB_SHA unshare --net bash "$0" --inside-normal
fi
if [ "$#" -eq 1 ] && [ "$1" = --unpartitioned-normal ]; then
  exec sudo --preserve-env=QPXD_BIN,GITHUB_SHA,QPX_STREAMING_MTU_ORDER unshare --net bash "$0" --inside-unpartitioned-normal
fi
if [ "$#" -ne 1 ] || [[ "$1" != --inside && "$1" != --inside-normal && "$1" != --inside-unpartitioned-normal ]] || [ "$(id -u)" -ne 0 ]; then
  echo "unsupported streaming MTU diagnostic invocation" >&2
  exit 2
fi
namespace="$(readlink /proc/self/ns/net)"
host_namespace="$(readlink /proc/1/ns/net)"
if [ "$namespace" = "$host_namespace" ]; then
  echo "streaming MTU diagnostics must not change the host network namespace" >&2
  exit 1
fi
if [[ ! "${SUDO_UID:-}" =~ ^[0-9]+$ ]] || [[ ! "${SUDO_GID:-}" =~ ^[0-9]+$ ]] || [ "$SUDO_UID" -eq 0 ]; then
  echo "streaming MTU diagnostics require an unprivileged invoking user" >&2
  exit 1
fi
mkdir -p "$ROOT_DIR/target/perf/profiles"
profile_dir="$(mktemp -d "$ROOT_DIR/target/perf/profiles/streaming-mtu.XXXXXX")"
chown "$SUDO_UID:$SUDO_GID" "$profile_dir"
affinity_arguments=()
evaluation_mode=window-diagnostic
cpu_partition=True
measurement_script="$ROOT_DIR/scripts/perf-diagnose-streaming-affinity.sh"
if [ "$1" = --inside-normal ]; then
  affinity_arguments=(--normal)
  evaluation_mode=partition-diagnostic
fi
if [ "$1" = --inside-unpartitioned-normal ]; then
  evaluation_mode=acceptance
  cpu_partition=False
  measurement_script="$ROOT_DIR/scripts/perf-audit-streaming-compare.sh"
fi
failed=0
case "${QPX_STREAMING_MTU_ORDER:-65536-1500}" in
  65536-1500) mtus=(65536 1500) ;;
  1500-65536) mtus=(1500 65536) ;;
  *) echo "unsupported streaming MTU order" >&2; exit 2 ;;
esac
for mtu in "${mtus[@]}"; do
  phase="$profile_dir/mtu-$mtu"
  mkdir "$phase"
  ip link set dev lo mtu "$mtu" up
  ip -json link show dev lo > "$phase/interfaces-before.json"
  python3 - "$phase" "$mtu" "$namespace" "$host_namespace" "$cpu_partition" <<'PY'
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
interfaces = json.loads((root / "interfaces-before.json").read_text())
mtu = int(sys.argv[2])
if len(interfaces) != 1 or interfaces[0]["ifname"] != "lo" or interfaces[0]["mtu"] != mtu:
    raise SystemExit("streaming diagnostic loopback MTU was not applied")
(root / "network-environment.json").write_text(json.dumps({
    "measurement": "streaming_same_runner_mtu_diagnostic_v1",
    "network_namespace": sys.argv[3], "host_network_namespace": sys.argv[4],
    "loopback_mtu": mtu, "diagnostic_cpu_partition": sys.argv[5] == "True",
    "replaces_required_gate": False,
}, indent=2) + "\n")
PY
  chown -R "$SUDO_UID:$SUDO_GID" "$phase"
  if ! setpriv --reuid "$SUDO_UID" --regid "$SUDO_GID" --init-groups env \
    QPX_STREAMING_COMPARE_LOG_DIR="$phase/logs" \
    python3 "$ROOT_DIR/scripts/perf-evaluate.py" "streaming MTU $mtu diagnostic measurement" -- \
      bash "$measurement_script" "${affinity_arguments[@]}" "$phase/comparison.jsonl"; then
    failed=1
  fi
  ip -json link show dev lo > "$phase/interfaces-after.json"
  python3 - "$phase" <<'PY'
import json
from pathlib import Path
import sys
root = Path(sys.argv[1])
if json.loads((root / "interfaces-before.json").read_text()) != json.loads((root / "interfaces-after.json").read_text()):
    raise SystemExit("streaming diagnostic interface changed during measurement")
PY
  if ! setpriv --reuid "$SUDO_UID" --regid "$SUDO_GID" --init-groups \
    python3 "$ROOT_DIR/scripts/perf-evaluate.py" "streaming MTU $mtu diagnostic objectives" -- \
      bash "$ROOT_DIR/scripts/check-streaming-performance.sh" "$phase/comparison.jsonl" \
      "$ROOT_DIR/perf/streaming-performance-objectives.json" "$evaluation_mode"; then
    failed=1
  fi
done
exit "$failed"

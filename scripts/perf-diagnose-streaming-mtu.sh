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
if [ "$#" -ne 1 ] || [ "$1" != --inside ] || [ "$(id -u)" -ne 0 ]; then
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
failed=0
for mtu in 65536 1500; do
  phase="$profile_dir/mtu-$mtu"
  mkdir "$phase"
  ip link set dev lo mtu "$mtu" up
  ip -json link show dev lo > "$phase/interfaces-before.json"
  python3 - "$phase" "$mtu" "$namespace" "$host_namespace" <<'PY'
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
    "loopback_mtu": mtu, "diagnostic_cpu_partition": True,
    "replaces_required_gate": False,
}, indent=2) + "\n")
PY
  chown -R "$SUDO_UID:$SUDO_GID" "$phase"
  if ! setpriv --reuid "$SUDO_UID" --regid "$SUDO_GID" --init-groups env \
    QPX_STREAMING_COMPARE_LOG_DIR="$phase/logs" \
    python3 "$ROOT_DIR/scripts/perf-evaluate.py" "streaming MTU $mtu diagnostic measurement" -- \
      bash "$ROOT_DIR/scripts/perf-diagnose-streaming-affinity.sh" "$phase/comparison.jsonl"; then
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
      "$ROOT_DIR/perf/streaming-performance-objectives.json" window-diagnostic; then
    failed=1
  fi
done
exit "$failed"

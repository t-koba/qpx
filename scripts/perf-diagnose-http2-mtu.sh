#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ "$(uname -s)" != Linux ]; then
  echo "HTTP/2 MTU diagnostics require Linux network namespaces" >&2
  exit 1
fi
if [ "$#" -eq 0 ]; then
  exec sudo unshare --net bash "$ROOT_DIR/scripts/perf-diagnose-http2-mtu.sh" --inside
fi
if [ "$#" -ne 1 ] || [ "$1" != --inside ] || [ "$(id -u)" -ne 0 ]; then
  echo "unsupported HTTP/2 MTU diagnostic invocation" >&2
  exit 2
fi
namespace="$(readlink /proc/self/ns/net)"
initial_namespace="$(readlink /proc/1/ns/net)"
if [ "$namespace" = "$initial_namespace" ]; then
  echo "HTTP/2 MTU diagnostic must not change the host network namespace" >&2
  exit 1
fi
if [[ ! "${SUDO_UID:-}" =~ ^[0-9]+$ ]] || [[ ! "${SUDO_GID:-}" =~ ^[0-9]+$ ]] || [ "$SUDO_UID" -eq 0 ]; then
  echo "HTTP/2 MTU diagnostic requires an unprivileged invoking user" >&2
  exit 1
fi
mkdir -p "$ROOT_DIR/target/perf/profiles"
profile_dir="$(mktemp -d "$ROOT_DIR/target/perf/profiles/http2-mtu.XXXXXX")"
ip link set dev lo mtu 1500 up
ip -json link show dev lo > "$profile_dir/interfaces.json"
python3 - "$profile_dir" "$namespace" "$initial_namespace" <<'PY_NAMESPACE'
import json
from pathlib import Path
import sys
root = Path(sys.argv[1])
interfaces = json.loads((root / "interfaces.json").read_text())
if len(interfaces) != 1 or interfaces[0]["ifname"] != "lo" or interfaces[0]["mtu"] != 1500:
    raise SystemExit("isolated HTTP/2 loopback MTU was not applied")
(root / "manifest.json").write_text(json.dumps({
    "measurement": "http2_isolated_mtu_v1", "diagnostic_instrumentation": True,
    "network_namespace": sys.argv[2], "host_network_namespace": sys.argv[3],
    "loopback_mtu": 1500, "body_bytes": 1048576, "max_concurrent_streams": 100,
    "required_samples_per_role": 3, "replaces_required_gate": False,
}, indent=2) + "\n")
PY_NAMESPACE
chown -R "$SUDO_UID:$SUDO_GID" "$profile_dir"
# Run servers as the original user inside the owned namespace, not as root.
# Request completion and duration checks remain mandatory.
exec setpriv --reuid "$SUDO_UID" --regid "$SUDO_GID" --init-groups env \
  QPX_HTTP2_COMPARE_NATIVE_DIAGNOSTICS=1 QPX_HTTP2_COMPARE_BODY_SIZES=1048576 \
  QPX_HTTP2_COMPARE_MAX_CONCURRENT_STREAMS_VALUES=100 \
  QPX_HTTP2_COMPARE_SAMPLE_ATTEMPTS=3 \
  bash "$ROOT_DIR/scripts/perf-audit-http2-compare.sh"

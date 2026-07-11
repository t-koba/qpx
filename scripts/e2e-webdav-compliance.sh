#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
QPXD_BIN="${QPXD_BIN:-$ROOT_DIR/target/debug/qpxd}"
LITMUS_BIN="${LITMUS_BIN:?LITMUS_BIN is required}"
CALDAVTESTER_DIR="${CALDAVTESTER_DIR:?CALDAVTESTER_DIR is required}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/qpx-webdav-e2e.XXXXXX")"
QPXD_PID=""

cleanup() {
  if [[ -n "$QPXD_PID" ]]; then kill "$QPXD_PID" 2>/dev/null || true; fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

mkdir -p "$TMP_DIR/root/dav" "$TMP_DIR/state"
QPX_STATE_DIR="$TMP_DIR/state" \
QPX_WEBDAV_ROOT="$TMP_DIR/root" \
QPX_WEBDAV_METADATA="$TMP_DIR/webdav.redb" \
  "$QPXD_BIN" run -c "$ROOT_DIR/integration/webdav/qpx.yaml" >"$TMP_DIR/qpxd.log" 2>&1 &
QPXD_PID=$!
for _ in $(seq 1 60); do
  if nc -z 127.0.0.1 18086 >/dev/null 2>&1; then break; fi
  sleep 1
done
nc -z 127.0.0.1 18086

"$LITMUS_BIN" http://127.0.0.1:18086/dav/ unused unused

mkdir -p "$TMP_DIR/caldav/tests" "$TMP_DIR/caldav/data"
cp "$ROOT_DIR/integration/webdav/caldav/serverinfo.xml" "$TMP_DIR/caldav/serverinfo.xml"
cp "$ROOT_DIR/integration/webdav/caldav/tests/qpx.xml" "$TMP_DIR/caldav/tests/qpx.xml"
cp "$ROOT_DIR/integration/webdav/caldav/data/"* "$TMP_DIR/caldav/data/"
cp "$CALDAVTESTER_DIR/scripts/server/serverinfo.dtd" "$TMP_DIR/caldav/serverinfo.dtd"
cp "$CALDAVTESTER_DIR/scripts/tests/CalDAV/caldavtest.dtd" "$TMP_DIR/caldav/tests/caldavtest.dtd"
(
  cd "$CALDAVTESTER_DIR"
  python3 testcaldav.py \
    --print-details-onfail --stop \
    --basedir "$TMP_DIR/caldav" qpx.xml
)
echo "WebDAV and CalDAV external compliance suites passed"

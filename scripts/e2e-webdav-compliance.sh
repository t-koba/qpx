#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
QPXD_BIN="${QPXD_BIN:-$ROOT_DIR/target/debug/qpxd}"
LITMUS_BIN="${LITMUS_BIN:?LITMUS_BIN is required}"
CALDAV_TESTER_BIN="${CALDAV_TESTER_BIN:?CALDAV_TESTER_BIN is required}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/qpx-webdav-e2e.XXXXXX")"
QPXD_PID=""

cleanup() {
  status=$?
  if [[ -n "$QPXD_PID" ]]; then kill "$QPXD_PID" 2>/dev/null || true; fi
  if [[ $status -ne 0 ]]; then
    [[ -f "$TMP_DIR/qpxd.log" ]] && sed -n '1,240p' "$TMP_DIR/qpxd.log" >&2
    [[ -f "$TMP_DIR/caldav-results.json" ]] && cat "$TMP_DIR/caldav-results.json" >&2
  fi
  rm -rf "$TMP_DIR"
  exit "$status"
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

curl --fail --silent --show-error \
  --request MKCALENDAR \
  --header 'Content-Type: application/xml' \
  --data '<C:mkcalendar xmlns:C="urn:ietf:params:xml:ns:caldav" xmlns:D="DAV:"><D:set><D:prop><D:displayname>Compliance</D:displayname></D:prop></D:set></C:mkcalendar>' \
  http://127.0.0.1:18086/dav/compliance

"$CALDAV_TESTER_BIN" \
  --caldav-url http://127.0.0.1:18086/dav/ \
  --caldav-username unused \
  --caldav-password unused \
  --run-feature create-calendar \
  --run-feature search.time-range.event \
  --run-feature freebusy-query \
  --format json >"$TMP_DIR/caldav-results.json"
jq -e '.features | length == 0' "$TMP_DIR/caldav-results.json" >/dev/null
echo "WebDAV and CalDAV external compliance suites passed"

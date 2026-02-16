# Local Response and Routing Guide

`qpxd` can return proxy-local responses without forwarding traffic upstream.
Use this for block pages, maintenance notices, health endpoints, and captive-portal responses.

## 1. Where it works

- Forward proxy:
  - `listeners[].rules[].action.type: respond`
- Transparent proxy:
  - `listeners[].rules[].action.type: respond`
- Reverse proxy:
  - `reverse[].routes[].local_response`

## 2. Configuration rules

- `respond` requires `local_response`:
  - `listeners[].default_action`
  - `listeners[].rules[].action`
- For reverse routes, set exactly one:
  - `upstreams`
  - `local_response`
- TLS passthrough is configured separately:
  - `reverse[].tls_passthrough_routes[]`
  - TLS passthrough routes do not support `local_response`.

## 3. Response shape

`local_response` fields:
- `status` (`u16`, default `200`)
- `body` (`string`)
- `content_type` (`string`, optional)
- `headers` (`map<string,string>`, optional)

If `content_type` is omitted and `body` is non-empty, `qpxd` sets:
- `Content-Type: text/plain; charset=utf-8`

## 4. Header policy interaction

- Forward/transparent mode:
  - `headers.response_*` controls are applied to local responses too.
- Reverse mode:
  - Local responses are defined directly in the matched route.

## 5. HTTP semantics applied

Even for local responses, `qpxd` keeps RFC-conformant message semantics:
- no response body for `HEAD`
- no response body for `1xx`, `204`, `304`
- hop-by-hop header sanitization and `Via` behavior are kept consistent with proxy paths

## 6. Ready-to-use samples

- `config/usecases/06-local-response/all-modes-policy.yaml`
- `config/usecases/06-local-response/forward-debug.yaml`
- `config/usecases/06-local-response/reverse-maintenance.yaml`
- `config/usecases/06-local-response/transparent-captive-portal.yaml`

## 7. Quick verification commands

Forward local response:
```bash
target/debug/qpxd run --config config/usecases/06-local-response/forward-debug.yaml
curl -sS -x http://127.0.0.1:18181 -H 'Host: proxy.local' http://proxy.local/proxy/healthz
curl -i -sS -x http://127.0.0.1:18181 http://bad.phishing.invalid/
```

Reverse local response:
```bash
target/debug/qpxd run --config config/usecases/06-local-response/reverse-maintenance.yaml
curl -i -sS -H 'Host: app.example.com' http://127.0.0.1:19181/status
curl -i -sS -H 'Host: app.example.com' http://127.0.0.1:19181/maintenance/window
```

Transparent local response (Host/SNI fallback path):
```bash
target/debug/qpxd run --config config/usecases/06-local-response/transparent-captive-portal.yaml
curl -i -sS -H 'Host: connectivitycheck.gstatic.com' http://127.0.0.1:15181/generate_204
```

Automated end-to-end:
```bash
cargo build -p qpxd
./scripts/e2e-local-response.sh
```

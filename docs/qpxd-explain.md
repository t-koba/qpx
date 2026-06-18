# qpxd explain

`qpxd explain` renders the compiled runtime plan.

```bash
qpxd explain -c config/qpx.example.yaml --edge site --route app
qpxd explain -c config/qpx.example.yaml --format json
```

The JSON output is deterministic and includes:

- edge and route identity
- target type
- effective streaming limits
- module body mode
- buffering requirement and reasons
- cache, capture, response-rule, and local-response summaries

## JSON Contract

`qpxd explain --format json` is the current canonical output contract for the
checked-out release or commit. It is not versioned and does not carry backward
compatibility branches: when the contract intentionally changes, update this
document, examples, and snapshots in the same change. Snapshot tests guard
against accidental drift.

Top-level shape:

```json
{
  "edges": [
    {
      "edge": "public-http",
      "kind": "reverse",
      "aggregate_execution_plan": ["capture_plaintext"],
      "routes": [
        {
          "name": "app",
          "target": {"type": "upstream"},
          "execution_plan": {}
        }
      ],
      "tls_passthrough_routes": []
    }
  ]
}
```

Common `execution_plan` fields:

- `flags`: compiled execution flags such as `auth`, `ext_authz`,
  `cache_lookup`, `response_rules`, `request_modules`, `response_modules`,
  `capture_plaintext`, `capture_body`, `retry_body_buffer`, `mirroring`,
  `websocket`, `ipc`, and `frozen_request`.
- `streaming`: resolved body channel, body timeout, HTTP/3 body byte, gRPC,
  and SSE limits.
- `module_body_mode`: aggregate module body mode, for example
  `headers_only`, `stream_transform`, `request_buffer_inspect`,
  `response_buffer_inspect`, or `request_and_response_buffer_inspect`.
- `buffering`: `{ "required": bool, "reasons": [string] }`.
- `capture`: encrypted/plaintext capture summary.
- `cache`: configured cache backend summary, or `null`.
- `local_response`: local response summary, or `null`.
- `modules`: stage-to-module labels.
- `module_details`: per-module body mode, streaming safety, and module-specific
  details.
- `response_rules`: response-rule observation summary, or `null`.

Reverse `target.type` is one of `upstream`, `weighted`, `ipc`,
`local_response`, or `tls_passthrough`. Forward and transparent rules render an
`action` plus an `execution_plan`.

## Buffering Reasons

Buffering reasons use a small string vocabulary shared by docs, JSON, and
runtime metrics:

- `request.size_exact_unknown`
- `response.size_exact_unknown`
- `response_rules.response_size_exact_unknown`
- `rpc.body`
- `http_guard.body`
- `retry.body_template`
- `http_modules.request_body`
- `http_modules.response_body`
- `response_rules.response_body`
- `response_rules.request_body`

`streaming_requirement: required` rejects any route or action that would emit a
buffering reason. Use `streaming_requirement: preferred` only when bounded
buffering is an intentional cost.

Example no-buffering route:

```yaml
edges:
- kind: reverse
  name: api
  listen: 127.0.0.1:8443
  routes:
  - name: stream-only
    streaming_requirement: required
    match:
      host: [api.example.test]
    target:
      type: upstream
      upstreams: [http://127.0.0.1:8080]
```

Expected JSON excerpt:

```json
{
  "name": "stream-only",
  "execution_plan": {
    "buffering": {
      "required": false,
      "reasons": []
    }
  }
}
```

Use this in CI to reject unexpected buffering before a config is deployed.

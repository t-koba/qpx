# Module Body Modes

HTTP modules declare their body access capability. The compiled route plan aggregates those capabilities and exposes buffering reasons through `qpxd explain`.

Modes:

- `headers_only`: does not inspect or rewrite body bytes.
- `stream_transform`: transforms chunks while preserving streaming.
- `stream_observe`: observes bounded chunk summaries while preserving
  streaming.
- `buffer_inspect`: inspects a materialized request or response body.
- `buffer_rewrite`: rewrites a materialized request or response body, unless
  implemented as a streaming transform.
- `request_body_buffered`: needs the request body materialized.
- `response_body_buffered`: needs the response body materialized.
- `request_and_response_body_buffered`: needs both directions materialized.

Streaming-safe modes are `headers_only`, `stream_transform`, and bounded
`stream_observe`. Buffering-required modes are `buffer_inspect`,
`buffer_rewrite`, `request_body_buffered`, `response_body_buffered`, and
`request_and_response_body_buffered`.

Built-in module contract:

| Module class | Body mode | Streaming contract |
| --- | --- | --- |
| Header mutation / cache purge | `headers_only` | Streaming safe. |
| Response compression | `stream_transform` | Streaming safe with bounded worker backpressure. |
| Bounded observers | `stream_observe` | Streaming safe while limits are enforced. |
| Exact body inspection | `buffer_inspect` | Buffering required. |
| Full body rewrite | `buffer_rewrite` | Buffering required unless implemented as a streaming transform. |
| Subrequest | `headers_only` today | Phase-dependent; request and response header phases stay streaming safe unless future settings require body access. |

`streaming_requirement: required` rejects buffering-required modules. Omitted `streaming_requirement` also rejects implicit buffering. `streaming_requirement: preferred` is the explicit opt-in for bounded buffering features.

`qpxd explain --format json` reports the aggregate `module_body_mode` and each
module's `module_details` with `body_mode`, `streaming_safe`, and any configured
buffer byte caps. Use these snapshots to prevent accidental module contract
drift.

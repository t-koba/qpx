# Module Body Modes

HTTP modules declare their body access capability. The compiled route plan aggregates those capabilities and exposes buffering reasons through `qpxd explain`.

Modes:

- `headers_only`: does not inspect or rewrite body bytes.
- `streaming`: transforms or observes chunks while preserving streaming.
- `request_body_buffered`: needs the request body materialized.
- `response_body_buffered`: needs the response body materialized.
- `request_and_response_body_buffered`: needs both directions materialized.

`streaming_requirement: required` rejects buffering-required modules. Omitted `streaming_requirement` also rejects implicit buffering. `streaming_requirement: preferred` is the explicit opt-in for bounded buffering features.

# HTTP/3 Streaming

HTTP/3 request and response bodies are relayed as bounded streams. `Content-Length` is checked against transmitted body bytes on supported ingress and upstream paths. Response send failures are stage-aware: qpx can send fallback responses only before final response headers have been sent.

Request body drain is controlled by:

```yaml
runtime:
  h3_request_body_drain:
    mode: bounded
    max_concurrent: 1024
    timeout_ms: 30000
```

Metrics:

- `qpx_h3_request_body_drains_started_total`
- `qpx_h3_request_body_drains_completed_total`
- `qpx_h3_request_body_drains_aborted_total`
- `qpx_h3_request_body_drains_limited_total`
- `qpx_h3_request_body_drain_duration_seconds`
- `qpx_h3_response_send_errors_total`
- `qpx_h3_origin_pool_connections`
- `qpx_h3_origin_pool_inflight`
- `qpx_h3_origin_pool_wait_seconds`
- `qpx_h3_origin_pool_reuse_total`
- `qpx_h3_origin_pool_evictions_total`
- `qpx_h3_origin_pool_connection_errors_total`

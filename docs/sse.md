# SSE

`text/event-stream` responses are treated as latency-sensitive streams. Compression is bypassed by default through the SSE policy, and body buffering is not part of the default SSE path.

Config:

```yaml
sse:
  disable_compression: true
  flush_policy: low_latency
  idle_timeout_ms: 300000
  max_stream_duration_ms: 3600000
  max_line_bytes: 8192
  max_event_id_bytes: 256
```

Metrics:

- `qpx_sse_events_total`
- `qpx_sse_bytes_total`
- `qpx_sse_stream_duration_seconds`
- `qpx_sse_streams_active`
- `qpx_sse_first_event_latency_seconds`
- `qpx_sse_inter_event_latency_seconds`
- `qpx_sse_idle_disconnects_total`
- `qpx_sse_idle_timeouts_total`
- `qpx_sse_max_duration_exceeded_total`
- `qpx_sse_reconnections_total`

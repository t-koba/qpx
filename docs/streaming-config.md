# Streaming Configuration

qpx resolves streaming limits in this order:

1. route-level `streaming`, `grpc`, and `sse`
2. listener-level `streaming`, `grpc`, and `sse`
3. `runtime` defaults

The resolved values are used by HTTP/3 request relays, HTTP/3 response senders,
HTTP/1 and HTTP/2 ingress body channels, response compression, and RPC frame
observers.

## Runtime Defaults

```yaml
runtime:
  body_channel_capacity: 16
  h3_origin_pool_max_connections_per_origin: 4
  h3_origin_pool_max_inflight_streams_per_connection: 128
  unknown_length_exact_size: reject
  max_grpc_message_bytes: 4194304
  max_grpc_web_trailer_bytes: 65536
  max_grpc_stream_duration_ms: 300000
  sse:
    disable_compression: true
    flush_policy: low_latency
    idle_timeout_ms: 300000
    max_stream_duration_ms: 3600000
    max_line_bytes: 8192
    max_event_id_bytes: 256
```

## Listener And Route Overrides

```yaml
edges:
- kind: reverse
  name: api
  listen: 127.0.0.1:8443
  streaming:
    body_channel_capacity: 32
    body_read_timeout_ms: 30000
    body_send_timeout_ms: 30000
  grpc:
    max_message_bytes: 16777216
    max_web_trailer_bytes: 65536
    max_stream_duration_ms: 300000
    observe_messages: true
  sse:
    disable_compression: true
    flush_policy: low_latency
    idle_timeout_ms: 300000
    max_stream_duration_ms: 3600000
    max_line_bytes: 8192
    max_event_id_bytes: 256
  routes:
  - name: ml-inference
    match:
      host: ["ml.example.test"]
    target:
      type: upstream
      upstreams: ["ml"]
    streaming:
      body_channel_capacity: 64
      body_read_timeout_ms: 120000
    capture:
      plaintext:
        enabled: true
        headers: true
        body: stream_sample
        body_sample_bytes: 4096
    grpc:
      max_stream_duration_ms: 7200000
    streaming_requirement: required
```

## Protocol Guidance

General HTTP usually works with the defaults. Increase
`body_channel_capacity` only when upstream and downstream flow control can
benefit from more in-flight chunks.

For gRPC unary traffic, keep short body timeouts and the default capacity. For
gRPC streaming, use a larger capacity, set `max_stream_duration_ms` to the
expected call duration, and rely on `grpc-timeout` to propagate tighter client
deadlines upstream.

For SSE, keep compression disabled, use `flush_policy: low_latency`, and set
`idle_timeout_ms` higher than the longest expected heartbeat gap.

WebTransport uses its own datagram and associated stream capacities under
`runtime.webtransport_*`.

HTTP/3 upstream relay is enabled with `h3://` upstream URLs when the
`http3-backend-h3` feature is active. HTTPS upstream discovery also records
same-host `Alt-Svc: h3=":port"` alternatives and DNS HTTPS records with
`alpn=h3`; safe empty-body requests may use the discovered H3 endpoint while
retaining HTTPS fallback. Cross-host Alt-Svc alternatives are intentionally not
used. `h3_origin_pool_max_connections_per_origin` and
`h3_origin_pool_max_inflight_streams_per_connection` tune H3 origin pools; with
the qpx HTTP/3 backend they also tune upstream qpx-h3 CONNECT/WebTransport
session pooling.

The default hot path is streaming-first: routes do not buffer bodies unless a
feature explicitly requires exact body inspection or retry templating.
`body: stream_sample` keeps body capture on the streaming path by emitting only
the first `body_sample_bytes`. `body: full` also stays on the streaming path by
teeing chunks to the exporter while forwarding them, but it must be bounded
with `max_body_bytes`.

When `streaming_requirement` is omitted, qpx keeps the hot path
streaming-first and rejects any route/action that can buffer bodies. Set
`streaming_requirement: preferred` to explicitly opt into exact inspection and
bounded buffering. Set `streaming_requirement: required` to keep a hard
no-buffering assertion. Unknown-length exact `request_size` / `response_size`
matching also requires `runtime.unknown_length_exact_size: buffer`; the default
`reject` mode keeps this EOF/spool/replay path out of the hot path even when a
route has `streaming_requirement: preferred`. The guarded features include
`request_size` / `response_size` matchers, buffering HTTP guard profiles,
`match.rpc.*` predicates that need full request/response body observation,
retry templates, buffering HTTP modules, and response
rules that need request or response body observation.

When `Content-Length` is unavailable, exact `request_size` / `response_size`
matching must read the body to EOF to compute the exact size and then replay
it. That path is intentionally treated as explicit bounded buffering rather
than as part of the default streaming hot path.

Other intentionally non-hot-path features follow the same contract:

- cache writeback keeps the client response path streaming and passes the
  mirrored body directly into the backend streaming write API; custom backends
  must implement that API instead of relying on implicit full-object reads;
- HTTP/3 SETTINGS and known control frames are decoded from the stream without
  holding the whole frame payload, while HEADERS/trailers still hold the
  bounded QPACK field section until it can be decoded;
- response compression is an explicit response module and uses a bounded,
  per-module worker pool; tune
  `settings.worker_count` for compression-heavy routes;
- FTP-over-HTTP is a compatibility path that bridges to blocking FTP I/O and is
  not part of the zero-buffer HTTP hot path.

Use `qpxd explain` to make the cost explicit before rollout. Routes that can
buffer bodies include a section like:

```text
buffering
  mode: explicit
  because
    - rpc.body
    - request.size_exact_unknown
    - retry.body_template
```

## Observability

RPC streaming observability emits protocol-level metrics for gRPC, gRPC-Web,
and Connect:

- `qpx_rpc_messages_total`
- `qpx_rpc_message_bytes_total`
- `qpx_rpc_status_total`
- `qpx_rpc_stream_duration_seconds`

SSE observability emits:

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

`qpx_upstream_slow_body_total` increments when a streamed response body read
takes at least 80% of the configured body read timeout.

Body buffering observability emits:

- `qpx_body_buffering_events_total{direction,reason}`
- `qpx_body_buffering_bytes_total{direction,reason}`
- `qpx_body_spooled_bytes_total{direction,reason}`
- `qpx_body_spool_errors_total{direction,reason,error}`
- `qpx_body_spool_cleanup_errors_total{direction,reason,error}`
- `qpx_body_mirror_drops_total{mirror,reason}`
- `qpx_cache_writeback_body_bytes_total`

The `reason` label matches the `qpxd explain` cost vocabulary, for example
`rpc.body`, `request.size_exact_unknown`, `response.size_exact_unknown`,
or `http_guard.body`.

Cache writeback uses a lossy mirror so downstream response streaming is not
blocked by a slow cache backend. Dropped writeback mirror chunks increment
`qpx_body_mirror_drops_total{mirror="cache_writeback",...}` so hit-rate loss
under load is visible without putting cache completeness back on the hot path.
Reverse streaming mirrors use the same primary-protecting drop behavior and
report `qpx_body_mirror_drops_total{mirror="reverse_streaming_mirror",...}`.
Built-in HTTP and Redis cache backends stream the mirrored body directly from
the writeback worker into the backend while enforcing the cache object byte cap.
The metadata commit happens only after the backend body write succeeds. Custom
cache backends must implement `put_object_stream`; the trait default fails
closed so a custom backend cannot accidentally reintroduce hidden full-object
materialization.

Tunnel observability emits the common tunnel metric family across TCP CONNECT,
WebSocket upgrade tunnels, HTTP/2 and HTTP/3 extended CONNECT, and
WebTransport bidi streams:

- `qpx_tunnel_active{protocol,listener,route}`
- `qpx_tunnel_bytes_total{protocol,listener,route,direction}`
- `qpx_tunnel_duration_seconds{protocol,listener,route,close_reason}`
- `qpx_tunnel_resets_total{protocol,listener,route,reason}`
- `qpx_tunnel_idle_timeouts_total{protocol,listener,route}`
- `qpx_tunnel_low_speed_timeouts_total{protocol,listener,route}`
- `qpx_tunnel_backpressure_seconds_total{protocol,listener,route,direction}`

Generic stream aliases (`qpx_streams_active`, `qpx_stream_bytes_total`,
`qpx_stream_duration_seconds`, `qpx_stream_resets_total`,
`qpx_stream_idle_timeouts_total`, and `qpx_stream_backpressure_seconds_total`)
use the same low-cardinality `protocol`, `listener`, `route`, `direction`, and
`reason` vocabulary for dashboards that combine tunnel and non-tunnel streams.

## Troubleshooting

If memory grows under streaming load, lower `body_channel_capacity` before
lowering body size limits. If latency grows, inspect upstream body timing and
SSE/gRPC stream duration metrics. If gRPC calls end early, compare the inbound
`grpc-timeout` with the resolved proxy `max_stream_duration_ms`.

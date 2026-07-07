# RPC Streaming

qpx observes gRPC, gRPC-Web, and Connect streams incrementally. Message limits are enforced while frames are parsed, and status is extracted from protocol-appropriate trailers or end-stream metadata.

Metrics:

- `qpx_rpc_messages_total`
- `qpx_rpc_message_bytes_total`
- `qpx_rpc_status_total`
- `qpx_rpc_stream_duration_seconds`

High-cardinality labels such as service, method, procedure, user, and peer address are not default metrics labels. Put detailed values in access logs or audit records instead.

Observer contract tests live in qpxd, not qpx-http. The observer implementation
is tied to qpxd's HTTP dispatch, body limits, streaming deadlines, and metric
emission; qpx-http intentionally remains a transport helper crate without a
public observer surface. The regression contract is fixed by qpxd gRPC,
gRPC-Web, Connect, and SSE tests plus the matching fuzz targets.

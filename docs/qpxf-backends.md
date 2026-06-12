# qpxf Backends

qpxf runs CGI, FastCGI, SCGI, and WASM backends behind the qpx IPC boundary. Backend failures are treated as response failures and should not return incomplete pooled connections to service.

Important operational limits:

- request stdin byte limits
- response byte limits
- backend timeout
- stderr logging policy
- IPC SHM/TCP mode

Metrics use the `qpxf_backend_*` family:

- `qpxf_backend_requests_total{kind,result}`
- `qpxf_backend_connections_active{kind}`
- `qpxf_backend_pool_reuse_total{kind}`
- `qpxf_backend_pool_discard_total{kind,reason}`
- `qpxf_backend_response_wait_seconds{kind}`
- `qpxf_backend_broken_responses_total{kind,reason}`
- `qpxf_backend_timeouts_total{kind,phase}`

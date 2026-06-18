# qpxf Backends

qpxf runs CGI, FastCGI, SCGI, and WASM backends behind the qpx IPC boundary.
Backend failures are treated as response failures and should not return
incomplete pooled connections to service.

## Failure Matrix

| Backend | Failure | Expected qpxf behavior |
| --- | --- | --- |
| FastCGI | backend closes mid-response | fail request and discard connection |
| FastCGI | missing `END_REQUEST` | fail request and discard connection |
| FastCGI | slow backend timeout | fail request and do not reuse connection |
| FastCGI | incomplete response | never return connection to idle pool |
| FastCGI | complete responder `END_REQUEST` | return connection to idle pool when `pool.max_idle` allows |
| SCGI | invalid or missing non-empty `Content-Length` | reject before collecting stdin |
| SCGI | backend closes mid-response | fail request |
| SCGI | backend does not read body | timeout or write failure cleans up worker |
| SCGI | invalid response header | server-side CGI response parsing rejects the response |
| SCGI | client cancel | abort worker and release concurrency permit |

FastCGI pooling is intentionally conservative: a connection is reusable only
after a complete responder `END_REQUEST`. SCGI uses per-request connections and
requires a valid `Content-Length` for non-empty stdin so qpxf does not buffer
the full upload to construct the SCGI netstring.

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

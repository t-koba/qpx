# Function Executor

`qpxf` is a hardened function executor that runs alongside `qpxd`. `qpxd`
routes reverse requests to `qpxf` over QPX-IPC with route targets of
`target.type: ipc`; `qpxf` owns the IPC server, routing, and backend execution.

The default `qpxf` build enables the `wasm` feature, which pulls in
`qpx-wasm`. Use `cargo build -p qpxf --no-default-features` for a CGI-only
build.

## Backends

| Backend | Runtime behavior |
|---|---|
| CGI scripts | Spawns RFC 3875-style external processes with path containment, symlink-escape prevention, concurrent I/O, and configurable size limits. |
| WASM modules | Executes WASI-compatible modules through `qpx-wasm` / wasmtime with module/stdin/stdout/stderr caps, memory limits, wall-clock timeout, stderr capture, and optional pool/prewarm settings. |
| FastCGI | Sends CGI-shaped requests to persistent FastCGI responders over TCP or `unix://`, with per-backend connection pool limits and deterministic `SCRIPT_NAME` / `PATH_INFO` splitting via `script_name_prefixes`. |
| SCGI | Sends CGI-shaped requests to SCGI responders over TCP or `unix://` using per-request connections. Non-empty stdin requires a valid `Content-Length` so the SCGI netstring can be built without buffering the full upload. |

## IPC Transport

For local deployments, `qpxf` defaults to a user-scoped `unix://` socket. Any
TCP listener, including loopback, requires `allow_insecure_tcp: true` in the
`qpxf` config.

For `target.type: ipc` reverse routes, `mode` controls body transfer:

| `mode` | Body transfer | When to use |
|---|---|---|
| `shm` | Shared-memory ring buffer | Same-host Unix deployments with owner-only SHM file permissions. |
| `tcp` | Streamed over the IPC connection | Cross-host, Windows, or other non-Unix deployments. |

```yaml
routes:
  - match: { path: ["/cgi-bin/*"] }
    target:
      type: ipc
      endpoint: "${QPXF_UNIX_LISTEN}"
      mode: shm
      timeout_ms: 30000
```

## Local Sample

```bash
# Validate the paired qpxf sample, including backend initialization.
cargo run -p qpxf -- check --config config/usecases/12-ipc-gateway/qpxf.yaml

# Start qpxf.
qpxf_runtime="${XDG_RUNTIME_DIR:-$HOME/.qpx/run}"
install -d -m 700 "$qpxf_runtime"
export QPXF_UNIX_LISTEN="unix://$qpxf_runtime/qpxf.sock"
cargo run -p qpxf -- --listen "$QPXF_UNIX_LISTEN" --config config/usecases/12-ipc-gateway/qpxf.yaml

# Start qpxd routed to qpxf.
cargo run -p qpxd -- run --config config/usecases/12-ipc-gateway/qpx.yaml
```

The `12-ipc-gateway` sample pair ships with repo-local CGI/WASM fixture
handlers so it can be checked and smoke-tested as-is. Override
`QPXF_SAMPLE_CGI_ROOT` / `QPXF_SAMPLE_WASM_MODULE` to use your own handlers.

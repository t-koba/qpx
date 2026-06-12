# qpx Architecture

`qpx` is a Rust workspace for forward, reverse, transparent, HTTP/3, capture, and IPC proxying. The workspace is intentionally split so reusable protocol/config code stays outside the daemon and high-risk I/O boundaries remain explicit.

## Crates

- `qpx-core`: shared configuration types, validation, redaction, TLS helpers, shared-memory ring, and low-level protocol utilities.
- `qpx-http`: shared HTTP runtime primitives (body channels/spooling with cancellation, protocol helpers, sharding, TLS glue) lifted out of `qpxd` for reuse by sibling crates.
- `qpx-auth`: Basic, Digest, LDAP, and auth cache logic.
- `qpx-h3`: the qpx-owned HTTP/3 transport implementation used where the stock `h3` crate cannot expose the required control points.
- `qpx-wasm`: WASM execution support used by `qpxf`.
- `qpx-acme`: ACME provisioning helpers.
- `qpx-observability`: access logging, file logging, and tracing support.
- `qpxd-cache`: RFC 9111 proxy cache implementation (entries, freshness, Vary, invalidation, in-memory / Redis / HTTP object-storage backends).
- `qpxd`: the proxy daemon. It owns runtime plans, listeners, forwarding, reverse dispatch, cache orchestration, transparent mode, HTTP/3 broker, and upstream clients.
- `qpxf`: IPC/CGI/FastCGI/SCGI/WASM backend executor.
- `qpxr`: capture stream receiver.
- `qpxc`: capture/control CLI.
- `xtask`: repository structure and budget gates.

## qpxd Runtime Shape

Configuration is parsed in `qpx-core`, compiled into a `RuntimePlan` in `qpxd`, and then consumed by listener-specific dispatch paths. Request handling is intentionally split by ingress type:

- forward HTTP/1, HTTP/2, and HTTP/3 under `qpxd/src/forward/`
- reverse HTTP and IPC under `qpxd/src/reverse/`
- transparent HTTP/UDP under `qpxd/src/transparent/`
- shared HTTP body, policy, module, cache, and protocol helpers under `qpxd/src/http/`
- upstream origin and proxy clients under `qpxd/src/upstream/`

Dispatch paths should keep ingress-specific code thin and delegate common behavior to `qpxd/src/http/dispatch`, `qpxd/src/http/body`, and shared policy helpers. `cargo xtask structure` enforces file-size and dependency-direction budgets so new code does not grow monolithic dispatch files again.

## Streaming Contract

The default contract is streaming-first. Features that require exact body inspection, unknown-length exact-size matching, retry templates, or non-streaming mirrors are explicit compatibility paths. Runtime plans carry buffering reasons, and `streaming_requirement` validation rejects implicit buffering where the route asks for strict streaming.

## Security Boundaries

External protocol input must not panic. Network parsing errors should return protocol errors, reset streams, or drop packets. Secure local files must use owner-only permissions and reject symlinks or hard links. Shared-memory and capture paths are treated as sensitive plaintext surfaces.

## Quality Gates

The repository gate is not a checklist in prose. It is enforced through:

- `cargo fmt --check`
- `cargo clippy --workspace --all-targets --locked -- -D warnings`
- `cargo test --workspace --locked`
- `cargo doc --workspace --locked --no-deps --document-private-items` with `RUSTDOCFLAGS=-D warnings`
- `cargo xtask structure`
- `cargo xtask budget`
- CI e2e, perf smoke, fuzz smoke, sanitizer, and release preflight jobs


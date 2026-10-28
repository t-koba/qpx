# qpx Architecture

`qpx` is a Rust workspace for forward, reverse, transparent, HTTP/3, capture, and IPC proxying. The workspace is intentionally split so reusable protocol/config code stays outside the daemon and high-risk I/O boundaries remain explicit.

## Crates

- `qpx-core`: shared configuration types, validation, redaction, TLS helpers, shared-memory ring, and low-level protocol utilities, including the HTTP token vocabulary that the configuration validation, the DPoP claim validation, the header codecs and the HTTP runtime share.
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

## Owned HTTP Message Boundary

`qpx-core::http_message` provides opaque `Headers` and body-generic
`Request<B>` / `Response<B>` carriers. Ordinary fields require a validated name
that excludes Content-Length; the declaration has typed read/set/remove
operations. There is no raw-map, raw-Parts, `Deref`, or `AsRef` escape. Closed
policy diagnostics and literal Vary selection use the existing core header view.

At decoded codec/library ingress, `from_http` moves a standard message into the
owner. Body stages use `map_body` or `into_head_and_body` and retain the owned
head. Only an actual serializer boundary should use `into_http_for_codec`, which
rejects invalid/conflicting declarations and canonicalizes valid ones. Upstream
preparation facades are internal stages, not serializer boundaries. The carrier
does not infer body sizes, choose transfer coding, apply HEAD/no-body status
rules, or poll bodies/trailers; those remain protocol responsibilities.

**Migration status:** these primitives and their cross-crate contract tests are
available, but the shared live-message spine still uses standard HTTP messages.
`CompiledHeaderControl`, qpx-http normalization, qpxd preparation/policy/modules,
cache live-message APIs, capture/logging, and finalization must be migrated
coherently with their forward, reverse, transparent, MITM, CONNECT and WebSocket
consumers. No temporary raw/owned dual facades have been introduced. The distinct
raw-H1 and interim owners and cache persistence format are unchanged. This does
not establish global structural ownership or justify reducing the source gate.

The ordinary forward terminal response suffix now imports after standard-only
policy/modules/cache/finalization and carries `Response<Body>` through export
preview, sample/full body capture, size limiting, dispatch audit/log-context
annotation, and H1/H2 access-log/service or H3 codec egress. Cache hit/collapse,
response-policy replies and stale fallbacks import at their terminal capture
calls. Early standard replies import when joining that suffix. A private carrier
mechanism shares capture/annotation with the still-standard reverse,
transparent, MITM and WebSocket paths; it exposes no raw heads or maps. Preview
serialization preserves duplicate framing spellings and renders non-text header
values as empty text. The raw-H1 direct/in-memory paths, including their existing
size-limit-before-InMemory decision, remain unchanged.

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


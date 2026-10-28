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

**Migration status:** shared request preparation/header control, response-rule
continuation (including body/RPC observation), live cache operations, downstream
modules, capture/logging and finalization use owner-backed carriers. Ordinary
forward and reverse upstream responses are adopted after the actual upstream
module hook and remain owned through policy and cache writeback to downstream
egress. Cache hits, collapsed hits, stale fallbacks and 304 revalidation produce
owned responses directly. MITM and transparent consumers share the same response
policy without adding caching. Generated local responses are separate sources.

Cache persistence keeps its historical textual field-pair JSON schema and
fixtures. The owner-backed `CacheFields` carrier has only fixed-format
`to_cache_json`/`from_cache_json` persistence operations; it does not implement
generic serde traits or hand framing values to a caller-supplied serializer. The
qpxd-cache metadata codec embeds the fixed JSON array directly with `RawValue`,
so hot admission captures fields without a JSON round trip and persistence bytes
retain their prior shape. 304 revalidation merges fields inside `CacheFields`;
no live path recovers cached pairs. Restored fields hydrate into opaque headers,
and cache hits replace stored framing with the computed representation length.
Raw-cache InMemory responses export only at that serializer boundary. Raw-H1/interim
owners and direct relay algorithms are unchanged. Preview serialization still
renders non-text values as empty text.
These slices do not establish global structural closure or justify reducing the
source gate; specialized raw-H1, interim and library/module boundaries remain
explicit and must be reviewed separately.

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


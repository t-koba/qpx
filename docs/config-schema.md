# Config Schema

qpx uses a single current canonical configuration format. It does not carry a
schema-version compatibility branch; invalid or obsolete config shapes should be
rewritten to the current format instead of being interpreted through fallback
version logic.

Unknown keys are rejected so typos do not silently fall back to defaults. Use
`qpxd schema` to inspect the current machine-readable schema and `qpxd check` to
validate a concrete config file.

## Canonical Shape

- `runtime`: process/runtime protocol limits.
- `telemetry`: logging, metrics, OpenTelemetry, ACME, and capture exporter.
- `security`: built-in auth, identity sources, named sets, destination
  intelligence, upstream trust profiles, and decision service contracts.
- `http`: reusable HTTP policy, guard profiles, and module chains.
- `traffic`: reusable `rate_limit_profiles`.
- `caches`: cache backend definitions.
- `edges[]`: forward, reverse, and transparent entry points.

Reverse routes use exactly one typed `target`: `upstream`, `weighted`, `ipc`,
`local_response`, or `tls_passthrough`.

Reverse-route `path_rewrite` (`strip_prefix`, `add_prefix`, `regex`) is a
mechanical transformation of the raw request path, not an authorization or
upstream scope boundary. qpx matches routes and rewrites the same opaque path
representation; it does not decode percent escapes or resolve dot segments.
Enforce path-based access with `match` and identity rules, which see that same
raw path, and rely on the upstream to interpret the path it receives.

Browser-facing reverse routes can own CORS under
`edges[kind=reverse].routes[].http.cors`. The same policy surface covers every
HTTP reverse target. See [`docs/cors.md`](cors.md).

The same `http` object also accepts `fetch_metadata`, `browser_security`,
`cookies`, `reporting_collector`, and RFC 9440 `client_certificate` policies.
These fields are reverse-route-only and are validated before the runtime plan
is built. See [`browser-origin-security.md`](browser-origin-security.md).

Cache backends support `redis`, `http`, and `disk` kinds. `disk` backends use
`path`, `max_bytes`, and optional `sweep_interval_secs`; the path is created as
owner-only directories, symlinked path components are rejected, and objects are
stored under sharded SHA-256 filenames with atomic same-directory renames.
`writer_mode` is typed. `single_instance` is the default; process-local locking
alone is never treated as cross-process safety. Remote backends enforce one
writer per namespace with a backend lease during publication, independently of
that setting; `writer_mode: shared` stays rejected for them.
Remote leases are bounded by `writer_lease_ttl_ms` (default `5000`, must be
greater than zero). While a writer holds a lease it renews that lease every
third of the TTL, so slow commits cannot lose ownership simply by running
longer than one bound. A failed renewal revokes the lease in-process. The
authoritative variant-index and metadata mutations carry the holder token
inside the same backend operation: Redis runs a Lua `EVAL` that checks the lease
key and applies `SET`/`DEL` atomically, and the HTTP gateway must check
`X-Qpx-Writer-Lease` in the same object `PUT`/`DELETE`. A lease lost between the
pre-check and the mutation therefore cannot overwrite a successor's published
state. The pre- and post-publication ownership checks remain as early aborts and
diagnostics; they are not the fencing mechanism. Choose a TTL long enough to
tolerate normal backend latency between renewals.

- `redis`: the lease is a namespace-wide key `qpx:writer-lock:<namespace>` created
  with `SET NX PX <writer_lease_ttl_ms>` and released with a token-checked Lua
  compare-and-delete. A crashed writer's key expires within the TTL instead of
  blocking the namespace forever. Authoritative `SET` and `DEL` of index and
  metadata objects use `EVAL` scripts that compare the lease key to the holder
  token and apply the mutation only on a match; a stale writer cannot alter the
  successor's objects. A competing writer waits for the configured `timeout_ms`
  (at least 250 ms) and then fails the commit rather than writing unguarded.
  Redis `SET` must support `NX` and `PX`, and the server must allow `EVAL`.
- `http`: the gateway must implement `PUT /v1/cache/<namespace>/_writer_lock`
  with `If-None-Match: *`, a plain-text lease token body,
  `X-Qpx-Writer-Lease-Ttl-Ms` (the gateway expires the lease after that bound),
  `201 Created` on creation and `412 Precondition Failed` when held. The same
  path must also accept `PUT` with `If-Match: "<token>"` and
  `X-Qpx-Writer-Lease-Ttl-Ms` to renew one's own lease, returning `204 No
  Content` (or `200 OK`) only when the token still matches; a failed renewal
  revokes the holder. `GET /v1/cache/<namespace>/_writer_lock` returning the current plain-text
  token with `200 OK` (or `404 Not Found` when unheld); and
  `DELETE /v1/cache/<namespace>/_writer_lock` with `If-Match: "<token>"`,
  returning `204 No Content` (or `200 OK`) only when the token matches. Other
  responses fail the commit closed with a clear error. On authoritative object
  `PUT` and `DELETE` the gateway must also receive `X-Qpx-Writer-Lease:
  <token>`, compare it with the live lease value, and apply the object mutation
  only on a match, in one atomic gateway operation; reject a missing or stale
  token with `409 Conflict`. Conditional create/delete and these fenced object
  mutations must be atomic across clients; a gateway that merely accepts every
  PUT must not be used for cache writes. A gateway that returns `404` or
  `405` for the lease PUT is treated as a legacy backend only when
  `allow_local_only_remote_coordination` is explicitly set to `true` on that
  backend (default `false`): writes then continue with process-local
  coordination only, a warning is logged, and cross-instance exclusivity is
  not claimed. With the default, such a gateway fails the commit closed with
  a clear error. Enable the opt-in only when the namespace is written by a
  single process.

Both leases are namespace-wide, so differently named backends still contend for
the same remote namespace. Staged body I/O happens before the lease is taken.

The lease value is created with its token before the conditional create is sent.
A live client whose create was applied but whose reply is lost or times out
releases that exact token (`If-Match` DELETE / token-checked Lua compare-and-delete)
before reporting the error; if its acquisition future is cancelled before the
reply is seen, the same fenced release is attempted from the lease's drop path.
Ordinary contention (`412` / `SET NX` false) only retries and never deletes
another client's token, and a stale holder cannot release, retire, or publish
under a new owner's lease. Contention errors name the namespace and lease
key/URI, and
an operator can inspect a stuck lease with `GET` (HTTP) or `GET qpx:writer-lock:<namespace>`
(Redis); it clears itself within the configured TTL. A live client that lost
its lease fails the commit at the publication re-check.

Disk alone supports opt-in `writer_mode: shared` on Unix, provided the filesystem
honors process-shared advisory OS file locks. Other platforms reject shared mode;
lock setup/acquisition errors fail closed, not back to process-local locking.
All writers of the same root must use shared mode, the same user, and the same
`commit_lock_stripes` (>0, default 64). The root pins the stripe count: a mismatch
is rejected with the stored count, the expected count and the recovery options
(restore that count or use a fresh cache root). Change the count only with all
clients stopped and the lock directory reset.
A complete pin is never rewritten: an interrupted update could erase the count
an already running writer uses. An unreadable pin fails closed until the layout
file is restored or the root is replaced.
The private `.qpx-commit-locks` directory holds two bounded stripe domains
(primary and object), at most twice that many stable lock files plus one layout file; never remove/replace this directory or its files while any
client uses the root. They live for the root's lifetime and are not cache objects
or eviction candidates. Simultaneous layout setup is retried within the lock
timeout before failing closed. The layout lock inode is never replaced; only
first initialization writes the pin.

The backend `timeout_ms` bounds primary/object lock contention (retries are spaced at
roughly 1/64 of that timeout, with a 1 ms minimum interval). Index publication,
legacy-304 retirement/publication, and
invalidation hold the same namespace/primary stripe lock; body staging/streaming
does not. A timed-out commit is not published, and a timed-out invalidation returns
an error. Shared reads bypass process-local hot/decoded response/index caches so
another instance's publication or invalidation is visible. Existing object format,
TTL and Vary stay unchanged. Object replacement, metadata retirement and deletion
also hold a stripe derived from the exact object file ID; nested acquisition is
always primary then object, never the reverse. Expiration/corruption cleanup
re-reads the current file under that lock, including during startup indexing.
Eviction checks device/inode/change-time identity under the lock and forgets stale
per-instance candidates rather than unlinking another writer's replacement.
Readers retain the file they validated, so unlink/rename cannot switch their body.
Eviction remains per-instance best-effort accounting, not a shared-root capacity
quota or remote-backend protocol. Malformed noncanonical object filenames are
ignored in shared mode because they have no valid object-lock identity.

ACME supports `challenge: http-01`, `tls-alpn-01`, or `dns-01`. HTTP-01 uses
`http01_listen`; TLS-ALPN-01 uses an ACME-managed reverse TLS certificate and
serves a temporary `acme-tls/1` challenge certificate; DNS-01 uses
`dns_hook.set_command` and `dns_hook.clear_command` with `QPX_ACME_DOMAIN` and
`QPX_ACME_TXT_VALUE` in the hook environment. Each hook invocation is bounded by
`dns_hook.timeout_secs` (default 60, minimum 1); this deadline is separate from
`propagation_wait_secs`. A timed-out set hook triggers the configured clear hook
before renewal moves on. On Unix, timeout/cancellation kills the hook's process
group; on Windows, the shell is assigned to a Job Object before it is resumed,
so descendants are covered as well. Windows hook startup fails closed if the
host's job policy refuses assignment. A hook that deliberately daemonizes outside
its Unix process group can still outlive the timeout; normal shell exit preserves
existing detached-child behavior.

## Validation Workflow

```bash
cargo run -p qpxd -- schema --format json
cargo run -p qpxd -- schema --format yaml
cargo run -p qpxd -- check --config config/qpx.example.yaml
cargo run -p qpxd -- explain --config config/qpx.example.yaml --format json
```

`run`, `check`, `explain`, and `match` accept repeated `--config` arguments.
Files are merged in order; later files override earlier scalar/object values,
while named collections append and are then validated for duplicate names.

See [`config/README.md`](../config/README.md) for the sample index and
configuration notes.

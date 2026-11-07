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
`writer_mode` is typed: `single_instance` (default) is a deployment requirement,
not a runtime singleton lock. qpx does not detect or prevent another process from
writing the same namespace; the operator must ensure there is only one writer.
Process-local locking is not cross-process safety. HTTP and Redis remain
single-writer only: `writer_mode: shared` is rejected.

Disk alone supports opt-in `writer_mode: shared` on Unix, provided the filesystem
honors process-shared advisory OS file locks. Other platforms reject shared mode;
lock setup/acquisition errors fail closed, not back to process-local locking.
All writers of the same root must use shared mode, the same user, and the same
`commit_lock_stripes` (>0, default 64). The root pins the stripe count: a mismatch
is rejected. Change it only with all clients stopped and the lock directory reset.
The private `.qpx-commit-locks` directory holds two bounded stripe domains
(primary and object), at most twice that many stable lock files plus one layout file; never remove/replace this directory or its files while any
client uses the root. They live for the root's lifetime and are not cache objects
or eviction candidates. Simultaneous lock-layout setup may fail closed; retry
startup after the other initializer completes.

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
`QPX_ACME_TXT_VALUE` in the hook environment.

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

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
  intelligence, upstream trust profiles, and external authorization decisions.
- `http`: reusable HTTP policy, guard profiles, and module chains.
- `traffic`: reusable `rate_limit_profiles`.
- `caches`: cache backend definitions.
- `edges[]`: forward, reverse, and transparent entry points.

Reverse routes use exactly one typed `target`: `upstream`, `weighted`, `ipc`,
`local_response`, or `tls_passthrough`.

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

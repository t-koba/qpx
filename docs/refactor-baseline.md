# Refactor Baseline

This document records the mechanical gates used by `plan-p3.md`. The authoritative current numbers are produced by `cargo xtask structure` and `cargo xtask budget`; this file explains how to refresh and interpret them.

## Current Gate Set

- `cargo xtask structure`
  - advisory LOC budgets from `xtask/src/budget.rs`
  - `qpx-core` TLS dependency baseline
  - response finalization entrypoint checks
  - unsafe block documentation checks for production source files
  - production `unwrap()`/`expect()` checks across workspace crate `src/` trees
  - production `panic!`/`todo!`/`unimplemented!` checks across workspace crate `src/` trees
  - public `anyhow` boundary baseline for library crates, including result-returning functions/methods and error aliases
  - dependency duplicate-name baseline, to prevent new duplicate crate names while C10 is ratcheted down
  - raw metrics macro baseline, to ratchet metric-name centralization downward
  - duplicate test helper baseline for C1 support consolidation
  - long function advisory notices, to highlight large dispatch/helper functions for quality review without making source length a hard failure criterion
  - dispatch dependency direction checks
  - Phase 3 architecture consolidation baselines for parallel dispatch files, connection-pool struct families, qpxd-owned TLS types, and response/header transform bypasses
  - documentation entrypoint and forward/reverse refactor spike section checks
  - response capture-after-finalization ordering checks
  - dispatch cache-collapse commonality checks, so forward/reverse collapsed cache responses use shared outcome/finalization helpers
  - security QA fuzz target checks, so required fuzz jobs and `fuzz/fuzz_targets/*.rs` sources stay in sync
- `bash ./scripts/check-public-api.sh`
  - public API fingerprints for `qpx-core`, `qpx-auth`, `qpx-h3`, `qpx-acme`, and `qpx-observability`
  - the CI `public-api` job installs `cargo-public-api` and runs this script
- `cargo xtask budget`
  - advisory file-level LOC budgets, useful as a regression signal but not a hard pass/fail criterion
  - advisory workspace total LOC baselines for production Rust, test Rust, and Markdown docs
- `bash ./scripts/check-ci-acceptance-gates.sh`
  - CI acceptance-gate presence checks for MSRV, fmt, workspace build/test, clippy, docs, coverage, public API, unused-dependency scan, dependency audits/policy, e2e/config audits, perf smoke, advanced transport perf, nightly Criterion bench, ASAN test coverage, fuzz target coverage, and CodeQL jobs
  - `qpx-acme`, `qpx-auth`, `qpx-h3`, `qpx-observability`, and `qpx-wasm` keep `#![warn(missing_docs)]` enabled under the doc gate
  - Phase 3 dispatch access, pool-shaping, streaming-limit, DATAGRAM, mirror, ext_authz-buffer, secure-file, and TLS-boundary gates, to keep shared ext_authz/audit helpers, H2 reservations, H3 request-open actors, QPX H3 inflight-aware pooling, H3 fail-closed request limits, prefix-aware DATAGRAM send paths, lock-free DATAGRAM receive snapshots, bounded mirror fan-out, reusable ext_authz response buffers, hardlink-resistant secure writes, and qpx-core TLS primitives from regressing
  - `deny.toml` skip-entry baseline, to prevent new multiple-version exceptions without ratcheting

## Refresh Procedure

Run:

```sh
cargo xtask structure
cargo xtask budget
bash ./scripts/check-ci-acceptance-gates.sh
./scripts/measure-structure.sh $(cut -f1 xtask/loc-budgets.tsv)
```

LOC budgets and long-function reports are advisory trend signals. `xtask` reports LOC drift and long functions as notices, not failures, so reviewers can ask why code grew or why a function remains large without forcing arbitrary shortening. When a phase intentionally simplifies a file or module, lower the relevant baseline in `xtask/src/budget.rs` or `xtask/loc-budgets.tsv` in the same change. Do not contort code, delete useful behavior, or split modules only to satisfy a line-count target; prefer clear ownership, lower duplication, better tests, and measurable hot-path improvements.

Current workspace total LOC advisory baseline:

| Class | Current | Advisory Baseline |
|---|---:|---:|
| Production Rust | 110,897 | 108,912 |
| Test Rust | 33,715 | 32,227 |
| Markdown docs | 2,533 | 2,467 |

The current values are intentionally above the initial advisory baseline. The
increase comes from Phase 3/4 regression gates, acceptance checks, fuzz target
coverage, boundary documentation, and targeted tests added to preserve behavior
while consolidating hot paths. This drift is tracked as a review signal, not a
failure condition; ratchet the baseline downward only when redundant
implementations are removed without losing behavior or performance.

## Phase Notes

- Phase 0: gate scaffolding exists through `xtask`, CI structure workflow, and advisory LOC baselines.
- Phase 1: production panic/unwrap and unsafe documentation gates are represented by `xtask`, workspace lints, and clippy/doc jobs. `cargo xtask structure` also verifies the workspace lint posture: rust-version 1.87, `dead_code`/`unused`/`unsafe_op_in_unsafe_fn = "deny"`, and `clippy::undocumented_unsafe_blocks = "deny"`. Public `anyhow::Result` library boundaries are now capped at 0 by `xtask`; new library public APIs must use crate-specific or otherwise explicit result types.
- Phase 1: `qpx-auth`, `qpx-h3`, `qpx-wasm`, and `qpxc` are explicitly `#![forbid(unsafe_code)]`; `cargo xtask structure` keeps those markers present. Crates that still require audited `unsafe` remain covered by the documented unsafe gate.
- Phase 1: `qpx-h3` exposes a crate-specific `H3Error` enum rather than aliasing `anyhow::Error`; `cargo xtask structure` rejects public library aliases or re-exports back to `anyhow::Error` or `anyhow::Result`, and rejects public functions, inherent methods, trait methods, trait associated type defaults, public struct fields, and non-error enum variants that expose `anyhow::Result` or `anyhow::Error`, including items inside inline public modules.
- Phase 2: `ARCHITECTURE.md` now records crate boundaries and quality gates and should be kept current with behavior changes.
- Phase 2: `qpx-acme`, `qpx-auth`, `qpx-h3`, `qpx-observability`, and `qpx-wasm` have `#![warn(missing_docs)]` enabled and fixed by `cargo xtask structure`; extend the same posture to the remaining library crates as their public docs are completed.
- Phase 2: CI coverage is no longer report-only; `cargo llvm-cov --workspace --locked --fail-under-lines 20` enforces an initial line coverage floor of 20%. Raise this threshold when coverage work lands.
- Phase 2: public API fingerprints are enforced by `scripts/check-public-api.sh`; `cargo xtask structure` verifies that the script keeps exactly the expected library crates and a 64-hex SHA-256 fingerprint for each. Intentional API changes must update the corresponding hash in the same change.
- Phase 2: `scripts/check-ci-acceptance-gates.sh` is run by the structure workflow so required CI gates cannot be removed silently.
- Phase 2: duplicate dependency names are capped at 36 by `cargo xtask structure`; dependency cleanup must lower this baseline rather than add new duplicate crate names.
- Phase 2: dependency policy skip entries are capped at 53 by `cargo xtask structure`; every skip must carry a reason, `[bans] multiple-versions` and wildcard bans must stay at `deny`, `skip-tree` must stay empty, and unknown registry/git sources must stay denied. Dependency cleanup should ratchet this baseline downward.
- Phase 2: raw metrics macro calls outside metrics facade files are capped at 0 by `cargo xtask structure`; new metric emitters must go through subsystem metrics facades rather than raw macro calls in hot-path code. The check parses Rust syntax and catches direct or qualified `counter!`, `gauge!`, and `histogram!` calls.
- Phase 2: duplicated test helper definitions are capped at 0 by `cargo xtask structure`; shared helper definitions are allowed once, but reintroducing per-test copies fails the gate. The check scans every workspace crate's `tests/` tree plus `src/` test contexts (`#[cfg(test)]` inline modules/functions and test-named files), parses Rust syntax, and covers private, public, crate-public, synchronous, and async helper function definitions.
- Phase 3: dispatch, pool, TLS, and response/header transformations should only be considered complete when the relevant `xtask` duplication checks improve and any LOC movement has a quality-based explanation. `cargo xtask structure` now enforces baselines for parallel dispatch file families, connection-pool struct families, qpxd-owned TLS types, direct header mutation bypasses, and direct response-policy engine uses so consolidation can ratchet actual duplication and bypasses downward. Forward/reverse commonality and non-goals are recorded in `docs/refactor-fwd-rev.md`, qpxd crate-split criteria are recorded in `docs/refactor-crate-boundaries.md`, and `cargo xtask structure` rejects dropping those explicit boundaries and high-risk non-goals.
- Phase 3: forward, reverse, transparent, and MITM dispatch access paths must keep shared audit/ext_authz helpers. Forward request guard/policy audit, MITM guard/ext_authz audit, and transparent guard audit also use `build_dispatch_audit_context` instead of reconstructing log context and `DispatchAuditContext` by hand. MITM ext_authz continue/deny handling now uses `apply_ext_authz_http_access`, matching the HTTP dispatch paths instead of branching by `ExtAuthzEnforcement` locally. Reverse dispatch carries the context built by access control instead of rebuilding it from log-context fragments. `cargo xtask structure` rejects direct `DispatchAuditContext::new`, direct ext_authz policy extraction, and direct `ExtAuthzEnforcement` branching in those access files, and rejects direct audit context construction in the representative forward/reverse/transparent/MITM dispatch paths.
- Phase 3: forward/reverse cache collapse paths must keep using shared `dispatch_cache_collapse_continue`, `dispatch_cache_collapse_response`, and `finalize_dispatch_collapsed_cache_decision` helpers. `cargo xtask structure` rejects reintroducing direct collapsed hit/stale outcome selection in those paths.
- Phase 3: rate/concurrency-limit local responses stay centralized in `rate_limit_response_for_parts` and `concurrency_limited_response_for_parts`. `cargo xtask structure` rejects direct `too_many_requests_response` construction and direct `RateLimited` / `ConcurrencyLimited` annotation in forward/reverse/transparent/MITM dispatch implementations outside the shared helper.
- Phase 3: dispatch local responses that need audit annotation use `annotated_local_response`; MITM respond-action local responses now defer construction until the shared audit context exists, instead of building a response and annotating it later. `cargo xtask structure` rejects reintroducing `finalized_local_response` in forward/reverse/transparent/MITM/http dispatch paths outside the shared helper.
- Phase 3: Max-Forwards early responses use `annotated_max_forwards_response` in reverse, transparent, and MITM dispatch paths, keeping trace handling and audit annotation behind the shared helper. `cargo xtask structure` rejects direct `handle_max_forwards_in_place` use in those representative dispatch paths outside the helper.
- Phase 3: request-body-too-large responses in HTTP dispatch preparation, reverse preparation, and MITM request observation use `request_body_too_large_response`; `cargo xtask structure` rejects rebuilding `StatusCode::PAYLOAD_TOO_LARGE` responses directly in those representative paths.
- Phase 3: direct origin H2 pooling now has explicit reservations, H3 origin request opening is actor/queue based with bounded-send backpressure, QPX H3 upstream pooling is inflight-aware, and upstream proxy selection implements the shared `ConnectionPool<T>` acquire boundary without changing selection or permit-drop release semantics. The acceptance gate keeps those pool-shaping primitives present while deeper pool abstraction work continues. `cargo xtask structure` rejects production H3 origin open-queue `try_send` and old `Mutex<H3SendRequest>` request-open serialization so temporary queue pressure cannot silently become immediate request rejection or connection-local lock contention again, and rejects dropping the representative `ConnectionPool` boundary.
- Phase 3: H3 origin saturated waits use the same effective stream capacity as connection selection, including the open-queue cap, so configurations with high `max_inflight_streams_per_connection` cannot spin on a queue-limited connection.
- Phase 3: H3 origin effective load uses reserved inflight streams only and does not add open queue depth again; `cargo xtask structure` rejects reintroducing queued-request double counting while keeping stream capacity capped by open queue capacity.
- Phase 3: H3 request-side route streaming limits use fail-closed head-time composition and route-time body limiting for forward and reverse paths; the acceptance gate keeps the shared `request_side_fail_closed` helpers present.
- Phase 3: qpx-h3 DATAGRAM receive dispatch uses ArcSwap snapshots for read-mostly routing, and QPX DATAGRAM senders expose a prefix-aware send API for producers that already hold framed bytes. The ambiguous `send_datagram(payload)` convenience API was removed so callers must choose either `send_prefixed_datagram` or explicit scratch-backed unprefixed sending at the Quinn single-buffer boundary. The acceptance gate and `cargo xtask structure` keep these primitives present while Quinn-owned-buffer boundaries remain explicit.
- Phase 3: qpx-h3 stream/session DATAGRAM registries, qpxd session indexes, and response-compression session worker selection share private `sharding::modulo_u64` helpers instead of reintroducing per-registry modulo arithmetic. qpxd pool/cache/rate-limiter shard allocation uses shared `sync_mutex_shards` / `async_mutex_shards` helpers instead of repeating `Vec::with_capacity(shards)` initialization loops, and async sharded pool/cache maps use `AsyncShardMap` instead of carrying `Vec<Mutex<HashMap<...>>>` fields plus per-call shard math. `cargo xtask structure` rejects the known manual session/stream shard modulo and shard-initialization patterns so C8 cleanup cannot silently drift back.
- Phase 3: reverse mirrors are bounded per endpoint before spawning mirror tasks, and ext_authz responses use reusable bounded buffers; `cargo xtask structure` rejects mirror task spawns that occur before permit acquisition and rejects ext_authz response collection falling back to `to_bytes_limited` or `collect().await`, while the acceptance gate keeps both hot-path resource controls present.
- Phase 3: reverse request retry templates remain a compatibility slow path for explicitly bounded, known-length bodies only. `cargo xtask structure` rejects unknown-length retry template eligibility, whole-body collection helpers in the template path, and configurations where route retry body thresholds can exceed the runtime template cap.
- Phase 3: qpxf CGI stdout header parsing keeps body leftovers as `Bytes` slices and uses `memchr::memmem` for chunk-local header terminator search, avoiding the older byte-window scan while preserving cross-chunk boundary detection. `cargo xtask structure` rejects reverting the parser to initial-body materialization or a non-memmem terminator scan.
- Phase 3: qpxf IPC rejection and error paths keep bounded cleanup: TCP and SHM rejected-request drains stop at `max_stdin_bytes`, TCP incomplete CGI headers abort the executor/stdin relay before returning, and SHM initial body-leftover write failures abort and release the response ring instead of continuing with a corrupted success response. `cargo xtask structure` rejects dropping those cleanup/backpressure guards.
- Phase 3: secure output files, MITM CA material, ACME material, qpxr pcapng capture files, and SHM ring files use fd-validated hardlink-resistant opens plus fd-based permission changes on Unix; `cargo xtask structure` rejects dropping hardlink/owner validation, reverting protected writes to path-based chmod after open, bypassing the secure helper for qpxr capture files, or chmodding SHM ring files before fd validation.
- Phase 3: TLS material loading, config construction, CA handling, and dynamic MITM cert resolution stay anchored in `qpx-core::tls`; qpxd keeps client connection, trust-policy, sniffing, and application wiring responsibilities. The acceptance gate checks that boundary while deeper TLS consolidation continues.
- Phase 3: dispatch response policy, reverse response-rule candidate/context construction, final response header finalization, and upstream proxy authorization header mutation now have shared entrypoints; `CompiledHeaderControl` implements the protocol-local `HeaderTransform` boundary, and `ListenerResponsePolicyDecision` implements the dispatch-local `ResponseTransform` boundary. The acceptance gate keeps `apply_dispatch_response_policy`, `response_policy_parts`, `finalize_response_headers_common`, `finalize_response_with_headers_in_place`, and `set_proxy_authorization_header` present. `cargo xtask structure` rejects direct request and response header-control entrypoint use outside `http/protocol`, rejects removing the `HeaderTransform` trait boundary, and rejects inlining listener response-policy decision matching back into `apply_dispatch_response_policy`.
- Phase 3: reverse response rules keep direct `apply_listener_response_policy` / `ListenerResponsePolicyDecision` access only behind the `#[cfg(test)]` verification entrypoint; production dispatch must go through `apply_dispatch_response_policy(DispatchResponsePolicyInput { ... })`, enforced by `cargo xtask structure`.
- Phase 3: `cargo xtask structure` rejects direct `PROXY_AUTHORIZATION` header insert/remove outside `http/protocol/header_control.rs`, keeping upstream proxy authorization mutation behind `set_proxy_authorization_header` while allowing config/redaction/semantics code to continue treating the header name as data.
- Phase 3: QPX H3 static responses use `qpx_static_response` so status/body/Content-Length construction is localized before finalization and send-stream handling. `cargo xtask structure` rejects bypassing that constructor or reverting static response bodies through `Vec` materialization; `cargo check -p qpxd --features http3-backend-qpx --lib --locked` and the QPX `mitm`/`acme`/combined HTTP/3 feature checks are part of the local verification set so qpx-h3 typed-error boundaries cannot silently fall out of the feature matrix.
- Phase 3: response capture preview ordering is enforced by `cargo xtask structure`; forward, transparent, reverse HTTP, reverse IPC, and MITM upstream success paths must finalize downstream headers before capture/export. The check uses path-specific success-path markers so already-finalized local response policy captures are not incorrectly treated as regressions.
- Phase 3: qpxr capture publishes history/live before persistence and uses non-awaiting file-sink enqueue; `cargo xtask structure` rejects reintroducing file-sink backpressure ahead of live/history delivery.
- Phase 3: qpxr capture history age and save rotation arithmetic is saturating/checked at the boundary; unit tests cover extremely large history durations and `u64` rotation-size overflow.
- Phase 3: reverse ext_authz shared-client entrypoints were reduced to direct request functions; compatibility-style singleton client facades should not be reintroduced.
- Phase 3: config canonical deserialization now has a qpxd sample/usecase load guard before any C7 boilerplate reduction. The acceptance gate keeps `sample_qpxd_configs_load`, deterministic sample env expansion, schema-version enforcement, and the canonical-loader panic-macro ban present so future cleanup cannot silently drop real sample coverage or reintroduce dummy/unreachable conversion paths.
- Phase 4: `cargo xtask structure` validates that CI still contains the required acceptance surface: fmt/check/build/test/doc/clippy matrix, coverage threshold, public API snapshots, audit/deny, e2e/config audits, perf smoke/bench, ASAN, fuzz smoke, CodeQL, and structure/budget workflow steps. This keeps the final plan-p3 acceptance model from drifting into documentation-only intent.

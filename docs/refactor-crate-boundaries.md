# qpxd Crate Boundary Refactor Spike

This note records the Phase 3f boundary decision from `plan-p3.md`. Splitting
`qpxd` into member crates is useful only when it improves dependency direction,
compile boundaries, and ownership clarity. It must not become a cosmetic source
movement exercise.

## Current Decision

Keep `qpxd` as a single crate for the current Phase 3 pass while the dispatch,
pool, TLS, response policy, streaming, DATAGRAM, and capture boundaries are
still being tightened inside the crate.

The current gate posture is intentional: shared primitives live in narrower
modules, and `cargo xtask structure` rejects drifting those primitives back into
mode-specific implementations. Splitting before those dependencies are acyclic
would create facade crates or compatibility glue without improving the design.

do not split qpxd solely to move LOC. The LOC budget is advisory; a split is
acceptable only when the resulting crate boundary carries a real invariant.

## Split Criteria

A future member crate extraction is acceptable only when all of the following
are true:

- no feature loss;
- no default hot-path performance regression;
- Cargo-enforced dependency direction is stronger than the current module gate;
- extract only acyclic boundaries;
- keep qpxd as wiring for CLI, runtime assembly, and process lifecycle;
- tests and existing `xtask` gates prove the moved code still preserves capture,
  streaming, cache, retry, TLS, and HTTP/3 semantics.

Good candidates are modules whose public surface is already stable and whose
dependencies point inward: cache storage primitives, reusable HTTP protocol
helpers, typed metrics, or qpx-core-owned TLS construction. Bad candidates are
request state machines whose control flow still depends on forward, reverse, or
transparent mode facts.

## Non Goals

The following are not valid reasons to create a crate:

- satisfying an arbitrary file or crate length target;
- hiding duplicated code behind a new facade;
- preserving a deprecated call shape through compatibility wrappers;
- moving mode-specific orchestration into a generic request dispatcher;
- introducing new public API solely because Cargo needs a crate boundary.

When a boundary is ready, the extraction should delete redundant module-level
branches and keep the same behavior behind a smaller, clearer API.

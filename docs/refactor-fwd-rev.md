# Forward/Reverse Dispatch Refactor Spike

This note records the Phase 3g spike from `plan-p3.md`: forward and reverse HTTP
dispatch share several mechanics, but they should not be fully merged. The safe
target is a shared library of request dispatch stages plus thin mode-specific
orchestration.

## Shared Mechanics

Forward and reverse both run this high-level sequence:

1. derive request identity, destination metadata, and audit context;
2. apply ext_authz, HTTP guards, request rate limits, and concurrency limits;
3. prepare request headers and local module responses;
4. perform cache lookup and collapsed response handling when configured;
5. choose an upstream target and stream the request body;
6. apply response policy, cache finalization, capture/export, and response
   finalization before returning downstream.

The following code is already shared or should remain shared:

- `qpxd/src/http/dispatch/audit_builder.rs` for audit context construction;
- `qpxd/src/http/dispatch/ext_authz_access.rs` for ext_authz allow/deny handling;
- `qpxd/src/http/dispatch/cache_decision.rs` and `cache.rs` for cache hit and
  stale-if-error finalization;
- `qpxd/src/http/dispatch/limit_response.rs` for rate/concurrency limit
  responses;
- `qpxd/src/http/dispatch/response_policy.rs` and `prepare/response.rs` for
  local responses that need dispatch annotation.

These helpers are the right boundary: they eliminate duplicated response
building and policy plumbing without forcing the two proxy directions into one
control-flow type.

## Required Differences

Forward request dispatch keeps client-selected upstream semantics:

- the upstream proxy target is derived from the action and effective listener
  policy;
- authority handling must preserve forward-proxy behavior, including CONNECT and
  absolute-form HTTP request handling;
- cache keys use the outbound target selected by the forward action;
- local block/respond rules may need to drain the client request body after a
  local response.

Reverse request dispatch keeps route-selected upstream semantics:

- route selection can depend on destination, request body size, body/RPC
  observation, and route-specific streaming limits;
- reverse HTTP and IPC attempts can retry across route upstreams and must keep
  interim responses, health state, and stale-if-error behavior intact;
- mirrors are route-scoped side effects and must remain bounded independently
  from the main upstream attempt;
- route headers, local route responses, and response rules are route artifacts,
  not generic forward action artifacts.

Merging these differences into one large `RequestDispatch` implementation would
add branching and state that the hot path does not need. That would be a
maintainability regression and risks performance regressions through wider
context structs and less obvious early returns.

## Refactor Boundary

The intended final shape is:

- shared HTTP dispatch modules own reusable policy, audit, response, cache, and
  limit primitives;
- forward/reverse/transparent modules own mode-specific orchestration and
  upstream selection;
- common helpers accept already-derived mode facts instead of pulling mode
  modules back into `http/dispatch`;
- any new shared helper must remove real duplicated behavior, improve a
  responsibility boundary, or enforce a new mechanical gate without adding a
  compatibility branch.

Do not introduce a generic dispatch facade solely to preserve an old call shape.
If a helper is only a pass-through and does not remove duplicated behavior, it
should be deleted.

## Next Safe Extraction Targets

The remaining safe candidates are narrow and measurable:

- response capture/export after final response header mutation;
- cache writeback/revalidation finalization for reverse HTTP and IPC;
- concurrency-limit acquisition helpers that return typed local responses;
- route-independent response policy annotation.

The following are intentionally not extraction targets unless benchmarks and
tests prove no regression:

- the full forward/reverse request state machine;
- route selection and body-observation ordering;
- retry template creation and replay;
- WebSocket/CONNECT special cases that differ by proxy direction.

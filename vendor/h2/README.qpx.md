# qpx h2 transport patch

This directory pins upstream `h2` 0.4.13. qpx changes the two internal
stream-state mutexes from `std::sync::Mutex` to `parking_lot::Mutex` and makes
per-frame, HPACK, flow-control, and queue tracing opt-in through the
`wire-tracing` feature. The public API, HTTP/2 state machine, flow control,
framing, and wire behavior are unchanged.

The patch removes kernel mutex contention when independent HTTP/2 streams are
processed by different runtime workers. `parking_lot` mutexes do not implement
poisoning, so a panic still unwinds normally but does not make unrelated stream
cleanup fail solely because the shared lock was poisoned.

The default build retains protocol error diagnostics but omits disabled
wire-level callsites and span entry from hot paths. Build qpxd with
`h2-wire-tracing` when full frame and scheduler tracing is required. CI compiles
and tests the opt-in path through the workspace all-features lane.

The fork can be removed only after an upstream release provides equivalent
contention behavior and passes the qpx HTTP/2 contract, interoperability, and
comparative performance gates.

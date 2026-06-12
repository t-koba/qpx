# Performance

qpx is streaming-first on the default HTTP hot path. Features that need exact body inspection, retry templates, full capture, or compatibility bridges are explicit and bounded.

CI perf smoke tests are regression detectors, not throughput claims. Result JSON should be compared against the same runner class. Dedicated benchmark claims require fixed hardware, pinned CPU policy, and representative upstream/downstream latency.

Set `QPX_PERF_SMOKE_JSON=/path/to/perf.jsonl` when running
`cargo test -p qpxd --release --test perf_smoke -- --nocapture` to append
machine-readable perf smoke records.

Current local smoke baselines from the plan-f1 Phase 0 lanes, measured with
`cargo test -p qpxd --release --test perf_smoke -- --nocapture` on the
developer runner:

| Lane | Requests | Throughput | p95 |
| --- | ---: | ---: | ---: |
| `reverse_dispatch_rules_200` | 512 | 25122 req/s | 2 ms |
| `reverse_h3_bulk` | 128 | 96 req/s | 32 ms |
| `reverse_ipc_executor` | 32 | 575 req/s | 8 ms |
| `forward_mitm` | 32 | 2381 req/s | 2 ms |

Key cost signals:

- `qpx_body_buffering_events_total`
- `qpx_body_spooled_bytes_total`
- `qpx_h3_request_body_drains_*`
- `qpx_h3_origin_pool_*`
- `qpx_datagrams_*`
- `qpx_tunnel_*`

Use `qpxd explain --format json` before rollout to identify routes that can buffer and why.

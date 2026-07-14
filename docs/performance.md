# Performance

qpx is streaming-first on the default HTTP hot path. Features that need exact body inspection, retry templates, full capture, or compatibility bridges are explicit and bounded.

CI performance tests are regression and dominance gates, not marketing
throughput claims. Every external comparison runs qpx, the direct backend, and
the competing proxies on the same runner and uses dimensionless ratios. A
dedicated benchmark claim still requires fixed hardware, pinned CPU policy, and
representative upstream/downstream latency.

Set `QPX_PERF_SMOKE_JSON=/path/to/perf.jsonl` when running
`cargo test -p qpxd --release --test perf_smoke -- --nocapture` to append
machine-readable perf smoke records.

CI stores these JSONL records as artifacts. Each line has the current canonical
shape:

```json
{
  "bench": "h3_qpx_backend_stream_100mb",
  "first_byte_ms": 8.7,
  "p95_chunk_gap_ms": 3.1,
  "total_ms": 1350.0,
  "rss_peak_mb": null,
  "cpu_ms": null,
  "bytes": 104857600,
  "commit": "abcdef0"
}
```

Runner-local values are regression signals only. Compare them against the same
runner class and the same benchmark lane; do not use CI artifacts as absolute
throughput claims.

The HTTP/1 comparison writes `target/perf/perf-audit-proxy-compare.jsonl` with
`direct-backend`, `qpxd`, nginx, Apache, and lighttpd rows. The benchmark
interleaves every implementation across three rounds and requires a majority of
valid samples. It aggregates each metric independently: lower medians for
throughput and CPU efficiency, upper medians for latency, and maxima for error
and memory counters. This prevents an unusually fast request-rate sample from
silently carrying unrelated latency or CPU measurements into the result.
`scripts/compare-proxy-baseline.sh` evaluates all of these axes against the best
external result on the same runner:

- request throughput;
- requests per process-tree CPU second;
- p99 latency;
- the geometric multi-axis dominance score.

The gate also preserves the prior runner-relative baseline. On every lane, qpx
must exceed the independently strongest external throughput and CPU-efficiency
results by at least 25%, beat the best external p99 latency by at least 20%, and
reach a geometric multi-axis dominance score of at least 1.25. This is stricter
than comparing qpx with a single chosen competitor because the reference may
come from a different implementation on each axis. It rejects a lane without at
least 10% direct-backend headroom, and rejects throughput or CPU sample spread
above 10%. Direct-backend efficiency and p99 spread remain in the artifact so
backend saturation and runner noise remain visible.

The TLS HTTP/2 comparison uses h2load against the direct static HTTP/2 backend,
qpx, and nginx. It covers both one stream per connection and 100 multiplexed
streams for the short and 1 MiB lanes. Every implementation is interleaved
across rounds and uses the same conservative per-metric aggregation as the
HTTP/1 comparison. The benchmark records proxy CPU and backend CPU separately,
then compares qpx and nginx by requests per total-system CPU second. The direct
backend is a workload and saturation reference; its request rate is not treated
as a proxy ceiling because its TLS/H2 topology differs from the two proxy lanes.
`scripts/check-http2-performance.sh` requires no per-lane throughput or
total-system CPU-efficiency regression, bounds mean latency to 1.05x, p99 to
1.1x, and maximum latency to the external leader on every lane. Every lane must
reach at least 1.25 multi-axis dominance, and the geometric score across the
complete four-lane matrix must reach 1.5. qpx sample spread is capped at 10%;
reference spread is recorded and capped separately so runner noise cannot
silently excuse a qpx regression. The qpx HTTP/2 server polls active stream
futures in the connection task, preserving concurrency without per-stream task
creation or atomic stream bookkeeping.

To update the proxy baseline, download the latest `qpx-nightly-perf-jsonl`
artifact from the scheduled `nightly_perf_bench` job and regenerate the baseline
with the same checker:

```bash
scripts/compare-proxy-baseline.sh --generate-baseline target/perf/nightly-proxy-compare.jsonl perf/baseline-proxy-compare.json
scripts/compare-proxy-baseline.sh target/perf/nightly-proxy-compare.jsonl perf/baseline-proxy-compare.json perf/proxy-performance-objectives.json
```

Commit the regenerated baseline JSON together with the performance reason.
Baseline generation records measured ratios only. The independent
`perf/proxy-performance-objectives.json` contains release policy and is never
rewritten by baseline generation; it must not be weakened merely to accept a
failing run.

## Long streaming gate

`scripts/perf-audit-streaming-compare.sh` transfers a 100 MiB response through
the direct backend, qpx, nginx, Apache, and lighttpd. It measures fast readers
and deliberately slow readers. Observations occur at fixed cumulative 64 KiB
boundaries; operating-system `recv` segmentation therefore cannot favor a
proxy that happens to emit smaller frames. The five implementations are
interleaved across rounds. Each proxy requires a majority of valid samples and
uses independent conservative medians for total time, latency, and CPU
efficiency. Fast mode performs eight complete transfers per sample so subsecond
timer quantization cannot dominate CPU accounting. CPU efficiency includes both
the proxy and the shared backend. Stability is mandatory for qpx, the direct
backend, the winning external proxy, and every external proxy within 25% of the
leader. A distant unstable implementation remains visible in the artifact but
cannot invalidate an otherwise stable competitive comparison.

`scripts/check-streaming-performance.sh` enforces the tracked objectives in
`perf/streaming-performance-objectives.json`. For a fast reader, qpx must:

- exceed the fastest external proxy's throughput by at least 50%;
- retain at least 80% of direct-backend throughput;
- exceed the throughput leader's total-system CPU efficiency by at least 25%;
- keep first-byte latency within 1.1x of the leader and make both p99 and
  maximum inter-observation gaps no worse than the leader;
- exceed the multi-axis dominance score by at least 25%.

For a slow reader, total time, first byte, p99 gap, and maximum gap are bounded
relative to the direct backend. This independently detects lost backpressure or
event-loop starvation even when bulk throughput remains high.

## Allocation gate

The production binary uses mimalloc by default. The allocation profiler builds
the same code with the `system-allocator` feature so Valgrind DHAT can observe
every allocation accurately. `scripts/check-allocation-budget.sh` enforces the
per-request byte and allocation-count budgets in `perf/allocation-budget.json`.
The profiling allocator switch changes only allocation instrumentation; it does
not disable HTTP functionality.

Tracked lanes:

- `reverse_http1_plain_small`
- `reverse_http2_plain_small`
- `h3_h3_backend_unary_1kb`
- `h3_qpx_backend_unary_1kb`
- `h3_h3_backend_stream_100mb`
- `h3_qpx_backend_stream_100mb`
- `h3_sse_100_events`
- `grpc_server_stream_10000_messages`
- `grpc_web_text_stream_10000_messages`
- `connect_streaming_messages`
- `client_cancel_mid_stream`
- `body_channel_capacity_sweep`

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

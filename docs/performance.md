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

The same interleaved HTTP/1 harness also measures qpx in its other production
roles instead of inferring their performance from the minimal proxy lane:

CI invokes that harness through `scripts/perf-audit-proxy-matrix.sh`. The
orchestrator keeps a single build and CI step, but gives the generic proxy,
local origin, WebDAV origin, plain cache, and feature-rich cache groups fresh
processes and state directories. Only implementations selected for a group are
started. It validates the exact 34-row matrix before publishing one atomic
JSONL result, so isolation cannot silently omit a competitor or lane. The timed
sample count is unchanged; isolation adds only process startup and removes idle
services from scheduler accounting. Fatal socket errors remain forbidden;
sampling-boundary read errors use the same recorded ppm ceiling as the inner
harness. A rejected combined matrix is retained with an `.invalid` suffix for
diagnosis instead of replacing the last accepted artifact.

The role order remains WebDAV, plain cache, then feature-rich cache in every
round, while implementation order reverses inside each role on alternating
rounds. This pairwise counterbalance prevents feature-rich access-log file
reclamation from contaminating a different role's next timed sample without
giving either implementation a fixed first position.

- `proxy_cache_hit_http1` compares the persistent qpx disk cache with nginx
  `proxy_cache` for 1 KiB and 1 MiB objects. Both caches must report a verified
  hit before and after sampling. qpx keeps persistence as the source of truth
  while a bounded 64 MiB LRU serves hot objects up to 2 MiB without reopening
  or decoding the cache file on every request. A lock-free recent-object
  snapshot keeps the steady-state hit path independent of disk metadata and
  cache-maintenance locks. Expiry sweeping is owned by one delayed background
  task rather than being opportunistically duplicated by requests. Hot payloads
  retain the single-frame `Bytes` fast path without a producer task or copy.
- `origin_local_http1` compares qpx local origin responses with nginx static
  responses for the 1 KiB request-rate lane.
- `origin_webdav_http1` compares qpx WebDAV GET with Apache `mod_dav_fs` for
  1 KiB and 1 MiB resources. This deliberately uses a DAV-capable reference;
  comparing qpx WebDAV only with a semantics-free static file server would not
  be an equivalent workload. redb remains the durable metadata source of truth;
  committed properties, content types, and bindings are published through
  immutable read snapshots. File data is shared only while its size and
  modification timestamp still match the filesystem, so the optimization does
  not turn external file changes into stale responses. Canonical resource IDs
  are Arc-backed, while every path component is still checked for symlink
  traversal on each filesystem access. The comparison mounts the same physical
  data directory at `/dav/` in both products: qpx uses its normal
  `path_rewrite.strip_prefix` route feature and Apache uses `Alias`. A compiled
  single-route WebDAV dispatch avoids constructing unused generic proxy policy
  state only when the execution plan proves that authorization, HTTP modules,
  rate limits, header policy, mirrors, and response rules are absent. Adding
  any of those features selects the complete dispatch path; path rewriting,
  API metadata, HSTS, request limits, route matching, and security rejection
  remain active in the direct path. The Apache reference disables
  `FollowSymLinks`, and startup probes require both products to reject a real
  symlink escaping the served root. The versioned
  `webdav_filesystem_redb_symlink_safe_v2` profile prevents results from the
  weaker reference configuration being accepted as equivalent evidence. A
  lock-free one-entry hot-path snapshot reuses only the canonical
  `ResourceId` for a repeated URI and applies a simple mount-prefix rewrite
  without rebuilding the URI. Filesystem metadata, body freshness, ACL, and
  authorization results are never stored in that snapshot.
- `feature_rich_cache_hit_http1` compares qpx and nginx with persistent cache,
  access logging, request rate limiting, request/response header policy,
  metadata headers, compression configuration, and protocol-safety processing
  enabled. qpx additionally exercises its RFC 7239 and API-lifecycle codecs.
  This is the fixed `feature_rich_cache_hit_v1` workload profile; benchmark
  environment variables cannot disable individual features. Inapplicable
  modules may prove they are inactive for a request before allocating session
  state, but they remain configured and are verified on applicable requests.
  The compiled rate-limit plan also records whether its key needs identity or
  route metadata. Global and source-address limits therefore avoid building
  unused authorization context. Integer-rate token buckets use a lock-free
  GCRA state and a bounded one-entry hot-key snapshot; rates that cannot be
  represented exactly retain the locked token-bucket implementation rather
  than accepting a semantic approximation. Protocol-guard rejection remains a
  synchronous head operation, while owned audit and route context is allocated
  only when configured body inspection actually needs it.
  Combined access logging retains timestamp, status, byte count, Referer,
  User-Agent, latency, redaction, escaping, buffered writes, and periodic
  flushing. Its stable request fields are compiled once per active request
  shape instead of being reformatted for every response. Sixteen bounded
  64 KiB shards spread file writes across the run instead of creating large,
  synchronized write bursts under sustained load;
  a replacement pool covering the complete bounded writer queue is allocated
  before serving traffic. A temporarily delayed writer therefore cannot force
  response-path allocation while the queue still has capacity. Queue limits,
  overflow reporting, background writes, periodic flushing, and shutdown
  delivery remain enforced.
  The comparison retains only bounded head and tail samples of high-volume
  access logs as CI artifacts. Each timed sample still writes its complete log
  to a regular file. After the load phase, the harness gives both writers 1.25
  seconds to drain and includes that work in process-tree CPU accounting. It
  then refreshes the bounded evidence, truncates the file, and waits 0.75
  seconds before allowing another sample. This keeps asynchronous log work and
filesystem reclamation from leaking into the next independent sample. It
  verifies output from both implementations and removes all temporary files on
  normal and abnormal exit. This preserves the production formatting, buffering, and
  filesystem-write cost without accumulating hundreds of megabytes per CI run.

Async-I/O comparisons allocate the same workers to qpx and the applicable
nginx reference: three for local-origin, four for cache, and four for the
feature-rich role. WebDAV uses two qpx async-I/O workers; this preserves the
single-frame `Bytes` fast path without cross-worker memory-bandwidth contention
under the fixed 64-connection load. The qpx WebDAV runtime bounds its blocking
filesystem pool at 16 threads, independently of async I/O. The pool remains
idle when no blocking operation is queued, retains cold-file and metadata
parallelism, and is included in process-tree CPU accounting. Apache event MPM
uses one request thread per active request while its
event listener owns idle keep-alive connections. Its complete
production-default event topology is explicit: three initial servers, 25
`ThreadsPerChild`, and 400 `MaxRequestWorkers`. Forcing it to four threads would
measure an artificial connection bottleneck, while collapsing the topology to
one oversized child was observably less stable than the production default.
Every row records `execution_model`, `role_workers`, and the applicable
`blocking_workers`; the checker requires equal workers for two async-I/O
products and explicitly validates the model mismatch for WebDAV. The objective
file pins every role topology and versioned workload profile. Complete-request
and error gates prove that both models serve the 64-connection workload. CPU
efficiency accounts for the resulting execution cost, and Apache CPU and memory
accounting covers its complete process tree. Unknown `QPX_PROXY_COMPARE_*`
environment variables are rejected so a misspelled benchmark control cannot
silently run a different matrix.

The qpx binary used by this harness enables the default production feature set
plus both HTTP/3 backends. Profiling-only `system-allocator` and the alternative
native-TLS build are intentionally excluded: enabling an instrumentation
allocator or two mutually exclusive TLS execution choices does not represent a
production request path. Runtime features are measured by the feature-rich
route rather than treated as zero-cost merely because they compile.

`scripts/check-origin-cache-performance.sh` enforces every declared lane in
`perf/origin-cache-performance-objectives.json`. Request-rate lanes require at
least 25% more throughput and CPU efficiency, at least 20% lower p99 latency,
and a geometric multi-axis dominance score of at least 1.25. The fully enabled
1 KiB lane requires at least 20% more throughput and CPU efficiency together
with 20% lower p99 and a 1.3 dominance score. For 1 MiB loopback lanes, memory
bandwidth and the client can become the shared throughput ceiling; those lanes
therefore forbid throughput regression, cap p99 at 1.15x, require at least 40%
higher CPU efficiency, and retain a dominance score of at least 1.1. WebDAV
additionally requires at least 50% higher CPU efficiency. This prevents a
bandwidth ceiling from hiding material efficiency or tail-latency gains without
accepting a merely marginal overall result. Missing
roles, unequal worker counts, unverified responses, unstable samples, or a
partially emitted matrix fail the release gate. Stability uses the narrowest
majority window of valid interleaved samples, matching the conservative median
instead of allowing one discarded outlier to dominate a max/min spread. qpx
majority spread is capped at 10%, and the reference at 15%. Connect, write,
timeout, non-2xx, and body-length errors must be zero. `wrk` read errors caused at the
sampling boundary are accepted only within the recorded 1000 ppm ceiling, and
failed-request accounting must match that bounded count exactly.

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

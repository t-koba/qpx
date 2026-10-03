# Performance

qpx is streaming-first on the default HTTP hot path. Features that need exact body inspection, retry templates, full capture, or compatibility bridges are explicit and bounded.

CI performance tests are regression and dominance gates, not marketing
throughput claims. Every external comparison runs qpx, the direct backend, and
the competing proxies on the same runner and uses dimensionless ratios. A
dedicated benchmark claim still requires fixed hardware, pinned CPU policy, and
representative upstream/downstream latency.

## Required audit categories and independent comparisons

The audit has eight isolated jobs: protocol, HTTP/1 proxy and origin/cache,
HTTP/2, streaming, allocation, netem, HTTP/3 interoperability, and callgrind.
The aggregate `perf_audit` gate requires every category to succeed, including
all 16 existing measurements and evaluations. Missing or skipped evaluations
fail the category and the release gate. `scripts/check-perf-audit-gates.py`
checks this wiring as part of the CI acceptance checks.

Every evaluation preserves its command exit status and writes its complete
output and a structured result under `target/perf/evaluations/`. Each category
uploads those files even on failure. Origin/cache and HTTP/2 results also list
the actual ratio, limit, direction, and violation percentage in the Actions
summary. Invalid sample diagnostics remain in the full log and summary.

The aggregate job downloads all eight category artifacts and checks every
required evaluation's commit, label, exit status, and log. Missing artifacts,
missing objective checks, invalid numeric values, and failed or skipped jobs
fail the aggregate gate. `qpx-perf-audit-summary` preserves both JSON and Markdown
reports, including absolute measurements, ratios, runner environments, and
the minimum, mean, maximum, and population standard deviation across independent
runs. Every individual run must pass; an average cannot hide a failed run.
The aggregate Actions summary includes the thresholds, violations, and diagnostic
log tails from all categories.

An initial cost comparison from GitHub job timestamps is retained below. Wall
time spans the audit jobs from their first start to final completion; runner
time sums their individual durations, including the shared build and aggregate
jobs after splitting. It excludes workflow queue time and unrelated CI jobs.

| Run | Audit wall time | Audit runner time | Result |
| --- | ---: | ---: | --- |
| [Original audit, `9500bb1`](https://github.com/t-koba/qpx/actions/runs/35880330277) | 95.55 min | 95.55 min | Failed |
| [Split audit, `fccf507`](https://github.com/t-koba/qpx/actions/runs/37100811495) | 35.57 min | 84.10 min | Failed |

These are observed failed runs, not a controlled performance comparison or proof
of completion. Repeat this accounting for the final revision's three successful
independent comparisons before claiming the final CI cost.

For three independent Linux comparisons, dispatch CI on the implementation
branch with `repeat_perf=true` and an explicit `baseline_ref` commit. HTTP/1,
HTTP/2, and streaming each run on three separate Ubuntu 24.04 runners. A shared build job builds the baseline and candidate before any comparison,
and every HTTP/1, HTTP/2, and streaming runner runs both revisions sequentially with the candidate's
measurement harness. Run 2 reverses revision order. HTTP/1, HTTP/2, streaming,
and netem use the same artifact binaries built with Rust 1.98.1; every runner
verifies the revision, compiler, executable permissions, and SHA-256 checksum
before measuring. This avoids redundant builds and prevents compiler updates
from changing the before/after comparison. Baseline
results and logs are separate artifacts. The baseline is checked in explicit
`measurement-quality` mode: complete samples, process accounting, and finite
stability limits are required, while product performance objectives apply to
the candidate in the default `acceptance` mode. An unstable or incomplete
baseline fails the comparison step. Other benchmarks never run concurrently
on that runner.

The runner manifest records CPU model, memory, kernel, runner image, compiler,
and revision. HTTP/1 records retain ready-process RSS (after one successful
readiness probe), the baseline before load, peak RSS, and both growth values.
A readiness measurement includes the probe and is not a pre-request allocation
measurement. This distinction must be preserved when interpreting memory costs.

Set `QPX_PROXY_COMPARE_THREAD_DIAGNOSTICS=1` only for a separate Linux
diagnostic run. It samples every implementation's process tree, including
per-thread CPU, scheduler queue time, and wait channel, into CSV files. This
sampling perturbs the workload; diagnostic records cannot satisfy either
HTTP/1 performance gate. The `proxy-phases` diagnostic enables the internal
`qpx_perf_phase` tracing target and records one timing per 1024 invocations at
each phase call site. It separates origin response headers, cache body transfer,
persistence and index updates, WebDAV metadata/file reads, blocking dispatch,
and file-backed sending. Timings are elapsed wall time, include scheduling and
can overlap; they must not be added together or interpreted as CPU time. The
phase summary retains the source log, sample count, interval, median, p99 and
maximum. Raw logs and thread samples remain diagnostic artifacts.
Sampled Linux file sends also record the TCP send queue and its unsent subset
after handing the body to the kernel. `socket-queue-summary.json` preserves
their byte distributions by source and body size. Sampling failures invalidate
the diagnostic summary; these measurements never run in ordinary gates.
The Linux sample on `0c16efb` showed a median 917,610 unsent bytes when a
1 MiB WebDAV send returned, while the send itself took a median 70.8 us.
File-backed transfers now temporarily apply a 64 KiB `TCP_NOTSENT_LOWAT` so
socket readiness follows client progress. The original setting is restored
after success, I/O failure, and cancellation. This changes queue management,
not the total socket buffer or the file contents. See the
[Linux TCP queue documentation](https://kernel.org/doc/html/v5.12/networking/ip-sysctl.html#tcp-notsent-lowat-unsigned-integer).

The `feature-callgrind` diagnostic profiles the actual 1 KiB feature-rich
configuration after warmup, with collection enabled only during the timed
requests. It preserves instruction profiles and annotations. On revision
`30d2ddc`, memory copies accounted for 50.72% of instructions in the first
sample; the outer reverse dispatcher contributed 36.76% through copies into
its heap allocation. The dispatcher now constructs the pinned future in a
separate function and boxes only the selected span variant. This preserves
request-span behavior and avoids moving both inactive variants on the hot path.
A second instruction profile still placed about 50% of its instructions in
memory copies, now in that constructor. Boxing only the cold IPC/HTTP dispatch
branches after a cache miss reduces the outer future from 30,488 to 20,544 bytes
on the local ARM64 debug build; cache hits do not allocate those branches.
Separating the general route state and allocating provider resolution only when
needed reduces this further to 6,472 bytes in the same compiler diagnostic.
The future-size regression uses a real compiled route and an 8 KiB budget.
The Linux native CPU diagnostic on revision `203f44a` attributed 11.76% of
feature-rich CPU samples in its second timed window to memory copies. Further
state-size inspection found that every head-only HTTP guard carried 3,776 bytes
of inactive body-evaluation state. Immediate guard results now use a ready
future; only body evaluation allocates its pending state. The same local ARM64
build measures 240 bytes for this guard. Reverse access control allocates the
provider future only when a provider is configured and borrows audit context
until rejection or body inspection requires ownership. Its size regression has
a 4 KiB budget. Request-collapse leaders also return a ready result; only
followers allocate the waiting and repeated-lookup state. QUERY body hashing
is allocated only for QUERY requests. These changes preserve guard, provider,
rate-limit, collapse, and body-inspection behavior; native profile shares and
state sizes are diagnostic evidence, not proof of passing performance ratios.
The exact Linux ELF from diagnostic revision `ec1e2ed` still copied 14,288 bytes
into the reverse-request allocation and 6,456 bytes into the uninstrumented
dispatcher allocation. Allocating with `Box::new_uninit` before constructing
the future and completing it with safe `Box::write` removes those whole-state
copies. The ELF from revision `2cd69fe` retains only initialized captures
(a 1,624-byte request-state block and a 656-byte dispatcher block), while the
allocation count and pinning boundary remain unchanged. Both native profiles
have zero lost samples and preserve the ELF digest. This proves the generated
copy removal; it does not establish passing normal performance objectives.
The `cache-miss-callgrind` diagnostic profiles the actual persistent cache
workload, including warm hits and unique misses, with the same instrumentation
boundaries and raw profiles as `feature-callgrind`.
The `proxy-native` diagnostic uses Linux perf's software CPU clock at 199 Hz
with DWARF call stacks, including kernel CPU work. It preserves raw profiles
and symbol reports for the cache and feature-rich roles. The exact ELF executable
is preserved as gzip with its SHA-256 and uncompressed size before measurement,
so raw addresses and DWARF stacks can be resolved after the runner is removed. All reports
are retained before sampling-quality validation; any lost samples fail the
diagnostic and are recorded explicitly in `sampling-quality.json`. Each perf
ring uses 8 MiB to retain DWARF samples during report-consumer scheduling delays;
the lifecycle record preserves that diagnostic buffer capacity. Its isolated process
group owns both the profiler and server and waits for their shutdown. These
instrumented records cannot satisfy normal performance acceptance gates.
Before measurement, a real qpxd local-response server verifies that terminating
the wrapper closes the complete profiler/server process group. Lifecycle records
retain the owner, timestamps, exit status, and any forced shutdown; incomplete
shutdown is a diagnostic failure. CPU diagnostics have a 20-minute deadline,
and individual symbol reports have a three-minute deadline. Self-CPU reports omit
rendered call graphs while raw DWARF stacks remain available for further analysis.
The `http2-native` variant records the 1 KiB, 100-stream workload in the same
way. HTTP/2 schema 11 requires explicit instrumentation provenance and workload-only
CPU and scheduler counter windows. Counter snapshots surround the completed
client workload before stopping samplers or processing their output. Native
diagnostic rows and rows missing that provenance are rejected by the required
gate. Reports are restricted to the workload windows recorded by the real RSS
sampler's monotonic timestamps, separating warmup and the individual samples.
The `streaming-native` variant records the fast and slow 100 MiB transfers with
the same owned profiler group and workload-window reports. Streaming schema 10
also requires explicit instrumentation provenance and rejects native diagnostic
records in the required gate. CPU profiles are diagnostic evidence only; the
uninstrumented streaming comparison remains mandatory.
The persistent miss instruction profile exposes an eviction-specific cost:
after the hot cache fills, repeated path-component comparisons dominate the
second and third samples. Recent-entry invalidation now compares the existing
32-byte disk file identity, shared by a response's body and metadata, rather
than reparsing every path. Canonical path validation also avoids constructing
temporary paths. Real-file eviction tests verify that both recent entries are
invalidated while the persistent object remains readable.
These diagnostic percentages and type sizes are not throughput improvements;
acceptance still requires three independent normal comparisons. The `origin-cache` diagnostic
runs the normal origin/cache workload and its unchanged objectives separately
from instrumentation, to obtain focused feedback before the complete CI matrix.

Linux descriptor snapshots and I/O counters use the same privileged reader for
both implementations because reference servers can disable process dumping.
Unreadable data is a measurement failure. FD and RSS peak sampling use persistent readers at 20 Hz and 100 Hz respectively,
so polling does not repeatedly launch interpreters or shell utilities during
load. Raw observations and achieved sampling gaps are preserved with the logs;
a sampler failure or missing completion record invalidates the measurement.
Normal WebDAV comparisons do not sample only qpx's threads. HTTP/2 reference instability must fail measurement quality checks;
a permissive spread value must not be used to turn an unstable lane green.

A CI run passing the old role thresholds does not prove nginx/Apache parity.
Tighten the principal role objectives only after all three independent valid
comparisons demonstrate the new limits; retain raw results for that decision.

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

Persistent in-memory object writes use vectored I/O for framing, body, and
metadata rather than issuing a separate write for each buffer. Short writes
advance the remaining buffers; interrupted writes retry and zero-progress or
other failures propagate. The atomic rename and capacity accounting remain
unchanged. Directory validation runs at the actual write boundary, checks
existing components before attempting creation, and never memoizes verified
paths. Replacing a previously checked parent with a symlink is rejected on the
next write. Real-filesystem tests cover concurrent directory creation, parent
replacement, complete object sizes, restart reads, and empty objects.
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
HTTP/1 comparison. Each round performs an immediately preceding calibration of
at least two seconds, converts that measured rate to a fixed request count, and
records the calibration duration, calibration requests, and resulting benchmark
request count. This keeps request accounting exact while preventing a short
calibration interval from amplifying runner noise. The benchmark records proxy
CPU and backend CPU separately, then compares qpx and nginx by requests per
total-system CPU second. The direct backend is a workload and saturation
reference; its request rate is not treated as a proxy ceiling because its
TLS/H2 topology differs from the two proxy lanes.
`scripts/check-http2-performance.sh` requires no per-lane throughput or
total-system CPU-efficiency regression, bounds mean latency to 1.05x, p99 to
1.1x, and maximum latency to the external leader on every lane. Every lane must
reach at least 1.25 multi-axis dominance, and the geometric score across the
complete four-lane matrix must reach 1.5. qpx sample spread is capped at 10%;
reference spread is recorded and capped separately so runner noise cannot
silently excuse a qpx regression. The qpx HTTP/2 server runs streams
concurrently in the owning connection task. The single active stream reuses its
boxed future allocation; a second stream promotes both streams into the
connection-local concurrent scheduler. The scheduler drains ready completions
between accepts, and divides its initial response buffer budget across active
streams so multiplexed responses cannot collectively overrun the connection
flow-control window. Stream errors remain visible and the connection idle
deadline starts from the latest stream completion. Peer resets are observed
while service execution and response-body production are pending, so cancelled
work releases its upstream resources promptly. Expected peer cancellation is
recorded at debug level; protocol, framing, and local implementation errors
remain warnings or request failures.

The HTTP/2 Callgrind lane establishes warm connections while instrumentation is
disabled, records those warm-up requests separately, and enables instruction
counting only for the fixed measured request batch. This prevents TLS key
exchange and connection setup from dominating what is reported as an HTTP/2
request-path profile. The measured batch still uses the production TLS and
HTTP/2 implementation; only the location of the profiling window changes.

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
interleaved across three rounds. Every scheduled sample must be valid; missing
or invalid samples fail the measurement. Each proxy
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

HTTP/2 completion processing now drives the connection after at most eight
ready completions, after an admission poll, or immediately after the final
outstanding stream completes. The native 1 KiB/100-stream profile attributed
2.19% of its second timed window to the connection driver itself; the change
avoids flushing each already-ready completion separately while preserving
flow-control progress. Real TCP regressions cover 128 responses and concurrent
slow readers with bodies larger than the connection flow-control window.
This is a candidate optimization until normal Linux comparisons pass.

Closed-idle origin tests synchronize with TCP EOF on the pooled client socket,
rather than treating a server-side close notification as proof that the client
has received FIN. Every pooled raw HTTP/1 connection is probed on reuse; the
previous five-second probe exemption is removed. No new request retry is added.
The native proxy diagnostic also preserves bounded memory-copy caller reports
for each second timed window, with absolute sample percentages. These reports
identify the remaining copy paths without treating instruction counts or
instrumented timings as acceptance measurements.

Streaming CPU efficiency uses Linux process CPU clocks, not `/proc/stat` tick
counts. The previous 100 Hz accounting quantized subsecond fast-transfer CPU
measurements to 10 ms. Schema 7 requires nanosecond process-clock provenance;
raw before/after snapshots preserve per-process CPU values and clock resolution.
Completed thread CPU time remains included in its process clock. Schema 9 brackets
CPU and scheduler counters immediately around the client workload, before sampler
shutdown and report processing. Resource peaks still use the complete sampled
workload; this counter boundary correction does not change any performance limit.
Workload sizes,
reference pairing, sample aggregation, and all acceptance thresholds are unchanged.
A disappearing measured process, inadequate clock resolution, or decreasing CPU
counter invalidates the measurement instead of becoming zero CPU consumption.
Resource ratios use the same validation across proxy, origin/cache, HTTP/2, and
streaming gates. Equal measured zero costs mean parity. A positive measured cost
against a zero reference has no finite ratio: it fails with the workload, metric,
both absolute values, and a null ratio. Maximum floating-point sentinels and
non-finite violation percentages are not used for this case.

Native copy-call reports disable perf's inline source expansion: the runner's
addr2line resolver failed to read its cached ELF and retried each address until
the report deadline. Function call chains remain recorded and displayed; the
raw DWARF stacks and real binary are preserved for source-level analysis.
The `webdav-native` diagnostic profiles the normal 1 KiB and 1 MiB WebDAV
workloads against Apache, retaining per-thread waiting snapshots and six timed
CPU reports. It preserves the normal allocator environment and does not replace
any required performance gate.

The `http2-windows` experiment compares h2load's 30-bit default stream/connection
windows against 24-bit windows, sequentially on the same runner with the same
binary, 1 MiB bodies, and 100 streams. It records the wrapper and exact client
settings and keeps all records explicitly diagnostic; required gates reject them.
Each condition still enforces the existing finite 1.25 reference and 1.1 candidate
throughput/CPU spread limits and requires complete clean samples. A failed first
condition does not suppress evidence from the second condition. This diagnoses
reference stalls without changing the required workload or its objectives.

The `webdav-sockets` diagnostic samples Linux TCP information for both real
WebDAV servers alongside thread counters. It preserves raw `ss` output, process
identity, timestamps, TCP MSS, and observed bytes per data segment for every
workload round. This instrumented run is excluded from acceptance. Its segment
density describes observed active connections rather than a total packet count;
missing traffic attribution or workload rounds fail the diagnostic.

HTTP/2 request-count calibration must finish within 1.25 times the target
measurement duration. Each measured sample must last between target / 1.25
and target * 1.25 (8–12.5 seconds for the default 10-second workload). This
budget uses the reference throughput stability envelope: a short sample can
underrepresent scheduler and resource costs, while a stalled calibration can
underestimate the subsequent request count. Every scheduled sample must be
valid; failed samples cannot be discarded to obtain a passing majority. The
gate verifies the minimum and maximum durations across all samples. Invalid
samples retain their actual metrics, limits, and reasons in JSONL artifacts,
and the raw per-request latency logs are retained for valid and invalid runs.

CPU, scheduler-delay, and process-tree I/O counters must not decrease between
observations. A decrease invalidates the measurement with the counter name,
before/after values, delta, and zero lower bound; it is never clamped to zero.
Proxy and backend scheduler counters are checked separately before summing so
one process cannot hide a missing observation from another. The real process
sampler check also verifies rejection of reversed real CPU observations.

The `http2-io` diagnostic traces the real h2load client, both reverse proxies,
and their real nginx origins for the 1 MiB / 100-stream workload. It records
epoll/poll waits, futex waits, socket options, connection/close operations,
and descriptor ownership with per-process timestamps and syscall durations.
Payload read/write buffers are excluded. Each tracer and its actual program
share an owned process group with bounded termination, verified first using
a real qpxd local-response server. Traced measurements carry diagnostic
provenance and cannot satisfy required performance gates. Long waits and
process lifecycle records are retained even when measurement quality fails.

The HTTP/2 syscall diagnostic uses strace seccomp filtering to avoid ptrace
stops for unobserved payload I/O. Its real-server ownership probe and every
server lifecycle must confirm kernel seccomp filter mode in `/proc`; an
unavailable filter cannot silently fall back to a valid diagnostic run.

## Observed CI timing after category separation

Job timestamps from the original [CI run 35880330277](https://github.com/t-koba/qpx/actions/runs/35880330277)
and [CI run 37077837510](https://github.com/t-koba/qpx/actions/runs/37077837510)
provide the following observations. Performance wall time spans the first
performance job start through the last performance job completion. Runner time
sums elapsed time for performance jobs, including the shared build and aggregate.
Queue time is excluded.

| Observation | Original audit | Separated categories |
|---|---:|---:|
| Performance wall time | 95.55 min | 34.37 min |
| Performance runner time | 95.55 min | 91.55 min |
| Entire CI wall time | 95.83 min | 34.47 min |

Both executions failed their performance gate. They used different product
commits and measurement validation rules, so this single pair does not establish
a reproducible runner-cost improvement. The separated run's longest lane was
proxy at 30.13 minutes; HTTP/2 took 12.25 minutes and netem 17.73 minutes.
Repeat this accounting after all required measurements pass at the final commit.

The `http2-events` diagnostic records kernel syscall tracepoints without ptrace.
It observes enter/exit events for epoll waits and connect calls with
`CLOCK_MONOTONIC`, retaining process and thread IDs for alignment with resource
sample windows. Linux SOCK_DIAG snapshots retain acknowledged, sent, received,
and unsent bytes, send/receive windows, queue depths, and retransmission counters
every 100 ms for the five IPv4 benchmark listener ports. Socket cookies identify
connections across port reuse. Kernel tracepoints record retransmissions.
System-wide futex events and per-packet TCP probe events are excluded: idle waits
dominated the first recording, and per-packet recording produced 5.7 GB of data
without reproducing the long stall. A real TCP readiness and SOCK_DIAG counter
probe verifies both recorders before the
comparison. Missing tracepoints, missing comparison processes, or lost events
fail the diagnostic. Raw perf data and the decoded event stream are retained.
Payload buffers are not captured, and instrumented measurements remain excluded
from acceptance. This diagnostic is intended for stalls that disappear under
strace; kernel recording still requires checking its effect on the workload.

The `http2-mtu` diagnostic runs the real 1 MiB, 100-stream comparison in an
owned Linux network namespace, sequentially comparing loopback MTU 65536 and
1500 on the same runner. It does not modify the host interface or replace
required measurements. Both results, logs, and exit statuses are retained; a
failed phase makes the diagnostic fail after both phases finish. Both phases
use the same 100 ms SOCK_DIAG sampler, retaining negotiated MSS, queues, receive
windows, and ACK progress without capturing payloads. Sampler metadata includes
its process CPU time, elapsed time, and fraction of one CPU core, so observer
overhead can be assessed rather than assumed negligible. Calibration lasts at
least eight seconds in this diagnostic only; normal comparisons retain their
existing calibration setting. The namespace
identity and interface MTU are recorded before starting servers; all three samples still
require complete responses within the existing duration budget. Its rows are
marked diagnostic and cannot satisfy required acceptance gates. This experiment
also runs the existing HTTP/2 checker in `diagnostic-quality` mode with its
explicit namespace/workload manifest. This mode requires all declared samples
and all three roles, preserves the existing finite spread limits, and skips
product objectives. Ordinary acceptance and measurement-quality modes still
reject all instrumented rows. A duration-valid but unstable phase fails rather
than being reported as a successful diagnostic comparison. The experiment
investigates transport stalls seen with queued output and advertised receive
windows below the ordinary loopback MSS; it is not evidence of a resolved cause
until independently reproduced comparisons establish the effect.
The `http2-observer` variant fixes MTU at 1500 and calibration at eight seconds,
then runs sampled and unobserved phases sequentially on the same runner. Both
retain three samples per role and use the same diagnostic-quality checker and
existing spread limits. The unobserved phase is still explicitly diagnostic;
it cannot replace any normal gate. This isolates TCP sampler overhead from
transport and calibration settings instead of assuming its measured CPU share
has no effect on workload stability.
The `http2-quality` variant runs all four required body/stream lanes without the
TCP sampler, keeping MTU 1500 and eight-second calibration in its own network
namespace. Its manifest must declare the complete normal matrix. Diagnostic
quality applies the default 1.1 candidate and 1.25 reference spread limits to
every lane, including the 1 MiB/one-stream lane with wider temporary normal
overrides. Missing lanes or failed samples invalidate the diagnostic. Normal
measurement conditions remain unchanged until independent complete-matrix
diagnostics establish reproducibility.

The `scheduler-accounting` diagnostic validates Linux taskstats TGID CPU delay
accounting with real competing processes on one CPU. It enables
`kernel.task_delayacct` before starting the probe, observes a busy thread while
alive and after joining it, and requires both its scheduler delay and event
count to remain accumulated. The probe runs on the host and inside an owned
network namespace, retaining both JSON snapshots. Missing kernel support,
privilege failures, unavailable accounting, or decreasing counters fail the
diagnostic. The host and namespace probes passed with an observed positive
worker delay retained after thread exit. HTTP/1 schema 5, HTTP/2 schema 11, and
streaming schema 10 therefore use TGID accounting instead of live-TID schedstat
sums, which can decrease when request threads exit. Accounting is enabled before
server startup. Both boundary snapshots retain process identities, taskstats
versions, event counts, and delay totals; process disappearance, identity changes,
or decreasing counters invalidate the measurement. Required checkers reject
records without the new accounting provenance. Performance thresholds remain
unchanged.

Native proxy diagnostics also decode the second sample's real call chains with
instruction addresses and symbol offsets. The exact ELF and its checksum remain
retained with the profile. These records distinguish hot copies within a large
async state machine from copies on cold branches; function-level percentages
alone cannot identify which copy should be changed. Decoding occurs after all
workload measurements and fails if no samples are produced.

RSS and descriptor sampler metadata retain their own CPU time, elapsed time,
and fraction of one CPU core. This measures observer cost directly without
subtracting it from server measurements or assuming calibration and measured
workloads see identical competition.

The retained Linux ELF from the cache-request borrowing diagnostic still reserves
`0x62a8` bytes on every poll of the request executor, with six page probes and
cold boxed transport futures copied through that stack. The plain HTTP, retrying
HTTP, IPC, and WebSocket constructors now allocate before creating their state
behind non-inlined constructors. They keep the same existing allocations and
protocol behavior while preventing concrete cold futures from becoming caller
stack temporaries. The unconditional plain HTTP path remains inline. The
retained Linux diagnostic at `1156c56` verifies a 15,048-byte (`0x3ac8`)
request-executor poll frame, down from 25,256 bytes (`0x62a8`), with three
page probes instead of six. The large cold-future copies are absent from that
frame. This is a 40.4% frame reduction in the exact profiled ELF; it does not
establish throughput, CPU-efficiency, or latency acceptance. Normal paired
measurements and independent repetitions remain required.

The decoded feature-rich cache-hit sample also identifies 90 memory-copy samples
at 47 callsites within the request executor, including 352-byte request moves
and 1,296-byte stage results. Access-control and module preparation now borrow
the request kept by their caller rather than returning it in stage results.
Exclusive borrowing preserves the existing Send requirement for bodies that
are not Sync. The obsolete module-result wrapper is removed. Evaluation order,
header rewrites, module responses, and request ownership on upstream dispatch
remain unchanged; the performance effect must be measured independently.

The optional `http2-affinity` diagnostic runs the complete HTTP/2 matrix in an
isolated network namespace with a 1,500-byte loopback MTU. It reserves one
available CPU for the real h2load process and the remaining CPUs for servers
and resource observers, retaining the disjoint partition in its manifest.
The eight-second calibration and all three samples per role use that same
partition. Every lane retains the default finite measurement-spread limits.
This experiment tests CPU competition as a cause of calibration instability;
it neither replaces normal acceptance gates nor establishes causality alone.

The retained native ELF at `2760716` verifies a further request-executor poll
frame reduction from 15,048 bytes to 12,216 bytes (`0x2fb8`), with two page
probes. Source-line decoding maps a remaining 352-byte copy to the owned
request entering `ReversePostModuleInput`; the observed access-result copy
is now 944 bytes. Sample counts alone are not a paired CPU-efficiency result.

GitHub job start/end timestamps provide an initial CI scheduling comparison:
run `35880330277` spent 95.55 minutes in the single performance audit; run
`37121209517` spanned 35.15 minutes from the performance build start through
aggregation, with 92.60 summed runner minutes across the build, eight categories,
and aggregate gate. These figures exclude queue time and other workflow jobs.
The commits, resource accounting, and cache state differ, so this is an observed
operational result rather than a controlled estimate of split-only savings.
Both runs failed acceptance; reduced waiting time does not establish completion.

Native diagnostics decode the second workload sample's complete call chains
for WebDAV and streaming as well as proxy workloads. Kernel and user-space
callers retain instruction addresses and symbol offsets. This lets task-switch
and mutex hot spots be attributed to file sending or metadata processing after
measurement, without running report generation during the benchmark.

The first complete CPU-partition diagnostic, run `37124959646` at `18e0fbe`,
failed measurement quality. Completed samples included 6.81, 12.70, and
16.83 seconds against the unchanged 8.0-to-12.5-second measurement window.
All requests in those samples completed successfully. CPU partitioning alone
therefore did not establish reliable calibration and is not adopted by normal
acceptance gates. The failed experiment's manifest, client logs, and raw
resource snapshots remain retained in its diagnostic artifact.

The fast streaming diagnostic at `dc969d0` retained only 47 CPU samples in
the second workload window. That is insufficient for precise hot-spot ranking.
Native streaming diagnostics therefore use 64 sequential 100 MiB transfers
instead of eight, preserving one active client, fresh connections, and all
response-completion checks. Normal required streaming measurements remain at
eight transfers. Extended native records remain instrumented diagnostic data
and cannot satisfy the normal performance gate.

The WebDAV callsite diagnostic at `147ad23` records blocking-pool condition
variables among the mutex callers, with 53 task-wakeup and 30 futex-wait CPU
samples in the second 1 MiB window. Thread snapshots retain two main runtime
workers and roughly 20 additional blocking workers. A runtime-owned WebDAV
admission semaphore was evaluated at `44f25c2`, limiting active filesystem
handlers to the lesser of the configured worker and blocking-thread counts.
The same-runner comparison in Actions run `37130078125` rejected this change:
1 MiB qpx throughput fell from 5921.87 to 5692.24 requests/s, CPU efficiency
fell from 5792.12 to 4930.05 requests/CPU-second, and p99 rose from 78.141 to
147.939 ms. Candidate CPU-efficiency spread was 1.1534, exceeding the unchanged
1.15 quality limit, so this run also fails measurement quality and cannot prove
a precise regression magnitude. The trial was removed; the profile alone did
not justify adopting blocking admission. Raw records and the comparison
diagnostic remain available for subsequent investigation.

The optional `webdav-revision` diagnostic builds its requested baseline and
candidate before measuring either on one Linux runner. It retains exact commit
identities and binary hashes, three interleaved samples per competitor, raw
resource snapshots, and both 1 KiB and 1 MiB workloads. Baseline measurement
quality, candidate measurement quality, unchanged existing acceptance, and the
1 MiB p99 goal are separate retained evaluations. The focused objectives copy
only the existing WebDAV lanes without weakening any limit; the additional
p99 objective can only tighten its current bound to 1.0. The diagnostic cannot
replace the complete required performance matrix.

HTTP/2 request-count calibration now enables the same h2load latency log and
Linux process-tree RSS/FD observers used during measurement. Previously those
observers and the per-request log were absent during calibration, so its rate
estimate described a different client and runner load. Every calibration round
retains its own h2load output, latency log, and observer metadata. This corrects
the condition mismatch without changing duration budgets, completion checks,
sample counts, or stability limits. It does not establish that observer cost
caused the previously observed HTTP/2 stalls; full-matrix independent quality
runs are still required.

Independent baseline comparisons at `5390482` against `9500bb1` completed in
[Actions run 37126374419](https://github.com/t-koba/qpx/actions/runs/37126374419).
Each Linux runner built both versions before measuring; run 2 reversed version
order. Non-performance workspace/OS, feature-matrix, preflight, and external
interoperability jobs passed. All three proxy and HTTP/2 gates failed; only
streaming run 2 passed. These runs do not establish performance completion.
The following candidate ratios retain each independent result rather than
averaging away failures:

| Workload and metric | Run 1 | Run 2 | Run 3 | Requested bound |
| --- | ---: | ---: | ---: | ---: |
| Local 1 KiB RSS | 0.997 | 0.991 | 1.014 | <= 1.06 |
| Feature-rich 1 KiB throughput | 0.904 | 1.050 | 0.802 | >= 1.0 |
| Feature-rich 1 KiB CPU efficiency | 0.997 | 1.242 | 0.834 | >= 1.0 |
| Feature-rich 1 KiB scheduler delay | 0.911 | 1.179 | 0.860 | <= 1.0 |
| Cache miss 1 KiB throughput | 0.964 | 2.073 | 1.659 | >= 1.0 |
| Cache miss 1 KiB CPU efficiency | 0.896 | 1.142 | 0.768 | >= 1.0 |
| Cache miss 1 KiB p99 | 0.472 | 0.341 | 0.450 | <= 1.0 |
| Cache miss 1 KiB scheduler delay | 2.926 | 2.154 | 1.646 | <= 1.0 |
| WebDAV 1 MiB CPU efficiency | 1.413 | 1.380 | 2.042 | >= 1.5 |
| WebDAV 1 MiB p99 | 1.489 | 0.761 | 3.211 | <= 1.0 |

Candidate WebDAV throughput improved in all three same-runner baseline pairs,
but its absolute CPU efficiency declined in all three. Cache-miss p99 improved
in all three pairs, while its scheduler delay increased. The separate raw and
aggregated baseline/candidate JSONL, process snapshots, environment records,
and retained evaluations are in the per-category artifacts. Existing limits
remain unchanged; unmet stronger goals have not been declared passing.

The extended streaming native diagnostic at `b874d77` completed without lost
samples. Its fast windows contain 376, 429, and 369 CPU samples, compared with
47 in the prior second window. Kernel networking, packet handling, and locking
dominate the observed hot symbols; the second window attributes 6.53% of sampled
events to `_raw_spin_unlock_irqrestore`. This identifies further investigation
areas but does not justify a product change or prove a normal gate improvement.

A subsequent WebDAV trial at `dd688ef` increased the contended file-send quantum
from 64 KiB to 128 KiB while retaining the 64 KiB Linux `TCP_NOTSENT_LOWAT`.
Native callsites at `147ad23` identified file-splice, TCP-send, and task-wakeup
work, but three same-runner comparisons rejected larger batches. Runs
`37134112087`, `37134113984` (reversed version order), and `37134115967` all
passed baseline/candidate measurement quality. Candidate 1 MiB CPU efficiency
fell by 5.0%, 12.1%, and 1.0%, and throughput fell by 2.5%, 4.2%, and 0.7%.
p99 changed from 100.248 to 113.376 ms, 67.399 to 60.817 ms, and 45.766 to
91.433 ms. All three failed the p99 goal. The trial was removed; active-transfer
thresholds, send-queue management, and scheduling quanta retain their previous
behavior. Raw comparisons and failure evaluations remain diagnostic evidence.

The refreshed feature-rich callgrind diagnostic at `d0cd523`, Actions run
`37133652146`, records 40,126 requests in its second window. Direct edges from
the audit-context builder attribute 16,893,042 copy instructions to its
by-value setters in `audit.rs`, with five calls per request. The builder now
initializes the final structure once, preserving every field and existing
observability condition. The single-use constructor and setters are removed.
This introduces no allocation and changes no audit/access-log semantics;
instruction profiles and normal comparisons must verify its performance effect.
The refreshed profile at `3eea4ef`, run `37134615410`, confirms direct
audit-builder copy calls fell from six per request (240,756 calls for 40,126
requests) to one (21,427 calls for 21,427 requests). Copy instructions at that
builder fell from approximately 486 to 65 per request. These normalized counts
verify removal of the targeted copies; they do not substitute for normal
throughput or CPU-efficiency acceptance.

The cache-miss callgrind diagnostic at `d0cd523`, Actions run `37133654237`,
retains separate hit dumps (parts 1-3) and persistent-miss dumps (parts 4-6).
Its second miss dump records repeated path-component parsing and `Path::hash`
work from the in-memory LRU. The LRU now uses the existing canonical 32-byte
disk file identity instead of owning and hashing a `PathBuf` for each object.
Disk filenames, SHA-256 identity generation, durable data, eviction order,
capacity accounting, and expiry handling are unchanged. Removal reuses the
validated identity for both hot and persistent indexes; noncanonical paths fail
before filesystem deletion. A real-file regression test verifies that rejection
preserves an unrelated file. Normal comparisons and a refreshed instruction
profile must still establish the performance effect.

The matched-observation HTTP/2 quality runs `37133211649`, `37133213817`, and
`37133215946` all failed. Recorded invalid durations include direct-backend
7.86/6.93 s, direct-backend 7.53 s, and direct-backend 6.66 s, respectively;
run 1 also records nginx 15.31 s and run 3 a direct-backend calibration of
13.87 s. All duration and completion criteria remain enforced. Linux diagnostic
runs now retain GNU time records for each calibration and measured h2load
process, including user/system CPU, context switches, peak RSS, and exit status.
The same wrapper observes calibration and measurement, while ordinary required
runs continue to execute h2load directly. These client observations supplement
server resource records and cannot satisfy the normal gate.

Review of the file-identity LRU exposed an existing inline-metadata defect:
body and metadata inserts used the same physical-file key and replaced each
other's LRU value. Real-file regression tests reproduced returning `metadata`
instead of `original` after a recent-cache slot collision, and accounting for
only 8 bytes when an 8-byte body and 8-byte metadata were both retained.
Hot entries now own the body's optional bytes and inline metadata separately
under one physical identity and account for their combined length. A completed
file write publishes both eligible recent views in one snapshot, removing old
views and avoiding a second LRU update and snapshot publication. Oversized
bodies still retain eligible metadata; an over-capacity combined object leaves
no unaccounted recent views. The existing eviction fixture now budgets the
actual 16-byte combined object and still verifies invalidation of both views.
Disk schema, filenames, writeback admission, and durable publication are unchanged.

Client usage evidence from `ad7b8d4`, Actions run `37135785415`, records average
h2load CPU use from 0.54 to 1.70 cores across the complete HTTP/2 matrix.
System CPU accounts for approximately 37-63% of its CPU time. Invalid measured
durations include direct-backend 7.94/14.14 s and nginx 13.21/6.95 s. These
observations do not distinguish networking from per-request log writes and
do not justify changing the load generator or the duration limits.

The `http2-client` diagnostic samples the actual packaged h2load with perf
CPU-clock at 199 Hz, without call graphs. It retains each process's complete
arguments and monotonic lifecycle timestamps, raw CPU data, symbol report,
and lost-sample validation, enabling alignment with calibration and measured
request logs. All four body/stream lanes run in an isolated MTU-1500 namespace
with the existing full quality settings. Profiling processes share owned
process groups with their real clients; interrupted, missing, empty, or lost
profiles fail explicitly. GNU time in this experiment includes the profiler,
as stated in its manifest; these values cannot substitute for direct client
CPU records or normal required performance results.

Normalized persistent-miss callgrind windows retain all three measurements
instead of comparing raw instruction totals with different request counts:

| Profile revision | Miss window 1 Ir/request | Miss window 2 Ir/request | Miss window 3 Ir/request |
| --- | ---: | ---: | ---: |
| `d0cd523` before file-identity LRU | 245,967 | 249,745 | 254,515 |
| `ad7b8d4` with file-identity LRU | 235,470 | 241,372 | 244,818 |
| `086e86a` with combined body/metadata | 234,242 | 237,359 | 238,173 |
| `c595b3e` with recent shard filters | 230,020 | 233,026 | 234,602 |

The refreshed `086e86a` profile, Actions run `37138034288`, still attributes
14,006,016 instructions in its second miss window to full file-identity
comparisons while invalidating recent views. Recent-cache shards now retain
a 64-bit membership filter derived from their file identities. Invalidation
skips shards that cannot contain a removed file and still compares full
identities in every candidate shard. Changed shards rebuild the filter before
publishing the immutable snapshot. Filter collisions therefore affect only
the amount of work, never eviction decisions. A real-file regression test
replaces and deletes one of two distinct objects sharing a filter bit and
verifies the other remains available in the recent cache. A refreshed profile
and normal comparisons must establish the performance effect of this trial.
The refreshed `c595b3e` profile, Actions run `37139269244`, completed successfully.
Its second miss window reduces recent-update self instructions from approximately
11,229 to 5,496 per completed request, while total instructions decline in all
three miss windows. This verifies removal of the targeted scan work, not normal
throughput, latency, or CPU-efficiency acceptance.

Copy callsites in the `086e86a` persistent-miss profile include the request-export
call at `dispatch_http.rs:140` (847,737 instructions and 13,059 copy calls).
Request export now borrows the owned request exclusively rather than returning
it through an async state machine. Sample/full capture replace only its body,
preserving the method, URI, version, headers, extensions, preview serialization,
channel limits, deadlines, and exporter behavior. Reverse HTTP/IPC, forward,
MITM, and transparent callers use the same internal interface; obsolete owned
helper signatures are removed. Existing real shared-memory capture tests and
the full workspace validate the behavior. Refreshed profiles and normal
comparisons must establish the performance effect of this trial.

The first client CPU diagnostic (`37138641272`) preserved 161 raw profiles,
but its initial report step ran as root against files owned by the invoking
runner and its new manifest was missing from the diagnostic quality checker.
Report generation now runs as the owning runner in an always-run workflow step;
the checker validates the diagnostic's explicit profiler provenance using the
unchanged full matrix limits. Run `37140288891` reanalyzed the original data
without sending any new requests and retained the source and analysis run IDs.
All four lanes passed measurement quality in that single instrumented run.
148 CPU profiles were valid with no lost samples; 13 short warmups had no CPU
samples and kept the overall profile result failed. Future captures sample
every logged calibration and measurement, while short connection warmups run
the same real h2load without CPU sampling. Empty or lost sampled windows still
fail. Valid second-round profiles emphasize socket reads, copying into user
buffers, syscall entry, and task/network synchronization; the data does not
establish per-request log writes as the dominant cause. One instrumented
quality success does not establish normal measurement stability.

The balanced-affinity diagnostic reserves two available CPUs for real h2load
and the remaining CPUs for servers and resource observers, requiring at least
two server CPUs. The preceding one-client-CPU trial cannot provide headroom
for the observed average client demand of up to 1.70 cores. The new partition
is recorded and checked as disjoint; insufficient CPUs fail explicitly. It
retains all body/stream lanes, interleaved sampling, logged 8-second minimum
calibration, completion accounting, and finite spread/duration bounds. Three
independent Linux runs must establish quality before considering these
conditions for a normal required measurement. CPU profiling remains disabled
in this experiment; ordinary required gates remain unchanged.

The `086e86a` persistent-miss callgrind profile attributes approximately
3.05 million instructions each to copying the HTTP attempt into its await
state and constructing the attempt itself, plus 3.00 million instructions to
its timeout construction, across 4,353 requests. Compiler state probes show
11,880 bytes for the attempt, including an inactive 9,184-byte HTTPS future;
the plain HTTP future itself is 4,744 bytes. HTTPS now constructs its future
in separately allocated storage only when that branch is selected. Its
handshake, certificate verification, connection pool, and HTTP/3 behavior
remain inside the same future body. The uncommon non-interim version branch
also constructs its state outside the common attempt. Together these changes
reduce the attempt to 8,728 bytes on the local ARM64 compiler, versus 9,544
bytes with only HTTPS separated. Plain HTTP and IPC retain their existing
allocation paths. A 9 KiB state budget guards against reintroducing inactive
protocol state. Workspace tests pass, but refreshed Linux instruction profiles
and normal performance measurements must establish the actual benefit and
check the cost of the additional HTTPS-only allocation.

Balanced-affinity diagnostic runs `37141272853`, `37141275017`, and
`37141277021` all pass the unchanged complete-matrix quality checker on
`21ed941`. Each records client CPUs `[0, 1]`, server CPUs `[2, 3]`, an isolated
1500-byte loopback MTU, three interleaved samples per role, and matching
requested/completed counts in all four lanes. Across all runs, measured sample
durations are 9.06–11.04 seconds; maximum qpxd throughput spread is 1.0923 and
maximum reference throughput spread is 1.1382, below the existing 1.10/1.25
limits. Complete raw logs remain in each Actions artifact. These results
establish measurement quality, not product performance acceptance.

Normal CI now invokes the isolated balanced measurement wrapper for both
baseline and current binaries. It verifies the namespace, MTU, and actual CPU
affinities, runs the real uninstrumented h2load, and embeds the environment in
each sample and aggregate. The normal checker rejects missing or inconsistent
environments, diagnostic data, insufficient CPUs, incomplete counts, and
unstable samples. Every existing performance threshold remains unchanged.
The normal three-run comparison must independently verify these conditions
and product acceptance; diagnostic results are never relabeled as normal data.

The refreshed `fdb7c03` profiles completed in Actions runs `37143171706`
(persistent miss) and `37143173866` (feature-rich hit). In the second miss
window, the three targeted attempt/await/timeout copy sites decrease from
approximately 701/701/689 to 605/605/593 instructions per call against
`9c2041f`, confirming removal of the intended copying. Whole-program miss
instructions per completed frontend request decrease in each of the three
windows, but writeback completion counts vary within those windows; this
normalization is not a precise measure of persistence cost or CPU efficiency.
Feature-rich hit instructions remain similar, as expected when no HTTPS
upstream attempt is made. Normal throughput, CPU efficiency, tail latency,
and queue-delay acceptance still require independent normal measurements.

The `9c2041f` feature-rich profile also attributes 3,117,750 copy instructions
to construction of the guarded-request future at `dispatch.rs:505`, and
3,242,460 to its earlier request-limit boundary at `prepare.rs:552`. Body
limiting now borrows the request and replaces only the body. Every reverse,
forward, MITM, transparent, and common dispatch caller uses the same internal
interface. Guard buffering moves the owned request only when observation
actually consumes its body. Limits, observed-size rejection, body deadlines,
streaming errors, and response handling retain their existing behavior. The
existing streaming-limit test now also verifies request context survives
wrapping. This is a separate optimization trial requiring fresh profiles and
normal comparisons; it does not change public APIs or configuration.

The three complete balanced-affinity quality runs also support removing the
old 1 MiB/single-stream reference-spread exceptions (5.2 for throughput and
1.6 for CPU efficiency). Every normal reference lane now uses the existing
1.25 spread ceilings; qpxd keeps its existing 1.10 ceilings. This tightens
measurement quality and does not relax any product objective.

The refreshed `42c4157` feature-rich profile (`37144416673`) reduces total
instructions per completed frontend request in all three windows, from
47,228/47,278/47,488 to 46,792/46,712/46,886 against `fdb7c03`. This confirms a
small consistent instruction reduction; it does not establish the required
throughput or CPU-efficiency ratios. Normal run `37143289872` on `0b28482`
still fails streaming: run 1's slow queue-delay ratio is 8.9549 against 1.5,
run 2's fast total-CPU efficiency is 1.2322 against 1.25, and run 3's slow
queue-delay ratio is 1.5505 against 1.5. These failures remain enforced.

The cache-writeback diagnostic enables the existing local metrics recorder
and retains real Prometheus snapshots around each workload. It reports body
bytes collected and admission rejections using the unchanged bounded product
writeback controller, plus raw frontend completion counts and capture times.
An uninitialized rejection counter explicitly means no rejection has yet
registered it; the body counter must exist after warmup. Missing pairs, missing
workloads, invalid/decreasing counters, and incomplete evidence fail the
diagnostic. Collection is before metadata encoding and persistence, so its
counter is never presented as durable completion. Window edges may include
in-flight work and metric scrapes. Every diagnostic sample remains marked
intrusive and cannot satisfy normal acceptance; full raw snapshots are saved
even if comparison or summary generation fails.

The first real writeback diagnostic (`37146028231`, `76e98d8`) reports
64,396/78,955/75,787 admission rejections for 105,991/118,214/111,144
completed miss requests. Collected body-byte deltas are
42,637,312/40,241,152/36,270,080. These intrusive windows show substantial
pressure on the unchanged admission controller; they do not measure durable
completion or prove normal throughput. Its original file-mtime capture times
were rewritten during artifact handling and are invalid. Capture timestamps
are now explicit sidecar contents, must be present and strictly ordered, and
survive archival independently of file metadata. Historical counter deltas
remain usable, but historical timestamps must not be used for rates.

The WebDAV scheduling diagnostic uses real 1 MiB file transfers and records
I/O-pending poll counts and explicit cooperative yields alongside sampled
Linux socket queues. Only transfers selected by the existing phase sampler
wrap the I/O future to count polls. Unsampled transfers retain their original
I/O path, and scheduling quanta, admission, and socket thresholds are
unchanged. This observation must precede any attempt to eliminate redundant
handoffs; neither the diagnostic nor its counters can satisfy normal gates.

The scheduling observation (`37147472978`, `8cdbd46`) retains 125 sampled
1 MiB transfers. Fourteen have both pending I/O polls and explicit yields
(including two with 14 pending polls and 15 explicit yields). Sampled file
send time has median 221 microseconds and p99 16.24 milliseconds, compared
with 2.97 milliseconds p99 for blocking dispatch and 97 microseconds for
file reading. These diagnostic timings locate a tail in the send path but
do not prove a causal relationship between individual handoffs and latency.

A separate trial now counts actual pending I/O polls for every file transfer
and skips the immediately following cooperative handoff when I/O already
returned execution to the runtime. Transfers making uninterrupted progress
still enforce the existing quantum; socket queue limits, file ownership,
errors, and cancellation behavior remain unchanged. Sampled avoided-handoff
counts verify that the trial reaches the intended branch. Real-file tests
and same-runner revision comparisons must establish correctness and benefit
before this trial is accepted as a performance improvement.

Normal independent run `37143289872` on `0b28482` now has complete proxy
results. All three local 1 KiB RSS ratios (1.0183/1.0472/1.0270) meet 1.06,
and all three feature-rich 1 KiB queue-delay ratios
(0.9710/0.9445/0.8921) meet 1.0. The stronger goals remain unmet:
feature-rich throughput ratios are 0.8662/0.8904/0.8999 and CPU-efficiency
ratios 0.9010/0.9301/1.0194; miss throughput is 0.9248/0.8721/1.3922,
CPU efficiency 0.8501/0.7186/0.9327, and queue delay 2.1840/3.1854/2.5068.
Large WebDAV p99 ratios are 1.1167/1.7713/1.8621, with existing CPU-efficiency
acceptance failing in runs 1 and 3. The normal proxy jobs also fail the
existing reverse-proxy queue-delay and 1 MiB CPU-baseline checks. These
results do not constitute CI normalization or final performance acceptance.

Native proxy diagnostic `37147538478` on `8cdbd46` succeeds with zero lost
samples for both real server profiles. Its second miss window contains
4,447 callchain samples, including 626 sampled inside allocator functions
and 128 containing directory validation. Allocator callers include request
preparation, upstream dispatch, and cache-key construction. Directory checks
are therefore not the only cost and must not be removed speculatively.

Cache keys previously allocated three separate shared `OnceLock` owners for
the primary digest and two derived storage keys. A separate trial groups
those locks in one shared owner, removing two allocations per newly created
key and two reference-count updates per clone. Method-group changes still
create fresh derived state; content-digest changes retain the original
primary-key sharing semantics. Public methods, digest inputs, storage-key
formats, and writeback admission are unchanged. Existing cross-thread and
storage-key identity tests verify these invariants; fresh profiles and normal
comparisons must establish the performance effect.

The file-handoff trial `19acf14` is rejected and its product change is
reverted. Same-runner pairs `37148326780`, `37148328724`, and `37148330817`
compare against `8cdbd46`, reversing version order in the middle pair. Large
file CPU-efficiency ratios change from 1.4306/1.3606/1.4003 to
1.1996/1.3733/1.3331, and p99 ratios from 1.6125/1.0956/1.2875 to
1.7308/2.0963/1.5701. Pair 1's current CPU-efficiency spread is 1.1658,
exceeding 1.15, so its measurement quality fails and it cannot establish a
performance comparison. Pairs 2 and 3 pass quality for both versions but
their current p99 ratios worsen; current CPU ratios also miss the existing
1.5 objective. The intrusive scheduling
run `37148332829` confirms the trial avoids up to 12 handoffs per sampled
transfer, but reducing that counter is insufficient evidence of benefit.
The original handoff behavior is restored; all raw trial evidence remains in
Actions artifacts. The independent derived-cache-key trial is retained.

Review of the raw cache path finds that its conditional/directive exclusion
matched only lowercase and conventional title-case header names. The
existing real-server fixture now reproduces a failure with mixed-case
`iF-nOnE-mAtCh` before the fix. Header names are compared case-insensitively,
and the existing exclusion test also exercises mixed-case Range,
Cache-Control, and Pragma. This preserves generic conditional/cache-directive
handling for every legal casing and is a correctness fix, not a relaxation
of feature semantics or performance criteria.

Feature-rich Callgrind run `37149351082` on `92f1cc7` succeeds. Against
`42c4157`, whole-program instructions per completed request decrease in all
three windows from 46,792/46,712/46,886 to 46,219/46,565/46,623. This is a
small instruction reduction; normal throughput and CPU-efficiency goals
remain unproven. The file-handoff trial present in `92f1cc7` is not exercised
by this 1 KiB in-memory cache workload and has since been reverted.

Miss Callgrind run `37149349025` on `92f1cc7` also succeeds. In its second
miss window, `CacheRequestKey::from_parts` calls the allocator once per
constructor (10,054/10,054), compared with three times on `42c4157`
(25,659/8,553). This confirms the intended two-allocation removal independently
of frontend normalization. Whole-program instructions per completed miss
request decrease from 229,389/225,949/231,319 to 228,474/225,230/230,126;
in-window writeback variation still prevents interpreting these totals as a
precise persistence-cost reduction.

The native allocation review also exposes unused cache-miss preparation.
The production listener dispatches generic targets before calling the raw
origin dispatcher, so its prepared raw cache-miss descriptor cannot serve a
production cache miss. It nevertheless serializes an origin head, clones
route/cache policy, prepares an origin, and parses a second header map for
each new eligible request head. That unused descriptor, its unreachable
dispatcher branch, and its private duplicate response-limit helper are now
removed. The raw hot-hit path remains; misses retain the production generic
path with request collapse, revalidation, body limits, and bounded writeback.
The existing real-server differential test now also uses that production
generic path to fill its real disk cache before comparing hot-hit responses.
Fresh profiles must quantify the cleanup's performance effect.

The next allocation experiment shares the already derived primary key from
the raw cache probe with the generic cache lookup on the same worker. The
generic lookup still normalizes the request independently and compares all
four identity components (method group, scheme, authority, path-and-query)
before reuse. The memo contains one key per worker, no cache response or
admission decision; namespace, policy, revalidation, and persistence checks
remain in their existing paths. A different component or a missing authority
cannot reuse it. The generic lookup also borrows the URI path-and-query
instead of allocating a temporary string before creating its shared key.
Profiles and normal measurements must establish whether the saved key
allocation and duplicate digest work outweigh the additional memo ownership.

Feature-rich Callgrind run `37152238504` on cleanup revision `1cd6a36`
succeeds, with 46,635/46,699/46,711 instructions per completed request.
Compared with `92f1cc7` (46,219/46,565/46,623), this provides no evidence
of a feature-rich instruction improvement from the unused miss cleanup.
The new key-sharing experiment passes 1,302 workspace tests across 47
suites and all-feature Clippy. An all-feature local test attempt stops at
linking because of disk exhaustion; it is not counted as a test pass.

Cache-miss Callgrind run `37152892350` on `73ae6f0` confirms removal of
the duplicate constructor: the second miss window falls from 10,136
constructors / 5,028 frontend requests on `1cd6a36` to 8,015 / 7,959.
The earlier profile has two constructor callers (raw probe and generic
lookup); the new profile has only the raw probe caller. Both revisions
allocate once per constructor. Whole-program instructions per completed
miss request change from 227,152/225,808/224,040 to
212,915/213,016/211,798. Background persistence work still varies with
admission and sampling windows, so normal CPU-efficiency and throughput
measurements remain necessary. Feature-rich instructions stay approximately
unchanged (46,573/46,892/46,718); that path does not perform the raw probe.

A real-server/disk-cache fixture now verifies that structured JSON access
logging prevents raw request preparation entirely. The existing destination
trace guard already provides this protection; no additional production
condition is added. The additional regression test passes with all 1,303
workspace tests across 47 suites, all-feature Clippy, and the unchanged
eight-category / sixteen-evaluation performance-gate presence checks.

CI run `37152861672` exposes a shared-ring notification race in coverage:
`body_without_content_length_reaches_handler` receives HTTP 408 for its SHM
body. The producer previously decided whether to signal from the ring's
empty state before copying a frame. A consumer can drain the prior frame
and register its wait during that copy, leaving a newly published frame
without a doorbell signal. A deterministic test stages this ordering in a
real mapped ring with a real named semaphore; the previous publication
logic times out after two seconds, while the corrected logic completes.
Publication now checks the current wait flag, and both data and space
publication/registration/recheck operations share a sequential atomic order
so the waiter observes the published index or the publisher observes the
registered waiter. No timer, retry, ring layout, public API, or setting changes.
The real CGI/SHM IPC regression suite passes in 20 independent processes
(100 test executions), and the workspace passes 1,305 tests across 47 suites.

Normal proxy run `37152861672` on `73ae6f0` still fails required gates.
Local 1 KiB RSS is 1.003055 of nginx and feature-rich 1 KiB queue delay is
0.935621, within their existing limits. Feature-rich throughput/CPU efficiency
remain 0.886464/0.929788. Miss 1 KiB throughput/CPU efficiency are
0.957192/0.846100, with queue delay 2.885400 (above the existing 2.6 limit)
and p99 0.311183. WebDAV 1 MiB p99 is 1.331352 and CPU efficiency is
1.412388 (below the existing 1.5 limit). Reverse-proxy static-baseline CPU
and queue-delay checks also fail. The constructor removal is verified but
does not complete the normal performance objectives; no stronger objective
is enabled or existing limit weakened on the strength of these profiles.

The next miss-path experiment removes the tee relay only for a complete
single-frame in-memory body without trailers, a close signal, or a file
extent, and only when every mirror's size limit accepts the frame. The raw
origin reader already builds such bodies when its response-head buffer
contains the complete Content-Length payload. Instead of two channels and
a relay task, the lossy tee shares the immutable bytes with its mirrors and
returns the original primary body, retaining its transport flags and resource
ownership. Streaming, oversized, trailer-bearing, and file-backed bodies keep
the existing bounded relay and abort/drop accounting. Cache admission and
disk persistence remain unchanged. Native allocation samples include body
channel construction, but Linux profiles and normal measurements must still
quantify this experiment's actual effect. The three resource/limit/trailer
regressions pass with all 1,308 workspace tests across 47 suites, all-feature
Clippy, and the eight-category / sixteen-evaluation gate checks.

The feature-rich state-copy experiment borrows the request in
`ReversePostModuleInput`; only WebDAV, WebSocket, and uncached upstream
dispatch transfer its ownership. Cache hits retain it in the existing parent
allocation instead of moving it through another input and future. Local
ARM64 measurements change the input from 608 to 264 bytes and the dispatcher
future from 5,032 to 4,336 bytes; the request itself stays 352 bytes and cache
preparation stays 3,216 bytes. All 1,308 workspace tests across 47 suites and
all-feature Clippy pass, including real-server authentication, cache,
WebDAV, WebSocket, retry, and mirror scenarios. Linux instruction profiles
and normal throughput/CPU measurements must still establish the effect.
The tee experiment's feature-rich run `37155863069` attempt 1 fails before
measurement because crates.io DNS cannot resolve; its original failure log
is retained and attempt 2 reruns the same revision. No measurement from
attempt 1 is counted as valid.

Completed tee profiles (`37155856786` and `37155863069` attempt 2) remove
the relay task and body-channel calls from the sampled miss path. Total
miss instructions per request are 222,051/223,993/221,410, compared with
212,915/213,016/211,798 before the experiment. Background persistence work
varies, so removal of those calls does not establish an overall improvement.
Feature-rich instructions remain 46,573/46,860/46,814. The subsequent request
borrow profiles (`37156450764`, `37156454915`) report feature-rich
46,026/46,422/46,597 and miss 222,600/225,530/223,899. Only the feature-rich
samples consistently decrease relative to the immediately preceding revision;
normal measurements still decide whether either experiment is retained.

Prepared generic HTTP/1 requests now borrow their existing downstream
combined-log snapshot rather than constructing another request and cloning
its URI and logging headers on every dispatch. Access-log configuration
changes require restart, and the cached preparation validates runtime identity.
A real qpxd process, TCP origin, persistent downstream connection, and log
file verify exactly one record per request, changed request metadata after
reuse, downstream headers before route rewriting, and query-key redaction.
All 1,309 workspace tests across 47 suites and all-feature Clippy pass.

Normal pre-tee run `37155205831` still fails performance gates: local 1 KiB
RSS is 1.013392 and feature-rich queue delay is 0.880215, while feature-rich
throughput is 0.918226. Miss throughput/CPU efficiency are 1.409982/0.995412
and queue delay is 3.072445 (above the existing 2.6 limit). WebDAV 1 MiB CPU
efficiency is 1.465196 (below 1.5) and p99 is 2.685720. Coverage passes after
the shared-ring notification fix, but these results do not satisfy the final
performance objectives or the three-independent-run requirement.

Native miss samples attribute 52 allocator samples to
`RawHttp1ConnectionCache::store_prepared_request`. Callgrind round 2 records
8,712 direct malloc calls from that function for 4,315 completed miss requests
on `84efde0`: both the prepared request and serialized header are allocated
on each replacement. The connection now reuses its existing prepared-request
box, and copies a changed header into its existing box only when its length
is identical. Different lengths replace the header box, preserving exact
storage size rather than retaining spare capacity. The mutable cache borrow
excludes readers during replacement, and runtime-generation validation is
unchanged. The real downstream-log test changes URI and logging headers to
different values of equal length and checks that all metadata updates.
All 1,309 workspace tests across 47 suites, all-feature Clippy, formatting,
and the eight-category / sixteen-evaluation gate checks pass. Linux profiles
must still quantify allocation removal and normal performance effects.

The existing same-runner WebDAV revision harness is generalized as
`scripts/perf-diagnose-origin-cache-revision.sh`. The diagnostic workflow's
`cache-revision` workload compares 1 KiB persistent hits, persistent misses,
and feature-rich hits for two exact revisions on the same runner. Both
release binaries are built before any measurement; version order is explicit,
and each version retains three alternating qpx/reference samples. Manifests
record commits, binary hashes, required lanes, and sample counts. Both versions
must pass measurement-quality checks, while the current version also checks
existing acceptance and the stronger throughput/CPU/queue goals without
weakening stricter existing limits. Logs and results remain diagnostic artifacts
and do not replace any of the eight required CI categories. The real normal
`fa473e2` data passes the generated quality objectives and fails the stronger
goals as expected; shell syntax and repository structure checks pass.

Normal tee run `37155826620` reports miss throughput/CPU efficiency
0.925525/0.833296 and queue delay 2.486278, within the old 2.6 queue limit
but outside the stronger goals. Feature-rich throughput/CPU efficiency are
0.874028/0.907004. WebDAV 1 MiB p99 is 0.876709, while CPU efficiency is
1.359520, still below its existing 1.5 limit. These separate-runner results
cannot establish a causal effect of the tee change; paired revision measurements
are necessary before retaining or rejecting the experiment.

The completed prepared-storage miss profile (`37157765844`) records
273 direct malloc calls from `store_prepared_request` in each measured window:
0.057/0.064/0.063 calls per completed request, compared with 2.019 in the
preceding round-2 profile. Total miss instructions stay approximately unchanged
(223,230/225,761/225,230), and feature-rich instructions are
46,171/46,127/46,166. Allocation removal is verified; the normal throughput,
CPU-efficiency, and queue objectives still require paired measurements.

Native feature-rich samples attribute memory copies to the general request
state machine. Local ARM64 layout measurements identify a 2,568-byte guarded
body-buffering future that is constructed even when buffering is unnecessary.
Guard preparation now returns the synchronous streaming-limit result as a
ready future, allocating the buffering future only when observation actually
consumes the request body. Guard checks, observed-body reuse, size limits,
read deadlines, and error responses keep their existing behavior. Its common
future shrinks to 240 bytes; cache/dispatch futures remain 3,216/4,336 bytes.
All 1,309 workspace tests across 47 suites pass. The added 512-byte layout
budget passes separately, as do final all-feature Clippy, formatting, structure,
and the unchanged eight-category / sixteen-evaluation gate checks. Linux
profiles and normal measurements remain necessary before adopting this trial.

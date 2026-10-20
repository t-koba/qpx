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

The standalone HTTP/1 comparison writes
`target/perf/perf-audit-proxy-compare.jsonl` with `direct-backend`, `qpxd`, nginx,
Apache, and lighttpd rows. It interleaves implementations across three rounds.
Every timed sample must be functionally valid. Each metric aggregates
independently: lower medians for throughput and CPU efficiency, upper medians
for latency, and maxima for error and memory counters. This prevents a fast
request-rate sample from carrying unrelated latency or CPU values into a result.
`scripts/compare-proxy-baseline.sh` reports throughput, CPU efficiency, p99,
multi-axis dominance, and historical absolute/normalized qpx comparisons.

Competitive targets remain in `perf/proxy-performance-objectives.json`: the
lanes aim for at least 15% more throughput and CPU efficiency than the strongest
external result per axis, at least 5% lower p99, and dominance of at least 1.1.
Existing spread caps are unchanged: 1.10 for throughput/CPU and 1.25 for p99.
Over-cap spread by qpx makes the lane `INCONCLUSIVE` without remeasurement;
candidate variance can itself signal a regression. When the candidate spread is
within cap, over-cap spread by the direct backend **or any external reference**
is `RETRYABLE_INVALID` and may trigger a bounded remeasurement. Candidate-side
inconclusive status takes precedence if both candidate and reference spreads
exceed their caps. Neither status is a pass or a scored regression. Direct-backend
efficiency/headroom remains a diagnostic, not a proxy ceiling. RSS compares qpx
to nginx's same-class resident footprint while the other resource axes retain
best-of-breed external references.

These are competitive objectives, not a shared-runner regression oracle. The
required current-versus-pinned-release pair, bounded validity retries, fixed
per-metric regression tolerances and controlled-hardware opt-in are described
under **Shared-runner validity and paired-regression contract** below. The old
spread-derived allowance and global run-to-run noise floor are removed from
these checkers: spread establishes validity and cannot widen a pass allowance.

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
filesystem pool at 128 threads, independently of async I/O. The pool remains
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

`scripts/check-origin-cache-performance.sh` reports every declared competitive
lane in `perf/origin-cache-performance-objectives.json`. The objectives retain
throughput, CPU-efficiency, p99, dominance, RSS and FD targets; the shared-runner
policy below determines which measurements can decide CI. The workload and role
topology in the objectives are mandatory in both the competitive measurement and
the current-versus-release pair. Connect, write, timeout, non-2xx and body-length
errors must be zero. `wrk` read errors at the sampling boundary retain their
recorded 1000 ppm ceiling and exact failed-request accounting. No failed sample
is discarded or replaced by a later functional success.

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
`scripts/check-http2-performance.sh` reports the four competitive lanes in
`perf/http2-performance-objectives.json`, including the 1.5 aggregate dominance
objective. Existing throughput/CPU spread caps and all competitive objectives
are unchanged. HTTP/2 now also records p99 spread, with a 1.25 cap for each
implementation; the HTTP/1 origin/cache lanes use the same p99 cap. A spread
breach by **any** required implementation leaves that measurement invalid; it
is never scored as passed or regressed.
The qpx HTTP/2 server runs streams
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

### Matched-source comparison for the reverse HTTP/1 path

The streaming lane reports one ratio per run, so comparing the ratio of one
run with the ratio of another run compares two noisy statistics, not two
implementations. Two qpxd builds measured against the same origin in the same
round, alternating which build is measured first, isolate the build
difference from runner and origin load. The paired policy lanes already work
this way: `scripts/perf-audit-policy.py` measures the current build and the
pinned previous release against one origin, alternating the order within each
round and publishing the per-round deltas.

Applied to the reverse HTTP/1 path, the last green streaming run `5ecb4d1` was
compared with the current tree over 30 rounds of the streaming lane's own
workload, using that lane's own backend, client and qpxd configuration:

- The paired current-minus-green difference in the qpx-versus-origin ratio
  has median `-0.020` with a bootstrap 95% interval of `-0.099` to `+0.025`.
  The step seen across CI runs was `+0.39`, from `1.03x` to `1.42x`, which
  lies far outside that interval.
- Bootstrapping the lane's own median-of-three statistic from the same
  measurements gives a 2.5th percentile of `0.957` and a 97.5th percentile of
  `1.798`. A single run's median-of-three lands at or below `1.03` about 12%
  of the time and at or above `1.42` about 38% of the time, so one run's value
  cannot by itself establish a change.
- In the 1 MiB reverse lane, the current build's requests per CPU second
  exceed the green build's by a median of `+41.6`, with a bootstrap 95%
  interval of `+23.1` to `+109.4`. The ratio seen across CI runs fell from
  `6.73` to `3.48`, which this measurement does not reproduce.

The reverse HTTP/1 path therefore shows no regression between the two
builds.

These figures come from a one-off measurement of that pair of builds, and
the repository does not yet ship a harness that reproduces them: the bootstrap
interval and the median-of-three quantiles above were computed from the
recorded per-round samples, and the paired policy lanes report per-round
deltas rather than a bootstrap interval. Until such a harness exists, treat
these numbers as the record of that measurement rather than as a result the
product's tooling regenerates. The conclusion does not depend on the tooling:
a question about whether one build regressed against another is answered by
measuring both against one origin in the same round, as the paired policy
lanes do, and not by comparing ratios taken from separate runs.

### Shared-runner validity and paired-regression contract

The proxy and HTTP/2 CI jobs use `scripts/perf-audit-policy.py run`, not a
competitive objective as a regression oracle. Their JSON objectives declare
`ci_policy`; all three files must agree. The required previous-release reference
is **v0.4.2**, pinned to `d67a148e7ccbbd272750415213601005af0f38c5`.
CI checks out that exact revision and builds both binaries in the same job using
one Rust toolchain, `--release --locked --features http3-backend-qpx` and identical
`RUSTFLAGS`. Separate target directories prevent accidental binary reuse.
Each pair records the current and previous source SHA, executable SHA-256,
`rustc -Vv`, runner/job identity and sampling order. Missing binaries or a
mismatched release pin are errors, not unmeasured performance.

For every pair-compatible workload, the pair reuses the existing sampler,
config, workers, client and functional probes. Pair compatibility defaults to
applicable. The four exceptions are declared per lane in
`perf/origin-cache-performance-objectives.json` via `pair_compatibility`, with
`applicable: false`, the exact `previous_sha` and an explanatory `reason`:

- WebDAV, 1KB and 1MB: v0.4.2 cannot express the top-level `origins` config.
- Feature-rich cache hit, 1KB and 1MB: v0.4.2 cannot express `http.forwarded`.

Only those qpx-vs-qpx pairs produce `NOT_APPLICABLE`, without sampling. Their
competitive functional probes, workloads and objective measurements still run
unchanged. A stale compatibility SHA is an error when the pin changes, not an
automatic exemption for a new pin. Summaries retain every declared assessment,
list skipped pairs in `coverage.not_applicable`, and include the pin and reason
in each result; `coverage.required` excludes these non-expressible pairs.

The shared HTTP/2 config omits `runtime.upstream_max_idle_connections_per_origin`
because v0.4.2 does not support it; neither binary gets a role-specific config.
Qpx cache probes recognize both RFC `Cache-Status` and v0.4.2's `X-Qpx-Cache`,
while still requiring the actual HIT/MISS result, status and body validation.
Same-role samples (including origin-local) are checked for internal workload and
worker consistency before aggregation, separately from competitive equivalence.

Three rounds measure current/previous,
previous/current, then current/previous. Startup and warmup are outside the timed
workload; restarting both implementations gives each sample the same initial
state. Per-round current/previous ratios are recorded, and their median is
gated **separately for each metric**:

| Metric | Valid-pair regression tolerance |
| --- | --- |
| Requests per second | current/previous must be at least **0.95** (at most 5% loss) |
| Requests per CPU second | current/previous must be at least **0.95** (at most 5% efficiency loss) |
| p99 response latency | current/previous must be at most **1.10** (at most 10% increase) |

HTTP/2 CPU includes the proxy and backend; HTTP/1 retains its process-tree CPU
measurement. These fixed tolerances are explicit CI policy, **not** a spread
band: no observed spread, queue delay, dominance average, historical baseline or
competitor advantage changes them. In particular, a throughput gain cannot
cancel a p99 regression. Both qpx identities use the existing **qpx** spread
caps, never the more permissive external-reference cap. Paired spread uses the
full max/min of the three samples, not a best subset or a blend of attempts.

Evaluation validates schema, request/error accounting, responses, resources,
workload equivalence and identities **before** checking spread or performance.
Candidate qpx functional failures, malformed candidate measurements, and
candidate-side startup/tool or wrong-body/cache-result failures produce `ERROR`
and exit **1**, immediately and without retries. An invalid pinned-release sample
or measurement makes its paired lane `INCONCLUSIVE`/unmeasured, retaining the
reason and logs; it is not retried because re-running the whole pair could hide
candidate instability. A pinned-binary identity/configuration error remains a
hard `ERROR`. An over-cap spread on the current qpx candidate also produces
`INCONCLUSIVE` immediately and is not remeasured; it can never be hidden by a
later attractive sample. A reference-only over-cap spread produces
`RETRYABLE_INVALID`. A parsed **competitive reference-side transient invalid
sample** can request a retry via sampler exit **75**:

- HTTP/2: parsed invalid-request/error or non-2xx accounting from nginx or the
  direct control backend, after counters, timings and latency rows are parsed.
  Other invalid reference data leaves the lane `INCONCLUSIVE`; candidate qpx
  errors remain `ERROR`.
- HTTP/1 proxy/origin/cache: a reference read-error overrun, only with otherwise
  clean request accounting, status probes, response lengths and cache results.
  The existing **1000ppm** default read-error ceiling is unchanged. Other
  invalid reference data leaves the lane `INCONCLUSIVE`; candidate qpx errors
  remain `ERROR`.

The driver maps competitive sampler exit 75 to `RETRYABLE_INVALID`. Candidate
qpx sampler failures are `ERROR`; a competitive sampler failure with a valid
candidate record but missing/invalid reference lanes is `INCONCLUSIVE`. An
invalid pinned previous-release sample is also `INCONCLUSIVE`, never a retry
request. No spread caps, paired regression floors or functional error
tolerances are widened. After `RETRYABLE_INVALID`, the driver re-measures the
**whole relevant pair or competitive lane group**, with at most **two additional
attempts** (three total). Candidate-side spread and non-transient pinned-reference
failures are terminal and do not start another measurement. The driver accepts
the first valid attempt, even if that attempt regresses, and never retries a
valid regression or selects the best attempt.
Other already-valid lanes are not re-measured. All raw samples, logs,
measurements and results from every attempt remain under
`target/perf/{proxy,http2}-policy/` and are uploaded with `if: always()`.

At exhaustion, or when a paired reference sample is invalid, the lane is
`INCONCLUSIVE`/unmeasured with explicit required/valid/unmeasured coverage. The
summary remains visibly `INCONCLUSIVE`, but the shared-runner job exits **0**:
there is no measured qpx regression to report. This is neither a measured pass
nor a qpx regression. In short: lane unmeasured — reported visibly, not failed.
A valid paired regression or candidate `ERROR` remains
exit **1**, even when another lane is inconclusive. Controlled competitive
objective misses remain blocking. `NOT_APPLICABLE` is explicit coverage
exclusion, not a passing measurement. A report is `COMPLETE` only when every
required lane is measured; an inconclusive report can still be non-blocking.

Competitive dominance (including WebDAV), nginx/apache/lighttpd comparisons,
and historical absolute and normalized qpx baselines remain visible as JSON
artifacts/trends. `QPX_PERF_ASSESSMENT=shared` is the documented default and is
explicit in these CI jobs; competitive objective misses are `REPORT_ONLY`, and
incomplete competitive lanes remain `INCONCLUSIVE` without blocking the job.
Candidate functional or measurement-invalid errors still block. A separately
configured **controlled-hardware** assessment may set
`QPX_PERF_ASSESSMENT=controlled` to gate the unchanged competitive targets and
historical thresholds, without noise allowances or retries of valid misses.
Do not enable that mode on an ordinary shared runner. Scheduler queue-delay
ratios are diagnostics only in **both** modes and never affect the exit decision.
The standalone checkers inspect competitive JSONL and preserve missing or
invalid reference lanes as `INCONCLUSIVE` in their JSON output; shared assessment
returns success for these non-findings. They do not assert that the paired
regression gate ran. Exit 75 is an internal sampler signal for retryable
competitive-reference invalidity. Existing streaming and netem checks are
separate assessments, unchanged by this policy.

Run the synthetic policy and sampler fixtures (no full benches or network).
They exercise real shell sampler functions with deterministic tool output,
retry bounds, compatibility exclusions and origin pairing. The generated wrk
Lua cache probe is also executed when the LuaJIT library (provided by `wrk` on
CI runners) is installed; otherwise that one test is reported as skipped:

```bash
python3 scripts/test-perf-policy.py
```

It covers equal pairs with competitive/queue-delay misses, each independent
metric regression, terminal candidate-side spread invalidity, retryable
reference-side spread invalidity followed by equal/regressed/exhausted outcomes,
regression plus an inconclusive lane, missing/corrupt/schema/wrong-response
errors, interleaved order, and the public checker entrypoints. It retains all
fixture attempts and coverage summaries in `target/perf/policy-fixtures/`.
To run the actual pair assessment after building the two binaries as above:

```bash
python3 scripts/perf-audit-policy.py run proxy target/perf/proxy-policy \
  --previous-bin "$QPX_PREVIOUS_BIN" \
  --previous-sha d67a148e7ccbbd272750415213601005af0f38c5
python3 scripts/perf-audit-policy.py run http2 target/perf/http2-policy \
  --previous-bin "$QPX_PREVIOUS_BIN" \
  --previous-sha d67a148e7ccbbd272750415213601005af0f38c5
```

Output directories must be new, so a run cannot overwrite earlier attempts.

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
cannot invalidate an otherwise stable competitive comparison. qpx's own p99
gap, scheduler queue-delay and CPU-rate sample spreads must also stay within
the tracked stability cap: a wider spread makes those metrics unjudgeable
rather than merely noisy, and the run fails as invalid.

`scripts/check-streaming-performance.sh` enforces the tracked objectives in
`perf/streaming-performance-objectives.json`. For a fast reader, qpx must:

- exceed the fastest external proxy's throughput by at least 10%;
- retain at least 35% of direct-backend throughput;
- exceed the throughput leader's total-system CPU efficiency by at least 25%;
- keep first-byte latency within 1.1x of the leader and bound p99
  inter-observation gaps to 3.2x and maximum gaps to 250x;
- exceed the multi-axis dominance score by at least 25%.

For a slow reader, total time, first byte, p99 gap, and maximum gap are bounded
relative to the direct backend. This independently detects lost backpressure or
event-loop starvation even when bulk throughput remains high.

Every objective is judged against a measurement band. The tail objectives (p99
chunk gap and scheduler queue delay) use the spread of their own metric, because
a tail statistic moves further between samples than a total does. The
remaining objectives - the time, CPU-rate, first-byte, max-gap, dominance and
resource-peak ones - use the lane's observed total-time and CPU-rate sample
spread, because the benchmark publishes no per-sample spread for the metrics
they measure. A miss inside that band is reported as a marginal objective and
stays visible for trend review; a miss beyond it is a decisive failure.
Reference spreads never widen the band, because competitor instability must not
excuse a qpx miss.

Every band is bounded by a named policy multiplier, so an objective's
effective limit stays within a bounded factor of its documented cap: the
time and CPU-rate objectives use `stability.max_lane_noise_multiplier` (1.25),
and the tail objectives use `stability.max_tail_noise_multiplier` (1.5), which
is wider because a tail statistic moves further between samples than a total
does. The bound matters because the band comes from the subject's own
measurement: without it, a subject whose regression also inflates its
measurement noise would widen the band far enough to excuse the miss it
caused, and the effective limit would be data-dependent rather than the
documented cap. The band also has a floor, `stability.min_measurement_noise_multiplier`
(1.05). A shared CI runner varies more between runs than one interleaved
lane spread shows, so a perfectly stable measurement can still miss a cap by
a few percent for no product reason; that miss is reported as marginal
rather than failing the gate. The floor is the band's lower bound and the
multiplier its upper bound, and the multiplier wins if the two are ever
configured inconsistently.

The band is a multiplicative slack, so the direction of the objective decides
how it moves the effective limit. For a maximum-direction objective the
effective limit is the cap times the band, so a band of 1.25 makes the cap
1.25 times stricter. For a minimum-direction objective the cap is divided by
the band, so the same band makes the cap 1.25 times stricter in the other
direction: with the lane band at its maximum of 1.25, the fast throughput
objective's cap of 1.1 has a decisive bar of 1.1 / 1.25 = 0.88. Within the
bound the measured spread still sets the band, so the same miss on a stable
measurement is still reported against the cap.
`scripts/test-streaming-performance.py` exercises both sides of both bounds
against synthetic lanes so the noise model is checked without running the
benchmark.

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

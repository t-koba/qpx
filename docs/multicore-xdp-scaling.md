# Multicore and XDP scaling guide

This document focuses on practical scale-out settings for `qpxd` on multi-core hosts.

## What `qpxd` now does internally

1. Runtime tuning from config (`runtime.*`)
   - `worker_threads`: Tokio worker thread count.
   - `max_blocking_threads`: Tokio blocking pool upper bound.
   - `acceptor_tasks_per_listener`: number of TCP acceptor sockets per listener.
   - `reuse_port`: enables `SO_REUSEPORT` fan-out on supported platforms.
   - `tcp_backlog`: listen backlog.

2. Listener fan-out with `SO_REUSEPORT`
   - forward/reverse/transparent listeners now bind multiple sockets when configured.
   - each socket has its own async accept loop.
   - this reduces lock contention around a single accept path and improves multicore scaling.

3. Matcher hot path allocation control
   - rule and reverse prefilter matching now reuses thread-local bitset buffers.
   - prefilter candidate traversal is bit-iteration based and avoids per-request candidate vector allocation.

## XDP and metadata scope

`qpxd` currently integrates with XDP/L4 frontends by consuming PROXY metadata (`xdp.metadata_mode: proxy-v1` or `proxy-v2`).

- source/destination context can be injected by an external L4/XDP layer.
- rule engine then uses that metadata for `src_ip` and transparent-destination matching.
- security defaults:
  - `xdp.require_metadata` defaults to `true` when XDP metadata mode is enabled.
  - `xdp.trusted_peers` is required and metadata is accepted only from those CIDRs.

This is not AF_XDP userspace packet processing inside `qpxd` itself.

## Linux IRQ/RSS checklist (required for high pps)

`qpxd` can only scale as far as NIC queue/IRQ distribution is healthy. For Linux production:

1. Enable multi-queue and confirm queue count
   ```bash
   ethtool -l <iface>
   ethtool -L <iface> combined <N>
   ```

2. Keep RSS hash on L3/L4 tuples
   ```bash
   ethtool -n <iface> rx-flow-hash tcp4
   ethtool -n <iface> rx-flow-hash tcp6
   ```

3. Pin NIC queue IRQs across CPUs (or NUMA-local CPU set)
   ```bash
   grep <iface> /proc/interrupts
   # then set smp_affinity for each IRQ in round-robin/NUMA-local policy
   # helper:
   ./scripts/irq-affinity-plan.sh --iface <iface> --cpus 0-15
   # apply:
   sudo ./scripts/irq-affinity-plan.sh --iface <iface> --cpus 0-15 --apply
   ```

4. Validate queue/IRQ spread under load
   ```bash
   watch -n1 'grep <iface> /proc/interrupts'
   ```

5. Keep process CPU placement aligned with IRQ policy
   - pin `qpxd` to the same CPU set/NUMA node used by NIC RX/TX queues.
   - avoid cross-NUMA memory traffic for high-throughput proxies.

## Suggested baseline runtime settings

```yaml
runtime:
  worker_threads: 16
  max_blocking_threads: 512
  acceptor_tasks_per_listener: 16
  reuse_port: true
  tcp_backlog: 8192
```

Use `config/usecases/08-performance-and-xdp/runtime-multicore-scaling.yaml` as a starting point.

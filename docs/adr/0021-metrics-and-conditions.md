# ADR 0021: Metrics per machine, host conditions, and what a host does under pressure

Date: 2026-10-21 · Status: accepted

## Context

Kubernetes gives an operator per-pod series (cAdvisor through the kubelet's `/metrics`), pod state series (kube-state-metrics), `kubectl top`, node conditions that keep the scheduler off a node under pressure, image garbage collection when the disk runs low, and log rotation by size (`KUBERNETES-MAP.md`, Observability, Scheduling and nodes, Configuration and images). briqyard had host-level `/metrics`, a per-machine `stats` that probes the cgroup and ZFS on each call, a pool that fills until every machine stops, images removed only by age, and a console rotated only at a cold boot.

## Decisions

**Per-machine series on `/metrics`, from the tick's last measure.** The tick (15 s) already reads every machine's cgroup, the pool's datasets and the internet counters for usage (ADR 0017); the meter now keeps those readings, and a scrape formats them: no probe per scrape, so its cost does not grow with how often Prometheus asks. Labels: `machine`, `tenant`, `name`, and `role="gateway"` on a tenant's gateway.

| Series | Type | From |
|---|---|---|
| `briqyard_machine_cpu_seconds_total` | counter | the cgroup's `cpu.stat`, what it grew by each tick |
| `briqyard_machine_memory_bytes` | gauge | the cgroup's `memory.current` (guest memory touched plus Firecracker's) |
| `briqyard_machine_memory_limit_bytes` | gauge | its size; the cgroup allows 256 MB more for Firecracker |
| `briqyard_machine_disk_used_bytes` | gauge | its datasets, their snapshots and its memory snapshot |
| `briqyard_machine_internet_{in,out}_bytes_total` | counter | the NAT counters |
| `briqyard_machine_ingress_{in,out}_bytes_total` | counter | the ingress proxy |
| `briqyard_machine_egress_dropped_packets_total` | counter | the drop counters (ADR 0018) |
| `briqyard_machine_restarts_total` | counter | restarts by its policy |
| `briqyard_machine_state{state}` | gauge, 1 | one series per machine, its state now |
| `briqyard_machine_boot_seconds` | gauge | `starting` to `running`, its last start (a resume included) |

Counters start at zero with the daemon, as the usage counters do; Prometheus reads a smaller value as a reset. The state is one series per machine, not one per state with zeros (kube-state-metrics' shape): `count by (state)` is the same answer with a seventh of the series. Host series: `briqyard_pool_bytes{kind="size|used|free"}`, `briqyard_host_condition{condition}`, `briqyard_events_total{type,reason}`; the existing names stay.

**Two host conditions, as Kubernetes's node conditions: `memory_pressure` and `disk_pressure`.** `memory_pressure` is committed memory (what running machines reserved) over `conditions.memory_pct` (95) of capacity; `disk_pressure` is the pool's free space under `conditions.disk_free_pct` (10) of its size. No `pid_pressure`: a machine's processes are in its own kernel. Computed by the tick, after the measure; `{type, status, since, message}` in `/v1/status` and the heartbeat; `since` is when the status last changed, the message says the figures now. A change is an event, `host_condition`: a warning when it turns true, normal when it clears.

**The fleet places no new tenant on a host with a condition true, and refuses its tenants' creates there.** A new tenant goes to another host; a pinned tenant's create (a fork, its gateway) answers 503 `capacity` with the condition's message, which the provider already retries. The autoscaler counts no free memory on such a host. The daemon itself admits what it is asked: a start or a create still fits by memory, and refusing at the host would refuse the operator's own repair.

**Under disk pressure the tick removes unused images, oldest first, until the pool is back over the threshold.** Unused: no dataset clones it and no record names it. ZFS frees a destroyed dataset's blocks in the background, so `available` lags: the tick counts each removal's `used` as freed instead of reading the pool again, and stops once the free space plus what it freed is over the threshold. The `image_keep_days` rule stays. Every image removal is an event, `image_removed`, with `reason` in `data`: `disk_pressure`, `unused` (the age rule) or `request`.

**The console rotates by size while the machine runs.** Past `console_max_mb` (64), the daemon's writer renames `console.log` to `console.<start>.log` and reopens it, under the lock both stamp tasks write through: no line is lost and the machine does not notice. One previous file is kept, named after the offset it starts at in the whole console: a `/logs` cursor is that offset, so a page reads across both files, and a cursor rotated away twice reads on from the oldest line kept. A daemon-wide lock orders a rotation against a reader finding the files; a rotation takes a rename, an unlink and an open. The rotation at a cold boot is gone: the writer rotates at open when the file is already past the size.

**`briqyard top` reads `GET /v1/top`, which the daemon answers from the tick's last two measures.** CPU percent, memory, disk, and internet and ingress bytes per second over that window (15 s, `window_sec`), per running machine. The alternative, two reads of every machine's stats a second apart from the CLI, is 2N requests and a wait, has no network counters, and through the fleet a fan-out of fan-outs. With `tenant`, the fleet forwards to the tenant's host; without, it asks every host and fails whole, as listings do (ADR 0006).

## Consequences

- A machine's console takes at most twice `console_max_mb` on the run dir: 25 GB for 200 machines at the default. Lines rotated away twice are gone, as in Kubernetes.
- Series are as fresh as the last tick (15 s, Prometheus's usual interval). A machine started since the last tick has no CPU or memory yet; `top`'s rates need two ticks.
- Per-machine series grow with machines: 12 series each, 2,400 for 200 machines. A Prometheus that does not want them drops them by name.
- A create between its image's resolution and its clone can lose the image to a removal; it fails, and a retry pulls again. The age rule had the same window; pressure makes it likelier on a full host, which the fleet no longer places on.
- Not built: eviction under pressure (stopping machines to free memory or disk), thresholds per host from the fleet, a `ready` condition (probes).

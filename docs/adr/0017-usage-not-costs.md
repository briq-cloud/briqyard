# ADR 0017: briqyard reports usage, never costs

Date: 2026-10-20 · Status: accepted; amended with the implementation the same day (marked *Built*), by ADR 0018 (`egress_dropped_packets`), and by ADR 0023 (a destroyed machine's backups)

## Context

A runtime on rented servers has no per-machine list price: a server is a fixed monthly price, object storage is per GB-month, egress is mostly included. briqyard reports what it can measure; turning usage into prices is the control plane's job, with its own model.

## Decisions

**Usage is measured per machine, in hourly buckets, with no price anywhere in briqyard.** A bucket is one machine and one UTC hour:

| Group | Fields | Source |
|---|---|---|
| Identity | `hour`, `machine_id`, `tenant`, `role` (`gateway` or none), `metadata` (the briq id), `size` (vCPUs, memory MB) | the record |
| Compute | `running_seconds`, `suspended_seconds`, `cpu_seconds` (CPU time used), `memory_mb_seconds` (`size.memory_mb` × running seconds: what is reserved) | the state, the cgroup's `cpu.stat` |
| Disk | `root_gb_hours`, `volume_gb_hours` (allocated size × hours), `disk_used_gb_hours` (bytes the datasets take), `snapshot_gb_hours` (local snapshots, memory snapshots included) | ZFS |
| Object storage | `backup_gb_hours` (bytes of the machine's backups in the store) | the backup records |
| Network | `internet_out_bytes`, `internet_in_bytes` (through the host's NAT), `ingress_out_bytes`, `ingress_in_bytes` (through the host's endpoints); `egress_dropped_packets` (what its egress limits dropped, ADR 0018) | per-machine counters in nftables, the ingress proxy's byte counts |

Intra-tenant traffic is not counted: it is bridged, never routed, and costs nothing on one host.

**Measured by the daemon's tick, kept on the host.** The tick (every 15 s) adds what each machine used since the last tick to the open hour's bucket; a counter that went backwards (a restart) adds what it reads. Buckets are written to the store once a minute and when the hour closes; a crash loses at most a minute. A closed hour never changes. Closed hours are kept `usage_keep_days` (90).

**Read through the API, whole or not at all.** `GET /v1/usage?from=<hour>&to=<hour>[&tenant=]` answers the buckets in the range, each with `closed: true|false`. The fleet asks every host and fails when one does not answer, as listings do (ADR 0006): a usage report missing a host undercounts.

**A machine destroyed in an hour keeps its bucket** to the end of retention: the hour it ran stays counted.

*Built:* running is `starting` to `stopping` (the process holds its memory), suspended is `stopped` with a snapshot; time is accrued at every state change, so a stop between ticks is exact. The bucket is one flat JSON object: the field names carry their group and unit. Backups are counted from the machine record's `backup_bytes`, added at each backup, not by reading the store every tick. CPU and network land in the hour of the tick that reads them. A counter that goes backwards adds what it reads, except the first CPU reading after a daemon start, which is the base (an adopted machine's earlier CPU is not this daemon's); the internet counters start at zero with the table at every daemon start. Ingress bytes are added as they pass, not when the connection ends: a long connection lands in the hours it ran, and one cut short still counts. While the daemon is down nothing is measured; a crash loses that time and at most the last minute. The destroy measures the machine a last time, then removes its counters; counters that cannot be removed keep the destroy from finishing, since the address would come back with the old count.

## Consequences

- A control plane collects the closed hours it has not collected yet, idempotently, and applies its own model to them.
- The host's own overhead (the daemon, unused capacity) is not a machine: a control plane derives it as the host's capacity minus what machines used.
- *Built:* a destroyed machine's backups stay in the store, and no bucket reports them after its last hour; and a host released by `retire` takes its stored hours with it. A control plane collects before both, or a later change reports them.
- *Amended by ADR 0023:* a destroyed machine's backups go on in its own buckets (`backup_gb_hours` only) until they are deleted.

# ADR 0017: briqyard reports usage, never costs

Date: 2026-10-20 · Status: accepted (Sylvain, 2026-10-20); amended with the implementation the same day (marked *Built*), and by ADR 0018 (`egress_dropped_packets`)

## Context

On Fly, briq prices its own infrastructure from Fly's list prices and inventory. On briqyard there is no list price: we pay a fixed monthly price per server, object storage per GB-month, and egress mostly included. Sylvain: briqyard reports usage; briq turns it into costs and billing. The cost model lives in briq.

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

**Read through the API, whole or not at all.** `GET /v1/usage?from=<hour>&to=<hour>[&tenant=]` answers the buckets in the range, each with `closed: true|false`. The fleet asks every host and fails when one does not answer, as listings do (ADR 0006): a usage report missing a host is a bill missing a host.

**A machine destroyed in an hour keeps its bucket** to the end of retention: briq bills the hour it ran.

*Built:* running is `starting` to `stopping` (the process holds its memory), suspended is `stopped` with a snapshot; time is accrued at every state change, so a stop between ticks is exact. The bucket is one flat JSON object: the field names carry their group and unit. Backups are counted from the machine record's `backup_bytes`, added at each backup, not by reading the store every tick. CPU and network land in the hour of the tick that reads them. A counter that goes backwards adds what it reads, except the first CPU reading after a daemon start, which is the base (an adopted machine's earlier CPU is not this daemon's); the internet counters start at zero with the table at every daemon start. Ingress bytes are added as they pass, not when the connection ends: a long connection lands in the hours it ran, and one cut short still counts. While the daemon is down nothing is measured; a crash loses that time and at most the last minute. The destroy measures the machine a last time, then removes its counters; counters that cannot be removed keep the destroy from finishing, since the address would come back with the old count.

## Consequences

- briq collects closed hours it has not collected yet, idempotently, and prices them with its own model (server price × share, object storage price, egress over an allowance). The Costs page and billing read briq's tables, not briqyard.
- briq's metering of running time stays the source of what a customer is billed until the two are reconciled; the usage feed is what makes disk, storage and network billable later.
- The host's own overhead (the daemon, unused capacity) is not a machine: briq derives it as the server's price minus what machines used.
- *Built:* a destroyed machine's backups stay in the store, and no bucket reports them after its last hour; and a host released by `retire` takes its stored hours with it. briq collects before both, or a later change reports them.

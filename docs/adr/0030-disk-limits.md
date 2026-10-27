# ADR 0030: Disk limits per machine, by Firecracker's rate limiter; CPU shared by size

Date: 2026-10-21 · Status: accepted; amends ADR 0021 (three more per-machine series)

## Context

Sandboxes run untrusted code, and every machine of a host writes to the same NVMe pool. ADR 0018 limits a machine's network; its disk had no limit, so one machine running `fio` or a runaway build could take the pool's whole bandwidth and every neighbour's database waits behind it. Kubernetes has no pod field for block IO: a node operator sets cgroup v2 `io.max` by hand, or a CSI driver offers QoS. Rented microVM volumes are commonly capped by machine size: 4,000 IOPS and 16 MiB/s on a one-vCPU shared size, up to 32,000 IOPS and 128 MiB/s on a 16-vCPU dedicated one.

Firecracker has a rate limiter on each drive: a token bucket for bytes and one for requests, each with a one-time burst, set in the drive's config and changed on a running VM by `PATCH /drives/{id}` (v1.17). A bucket of size 0 is no limit. Requests over a bucket wait in the virtio queue; nothing fails.

## Decisions

**`disk_limits` on create and PATCH, applied to each disk the guest writes: the root disk and the volume.** The config drive (read-only, a few KB) has none.

| Field | Meaning | Host default (`disk_limits`) |
|---|---|---|
| `bandwidth_mb` | MB (2^20 bytes) a second, reads and writes together; 0: none; at most 100000 | `bandwidth_mb_per_vcpu`: 32 |
| `iops` | requests a second (reads, writes, flushes); 0: none; at most 10,000,000 | `iops_per_vcpu`: 4000 |
| `burst_sec` | what each limit lets through at full speed once, in seconds at its rate; at most 3600 | `burst_sec`: 10 |

As ADR 0018: a machine's own value overrides the host's, per field, and is absolute; PATCH changes the fields it names; the view shows the values in force. The CLI: `machine run --disk-bw --disk-iops --disk-burst`, `machine set-disk-limits`, a `DISK` column, a `describe` line.

**The host's default is a rate per vCPU of the machine's size.** A machine's share of the host is its size: memory reserved, CPU capped at its vCPUs. The disk follows the same share, so a 4-vCPU database is not throttled like a 1-vCPU sandbox, and a size change brings its limits at the next boot (ADR 0024). The per-vCPU values are chosen so that a host's machines add up to about its device: at the default capacity (4 vCPUs a hardware thread, 48 on a 12-thread OVH Advance), 48 × 32 MB/s is 1.5 GB/s and 48 × 4000 is 192k requests a second, about a datacenter NVMe pair through a ZFS mirror. A machine alone on an idle host gets its cap, not the device; that is the price of a cap that holds when the host is full. One host-wide value was rejected: it makes the size meaningless for the disk, and the caps of a full host of large machines would add up past the device.

**Buckets one second deep, the burst once.** Each bucket holds a second at its rate (`refill_time` 1000 ms) and starts with `burst_sec` seconds more (`one_time_burst`), so a boot reads its image at full speed (10 s at 32 MB/s is 320 MB, a Python image's root) and the rate holds after. A start, a wake and a change each give the burst again, as an egress limit's bucket starts full (ADR 0018).

**Given at boot, set again after a resume, changed live.** The drive's `PUT` carries the limiter at a cold boot. A memory snapshot holds the limiter of the run it paused, so after `snapshot/load` the daemon PATCHes both drives with the values in force: a change made while the machine slept is in force when it wakes. On a running machine a PATCH of `disk_limits` calls `PATCH /drives` first, the record after; refused, both keep what they had (500, the reason named). A stopped machine's change is its record's, read at the next boot. An event `updated` with `fields: ["disk_limits"]`.

**Throttling and disk bytes on `/metrics`, from Firecracker's metrics.** The daemon makes a FIFO next to the API socket in the jail (owned by the jail's user) and tells Firecracker to write there (`PUT /metrics`, before the boot or the load); a task reads it while the process lives. Firecracker writes a line a minute, each counter what it grew by since the line before, so the daemon adds the `block` totals into the machine's counters: `briqyard_machine_disk_read_bytes_total`, `_disk_write_bytes_total`, `_disk_throttled_total` (requests the limiter held back), from the daemon's start and across the machine's boots. Firecracker opens the path read-write and non-blocking, so it never blocks on the pipe; a reader that falls behind loses a line. An adopted machine's pipe is opened again by the new daemon. A regular file was rejected: Firecracker appends a line of several KB a minute forever. A `FlushMetrics` call per tick was rejected: a minute is fresh enough for a counter of throttling, and it is one call per machine per tick. Disk bytes are not in usage (ADR 0017): nothing bills them.

**CPU: shared by size under contention, `cpu.weight` 100 per vCPU.** A machine's vCPUs already bound it: the jail's `cpu.max` is its vCPUs' worth of CPU time, and Firecracker's own threads (the block and network emulation included) are in that cgroup, so a machine's IO costs its own CPU. What was missing is the share when the host's CPUs are oversubscribed (4 vCPUs a thread by default): every cgroup had the default weight 100, so a 1-vCPU sandbox and an 8-vCPU database got the same CPU. The jailer now sets `cpu.weight` to 100 × vCPUs, one argument. With 16 busy 1-vCPU machines and one busy 8-vCPU on 8 threads, the 8-vCPU gets 2.7 CPUs instead of 0.47.

**Measured on the dev VM** (Lima, nested virtualization on a Mac, the pool a file on the VM's disk: not a benchmark of an NVMe; `fio` in alpine guests, 4 GB volumes, O_DIRECT; script and runs in `../research/2026-10-21-disk-limits.md`):

| | seq read MB/s | seq write MB/s | 4k rand read IOPS (qd 32) | 4k rand write IOPS (qd 32) |
|---|---|---|---|---|
| no limit | 99 | 8 | 8,655 | 1,539 |
| 32 MB/s, 4000 IOPS, no burst | 34 | 19 | 4,196 | 1,990 |

Reads, which the VM serves fast, stop at the limits (34 against 32 MB/s and 4,196 against 4,000: the bucket's first second). At 4 MB/s and 200 IOPS: 3 MB/s and 206 IOPS. Writes are under the limits here: the VM's disk is the bottleneck. The VM cannot show the neighbour effect: a second guest's 4k reads at queue depth 1 went 684 → 456 IOPS under the other's flood (64k random read-write, qd 64) in one run, and 238 → 1,110 in the next (the pool's cache on the Mac's disk), the flood limited or not. That measurement belongs on a real host (below). The e2e suite checks the mechanism with `dd` and O_DIRECT: at 4 MB/s and no burst, 32 MiB written to the volume takes 6.2 to 7 s (7 s nominal: the bucket's first second is free; checked at 5), 16 MiB read from the root disk 2.5 s (3 nominal; checked at 2), 32 MiB read in 0.12 s once lifted live, and a limit set while suspended holds after the resume.

**To re-measure on the first OVH host** before the defaults are trusted: `fio` on a raw zvol of the pool (seq read and write 1M qd 8, 4k random read and write qd 32), then the same in a guest with no limit (Firecracker's overhead), then two guests with one flooding at the defaults while the other measures p99 latency at qd 1. If the device does much more than 1.5 GB/s and 200k IOPS, raise the per-vCPU values to device ÷ advertised vCPUs.

## Consequences

- A machine's disk throughput is capped even on an idle host: a 1-vCPU machine reads at 32 MB/s after its burst. A control plane can raise a machine's own values; `0` lifts a limit.
- Root disk and volume are limited separately, so a machine can do twice the rate across both.
- The burst comes again at every start and every change, so a machine that restarts in a loop gets it each time; its restart backoff (ADR 0022) bounds how often.
- Throttling is visible a minute late, and from the daemon's start (counters restart at zero with it, as ADR 0021's).
- Per-machine series are 15 each now (ADR 0021 said 12).
- Not built: a limit on the pool as a whole (cgroup `io.max` on the jail's parent, which would need the zvols' device numbers per pool), read and write limits apart, a burst that refills (Firecracker's buckets refill only their size).

# MicroVM field guide (2026-10-18, extended 2026-10-19)

The research behind ADR 0001, 0002 and 0007. Checked on GitHub and vendor docs on 2026-10-18; OVH prices from its public catalog on 2026-10-19. The long form with diagrams: https://claude.ai/artifact/9XosKk1tk9dPtd8PYqehJY (internal).

## Verdicts

| Option | What | Verdict |
|---|---|---|
| Fly Machines | Firecracker + NVMe volumes, rented | Keep. The model to copy |
| E2B runtime | E2B's backend, Apache 2.0, Go, Firecracker | Most mature sandbox stack. No team network, no durable data volume, no raw TCP. Not forked (ADR 0001) |
| Ubicloud | Open cloud on bare metal, Cloud Hypervisor, AGPL, Ruby | Closest to Fly's model. Reference only; hosted cloud a possible second provider |
| SPACE (Perplexity) | Firecracker on Kubernetes, Rust, 0.8 | Open multi-host install; `Unsafe` disk, three weeks old |
| Agent Substrate + AX | gVisor / Cloud Hypervisor on Kubernetes | HTTP-only ingress, tar-snapshot volumes, isolation unfinished |
| Daytona | Docker, privileged | Unmaintained since 2026-06, AGPL |
| Neon | Postgres with storage on S3 | Postgres only. Maybe an engine for the recipe someday |
| Kubernetes + Kata | A pod as a microVM | Wrong unit (ADR 0001) |

## Isolation

| Technology | Boundary | Start | Memory snapshot | Live migration | Needs KVM |
|---|---|---|---|---|---|
| Containers | namespaces, shared kernel | ~50 ms | CRIU, fragile | no | no |
| gVisor | a second kernel in user space | ~containers | yes | no | optional |
| Firecracker | hardware | ~125 ms (vendor) | yes; diff in preview | no (SharedMemfd design, 2026-10) | yes |
| Cloud Hypervisor | hardware | ~100s of ms | yes | yes | yes |
| QEMU + KVM | hardware | ~1 s | yes | yes | yes |

Firecracker as of 1.17 (2026-09): memory hotplug (virtio-mem), device hotplug and io_uring in developer preview, discard opt-in, `Unsafe` and `Writeback` cache modes, jailer and seccomp, VMClock on restore. VFIO GPU passthrough merging on `main`. A minor release a quarter, patches for the last two.

## Where KVM runs

Dedicated or bare metal: always. GCP, Azure: nested. AWS: nested since 2026-02 on C8i/M8i/R8i, else `.metal`. A Mac M3+ with macOS 15+: nested inside a Linux VM (Lima `vz`), ARM64 only; OrbStack did not expose `/dev/kvm`. Fly, Railway, PaaS: no. Nested virtualization costs most on disk and network I/O: fine for development, not for dense production.

## Storage

Three kinds: block (in-place writes, microseconds, one machine at a time), file (shared, milliseconds), object (whole objects, tens of milliseconds, cheapest, durable). A database needs block underneath; Neon and ClickHouse Cloud use S3 only because they rewrote the engine. briq runs any image: the durable layer must be a disk.

| Disk setup | VM crash | Host power cut | Host lost | Who |
|---|---|---|---|---|
| `Unsafe` local, saved at sleep | since last save lost | can corrupt | since last upload lost | SPACE, sandboxes |
| `Writeback` local + snapshots to S3 | kept | kept | back to last snapshot | Fly volumes, briqyard |
| Replicated block (DRBD, Mayastor, Ceph) | kept | kept | kept | AWS EBS; not needed now |
| Storage outside the VM | kept | kept | kept | Neon; Postgres only |

Fly does not replicate volumes either: NVMe on the machine's server, daily snapshots. That is the bar.

## Licenses

Apache 2.0, MIT, BSD, MPL, GPL: a competing hosted service is allowed. AGPL: allowed if we publish our modified source (Ubicloud, Daytona, ZeroFS). BSL and SSPL: written to block it. The risk with company-owned open source is a license change for future versions and a free package kept small on purpose (E2B Embed is one machine).

## Servers, monthly, excl. VAT

| Server | Cores / threads | RAM | NVMe | € / month | € per GB RAM |
|---|---|---|---|---|---|
| OVH Eco SYS-4 | 16 / 32 (EPYC 7371, 2018) | 128 GB ECC | 2 × 960 GB | 89.99 | 0.70 |
| OVH Eco RISE-L | 16 / 32 (Ryzen 9 9950X) | 128 GB DDR5 | 2 × 960 GB | 149.99 | 1.17 |
| OVH Eco RISE-8 | 32 / 64 (EPYC 7532) | 256 GB ECC | add-on | 189.99 + disks | 0.74 |
| OVH Advance-5 | 24 / 48 (EPYC 8224P) | 96 GB ECC | 2 × 960 GB | 395–427 | 4.1 |
| OVH Scale-a1 | 16 / 32 (EPYC 9135) | 128 GB, to 3 TB | add-on | 600–648 | 4.7–5.1 |
| OVH bm-l1 (hourly) | 16 / 32 | 128 GB | 2 × 960 GB | 1.45 / h ≈ 1,060 | 8.3 |
| Hetzner AX42-1 | 8 / 16 | 64 GB | 2 × 1.92 TB | 97.30 + 49 setup | 1.52 |
| Hetzner AX102-1 | 16 / 32 (7950X3D) | 128 GB | 2 × 1.92 TB | 257.30 + 129 setup | 2.01 |
| Scaleway EM-I120E | 8 / 16 | 64 GB | 2 × 960 GB | 134.99 (hourly too) | 2.11 |
| Scaleway EM-I620E | 64 / 128 | 576 GB | 2 × 3.84 TB | 679.99 | 1.18 |

OVH: no setup fee, 12 months about 5 % off, memory add-ons rose steeply in 2026. vRack: free layer 2 across every region (500 Mbps on SYS, 1 Gbps on Rise, 25–50 Gbps on Advance and Scale). Reading: OVH Eco for capacity, Scaleway for hourly trials, Advance and Scale only for an SLA or the fast private link.

## Density and cost per briq

8 GB for the host, 15 % free, no memory overcommit, shared vCPUs 4 per thread. Running at once on an AX102-1 (102 GB usable): 128 nano, 51 small, 25 medium, 12 large. Compute cost per running briq-hour on an AX102-1 60 % full: nano 0.0047 €, small 0.0117 €, medium 0.0238 €, large 0.0497 €, against Fly's 0.0052 / 0.0178 / 0.0356 / 0.1261 € and our prices 0.01 / 0.045 / 0.09 / 0.30 €. Break-even fill against Fly: 54 % nano, 39 % small, 40 % medium, 24 % large. Dollars at the ECB rate of 2026-10-16 (1.1253).

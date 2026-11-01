# 0071: Versioned target-zero balloon reporting

Status: accepted for implementation; default enablement requires native qualification.

New cold boots may use `balloon.enabled: true`, initially false. The fixed
`balloon-reporting-v1` profile installs one virtio balloon before InstanceStart:
target 0 MiB, OOM deflation true, statistics every five seconds, free-page reporting
true and free-page hinting false. A rejected configuration fails the boot. There is
no inflation controller or public memory-control endpoint.

Full configured memory remains reserved and charged by the existing admission,
quota, usage and cgroup rules. Reported reclaim never creates allocatable capacity.
OOM deflation is a device setting, not a host OOM protection guarantee.

Each new cold incarnation records a separate `boot_identity` before VMM launch. Its
schema v1 contains the explicit device profile, guest kernel SHA-256, VMM SHA-256,
host kernel release and PCI/MMIO transport. Artifacts are hashed once at daemon
startup. Mutable target/actual pages remain device state in the Firecracker snapshot.
The historical `memory_spec` digest and `vmm_version` API meaning stay unchanged.

Memory loads with a new identity require exact artifact/transport compatibility and
a recognized schema/profile, regardless of today's rollout switch. Absent legacy
identities retain the historical VMM version check and restore without injecting a
device. Named memory snapshots copy the effective identity. Disk-only restores,
forks and resets choose the current profile at their subsequent cold boot. Failed
memory loads return to the manager, which saves the cold identity before launching
a replacement VMM. Incompatible loads emit an explicit cold-start reason and keep
the named snapshot.

Adoption preserves a running incarnation. It reads the balloon configuration without
changing devices. If durable provenance is missing but a device is observed, it
records an ambiguous schema-0 identity: the VMM stays alive, telemetry can identify
the observed profile, and future memory loads require a cold fallback. Current
artifacts cannot establish what a historical VMM loaded. A successful device
observation contradicting saved metadata also makes provenance ambiguous: a rollback
to an older daemon can preserve unknown metadata across a cold boot. Failed telemetry
reads preserve a known identity. Artifact provenance is also bound to the actual
VMM PID, Linux process start ticks and host boot ID after launch. Adoption requires
that binding before treating preserved metadata as strong provenance, even when the
device profile matches. Unconfirmed metadata is retained on read failure, but suspend
and named memory snapshots publish only an ambiguous identity and therefore require
an explicit cold fallback on their next start. Plain stops remain available.

Memory telemetry is additive. `memory_bytes` remains cgroup `memory.current`;
optional anon/file charges need not sum to it. The existing tick caches bounded
balloon reads and FIFO increments. API read time is explicitly distinct from guest
sample time, which Firecracker does not expose. A FIFO update time is only the host's
observation. Missing guest counters stay absent. Failed reads omit value gauges and
never change lifecycle, profile or capacity. Stopped machines emit no fresh memory
or balloon value gauges.

Reporting may discard free pages while actual balloon remains zero. Cumulative
reported bytes include repeated pages and are not unique resident reclaim. Actual
host/cgroup reduction, correct refaults and workload measurements are required
before claiming a benefit. See [native qualification](../balloon-reporting.md).

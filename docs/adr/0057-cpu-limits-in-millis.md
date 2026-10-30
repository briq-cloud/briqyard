# ADR 0057: CPU limits in millis

Date: 2026-10-30 · Status: accepted

A guest CPU count is its topology, not its CPU-time reservation. Small system machines need
less than one CPU without sharing a process or a VM with another namespace. The gateway
measurements are in [the research note](../research/2026-10-29-gateway-size.md).

`size.cpu_millis` optionally sets CPU time in thousandths of a CPU. It is an integer from 1
to `vcpus × 1000`; omitted, it means `vcpus × 1000`. `vcpus` still sets Firecracker's guest
CPU count. The jailer is required for fractional limits: a host without it refuses the size
before modifying a machine or replacing a gateway.

The cgroup's `cpu.max` uses a 100,000 µs period for limits of at least 10m, with quota
`millis × 100`. For 1–9m the period is 1,000,000 µs, with quota `millis × 1000`.
Linux rejects quotas below 1,000 µs: a development-host probe rejected `100 100000`,
accepted `1000 100000`, and accepted `1000 1000000`. `cpu.weight` is
`max(1, millis / 10)`, retaining the existing weight of 100 per whole CPU.

Host capacity remains the configured shared-CPU budget in `capacity.vcpus`. Reports add
`capacity.cpu_millis = vcpus × 1000`; used capacity sums the effective limits of machines
starting, running or stopping. Guest CPU counts remain visible independently. Admission,
fleet placement and in-flight holds use millis. CPU is reserved under the same lock as
memory and released when the machine stops. Pending sizes count when applied at start.
Memory admission and guest memory sizes are unchanged. Backup records expose their captured
size for placement of a size-omitted restore; the fleet resolves and pins the selected backup
ID before reserving resources. Older sealed records without size metadata require an explicit
restore size through the fleet. No secret fields or pool keys are exposed in that metadata.

Namespace quotas gain `cpu_millis`. The legacy `vcpus` quota means `vcpus × 1000` CPU
millis; if both are present, the stricter CPU limit applies. Old persisted sizes and quota
records retain their meaning. Usage buckets include the size's optional millis; measured
`cpu_seconds` remains actual consumed time. The `briqyard_vcpus` metric reports CPU
reservation equivalents (`millis / 1000`), rather than guest topology.

Upgrade hosts before the fleet. Old reports lack precise CPU accounting; the new fleet
excludes those hosts from placement and refuses CPU-bearing updates that an old host
would silently ignore. Reads and cleanup remain available during the upgrade.

The gateway's selected memory, CPU and admission profile remains pending the completed
stress and fault measurements. This primitive applies to every machine; no gateway-specific
resource class or credential handling enters the runtime.

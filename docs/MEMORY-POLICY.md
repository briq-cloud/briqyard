# Host memory policy

[ADR 0065](adr/0065-oom-protection-and-physical-memory.md) defines the fixed process preferences,
VMM containment and physical reservation. Machine sizes, namespace quota memory and usage
buckets remain guest memory. Host `used.memory_mb` includes 256 MiB per committed VMM.
The allowance equals the existing hard ceiling; it is not an RSS estimate.

## Read-only checks

Run on the host, without changing a setting:

```sh
systemctl show -p MainPID -p OOMScoreAdjust -p OOMPolicy briqyardd briqyard-fleet
cat /proc/swaps
cat /sys/kernel/mm/ksm/run /sys/kernel/mm/ksm/pages_shared /sys/kernel/mm/ksm/pages_sharing
systemctl show -p LoadState -p ActiveState systemd-oomd.service systemd-oomd.socket
systemctl show -p ManagedOOMSwap -p ManagedOOMMemoryPressure -- -.slice system.slice briqyardd.service
cat /sys/fs/cgroup/cgroup.controllers
grep '^MemTotal:' /proc/meminfo
cat /sys/module/zfs/parameters/zfs_arc_max
briqyard status
briqyard host ls
```

Missing KSM files are acceptable when the facility is absent. Inspect any additional service
ancestors; a `ManagedOOM*=kill` policy is independent of kernel `oom_score_adj`. Installed
systemd-oomd service/socket must be masked and explicitly inactive, with service `MainPID=0`.
A mask alone does not stop an already active unit. Absent units need the same positive
inactive/zero-PID evidence. Verify each supervisor's actual
`/proc/<MainPID>/oom_score_adj` is -900; unit declarations alone do not prove process state.
The daemon reports a bounded `memory_protection` condition when host or live-VMM enforcement
is unresolved. Unjailed development reports containment unavailable and is not protected
fleet capacity. Local unjailed development operation still uses explicit scores.

For one owned live machine, inspect only its canonical leaf:

```sh
id=m_REPLACE_WITH_OWNED_ID
leaf=/sys/fs/cgroup/firecracker/$(printf '%s' "$id" | tr _ -)
cat "$leaf/cgroup.procs" "$leaf/memory.max" "$leaf/memory.oom.group"
cat "$leaf/memory.swap.max" "$leaf/memory.swap.current" "$leaf/memory.events.local"
```

Expected: hard memory is guest MiB plus 256 MiB, group 1, swap max 0. The process score is +500,
or +250 for the runtime-owned gateway. The canonical leaf must match the process's cgroup
membership; a persisted PID or path alone is insufficient ownership evidence. Per-machine
memory-limit metrics describe guest size; the host reservation and VMM cgroup ceiling are
separate quantities.

The daemon never drains swap, unmerges KSM, changes oomd or lowers a live ceiling while
adopting. A positive adoption survives policy failure and blocks incremental admissions.
An unreadable/unlimited live ceiling cannot supply free capacity. Resolve the prerequisite
in drained maintenance or enforce the next incarnation; do not restart a guest solely to
clear this condition.

## Explicit host maintenance

Bootstrap checks cgroup v2 controls and rejects used swap or existing KSM shared pages before
memory-changing maintenance. It configures persistent no-swap, masks installed oomd/KSM
services and stops KSM merging. Never replay bootstrap on an occupied host as a substitute for
a drained maintenance procedure. Stopping merging does not unmerge existing pages; draining
swap or unmerging can cause a memory spike. No automatic unmerge is implemented.

Capacity includes the configured system reserve and ARC ceiling. A configured allocation
budget above physical RAM after those reserves blocks protected admission. Automatic capacity
has no lower floor: exhausted reserves expose zero capacity. The system reserve still covers
helpers, kernel allocations and buffers; VMM admission does not bound every host allocation.

Use matching binary and unit versions. An older binary without child-score resets must use
its matching older units; this does not establish the new protection contract. Unknown
registry fields are preserved for older readers. Host memory-policy absence means legacy
accounting; mixed hosts retain candidate-specific reservations. A heartbeat's used figure
already includes its overhead. A policy change with incompatible pending holds blocks new
placement until reconciliation or release.

## Validation commands

Native checks:

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
bash -n hack/bootstrap-host.sh hack/oom-group-smoke.sh
```

Run the same workspace tests on Linux before publication, in a target directory belonging to
the source tree. Linux is required for pre-exec inheritance, procfs/pidfds and kernel cgroups.
The protected-parent regression changes only its child process's score, then proves ordinary
helpers reset to 0, VMM preferences survive forks and the parent remains -900:

```sh
sudo cargo test -p briqyard-api --features host-process \
  host_process::tests::protected_parent_resets_helper_scores -- --exact --ignored
```

On an **exclusive, empty disposable Linux host only**, after independent ownership and
empty-runtime preflight:

```sh
sudo hack/oom-group-smoke.sh --disposable-empty-host
```

This creates one owned 256-MiB parent cgroup and 32-MiB leaves. It exhausts only an owned
VMM stand-in leaf, verifies group kill and unchanged sibling/supervisor incarnations and
scores, then removes every owned actor and cgroup. It has finite readiness/load deadlines and
parent-death watchdogs. It changes no host-wide OOM or memory setting. It does not exercise a
shared-host global OOM, prove deterministic class victim ordering or substitute for real
microVM lifecycle tests.

With the repository VM lock held by the operator, run existing daemon and fleet suites,
including two-host and registry-restore coverage, stress/invariants and lifecycle races.
Install matching binaries/units before those tests. Use the suite's own disposable namespace
and exact cleanup. Verify actual guest OOM separately from a VMM cgroup OOM; exit 137 alone
cannot distinguish them. Check live leaf controls and supervisor PIDs through cold boot,
pause/resume, fork, restore, size change and handover. A handover policy-write failure must
retain the guest, block new allocations and recover on a later valid incarnation.

The required suites are `hack/e2e.sh`, `hack/fleet-smoke.sh`, `hack/fleet-two-hosts.sh`,
`hack/fleet-restore.sh`, `hack/stress.py` with `hack/stress-invariants.sh`, and `hack/chaos.py`.
Heavy suites and scoped OOM tests require an exclusively owned disposable environment.

# 0065 — OOM protection and physical memory reservations

Date: 2026-10-31. Status: accepted.

## Decision

Protect the host supervisors, contain each VMM and reserve its existing hard ceiling against
physical capacity. Keep namespace quotas and machine sizes expressed in guest memory.

| Process | `oom_score_adj` |
|---|---:|
| briqyardd, briqyard-fleet | -900 |
| Host utility and its descendants | 0 |
| Ordinary VMM, including databases | +500 |
| Runtime-owned namespace gateway VMM | +250 |

The supervisor units use `OOMPolicy=continue`. Host utilities explicitly reset inheritance
before exec. The jailer receives its VMM score before forking or dropping credentials; the
actual VMM's score and leaf membership are checked before boot, snapshot load or resume.
Only the persisted runtime gateway role selects +250. Names, images, metadata, commands and
machine-create fields confer no priority. There is no arbitrary-score or workload-class API.
These are relative kernel preferences, not guaranteed victim order or supervisor survival.

The VMM leaf `/sys/fs/cgroup/firecracker/<machine-id>` has `memory.oom.group=1`,
`memory.swap.max=0`, and the existing hard ceiling **guest MiB + 256 MiB**. One checked function
computes that ceiling and its physical admission reservation. The allowance is a conservative
reservation equal to the hard limit, not measured fixed RSS. It is not reduced here.

Creating-with-start, starting, running and stopping hold the physical reservation under the
existing machine-map lock. A stopped or suspended machine releases running memory as before.
A next-size reservation subtracts the previous physical charge and adds the new one once.
Namespace quotas, guest-visible RAM and usage buckets retain guest memory; VMM overhead does
not consume a namespace's memory quota. Snapshot/page-cache capacity and non-VMM allocations
still need separate host headroom.

## Adoption and failure

Positive process adoption and memory-policy enforcement are separate results. Open the owned
process directory, verify its command-line identity/start time and exact canonical leaf, then
use directory-relative opens for updates. New owned launches retain a pidfd for race-free
abort signals. Never write through a record-supplied cgroup path or a newly reused numeric PID.

Do not lower an existing live `memory.max`. Reserve the larger of the checked ceiling and the
observed live ceiling; an unlimited/unreadable ceiling reserves unavailable capacity. Any
unresolved control write/readback, membership, live ceiling or existing swapped pages leaves
the adopted guest alive and managed, reports a bounded condition and blocks incremental
admission. It does not return false adoption, restart a guest, drain swap or unmerge pages.
Later starts enforce policy on their new incarnation.

Unjailed development launches explicitly set the VMM score and report containment unavailable.
Direct development operation remains possible; a fleet does not treat this as protected
readiness. Protected operation requires the jailer, cgroup controls and host prerequisites.

Capture `memory.events.local` at admission/adoption and before lifecycle cleanup removes the
leaf. Log per-incarnation deltas. An exit code 137 or a guest `oom_killed` report alone does not
identify a VMM cgroup OOM. Local kill counters without local limit evidence remain unclassified;
reset/unreadable counters are unavailable evidence. Existing restart/backoff policy is retained.

## Host and fleet accounting

Status, heartbeat and persisted host records carry optional
`memory_policy: { version: 1, vmm_overhead_mb: 256 }`. This describes accounting; inspect
conditions for protection readiness. Absence denotes legacy accounting. Unknown versions or
allowances refuse new placement. The fleet computes each candidate's request charge using
that candidate's policy and holds exactly the selected charge. A host's reported usage already
includes its allowance; do not add it again. A policy change with outstanding incompatible
holds blocks placement until those holds reconcile or release. Rejection and cancellation
release the held physical amount.

A new fleet retains guest-only placement on legacy hosts and labels them `legacy`. An older
fleet may underreserve in-flight holds against a new host; the daemon's locked physical
admission remains the final guard. Those combinations are not placement-equivalent. Record
fields remain additive and unknown registry fields survive older readers. A binary change
must use matching supervisor units; older binaries without child-inheritance resets require
their matching older units and do not establish this protection contract.

Capacity must fit physical RAM after system and configured ARC reservations. The automatic
capacity calculation has no 1-GiB floor: exhausted reservations yield zero, not invented RAM.
The runtime only inspects swap, KSM, oomd, ancestor ManagedOOM policy and capacity. Unresolved
prerequisites block protected admission. Explicit bootstrap verifies cgroup controls and
persistent no-swap/no-oomd/no-KSM settings; occupied-host maintenance must be drained when swap
or merged pages exist. Stopping KSM merging does not unmerge existing pages.

## Scope and validation

This supplies physical overhead admission, fixed OOM preferences and per-leaf containment.
Kubernetes requests/limits, Pod Overhead, QoS preference, PriorityClass/preemption and
node-pressure eviction are distinct mechanisms. No workload QoS classes, preemption, pressure
eviction, overcommit or priority selection are introduced.

Native unit coverage includes accounting domains, overflow, exact final-slot races, pending
creates, replacement sizes, gateway roles, positive adoption failures, PID-directory reuse,
missing controls, write refusal, live ceilings, swap, event deltas, mixed hosts and hold
reconciliation/rollback. Linux subprocess tests check real score inheritance and supervisor
isolation. The [memory-policy runbook](../MEMORY-POLICY.md) lists the required Linux and scoped
OOM validation. No shared-host/global-OOM experiment is part of normal tests.

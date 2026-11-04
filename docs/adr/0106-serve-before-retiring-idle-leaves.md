# ADR 0106: Serve before retiring idle cgroup leaves

2026-11-04 · Candidate; amends ADRs 0068 and 0099.

## Decision

Keep the complete recovery barrier unchanged: service-member settlement, inventory and
rechecks, original process identity, death and OOM evidence. Settle orphan processes before
artifact cleanup and opening spawning. Read final counters in the collector before removal:
an orphan has no surviving usage identity, so its debug-only totals do not gate serving. Unknown members
still refuse recovery. No recovery settlement is allowed after the gate opens.

Retain each settled orphan's factory registration in a dedicated set. Do not remove its
empty cgroup at startup. After API and ingress listeners are installed, one collector lists
leaves and tries at most 128 per pass, with 16 blocking removals in flight. It waits one second
after each pass, without overlapping passes or catch-up. Failed candidates go last next time.
This replaces the tick's 15 s pass. A serial 15 s cadence would take about 13 minutes for
6500 leaves; bounded concurrency allows kernel RCU grace periods to overlap. Native timing
is required before claiming a measured drain rate.

A known stopped machine still requires its nonwaiting lifecycle lock, final metering and
factory death proof. Restart cannot race its removal. An orphan's original registration
remains reserved through successful removal; `register_new` rejects reuse. Only then is
it forgotten. An unknown leaf discovered after startup receives no authority and is counted
but never removed. No guest init changes.

The gauges count all remaining idle leaves, including queued or refused orphans; they reach
zero only after removal. No repository alert consumes the idle gauge. A temporary backlog
therefore remains visible without introducing an alert suppression rule.

## Evidence

The previous startup serially removed 6500 idle leaves before listening: API downtime 243.6 s,
endpoint gap 243.8 s in the upgrade-path experiment. Each memcg removal waits roughly
25–50 ms in the kernel. The inventory cap is already 65,536 (#134), not 4096.
`recovery inventory checked` records read-only barrier time and identity count independently
of adoption and deletion. The first candidate only moved removal and failed the downtime bounds: its orphan phase
spent 198.770 s before listening while the complete barrier took 4.561 s. This is evidence
that the counter reads, not removal alone, block serving. The old daemon handed over in
0.140 s. See [the measured timeline](../research/2026-11-04-startup-leaf-timing.md).

Native upgrade and scale runs must measure the candidate's
inventory, downtime, adoption and retirement; results are pending. The queued-orphan event
now measures synchronous settlement alone. Aggregate cumulative microsecond timings for
`cgroup.procs`, `cgroup.events`, `cpu.stat`, `memory.current` and `memory.events.local` separate
the actual control reads; counts accompany them. Load, backing, service settlement, inventory,
recheck, network, adoption and artifact cleanup have separate elapsed-time events.

Unit coverage requires startup to retain 260 orphan leaves, a bounded pass to leave 132,
then four, then zero, with the idle gauge reflecting each backlog. Existing tests cover
known-machine lock exclusion, running VMMs, final usage once, refusal and fair retry.

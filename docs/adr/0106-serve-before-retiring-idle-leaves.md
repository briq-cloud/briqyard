# ADR 0106: Serve before retiring idle cgroup leaves

2026-11-04 · Candidate; amends ADRs 0068 and 0099.

## Decision

Keep the complete recovery barrier unchanged: service-member settlement, inventory and
rechecks, original process identity, death and OOM evidence. Settle orphan processes and
read their final counters before artifact cleanup and opening spawning. Unknown members
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
of adoption and deletion. Native upgrade and scale runs must measure the candidate's
inventory, downtime, adoption and retirement; results are pending. The queued-orphan event
also measures synchronous settlement and final-counter reads.

Unit coverage requires startup to retain 260 orphan leaves, a bounded pass to leave 132,
then four, then zero, with the idle gauge reflecting each backlog. Existing tests cover
known-machine lock exclusion, running VMMs, final usage once, refusal and fair retry.

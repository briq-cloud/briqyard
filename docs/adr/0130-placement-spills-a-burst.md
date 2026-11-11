# ADR 0130: Placement spills a burst to the next allowed region when the preferred one is queueing boots

Date: 2026-11-11 · Status: proposed · Amends ADR 0128 (placement admission walk) · Builds on ADR 0044 (holds), ADR 0129 (boots at once), ADR 0025 (a namespace never spans regions)

## Context

ADR 0128 walks the caller's regions in order and leaves a region only when it is `full`. A burst into a region that still has room but whose hosts are already booting many machines does not leave it: each host boots `boots_at_once` guests at a time (ADR 0129), so the n-th create on a host waits about ⌈n / boots_at_once⌉ boot waves. Meanwhile the later regions the caller allowed are idle.

Measured with nano sandboxes (per-sandbox time to the first command, p50):

| Run | Burst | p50 | p90 |
|---|---|---|---|
| Two hosts, one region | 50 | 2.18 s | 3.56 s |
| Two hosts, one region | 100 | 3.30 s | 4.88 s |

Doubling the burst adds about 1.1 s at p50 on the same hosts: the queue, not the boot itself. A region with room can still be the slow choice.

## Decision

**A host's queue is the creates placed on it that no report counts yet.** The fleet already keeps them: the holds of ADR 0044 (creates and admission requirements, until a heartbeat counts the machine). `queued(host)` is their number. The daemon adds `boots_at_once` to its heartbeat (the value its gate uses, ADR 0129); a host that does not report it counts as `max(2, vcpus × 3 / 2)`, the same default.

**Waves.** `waves(host) = queued(host) / boots_at_once(host)`, a fraction. Within a region, the host pick of ADR 0128 orders candidates by fewer waves first, then most free memory, so a burst also spreads over a region's own hosts by queue, not only by memory.

**A new region class, `busy`.** A region with at least one candidate host, where every candidate has `waves ≥ placement.spill_waves` (fleet config, default 2; 0 turns spilling off). The walk:

| Region class | Walk |
|---|---|
| `placed` and not `busy` | stop, place here |
| `busy` | remember the first busy region, try the next |
| `full` | next region, as before |
| `unconfirmed` | stop with 503, as before: an outage is never a reason to move |
| `ineligible` | as before |

A walk that finds no region with room and no queue places in the first `busy` region it remembered. Being busy never refuses a create; it only changes the order among regions that have room.

**Only between regions the caller listed.** `regions` stays the allowlist (ADR 0128), and the request gains `spill_when_busy` (default `false`). A caller that sends one region, or leaves the flag off, gets exactly ADR 0128. The control plane decides who opts in, for example a team that already allows other regions when its own is full.

**Recorded like any decision.** The answer's `regions` lists `busy` with the waves seen, and replay returns the stored answer (ADR 0128). The metrics count spills per region pair.

## Consequences

- A burst uses every allowed region's boot capacity before queueing two waves deep in one.
- A spilled namespace stays in its region for its whole life (ADR 0025): every later call pays that region's latency. Hence a threshold in waves, not "any queue", and the opt-in flag.
- `queued` is fleet memory only: after a fleet restart it starts at zero until reports arrive. The walk then underestimates queues for one heartbeat, which is the behaviour of ADR 0128 today.
- Spreading across providers, not only regions, is the control plane's job: it can use the same signal (a `busy` outcome in the answer) to send the next creates of a burst elsewhere. Out of scope here.

## Test plan

- Registry unit tests: the walk table above, waves with and without a reported `boots_at_once`, the host order inside a region, `spill_waves = 0`, replay of a spilled decision.
- `hack/fleet-two-hosts.sh` with two regions of one host each: a burst of 3 × `boots_at_once` with `spill_when_busy` lands in both regions, and without it lands in the first.
- Staging: a 100-nano burst with a preferred region and spilling on, against the same burst with it off: p50 and p90 to the first command, and the latency of a command to a spilled sandbox afterwards.

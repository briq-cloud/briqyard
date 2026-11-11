# ADR 0130: Placement spills a burst to the next allowed region when the preferred one is queueing boots

Date: 2026-11-11 · Status: proposed · Amends ADR 0128 (placement admission walk; this is the reopening its last section anticipated) · Builds on ADR 0044 (holds), ADR 0129 (boots at once), ADR 0025 (a namespace never spans regions)

## Context

ADR 0128 walks the caller's regions in order and leaves a region only when it is `full`. A burst into a region that still has room but whose hosts are already booting many machines does not leave it: each host boots `boots_at_once` guests at a time (ADR 0129), so the n-th create on a host waits about ⌈n / boots_at_once⌉ boot waves. Meanwhile the later regions the caller allowed are idle.

Measured with nano sandboxes (per-sandbox time to the first command):

| Run | Burst | p50 | p90 |
|---|---|---|---|
| Two hosts, one region | 50 | 2.18 s | 3.56 s |
| Two hosts, one region | 100 | 3.30 s | 4.88 s |

Doubling the burst adds about 1.1 s at p50 on the same hosts: the queue, not the boot itself. A region with room can still be the slow choice.

## Decision

**A host's queue is the boots placed on it that the host has not answered yet.** The fleet already keeps them: a hold (ADR 0044) with no `made` time is a create the host has not answered (it answers once the guest has booted) or an admission requirement not dispatched yet. `queued(host)` counts those holds, and only requirements that boot a machine: a gateway requirement does not count. A hold with a `made` time is a finished boot waiting for the next report; it does not count, or a steady create rate below the gate would look busy.

**The gate.** The daemon adds `boots_at_once` to its heartbeat (the value its gate uses, ADR 0129). A host that does not report it is never busy: guessing it from the capacity vCPUs would overstate it several times over.

**Waves.** `waves(host) = ⌊queued(host) / boots_at_once(host)⌋`. Within a region, the host pick of ADR 0128 keeps its keys and adds waves before free memory: a host holding a validated seed first, then the nested-hypervisor key (ADR 0088), then fewer whole waves, then most free memory.

**A new region class, `busy`.** A region with at least one candidate host, where every candidate has `waves ≥ placement.spill_waves` (fleet config, default 2; 0 turns spilling off). The walk with `spill_when_busy`:

1. Classify every region as ADR 0128 does, plus `busy`. The first region keeps its own rules: `ineligible` refuses as before, `unconfirmed` refuses as before.
2. Among the regions with a candidate (`placed` or `busy`), place in the one with the lowest `waves(best candidate) + index × spill_waves`, where `index` is its position in `regions`; ties go to list order. The preferred region wins until it is `spill_waves` deep, then the burst balances across regions instead of piling back onto the first one.
3. A later region that is `unconfirmed`, `full` or `ineligible` is skipped, never a refusal, once an earlier region had a candidate. With no candidate anywhere the walk ends as ADR 0128's does.

A seeded candidate in a busy region is compared with its waves like any other: a seed saves a cold boot, not a queue.

**Only between regions the caller listed, only for a new binding.** `regions` stays the allowlist and its order the only weight (ADR 0128). The request gains `spill_when_busy` (default `false`): the caller's consent to a namespace that may live in a farther region for its whole life. The fleet does not know the caller's latency to each region, so it takes no per-region weight. A caller that sends one region, or leaves the flag off, gets exactly ADR 0128. A namespace already pinned (`binding: existing`) answers before the walk, as before: `busy` never applies to it.

**Recorded like any decision.** The answer's `regions` gains the outcome `busy`, with the waves seen, and replay returns the stored answer (ADR 0128). A spill is not a refusal: `count_full` does not count it. The metrics count spills per pair of regions. Rollback: an older fleet that loads a stored `busy` outcome must read it as `full`, so the outcome enum takes a serde fallback in the release before the walk changes.

## Consequences

- A burst uses every allowed region's boot capacity before queueing `spill_waves` deep in one.
- A spilled namespace stays in its region for its whole life (ADR 0025): every later call pays that region's latency. Hence a threshold in waves, and the opt-in flag.
- The signal under-counts what takes the gate without a hold: starts, wakes and resumes (`machine/start.rs`), and forks and restores, which bypass admission. A host busy with those looks less busy than it is.
- An admission abandoned before its dispatch counts until its hold deadline (`placement.admission_hold_sec`, 240 s by default).
- `queued` is fleet memory only: after a fleet restart it starts at zero, so the walk underestimates queues until creates are placed again.
- Spreading across providers, not only regions, is the control plane's job: it can read the `busy` outcomes in the answer to send the next creates of a burst elsewhere. Out of scope here.

## Test plan

- Registry unit tests: the walk above, including `busy` then `unconfirmed` (places in the busy region), all regions busy (the distribution follows the score), a pinned namespace (ignores `busy`), a seeded host in a busy region, a host that does not report `boots_at_once` (never busy), `spill_waves = 0`, abandoned admissions expiring from the queue, replay of a spilled decision, and an older fleet loading a `busy` record.
- A steady create rate below the gate makes no spill.
- `hack/fleet-two-hosts.sh` with two regions of one host each: a burst of 3 × `boots_at_once` with `spill_when_busy` lands in both regions, and without it lands in the first.
- Staging: the length of one boot wave in seconds (to justify `spill_waves = 2`), then a 100-nano burst with a preferred region and spilling on, against the same burst with it off: p50 and p90 to the first command, and the latency of a command to a spilled sandbox afterwards.

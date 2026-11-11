# ADR 0130: Placement spills a burst to the next allowed region when the preferred one is queueing boots

Date: 2026-11-11 · Status: accepted (phase 1: signal and rollback-safe outcome, shipped; phase 2: the walk, `placement_spill_v1`) · Amends ADR 0128 (placement admission walk; this is the reopening its last section anticipated) · Builds on ADR 0044 (holds), ADR 0129 (boots at once), ADR 0025 (a namespace never spans regions)

## Context

ADR 0128 walks the caller's regions in order and leaves a region only when it is `full`. A burst into a region that still has room but whose hosts are already booting many machines does not leave it: each host boots `boots_at_once` guests at a time (ADR 0129), so the n-th create on a host waits about ⌈n / boots_at_once⌉ boot waves. Meanwhile the later regions the caller allowed are idle.

Measured with nano sandboxes (per-sandbox time to the first command):

| Run | Burst | p50 | p90 |
|---|---|---|---|
| Two hosts, one region | 50 | 2.18 s | 3.56 s |
| Two hosts, one region | 100 | 3.30 s | 4.88 s |

Doubling the burst adds about 1.1 s at p50 on the same hosts: the queue, not the boot itself. A region with room can still be the slow choice.

## Decision

**A host's queue is reported by the host, plus what was placed since.** The daemon's create answers once the machine is recorded in `creating` (ADR 0048); the boot follows in a task that waits on the boot gate. So the fleet cannot see the queue from its own holds alone. The heartbeat gains two figures:

- `boots_at_once`: the gate's size (ADR 0129);
- `boot_queue`: the boots the host has accepted and that have not left the gate yet, counted from the moment the machine is recorded (its image and disks come before the gate, and count too). Every boot counts: a create, a gateway, a start, a wake, a resume, a fork, a restore. A warm-slot fill competes for the gate like any other boot, so it counts.

`queued(host) = boot_queue + holds not answered before at`, where `at` is when the figures were asked for: a hold not answered yet, or answered after `at` (the rule ADR 0044 applies to memory, `registry/mod.rs`). A hold answered before `at` is in `boot_queue` already. A create in transit at `at` can be counted twice for a moment; that errs towards spreading, never towards a refusal.

**Busy is confirmed by a fresh read, outside the lock.** A heartbeat is up to one report interval old, so boots that finished since still count in it. The walk runs under the registry lock, so the read cannot happen inside it:

1. Decide from the figures in memory. No region found busy: that is the answer.
2. Otherwise release the lock and read the candidate hosts of every region found busy, in parallel, with a timeout of its own well under one boot wave (`placement.busy_read_ms`, 300 by default, at most 1000). A host read or heard from (a heartbeat) less than a second ago (a read in flight is one: its timeout is under a second), or a host that does not answer, keeps its figures from memory; a create never waits for another create's read. The read is the one a delete makes to free what a machine held: the host's status, taken into the registry as a heartbeat would (`used`, free disk, `boots_at_once`, `boot_queue`).
3. Take the lock again, check replay as ADR 0128 does, and decide once more with the new figures. That decision is final: no further read.

`/v1/hosts` shows both figures for each host.

**Counting the queue.** The holds of a host are exactly those its last figures do not count yet (`report` drops a hold made at or before the report, ADR 0044), so `queued(host) = boot_queue + holds`: one hold per requirement (a gateway, a consumer), taken by the decision and kept until its dispatch or its deadline. A host that reports neither `boots_at_once` nor `boot_queue` has no waves and is never busy. A fresh read is asked at `at` = the moment the request leaves, so a create answered while the read is in flight can be counted twice, never missed.

**Waves.** `waves(host) = ⌊queued(host) / boots_at_once(host)⌋`. Everything waves change, the host order and the depth below included, applies only to a request with `spill_when_busy` and more than one region, on a fleet with `spill_waves > 0`; any other create is placed exactly as ADR 0128 places it. Within a region, the host pick of ADR 0128 keeps its keys and adds waves before free memory: a host holding a validated seed first, then the nested-hypervisor key (ADR 0088), then fewer whole waves, then most free memory.

**A region's depth** is the waves of the host the pick would choose there. A host `spill_waves` or more deep loses its seed and nested-hypervisor preference, so the pick does not queue on a deep seeded host beside an idle one. A region with candidates is `busy` when its depth is at least `placement.spill_waves` (fleet config, default 2).

**The walk with `spill_when_busy`** (and `spill_waves > 0`; 0 is exactly the walk of ADR 0128):

1. Walk `regions` in order, classifying each as ADR 0128 does. Before any region with a candidate, its rules hold unchanged: the first region `ineligible` refuses, an `unconfirmed` region stops the walk with 503, a `full` one moves on.
2. Once a region with a candidate has been seen, later regions are still classified, and those without a candidate (`full`, `unconfirmed`, `ineligible`) are skipped, never a refusal.
3. Among the regions with a candidate, score each `depth + index × spill_waves`, where `index` is its position in `regions`. A later region wins only with a strictly lower score. The preferred region keeps every create until it is more than `spill_waves` deeper than the next one; then the burst balances across regions instead of piling back onto the first.

A seed saves a cold boot, not a queue: a seeded host counts with its waves like any other.

**The wire.** `spill_when_busy` is a boolean of the admission body, absent or `false` by default. The body refuses fields it does not know (ADR 0128), so a fleet before this ADR answers 400 to it. The fleet therefore advertises the capability `placement_spill_v1: true` in `GET /v1/status`, beside `placement_admission_v1`; a client sends `spill_when_busy` only to a fleet that says so, and an older fleet (the field absent) gets the body of ADR 0128 and places as before. The capability means the field is accepted; with `spill_waves = 0` the fleet accepts it and walks as ADR 0128.

**Replay.** The fingerprint of a body (ADR 0128) leaves out `spill_when_busy` when it is `false` or absent, so a retry of a body sent before this ADR, or by a client that never sends the flag, matches its stored admission. A body with `true` is a different body from the same one with `false`: the same id with the other value is 409. The stored record does not keep the flag: it matters to the decision alone, and a fleet rolled back past this ADR rejects a field it does not know when it loads the registry.

**Only between regions the caller listed, only for a new binding.** `regions` stays the allowlist and its order the only weight (ADR 0128). The request gains `spill_when_busy` (default `false`): the caller's consent to a namespace that may live in a farther region for its whole life. The fleet does not know the caller's latency to each region, so it takes no per-region weight. A caller that sends one region, or leaves the flag off, gets exactly ADR 0128. A namespace already pinned (`binding: existing`) answers before the walk, as before: `busy` never applies to it.

**Recorded like any decision.** The answer's `regions` gains the outcome `busy`, with the depth seen, for a region passed over because of its queue; the region placed in is `placed`, busy or not; a later region with candidates that was not needed is omitted, as ADR 0128 omits regions it did not reach. Replay returns the stored answer (ADR 0128). A spill is not a refusal: `count_full` does not count it. The outcomes run up to the region placed in, so a spilled answer lists each earlier region as `busy` (its depth), `full`, `unconfirmed` or `ineligible`. The metrics count spills in `briqyard_fleet_placement_spills_total{from,to}`: `from` is the first region passed over for its queue, `to` the region placed in; both have hosts, so a caller's typo makes no series. Rollback: an older fleet that loads a stored `busy` outcome must read it as `full`, so the outcome enum takes a serde fallback in a release before the walk changes.

## Consequences

- A burst uses every allowed region's boot capacity before queueing `spill_waves` deep in one.
- A spilled namespace stays in its region for its whole life (ADR 0025): every later call pays that region's latency. Hence a threshold in waves, and the opt-in flag.
- A spill costs one extra read of the busy region's hosts on the create path, rate-limited per host.
- An admission abandoned before its dispatch counts until its hold deadline (`placement.admission_hold_sec`, 240 s by default).
- After a fleet restart, the holds are gone; the next reports carry the queue again.
- Spreading across providers, not only regions, is the control plane's job: it can read the `busy` outcomes in the answer to send the next creates of a burst elsewhere. Out of scope here.

## Test plan

- Daemon: `boot_queue` counts gate holders and waiters for every kind of boot.
- Registry unit tests: the walk above, including `busy` then `unconfirmed` (places in the busy region), all regions busy (the distribution follows the score), a pinned namespace (ignores `busy`), a seeded host in a busy region, a host that does not report `boots_at_once` or `boot_queue` (never busy), `full` then `unconfirmed` then a placed region (refuses as ADR 0128), a tie at exactly `spill_waves` (stays), `spill_waves = 0`, abandoned admissions expiring from the queue, replay of a spilled decision, and an older fleet loading a `busy` record.
- A steady create rate below the gate makes no spill.
- Flag off, one region with the flag on, or `spill_waves = 0`, with a deep seeded host: the pick is the one of ADR 0128.
- `hack/fleet-two-hosts.sh` with two regions of one host each: a burst of 3 × `boots_at_once` with `spill_when_busy` lands in both regions, and without it lands in the first.
- Staging: the length of one boot wave in seconds (to justify `spill_waves = 2`), then a 100-nano burst with a preferred region and spilling on, against the same burst with it off: p50 and p90 to the first command, and the latency of a command to a spilled sandbox afterwards.

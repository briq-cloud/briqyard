# ADR 0128: One placement admission for a namespace's first requirements, across an ordered list of regions

Date: 2026-11-10 · Status: proposed; no code in this change · Builds on ADR 0013 (placement reserves what it places), ADR 0025 (a namespace never spans regions), ADR 0044 (holds), ADR 0056 (a fork is made on its source's host), ADR 0076 (seed admission), ADR 0119 (what the registry forgets)

## Context

A control plane that offers a region *preference* needs the fleet to answer one question: where can this namespace's first machines go, trying the regions in this order, without leaving anything behind in a region it then abandons?

Today it cannot ask:

| Fact | Effect |
|---|---|
| `POST /v1/machines` names one `region`; a `503 capacity` is the answer for it | A caller that retried in another region would do so after `place` pinned the namespace and a hold was taken |
| A first machine's `capacity` answer unpins the namespace (ADR 0013), but the daemon may have made the namespace's network before it refused | A refusal does not prove nothing was created. Only the fleet's own check, before any host is asked, does |
| A credential gateway is a machine of the same namespace (ADR 0016) and its `PUT` pins the namespace before the consumer's create | The gateway can land in a region the consumer does not fit in; the pair is placed in two steps |
| Seed admission (ADR 0076) freezes one region, one size and one seed | It does not account for the gateway, a volume, a runtime class or an ordered list of regions |
| A write with no answer may have completed | A missing machine or a namespace 404 does not authorize another dispatch somewhere else |

Catching `capacity` around the machine POST and trying the next region is refused: the refusal is not proof of no effect, and the retry has no durable identity.

## Decisions

**A placement admission is a durable decision, made once, under the registry lock, before any host is asked.** `PUT /v1/namespaces/{ns}/admissions/{id}`, authenticated like seed admission (`capability_unsupported` without a configured token). `id` is the caller's request identity (`valid_sandbox_request_id`), unique per namespace. The seed route (`sandbox-admissions`) stays as it is; an id lives in one of the two tables and a `PUT` to the other with the same `(namespace, id)` is 409.

```json
{
  "regions":      ["beauharnois", "gra"],
  "requirements": [
    {"role": "gateway",  "size": {…}, "runtime_class": "default"},
    {"role": "consumer", "size": {…}, "volume_gb": 20, "runtime_class": "default",
     "memory_profile": "init-ready-v1", "egress_siblings": false,
     "sandbox_seeds": [{"machine_id": "…", "snapshot": "…", "generation": "…"}]}
  ]
}
```

`regions` is non-empty, without repeats, in the caller's order: it is an allowlist and a preference, nothing else. `requirements` lists everything the namespace's first dispatches will ask for, the gateway included, with the fields the create already carries (size, volume, runtime class, memory profile, `egress.siblings`, seeds). The fleet reuses the predicates `place` and `create_machine` apply today; it does not copy them.

```json
{"region": "beauharnois", "host": "h_…", "binding": "new", "mode": "cold",
 "regions": [{"region": "beauharnois", "outcome": "placed"}]}
```

`binding` is `new` (the admission pinned the namespace) or `existing` (it already was). `mode` is `sandbox-seed` or `cold` as in ADR 0076; `seed` names the selector used. `regions` lists the outcome of each region walked (`placed`, `full`, `ineligible`); it is evidence, not a promise.

**Resolution order: binding first, preference second.** Under one lock acquisition:

1. A namespace already pinned: the answer is its host and region, `binding: existing`, whatever `regions` says. The requirements must fit that host (the same arithmetic as step 3, one host); if they do not: 503 `capacity`. A stack is never split.
2. A fork, restore or volume source keeps today's path (a create without an admission): the control plane does not admit what it can resolve itself.
3. Otherwise walk `regions` in order. A region is classified once:

| Class | When | Walk |
|---|---|---|
| `placed` | a host of the region, ready, takes new namespaces (ADR 0042's conditions), serves every requirement (runtime class, profile, siblings, seed on that host) and has room for **their sum**: memory (physical reservation), CPU, disk | stop; pin the namespace, take the hold, store the decision |
| `full` | every host of the region that serves the requirements is ready, fresh and without room | next region |
| `ineligible` | no host of the region serves the requirements at all | **first region**: 409 `capability_unsupported`, as today. A later region: skip it |
| `unconfirmed` | a host that would serve them is down, stale, joining, or draining without a decision (anything but ready and full) | stop: 503 `capacity`, `reason: region_unconfirmed`. The next region is **not** tried |

Why the first region may not be `ineligible`: a preference must not weaken what a single region refuses today. Why `unconfirmed` stops the walk: an outage is not proof of no capacity; the caller sees a refusal and retries later, never a placement elsewhere. A host the operator is draining or retiring (ADR 0027) is a decision, not an outage: it counts as not serving.

4. The walk ends without `placed`: every region `ineligible`, 409 `capability_unsupported`; otherwise 503 `capacity` naming each region's class. **A refusal stores nothing**: no pin, no hold, no record. It is counted as `capacity` in each region found `full` (ADR 0042), once per request.

The host inside a region is the one `place` picks today (most free memory, hosts without a hypervisor of their own first for a default machine, ADR 0088). A seed is used only when it is on the chosen host; a region with room but no usable seed is `cold`, never a seed of another region.

**The decision is a registry record, written before the answer.** Keyed `(namespace, id)`: fingerprint of the canonical body, answer (host, region, mode, seed), phase, dispatched roles, time. Saved before the 200 (ADR 0043), so a restart cannot lose a decision a caller was told. The namespace pin is made in the same save.

**Replay returns the original answer, whatever the fleet looks like now.** The same `id` and an equal body: 200 with the stored decision, no new walk, no new count. A different body: 409 `conflict` (`admission request identity conflict`). A cancelled id: 409. The decision does not follow capacity: a region that has since filled, or one added with higher priority, changes nothing for an id already answered.

**Dispatch goes through the admission.** The gateway `PUT` and the create carry `x-briqyard-placement-request-id: <id>` (the header seed admission already uses). The fleet checks the admission exists, is not cancelled, the request's `region` equals the decision's, and the request is one of the admitted requirements (same role, same size, volume, class, profile). A mismatch is 409 and nothing is forwarded. There is no new walk: the host is the decision's. Marking the role dispatched happens before the host is asked, as ADR 0076's dispatch does; the first dispatch of any role ends cancellation.

**Capacity is held from the decision to the dispatch.** The admission takes one hold for the sum of the requirements (ADR 0044), so two admissions cannot be answered for the same last slot. A dispatch converts its part of the hold; the rest goes with the other role's dispatch. The hold is in memory, as holds are, and has a deadline (`admission_hold`, 10 minutes by default) pruned by the heartbeat, with no timer of its own (ADR 0119). After the deadline or a fleet restart the decision stands and the dispatch checks the admitted host's room again, as a create does. If the host has none: 503 `capacity`, the pin and the decision kept (the namespace is not unpinned: the control plane has already recorded the region). The caller retries; it never re-admits elsewhere. This narrows the window to the hold's life; it cannot close it, and the ADR does not claim it does.

**Cancel is `DELETE` on the same path, only before any dispatch.** It releases the hold and tombstones the id. The pin is released too when the namespace has no machine, no gateway, no other pending admission and no route; otherwise it stays (another member may need it). After any role was dispatched: 409 `admission already dispatched`. An uncertain dispatch keeps its decision: the control plane adopts in the admitted region only (ADR 0076's rule for routes). A pending admission nobody dispatched or cancelled is cancelled by the heartbeat after the replay window (24 h, ADR 0119), pin and hold released under the same rule.

**Concurrent first members share one binding.** Two admissions for one namespace serialize on the registry lock: the first pins it, the second answers `existing` and is accounted on that host. The second's requirements not fitting is 503 `capacity`.

**Never a fallback on anything but confirmed capacity.** The fleet's walk reads its own registry; it does not turn an authentication, authorization, policy, capability, validation or transport failure into a capacity class. Those keep their codes (401/403, `quota`, `capability_unsupported`, 400, 5xx) and end the request.

**The wire is additive (ADR 0027).** The fleet advertises `placement_admission_v1: true` in its status. A caller that does not see it does not call the route and places as before; an older fleet answers 404 and the caller treats that as the capability absent, not as capacity. Hosts and the daemon change nothing. The OpenAPI fragment and `FLEET-OPERATIONS.md` ship with the code, with a CLI column if the CLI lists admissions.

## Failure matrix

| Situation | Answer | Stored | Another region tried |
|---|---|---|---|
| Preferred region has room | 200 `new`, preferred | decision, pin, hold | no |
| Preferred `full`, next has room | 200 `new`, next | decision, pin, hold | yes, after confirmation |
| All regions `full` | 503 `capacity`, each class | nothing | all, in order |
| A host of the preferred region is down or stale | 503 `capacity`, `region_unconfirmed` | nothing | no |
| First region `ineligible` | 409 `capability_unsupported` | nothing | no |
| Namespace pinned, fits | 200 `existing` | decision, hold | no |
| Namespace pinned, does not fit | 503 `capacity` | nothing | no |
| Same id, same body, any time | 200, original | — | no |
| Same id, other body | 409 | — | no |
| Gateway fits, consumer does not | 503 `capacity` (the sum is checked) | nothing | next region by the same rule |
| Dispatch after the hold expired, host full | 503 `capacity` | decision kept | no |
| Dispatch reply lost | decision stays `dispatched`; the caller adopts or retries the same id | decision | no |
| Cancel before dispatch | 204 | tombstone | — |
| Cancel after dispatch | 409 | — | — |
| Restart between answer and the caller's save | replay returns the same decision | decision | no |
| No token configured | 409 `capability_unsupported` | — | — |

## Tests that gate the change

Registry-level unit tests, then `hack/fleet-two-hosts.sh` extended with two regions:

- each row of the matrix, with two regions of two hosts each;
- the gateway-plus-consumer sum decides the region (consumer alone would fit the preferred one);
- two concurrent admissions for one new namespace end on one host;
- a replay after the preferred region filled returns the original region;
- a registry restored from backup returns the same decision (ADR 0032);
- a seed on another region's host is never selected, including when it is the only seed that fits;
- a stale host in the preferred region refuses and does not place elsewhere;
- a pruned admission whose route is kept is not pruned (ADR 0119);
- after a refusal the registry is byte-identical to before.

## Consequences

- The control plane persists the answer (`region`, `host`) before it asks for a gateway or a machine, and never calls `place` again for that id. That is the one place fallback is decided.
- A namespace's first dispatch can still be refused for capacity after a decision (hold expired, restart). The control plane must treat it as retryable in the admitted region, not as a signal to re-admit.
- The fleet holds capacity for admissions that are never dispatched, up to 10 minutes, and a tombstone and a pin up to 24 hours. Both are bounded by the heartbeat's pruning.
- The routes of seed admission and the general one overlap in purpose. Folding the seed route into this one (a seed is a requirement) is a later ADR once this one has run for a release; it is not done here so that ADR 0076's contract keeps its qualification.
- Not decided here, and left to the control plane: what a "preference" means to a person, what is shown, and what is promised about where data lives. This ADR promises only that a decision is durable and that a refusal leaves nothing behind.
- Reopen when a region needs weights (spread, not order), when a host can serve a namespace's requirements across two hosts, or when holds should survive a restart.

## Open points for review

1. **First region `ineligible` refuses.** Alternative: skip it like a later region. Chosen to keep a preference from weakening today's behaviour; the cost is a refusal where another region could serve.
2. **`unconfirmed` stops the walk.** Alternative: treat a down host as no capacity. Chosen because an outage must not move placements; the cost is a refusal while a host is down.
3. **Hold deadline of 10 minutes.** Chosen above a gateway-then-consumer sequence at the control plane's job cadence; to be measured with the first control plane that uses the route.
4. **Whether the execution-channel work (ADR 0045) needs the answer's `host` to select a regional gateway.** The answer carries it; no regional gateway authorization is defined or assumed here.

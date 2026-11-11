# ADR 0128: One placement admission for a namespace's first requirements, across an ordered list of regions

Date: 2026-11-10 · Status: accepted; implemented in `briqyard-fleet` (see Amendments) · Builds on ADR 0013 (placement reserves what it places), ADR 0025 (a namespace never spans regions), ADR 0044 (holds), ADR 0056 (a fork is made on its source's host), ADR 0076 (seed admission), ADR 0119 (what the registry forgets)

## Context

A control plane that offers a region *preference* needs the fleet to answer one question: where can this namespace's first machines go, trying the regions in this order, without leaving anything behind in a region it then abandons?

Today it cannot ask:

| Fact | Effect |
|---|---|
| `POST /v1/machines` names one `region`; a `503 capacity` is the answer for it | A caller that retried in another region would do so after `place` pinned the namespace and a hold was taken |
| A first machine's `capacity` answer unpins the namespace (ADR 0013), but the daemon may have made the namespace's network before it refused | A refusal does not prove nothing was created. Only the fleet's own check, before any host is asked, does |
| A credential gateway belongs to the namespace (ADR 0016) and its `PUT` pins the namespace before the consumer's create | The gateway can land in a region the consumer does not fit in; the pair is placed in two steps |
| Seed admission (ADR 0076) freezes one region, one size and one seed | It does not account for the gateway, a volume, a runtime class or an ordered list of regions |
| A write with no answer may have completed | A missing machine or a namespace 404 does not authorize another dispatch somewhere else |

Catching `capacity` around the machine POST and trying the next region is refused: the refusal is not proof of no effect, and the retry has no durable identity.

## Decisions

**A placement admission is a durable decision, made once, under the registry lock, before any host is asked to create.** `PUT /v1/namespaces/{ns}/admissions/{id}`, authenticated like seed admission (`capability_unsupported` without a configured token). `id` is the caller's request identity (`valid_sandbox_request_id`), unique per namespace.

It is a record of the same table as seed admissions, with a `kind` (`#[serde(default)]` to `seed`, so every record written before loads; `placement`). The placement body is its own type: the seed `Request` denies unknown fields and requires a seed. An older fleet reads the record as a seed's (its unknown fields are ignored). A cold record, or one past `pending`, fences nothing there. A record with mode `sandbox-seed`, phase `pending` and a host satisfies the older fleet's `pending_seed()`: it fences its namespace and host there, the older prune never forgets it, and a dispatch under it answers 409 `admission cancelled` (the record has no seed request). The older fleet also cannot load the new `expired` phase. So a rollback below this change waits until no placement admission is pending and the tombstones have been pruned (`FLEET-OPERATIONS.md` says so). One key `(namespace, id)`, one meaning: a `PUT` of either kind to an id held by the other, or to a cancelled id, is 409; a cancel of an unknown id writes a tombstone both kinds find. Pruning, the header check and the fences below read that one table. The seed route (`sandbox-admissions`) and its contract do not change.

```json
{
  "regions":      ["region-a", "region-b"],
  "requirements": [
    {"role": "gateway",  "size": {…}, "runtime_class": "default"},
    {"role": "consumer", "size": {…}, "volume_gb": 20, "runtime_class": "default",
     "memory_profile": "init-ready-v1", "egress_siblings": false,
     "sandbox_seeds": [{"machine_id": "…", "snapshot": "…", "generation": "…"}]}
  ]
}
```

`regions` is non-empty, without repeats, in the caller's order: an allowlist and a preference, nothing else. `requirements` lists everything the namespace's first dispatches will ask for, the gateway included, at most one `gateway` and one `consumer`, with the fields the create already carries (size, volume, runtime class, memory profile, `egress.siblings`, seeds). The fleet reuses the predicates `place` and `create_machine` apply today; it does not copy them.

```json
{"region": "region-a", "host": "h_…", "binding": "new", "mode": "cold",
 "regions": [{"region": "region-a", "outcome": "placed"}]}
```

`binding` is `new` (the admission pinned the namespace) or `existing` (it already was). `sandbox_seeds` belong to the `consumer` requirement only, and so do `mode` (`sandbox-seed` or `cold`, as in ADR 0076) and `seed`, the selector used. `regions` lists the outcome of each region walked; it is evidence, not a promise.

**Resolution order: binding first, preference second.**

1. A namespace already pinned: the answer is its host and region, `binding: existing`, whatever `regions` says. The requirements must fit that host (the arithmetic of step 3 on one host); if not: 503 `capacity`. A stack is never split.
2. A fork, restore or volume source keeps today's path (a create without an admission): the control plane does not admit what it can resolve itself.
3. Otherwise walk `regions` in order. A region is classified from its hosts, once:

| Host | Counts as |
|---|---|
| ready, fresh, serves every requirement, has room for **their sum** (physical memory reservation, CPU, disk) | `placed` candidate |
| ready, serves them, no room under the host's fill ceiling, or under a pressure condition | `full` (pressure is a capacity signal today, ADR 0042) |
| down, stale, `upgrading`, or ready with its memory policy unresolved, and it served the requirements at its last report | `unknown`; tested before `full`, because `pressure()` includes the unresolved policy |
| draining, retiring, failed, never reported, `joining`, `provisioning`, `bootstrapped` | ignored: an operator decision, or not capacity yet |
| ready and serving nothing the requirements need | ignored |

| Region class | When | Walk |
|---|---|---|
| `placed` | at least one `placed` candidate, whatever the other hosts are | stop; pick the host as `place` does (most free memory; a default machine avoids hosts with a hypervisor of their own first, ADR 0088), preferring one that holds a validated seed (below); pin, hold, store |
| `unconfirmed` | no candidate, at least one `unknown` host | stop: 503 `capacity`, `reason: region_unconfirmed`. The next region is **not** tried |
| `full` | no candidate, no `unknown`, at least one `full` host | next region |
| `ineligible` | no host counted at all (none serves the requirements, or the region has no usable host) | **first region**: its own refusal, as a single-region create gives today (409 `capability_unsupported`, 400 for a runtime class no host serves, 503 `capacity` for a region with no host). A later region: skip it |

Why the first region may not be `ineligible`: a preference must not weaken what a single region refuses today. Why `unconfirmed` stops the walk: an outage is not proof of no capacity; the caller sees a refusal and retries later, never a placement elsewhere. A draining or retiring host (ADR 0027) is an operator decision, not an outage.

4. The walk ends without `placed` (the first region was not `ineligible`, step 3 refused otherwise): 503 `capacity` naming each region's class. A first region that was `full` with every later region `ineligible` is a shortage, not a capability error: 503 too. **A refusal stores nothing.** It is counted as `capacity` in each region found `full` (ADR 0042), once per request.

**Seeds are checked before the walk and rechecked inside it.** `check_sandbox_selector` asks the seed's host over the network, so it runs before the lock, as seed admission does. A seed whose check fails (not found, mismatched, host unreachable) is dropped from the candidates: the placement is `cold` if no seed remains, never a class and never an error for the walk. Under the lock the chosen host must still be the seed's host; if not, the mode is `cold`. Within a region a host that holds a validated seed and has room is preferred over the host `place` would pick; a seed is never used on another host, so never in another region.

**The decision is a registry record, written before the answer.** Keyed `(namespace, id)`: kind, fingerprint of the canonical body, answer (host, region, mode, seed), phase, dispatched roles, time. The answer is the decision only once it is saved (ADR 0043). A failed save is a 5xx with the state in memory uncertain: the caller sends the same id again and gets the same decision if the fleet still holds it, or a fresh walk if it restarted, which is safe because nothing was promised or dispatched.

**The pin outlives the heartbeat while the admission is pending.** Today a pin is kept by moves, pending seed admissions, unaccepted routes, a host that lists the namespace, or ten minutes (`registry/mod.rs`). A `placement` admission is **pending while any of its requirements is neither dispatched nor cancelled**, not only before the first dispatch (the seed admission's single phase flips at the first). While pending it is a fence in every place a pending seed admission is: heartbeat reconciliation, the `named` set of `Registry::prune`, `forget`, operator unpin and namespace delete (which refuse), and the dispatch fences of `create_replay.rs`. When the last requirement is dispatched, its create's hold and route fence the namespace as for any create. Without it, a decision would stand for a day while its pin expired in ten minutes and the next member could be placed in another region.

**Replay returns the original answer, whatever the fleet looks like now.** The same `id` and an equal body, for as long as the record is kept: 200 with the stored decision, no new walk, no new count. A different body: 409 `conflict` (`admission request identity conflict`). The decision does not follow capacity: a region that has since filled changes nothing for an id already answered.

**Dispatch goes through the admission.** The gateway `PUT` (as `placement_request_id`, the query parameter it already takes) and the create (the `x-briqyard-placement-request-id` header) carry the id. The fleet checks the admission exists, is not cancelled or expired, the request's `region` equals the decision's, and the request is the admitted requirement of its role: the gateway `PUT` is the `gateway`, a machine create is the `consumer` (same size, volume, class, profile). A create carries no role; the route does. A dispatch repeated for a role already dispatched is the caller's retry (the create's name is its idempotency key, ADR 0048; a repeated gateway `PUT` replaces the same gateway) and takes no new hold. A mismatch is 409 and nothing is forwarded. There is no new walk: the host is the decision's. Before marking the role dispatched, the fleet checks that host's room for that requirement itself, as the unbound path does; a pinned host is returned unchecked by `place` today, so the check is new. If it fails: 503 `capacity`, role not marked, decision and pin kept.

**The gateway `PUT` becomes a dispatch.** Today only a create marks an admission dispatched. With a `placement` admission the gateway `PUT` marks the gateway role dispatched before the host is asked, because it creates the namespace's network on the host. Cancellation ends with the first dispatch of any role. This is new behaviour of the gateway route, only when it carries a `placement` id. A quota `PUT` shares the gateway's query and also makes the namespace on its host: with an id it is checked like the gateway `PUT` and ends cancellation, consuming no requirement.

**Capacity is held from the decision to the dispatch, one hold per requirement.** Each requirement takes a hold (ADR 0044) at the decision, tagged with the admission and given a deadline (`placement.admission_hold_sec`, 240 by default) that the heartbeat prunes, with no timer of its own (ADR 0119). Two admissions cannot be answered for the same last slot. A dispatch converts its requirement's hold: it recomputes the physical reservation with the host's current policy, takes it from the hold, clears the deadline (so the heartbeat cannot prune a hold mid-forward) and calls `made`; the room check counts the requirement's own hold as already taken, never twice. The other requirement waits for its own dispatch. Admission holds do not count in `memory_policy_unresolved`: that predicate asks about creates in flight, not decisions waiting. Holds are in memory, as holds are. After the deadline or a fleet restart the decision stands and the dispatch's room check (above) is the only guard. This narrows the window to the hold's life; it cannot close it, and this ADR does not claim it does.

**Cancel is `DELETE` on the same path, only before any dispatch.** It releases the holds and tombstones the id. The pin stays, as seed cancel keeps it: another member or a gateway not yet reported by its host may need it, and the heartbeat's rule releases it once nothing names the namespace. After any role was dispatched: 409 `admission already dispatched`. An uncertain dispatch keeps its decision; the control plane adopts in the admitted region only.

**A pending admission expires after the replay window** (24 h, ADR 0119) counted from its last change (the decision, its first dispatch, or a role newly dispatched; a retried role or a repeated quota `PUT` is not a change). It applies to placement admissions only: a seed admission pending stays a fence until its create is dispatched or it is cancelled, as before. This covers a partly dispatched one too, a gateway dispatched and a consumer never: the fence and the remaining hold are released, the id tombstoned, and the pin follows the heartbeat's rule for a namespace the host lists. A requirement already dispatched is not undone; its machine is the caller's to destroy. Operator unpin and delete refuse only until then. A late dispatch with that id is 409 `admission expired` until the tombstone is pruned (another window, ADR 0119), then 409 `placement admission missing`, and a `PUT` of the pruned id walks afresh like a new id. The control plane may then admit under a new id; nothing was dispatched under the old one, so a fresh walk is correct.

**Concurrent first members share one binding.** Two admissions for one namespace serialize on the registry lock: the first pins it, the second answers `existing` and is accounted on that host. If the second's requirements do not fit, 503 `capacity`.

**Never a fallback on anything but confirmed capacity.** The walk reads the fleet's own registry; it does not turn an authentication, authorization, policy, capability, validation or transport failure into a capacity class. Those keep their codes (401/403, `quota`, `capability_unsupported`, 400, 5xx) and end the request.

**The wire is additive (ADR 0027).** The fleet advertises `placement_admission_v1: true` in its status. A caller that does not see it does not call the route and places as before; an older fleet answers 404 and the caller treats that as the capability absent, not as capacity. Hosts and the daemon change nothing. The OpenAPI fragment and `FLEET-OPERATIONS.md` ship with the code.

## Failure matrix

| Situation | Answer | Stored | Another region tried |
|---|---|---|---|
| Preferred region has room | 200 `new`, preferred | decision, pin, holds | no |
| Preferred `full`, next has room | 200 `new`, next | decision, pin, holds | yes, after confirmation |
| All regions `full` | 503 `capacity`, each class | nothing | all, in order |
| A host that served the requirements in the preferred region is down or stale, none has room | 503 `capacity`, `region_unconfirmed` | nothing | no |
| First region `ineligible` | its own refusal | nothing | no |
| Namespace pinned, fits | 200 `existing` | decision, holds | no |
| Namespace pinned, does not fit | 503 `capacity` | nothing | no |
| Same id, same body, while the record is kept | 200, original | — | no |
| Same id, other body or other kind | 409 | — | no |
| Gateway fits, consumer does not | 503 `capacity` (the sum is checked) | nothing | next region by the same rule |
| Dispatch after the hold expired, host full | 503 `capacity`, role not marked | decision, pin kept | no |
| Dispatch reply lost | decision stays `dispatched`; the caller adopts or retries the same id | decision | no |
| Cancel before dispatch | 204 | tombstone, pin kept | — |
| Cancel after any dispatch, gateway included | 409 | — | — |
| Dispatch after expiry | 409 `admission expired` | tombstone | a new id may walk afresh |
| Gateway dispatched, consumer never | fence held until expiry (24 h from the last change), then released | decision | no |
| First region `full`, later regions `ineligible` | 503 `capacity` | nothing | no |
| Save fails | 5xx; same id again | uncertain | no |
| Restart after the saved answer | replay returns the same decision | decision | no |
| No token configured | 409 `capability_unsupported` | — | — |

## Tests that gate the change

Registry-level unit tests, then `hack/fleet-two-hosts.sh` extended with two regions:

- each row of the matrix, with two regions of two hosts each;
- every host state of the table classifies as written, including a mixed region (one candidate, one down host places);
- the gateway-plus-consumer sum decides the region (the consumer alone would fit the preferred one);
- two concurrent admissions for one new namespace end on one host;
- a replay after the preferred region filled returns the original region;
- a registry restored from backup returns the same decision (ADR 0032);
- a seed on another region's host is never selected, including when it is the only seed that fits; a seed check that fails yields `cold`;
- a pending admission's pin survives the heartbeat, `forget`, unpin and delete; a cancelled one's pin follows the heartbeat rule;
- a gateway `PUT` with an id ends cancellation;
- a pending admission with a kept route is not pruned (ADR 0119);
- after a refusal the registry is byte-identical to before.

## Consequences

- The control plane persists the answer (`region`, `host`) before it asks for a gateway or a machine, and does not walk again for that id. This is the one place fallback is decided.
- A namespace's first dispatch can still be refused for capacity after a decision (hold expired, restart). The control plane treats it as retryable in the admitted region, not as a signal to admit again elsewhere.
- The fleet holds capacity for admissions that are never dispatched, up to 4 minutes, and a fence up to 24 hours. Both are bounded by the heartbeat's pruning.
- The seed route and this one overlap in purpose; they share a table and a key. Folding the seed route into this one (a seed is a requirement) is a later ADR, once this one has run for a release, so that ADR 0076's qualification stands.
- Not decided here, and left to the control plane: what a preference means to a person, what is shown, and what is promised about where data lives. This ADR promises only that a decision is durable and that a refusal leaves nothing behind.
- Reopen when a region needs weights (spread, not order), when a namespace's requirements could span two hosts, or when holds should survive a restart.

## Open points for review

1. **First region `ineligible` refuses.** Alternative: skip it like a later region. Chosen so a preference does not weaken today's behaviour; the cost is a refusal where another region could serve.
2. **`unconfirmed` stops the walk.** Alternative: treat a down host as no capacity. Chosen because an outage must not move placements; the cost is a refusal while a host is down, however many other regions have room.
3. **Hold deadline of 4 minutes (first draft: 10).** Chosen above a gateway-then-consumer sequence at a control plane's job cadence; to be measured with the first control plane that uses the route.
4. **The answer's `host`.** It is returned for evidence and for a regional execution gateway to select on; no gateway authorization is defined or assumed here.

## Amendments

Made while implementing, none of which changes a decision above:

- **Rollback.** The first draft said an older fleet cannot load a registry with a `placement` record. It can: `kind` and `placement` are unknown fields to it, and the record reads as a seed admission: not fenced when cold or past `pending`, fenced (and answering 409 `admission cancelled` to a dispatch) when it is `sandbox-seed` and `pending`. What it cannot load is the `expired` phase this change adds. The Decisions paragraph and `FLEET-OPERATIONS.md` now say so.
- **Config.** The hold's deadline is `placement.admission_hold_sec` (seconds, default 240), next to `down_after_sec`.
- **The create's memory profile** is the field the create already carries for it, `template_build`; a seeded consumer is matched on its selector instead (a seed create names `sandbox_seed`).
- **A dispatch converts the hold** by taking the requirement's hold off the host before the room check and putting the ordinary create (or gateway) hold in its place under the same lock; on a failed check the admission hold is restored.
- **Expiry** is a phase (`expired`) of the same record, pruned with the other tombstones, not a second table.
- **Hold deadline, 2026-11-11.** The default of `placement.admission_hold_sec` is 240 seconds, down from 600. A briq with a credential gateway waits up to 180 seconds between the gateway PUT and the consumer create; 240 covers that with margin while giving abandoned holds back sooner. One minute was rejected: a slow gateway would lose the consumer's hold.

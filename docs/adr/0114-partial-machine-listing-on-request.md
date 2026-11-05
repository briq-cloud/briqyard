# ADR 0114: A machine listing may be partial, when the caller asks

Date: 2026-11-05 · Status: accepted; supersedes ADR 0006's "a listing is never partial" for machines

## Context

ADR 0006 made every fleet listing all-or-nothing: a host that is down or silent fails it, because a reader that takes a machine missing from a listing for gone must never see one missing for that reason. The rule is right for such a reader and costly for the others. A lookup by label (`?label=…`) asks every host; one host down fails it for every namespace, though the answer a caller needs may sit on the hosts that are up.

## Decision

**`GET /v1/machines?partial=true` skips a host that did not answer.** It also holds with `namespace=`, `tenant=` and `label=`.

- A host is skipped when it is `down`, unreachable, answers 5xx or answers a body that is not a listing. A 4xx (a bad label, a bad token) still fails the listing: every host would say it.
- The answer is `200`, the body as before (an array, `host` on each machine), plus `x-briqyard-unanswered-hosts: h_a,h_b`, the skipped hosts sorted by id. A `200` without the header is complete.
- A namespace listing asks its host alone: with that host down it is `200`, `[]` and the host in the header.
- Hosts that answered are learned as before (the registry's machine → host entries).
- The daemon ignores query parameters it does not know (`list_query`, `crates/briqyardd/src/api/machines.rs`), so `partial` is forwarded as it came.
- Without `partial=true` nothing changes: the first failure is the answer. Endpoints, backups, usage, top and events stay strict.

**A client that opts in reads absence as unknown, never as gone.** A machine missing from a partial listing may be on a host in the header, or on none; only a complete listing says it is gone. A caller that cannot keep that distinction does not send the parameter.

## Alternative considered

A fleet-side cache of the last machines each host reported, served for a host that is down. The listing would never fail and never say what is stale. It adds state the registry does not hold (machine contents, their age and when to drop them) and returns a machine that was destroyed meanwhile as present, the opposite error. Telling the caller which hosts are missing costs one header.

## Consequences

- A caller that handles a partial answer gets the machines of the hosts that are up while one is down.
- The strict default keeps every existing reader as safe as before.
- The header is the whole contract: a caller that ignores it has the strict-listing hazard back.

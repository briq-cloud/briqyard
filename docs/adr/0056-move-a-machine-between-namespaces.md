# ADR 0056: A machine moves between namespaces

Date: 2026-10-29 · Status: accepted for moves on one host; the move across hosts is not yet (below); follows ADR 0055 (the word), see ADR 0045 and the procedure in `OPERATIONS.md` ("Moving a namespace") for another host

## Context

A machine's namespace is set at its create. A control plane that makes one namespace per stack needs to put a machine in another one: a stack's service promoted into another stack, a machine that started alone and now joins its neighbours, a branch of a stack forked into a namespace of its own. Until now the only way was to destroy it and make it again, losing its address, its endpoints and its id.

No move operation existed on a host: moving between hosts is the operator's procedure (backups, destroys, `namespace unpin`, restores, `OPERATIONS.md`). This ADR adds a move to the machine API for one host. The cross-host case was built first as the same procedure run by the fleet, reviewed and taken out until it is designed properly ("Not yet").

## Decisions

**`POST /v1/machines/{id}/move` with `{ "namespace": "<target>" }`** on the daemon and the fleet, `briqyard machine move <id> --namespace <ns>`. The answer is a `MoveResult`: the machine as it is, `from` (the namespace it left), `previous_ip`, `restarted`. A namespace id is checked as at a create; the target may not exist yet. Moving into the namespace the machine is in does nothing and answers the same shape. `If-Match` is checked as for a stop.

| Case | What happens | Address | Restart |
|---|---|---|---|
| Alone in its namespace (no other machine, no gateway) and the target does not exist | the namespace is renamed: its record, the machine's, its endpoints'; the quota goes with it | same | no |
| The target exists on the host, or does not and the machine is not alone | a running machine is stopped, takes a free address of the target's network (made when new), starts again; its disks, name, endpoints and id are kept; a machine that was not running stays so | new | `restarted: true` when it ran |
| Through the fleet, the target pinned to another host | refused before anything happens: 409 `other_host`, naming both hosts ("moving across hosts is not supported yet") | | |

The fleet decides from its registry (namespace to host pins): a target pinned to another host is refused (third row), any other is the host's. A target the fleet does not know is pinned to the machine's host once the host made it.

**The rename is a rename.** The bridge, the subnet, the gateway's DNS and every address stay. In memory it is one step under the machines' lock (both names resolve at every instant; a create that read the old name is refused with a 409 and repeated, `add_machine`); on disk the new namespace record is written, then the machine's and its endpoints', then the old record deleted. A crash in between leaves two records on one subnet: the next start keeps the one a machine names (`drop_renamed_leftovers`). Usage up to the move is metered into the namespace it left first, so a bucket never mixes two.

**The restart is a stop and a start, not a hot move.** A guest's address is in its running kernel and its memory: no live change is correct, and Firecracker offers none. A machine is stopped as `machine stop` stops it (its process asked to end, then killed), the record takes the new address (the counters follow it: `uncount` the old, `count` the new), the namespace's names are republished, the start is a start (its quota, its memory, its gateway and its `via` are checked as any start's). A memory snapshot of the machine would resume on the old address: a move is refused (409) while one exists, and a suspended machine's next start is a boot.

**What refuses, and leaves everything as it was** (checked before a running machine is stopped): a machine that is creating, starting, stopping or destroying (`bad_state`); the namespace's gateway (the gateway's own route); another machine of the namespace whose `egress.via` names this one (409, change it first); an `egress` that cannot be kept in the target (`via` a machine of another namespace, or the gateway of a namespace without one; 400); the target's name taken (409) or quota (403); no address left (503). A start refused after the stop (memory, quota) leaves the machine stopped in the target and says why, as a restart does. A refusal in the window after the stop (a name taken meanwhile, the quota again, the counters of the new address) starts a machine that ran again, in the namespace it was in: "as it was".

**Another host: not yet.** Through the fleet, a target pinned to another host is refused before anything is touched (409 `other_host`: "the namespace X is on host B; moving across hosts is not supported yet"). Until then the operator's procedure applies (`OPERATIONS.md`, ADR 0045), which is a backup, a destroy and a restore under a new id. The fleet's version (stop, backup, restore there, destroy the source) was written and not shipped: a review found it could lose data, and it is not a thing to patch. What it needs:

- **A background job the caller polls**, not an HTTP handler that a hang-up drops mid-way; a move lasts minutes.
- **A journal** in the registry (source, backup, copy, step), so a fleet restart resumes or rolls back and never leaves the source stopped, two machines of one name, or a source gone with no endpoints.
- **The source held stopped** (no wake by a connection, no start) from the backup until the copy is verified, by the daemon, not by a check before the destroy.
- **One operation per machine at a time**: a second move, a start or a destroy of that machine is refused (409) while a move holds it.
- **The source destroyed only after the copy runs**, and a failed destroy of the source never destroys the copy: ask the source's state first.
- **Cleanup results reported**: a copy that cannot be destroyed stays in the registry and the error says so; endpoints that cannot be made again are listed in the result.
- **Snapshots are not carried**: disk and memory snapshots stay with the source and go with it; its backups stay held under the old id. The machine has a new id (a restore makes one).
- "Verified" must say what it checks (running, a readiness probe), not only that the restore succeeded.

**A fork may name a namespace.** `POST /v1/machines` with `fork` and a `namespace` other than the source's makes the copy in that namespace, on the source's host (a fork clones the source's ZFS snapshots, which only exist there): the quota, the name and the address are the target's. Through the fleet, a target pinned to another host is refused (400 `invalid`, naming both hosts) rather than copied through a backup: a fork asks for a snapshot taken now and a clone, and a fork that is a restore would be another operation under the same name. A target that is new is pinned to the source's host at the create, so the stack's next fork into it lands with the first. The daemon cannot tell who owns a namespace (it is a string); that a target belongs to the same owner is the control plane's check.

**Kept consistent**

| | After a move |
|---|---|
| Events | one `moved` event in the namespace left (about the machine) and one in the namespace joined, which is the machine's own and moves its `version`; `data` has `from`, `to`, `previous_ip`, `ip`, `restarted`. Past events keep the namespace they were logged in |
| Quota | the target's is checked (machines, disk, and memory and vCPUs of a machine that runs); the source's use falls with the machine. A rename carries the quota |
| Usage | hourly buckets keep the namespace they accrued in; the next ones carry the new name. Backups listed by namespace follow the machine, as `all_backups` reads its record; a backup's stored `namespace` stays the one it was made in |
| Endpoints | `EndpointRec.namespace` follows; the ingress dials the machine's address when a connection arrives, so a new address needs nothing |
| Gateway, egress | a rename never has a gateway (not alone); a machine `via: gateway` moves only to a namespace with one; its policy is rendered again at the start; the source's gateway stays with the source |
| Metrics | the `namespace` label of the machine's series changes from its next scrape; `briqyard_namespaces` counts the namespaces the host has |
| The namespace left | stays, empty, until `namespace rm`, as when its last machine is destroyed; the control plane removes it |

## What Kubernetes does

A pod's namespace is immutable: to put a workload in another namespace you delete it and create it again, and its address, its volume claims' bindings and its identity are new. That is right when a pod is cattle and a controller recreates it; it is wrong here, where a machine is a named disk with state that its owner moves between stacks, and recreating it is a backup, a destroy and a restore the caller would write anyway, badly. Where the move can be exact (a rename, or a restart on the same disks) briqyard does it and keeps the id; where it cannot (another host) it is not offered yet.

## Rejected

| Alternative | Why not |
|---|---|
| Delete and recreate, as Kubernetes | The caller would need the backup, the endpoints and the id mapping; the same-host cases need no copy at all |
| A hot move of a running machine | The guest's address lives in its kernel and memory; there is no correct live change |
| Keep the old address for a join | It belongs to another network's /24; a join is a new address by definition |
| The move across hosts in the HTTP handler, as first written | Data loss on a hang-up, a crash or a concurrent call ("Not yet") |
| A fork across hosts through a backup | A fork is a clone of a snapshot taken now; through a backup it would be a restore with another name. Refused with both hosts named |
| Move a gateway's machine with its namespace | The gateway is the namespace's, run by the daemon; a rename of a namespace with a gateway would rename a machine nobody asked about. Such a machine joins a new network and the gateway stays |
| Remove the namespace left at once | `namespace rm` is the control plane's call today for every last machine; a move is no different |

## Consequences

- A control plane renames a stack's namespace by moving its only machine, joins a machine to a stack with one call, and learns from `restarted` and `previous_ip` what it must update.
- A machine on another host's namespace is not moved by one call: the control plane places the namespace's machines on one host, or uses the operator's procedure.
- The registry's pin for the namespace left stays until the host stops listing it; a create into the old name lands on the same host, which is right.
- Tests: the daemon's (rename, join with a new address and moved counters, a stopped machine, a refused move changing nothing, `via`, a gateway, a rename cut short, a fork into a namespace), the fleet's (within a host, across hosts refused with nothing sent, a fork across hosts), a refusal after the stop starting the machine again, the CLI's parsing; `hack/e2e.sh` and `hack/fleet-two-hosts.sh` run them on real hosts (counts predicted until a VM run).

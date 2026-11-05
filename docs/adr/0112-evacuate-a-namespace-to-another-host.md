# ADR 0112: A namespace is evacuated to another host, under its own ids

Date: 2026-11-05 · Status: proposed · amends ADR 0056 ("Another host: not yet"), ADR 0008 and ADR 0035 (a restore under the backed-up id), ADR 0023 (pruning after an evacuate); fills the "Drain with eviction" row of `KUBERNETES-MAP.md`

## Context

A host leaves the fleet: retired, replaced, patched. Its machines must go on elsewhere. Today `host drain` stops placement and nothing more (Kubernetes's cordon, ADR 0027). Moving what is there is the operator's procedure in `FLEET-OPERATIONS.md` ("Moving a namespace"): back up, destroy, `namespace rm`, restore. It gives every machine a new id and a new namespace, destroys the source before anything is checked, and leaves a window where a heartbeat pins the name back on the old host. A control plane that keeps a public id per machine must then rewrite its mapping by hand. ADR 0056 refused the cross-host move of one machine for these reasons and listed what a real one needs: a background job, a journal, the source held, one operation at a time, the source destroyed last, verification that says what it checks.

What is fixed by the design: a machine's disks are ZFS zvols in a pool encrypted per host (ADR 0026). Backups are raw sends to a shared object store, incremental, their record sealed; another host of the fleet restores them with the key the fleet serves once, for a restore it forwarded (ADR 0035). A namespace is pinned to one host and carries its network, its gateway and the gateway's CA (ADR 0016); its machines reach each other by name on that host only. A restore is a create (ADR 0008): it makes a new id. Sandbox seeds (ADR 0076) and warm slots (ADR 0074) are host capacity, built by the operator, not owner data.

`kubectl drain` is the model: cordon, then evict every pod; the controller recreates it elsewhere. The difference is the one of ADR 0056: a machine is a named disk with state, so "recreate elsewhere" is a copy that must keep the identity.

## Decision

**The unit is the namespace, never one machine.** A namespace is on one host by construction. Moving one of its machines would split it: two networks, two gateways, names that do not resolve. `namespace evacuate` moves a whole namespace: every machine, its quota, its gateway declaration, its endpoints. The move of one machine into a namespace pinned to another host stays refused (ADR 0056, `other_host`): move it within the host first, or evacuate its namespace.

**Two verbs, both in the fleet.**

| Verb | What it does |
|---|---|
| `briqyard host drain <host>` | unchanged: cordon. Nothing new lands; what is there goes on |
| `briqyard namespace evacuate <namespace> [--to <host>] [--drop-snapshots]` | `POST /v1/namespaces/{id}/evacuate`: a job that copies the namespace to another host, verifies the copy, repoints the fleet, then removes the source |
| `briqyard host evacuate <host> [--parallel N]` | drain, then `namespace evacuate` of every namespace on the host, `N` at a time (default 1), stopping at the first that fits nowhere; the host is left `draining` with the rest listed. Kubernetes's `drain` |

The fleet runs it, not a script: it alone knows the pins, the keys, the hosts' room, and must keep them consistent while two hosts hold a copy. The daemons gain three primitives (below) and no policy.

**The same ids.** The copy keeps the namespace id, every machine id, every endpoint id, every name and label. A restore for an evacuate restores the whole record (name, labels, ports, probes, restart, backup policy, limits, egress, size, volume, files, env), not the subset a caller may override today (`inherit_run_config`). A control plane that maps a public id to `(machine, namespace)` changes nothing in that mapping. Ids are random, so adopting one on another host collides with nothing; the registry's index (machine → host, endpoint → host) is the one place that moves.

**What changes for the owner**: private addresses (another host's network; names stay, `previous_ip` and `ip` are reported per machine, as after a move), each endpoint's delivery address (the host's ingress; same id, port and token), memory state (a machine on the target boots; a memory snapshot does not travel), named disk snapshots (dropped, refused without `--drop-snapshots`), running exec sessions (cut). A control plane that stores an endpoint's delivery address reads its endpoints again after the job (`GET /v1/endpoints/{id}`, same ids) and tells its edge.

**Three daemon primitives, no policy in them.**

| Primitive | Contract |
|---|---|
| `POST /v1/machines/{id}/hold {job}` / `DELETE .../hold` | the machine is `held` by a job id, in its record, across a daemon restart. Phase 1 accepts only stopped machines. A backup already holding the machine's backup turn makes hold fail immediately with 409 `busy`; no hold is written. Hold takes that turn before the machine lock and checks the state again under the lock. Every backup checks the hold after taking its turn, including a requested backup queued before the hold. The holder may take the evacuation backup; scheduled backups skip a held machine. Held, it refuses start, exec, fork, move, resize, PATCH, snapshot, a scheduled backup and destroy with 409 `held` naming the job; the holder's calls carry the job id and pass. A second hold by another job is 409. Released by the holder, or by the operator with `--force` on the host |
| `restore` with `same_id: true` in a create | the machine takes the backed-up machine's id and its whole record. Refused when the id exists on the host (409). The fleet forwards it only inside an evacuate job that holds the source, so one id never runs twice |
| `POST /v1/machines/{id}/endpoints` with `id` | the endpoint keeps its id; the daemon gives it a port of its own host. Tokens and access mode belong to the control plane and remain there |

**The copy goes through the object store**, not a host-to-host stream. A backup while the machine runs (incremental where a chain exists), then a cold stop and a final incremental backup: the final send is the delta of the stop window, small. The restore on the target is the restore of ADR 0035: the key served once to that host for that backup, the receive checking the stream, a path native CI already runs. The backup stays in the store after the move, under the source's key: a second copy for free during the window the move is doubted. A direct `zfs send` between hosts over the private network would skip the round trip and is the faster path for a large running machine; it needs a new authenticated channel between hosts, a receive path of its own and firewall rules, and it leaves no copy behind. It is not built now: measure the store path first (phase 2 below); add the direct stream under the same journal if the measured downtime of a running machine is not acceptable.

A restore still passes create validation: its request uses the original DNS-label machine name, never the machine id (which contains `_`). Zero resource fields inherit from the backup. `start: false` is asynchronous: an ordinary restore moves through `creating` to `created`; an evacuation restore finishes `stopped` and held. The fleet waits for receive completion before comparing the restored record and disks. Draining the source prevents new placement there; evacuation placement still preserves the source region.

**The fleet's journal.** The registry holds `evacuations: namespace → {job, from, to, step, machines: [{id, backup, restored, verified, previous_ip, ip}], endpoints, started, error}`. Every step is written before and after its effect. The fleet writes the registry atomically (ADR 0032); a restart reads the journal and resumes the step it finds. Each step is idempotent: a backup whose id is in the journal and listed on the host is not taken again; a machine the target already has under its id is verified, not restored again; a destroy that answers 404 is done. One job per namespace; a namespace with an open job refuses a create, a move, a gateway change, an admission and a second evacuate (409 `evacuating`).

**One authoritative copy.** The journal owns machine and endpoint routing as well as the pin: before `switched`, only `from` is authoritative; from `switched` onward, only `to`. Machine and endpoint lists discard every non-authoritative copy before returning or indexing it. Locate consults the journal before its cache or host discovery; discovery rechecks authority under the registry lock before indexing its answer. Heartbeats, list replies and forwarded operations that began before the switch must recheck authority before publishing an index entry. Cancellation restores the source indexes atomically and retains the fence until target cleanup completes. Failed target cleanup stays visible and fenced, never rediscovered as authoritative. This applies to namespace-filtered and global lists, individual gets, mutations and endpoint discovery.

**The pin never floats.** While a job is open, the heartbeat keeps the namespace's pin as the journal says, whatever either host lists (as `namespace_moves` fences a move today). The switch is one registry write: pin → target, machine and endpoint indexes → target, step `switched`. The job never calls `unpin`, so the window of "Moving a namespace" (an unpinned name taken back by a heartbeat) does not exist. A heartbeat only ever fills a missing pin; it never moves one.

## Sequence

For one namespace. Steps 2 and 4 (start) exist in phase 2 only.

| # | Step | Where | Journal |
|---|---|---|---|
| 0 | Preflight: the namespace has no open operation; no machine is creating, starting, stopping or destroying; in phase 1, no gateway (409 `gateway`: "namespaces with a gateway cannot be evacuated in phase 1; its identity, configuration and data must travel together"); no sandbox seed or warm slot in it (refused: "built on the target instead"); no named snapshot unless `--drop-snapshots`; the source host answers. Target: `--to`, else placement over the whole namespace (region, runtime classes, egress siblings; memory for the machines that run, disk for every disk's logical size, not its clone-exclusive one; CPU), the source excluded, the most free memory first. Nothing fits: 503 `no_room` with the shortfall per resource; nothing touched. The target's room is held (ADR 0044) for the job | fleet | `planned` |
| 1 | Hold every machine on the source. A start from now on is 409 `held`; the control plane shows the machine as moving | daemon | `held` |
| 2 | Warm copy: a backup of each running machine while it runs | daemon | `warm` |
| 3 | Cold stop of the machines that run (as `machine stop`: the guest asked to exit, then killed), then a final backup of every machine, incremental on its chain. The source's quota record is read. A gateway is refused in phase 1; its migration needs a later design that exports and restores its record, role, disks and CA without a preceding gateway PUT | daemon | `cold`, backup ids |
| 4 | Target prepared: quota put; restores with `same_id`, machines by `egress.via` order, `start: false`. No gateway PUT is made: phase 1 refuses a source gateway; endpoints created with their ids. The key of each backup is served to the target only (ADR 0035) | fleet → target | `restored`, per machine |
| 5 | Verify. Every machine: record equal to the source's (id, name, labels, size, disks and their sizes, volume mount, env and files by digest); every disk received whole (the receive's checksums, the chain complete to the final backup). A machine that ran: started on the target, `running`, its readiness probe passing (or alive for 30 s with no probe). A machine that was stopped stays stopped: its check is the record and the receive. Any failure: rollback (below) | fleet | `verified` |
| 6 | Switch: pin, machine and endpoint indexes → target, in one write. One `evacuated` event in the namespace, with the machines' `previous_ip`/`ip` and the endpoints' new addresses | fleet | `switched` |
| 7 | Release the source: destroy its machines (the holder's call), remove the namespace there (the daemon's own route, not the fleet's unpin). Its backups stay for `keep_destroyed_days` (ADR 0023) and are reachable (ADR 0045) | daemon | `done` |

**Failures and resumes**

| Fails at | What the operator sees | On resume or cancel |
|---|---|---|
| 0 | a refusal with its reason; nothing changed | |
| 1 | some machines held, some not | hold the rest, or release all (cancel) |
| 2 or 3 | machines held; the ones that ran stopped; a backup missing | retry the backup; cancel: release the holds, start again what ran (the journal says which) |
| 4 | the target holds part of the copy | restore the rest; cancel: destroy the copy on the target, drop its namespace there, release and restart the source |
| 5 | verification names the machine and the check | rollback as at 4; the source is intact, nothing was destroyed |
| 6 | the write did not land: the pin is still the source's | the switch is retried; it is one write, there is no half |
| 7 | the source is destroyed in part | retry until 404; a source destroy that keeps failing leaves the job `finishing`, the destination untouched, the source's leftovers held. There is no rollback after 6 |
| the fleet restarts | the job continues from the journal | |
| the source host dies mid-job | before 6: cancel is impossible (its holds cannot be released): the job stops `stuck`, the operator chooses: wait for the host, or `--from-backups` (below) | |

`briqyard namespace evacuate cancel <namespace>` rolls back any job before step 6. `briqyard namespace evacuations` lists jobs, their step and their result; a done job is kept for 7 days.

**A host that is gone**: `namespace evacuate --from-backups` restores the last backups without the source, steps 1 to 3 skipped, data since the last backup lost and said so in the result. Its key is the retired key the fleet kept (ADR 0035). Same journal, same verification. Not in phase 1.

## What the owner sees

| | Stopped machine | Running machine |
|---|---|---|
| Downtime | none; a start during the job is refused as moving | from the cold stop (3) to `running` on the target (5): the final increment up and down, plus a boot. Minutes for a disk of gigabytes; measured in phase 2, reported per job |
| Private address | new; `<name>.internal` and `<id>.vm.internal` resolve to it | same |
| Public names | unchanged: the edge's | unchanged |
| Endpoints | same ids, ports, tokens; new delivery address; the control plane refreshes its edge | same; connections during the window fail until the refresh |
| Memory state | n/a | lost: a boot, as after a move |
| Backups | the chain continues on the target; the first backup there is whole (another key, ADR 0035); the old chain is listed and restorable for `keep_destroyed_days` | same |

Pruning after an evacuate: both live-machine `keep` pruning and destroyed-holder expiration operate only on backups under the host's own `key_id`. Chain length and incremental bases are computed within that key too. Backups under a different key remain listable and restorable; the target never deletes the source chain. The first target backup is whole. The source chain remains readable through destination restore and verification (step 5). Only after that verification and the switch may source destruction create its retention holder: `keep_destroyed_days` starts at source destruction, never at job creation or target restore. Until source destruction, a hold blocks source scheduling and pruning by ordinary callers; the holder's final backup must retain the complete chain it names. After source destruction, only the source host's holder expires that key's chain at `destroyed_at + keep_destroyed_days`, independently of how many backups the target has made. A target that has not yet made its own whole backup can restore from the retained source chain during this retention window. Beyond that window, the ordinary retention promise ends; an operator needing longer protection increases source retention before evacuation. Retired source keys remain available through the existing one-use restore authorization (ADR 0035). No protection is released on cancellation. Legacy unkeyed backups keep their existing destroyed-holder expiration semantics (amends ADR 0023).

## Rejected

| Alternative | Why not |
|---|---|
| `host drain` evicts, as `kubectl drain` | `host drain` is shipped as cordon and the state `draining` is on the wire; an operator who cordons must not move everything by surprise. `host evacuate` is the drain of Kubernetes, named for what it does |
| A script over existing APIs | it cannot hold the source, keep the ids, or stop the heartbeat from repinning; it is the procedure of `FLEET-OPERATIONS.md` with the same gaps |
| A move per machine across hosts (ADR 0056's first version) | splits a namespace; an HTTP handler drops the job on a hang-up; no journal |
| New ids and a remap in the control plane | every control plane writes the same remap, and the endpoints and backups change name too; the fleet's indexes already carry ids, they can carry them to another host |
| A direct `zfs send` between hosts now | a second channel to authenticate and firewall, a second receive path; the store path exists and is tested; build the stream when a measurement asks for it |
| Carrying memory snapshots | a resume on another host and CPU is not promised exact; ADR 0056 keeps them with the source |
| Moving seeds and warm slots | they are capacity the operator builds (ADRs 0074, 0076), bound to their host's datasets; building them again on the target is the honest copy |
| Keeping the private addresses (same subnet on the target) | a subnet is the host's to give; names are the contract (ADR 0056's join gives a new address too) |
| Holds that expire | a job that outlives an expiry would race the owner's start; a stuck job is visible and is cancelled, or released on the host with `--force` |

## Amendments

- ADR 0056: "Another host: not yet" becomes "another host: evacuate the namespace (ADR 0112)". Its list of what a cross-host move needs is met by this job: background, journal, source held, one operation per machine, source destroyed after the copy runs (verified at 5, destroyed at 7), cleanup results in the result, snapshots not carried, verification defined. One item changes: the machine keeps its id.
- `FLEET-OPERATIONS.md`: "Moving a namespace" becomes the `evacuate` commands; the manual procedure stays as the fallback for a fleet older than this release.
- `KUBERNETES-MAP.md`: "Drain with eviction" ✓ (`host evacuate`); the "Node upgrades" gap keeps its reboot step, now `host evacuate` first when the reboot is not safe for the machines.

## Tests

- Daemon: a held machine refuses each verb with 409 `held` and the holder passes; a hold survives a restart; hold during an in-flight backup is 409 `busy` with no record change, a queued pre-hold backup is refused once it acquires its turn, and scheduled backups skip holds; `same_id` restore equals the source's record field by field (labels, ports, probes, restart, backup policy, env and files digests); `same_id` with the id present is 409; an endpoint created with an id keeps it and its token.
- Fleet, mock daemons: the journal at every step (a kill point per step, then a restart resumes and ends `done`); cancel at steps 1 to 5 leaves the source as it was and the target empty; global and filtered machine/endpoint lists during copying return exactly one authoritative copy and cannot change indexes; a stale list/discovery reply across the switch cannot rewrite an index; rollback leaves gets and starts routed to the source; a heartbeat from either host during the job moves no pin; a create, move, admission or second evacuate during the job is 409; placement refuses with the shortfall; `--to` a host without the class or region is refused; a source destroy failing at 7 leaves `finishing` and the destination untouched; `host evacuate` stops at the first namespace with no room and lists the rest.
- Native CI, the two-host suite (`hack/fleet-two-hosts.sh`, ADR 0089): a namespace without a gateway with two stopped machines (one with a volume and a marker file written before), a quota and an endpoint, evacuated from host A to B: same ids and labels on B, the marker read after a start on B, the endpoint answering through B's address, the namespace gone from A, the old chain still listed after target `keep` pruning, with source expiration restricted to its own key and the configured post-destruction retention window; a gateway namespace refused before any hold or backup; a start during the hold is 409; the fleet killed between two restores and restarted finishes the job; cancel before the switch leaves A as it was. Phase 2 adds a running machine with the downtime measured and kept as suite evidence.

## Phasing

**Endpoint refresh contract.** After observing the job's durable `switched` state (or `done`), the control plane reads `GET /v1/endpoints/{id}` through the fleet for every endpoint id in the job result. The fleet must return only the destination's endpoint and its new `address`, protocol, guest `port`, destination `host_port` or HTTP `host`; it must not return the held source endpoint. The runtime calls this field `address`: the control-plane adapter derives its `delivery_address` from it. The control plane persists that new delivery address and updates its edge route before resuming traffic. Endpoint and machine ids stay unchanged. A failed refresh is retried; job completion alone does not update an external edge. The job result carries the endpoint ids and new endpoint values so a reconciler can discover all refreshes without consulting the source.

**Phase 1, stopped machines.** Daemon: hold, `same_id` restore, endpoint with an id. Fleet: the job for a namespace whose machines are all stopped (a running one is 409 `running`: stop it, or wait for phase 2), `--to` and placement, the journal with resume and cancel, the verification of record and receive, the switch, the source release, `namespace evacuations`. Gateways, seeds, warm slots and named snapshots refused as above. `host evacuate` runs these jobs sequentially; `--parallel` remains phase 2. CLI verbs. The daemon and fleet unit tests, and the native two-host case. Enough for a host that holds stopped owner machines and a seed: the namespaces are evacuated; the seed is built again on the target with its own procedure and dropped with the source.

**Phase 2, running machines.** Steps 2 and the start-and-probe of 5; `host evacuate` with `--parallel`; the downtime measured in native CI; then, if it asks for it, the direct stream.

**Phase 3, a host that is gone.** `--from-backups` with the retired key.

Nothing in phase 1 is a half of phase 2: what it does not handle, it refuses before it touches anything, and what it starts, it finishes or rolls back from the journal.

## Consequences

- A host leaves the fleet with one command per namespace, or one for the host, and its machines keep their ids: a control plane updates endpoint delivery addresses and nothing else.
- The fleet gains a job type with a journal. Admissions and moves already fence the heartbeat the same way; the journal is the third such fence and should share their code.
- A retired host's pool key stays needed as long as its chains are listed (`keep_destroyed_days`): the retired keys of ADR 0035 already cover it.
- The owner's memory state and named snapshots do not travel; the result lists what was dropped.

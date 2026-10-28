# ADR 0043: Fleet registry writes: one at a time, the newest, and none that undoes a host's answer

Date: 2026-10-28 · Status: accepted

## Context

The fleet's registry (`<state_dir>/registry.json`: hosts, their tokens and pool keys, tenant → host, machine → host, endpoint → host) was written by `AppState::save`: the registry cloned under its lock, then written outside it through one fixed temp file (`registry.json.tmp`: removed, made with `create_new`, synced, renamed). Nothing ordered two writes. A stress run on two real hosts (v0.1.1, the stress driver through the fleet at 24 and 32 workers) found:

| What | Seen |
|---|---|
| Two writes on the same temp file | 500 `registry` with `No such file or directory` (the other renamed it away) or `File exists` (the other made it): 60 `error` lines in 2 minutes, about 1 create in 3 refused |
| A create refused after the host made it | the second write (the index after the host's 201) failed: the machine ran, the caller had a 500 and no id |
| A write that lost | an older clone renamed in last (a lost update), or another writer's half-written temp file renamed into place |

In process, 300 writes at once on the old code fail within a second (`writes_at_once_all_land_and_the_file_ends_with_every_change`), and 64 creates at once answer 500 `registry`.

## Decisions

**Writes take turns, and each writes the registry as it is when its turn comes.** `save` takes an async mutex, then encodes the registry under its lock, then writes. A write therefore holds every change made before it was called, and a later write never lands an older registry: no generation counter is needed, the turn and the read at the turn are the order. A turn that finds the same bytes as the last write (SHA-256) writes nothing, so a burst of requests after one change costs one write. One writer means the temp file's name can stay fixed; a leftover (a crash mid-write) is removed first, as before.

**Durable before it counts.** The temp file is synced before the rename and the directory after it (unchanged). The write runs on the blocking pool with the turn moved into it: a request dropped mid-write does not release the turn while its file is still being written.

**The registry's backup needs nothing new.** It already takes its own turns (`Backup.last`, held across the upload) and reads the registry once its turn comes (ADR 0032); each object is put whole (an S3 PUT, the directory store's rename).

**Once a host acted, the host's answer stands.** A failed write is logged at `error` and the request answers what the host said: a create (201 with the machine's id, indexed in memory), a destroy, an endpoint added or removed, a tenant removed, the unpin after a first machine's `capacity`. The next write (a heartbeat's, every 15 s per host) carries the change. Refused alternatives: destroying on the host what a failed local write could not record turns a disk problem into the caller's loss; retrying the write in the request hides a disk that is failing. The index is a cache (a machine not in it is found by asking the hosts), and pins come back from the hosts' heartbeats. Before a host is asked, a failed write still refuses (500 `registry`): a pin the fleet would forget at a restart could send the tenant's next machine to another host.

**A call is what its path says.** The fleet matched a machine's `DELETE`, its plain `GET` and an endpoint's `POST` on the path with its query, so `DELETE /v1/machines/{id}?tenant=…` destroyed the machine and left it in the index. It matches `uri.path()` now.

## Numbers

In the dev VM, a fleet of its own in front of the VM's daemon, before (v0.1.1+ae2917a) and after (the script and its answers in `docs/research/2026-10-28-fleet-registry-writes.md`):

| Run | Before | After |
|---|---|---|
| 32 threads × 50 unpins (a write each, no host asked), then a create and a destroy each | 69 of 1600 unpins 500 `registry`, 69 `error` lines | 0 |
| `hack/stress.py --tenants 4 --per-tenant 3 --workers 32` | 1 create 500 `registry` | 0 failures, 0 invariant breaks |
| `hack/stress.py --tenants 8 --per-tenant 4 --workers 32` | 1 create 500 `registry` (and 20 refused for disk, ADR 0044) | 0 `registry` (the same 20 for disk) |

The VM's disk syncs fast and one host heartbeats: the real hosts' rate (about 1 create in 3) is the same race with slower syncs.

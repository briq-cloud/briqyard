# ADR 0031: Snapshots and restore in place: each disk swapped for a clone of its snapshot, the memory with it when asked

Date: 2026-10-21 · Status: accepted; amends ADR 0019 (`restored` for a snapshot, `snapshot_taken`, `snapshot_deleted`), ADR 0024 (a new image's root disk is swapped, not destroyed)

## Context

A sandbox's agent takes a checkpoint, tries something risky, and goes back: Fly Sprites' checkpoint and restore, E2B's pause and resume, Daytona's snapshots. A machine could take a snapshot of both disks (`POST /v1/machines/{id}/snapshots`), list it, delete it, and fork from a fresh one; it could not go back to one. Kubernetes' VolumeSnapshot restores into a new volume, which here is a fork; the map's gap (`../KUBERNETES-MAP.md`, Storage) is the rollback of a machine in place, to a snapshot it can find by name.

A restore must not break what depends on the machine's snapshots: newer snapshots the caller made, forks (a fork is a ZFS clone of a `fork-*` snapshot, which pins its origin), the backup chain (the next incremental is sent from the newest `bk-*` snapshot on the disk, ADR 0023), and the machine's lock and backup turn.

## Decisions

**Snapshots live in the machine's record.** `{id, name?, created_at, disks, memory?}`, oldest first. The record is what the API lists, so `created_at` is the snapshot's (it was the machine's), and a name finds it: `before-migration`, an id's characters, unique on the machine, never `s_…` (an id's shape), so `{snap}` in a path is an id or a name. Both disks are snapshotted in one `zfs snapshot root@s data@s`: one instant, crash-consistent across them. `snapshot_taken` and `snapshot_deleted` are events (two more: 35 reasons).

**A restore swaps each disk for a clone of its snapshot**: `clone <holder>@s <disk>.next`, `rename <disk> <disk>.<n>`, `rename <disk>.next <disk>`, then `promote <disk>` until its origin is outside the machine. The disk in use keeps its name; it owns every snapshot of its history (the one restored and those before it); the disk it replaced is *retired*: it keeps the snapshots made after the one restored, and whatever clones them. Measured on ZFS 2.4.1 in the VM: two restores back and forth leave every snapshot and the fork whole, and the second promote is needed (the first leaves the disk a clone of the retired one).

| Depends on the snapshots | `zfs rollback -r` | Swap and promote (taken) |
|---|---|---|
| newer snapshots the caller made | destroyed | kept, on the retired disk; a restore to one of them swaps back |
| a fork of a newer `fork-*` | refused ("dependent clones"); `-R` destroys the fork | kept: the fork clones the retired disk |
| the backup base | a newer `bk-*` destroyed; an older one stays | an older one moves with the history; a newer one is freed with the retired disk |
| the data written since | gone | gone (the retired disk is rolled back to its newest snapshot) |

**A retired disk stays only while it serves.** `tidy`, under the machine's lock, after a restore, a deletion, a new root disk, a fork's destroy (on its source) and at the daemon's start, removes until nothing more goes: a snapshot nothing clones that is an `s_` the record does not name for that disk, a `fork-*`, or anything on a retired disk but a named snapshot; then a retired disk that holds neither a named snapshot nor one something clones. A retired disk that stays is rolled back to its newest snapshot. Deleting a snapshot a retired disk hangs from (it is that disk's origin) drops it from the list; its blocks go with the last retired disk that needs them. The plain case (checkpoint, try, restore, nothing newer) leaves nothing retired.

**The backup chain stays correct, because the base is always in the disk's history.** A base is the newest `bk-*` on the disk in use (ADR 0023), and every snapshot on the disk in use is an ancestor of its content after a swap: a backup made before the snapshot restored moves with the history and the next backup continues from it; one made after is on the retired disk, freed (`bk-*` there serves nothing), so the next backup is whole. Either chain restores to what the machine has (unit tests, and the e2e suite on real ZFS with the content read back).

**The lock and the turn.** A restore takes the machine's backup turn, then its lock, as a backup does (`lock_with_turn`, which `lock_for_start` now uses too): no backup sends a disk while it is swapped. A running machine is stopped under that lock (`stopping`, `stopped`, the watcher has nothing to settle), swapped, then booted; a stopped, created or errored one stays as it is. `If-Match` is checked first. A fork takes its source's lock for its `fork-*` snapshot and clone, so no swap or tidy runs in between.

**A restore cut short is finished, not undone.** Its intent (`restoring: <snapshot>`) is written before the first disk moves. Each step is checked first (`.next` beside the disk is destroyed, `.next` alone is renamed into place, then the promotions), so the same restore run again converges, both disks together: the next restore, the next start (which takes the turn for it, as for a new root disk) or the daemon's start finishes it. Meanwhile a backup, a fork or a snapshot of the machine is refused (`bad_state`).

**A new image's root disk is a swap too (amends ADR 0024)**: a clone of the image's `@base` swapped in, the old root retired, kept while forks clone it, then freed by `tidy`; forks are no longer promoted over it. Each snapshot loses its root half (the root disk follows the image) and its memory; one that held only the root disk goes.

**Memory is an option on the same snapshot**: `{"memory": true}` on a running machine pauses it, has Firecracker write its memory and state (ADR 0005's suspend), flushes both zvols (`fsync` on the device: every write the guest made reaches ZFS, so the disks match the memory), snapshots the disks, resumes it, and moves the two files to `<jail_dir>/firecracker/<machine>/snapshots/<snap>.{state,mem}`, on the pool beside the chroot (ADR 0014). A restore of it hard-links them where a suspend leaves its own and marks the machine suspended: the start resumes it (Firecracker maps the file private, so the files serve the next restore too), and a stopped machine resumes at its next start. It resumes only into the spec it was taken with (image, entrypoint, command, env, files, size, by digest); otherwise the restore is of the disks and the boot cold, as ADR 0024 drops a suspend's snapshot. One snapshot concept: memory is a field of it, deleted with it, counted in `snapshot_gb_hours`. It is a small step on what suspend and snapshots on the pool already did: one VMM call more (`resume`).

**API.** `POST /v1/machines/{id}/snapshots {name?, memory?}`; `GET` lists; `DELETE …/snapshots/{snap}` (id or name; missing is success); `POST …/snapshots/{snap}/restore` with `If-Match`, answering the machine. `restored` (ADR 0019's reason for a machine made from a backup) also says a machine went back to a snapshot: `{snapshot, name, disks, memory}`. CLI: `machine snapshot create --name N --memory`, `ls` (a table with `NAME` and `MEMORY`), `restore ID SNAP`, `rm ID SNAP`.

Rejected, one line each:
- `zfs rollback -r`: one command, but it destroys newer snapshots and cannot pass a fork (table above).
- Rollback when nothing newer depends, swap otherwise: two paths for one operation; the swap costs four `zfs` calls more and is the only one that is always correct.
- Snapshots as a ZFS user property (`briqyard:name`): one place less to keep, but names, the memory's spec and the restore's intent want the record anyway.
- Refusing a restore past a fork, or to a snapshot a retired disk hangs from: a fork's life would decide what its source may do.
- A memory snapshot as a separate concept (a "checkpoint" next to a "snapshot"): two lists, two deletions, the same disks.
- The record naming its disk datasets (a generation per restore) instead of renames: every reader of `m/<id>/root` (jails, backups, usage, the sweep) would change.

## Consequences

- An agent can checkpoint, go wrong, and go back in a second or two (a stop, five `zfs` calls, a boot), or a quarter second more than a resume with memory; forks and backups carry on.
- A retired disk costs what it holds: the blocks of the snapshots newer than the one restored. `zfs list -t all -r byard/m/<machine>` shows them (`root.r_…`, `data.r_…`); usage counts them in the machine's snapshot bytes.
- A memory snapshot costs the machine's memory in disk, per snapshot, and pauses the machine while it is written (about a second per GB on NVMe). In-flight execs over vsock end with it (Firecracker resets vsock connections at a snapshot). Like a suspend's, it resumes only on this host's Firecracker; backups and forks never carry it.
- `s_*` snapshots made before this ADR are not in any record: the first `tidy` (the daemon's start) removes them. No host with real workload has any.
- A destroyed source's snapshots move to a fork promoted over it, as before; the fork's `tidy` (run after the destroy, under its lock) removes the ones it does not name.
- Not built: a fork from a named snapshot (`ForkSpec.snapshot`), a cap on snapshots per machine (quotas count volumes, not snapshots), the restore of a machine's spec with its disks.

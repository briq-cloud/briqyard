# ADR 0037: Firecracker 1.17: deleted blocks go back to the pool; snapshot files stay synced; vsock after a bare pause

Date: 2026-10-27 · Status: proposed; amends ADR 0002 (the disks take discards)

## Context

Every host runs Firecracker v1.17.0 (`hack/bootstrap-host.sh`). Three of its changes matter here:

- **virtio-blk discard**, opt-in per drive (`"discard": true`, writable drives on the `Sync` engine, our default). Every disk is a sparse zvol (`zfs create -s`, `refreservation` none; a root disk is a clone of its image's `@base`), so it only grows: a guest that deletes 10 GB keeps holding 10 GB of the pool until the machine goes.
- **`sync_snapshot_files`** on `PUT /snapshot/create`, default `true`: `false` returns before the state and memory files are fsynced (block devices are fsynced either way).
- **#6100**: after a bare pause and resume (`PATCH /vm` Paused then Resumed, no snapshot between) the vsock device dropped every new host-to-guest connection for good. A snapshot sends the guest a transport reset at `create`, so the bug was only the bare case.

## Decisions

**Each writable drive takes discards, and the guest issues them as it deletes.** `fc::Client::drive` sets `discard` on every writable drive (the root disk and the volume; the config drive is read-only). The kernel mounts the root disk with `rootflags=discard`; `briqyard-init` mounts an ext4 volume with `discard`. ZFS frees the zvol's blocks the guest discards, except those a snapshot still references (a backup's base, a fork's origin, a named snapshot): they come back when that snapshot goes. A guest may remount without `discard`; it then holds its blocks until it trims.

Measured in the dev VM (a 4 GiB volume, `volblocksize` 16K, the guest's discard granularity 16 KiB; `zfs get used` after `zpool sync`; nested virtualization):

| On the volume | `used` after the delete | `rm` + `sync` |
|---|---|---|
| a 1 GiB file, mounted `discard` | 1032 → 1 MiB | 0.23 s |
| 1024 files of 1 MiB, mounted `discard` | 1032 → 1 MiB | 0.34 s |
| a 1 GiB file, `nodiscard` | 1033 MiB kept; 1 MiB after `fstrim` (0.19 s) | 0.21 s |
| 1024 files of 1 MiB, `nodiscard` | 1033 MiB kept; 1 MiB after `fstrim` (0.07 s) | 0.09 s |

The root disk: 512 MiB written then deleted, 516 → 0 MiB. Online discard frees as much as `fstrim` and costs a quarter of a second on a 1 GiB delete.

Rejected, one line each:
- The device's discard alone, each guest running `fstrim`: an OCI image has no `fstrim` job, so the zvol never shrinks.
- The daemon running `fstrim` in each guest on a schedule: a scheduler and an exec into a tenant's machine for what the guest's own mount does. If online discard ever stalls a delete-heavy workload, a periodic `FITRIM` from `briqyard-init` is the fallback, still in the guest.

**`sync_snapshot_files` stays `true`.** A suspend writes the snapshot, then the record says `suspended` (written durably), then Firecracker is killed. Unsynced, a host crash before writeback leaves a state file whole and a memory file torn or short: the state file has a CRC, the memory file has nothing, so the next start resumes a guest on torn memory against disks that are whole. That is the one outcome a suspend must never produce. Recording the host's boot id with an unsynced snapshot and booting cold when it changed would make it safe, but a planned reboot is exactly a suspend then a new boot id (ADR 0027): every machine would boot cold after one, unless the daemon's stop synced and the sleeper's did not, two modes for one operation. For the memory snapshot of ADR 0031 (the machine paused while it is written), `false` with the daemon's own `sync_all` of both files before the record names the snapshot would be safe (a crash leaves files no record points to); measured (below), the pause does not shrink enough to be worth a second path.

MEASURE

**#6100 is covered for our pause paths.** A suspend pauses, creates and kills: never resumed in that process. A memory snapshot pauses, creates (the transport reset sent), flushes, snapshots the disks and resumes: the e2e suite has always execed into the machine after it. The bare case is ours too: when `snapshot/create` fails, `fc::snapshot` resumes the machine at once; under 1.16 that machine took no new exec, file transfer or session until it restarted. The e2e suite now pauses and resumes a running machine through its API socket and execs into it.

## Consequences

- The pool holds what guests hold, not what they ever wrote: a sandbox that installs and deletes dependencies all day stays at its working set.
- `rootflags=discard` and the init's mount change every root disk's init, so each image is built once more per host after the upgrade (the init is in the image key).
- A machine resumed from a snapshot taken before this change has no discard until its next cold boot (the drive's config is in the snapshot).
- e2e: 256 MiB deleted on a volume and on a root disk come back to the pool (258 → 0 MiB each); a bare pause and resume leaves exec working.
- Not checked against 1.16 (every host runs 1.17); the bare-pause check would hang there.

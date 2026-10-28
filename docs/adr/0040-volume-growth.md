# ADR 0040: A volume grows: its disk at the PATCH, its filesystem in the guest at the next boot

Date: 2026-10-28 · Status: accepted; amends ADR 0024 (`volume` in a PATCH, `pending.volume`), ADR 0025 (a growth is held to `disk_gb`), ADR 0031 (a restore keeps the volume's size; a memory snapshot holds it)

## Context

A volume's size was fixed at create (ADR 0024: "not built: a volume resize"). A database that fills its volume had to be backed up and restored into a bigger machine, a new machine with a new address. Kubernetes expands a PersistentVolumeClaim in place (`allowVolumeExpansion`): the claim's size goes up, never down; the volume grows, and the filesystem grows when a node next mounts it. The scope test (`../KUBERNETES-MAP.md`, Volume expansion) puts it here.

Measured on the dev VM (OpenZFS 2.4.1, kernel 7.0): `zfs set volsize` on a thin zvol allocates nothing; an incremental send (plain and raw `-w`) from a snapshot before the change to one after carries the new `volsize`, and its receive moves the dataset and its block device to it; a clone of a snapshot from before keeps the old size.

## Decisions

**`PATCH /v1/machines/{id}` takes `volume: {size_gb}`**, beside ADR 0024's fields (`SpecChange::volume`, `api::VolumeSize`). Only the size: the mount is fixed, and a body that names one is refused. CLI: `briqyard machine set ID --volume-gb N`.

```json
{"volume": {"size_gb": 20}}
```

| Asked | Answer |
|---|---|
| larger | the disk grows now, 200, `pending.volume` |
| the size it has | no change, no event (ADR 0024's rule; a retried PATCH succeeds) |
| smaller | 400 `invalid`, `volume: 10 GB asked, 20 GB held: a volume never shrinks` |
| no volume | 400 `invalid`: a volume is made at create |
| past the tenant's `disk_gb` | 403 `quota`, a `quota_exceeded` event, nothing changed |
| past the pool's free space | 503 `capacity` |
| a restore cut short, a destroy | 409 `bad_state` |

**The disk grows at the PATCH, the record with it.** Under the machine's lock: the pool's room checked, then, under the map's lock as a start's memory is (ADR 0025), the growth held to the tenant's quota and the new size put on the record, then `zfs set volsize`; refused there, the record goes back. From then on the record says the disk's size: the quota, usage, a fork, a backup's record and a restore read one value. Rejected: the record keeping the old size until the start while the disk is already larger, so that every reader would take the larger of two.

**The filesystem grows in the guest, at the next boot.** The init mounts an ext4 volume, then asks the kernel to grow it to the end of its device (`EXT4_IOC_RESIZE_FS`, what `resize2fs` asks of a mounted filesystem). The kernel does it online and returns at once when the filesystem fills the device already, so the init asks at every boot and needs no tool in the image. A refusal (a filesystem with errors) is a console line; the volume serves at the size it had. Rejected: the daemon running `e2fsck -f` and `resize2fs` on the host before the boot: slower, and host tools run as root over a filesystem a tenant wrote.

**Until that boot it is `pending`**: `pending.volume` in the view and `volume` in `fields` (an `updated` event with `pending: true`), cleared by the start that applies it (`applied`). It is the guest's view that waits: the record has the size already, so `pending_after` keeps the field without comparing it to the record. A guest's memory holds its disk's size as it read it at boot, so `volume` counts for `touches_snapshot`: that start drops a suspend's memory and boots cold, as for a new size.

**The pool's room is one rule, at a create and a growth**: the pool's free space (`zfs get available`) at least the volume's size, or the growth. Volumes are thin: it admits, it reserves nothing, as the fleet's placement does. The fleet forwards the PATCH as it is: the daemon knows the volume's size and its pool, and the next heartbeat moves the host's free space.

**A disk is never smaller than its record** (`fit_volume`):

- a fork or a restore may ask a larger volume than its source's: its disk grows to it after the clone or the receive; a smaller one is 400 `invalid`, as at a PATCH (Kubernetes: a claim restored or cloned from a snapshot is at least the snapshot's size);
- a restore in place of a snapshot from before a growth (ADR 0031) grows the disk back to the record's size, and its filesystem, the snapshot's, is `pending` until the next boot;
- a memory snapshot holds the volume's size as its guest booted with it (`memory_spec`: the record's size, and whether a growth waits for a boot): one taken before a growth, or after it and before the boot, is not resumed into the larger disk. That start is cold.

**Backups need nothing.** The chain goes on across a growth: the next backup is incremental, and its stream carries the new size. A backup's record is the grown record; a restore from it makes the larger disk.

## Consequences

- briq can grow a briq's volume with a PATCH and a restart, keeping its address, endpoints and data.
- Memory snapshots taken before this change hold another digest: each resumes cold once, as after a Firecracker upgrade (ADR 0027).
- A root disk made before this change carries an init that does not grow the filesystem (ADR 0027: the init is the root disk's): such a machine's filesystem grows once its root disk is made again (a new image, ADR 0024). The init reports no capability, so the daemon cannot refuse the PATCH for it.
- A grown volume keeps its quota share: a volume never shrinks.
- Not built: a growth seen by a running guest (Firecracker's `PATCH /drives` makes the guest read the new size; the init would then grow the mounted filesystem), which would make `volume` an at-once field; a filesystem other than ext4.

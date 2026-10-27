# ADR 0002: Disks: ZFS zvols on the host's NVMe, Writeback, an image to a root disk once

Date: 2026-10-18 · Status: accepted

## Context

A sandbox runtime typically keeps its writes in a diff beside the template and ships them to object storage at pause. A briq is a Postgres an agent comes back to next month: a committed write must be on disk when the machine says so. Same mechanism (the disk is part of the snapshot), different promise.

## Decisions

**Every disk is a ZFS zvol in one pool.** `<pool>/images/<digest>` holds a root disk built from an image with a `@base` snapshot; `<pool>/m/<id>/root` is a clone of it, `<pool>/m/<id>/data` the data volume. Clone is instant and copy-on-write; a fork is a clone of a snapshot of both disks; a snapshot is the base of a backup. LVM thin would do the same with worse tooling.

**The data volume is attached with Firecracker's `Writeback` cache.** A guest `fsync` reaches the host's drive. The default `Unsafe` drops flushes; durable volume services do not use it. Firecracker's own docs say Writeback when integrity matters.

**Local NVMe, no replication, no disk on S3.** Surviving the loss of a host is not needed yet; a storage cluster (DRBD, Mayastor, Ceph) is a system to run. Neon-style disks on S3 (ZeroFS) only pay off for big sleeping disks. Backups to object storage cover the host-lost case (ADR 0008), writes since the last one are lost, as on any unreplicated local volume.

**An image becomes a root disk once per digest.** Layers applied in manifest order into a directory the host controls, whiteouts honoured, every path resolved inside the directory, the last component never followed, devices skipped; then `mkfs.ext4 -d`. The host never mounts a guest filesystem.

**The root disk outlives stops.** Boot files are rewritten at each cold start from the config drive, so an edit in the machine lasts until then. A fresh data volume gets the image directory's owner and content and loses `lost+found`, so a database accepts it.

## Consequences

- A tenant's machines live where their disks are: one pool, one host (ADR 0006). Moving one is a backup sent on purpose.
- Placement counts free disk as well as memory.
- `zfs destroy` answers "busy" briefly after Firecracker exits: retried. Destroying a forked source promotes its clones first.
- Reopen replication when tenants need databases that survive hardware failure without their own replica.

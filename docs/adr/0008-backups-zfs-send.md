# ADR 0008: Backups: ZFS streams to an object store, incremental, restore is a create

Date: 2026-10-20 · Status: accepted; scheduling, retention and delete by ADR 0023; the store's client by ADR 0034; raw sends by ADR 0035; credentials from an environment file by ADR 0041

## Context

Disks are local and not replicated (ADR 0002). Losing a host must not lose a tenant's data for good, and a machine must be movable to another host on purpose.

## Decisions

**A backup is a ZFS snapshot of each disk streamed with `zfs send -c`** (raw, `-w`, since ADR 0035) to an object store, whole the first time, incremental from the previous backup's snapshot after. The record beside the streams (`backups/<machine>/<id>.json`) holds the machine's spec and the chain.

**The object store is S3 or a directory** (`briqyard-objstore` on Apache Arrow's `object_store` since ADR 0034: `s3://bucket/prefix` with multipart PUT in 32 MB parts and SigV4, or `file:///path`). A directory makes the e2e suite run without a bucket; the same code path.

**Restore is a create with `restore: {machine_id, backup}`**: the chain is received into fresh datasets on any host that reaches the store, then the machine boots as usual. The size check runs after the receive, so a restored volume is never refused for the size it had.

**`keep_snapshots` (1) backup snapshots stay on the host per machine**: the newest is the base of the next incremental send, nothing else.

## Consequences

- Writes since the last backup are lost when a host dies. Scheduling and pruning in the store are not built: the control plane calls `POST /machines/{id}/backups` when it wants one.
- A compressed send (`-c`) keeps the pool's lz4 blocks; the store sees ZFS stream format, readable only by `zfs receive`. A raw send (ADR 0035) keeps them encrypted too.
- Verified with a directory store in the e2e suite (whole, incremental, restore latest and first); a real bucket run is pending (Scaleway Object Storage).

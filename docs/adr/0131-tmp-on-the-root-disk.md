# 0131: `/tmp` on the root disk

Date: 2026-11-12
Status: accepted; amends ADR 0004

## Context

The init mounted a tmpfs on `/tmp` with the kernel's default size, half the machine's memory. A tmpfs
is not a reserved region: its pages come out of the guest's memory, so what a build writes to `/tmp`
leaves less for the build's own processes.

A real workload shows it. An install and a typecheck of a large TypeScript monorepo, run from a
directory under `/tmp` on a machine of 8 vCPUs and 15.6 GiB:

| `/tmp` | Result |
|---|---|
| tmpfs (7.9 GiB at most) | the typecheck is killed by the kernel for lack of memory (a process at about 2.2 GiB resident), then a build tool dies with SIGBUS on a tmpfs page it can no longer back |
| a directory of the root disk | passes: install 13.6 s, typecheck 22.1 s, 40.5 s for the whole workload, 3.25 GB written |

The root disk had about 6 GiB free. In Kubernetes, `/tmp` of a container is the container's disk; a
memory-backed `emptyDir` is something a pod asks for ([the map](../KUBERNETES-MAP.md)).

## Decision

- The init mounts nothing on `/tmp`. It is the directory of the root disk that `prepare_root` makes
  with mode 1777.
- The init empties `/tmp` at each boot, before anything runs: what a cold boot lost with the tmpfs
  it still loses. A symlink in it is removed, never followed. A resume does not run the init again,
  so a machine resumed from a snapshot with memory keeps its `/tmp`, as before.
- No size option and no memory-backed `/tmp` yet; a machine that needs one mounts a tmpfs itself.

## Consequences

- A process that fills `/tmp` fills the root disk, whose free space is limited (about 6 GiB in the case
  above) and does not depend on the machine's memory. The volume is the place for data that must outlive a boot.
- Files in `/tmp` are in disk snapshots and backups until the next boot empties them.
- A machine resumed from a snapshot taken with an earlier init runs that init: it keeps the tmpfs
  until it is booted again. A seed is such a snapshot: seeds made before this change are rebuilt for
  it to apply.
- The init's digest changes (ADR 0101); machines pick it up at their next cold boot.

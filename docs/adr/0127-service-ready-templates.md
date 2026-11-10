# 0127: Loaded-service memory templates

Date: 2026-11-10
Status: accepted; default-off, native qualification pending

A service that spends seconds or minutes loading (warming caches, building an index,
starting a runtime) can be cloned from memory instead of started again. ADR 0072 does this
for a pristine init parked before its first workload exec. This ADR extends the same sealed,
immutable artifact to a service that is already running. It does not fork a live parent: a
sealed template keeps the parent's fate out of the clone path, and reuses 0072's durable
readers, deletion fencing and recovery.

## Profile and flag

`service-ready-v1` is a template profile beside `init-ready-v1`. It is offered only when
`templates.enabled` holds and `templates.service_ready` (default false) is set. Both need
the exact init digest of 0072.

## Guest contract

A builder is created with `template_build: service-ready-v1` and `clone_hooks`:
`park` and `resume` argv arrays, with timeouts (default 30 s, at most 300 s). The hooks are
part of the immutable provenance. The builder is an ordinary running machine of any image
(network, probes, egress as requested); it has no volume and the default runtime class (so
no `kvm`), and it sleeps never.

A seal (`snapshot` with `memory` and `template`) does, in the guest init:

1. Refuse unless the service runs unparked, with the right init digest.
2. Run `park` as the workload's user. Non-zero or a timeout: the service keeps running and
   the seal is refused with 409 (`clone_hook_failed`, exit code and the last 4 KB of stderr).
3. Refuse when any established non-loopback TCP connection remains (`established_socket`),
   or when the table cannot be read. This check does not rest on the hook.
4. Freeze the workload's cgroup, take eth0 down, remove addresses and identity files.
5. Sync, pause and snapshot. The source is then stopped, sealed or not: a parked source never
   serves again. A source that keeps running is out of scope.

A failure before step 4 completes restores the service. A failure after it stops the source.

A clone restores strictly, then crosses 0072's identity barrier unchanged
(`clone_configure_v1`). `clone_activate_v1` for a service writes `/run/briqyard/clone.json`
(generation, hostname, ip, machine_id), runs `resume` while the workload is still frozen and
thaws it on exit 0. Readiness is the resume exit plus a live main process.

## Failure

A resume that exits non-zero or times out is terminal for that clone: the workload is never
thawed, its VMM is ended, and the machine is `error` with reason `clone_hook_failed`, so a
caller can tell it from a workload exit. Capacity is released after the VMM exit is
confirmed, as for any clone. Other clones are unaffected; there is no fleet transaction.

## Scope

Same namespace owner only, as in 0072. A clone keeps the sealed recipe: no overrides, egress
none, no volume. Every clone inherits the source's memory, secrets included; this is
acceptable within one owner and documented. Per-clone environment, volumes, a running source,
cross-host distribution and ports on clones are not provided.

## What the application owns

The runtime orders the hooks, bounds their time, keeps the workload frozen from park to
resume, resets the kernel RNG and gives each clone a fresh MAC, address, hostname,
machine-id and wall clock. The application closes and re-creates outbound sessions, reseeds
its own random generators, regenerates tokens and identifiers derived from the host, and
tolerates a clock jump. The runtime claims no userspace randomness safety.

## Not qualified

VMGenID, the effective MAC and VMClock behavior on the pinned Firecracker and kernel are
unqualified, as in 0072. The flag stays off in production until they are.

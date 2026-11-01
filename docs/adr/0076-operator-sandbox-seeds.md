# 0076: Operator-produced pristine sandbox seeds

Date: 2026-11-01
Status: implementation candidate; native qualification required before enablement

Ordinary create can select `sandbox_seed` with an immutable source machine, snapshot,
generation and request ID. It is exclusive with fork, restore and template building.
The existing command, environment, files, volume, ports, probes, restart, backup,
limits, egress and metadata keep their ordinary homes. Exact approved image/size,
`start:true` and a fresh fixed-capacity ext4 volume at `/work` are required.
Unsupported inputs are rejected before reader consumption. Explicit selection never
silently falls back to cold create.

Only operator-produced pristine public-image seeds cross namespaces. Both fleet
and daemon require configured API authentication. The daemon allowlist pins manifest,
image config, init digest, exact CPU/memory size and data capacity. Registry credentials,
caller preparation, ordinary snapshots and configured warm slots are excluded.
The shared admin bearer assigns destinations; namespace prefixes and caller metadata
are not runtime tenant authority. Team-produced sources remain unsupported.

A raw zero-backed, unformatted, never-mounted operator data device occupies the saved
third-drive topology. Its identity is `data` (`/dev/vdc`), with pinned byte capacity
and 512-byte guest-visible logical sectors. It is charged to the operator namespace through
the ordinary disk/accounting path. Init verifies whole-device identity, geometry,
no partitions/holders/mount/swap and zero outstanding I/O, obtains exclusive access,
drains and checks `BLKFLSBUF` before builder-ready. No guest command or workload runs
and no subsequent builder operation accesses that device. The existing Firecracker
pause/snapshot/flush boundary seals the artifact. Host physical allocation geometry is independent of guest logical sectors. Destination disks are newly allocated,
formatted with an explicit fresh ext4 UUID, synced and checked for exact byte capacity; placeholder bytes are never
cloned. Restored init repeats checked exclusive invalidation before mounting.

The namespace/request ID binds one canonical normalized full-create digest to one
machine under serialized admission. Its existing machine record carries the assignment;
a durable index preserves consumption even after record removal. Recovery rebuilds
missing index entries and rejects conflicting identities. Identical retry returns the
same machine, including failure; changed replay conflicts. Destroy does not permit
reusing that request ID.

The fleet durably writes a per-request routing intent before its first create dispatch,
under the same registry lock as placement and the existing temporary hold. Only that
initial handler may dispatch. An existing intent uses authenticated read-only daemon
lookup before source/capability/capacity/sibling gates; a changed digest conflicts.
Lost responses, removed hosts, malformed replies and even an authoritative daemon miss
never authorize dispatching that key again. This also fences crash-before-send intents.

Unresolved dispatch intents durably fence namespace deletion, unpinning, host removal
and relocation, even after cancellation or transient hold release. Matching validated
machine acceptance from POST or authenticated lookup settles that fence; timeout,
transport failure or lookup absence does not. New creates on the existing pinned host
remain available. No authoritative termination reconciliation API exists yet: an
unresolved request without recoverable acceptance requires explicit operator
reconciliation, never expiry or inferred termination.

Settled routing intents and daemon request-index tombstones contain metadata, not network or
resource holds. Normal empty-namespace/gateway/network deletion, unpin and host removal
remain available after settlement. New request IDs can place elsewhere after cleanup; old lookup results
do not repin that namespace. Existing temporary holds fence deletion during create, and
a namespace placement version prevents stale deletion responses from unpinning a later
create. Earlier-format namespace-wide fences, if encountered, require reconciliation
rather than silently disappearing.

The existing reader leases, boot incarnation, quarantine and durable clone stages are
reused. Before sending bind, the host freezes the complete resolved guest payload and
assignment receipt. It verifies the shared full-payload SHA-256, profile, protocol,
RAM marker and complete fresh identity, then durably saves acknowledgment before
network release. Activation and active ping must retain that exact hash and identity.
Main PID and first successful exec precede ordinary readiness probes. Interrupted
binds and uncertain exits keep the same reservation/reader and conservative recovery;
configured paused warm slots keep their separate contract.

The allowlist defaults empty. Tag-based create requests remain ineligible; no stale
tag-to-digest mapping or image rewrite substitutes for an explicit pinned request. Source checks and mocked lifecycle tests do not qualify
kernel discovery/queue behavior, restored block-cache invalidation, fresh UUID/data
visibility or sibling-clone isolation. Native Firecracker/kernel evidence for those
properties is required before an operator enables this profile. No such qualification
or end-to-end ordinary-create claim is made by this source change. `init-ready-v1`
and ordinary cold boot remain unchanged.

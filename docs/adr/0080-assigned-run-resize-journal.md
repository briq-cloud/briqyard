# ADR 0080: Assigned-run resize requires a durable update journal

2026-11-03 · Accepted; native qualification pending

## Context

The provider's resize operation can PATCH a data-volume increase while a machine is
running, then stop it and PATCH its size or image before starting it again. Ordinary
machines persist a live volume increase and retain image and size changes as `pending`
for the next boot. Assigned runs instead bind the machine record, backing disks and
process evidence to an exact durable `Current` record. Applying ordinary PATCH behavior
to an assigned run would make that record disagree with the machine or disk while the
run is still active.

## Decisions

- **Journal the provider's stopped resize as one transition.** A stopped PATCH may combine
  image, size, disk limits and data-volume growth. The durable update intent records the
  complete pending target; image resolution and root replacement are separately replayable
  under that intent. A running volume-only PATCH grows the data disk immediately and marks
  the filesystem growth pending for the next cold start.
- **Journal updates as authority transitions.** Each update intent must bind the exact
  source `Current` hash and machine-record fingerprint to the complete target record,
  normalized patch, and target DATA-volume geometry. Serialize it with the assigned-run
  lifecycle turn. Persist the intent before disk or record mutation; reconcile the exact
  source/target record, `Current`, and reader states at startup; delete the intent only
  after all three durable records agree. A conflicting or unknown state remains
  quarantined with its backing and capacity charges retained.
- **Reconcile before replacing an outstanding intent.** A failed machine write can leave
  memory at the latest target while disk still holds its predecessor. Before replacing
  the intent, validate and durably reconcile that existing transition using startup's exact
  source/target matching. A failure retains the existing intent and quota reservation.
  One predecessor is then sufficient; no history chain is needed. Both target and
  predecessor preserve source ownership, creation, workload and backing bindings, allowing
  only pending image/size/volume, event versions, disk limits and data-volume size growth.
- **Treat volume growth as an idempotent external side effect.** Recovery must inspect
  the existing zvol size and either finish growth to the journaled target or retain the
  intent on mismatch. A command error alone cannot establish whether growth occurred.
  Do not expose the new logical volume size until its target is durable. A resize that
  changes the next boot's workload invalidates any saved memory checkpoint.
- **Keep the exact volume intent through run settlement.** Stopping a process changes its
  run phase and PID, but does not revoke a volume update already acknowledged against that
  observed run. The settlement digest must authorize the exact update during startup repair
  and when the next run consumes it. Other record differences still fail closed.
- **Reserve namespace disk quota with the target record.** Running and stopped growth check
  quota and persist the journaled volume target while holding the machine-map admission lock.
  The durable intent precedes the record reservation and the external ZFS grow. Concurrent
  creates and growths therefore see the same committed disk use.
- **Persist cancellation of a pending resize.** A stopped resize back to the current size
  writes the no-pending target through the update journal. It cannot return success while
  leaving an older pending intent that a later start would apply.
- **Bind image changes to root replacement before the next run is reserved.** Image
  resolution and the intended image identity must be durable before the root swap starts.
  Recovery may finish or refuse the existing `.next` swap only under that exact intent;
  it must not let ordinary swap cleanup change the root GUID behind a settled run. The
  next run records the verified resulting root GUID before launch.
- **Keep run evidence immutable and chain the control change explicitly.** The update
  must not rewrite the observed process proof, run sequence, creation receipt, source
  identity, or prior-run hash. The run journal and reader must authenticate the update
  transition so the next run can use the exact settled target as its predecessor.
- **Treat the full provider resize lifecycle as a pre-enable requirement.** Integration
  must cover a running volume-only PATCH, stop and settlement, subsequent stopped
  size/image PATCHes, daemon restart, and the next assigned start. It must retain the
  existing run chain and exact process/backing proofs while making the update durable.
- **Do not change the provider contract to hide the gap.** The provider continues to
  issue its normal resize requests. The runtime's unbound warm-pool feature remains
  default-off until the lifecycle is implemented and qualified.

## Consequences

The current journal covers the provider's running volume PATCH and combined stopped resize,
including image-root replacement, retries, machine-record and ZFS repair after interruption,
and the next-run chain. The old root remains available until the consumed update and next
run authority are durable, then normal snapshot tidying retires it. This does not establish
warm-pool enablement or native qualification. Ordinary `pending` fields alone are not
sufficient evidence for volume or image changes.

# ADR 0080: Assigned-run resize requires a durable update journal

2026-11-03 · Accepted, lifecycle integration pending

## Context

The provider's resize operation can PATCH a data-volume increase while a machine is
running, then stop it and PATCH its size or image before starting it again. Ordinary
machines persist a live volume increase and retain image and size changes as `pending`
for the next boot. Assigned runs instead bind the machine record, backing disks and
process evidence to an exact durable `Current` record. Applying ordinary PATCH behavior
to an assigned run would make that record disagree with the machine or disk while the
run is still active.

## Decisions

- **Keep assigned-run updates fail-closed until journal integration exists.** A PATCH
  must not grow the data volume, change pending configuration, or rewrite run evidence
  unless a durable update intent can reconcile those effects after interruption.
- **Treat the full provider resize lifecycle as a pre-enable requirement.** Integration
  must cover a running volume-only PATCH, stop and settlement, subsequent stopped
  size/image PATCHes, daemon restart, and the next assigned start. It must retain the
  existing run chain and exact process/backing proofs while making the update durable.
- **Do not change the provider contract to hide the gap.** The provider continues to
  issue its normal resize requests. The runtime's unbound warm-pool feature remains
  default-off until the lifecycle is implemented and qualified.

## Consequences

This candidate does not claim assigned-run resize compatibility or warm-pool enablement.
Removing the guard requires a separate durable transition design with crash/replay tests;
ordinary `pending` fields alone are not sufficient evidence for volume or image changes.

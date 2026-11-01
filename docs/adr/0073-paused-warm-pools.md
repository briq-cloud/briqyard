# 0073: Paused slots of immutable qualified templates

Use the existing named-memory artifact/identity primitive and normal destination
machine records for host-local warm pools. Bind owner, immutable generation, recipe,
profile, CPU/init/boot identity and network policy in one fingerprint. Configure each
slot under quarantine and confirm Paused at the pre-activation barrier. Reserve its
full capacity while paused. Reconcile desired count in the existing tick.

Persist a bounded request receipt before activating one slot. Repeated/concurrent keys
reach that same destination, including after daemon restart or response loss. Transfer
its reservation, without a second host/fleet hold. Empty claims return pool_empty;
fail_fast avoids waiting for the allocation lock. No mode waits for refill or implicitly
allocates fresh capacity; the existing strict named-fork path does fresh admission.
Claimed machines never return to the pool. Retain receipts after destruction.

Adopt paused owned processes explicitly. Validate saved incarnation, boot/profile and
reader identity; otherwise settle through exact process/boot-boundary proof, without
activation. Unknown exit keeps full reservation and backing. The immutable template
validator determines supported profiles. Current init-ready support is partial Y2;
qualified service hooks, running Postgres/prepared state/mid-episode forks remain open.
Native correctness/performance evidence is required separately from source capability.

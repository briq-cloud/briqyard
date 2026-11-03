# ADR 0084: Assigned runs reserve physical VMM memory

2026-11-03 · Accepted; native qualification pending

## Context

Assigned continuation admission and warm-pool disk liabilities now share the runtime
with physical VMM reservations (ADRs 0065, 0068, 0077, 0078 and 0080). Guest memory alone
undercharges an assigned continuation by the fixed 256 MiB VMM overhead.

## Decisions

- **Use physical charges for host admission.** Under the machine-map lock, subtract
  the prior entry's physical charge only when it commits memory, then admit the
  target guest size plus VMM overhead. Namespace quotas continue using guest memory.
  A stopped assigned resize (ADR 0080) is journaled as the next run's pending size, so its
  memory is charged when that run is reserved, with this rule; `check_host_size` already
  refuses a guest size whose VMM ceiling overflows.
- **Track assigned launches and adoptions through memory protection.** Mark pending
  launches before entering the factory, retain uncertain launch liabilities, and
  retain the actual adopted ceiling and degradation status. Checkpoint termination
  uses the exact live process handle.
- **Keep disk liability independent.** Preserve warm root and data-volume liabilities
  from ADR 0078; neither disk field enters physical memory/CPU headroom arithmetic.
- **Initialize native recovery before assigned backing checks.** Establish the native
  recovery barrier and host memory status before examining assigned run backing.

## Consequences

The integration reserves the same VMM ceiling for ordinary and assigned boots without
changing namespace memory quotas or disk accounting. The update journal keeps its own
rules: the machine record is repaired before the admission writes its intent. macOS checks do
not qualify Linux containment.

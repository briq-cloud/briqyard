# ADR 0132: A new namespace goes to the host with the lowest share of memory used

Date: 2026-11-14 · Status: accepted · Supersedes the ordering of ADR 0006 (a tenant goes to the host with the most free memory) and of ADR 0128 and ADR 0130 where they name "most free memory" as the last key; their filters and other keys stand.

## Context

`place` and the sandbox admission pick (ADR 0128) ended on the most free memory in MB. With hosts of different sizes, the largest host always has the most free MB, so a smaller host receives nothing until the larger ones are nearly full. Load is uneven, and a burst (ADR 0044 holds, ADR 0130) piles onto the largest host.

## Decision

After every filter and key that exists (ready, under the fill ceiling, no pressure, capabilities, region, reservation, disk, CPU, the nested key of ADR 0088, a validated seed and fewer boot waves of ADR 0130), the host with the **lowest share of memory used** wins: `used.memory_mb / capacity.memory_mb`, where `used` already includes the holds of creates in flight.

- Shares are compared exactly: `used_a * cap_b < used_b * cap_a` in `u128`, no floats.
- Ties: the most free memory in MB, then the lowest host id. The choice is deterministic.
- A host that reports no memory capacity counts as full (share 1).
- One function, `HostRec::load_order`, serves both `Registry::place` and the sandbox pick, so the two cannot drift.
- A pinned namespace stays on its host. Forks stay with their source.

Not changed: `shortage` (which resource ran out, read from the roomiest host), `room` and the `largest_slot` signals (ADR 0042) report capacity, not a placement.

## Consequences

- Hosts of different sizes fill in proportion to their size: with a 100 GB and a 50 GB host, nine 10 GB machines land 6 and 3.
- A small host gets work as soon as the large one carries a share above it, not when the large one is full.
- Placing on the lowest share can leave the largest free block on a smaller host than before; a machine larger than every host's free memory is refused as before, by the reservation filter.

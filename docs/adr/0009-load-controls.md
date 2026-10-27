# ADR 0009: Load: boots take turns, a tag's digest is remembered

Date: 2026-10-20 · Status: accepted

## Context

The stress spike (`../research/2026-10-19-stress-spike.md`) started 24 guests at once on 6 vCPUs: 23 of 24 boots missed a fixed 60 s init timeout, and the second round's creates all failed at Docker Hub's unauthenticated pull rate limit because every create resolved the tag again.

## Decisions

**Boots take turns.** `boots_at_once` (half the host's threads, at least 2) is a semaphore around the Firecracker start and the wait for the guest; each boot gets the whole `boot_timeout_sec` (120) once it holds a turn. A slow host queues; it does not fail.

**A tag's digest is remembered** for `image_resolve_minutes` (10), in memory and on disk (`meta/ref-<sha>.json`). When the registry refuses (a rate limit), the image already on the host serves, with a warning. A digest reference never asks the registry.

**The ingress waits for a wake as long as the daemon would**: `boot_timeout_sec` + 30 s, not a fixed 90 s.

**Tenants made together take a lock** around the subnet allocation; a raced `ip link add` is tolerated.

## Consequences

- Under load a create can take minutes and still succeed; the control plane's timeout (130 s today) must follow the daemon's, or the transition must run detached from the request.
- A tag moved at the registry is seen within 10 minutes, not at once.

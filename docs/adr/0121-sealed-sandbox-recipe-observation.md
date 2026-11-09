# 0121 — Observe a validated sealed sandbox recipe

## Context

A catalog entry needs the sealed source's actual recipe. A snapshot's name or a caller-supplied receipt does not prove its image, initialization bytes, device geometry, or generation. Returning the internal clone artifact would expose unnecessary guest configuration.

## Decision

The source daemon serves `GET /v1/machines/{id}/snapshots/{snap}/sandbox-recipe`. Configured API authentication is required even on loopback. The snapshot parameter is an exact ID; aliases are refused.

The read holds the source lifecycle lock and reuses the provenance checks used by memory clones and sandbox admission. It returns only the validated image and initialization digests, generation, profile, source identities, size, root recipe and DATA-device geometry. Unresolved host recovery refuses the read. The lock wait is limited to five seconds; cancellation releases the waiter.

Every receipt identifies the observing manager's fresh 128-bit incarnation, current host boot, build version and loaded configuration identity (ADR 0120). The sealed artifact's boot identity is a separate digest. A programmatically constructed configuration remains explicitly unobserved.

## Limits

This is an observation, not an authorization or a persistent reservation. It creates no reader, pool, or guest request. A later operation must validate the artifact again and establish its own lifecycle and maintenance admission. Ordinary snapshot and clone semantics are unchanged.

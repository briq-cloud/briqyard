# 0120 — Machine creation provenance

Status: proposed; implementation and validation pending.

## Context

`memory_origin` describes a memory clone, but does not distinguish a direct sandbox
seed restore from an unbound warm assignment. Current boot mode also cannot establish
how a machine was first created: assigned continuations may boot fresh later.

The authenticated sandbox-request lookup resolves durable request authority, but the
fleet only uses that lookup while reconciling a create. Replaying a create to observe
provenance is unnecessary and gives the wrong read interface.

## Decision

Return optional `create_origin` through the existing machine GET/list projection.
Its kind is `sandbox_seed` or `unbound_warm`, with the original request ID and create
digest. The outer machine ID and namespace complete the binding. Absence means unknown;
it never means cold creation. This describes accepted creation, not readiness, successful
memory restore or the current boot method.

Use existing validated assignment receipts and a cache of sandbox indexes populated
only after durable persistence. Reconstruct through existing recovery. Projection adds
no filesystem reads, endpoint, worker or publication authority. Keep existing readiness
and assignment publication checks. Never downgrade suspicious assignment evidence to a
direct seed result. Direct seed evidence requires an exact index/binding match and no
assignment markers or cached assignment ownership.

Preserve original provenance across restart, checkpoint and fresh continuation, and
specification updates. Omit it for unsupported or ambiguous records. Old responses remain
valid when the optional field is absent. Consumers compare namespace, machine ID, request
ID and digest with their actual create; labels and requested selection are not evidence.

## Acceptance

Test direct seed, assigned warm, selector miss, missing and conflicting authority,
pending assignment, replay, recovery and continuation. Check that ordinary reads add no
store access and that the fleet preserves the optional field. Document the API and render
absence as `-` in the CLI. No pool policy, selection, resource reservation or default changes.

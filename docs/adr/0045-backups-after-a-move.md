# ADR 0045: Backups after a tenant moves: the holder's host, and a host's own key

Date: 2026-10-28 · Status: accepted; amends ADR 0023 (through the fleet) and ADR 0035 (the key route)

## Context

A tenant moves between hosts by backups, destroys, `tenant rm` and restores ("Moving a tenant", `OPERATIONS.md`). The destroyed machines' backups stay held on the old host for `keep_destroyed_days` (ADR 0023): listed, counted in usage, deleted on that host. Tests on two real hosts found two gaps:

| What | Seen |
|---|---|
| A held backup on the old host cannot be deleted through the fleet | `DELETE /v1/machines/{id}/backups/{b}?tenant=` went to the tenant's host: 404 while the tenant was pinned to its new host, 404 `machine not found` once unpinned. The fleet found a destroyed machine only through its tenant's current host |
| `GET /v1/backups?tenant=` asks only the tenant's host | the old host's held backups are not in it |
| A restore sent to a host keyed by the fleet (`storage.key: fleet`) is refused | 8 of e2e's restores: the daemon asked the fleet for the backup's key by id, and the fleet serves a key by id only for a restore it forwarded, even the host's own (403 `no_restore`) |

## Decisions

**A destroyed machine's backups are reached on the host that holds them.** For a backup path (`/v1/machines/{id}/backups/…`) of a machine no host has, the fleet asks every host's `/v1/backups` (with the `tenant` of the call when it has one) and forwards to the host that lists one of the machine's. A host that cannot answer fails the call with its answer, as a listing does: another host is never named in its place. Any other call about a machine no host has is a 404, without the search. `GET /v1/backups` asks every host, with `tenant` too.

Rejected: deleting the objects from any host that reaches the store. The holder (listing, usage, expiry) lives on the host that destroyed the machine (ADR 0023): the store would be cleaned while the holder stays listed and counted. Rejected too: keeping destroyed machines in the fleet's index, a second record of what the hosts already list.

**A host's own key needs no restore.** The daemon asks its own key from its source first (its file, or the fleet without a key id, which serves a host its key at any ask) and uses it when its id is the backup's; it asks the fleet by id only for another host's key. The fleet's key route also serves a host its own key by id without a restore, for daemons that ask that way. Another host's key, a forgotten one's included, is still served once, for a restore the fleet forwarded (ADR 0035).

# ADR 0045: Backups after a tenant moves: the holder's host, and a host's own key

Date: 2026-10-28 · Status: accepted; amends ADR 0023 (through the fleet) and ADR 0035 (the key route); amended 2026-10-29 (the search)

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

## Amended 2026-10-29: the search asks for one machine, every host at once

Chaos runs on two real hosts (v0.1.2, about 350 holders on each) found the search above too slow to use, and one answer wrong:

| What | Seen |
|---|---|
| A host's `/v1/backups` lists the store once per machine and holder, one after the other | 15 s on one host, 23.7 s on the other |
| The fleet asked the hosts one after the other, each for everything it holds | a `DELETE …/backups/…` of a destroyed machine took 4 s at the median, up to 40 s; 196 of them ran for 17 minutes |
| A record deleted between a listing's list and its read | the whole listing 500 (`s3 get backups/…json … not found`), and the fleet passed it on: two deletes of one chain racing answered 500, one after 153.8 s |

The 153.8 s were not retries of the 404 (the store retries a 5xx, a 429 or a failed connection, never a 404): they were the search's listings, run while the other deletes' ran on the same bucket.

**The search asks for the machine.** `GET /v1/backups?machine=<id>` (with `tenant` when the call has one) lists that machine's backups alone: none, from memory and without a store read, on a host that neither has it nor holds it. Every host is asked at once. The host that lists one of the machine's is the holder, whatever another could not answer: an id is made once, by one host, and only that host's destroy makes its holder. With no host listing it, a host that could not answer fails the search with its answer, as before. A host older than the filter ignores it and lists all it holds; the fleet keeps only the machine's (ADR 0027: an additive query).

**A listing reads the store at most 16 requests at a time per host**, machines and records alike, whichever listings ask. A record gone between the list and its read is not a backup: a deletion under way, never a failure.

Rejected: the fleet's index keeping a destroyed machine's host (above). It would grow with every destroy, holders or none, and only the host knows when a holder ends (`keep_destroyed_days` is the host's, and a deletion or the expiry ends it there). Asked for one machine, a host that does not hold it answers without the store, so asking every host costs a request each and one store listing in all.

Per `DELETE` of a destroyed machine's backup, with `n` holders on each of `h` hosts and `k` backups each: the search read the store up to `h·n·(1 + k)` times, one after the other; it now reads it `1 + k` times, on the holder.

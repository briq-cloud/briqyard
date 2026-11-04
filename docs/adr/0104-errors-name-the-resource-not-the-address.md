# ADR 0104: An API error names the resource, never an address; the detail goes to the log

2026-11-04 · Status: accepted; extends ADR 0035 and ADR 0045

## Context

A restore of a backup whose key the fleet does not hold answered `POST /v1/machines` with a 500
`internal` whose text was the error chain, fleet address included
(`the key of backup …: http://10.0.0.1:7430/v1/hosts/key answered 404 …`). `MError::Other` is
sent whole (`{err:#}`), so any `anyhow` chain reaches the caller. A missing key is not an
internal error, and the caller must not learn the fleet's address.

## Decisions

**A key the fleet cannot give is a typed error.** `poolkey::KeyError` says whether the fleet
refused (a 4xx: no such key, no restore open, unknown host, or no fleet to ask) or failed (no
answer, a 5xx, an unreadable answer). `Manager::backup_key` maps them:

| Case | Status | Code |
| --- | --- | --- |
| Key not held, or refused | 409 | `key_unavailable` |
| Fleet did not answer | 503 | `key_unreachable` |

409 because the backup exists and the restore cannot proceed in this state, as with the other
"not in that state" answers; 404 stays for a backup that does not exist. 503 is retryable, as
`capacity` is. The message names the backup. The full detail, the URL included, is a `warn`
line (`the key of a backup`).

**General rule: a new error that can carry an address, a path or a store key is typed, with a
message of the resource only; its chain is logged.**

**Not decided here.** `MError::Other` still answers `internal` with its chain: briq's file
operations show that text to the agent (`briqyard-files.ts`, `internal` carries the reason of a
failed read or write). A generic 500 needs a file error of its own first.

## Consequences

- `key_unavailable` and `key_unreachable` are in the OpenAPI for `POST /v1/machines`.
- Other `Other` chains and the fleet's `registry` 500 and `upgrade_failed` still return their text.

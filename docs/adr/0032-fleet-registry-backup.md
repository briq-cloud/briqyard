# ADR 0032: The fleet's registry is backed up to the object store, encrypted with age to a key kept off the fleet's host

Date: 2026-10-21 · Status: accepted; follows ADR 0026

## Context

The fleet's registry (`<state_dir>/registry.json`) holds every host's token and, since ADR 0026, every host's pool key. Lost, each host keeps running until its next reboot and then cannot read its pool: its machines are gone but for their backups. ADR 0026 made this backup a blocker before any tenant on a real host. Kubernetes has the same need for etcd (`../KUBERNETES-MAP.md`, etcd backup).

## Decisions

**The fleet writes its registry to an object store, the one the hosts already use.** `backup: { store, endpoint, region, recipient }` in the fleet's config: `s3://bucket/prefix` or `file:///path`, credentials from `BRIQYARD_S3_ACCESS_KEY` and `BRIQYARD_S3_SECRET_KEY` as a host's. The store client moved from the daemon to its own crate, `briqyard-objstore`, shared by both: one way to talk to a store. Objects: `fleet/registry.json.age`, the newest, and `fleet/registry-<UTC day>.json.age`, the last of each day, kept (a registry is a few KB; deleting is the operator's, with the bucket's lifecycle rules).

**Written once a minute when it changed, and before a key is handed out.** The fleet compares the registry's SHA-256 with what it last wrote and writes only a change; heartbeats change `last_seen`, so that is about once a minute, 1,440 small writes a day at most. A host's pool key is served only once the store holds it (the last write had that host with that key): a new key is written to the store before it is answered, and a store that refuses the write answers the host 503 `backup`, so no pool is ever created with a key the backup lacks. A write that fails in the background is an `error` line and is tried again a minute later. Rejected: a write per registry change (one per heartbeat, every host, every 15 s); a write only when a key is made (tokens, pins and tenant placements would be a day old).

**Encrypted with age to an X25519 recipient; the identity is kept off the fleet's host.** `backup.recipient` is an `age1…` public key; its identity (the private key) is made with `briqyard-fleet keygen --out <file>` (or `age-keygen`, same format) on the founder's machine and kept offline. The fleet can write a backup and cannot read one, so a copy of the fleet's disk or of the bucket opens nothing. age (`age` crate 0.12, the format and tool by Filippo Valsorda): one recipient string in the config, authenticated encryption, a CLI any operator can use without us (`age -d -i key registry.json.age`). Rejected: a symmetric key in the fleet's config (on the host the backup protects against losing; a copy of its disk would open the backup); GPG (keyrings, many options, a large tool for one recipient); NaCl sealed boxes (the same primitive without a file format or a tool); S3 server-side encryption alone (the provider holds the key, and a `file://` store has none).

**`briqyard-fleet restore --identity <file> [--from <object>]` writes the registry back**, from `backup.store`, decrypted, parsed as a registry (a backup that does not parse is refused, as a registry file is, ADR 0026), `0600`, and only when there is no registry: it never writes over what a fleet wrote. Then the fleet starts on it: hosts' tokens, pins and pool keys as of the backup. What happened after the backup and before the loss (a tenant placed, a host ordered) comes back from the hosts' heartbeats, as a fleet restart already does; a key made in that minute cannot be missing, since none is served unbacked.

## Consequences

- Restoring needs the identity: losing both the registry and the identity loses every key, as before. Keep the identity in two places off the fleet's host (the founder's password manager and a printed copy).
- A store that is down stops new keys (a bootstrap creating a pool, a host whose key was made but not yet written) with 503 `backup`; a host whose key the store holds gets it as before.
- The backup holds every host's token as well: rotating a token (ADR 0026, a disk swapped) leaves the old one in older daily objects, readable only with the identity.
- The fleet itself is still one process with one file: this is a backup, not availability. Fleet HA (`../KUBERNETES-MAP.md`) stays open.
- Development: `hack/fleet-restore.sh` adds a `backup:` section to the dev fleet's config for its run, with an identity on the fleet's host (development only), backs up, loses the registry, restores it, and checks that `fc2`, its pool locked as a reboot leaves it, comes back with its key from the restored registry.

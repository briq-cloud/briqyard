# ADR 0035: Backups are raw sends: the bucket holds ciphertext, a restore asks for the key by its id

Date: 2026-10-27 · Status: accepted; amends ADR 0008 (the send), ADR 0026 (a forgotten host's key is kept) and ADR 0023 (the first backup after it is whole)

## Context

The pool is encrypted (ADR 0026), but a backup was `zfs send -c`: ZFS decrypts what it sends, so the bucket held every tenant's disks in clear, protected only by the bucket's credentials and the provider's server-side encryption. ADR 0026 left this as its own decision: a raw send keeps the blocks under the host's key, so a restore on another host needs that key.

What ZFS does, checked on the dev VM (two scratch pools, each with its own `hex` key):

| Step | Result |
|---|---|
| `zfs send -w` of a zvol holding a marker, full and `-i` | no marker in either stream; the same snapshot sent `-c` shows it |
| `zfs receive -F -u` of both streams into the other pool | works without any key; the dataset is its own encryption root, `keystatus unavailable`, `keyformat hex` |
| `zfs load-key -L prompt` with the source pool's key, then `zfs change-key -i` | `encryptionroot` is the receiving pool, `available`; the data reads back |
| export, import, `load-key` of the receiving pool alone | the received dataset is `available`: it opens with its new pool |

A raw stream carries the dataset's master key wrapped by the source's wrapping key (the pool key of the host that sent it). `change-key -i` rewraps that master key with the parent's key without rewriting data.

## Decisions

**Every backup is a raw send: `zfs send -w`, incrementals `-w -i`.** The bucket holds the pool's ciphertext and nothing in clear, for the root disk and the volume. `-w` sends blocks as stored, so they stay compressed as `-c` did.

**The record says which key, by its id, never the key.** `Backup.key_id` is the first 16 bytes of SHA-256 over a fixed label and the pool key's 32 bytes, as hex (`briqyard_api::poolkey::id`). A hash of 32 random bytes tells nothing of them.

**The record's machine is sealed under the same key.** The record held the machine's spec in clear, its env and files with it: a tenant's secrets, in the bucket beside the ciphertext. It is now `sealed`: AES-256-GCM (ring, the TLS provider already in the daemon) under a key derived from the pool key by HKDF-SHA256, a random 96-bit nonce per record, and `<machine>/<backup>` as associated data, so a sealed spec opens in no other record. What stays in clear in the record: ids, tenant, name, times, sizes, the chain, `key_id`. The daemon asks its key's source (the key file, or the fleet's `POST /v1/hosts/key`) at the first backup after it starts, and keeps the id and the derived key, never the pool key.

**A restore asks for the key of that id, once.** `POST /v1/hosts/key {url, key_id}` with the host's own token, checked like any host call (the record at its address, its token, ADR 0026), answers the key of that id: a live host's or a forgotten one's. With a key file whose id matches, the host uses its own file and asks nothing (a host alone restores its own backups). The key opens the record's machine; the streams are received raw (no key needed), then the daemon runs `load-key` with it on each received disk and `change-key -i`. From then on the disk is under the restoring host's pool key and opens with the pool at every start. Without `change-key`, every received disk would stay its own encryption root, needing its source host's key at each start of the new host.

**Any host may ask for any backup's key.** Every host already reads every backup in the bucket: a restore lands on any host, so the hosts' credentials read all of `backups/`. A host given another host's key opens with it what it can already read, and that host's disks, which it does not have. Raw sends protect the backups against the bucket: its provider, a leaked bucket credential, a copy of the bucket. They do not protect against a host's root. Limiting the key to a restore the fleet forwarded would need the fleet to know which key each backup needs, and it cannot read backup records (its credential reaches `fleet/` only, ADR 0032). Every key the fleet serves this way is logged (`backup key served`: the caller, whose key, the id).

**A forgotten host's key is kept, as a retired key.** A forget (`host rm --force`, or the release of a retired host) moves the host's pool key into the registry's `retired_keys` (host id, key, when), still found by its id. Its backups stay readable after the host is gone, which is the case backups exist for (ADR 0008). ADR 0026 said a forgotten host's disks cannot be read again; that now holds for the host itself (no record, no key for its token), and for anyone who does not hold the fleet's registry. The registry is the fleet's own (`0600`, on an encrypted disk), and its backup is age-encrypted to a key kept offline (ADR 0032). Retired keys have no expiry: the fleet does not know when the last backup under a key is gone (lifecycle rules and `backup rm` delete them). An operator removes one by hand from the registry, with the fleet stopped. A route comes when it is needed.

**A raw increment continues only a raw backup under the same key.** The base of an incremental send must be a backup in the store with this pool's `key_id`. So the first backup after this change is whole, and a chain never mixes clear and raw streams, or two keys.

**Backups made before this change still restore.** A record without `key_id` is a chain in clear, its machine open: received as it always was, under the new host's pool encryption, with no key asked. Those streams stay in clear in the bucket until retention prunes their chain (ADR 0023) or `briqyard backup rm` deletes them.

| Rejected | Why |
|---|---|
| Sends in clear and S3 server-side encryption | the provider holds the key; a `file://` store has none (ADR 0026) |
| Encrypting the stream again in the daemon (age to a backup key) | a second key to keep for every host, and the data is already under one; raw is ZFS's own format |
| The source host's id in the record, and the fleet's key of that host | a host renamed or forgotten loses its backups; an id of the key finds it wherever it is kept |
| The key itself in the record, encrypted to the fleet | a key in the bucket, however wrapped; the fleet already keeps every key |
| The record's machine left in clear | a tenant's env and files in the bucket, in clear beside ciphertext disks |
| The record sealed with age to a fleet key | a second key the hosts would need at every restore; the pool key is already the one asked for |
| Dropping a forgotten host's key, its backups unreadable | a host lost is the reason to restore, and its record goes once its machines are restored elsewhere |
| Leaving a received disk its own encryption root | each such disk would need its source's key at every start of the new host |

## Consequences

- A host with a key file in a fleet (`storage.key: file:`) restores only its own backups unless it also has a fleet client (`fleet.url`, `fleet.advertise`, `token`). The fleet does not hold its key, so another host cannot restore its backups. A host in a fleet takes its key from the fleet (ADR 0026); a key file is for a host alone.
- A daemon's first backup after a start asks its key source once (the fleet, for a fleet-keyed host). When the fleet does not answer, that backup fails and is tried again `RETRY_AFTER` later (ADR 0023).
- A restore needs the fleet when the key is not the restoring host's file. A fleet that lost its registry, restored from its backup, still holds every key, retired ones included.
- The first backup of every machine after the upgrade is whole: one full stream each.
- `retired_keys` grows by one entry (about 150 bytes) for each forgotten host that had a key.
- Checked: `hack/e2e.sh` on `fc` (key file): the record has a 32-hex `key_id`, the key is in no object, and a secret of the machine's env is in none of them; the stream has no plaintext marker (the same snapshot sent in clear has it); a raw restore reads the marker back with its disk's `encryptionroot` the pool; a backup in clear, written as before this change, restores. `hack/fleet-two-hosts.sh` on `fc2` (key from the fleet): the same checks for a backup there, restored through the fleet onto `fc2` with the key the fleet served by its id. Unit tests: the record is sealed, opens to the machine's env, and does not open moved to another record; the fleet serves a live host's and a forgotten host's key by id to another host, 404 for an unknown id; the daemon takes its key file's key or asks the fleet, and refuses with no fleet to ask. A restore across two hosts' different keys needs a store both reach, which the dev VMs do not share (`fc2` has no store of its own). It is checked by ZFS on scratch pools (above) and by the unit tests, and runs for real once the first hosts share a bucket.

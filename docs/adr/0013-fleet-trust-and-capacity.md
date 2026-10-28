# ADR 0013: Fleet: one token per host, capacity reserved at placement, a tenant released by hand

Date: 2026-10-20 · Status: accepted; amended by ADR 0027 (`draining` takes nothing new and is never released, `retiring` is; `undrain`); ADR 0042 removed ordering: a host gets its token and pins from the bootstrap of `host add`

## Context

A review (2026-10-20) found five gaps. The fleet took any registration that carried a shared `host_token`: one compromised host could register any URL under any id and receive every tenant's requests, env secrets included. The bootstrap connected to a freshly delivered address with `StrictHostKeyChecking=accept-new` and nothing recorded. Placement read `used` from the last heartbeat, so a burst of creates landed on one host, and a tenant pinned to a host that then answered `capacity` was stuck there, with no way out short of forgetting the host. Registry writes failed silently.

## Decisions

**A host has one credential, its own API token, known to it and to the fleet alone.** The fleet forwards with it; the host's heartbeat presents it as its bearer. An ordered host gets a fresh one at the order (`HostRec.token`, written into the host by the bootstrap); a host the operator installs gets it in the fleet's `hosts:` entry. There is no shared `host_token`: nothing to steal from one host that opens another, and nothing the daemon's `fleet:` section needs beyond the fleet's URL and its own address. One token in both directions rather than two: the two parties are the same, and a token the fleet holds to forward with is already what a thief of the fleet's disk would want.

**A registration is taken for the one host record at the daemon's address, when it presents that record's token.** No record, or a record without a token: refused (`unknown_host` 403, `unauthorized` 401), logged at `warn` without the token. The fleet keeps the host under its own id (`h_<provider id>` for an order, the `hosts:` id for a static host); the daemon's `host_id` goes in the log only. A host listed without a token is polled, not registering. Every bearer comparison, fleet and daemon, is `briqyard_api::constant_eq`.

**The SSH host key is pinned at the first successful bootstrap.** Neither Scaleway's Elastic Metal API nor OVH's dedicated server API returns the server's host key (checked against both references on 2026-10-20; Hetzner Robot returns it for its rescue system only, which the bootstrap does not use), so there is nothing to pin from the provider. The key the server presents is taken into a file of its own for the attempt and, once the script succeeds, appended to `<state_dir>/known_hosts`; its fingerprint goes into the host's note (`ssh host key SHA256:… ed25519 pinned at first connect: check it against the provider's console`) and a failed attempt names the key it saw. Every later connect is `StrictHostKeyChecking=yes` against that file. Pinning on success rather than on first contact: OVH installs the OS after delivery, and a key seen before the install is not the host's.

**Placement reserves what it places.** `place` adds the machine's memory to the host's `used` and takes its disk from `disk_free_mb` in the registry, a fork on its source's host too, until the host's next heartbeat replaces both with what it really runs. Pure arithmetic in the registry, no timer: the next report is the truth.

**A `capacity` answer for a tenant's first machine unpins it.** The pin was made by that request and nothing of the tenant is on the host, so the retry is placed afresh. A later machine keeps its pin whatever the answer: the tenant's network is on that host, and splitting it is worse than a refusal.

**`POST /v1/tenants/{id}/unpin` releases a tenant from its host by hand**, touching no host: the operator's way to move a tenant (backups, then a restore placed afresh) or to free one stuck on a host that is full or gone. The host's next heartbeat pins the tenant again if it still has machines there, so the move is backups, destroy, unpin, restore, in that order.

**Endpoints are indexed to their host like machines**: at the create that goes through the fleet and from listings; a call on one goes to its host, found by asking every host only when the index does not have it. `GET /v1/endpoints` fails when a host is down or unreadable, never partial, for the same reason as machines.

**A registry write that fails is a failed request.** `save` logs at `error` and returns the error; a handler answers 500 `registry`; a create is refused before any host is asked, since a pin forgotten at the next restart could put the tenant's next machine on another host.

## Consequences

- A host installed by hand must be in the fleet's `hosts:` with its token before it can register; the fleet's `host_token` and the daemon's `fleet.token` are gone and a configuration that still has them is refused by name.
- The first bootstrap of a server trusts the key it sees; the note tells the operator to check the fingerprint against the provider's console. A reinstalled server needs its line removed from `<state_dir>/known_hosts`.
- Reservations make `used` in `briqyard host ls` run ahead of the hosts for up to one heartbeat.
- Unpinning a tenant that still has machines on a host splits it across hosts: the operator's responsibility, said in `OPERATIONS.md`.
- Reopen the key pinning if a provider's API starts returning host keys: the `Provisioner` trait would give them to the bootstrap, and the first connect would be strict too.

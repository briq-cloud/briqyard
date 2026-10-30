# ADR 0057: A server joins with a one-time token and a one-line install

Date: 2026-10-30 · Status: accepted; extends ADR 0028 (a host is also installed from the server), amends ADR 0026 (a host that joined pins its certificate at its first heartbeat)

## Context

`host add` has the fleet install the server over SSH: the fleet needs a key the server accepts and a route to its SSH port. A server in a network the fleet cannot dial, or one made from an image that runs a command at first boot, cannot be added. Kubernetes solves it the other way round: `kubeadm token create` mints a bootstrap token, `kubeadm join` on the node presents it, and the control plane answers with what the node needs. The same fits here, with the install as one line:

```bash
briqyard host token create --ttl 1h
curl -fsSL https://fleet.example/install.sh | FLEET_URL=https://fleet.example JOIN_TOKEN=<id>.<secret> sh
```

## Decisions

**A token is `<id>.<secret>`: 3 random bytes and 16 random bytes, as hex.** The registry keeps the id and the SHA-256 of the secret (`join_tokens`, `0600` like the rest), never the secret: the registry is backed up (ADR 0032) and read by whoever restores it, and a copy of it must not be a way in. The secret has 128 random bits, so a fast hash is enough: there is nothing to guess one from, and a salt or a work factor would only slow every join. The comparison is constant-time. The secret is shown once, in the answer to the create, written to the registry before.

**A token is used once, ends at its expiry, and can be revoked.** Default life an hour, at least a minute, at most 30 days. A token a host used cannot be revoked: the entry stays as the record of who used it, with the host, the time and the address the call came from. Ended tokens (used, revoked, expired) are kept 30 days for that audit, then dropped by the next mint. `host token ls` shows `active`, `used`, `expired`, `revoked`.

**Use is one step under the registry's lock.** The join checks the token and everything about the request (address, architecture, name, conflicts), then, with no await between, marks the token used, records the host and answers after the write. Of any number of calls with one token, one wins (a unit test and a fleet test run them at once). A write that fails takes the use and the host back before the error is answered, as a pool key is (ADR 0026). A refused request (a bad architecture, a name in use) spends nothing.

**A token can optionally carry a region, labels, a host id and an address.** The region and labels are the operator's, put on the host that joins; the joiner states neither. A token bound to a host id joins only as that id (`wrong_name` otherwise). A token bound to an address (`host token create --address 10.42.0.12`, or a network, `10.42.0.0/24`; IPv4, validated at the create) is used only by a call from it, checked against the address the fleet sees (`caller_address`), the way `host add` has the operator name the address. From anywhere else it is refused as every unusable token is (`invalid_token`, nothing spent, the reason in the log alone). This is the one bound that does not rest on the TTL: a token minted for a known server is useless from any other. The documentation's examples all use it. Labels are recorded and listed (`host ls`, `GET /v1/hosts`); nothing is scheduled on them yet.

**The join reuses what `host add` does.** The settings of the script come from the one function the SSH path uses (`bootstrap_settings`), so the two cannot drift: the host's own API token (made by the same `new_token`), `ADVERTISE`, the release and its read token, the pool device, the allowed clients, and, on a private network, the private address, interface, public ports and fleet address. The answer is these by their environment names, empty ones left out. The host's id and URL follow `host add`'s rules (`host_id`, `host_url`: an IPv4 address, `h_` and the address by default). Its record is `joining` (not `provisioning`: the SSH loop never touches it), `provider: join`.

| What the token gets | What it does not |
|---|---|
| a host record at the address the call came from, and that host's own API token | any other host's record, token or key |
| the settings of the bootstrap, the release's read token among them when the fleet has one | the pool key (the host asks for it with its own token, as ever: made at the first ask, ADR 0026) |
| | the fleet's token, the SSH key, the registry, the metrics token |
| | a second host: one use |

**The pool key and the backup credentials are not in the answer.** `host add` does not send the pool key either: the script asks `POST /v1/hosts/key` with the host's token, from the host's address, and the fleet makes it at the first ask. A join keeps that one path. The machines' store credentials are not sent by `host add` (ADR 0041: `/etc/briqyard/briqyardd.env` is the operator's), so a joined host gets them the same way.

**The caller must be seen.** A join is taken only when the fleet knows where the call came from (its own TLS, or a loopback proxy writing `X-Forwarded-For`; the check of ADR 0026), and only for the address the call came from: `address`, when sent, must be it; empty means it. Behind a proxy the fleet cannot see through, a token would let any holder name any address (the fleet would then dial it), so the join is refused there, saying why. A host on a private network joins from its private address, over the private network.

**A host that joined pins its certificate at its first heartbeat.** The SSH path reads the certificate over the pinned SSH connection and pins it before the daemon is accepted (ADR 0020). A join has no such channel: the daemon is not running yet. The first heartbeat of a `joining` host, made with its own token, from its own address, to the fleet's own endpoint, carries the certificate's fingerprint, and the fleet pins it there. From then on the pin is strict. Who could pin a wrong one: whoever holds the host's token and calls from its address, which is the host. This is trust on first use, so it is recorded as the SSH path records its pin: a `warn` line (host, peer, fingerprint) and the host's note, which the operator compares with `briqyardd tls-fingerprint` on the server.

**`install.sh` is the join and the bootstrap, not a second install.** The fleet serves `install.sh` at `GET /install.sh`, without a token: it is constant and holds nothing of the fleet's. The bootstrap script is not: `bootstrap.script` is the operator's file (ADR 0041 leaves the stores' credentials to them, and a registry login or a mirror's URL is a likely thing to write in it), so `GET /bootstrap-host.sh?url=<ADVERTISE>` is served as `POST /v1/hosts/key` is, only to the host that presents its own token from its own address (`the_host`, ADR 0026). The script holds no secret of the fleet's, but it is not public. `install.sh` keeps the join token in a variable of its own shell and removes it from the environment at the start, so nothing it runs (apt, its hooks, the bootstrap) inherits it. It checks the server first (root, architecture, Ubuntu, `/dev/kvm`, the drives named), installs `curl` and `jq` if missing, and only then sends the join (name, address, architecture, memory, CPUs; the token on stdin, never on a command line): the token is spent by the last step that is the server's own to check. It fetches the bootstrap script with the host's token the join answered, exports the answer and runs it. A join after a failed install replaces the record: a `joining` host that never heartbeated holds only a token no daemon has, so a new token at its address or id takes its place, rotating its token (a restored registry write failure puts the old record back); a host that heartbeated is a `conflict`. That script downloads the release's binaries for the architecture and checks each against the release's `SHA256SUMS-<arch>` before installing any, installs Firecracker and the kernel against pinned digests, makes the encrypted pool, writes the configuration and the unit, and starts the daemon: it is the code `host add` runs, and stays the only copy. `BRIQYARD_POOL_DEVICE` set on the server wins over the fleet's: the drives are the server's to name. `host add` is unchanged.

**TLS or an explicit word.** `FLEET_URL` must be `https://`. `http://` is refused unless `ALLOW_INSECURE_HTTP=1`, which also prints that the secrets cross in clear. curl is given `--proto` and `--proto-redir` of the scheme it started with, so a redirect cannot lower it. The bootstrap script then also checks that a plain-HTTP fleet is a private or loopback address.

## Threat model

| Threat | What happens |
|---|---|
| The token leaks before use | **a rogue node.** Whoever uses it first, from where the fleet accepts the call, becomes a host: once its first heartbeat makes it `ready` the fleet places customers' namespaces and machines on it, with their images and environment, and the join answer has already handed it `bootstrap.release_token` (a read token for the release) and the allowed clients. A bearer token is that powerful, as a kubeadm bootstrap token is. What bounds it: the TTL (an hour by default); `--address`, which makes the token useless from any address but the server's (the bound the operator should always set for a server they know; it is not available for an image booting on an address unknown beforehand); a bound host id (which the attacker simply uses); `host token revoke`; and the audit (`host token ls`, the `warn` lines for the token's making and use, the pin in the host's note). An unbound token is for networks where who can call the fleet is itself controlled |
| The token leaks after use | nothing: it is spent. A second call is `invalid_token` |
| A token is replayed | the same: one use, under a lock |
| Brute force | 128 secret bits; every refusal is one answer (`invalid_token`, a wrong address included) and a `warn` line with the reason, the address and the token id, never the token. No rate limit: nothing to gain from one |
| A host joins with another's name or address | an id in use and an address in use are `conflict`; the address must be the call's own; a token bound to an id refuses any other. A host cannot take over another's record, token or pool key |
| The join is read on the wire | it carries the token and the host's API token: `https://` only unless `ALLOW_INSECURE_HTTP=1` |
| The registry is copied (a backup, a restore) | it holds the hashes of unused tokens, which cannot be turned back into secrets |
| The bootstrap script is read by someone else | it is served only to a host presenting its own token from its own address, not to the internet: `bootstrap.script` may hold what the operator writes in it. `/install.sh` is open and constant |
| The scripts are changed in transit | they come from the fleet over the same TLS as the token. The binaries come from `bootstrap.release` over TLS, checked against the `SHA256SUMS` of the same release: that guards a corrupt download, not a release host that is taken over (as on the SSH path; signing releases is a separate decision) |
| The token is in the shell history or the environment | the command line `JOIN_TOKEN=… sh` is in the history of the shell that ran it: it is spent after the install, and expires. The script takes it out of its environment before it runs anything else (apt, the bootstrap), so no child inherits it |

## Consequences

- A joined host has no SSH key of the fleet on it, and `host upgrade` runs the bootstrap over SSH: it cannot upgrade a joined host until the fleet's key is authorized there. A token is spent, so `install.sh` does not upgrade either. Upgrading a joined host without SSH (it asks the fleet for its release) is a separate ADR.
- A fleet behind `tls: off` on a non-loopback address refuses joins. It already could not check a host's calls by address (ADR 0026).
- A joining host that never heartbeats stays `joining` with its note saying when and from where it joined; `host rm` forgets it.
- A VM run to check: `hack/fleet-two-hosts.sh`'s shape with `install.sh` in place of `host add` (a token, the one line on `fc2`, `ready` after the first heartbeat, the pool key from the fleet, a machine created on it).

## Not yet

- Reusable tokens for an image baked with one (kubeadm's reusable-within-TTL tokens, `--uses N`, or an address-bound reusable token): a token is single use, so an image boots one instance.
- A private CA: the fleet is authenticated by the system trust store only (no `FLEET_CA`, no `curl --pinnedpubkey`, nothing like kubeadm's `--discovery-token-ca-cert-hash`), so a fleet on a private CA cannot be joined.
- Joining over a private network from a public address: a join from outside `bootstrap.private_network` makes a public-API host (no `PRIVATE_*` settings), where `host add` refuses the address; the join neither refuses nor says so.

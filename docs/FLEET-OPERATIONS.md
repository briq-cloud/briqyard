# Fleet operations

## A fleet

`briqyard-fleet` runs anywhere that reaches every host (`/etc/briqyard/fleet.yaml`, unit in
`hack/briqyard-fleet.service`). Clients use the fleet's URL and `token` as they would a
daemon's; `briqyard host ls` shows the hosts.

On a server with no host, keep needrestart from restarting the fleet, as the bootstrap does on
a host (ADR 0050):

```bash
mkdir -p /etc/needrestart/conf.d && printf '%s\n' \
  '$nrconf{override_rc}{qr(^briqyardd\.service$)} = 0;' \
  '$nrconf{override_rc}{qr(^briqyard-fleet\.service$)} = 0;' > /etc/needrestart/conf.d/briqyard.conf
```

A host has one credential, its own API token, and the fleet must hold it before the host can
be anything to it: it forwards with it and takes the host's heartbeats (`fleet:` in the host's
config) only with it. A host added with `briqyard host add` gets its token from the bootstrap. A host you install yourself is listed under `hosts:` with it:

```yaml
hosts:
  - id: h1
    url: https://10.0.0.5:7420
    token: <the host's token>
    tls_fingerprint: <what the bootstrap script printed>
    region: gra
```

`region` is what a create's `region` names: a new namespace goes to a host of it, and stays in it
(ADR 0025). A host added takes the region `host add` gives it.

The fleet polls it every 15 s and accepts its heartbeats; without a `token` it is polled only.
An `https://` URL needs its `tls_fingerprint` and a fingerprint needs `https://` (refused at
start otherwise): the fleet accepts that one certificate from the host and nothing else, no CA,
and refuses a heartbeat reporting another (`tls_mismatch`). A host on plain HTTP (a loopback
daemon you forwarded) has neither.
A heartbeat from an address no entry, `host add` or join expects is refused (`unknown_host`), so no host
can speak for another. The registry is `<state_dir>/registry.json` (`0600`, its directory
`0700`); a write that fails is an `error` in the fleet's log, and a 500 `registry` on a request
that had not reached a host yet; once a host acted, its answer stands and the next write (a
heartbeat's) carries the change (ADR 0043).

Each host's pool key is in its record (ADR 0026): made at the host's first `POST
/v1/hosts/key` (its bootstrap creating the pool), served to that host alone (its token, at its
address, as a heartbeat), never listed, gone when the host is retired or forgotten. `briqyard
host rm` refuses a host that holds a key (409 `pool_key`) unless `--force`: its pool is
unreadable at its next restart, and a static host polled back gets a key its pool does not open.
A drained host stays drained; a retiring host is forgotten once empty. **Losing the
registry loses every key**: a host keeps running while its key is loaded, and cannot read its
pool after its next reboot. Back the registry up before a host holds anything that matters
(below); a host still up can be re-keyed with `zfs change-key`. The fleet's `state_dir` must be
on an encrypted disk: it opens every pool.

### The fleet in Docker (ADR 0060)

The fleet, not the host daemon, ships as an image: `ghcr.io/briq-cloud/briqyard-fleet:<version>`
(and `:latest` for a release that is not a pre-release; releases before the one that added it have no image), `linux/amd64` and `linux/arm64`, made
by the release workflow from the release's own binaries. The package is public: pulls need no login. It holds `briqyard-fleet` and the CLI
(`docker exec fleet briqyard host ls`). A host is still installed by `hack/bootstrap-host.sh`
(ADR 0028): it needs ZFS, `/dev/kvm`, firewall tables, bridges and cgroups, and its machines
outlive its daemon at a hand-over, which no container gives it.

| | |
|---|---|
| Base | `debian:trixie-slim` with `openssh-client` (the fleet installs hosts by running `ssh`), `curl` (the health check) and CA certificates |
| User | `briqyard`, uid and gid 10001; no root, no capability needed |
| Volumes | `/var/lib/briqyard-fleet` (`state_dir`: the registry and the pinned SSH host keys, mode `0700`, the fleet's alone, on an encrypted disk as above); `/etc/briqyard` (`fleet.yaml`, the SSH key, the TLS files: yours) |
| Configuration | `fleet.yaml` as for the unit, with paths inside the container. The image sets no `listen`: the file does |
| Credentials | `--env-file` (`BRIQYARD_RELEASE_TOKEN`, `BRIQYARD_S3_ACCESS_KEY`, `BRIQYARD_S3_SECRET_KEY`: same file shape as `fleet.env`); `BRIQYARD_LOG` sets the level |
| Health | `HEALTHCHECK` asks the fleet's `/healthz` at the address its `listen` names, over TLS or plain HTTP as `tls` says |
| Stop | `docker stop` sends SIGTERM: the calls in flight get 2 s, the exit is 0 |

What the container reads and writes must belong to uid 10001 (`chown`): a root-owned `0600`
SSH key cannot be read by `ssh`, and the fleet sets the mode of `state_dir` itself.

Once, on the server (the SSH key's public half goes in `authorized_keys` of every server you add,
as in step 4):

```bash
install -d -m 0700 -o 10001 -g 10001 /etc/briqyard /var/lib/briqyard-fleet
ssh-keygen -q -t ed25519 -N '' -f /etc/briqyard/fleet_ssh_key && chown 10001:10001 /etc/briqyard/fleet_ssh_key*
install -m 0600 -o 10001 -g 10001 /dev/null /etc/briqyard/fleet.env && nano /etc/briqyard/fleet.env   # BRIQYARD_RELEASE_TOKEN=…
install -m 0600 -o 10001 -g 10001 /dev/null /etc/briqyard/fleet.yaml && nano /etc/briqyard/fleet.yaml # as step 4
```

`docker run`, the layout of step 4 (a listener on loopback behind the edge, `tls: off`).
**`--network host`** keeps the address of every caller as the fleet sees it today: a host's
heartbeat and its pool key request are checked against the address they come from (ADR 0026),
and the `X-Forwarded-For` of an edge is trusted only from a loopback peer. A bridge network
with a published port changes both (the edge reaches the fleet from the bridge's gateway), so
use it only when the fleet serves its own TLS and no proxy is in front:

```bash
docker run -d --name briqyard-fleet --restart unless-stopped --network host \
  --env-file /etc/briqyard/fleet.env \
  -v /etc/briqyard:/etc/briqyard -v /var/lib/briqyard-fleet:/var/lib/briqyard-fleet \
  ghcr.io/briq-cloud/briqyard-fleet:<version>
```

The same as a Compose file:

```yaml
services:
  fleet:
    image: ghcr.io/briq-cloud/briqyard-fleet:<version>
    restart: unless-stopped
    network_mode: host
    env_file: /etc/briqyard/fleet.env
    volumes:
      - /etc/briqyard:/etc/briqyard
      - /var/lib/briqyard-fleet:/var/lib/briqyard-fleet
```

Day to day:

```bash
docker ps                                                  # STATUS: healthy
docker logs -f briqyard-fleet                              # the same JSON lines as journalctl -u briqyard-fleet
docker exec -e BRIQYARD_TOKEN=<fleet token> briqyard-fleet briqyard host add <ip> --address 10.42.0.11 --region gra
```

`keygen` and `restore` (below) are the fleet's subcommands: `docker run --rm -v … <image> restore --identity … --from …`
replaces the default arguments, and reads `/etc/briqyard/fleet.yaml` all the same.

**Upgrade**: pull the new tag, then replace the container; the fleet first, then the hosts
(`briqyard host upgrade`, above). Only the image changes: the registry and the configuration
are on the volumes. Pull before stopping, so the gap is the swap alone:

```bash
docker pull ghcr.io/briq-cloud/briqyard-fleet:<new version>
# docker run: docker rm -f briqyard-fleet, then the same command with the new tag
# Compose: change the tag in the file, then
docker compose up -d
```

A configuration field new in a release goes into `fleet.yaml` after the upgrade, and a rollback
is the older tag (see "Upgrade").

What a container loses against the unit (ADR 0051):

| | Unit | Container |
|---|---|---|
| The listening socket across a restart | Kept by systemd (`FileDescriptorStoreMax=1`): a call made meanwhile waits | Nothing keeps it: calls made between the stop and the new start are refused. Measured on a Mac, `docker restart`: 1.25 s |
| Restart after a crash | `Restart=on-failure`, 2 s | `--restart unless-stopped`, Docker's backoff from 0.1 s |
| Callers | Wait | A host sends its heartbeat each period, so one missed is the next; a call that lands in the gap is refused and its caller asks again |
| A `host upgrade` running at the stop | The host stays `draining` | The same: `briqyard host undrain <id>` |

The machines and the hosts' traffic are never in the fleet's path (the ingress is each daemon's),
so the gap is control only. Where it matters, keep the unit.

### The registry's backup (ADR 0032)

On your own machine, once: `briqyard-fleet keygen --out fleet-backup.key` prints the recipient
(`age1…`); keep the file off the fleet's host (two copies: a password manager and paper). In
the fleet's config:

```yaml
backup:
  store: s3://briqyard-backups/fleet     # or file:///path, development
  endpoint: https://s3.gra.io.cloud.ovh.net
  region: gra
  recipient: age1…                       # what keygen printed
```

with `BRIQYARD_S3_ACCESS_KEY` and `BRIQYARD_S3_SECRET_KEY` in the fleet's environment: the
fleet's own key, never a host's. In the bucket's policy the hosts' key writes `backups/` only and
the fleet's `fleet/` only, and versioning is on. The fleet
writes `fleet/registry.json.age` once a minute when the registry changed, and
`fleet/registry-<day>.json.age` with the last of each day; a host's pool key is served only once
the store holds it (503 `backup` otherwise). A failed write is `registry backup` at `error`.

To restore, on the fleet's host: stop the fleet, move `registry.json` aside if there is one,
copy the identity there for the moment, export the fleet's `BRIQYARD_S3_ACCESS_KEY` and
`BRIQYARD_S3_SECRET_KEY` (an S3 store), then

```bash
briqyard-fleet restore --identity fleet-backup.key        # --from fleet/registry-2026-10-21.json.age for a day's
```

which writes the registry (`0600`), refuses to write over one, and prints what the fleet will
trust: each host's id, url, pin prefix, token and pool key there or not, and the newest
heartbeat in the backup. Check them, then start the fleet and remove the identity from the
host. From the backup's last minute, a restore does not bring back an added host not yet
keyed (add it again), a rotated token (put it in the record), a drain, or a forget. Placements made since the backup come back from the hosts' heartbeats.
`age -d -i fleet-backup.key registry.json.age` reads a backup without us.

Where the fleet terminates the connection (its `tls`, or plain on loopback), a host's
heartbeat and key request must come from the address in its `url`: a host is listed by its
address, not a name. A fleet behind a proxy on the same machine (Caddy terminating TLS for
the fleet's name) has `tls: off` and a loopback `listen` (`127.0.0.1:7430`): the caller is
the last `X-Forwarded-For` value, which the proxy writes, and a call without one is refused.
Behind `tls: off` on any other address only the token is checked. **Retire or forget a host
before its server or a disk leaves our hands.** A disk the provider swaps while the host stays
carries the host's token: rotate it (a static host: a new `token` in its `hosts:` entry and in
its `/etc/briqyard/config.yaml`, then restart the fleet and the daemon; an added host: no
route yet, the same edit in `registry.json` with the fleet stopped).

The fleet's own listener serves TLS with a certificate of yours: `tls: { cert, key }`, PEM
files, a chain for the fleet's name (Let's Encrypt in production: `certbot certonly
--standalone -d fleet.example`, then `cert: /etc/letsencrypt/live/fleet.example/fullchain.pem`,
`key: …/privkey.pem`; restart the fleet after a renewal). Without `tls` it serves plain HTTP,
and refuses a non-loopback `listen` unless `tls: off` says something in front terminates TLS.
Hosts check the fleet against the web PKI roots.

### Capacity signals (ADR 0042)

When placement refuses a create for want of room, the fleet says where and what ran out. A
scaler of yours (or an alert and a person) reads it and adds a host with `briqyard host add`,
as Kubernetes's Cluster Autoscaler reads unschedulable pods. `GET /metrics` on the fleet,
Prometheus text:

| Series | Labels | What |
|---|---|---|
| `briqyard_fleet_hosts` | `state` | hosts in the registry |
| `briqyard_fleet_free_mb` | `resource="memory\|disk"`, `region` | free on the region's hosts that take a new namespace (ready, under `fill_ceiling`, no condition), summed |
| `briqyard_fleet_largest_slot_mb` | same | the most free on one of them: the largest machine (memory) or volume plus 2 GB (disk) the region still takes |
| `briqyard_fleet_unschedulable_total` | `resource="memory\|disk\|pressure"`, `region` | creates refused 503 `capacity` since the fleet started |

`memory`: no host had the memory free, or those with the room are under `memory_pressure`;
`disk`: hosts had the memory, none the disk, or those with both are under `disk_pressure`. A
new host fixes both. `pressure`: the namespace's own host (or a fork's source's) is under a
condition; a new host does not help, that host must be freed (or the namespace moved, below). A
region no host is in counts as `region="other"`; a create that asked for none, as `region=""`.
Those two carry `briqyard_fleet_unschedulable_total` only (and `""` the room too when a host
has no region): no host, no room. Counters start at 0 when the fleet starts. The token:
`metrics_token` in the fleet's config, or the API's; none on a loopback `listen` with `tls`
unset. `briqyard_fleet_host_state{host, region, state}` is 1 for each host's state.

`GET /v1/status` has the same per region (`regions`: `free`, `largest_slot`,
`unschedulable`; no `free` or `largest_slot` where no host is), and `briqyard host ls` prints
them under the hosts (`-` there). Each refusal is a `warn`
line `unschedulable` with `resource`, `region`, `namespace`, `host` (the namespace's), `memory_mb`,
`disk_mb` (asked) and `largest_memory_mb`, `largest_disk_mb` (the region's).

The alerts to watch them are in the monitoring stack (below): creates refused for memory or
disk (add a host in the region), for pressure (free the namespace's host), a largest slot under the
largest size you offer.

### Adding and removing hosts

The fleet buys no server (ADR 0042): you, or a scaler of yours reading the signals above, buy
one and add it.

```bash
briqyard host add 51.68.1.2 --address 10.42.0.11 --region gra   # POST /v1/hosts: a server you bought, bootstrapped
                                             # --public-tcp-ports 80,443,… (or none): its own, else the fleet's
briqyard host ls                             # its note says what the bootstrap last did
briqyard host retire h_123456                # POST /v1/hosts/{id}/retire: retiring, forgotten once empty
briqyard host drain h_123456                 # draining: no new namespace on it, kept
briqyard host undrain h_123456               # ready again, from draining or retiring
briqyard host rm h_123456                    # forget it (its machines are not touched)
```

A server added becomes a host on its own when the fleet's `bootstrap.enabled` is set: within
two minutes the fleet runs `hack/bootstrap-host.sh` on it over SSH (`ssh_user`, `ssh_key`: a
key the server takes for that user; `release`, `release_token`, `pool_device`, `fleet_url`,
`allowed_clients` for the script), with a token of its own for the host's API. A host whose API address is in `private_network` (a CIDR, the
vRack) is reached over SSH at its own address (`host add`'s first argument) and told its
private address: `private_interface` gets it when the server does not have it yet, and its
public interface takes SSH and `public_tcp_ports` only (ADR 0028). With `fleet_address` (the
fleet's own vRack address), the host resolves `fleet_url`'s name to it in `/etc/hosts`: the
fleet checks a host's calls by the address it knows the host at, its vRack one, and a call
through the public network would come from the public address and be refused
(`unknown_host`).
Once the script succeeds, a second connection, strict against the pinned SSH key, reads the
daemon's certificate fingerprint (`briqyardd tls-fingerprint`); the fleet pins it in the same
write that marks the host `bootstrapped` (the note says `api certificate … pinned`), and dials
`https://<ip>:7420` with it. A host whose API would be plain HTTP (a loopback `listen`, for
want of `allowed_clients`) fails the attempt.
The host is `bootstrapped` once the script succeeds and `ready` at its first heartbeat; a server
that cannot be installed after `max_attempts` is `failed`, with the last error in its note.
Without the bootstrap, run the script yourself with `FLEET_URL`, `ADVERTISE` and the
`BRIQYARD_TOKEN` the fleet holds for the host (an entry under `hosts:`).

#### A server that joins on its own (ADR 0059)

For a server the fleet cannot reach over SSH, or one made from an image: a bootstrap token, as `kubeadm token create`, and one line on the server (needs `bootstrap.enabled` and `bootstrap.release`). A token joins any number of servers until it expires or is revoked.

```bash
briqyard host token create --address 203.0.113.0/28 --ttl 2h --description "gra racks" --region gra --labels rack=a1   # prints <id>.<secret>, once
briqyard host token ls                                              # id, state, expiry, uses, last use, description
briqyard host token revoke ab12cd                                   # no new join takes it; hosts that joined stay
```

On the server, as root (`fleet.example` is `bootstrap.fleet_url`, as the server reaches it):

```bash
curl -fsSL --proto '=https' --proto-redir '=https' https://fleet.example/install.sh | FLEET_URL=https://fleet.example JOIN_TOKEN=<id>.<secret> sh
```

| Variable | |
|---|---|
| `FLEET_URL`, `JOIN_TOKEN` | required. `https://` only; `http://` needs `ALLOW_INSECURE_HTTP=1` (the secrets cross in clear) |
| `HOST_NAME` | the id to join as; default `h_` and the address. A token made with `--host` takes that id only |
| `BRIQYARD_POOL_DEVICE` | this server's drives; default the fleet's `bootstrap.pool_device` |

| `host token create` | |
|---|---|
| `--ttl <duration>` | how long it can be used: `30m`, `2h`, `7d`; default 24 hours; **`--ttl 0` never expires**; at most ten years otherwise. An expired token is refused and listed `expired` |
| `--description <text>` | free text, one line, shown in `host token ls` |
| `--address <IP or CIDR>` | **our addition to kubeadm's model.** The join must come from this address or network; from anywhere else the token is refused (the same `invalid_token`, the reason in the fleet's log). Without it, any holder of the token can join from anywhere, as with kubeadm |
| `--host`, `--region`, `--labels` | the id the host must join as, and the region and labels it is put in |

The token is reusable: each join is counted (`USES`) and the last is shown (host, address, time); every join is also a `warn` line in the fleet's log and in the host's note, both naming the token (the refusal lines are limited to one a minute per address). The fleet keeps the hash of the secret. **A leaked token joins hosts until it expires or is revoked**, and a host that joins is placed workloads once ready and is handed the release credentials (`bootstrap.release_token`) and, through its own host token, `bootstrap.script`: so a token holder reads whatever you wrote in that script, and nothing should be in it that your servers should not all hold. Keep the TTL short, `host token revoke` a token once the servers are in (hosts that joined stay), and **bind it with `--address`** whenever you know where the servers are; leave `--address` out for an image that boots on an address you do not know, and `--ttl 0` for a token you mean to keep in such an image, and revoke it when it leaves use. Expired and revoked tokens stay listed 30 days, with their uses, then are dropped. The call must come from the address the host will serve its API at, and the fleet must see it (its own TLS, or a loopback proxy setting `X-Forwarded-For`); a host on the private network joins over it. The fleet records the host `joining` and answers the settings `host add` would send over SSH. `install.sh` checks the server first (root, Ubuntu, KVM, the drives) and joins last; it then fetches `bootstrap-host.sh` from the fleet, which serves it only to the host that joined, on its own token from its own address (`bootstrap.script` may hold what the fleet cannot vouch for). The script is the one `host add` runs: it downloads the release's binaries and checks them against its `SHA256SUMS`. If the install fails after the join, run the same line again: a new join replaces the `joining` record when it comes from that record's address or with the token that made it (any other join at its id is a `conflict`; a host that heartbeated is never replaced). The host's first heartbeat pins its certificate, which the fleet logs and writes into the host's note: compare it with `briqyardd tls-fingerprint` on the server. The token is printed once, on stdout. The machines' store credentials are written on the host as for any other (`briqyardd.env`, ADR 0041). `host upgrade` reaches a joined host only if the fleet's SSH key is authorized on it.

The fleet is given no SSH host key with the server, so the bootstrap pins the key it sees:
the first attempt that succeeds appends it to `<state_dir>/known_hosts` and writes its
fingerprint into the host's note (`ssh host key SHA256:… ed25519 pinned at first connect`);
compare it with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the server. Every later
connect is strict against that file. A server reinstalled has a new key: remove its line from
the file.

A retire makes the host `retiring` (no new namespace lands on it) and forgets it once it runs
nothing: at once when it is already empty (the answer says `retired`), else within a minute of
its last machine's destroy. The server stays yours: give it back to its provider yourself. A
host from the `hosts:` list is retired by removing it from the configuration; forgotten through
the API, it is back on the next poll.

### Moving a machine to another namespace

```bash
briqyard machine move <id> --namespace <namespace>
```

Alone in its namespace and the target new: the namespace is renamed, the machine keeps its
address and is not restarted. The target exists on the host: the machine is stopped, takes an
address there and starts again (`restarted: true`, `previous_ip`); a machine that was not
running stays as it is. Through a fleet, the target pinned to another host: refused (409 `other_host`) before
anything happens, naming both hosts; moving across hosts is not supported yet, use the
procedure below. The namespace it left
stays until `briqyard namespace rm`. Refused (409): another machine sends its traffic through
this one, the target has a machine of that name, a snapshot with memory exists (it would resume
on the old address; delete it), the machine is starting, stopping or destroying. ADR 0056.

### Moving a namespace

Machines do not move between hosts on their own: a draining host keeps its namespaces until they
are removed. To take a namespace off a host (draining, full, or gone):

```bash
briqyard host drain h_old                          # nothing new lands there
briqyard machine backup <id>                       # each machine of the namespace (ADR 0008)
briqyard machine destroy <id>                      # each one, once its backup is listed
briqyard namespace rm <namespace>                        # its network and gateway on the old host; unpins it
briqyard machine restore --from <id> --namespace <namespace> --name <name>   # placed afresh
```

The old host keeps the destroyed machines' backups for `backup.keep_destroyed_days` (ADR
0023): `briqyard backups --namespace <namespace>` lists them with the new ones, and `briqyard backup
rm <id> <backup> --namespace <namespace>` deletes them on the host that holds them (ADR 0045).

A namespace's gateway (ADR 0016) is not backed up: `briqyard namespace gateway set` it again once the
namespace is unpinned (the fleet places the namespace with it), before the restores of its
`via:gateway` machines.

`briqyard namespace unpin <namespace>` (`POST /v1/namespaces/{id}/unpin`) drops the pin without asking
the host, for a host that is down for good or a pin left on a full host. A namespace unpinned
while it still has machines on a host is pinned back there by the host's next heartbeat, and a
machine created in between lands on another host, where it cannot reach the others: unpin
once the namespace has nothing left on the host, or mean to abandon what is there.

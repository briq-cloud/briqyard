# Operating a briqyard host

What an operator needs: how to install a host, what the configuration means, where things
live, how to upgrade, what to watch, and what to do when something is off.

## Install

A Linux server with KVM (`/dev/kvm`), Ubuntu 24.04 or newer. As root:

```bash
curl -fsSLO https://raw.githubusercontent.com/briq-cloud/briqyard/main/hack/bootstrap-host.sh
BRIQYARD_RELEASE=https://github.com/briq-cloud/briqyard/releases/download/v0.1.0 \
BRIQYARD_POOL_DEVICE=/dev/nvme1n1 \
BRIQYARD_TOKEN=$(openssl rand -hex 24) \
ALLOWED_CLIENTS=10.0.0.0/8 \
bash bootstrap-host.sh
```

It installs the packages (ZFS, nftables, e2fsprogs), makes the pool (on the device given, or on
a file for a trial), downloads Firecracker, its jailer and a guest kernel, installs the
binaries, writes `/etc/briqyard/config.yaml` and the systemd unit, and starts `briqyardd`.
With `FLEET_URL`, `FLEET_TOKEN` and `ADVERTISE` set, the host registers with a fleet.

| Variable | Default | Meaning |
|---|---|---|
| `LISTEN` | `0.0.0.0:7420` | The API's address; TCP endpoints and the HTTP ingress bind the same address |
| `ALLOWED_CLIENTS` | none | Comma-separated IPv4 CIDRs (a bare address is a `/32`) allowed to connect: the fleet's and the routers' networks. Written as `ingress.allowed_clients` |
| `ALLOW_PUBLIC` | none | `1` writes `ingress.allow_public: true`: anyone can connect, a firewall of your own is in front |
| `FIRECRACKER_VERSION`, `FIRECRACKER_SHA256` | `v1.17.0` and its release digest | The Firecracker and jailer every host runs |
| `KERNEL_URL`, `KERNEL_SHA256` | the CI build of `vmlinux-6.18.54` | The guest kernel; the digest is checked after the download |

A public `LISTEN` needs `ALLOWED_CLIENTS` or `ALLOW_PUBLIC`: with neither, the script binds
the API and the endpoints to loopback (the daemon refuses to start on a public bind without
one), and a host nobody reaches is the safe side. Every host runs the same
Firecracker and kernel, so a memory snapshot resumes anywhere and two hosts never differ by
the day they were installed; run the script again with new pins to upgrade them (stop
suspended machines first: a snapshot resumes only under the Firecracker that wrote it). The
kernel comes from Firecracker's CI bucket until we build and host it ourselves.

Then, from anywhere that reaches the host:

```bash
export BRIQYARD_URL=http://<host>:7420 BRIQYARD_TOKEN=<token>
briqyard status
```

## Configuration

`/etc/briqyard/config.yaml`; every field has a default.

| Field | Default | Meaning |
|---|---|---|
| `listen` | `127.0.0.1:7420` | The API. Listen wider only behind TLS or on a private network |
| `token` | none | Required as `Authorization: Bearer` on every request when set |
| `data_dir` | `/var/lib/briqyard` | State (`state/`), run files (`run/`), image metadata (`images/`), jails (`jail/`) |
| `firecracker`, `jailer`, `kernel`, `init` | `/usr/local/bin/...`, `/var/lib/briqyard/vmlinux` | The binaries and the guest kernel. No `jailer`: Firecracker runs as root (development only) |
| `jail_dir`, `jail_uid_base` | `<data_dir>/jail`, `100000` | Where chroots go; each machine gets a uid of its own from this base |
| `kernel_args` | none | Appended to the boot arguments |
| `pci` | `false` | Firecracker's PCI transport (needs a guest kernel with PCI) |
| `root_disk_gb` | `8` | Size of every root disk (thin) |
| `image_keep_days` | `14` | An image no machine uses is removed this long after it was built |
| `image_resolve_minutes` | `10` | A tag's digest is reused this long before the registry is asked again; when the registry refuses (a rate limit), the image already on the host serves |
| `boot_timeout_sec` | `120` | How long a guest may take to answer after its process starts |
| `boots_at_once` | half the threads, at least 2 | Boots run at once; the rest wait their turn, each with the whole timeout |
| `backup.store` | none | `s3://bucket/prefix` or `file:///path`; set, `POST /v1/machines/{id}/backups` works. Credentials in `BRIQYARD_S3_ACCESS_KEY` / `BRIQYARD_S3_SECRET_KEY` |
| `backup.endpoint`, `backup.region` | none | The S3 endpoint (`https://s3.fr-par.scw.cloud`) and region |
| `backup.keep_snapshots` | `1` | Backup snapshots kept on the host per machine (the newest is the base of the next incremental send) |
| `suspend_on_sleep` | `false` | Sleep with a memory snapshot: wakes in a quarter second, costs the machine's memory in disk |
| `storage.pool` | `byard` | The ZFS pool or dataset for every disk |
| `registries[]` | none | `{host, username, password}` for private registries |
| `network.range` | `10.64.0.0/10` | Tenant subnets, one /24 each (16,384 tenants) |
| `network.upstream_dns` | the host's, then `1.1.1.1` | Where the gateway forwards DNS |
| `network.egress` | the default route's interface | Where machines reach the internet |
| `ingress.tcp_ports` | `20000-29999` | Host ports handed to TCP endpoints |
| `ingress.bind` | `0.0.0.0` | Where TCP endpoints listen. A public address makes every endpoint public: bind a private one, or firewall the range |
| `ingress.allowed_clients` | none | CIDRs allowed to connect to the API, the endpoints and the HTTP ingress; required with a public `listen`, `bind` or `http` |
| `ingress.allow_public` | `false` | Start on a public address with no `allowed_clients`: a firewall of your own is in front |
| `ingress.advertise` | the host's primary address | The address endpoints are reported at (`address` on an endpoint): what a router on another machine dials, a private address when the host has one |
| `ingress.http`, `ingress.domain` | off, `byard.localhost` | The shared HTTP listener and the suffix of its host names |
| `capacity.memory_mb`, `capacity.vcpus` | host memory − 2 GB, threads × 4 | What the host hands out; shared vCPUs oversubscribe |
| `fleet.url`, `fleet.token`, `fleet.advertise`, `fleet.region` | none | Register with a fleet, every 15 s |

## Where things live

| Path | What |
|---|---|
| `<data_dir>/state/{machines,tenants,endpoints}/*.json` | The records, one file each, written atomically |
| `<data_dir>/run/<machine>/` | `console.log` (the guest's serial console, timestamped), `config.tar` (the config drive), sockets when not jailed |
| `<data_dir>/jail/firecracker/<machine>/root/` | The chroot: kernel, config drive, device nodes, sockets, `snap.state` and `snap.mem` while suspended |
| `<data_dir>/images/meta/*.json` | What each image is |
| `byard/images/<key>` | A root disk per image, with its `@base` snapshot |
| `byard/m/<machine>/root`, `.../data` | A machine's disks |

Every disk is a ZFS zvol: `zfs list -t all -r byard` shows them, `zfs get used,referenced` what
they take. A machine's `fork-*` and `s_*` snapshots on its disks are its forks' and its own.

## Upgrade

Install the new binaries and `systemctl restart briqyardd`. The daemon suspends every running
machine on the way down (a memory snapshot each) and marks it so; each one resumes on its next
use, in about a quarter of a second. Nothing reboots. A daemon that crashes instead leaves its
machines running (`KillMode=process`), and the next daemon adopts them.

The guest kernel and `briqyard-init` are baked into root disks: an image built with an older
init keeps it until the image is rebuilt (a new init hash makes a new image key; the old disk is
garbage-collected once no machine uses it).

## Backups

With `backup.store` set, `briqyard machine backup <id>` (`POST /v1/machines/{id}/backups`)
snapshots the machine's disks and streams them to the store: whole the first time, then only
what changed since the last backup whose snapshot is still on the host (`zfs send -c -i`).
Each backup is a record (`backups/<machine>/<id>.json`, the machine's spec included, secrets
included: the store is as sensitive as the host) plus one object per disk. A backup of a
running machine is crash-consistent, what a power cut would leave; stop the machine first for
a clean one, or let the application do its own consistency (Postgres does).

`briqyard machine backups <id>` lists them, from the store, so a machine that no longer exists
still has them. `briqyard machine restore --from <machine id> [--backup <id>] --tenant T --name
N` makes a new machine from one (`POST /v1/machines` with `restore`): the whole chain of
streams is received into fresh datasets, and the image, command, env, files, size and volume
come from the record unless the request sets them. Any host that reaches the store can
restore, which is how a machine moves off a dead host.

The state itself (`state/`) is small and lives only on the host; a lost host loses the records
of machines that were never backed up, and their disks. A machine's own `POST
/v1/machines/{id}/snapshots` is a local snapshot of its disks: instant, copy-on-write, not a
backup until sent elsewhere.

## Watch

- `GET /healthz`: the daemon is up. `GET /v1/status`: capacity, use, free disk.
- `GET /metrics`: Prometheus text: machines by state, memory and vCPUs used and capacity, free
  disk, counters of boots, resumes, suspends, execs and failed starts.
- Logs: one JSON line per event on stderr (journald under systemd): `journalctl -u briqyardd
  -o cat | jq`. Level with `BRIQYARD_LOG=debug` (or any `tracing` filter).
- A machine: `briqyard machine get <id>` (state, why it stopped, its process's exit), `briqyard
  machine logs <id>` (its console; `-f` follows).
- `briqyard machine stats <id>`: CPU time, memory and disk it uses now, from its cgroup and its
  datasets. `briqyard machine set-sleep <id> 3h|never` changes the window without a restart.

## When something is off

| Symptom | Look at |
|---|---|
| A create ends in `state: error` | `error` on the machine; the last console lines are in it. Then `briqyard machine logs` |
| The process exits at once (`stopped`, `exit.code`) | `briqyard machine logs`: the image's own output. `restart.policy: on-failure` tries three times |
| `the guest did not come up` | The kernel booted but the init did not answer on vsock within 60 s: console log, then the kernel (`kernel`) and init (`init`) paths |
| `no host has room` (fleet) | `briqyard host ls`: fill, free memory, free disk |
| `host h_… is down` (fleet, 503) | The host missed its heartbeats for `placement.down_after_sec`: its machines answer again once it is back. `briqyard host ls`, then the host's `journalctl -u briqyardd` |
| An endpoint connects but the service refuses | The machine was waking: clients retry, as connection pools do. Postgres accepts TCP before it is ready |
| `dataset is busy` | A zvol a Firecracker just released; the daemon retries for ten seconds |
| A jail refuses to start | `<run>/<machine>/console.log` holds the jailer's own messages |

## A fleet

`briqyard-fleet` runs anywhere that reaches every host (`/etc/briqyard/fleet.yaml`, unit in
`hack/briqyard-fleet.service`). Hosts either register themselves (`fleet:` in their config,
with the fleet's `host_token`) or are listed under `hosts:` and polled. Clients use the fleet's
URL and `token` as they would a daemon's; `briqyard host ls` shows the hosts.

### Adding and removing hosts

Hosts come and go through the API, by hand or from the autoscaler; both use the same
provisioner (`kind: hetzner-robot`, `scaleway` or `ovh`, credentials through `HETZNER_ROBOT_USER` /
`HETZNER_ROBOT_PASSWORD`, `SCW_SECRET_KEY`, or `OVH_APPLICATION_KEY` / `OVH_APPLICATION_SECRET` /
`OVH_CONSUMER_KEY`). Every provisioner is `dry_run: true` until the configuration says
otherwise: it records what it would order and orders nothing. Turn it off only once a dry run
has shown the right product, location and count.

```bash
briqyard host order --reason "launch week"   # POST /v1/hosts/order: a server, state provisioning
briqyard host ls                             # its note says what the provider and the bootstrap last did
briqyard host retire h_123456                # POST /v1/hosts/{id}/retire: drain, then release once empty
briqyard host drain h_123456                 # place no new tenant on it, keep it
briqyard host rm h_123456                    # forget it (its machines are not touched)
```

**OVHcloud** (`kind: ovh`) orders a dedicated server from the Eco range (Kimsufi, So you
Start, Rise; `ovh.range: eco`) or the Bare Metal range (Advance, Scale; `ovh.range: baremetal`)
through the API's cart: `ovh.plan_code` (`25risem01-v2` for example, from the catalog), in
`ovh.datacenter` (`gra`, `rbx`, `sbg`...), one month at a time, paid with the account's
preferred payment method and the retraction period waived, with the plan's default options
(memory, disks, bandwidth are not chosen here) and no OS. `ovh.subsidiary` is the OVH company
the order is made under (`FR` by default). The credentials are an API application
(`application_key`, `application_secret`) and a consumer key with rights on `/order/*`,
`/me/order/*`, `/dedicated/server/*` and `GET /me`; every request is signed with them and
OVH's own clock (`/auth/time`). The provider id is `order:<orderId>` until delivery. Every two
minutes the fleet reads the order's status; once it is `delivered`, it assumes one of the
order's details carries the server's service name as `domain` (a placeholder like `*001`
before), checks that name against the account's server list (`GET /dedicated/server`), reads
the server for its address, and starts an Ubuntu 24.04 install
(`POST /dedicated/server/<name>/install/start`, template `ubuntu2404-server_64`) with the SSH
key named `ovh.ssh_key_name`, which must already be in the account (`/me/sshKey`); the
bootstrap then fails every two minutes until the install is done, which is expected. A
delivered order whose details name no server of the account is an error in the host's note:
add the host by hand. A retire terminates the server (`POST /dedicated/server/<name>/terminate`):
OVH then emails a confirmation to accept, and the server is billed to the end of its period;
a retire before delivery is refused (cancel the order in the OVH manager). This provisioner has
not run against the real API yet: the request shapes follow OVH's API console, and the
delivery assumption above is the one to check first.

A server the fleet ordered becomes a host on its own when `provisioner.bootstrap.enabled` is
set: every two minutes the fleet asks the provider for the server's address, then runs
`hack/bootstrap-host.sh` on it over SSH (`ssh_user`, `ssh_key`: the key the provider installed;
`release`, `pool_device`, `fleet_url`, `allowed_clients` for the script), with a token of its
own for the host's API.
The host is `bootstrapped` once the script succeeds and `ready` at its first heartbeat; a server
that cannot be installed after `max_attempts` is `failed`, with the last error in its note.
Without the bootstrap, run the script yourself with `FLEET_URL` and `FLEET_TOKEN` set.

A retire drains the host first (no new tenant lands on it) and releases it at the provider
once it runs nothing: at once when it is already empty, else from the hourly pass as soon as
its last machine is destroyed. Machines do not move between hosts: a draining host keeps its
tenants until they are removed. A host from the `hosts:` list is retired by removing it from
the configuration; forgotten through the API, it is back on the next poll.

The autoscaler (`provisioner.enabled: true`) orders a host when no ready host has a slot of
`slot_mb` left and releases a provisioned host empty for `idle_grace`, between `min_hosts` and
`max_hosts`, one change a minute.

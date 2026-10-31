# Operating a briqyard host

What an operator needs: how to install a host, what the configuration means, where things
live, how to upgrade, what to watch, and what to do when something is off.

## Install

A Linux server with KVM (`/dev/kvm`), Ubuntu 26.04 (every suite runs there; 24.04 is untested).
Through a fleet, `briqyard host add` runs the script for you (below, and "First OVH host"). By hand, as root:

```bash
curl -fsSLO https://raw.githubusercontent.com/briq-cloud/briqyard/main/hack/bootstrap-host.sh
BRIQYARD_RELEASE=https://github.com/briq-cloud/briqyard/releases/download/v0.1.8 \
BRIQYARD_POOL_DEVICE=/dev/nvme0n1,/dev/nvme1n1 \
BRIQYARD_TOKEN=$(openssl rand -hex 24) \
PRIVATE_ADDRESS=10.42.0.11/16 ALLOWED_CLIENTS=10.42.0.0/16 \
bash bootstrap-host.sh
```

It installs the packages (ZFS, nftables, conntrack-tools, e2fsprogs, gdisk), caps the ZFS cache, turns swap off
for good, puts the API on the private network and closes the public interface when
`PRIVATE_ADDRESS` is set, makes the pool encrypted (on the devices given, or on a file for a
trial; ADR 0026), downloads Firecracker, its jailer and a guest kernel, installs the binaries
(each checked against the release's `SHA256SUMS-<arch>`), writes `/etc/briqyard/config.yaml`
(`0600`) and the systemd unit, and starts `briqyardd`.
The pool's key is the fleet's for this host when `FLEET_URL` is set (asked with
`BRIQYARD_TOKEN`, never written on the host); without a fleet, the script makes one in
`/etc/briqyard/pool.key` (`0600`): keep a copy off the host, the pool is unreadable without it.
A pool that exists and is not encrypted stops the script: ZFS cannot encrypt it in place.
Off loopback the API serves TLS with a certificate the daemon makes once (ADR 0020); the script
prints its fingerprint (`== api certificate`, `sha256 <64 hex digits>`).
With `FLEET_URL` and `ADVERTISE` set, the host registers with a fleet, presenting
`BRIQYARD_TOKEN`: the fleet takes the registration only when it expects that token at that
address (the host's `hosts:` entry, below).

| Variable | Default | Meaning |
|---|---|---|
| `BRIQYARD_POOL_DEVICE` | none (a file, `BRIQYARD_POOL_FILE_GB`, 50) | One device, or two comma-separated for a mirror (ADR 0028): a partition, an empty disk, or a disk with the OS on part of it, whose largest free space (10 GB or more) becomes a `briqyard-pool` partition. Mounted, swap, RAID or LVM members, any filesystem and a pool not imported (a re-run with the pool exported: `zpool import byard`) are refused; nothing is overwritten |
| `BRIQYARD_RELEASE`, `BRIQYARD_RELEASE_TOKEN` | `./bin` | Where the binaries are; each checked against the release's `SHA256SUMS-<arch>`. The token (contents read) fetches a private GitHub repository's release through its API |
| `BRIQYARD_ARC_GB` | 10 % of memory, 1 to 16 | The ZFS cache's ceiling (`/etc/modprobe.d/briqyard-zfs.conf`); the daemon's default capacity leaves it out |
| `PRIVATE_ADDRESS` | none | The host's address on a private network, with its prefix (`10.42.0.11/16`): `LISTEN`, the endpoints and `ADVERTISE` default to it, and the public interface takes SSH and `PUBLIC_TCP_PORTS` only (`nft list table inet briqyard_host`, loaded by `briqyard-firewall.service` at boot) |
| `PRIVATE_INTERFACE` | none | Where `PRIVATE_ADDRESS` is put (netplan, `/etc/netplan/60-briqyard-private.yaml`) when no interface has it yet |
| `PUBLIC_TCP_PORTS` | none | Ports the public interface takes besides SSH's own (read from `sshd -T`), comma-separated: an edge's beside the daemon (80, 443, its TCP listeners). Written as `network.host_ports` too |
| `LISTEN` | `PRIVATE_ADDRESS`'s, else `0.0.0.0:7420` | The API's address; TCP endpoints and the HTTP ingress bind the same address |
| `ALLOWED_CLIENTS` | none | Comma-separated IPv4 CIDRs (a bare address is a `/32`) allowed to connect: the fleet's and the routers' networks. Written as `ingress.allowed_clients` |
| `ALLOW_PUBLIC` | none | `1` writes `ingress.allow_public: true`: anyone can connect, a firewall of your own is in front |
| `BRIQYARD_KEY_FILE` | `/etc/briqyard/pool.key` | Without `FLEET_URL`: the pool's key file, made when missing, written as `storage.key: file:…` |
| `FIRECRACKER_VERSION`, `FIRECRACKER_SHA256` | `v1.17.0` and its release digest | The Firecracker and jailer every host runs |
| `KERNEL_URL`, `KERNEL_SHA256` | the CI build of `vmlinux-6.18.54` | The guest kernel; the digest is checked after the download |

A public `LISTEN` needs `ALLOWED_CLIENTS` or `ALLOW_PUBLIC`: with neither, the script binds
the API and the endpoints to loopback (the daemon refuses to start on a public bind without
one), and a host nobody reaches is the safe side. Every host runs the same
Firecracker and kernel, so two hosts never differ by the day they were installed; new pins
reach a host through an upgrade (below). The kernel comes from Firecracker's CI bucket until
we build and host it ourselves.

Then, from anywhere that reaches the host:

```bash
export BRIQYARD_URL=https://<host>:7420 BRIQYARD_TOKEN=<token> BRIQYARD_TLS_FINGERPRINT=<fingerprint>
briqyard status
```

The CLI trusts the daemon's certificate by that fingerprint alone. To read it again on the host:
`briqyardd tls-fingerprint`, or `openssl x509 -in /var/lib/briqyard/api-cert.pem -noout
-fingerprint -sha256` (colons and case do not matter).

### A registry mirror per region (ADR 0036)

One host of each region runs Zot, a pull-through mirror of Docker Hub, on its private address;
every daemon of the region pulls through it:

```bash
MIRROR_LISTEN=10.0.0.5:7440 bash hack/install-mirror.sh     # on that host, as root
```

```yaml
registry_mirrors:                                             # every host's config.yaml
  docker.io: http://10.0.0.5:7440
```

The script installs the pinned Zot (checked by digest), `hack/mirror/zot.json` with the
address, and the unit `briqyard-mirror` (data in `/var/lib/briqyard-mirror`); it refuses a
public address: the mirror has no authentication. Keep port 7440 to the private network in
the host firewall. Down, the daemons pull from Docker Hub as before (`journalctl -u briqyardd |
grep "mirror failed"`); `image_pulled` events say `through <mirror>` when it served.

## Configuration

`/etc/briqyard/config.yaml`; every field has a default.

| Field | Default | Meaning |
|---|---|---|
| `listen` | `127.0.0.1:7420` | The API. A public address is refused without `ingress.allowed_clients` or `ingress.allow_public` (ADR 0012). TLS unless loopback or `api_tls: false`; `/metrics` and `/healthz` too |
| `api_tls` | `true` | TLS on a non-loopback `listen`, with the daemon's own certificate (`<data_dir>/api-cert.pem`, made once, ADR 0020). `false`: plain HTTP on any address |
| `token` | none | Required as `Authorization: Bearer` on every request when set |
| `metrics_token` | none | A token of its own for `/metrics`, so a scraper never holds the API's (the API's opens it too: the fleet relays with it, ADR 0054). On a loopback `listen`, `/metrics` and `/v1/openapi.yaml` need no token at all |
| `data_dir` | `/var/lib/briqyard` | State (`state/`), run files (`run/`), image metadata (`images/`), jails (`jail/`). All of it `0700`, root's: records and config drives hold namespace secrets |
| `firecracker`, `jailer`, `kernel`, `init` | `/usr/local/bin/...`, `/var/lib/briqyard/vmlinux` | The binaries and the guest kernel. No `jailer`: Firecracker runs as root (development only) |
| `jail_dir`, `jail_uid_base` | `<data_dir>/jail`, `100000` | Where chroots and memory snapshots go: the daemon mounts `<pool>/jail` there, so they land on the pool, not on `/` (ADR 0014). Each machine gets a uid of its own from this base |
| `kernel_args` | none | Appended to the boot arguments |
| `pci` | `false` | Firecracker's PCI transport (needs a guest kernel with PCI) |
| `root_disk_gb` | `8` | Size of every root disk (thin) |
| `image_keep_days` | `14` | An image no machine uses is removed this long after it was built; under disk pressure, sooner (ADR 0021) |
| `usage_keep_days` | `90` | Closed hours of usage (`GET /v1/usage`) are kept this long, then removed by the tick |
| `events_keep_days` | `7` | Events (`GET /v1/events`, ADR 0019) are kept this long, and at most 100,000 lines per host; whole hours go, the newest always stays. Repeats of `session_opened`, `quota_exceeded`, `ready` and `not_ready` within 10 minutes of their line are one line with `count` (ADR 0047) |
| `image_resolve_minutes` | `10` | A tag's digest is reused this long before the registry is asked again (a `HEAD`, which Docker Hub does not count as a pull); when the registry refuses (a rate limit), the image already on the host serves |
| `conditions.memory_pct` | `95` | `memory_pressure` when committed memory is over this share of capacity (ADR 0021): the fleet places nothing new on the host |
| `conditions.disk_free_pct` | `10` | `disk_pressure` when the pool's free space is under this share of its size: the fleet places nothing new, and unused images go, oldest first, until it is back. `0`: never |
| `console_max_mb` | `64` | A running machine's console is rotated past this size; one previous file is kept |
| `boot_timeout_sec` | `120` | How long a guest may take to answer after its process starts |
| `boots_at_once` | half the threads, at least 2 | Boots run at once; the rest wait their turn, each with the whole timeout |
| `backup.store` | none | `s3://bucket/prefix` or `file:///path`; set, `POST /v1/machines/{id}/backups` works. Credentials `BRIQYARD_S3_ACCESS_KEY` / `BRIQYARD_S3_SECRET_KEY` in `/etc/briqyard/briqyardd.env` (root's, `0600`), read at the next start: change them with a hand-over, never `systemctl restart` (ADR 0041) |
| `backup.endpoint`, `backup.region` | none | The S3 endpoint (`https://s3.fr-par.scw.cloud`) and region |
| `backup.keep_snapshots` | `1` | Backup snapshots kept on the host per machine (the newest is the base of the next incremental send) |
| `backup.default_every`, `backup.default_keep` | none | The schedule of a machine created without `backup` (ADR 0023): both or neither, `every` at least `1h`, `keep` at least 1 |
| `backup.at_once` | `2` | Scheduled backups (and expired holders' deletions) the tick runs at once |
| `backup.keep_destroyed_days` | `30` | A destroyed machine's backups stay this long, then go with its holder |
| `suspend_on_sleep` | `false` | Sleep with a memory snapshot: wakes in a quarter second, costs the machine's memory in disk |
| `storage.pool` | `byard` | The ZFS pool or dataset for every disk. Encrypted: the daemon refuses one that is not (ADR 0026) |
| `storage.key` | `file:/etc/briqyard/pool.key` | Where the pool's key comes from when it is not loaded (after a reboot): `fleet` (`POST /v1/hosts/key` on `fleet.url`, with `token`, as the host at `fleet.advertise`) or `file:<absolute path>` (64 hex digits). Not read while the key is loaded |
| `registries[]` | none | `{host, username, password}` for private registries, `host` the registry as a reference names it (`ghcr.io`; `docker.io` for Docker Hub) |
| `registry_mirrors` | none | A pull-through mirror per registry, `{docker.io: http://10.0.0.5:7440}` (ADR 0036): an image's content is pulled from it first, from the registry when it fails; a tag is always resolved by the registry, and everything is checked by digest. The mirror gets no credentials |
| `network.range` | `10.64.0.0/10` | Namespace subnets, one /24 each (16,384 namespaces) |
| `network.upstream_dns` | the host's, then `1.1.1.1` | Where the gateway forwards DNS |
| `network.egress` | the default route's interface | Where machines reach the internet |
| `network.host_ports` | none | TCP ports of the host's own services (an edge beside the daemon, ADR 0028) that machines with egress `open` reach at the host's addresses, as the internet does; never at a namespace's `.1`. Not the daemon's ports, nor 53 |
| `egress_limits.blocked_ports` | `[25]` | Destination ports no machine reaches on the internet, TCP and UDP (ADR 0018). A machine's own `limits` override each field |
| `egress_limits.new_connections_per_minute` | `0` (none) | New internet connections a machine may open a minute, as many at once |
| `egress_limits.bandwidth_mbit` | `0` (none) | A machine's internet bandwidth, in and out together; at most 100000 |
| `disk_limits.bandwidth_mb_per_vcpu` | `32` | MB a second on each disk of a machine (root and volume), per vCPU of its size (ADR 0030). A machine's own `disk_limits` override each field with an absolute value. `0`: none |
| `disk_limits.iops_per_vcpu` | `4000` | Disk requests a second, per vCPU, on each disk. `0`: none |
| `disk_limits.burst_sec` | `10` | Seconds at those rates let through at full speed once after a start, a wake or a change |
| `ingress.tcp_ports` | `30000-32767` | Host ports handed to TCP endpoints (2,768; Kubernetes' NodePort range: under the kernel's ephemeral ports, no well-known service's, ADR 0028). `network.host_ports` must be outside it |
| `ingress.bind` | `127.0.0.1` | Where TCP endpoints listen. A public address is refused without `ingress.allowed_clients` or `ingress.allow_public` |
| `ingress.allowed_clients` | none | The IPv4 networks (`a.b.c.d/n`) that may reach the API, the HTTP ingress and the TCP endpoints; rendered into the daemon's nftables table (`nft list table inet briqyard`). Loopback always may. Empty: anyone who can route to the address |
| `ingress.allow_public` | `false` | Start on a public address with `allowed_clients` empty: a firewall of your own keeps the daemon's ports from the internet |
| `ingress.advertise` | the host's primary address | The address endpoints are reported at (`address` on an endpoint): what a router on another machine dials, a private address when the host has one |
| `ingress.http`, `ingress.domain` | off, `byard.localhost` | The shared HTTP listener and the suffix of its host names |
| `capacity.memory_mb`, `capacity.vcpus` | host memory − `reserved_memory_mb` − the ZFS cache's ceiling (`zfs_arc_max`, when set), (threads − `reserved_threads`) × 4 | What the host hands out; shared vCPUs oversubscribe |
| `capacity.reserved_memory_mb`, `capacity.reserved_threads` | `2048`, `0` | What the default capacity leaves to the host and its other services (an edge: 3072); unused when `memory_mb` or `vcpus` is set |
| `fleet.url`, `fleet.advertise`, `fleet.region` | none | Register with a fleet every 15 s, presenting `token` and the certificate's fingerprint. `advertise` has the API's scheme (`https://` for TLS), or the daemon refuses to start. An `http://` `url` must be a loopback or private address (ADR 0026) |

## A proxy in front

Endpoints are plain TCP and HTTP on the host, with no TLS, public names or access control:
those are a proxy's, as an ingress controller's in Kubernetes. The smallest setup is a proxy
on the host itself, the daemon's listeners on loopback. In `config.yaml`, before the first HTTP
endpoint (an endpoint keeps the name it got), then `systemctl restart briqyardd`:

```yaml
ingress:
  http: 127.0.0.1:8080          # the HTTP listener, routed by Host
  domain: apps.example.com      # an HTTP endpoint labelled web is web.apps.example.com
```

```bash
briqyard endpoint add <id> 3000 --http --host web   # web.apps.example.com → port 3000
briqyard endpoint add <db> 5432                     # a host port, 30000-32767: `endpoint ls`
```

HTTP, with [Caddy](https://caddyserver.com) on 80 and 443 (`/etc/caddy/Caddyfile`). Caddy
gets each name's certificate from Let's Encrypt and passes `Host` on as it came, which is what
the ingress routes by. WebSockets and streaming pass through.

```
web.apps.example.com {
	reverse_proxy 127.0.0.1:8080
}
```

A site per name, each with its DNS record to the host. For names made on the fly, a wildcard
record and a wildcard certificate, which needs Caddy built with your DNS provider's module
(DNS-01), in a `*.apps.example.com` site. Access control goes in the site too (`basic_auth`,
`forward_auth`): an endpoint answers anyone who reaches it.

TCP is passed as it is: TLS, when wanted, is the protocol's own (Postgres, Redis). Forward a
public port to the host port the endpoint got, here with nginx's `stream` module
(`libnginx-mod-stream`; the block is top level in `nginx.conf`, not under `http`):

```
stream {
	server { listen 5432; proxy_pass 127.0.0.1:30432; }
}
```

With the bootstrap's firewall (`PRIVATE_ADDRESS` set), the public interface takes SSH and
`PUBLIC_TCP_PORTS` only, set at its first run: `80,443,5432` here, the proxy's ports, never an
endpoint's own (the daemon refuses 8080 and 30000-32767 there).
A proxy on another server reaches the daemon over a private network: `ingress.http` and
`ingress.bind` on the host's private address, `ingress.allowed_clients` the proxy's. With
several hosts, send each name to the host its machine runs on (`briqyard machine ls`, HOST).
A connection to a sleeping machine wakes it, and waits for its boot.

## Where things live

| Path | What |
|---|---|
| `<data_dir>/state/{machines,tenants,endpoints}/*.json` | The records, one file each, written atomically, on `byard/state`; the namespaces' directory keeps its former name (ADR 0055) |
| `<data_dir>/api-cert.pem`, `api-key.pem` | The API's certificate and key (`0600`). Both removed, a new pair is made at the next start: a new fingerprint to pin. The certificate without its key: the daemon refuses to start |
| `<data_dir>/state/usage/<hour>.json` | Each machine's usage in that UTC hour (ADR 0017); the open hour is rewritten once a minute |
| `<data_dir>/state/events/<hour>.ndjson` | The host's events of that hour, one JSON line each, appended and synced (ADR 0019) |
| `<data_dir>/run/<machine>/` | On `byard/run`: `console.log` (the guest's serial console, timestamped), `console.<offset>.log` (the previous file, rotated at `console_max_mb`, named after where it starts in the console), `config.tar` (the config drive, `0600`), sockets when not jailed |
| `<jail_dir>/firecracker/<machine>/root/` | The chroot, on `byard/jail`: kernel, config drive (`0400`, the jail's user), device nodes, sockets, `snap.state` and `snap.mem` while suspended |
| `<jail_dir>/firecracker/<machine>/snapshots/` | `<snap>.state` and `<snap>.mem` of each snapshot taken with memory (ADR 0031); `<data_dir>/run/<machine>/snapshots/` without the jailer |
| `<data_dir>/images/meta/*.json` | What each image is, on `byard/images`, with the extraction scratch (`extract-*`) |
| `byard/jail` | A filesystem mounted at `jail_dir`: `zfs list byard/jail` is what the jails and the suspended machines hold |
| `byard/state`, `byard/run`, `byard/images` | Filesystems mounted at `<data_dir>/state`, `run`, `images`: nothing the daemon writes about a machine is on `/` (ADR 0026). Never mounted over files: a directory that already holds some is refused at start |
| `/etc/briqyard/config.yaml` | The config (`0600`: the host's token is in it); `pool.key` beside it on a host with a file key |
| `byard/images/<key>` | A root disk per image, with its `@base` snapshot |
| `byard/m/<machine>/root`, `.../data` | A machine's disks |
| `byard/m/<machine>/root.r_<n>`, `.../data.r_<n>` | Disks a restore retired, kept while a newer snapshot or a fork needs them (ADR 0031) |

The pool is encrypted (`zfs get encryption,keystatus byard`): after a reboot its key is not
loaded, and the daemon loads it before anything else, from `storage.key`. Without it the
daemon serves nothing, logs `pool locked` at `error` with why, and tries again (5 s, doubling to
a minute); the fleet sees the host `down`.

Every disk is a ZFS zvol: `zfs list -t all -r byard` shows them, `zfs get used,referenced` what
they take. A machine's `fork-*` and `s_*` snapshots on its disks are its forks' and its own: a
`fork-*` goes with the last machine cloned from it, an `s_*` with `briqyard machine snapshot rm
<id> <snap>` (or what a retired disk still needs, with that disk); the daemon's start removes
what a failed destroy or a crash left. A `.next` dataset is a restore under way.

## Upgrade

Through the fleet, one host or every host, machines running (ADR 0027). The fleet first, then
the hosts: a host is never newer than its fleet.

```bash
briqyard-fleet --version                                  # on the fleet's server: upgrade it first
briqyard host upgrade h_123456 --release 0.2.0            # or a release URL
briqyard host upgrade --all --release 0.2.0               # every ready or draining host, by id, one at a time
briqyard host ls                                          # VERSION, and each host's note
```

What one upgrade does (`POST /v1/hosts/{id}/upgrade`; the call answers when it is done):

| Step | |
|---|---|
| `upgrading` | Placement stops; the host's machines are served |
| Install | `hack/bootstrap-host.sh` over SSH with the release (`bootstrap.ssh_key`, the pinned host key), as at a bootstrap: packages, Firecracker and kernel pins, the binaries put in place by a rename, the unit |
| Hand-over | The script sends the running daemon SIGUSR2: it stops accepting, drains for up to 2 s, exits 75 and leaves every machine running; the unit starts the new one at once, which adopts them. Its listeners stay in systemd's store meanwhile (ADR 0051) |
| Back | `briqyardd --version` over SSH, then a heartbeat from a new start of that version that stopped nothing, within 5 minutes |
| Undrained | The host is back in its state; its note says `upgraded to <version> at <time>; machines handed over: N` |

A failure leaves the host `draining` with the reason in its note: fix it, then
`briqyard host undrain <id>`. `--all` stops at the first failure and names the hosts left. One
upgrade at a time per fleet. A static host (`hosts:`) needs the fleet's SSH key in root's
`authorized_keys`; its host key is pinned at its first upgrade. After a roll, set
`bootstrap.release` to the release, for the hosts added next.

A release is a URL where `<binary>-linux-<arch>` are (`briqyardd`, `briqyard-init`, `briqyard`,
`briqyard-fleet`) with their `SHA256SUMS-<arch>`, or a version of the project's releases; a
private repository's is read with `bootstrap.release_token`. Without a fleet, on the host:
`BRIQYARD_RELEASE=<url> bash bootstrap-host.sh` does the same install and hand-over.

What the machines see:

| | |
|---|---|
| Running | Nothing: no reboot, no pause |
| Their clients | Nothing refused: a connection or an API call made during the hand-over waits for the next daemon (its log: `serving again`, `gap_ms`). A connection through the ingress open more than 2 s after the signal is reset |
| Suspended | Resumed at their next start when Firecracker and the host kernel are the same; booted cold otherwise (`starting` says so) |
| Their init | The one in their root disk until it is made again (an image change); `init_version` on the machine |
| Their Firecracker | The process they booted with until their next start; `vmm_version` on the machine, the host's in `briqyard status` |

Each binary says what it is: `briqyardd --version`, `0.1.0+fdad892eeefa` (release and commit).
The wire between versions is additive (ADR 0027): a newer daemon reads every init in use, a
newer fleet every host one version behind. A caller uses a field new in a release once
`host ls` shows every host on it: an older host ignores a field it does not know. A
configuration field new in a release goes into the file after the upgrade (an older binary
refuses it), and out of it before a rollback, which is an upgrade to the older release.

**A reboot** (an OS or host kernel upgrade): `briqyard host drain <id>`, then on the host
`systemctl stop briqyardd` (every machine suspended), the upgrade and the reboot; the daemon's
start boots again each machine it stopped whose sleep window had not run out (cold, the kernel
changed), and `briqyard host undrain <id>`. `systemctl restart briqyardd` by hand does the same
without the reboot: a quarter-second pause per machine. A daemon that crashes leaves its
machines running (`KillMode=process`), and the next one adopts them.

**Security updates** (unattended upgrades) land on disk and never restart anything on their
own (ADR 0050): the bootstrap keeps needrestart off `briqyardd` and `briqyard-fleet`
(`/etc/needrestart/conf.d/briqyard.conf`), and `Unattended-Upgrade::Automatic-Reboot` stays
false. The daemon picks an updated library up at its next `host upgrade` (the same release
again is fine) or reboot. `briqyard doctor` warns when either would happen on its own.

A host from before ADR 0014 (jails on `/`): stop the daemon and empty `jail_dir` before the
first start that mounts `byard/jail` there, or the old files stay hidden on `/` and the
machines suspended then boot cold.

## Backups

With `backup.store` set, `briqyard machine backup <id>` (`POST /v1/machines/{id}/backups`)
snapshots the machine's disks and streams them to the store: whole the first time, then only
what changed since the last backup whose snapshot is still on the host (`zfs send -w -i`: raw,
the pool's ciphertext, ADR 0035).
Each backup is a record (`backups/<machine>/<id>.json`: ids, names, sizes, the chain in clear;
the machine's spec, its env and files, sealed under the pool's key) plus one object per disk. A backup of a
running machine is crash-consistent, what a power cut would leave; stop the machine first for
a clean one, or let the application do its own consistency (Postgres does). A stream goes up
in 32 MB parts, four at a time, each request tried again with backoff for up to 10 minutes
(ADR 0034). Give the bucket a lifecycle rule that aborts incomplete multipart uploads after a
day: a daemon cut mid-upload leaves one.

`briqyard machine backups <id>` lists them, from the store, so a machine that no longer exists
still has them. `briqyard machine restore --from <machine id> [--backup <id>] --namespace T --name
N` makes a new machine from one (`POST /v1/machines` with `restore`): the whole chain of
streams is received into fresh datasets, and the image, command, env, files, size and volume
come from the record unless the request sets them. Any host that reaches the store can
restore, which is how a machine moves off a dead host.

### On a schedule (ADR 0023)

A machine with `backup: {every, keep}` (`machine run --backup-every 6h --backup-keep 4`,
`machine set-backup <id> --every 1d --keep 5`, or `--off`) is backed up by the daemon's tick,
with or without the control plane: `every` after its last backup, 15 minutes after a failed one
(`backup_failed`, a warning event), `backup.at_once` at a time. A machine with no process
(stopped, created) whose disks wrote nothing since its last backup is not backed up again.

| Retention, `keep` 2 | sent | in the store |
|---|---|---|
| 1st | whole | 1 |
| 2nd | from 1 | 1 2 |
| 3rd | whole | 1 2 3 (2 is kept, 1 is its base) |
| 4th | from 3 | 3 4 |

Every `keep`-th backup is whole; after each backup, what is neither among the newest `keep`
nor a base of one goes (`backup_deleted`, `retention`). The store holds `keep` to
`2·keep − 1` backups, each restorable. `briqyard backup rm <machine> <backup>` deletes one;
refused while another continues from it, `--chain` deletes those too.

A destroy keeps the machine's backups for `backup.keep_destroyed_days`: a holder
(`state/holders/<id>.json`) keeps them listed (`briqyard backups --namespace T`, `--machine ID`
for one machine's, each with `deletes_at`) and counted in the machine's usage buckets
(`backup_gb_hours`). Through a fleet, `backup rm` of a destroyed machine's backup names its
namespace (`--namespace`).

In the store, per machine: `backups/<machine>/<id>.json` (the record) and
`backups/<machine>/<disk>/<id>.zfs` (a stream, `root` or `data`). Ids are times to the
millisecond, `20261021T101500.123Z`. A deletion removes the streams first, then the record.

The state itself (`state/`) is small and lives only on the host; a lost host loses the records
of machines that were never backed up, and their disks. A machine's own `POST
/v1/machines/{id}/snapshots` is a local snapshot of its disks: instant, copy-on-write, not a
backup until sent elsewhere. A restore to one (`briqyard machine snapshot restore <id> <snap>`)
keeps the backup chain correct: the next backup continues from the newest backup made before the
snapshot, or is whole.

## Watch

- `GET /healthz`: the daemon is up. `GET /v1/status`: capacity, use, free disk, `conditions`.
- `GET /metrics`: Prometheus text, from the tick's last measure (15 s; a scrape probes
  nothing). `metrics_token` gives the scraper a token of its own.

  | Series | Labels | What |
  |---|---|---|
  | `briqyard_machines`, `_total`, `_suspended` | `state` | machines on the host |
  | `briqyard_machines_stopped` | `reason="user\|idle\|exit\|host"` | stopped machines by why; `idle` is asleep |
  | `briqyard_memory_mb`, `briqyard_vcpus` | `kind="used\|capacity"` | committed to running machines, handed out |
  | `briqyard_pool_bytes`, `briqyard_disk_free_mb` | `kind="size\|used\|free"` | the pool |
  | `briqyard_host_condition` | `condition` | 1 while true |
  | `briqyard_events_total` | `type`, `reason` | events since the daemon started, folded repeats included |
  | `briqyard_{boots,resumes,suspends,execs,starts_failed,backups}_total`, `briqyard_namespaces`, `briqyard_endpoints` | | counts (`execs`: exec sessions included) |
  | `process_resident_memory_bytes` | | the daemon's own resident memory |
  | `briqyard_machine_cpu_seconds_total` | `machine`, `namespace`, `name`, `role` (a gateway's) | its cgroup's CPU time |
  | `briqyard_machine_memory_bytes`, `_memory_limit_bytes` | same | its cgroup's memory, its size |
  | `briqyard_machine_disk_used_bytes` | same | its disks, snapshots (retired disks included) and memory snapshots |
  | `briqyard_machine_{internet,ingress}_{in,out}_bytes_total`, `_egress_dropped_packets_total` | same | its traffic |
  | `briqyard_machine_disk_{read,write}_bytes_total`, `_disk_throttled_total` | same | its disks, and the requests its disk limits held back; from Firecracker's metrics, a line a minute |
  | `briqyard_machine_restarts_total` | same | restarts by its policy |
  | `briqyard_machine_state` | same, `state` | 1, one series per machine |
  | `briqyard_machine_boot_seconds` | same | its last start, `starting` to `running` |

  Counters count from the daemon's start. Alert on `briqyard_host_condition == 1`.
- `briqyard top [--namespace T]`: running machines by CPU, with memory, disk and network rates over
  the last 15 s (`GET /v1/top`; through the fleet, a namespace's host or every host).
- Conditions (ADR 0021): `memory_pressure`, `disk_pressure`, `storage_stalled` (ADR 0046) in
  `/v1/status` and `briqyard host ls`; each change is a `host_condition` event (`briqyard
  events`), a warning when it turns true. Under disk pressure the daemon removes unused images
  itself (`image_removed` events).
- Logs: one JSON line per event on stderr (journald under systemd): `journalctl -u briqyardd
  -o cat | jq`. Level with `BRIQYARD_LOG=debug` (or any `tracing` filter).
- Suspend timing: opt-in debug stages and offline analysis in [Suspend profiling](SUSPEND-PROFILING.md)
  (ADR 0063); snapshot syncing and stop deadlines are unchanged.
- A machine: `briqyard machine get <id>` (state, why it stopped, its process's exit), `briqyard
  machine logs <id>` (its console; `-f` streams each new line until the machine is destroyed).
  `briqyard machine ls -l app=web -l tier` selects by labels (its `metadata`; `run -l K=V` sets them).
- Quotas (ADR 0025): `briqyard namespace quota <namespace>` shows a namespace's limits and use;
  `--machines N --memory-mb N --vcpus N --disk-gb N` puts exactly those (the control plane sets
  them). A refusal is a `quota_exceeded` warning in `briqyard events --namespace <namespace>`.
- A shell in a machine (ADR 0029): `briqyard machine exec -it <id> -- sh`; `-i` alone for a pipe.
  Each session is a `session_opened` event (`briqyard events --machine <id>`) and an `exec
  session ended` log line with its code and length. A machine with a session open does not go
  to sleep; a client silent for 90 s is dropped and its command ended.
- Files (ADR 0061): `briqyard machine put <id> local/path /guest/path` and
  `briqyard machine get-file <id> /guest/path > local/path` stream raw bytes, at most 1 GiB.
  HTTP is `GET/PUT /v1/machines/{id}/files/content?path=<encoded-absolute-path>`; PUT accepts
  optional `Content-Length` and `mode=0644`; absent mode preserves regular file permissions
  (new files default to `0644`). A successful PUT returns JSON `{size, sha256}` from the guest. Uploads atomically replace the destination;
  interrupted uploads keep the old file. Parent symlinks are refused; use the resolved
  directory path. GET refuses symlinks and special files. The machine must be running and
  stays in use during the transfer. Bounds: 16 per daemon, four per guest, 60 s idle,
  900 s total. An old init is refused with its version: an image change rebuilds the root
  disk with the current init. The JSON `/files` API remains available.
  The CLI probes `/files/capabilities` first: a live `file_stream_v1` flag, not a version
  comparison. An older guest retains one JSON operation up to 1 MiB with legacy mode,
  symlink and partial-write semantics; its checksum is unverified. Upload and response
  buffers are bounded in the client. An old JSON GET can still allocate the whole file
  inside the old guest before encoding fails. Capability errors propagate without fallback.
- `briqyard machine stats <id>`: CPU time, memory and disk it uses now, from its cgroup and its
  datasets. `briqyard machine set-sleep <id> 3h|never` changes the window without a restart.
- What a machine runs (ADR 0024): `briqyard machine set <id> --image … --memory … -e K=V -- cmd…`
  is `pending` (in `get`, `describe`, the `PENDING` column) until its next start; `briqyard
  machine restart <id>` applies it now. A new image is pulled at that start and the root disk
  made again from it; the data volume stays. `--volume-gb N` grows the volume (ADR 0040): the
  disk at once, its filesystem at the next start (cold); never smaller.
- `briqyard usage --from <hour> --to <hour> [--namespace T] [--json]`: what each machine used
  per hour (ADR 0017); `nft list set inet briqyard internet_out` shows the raw counters.
- Namespace peers with a gateway (ADR 0064): `briqyard machine set-egress <id> via:gateway+siblings`.
  This opts into trusting current peers of the namespace. `via:gateway` restores strict access,
  including blocking established peer traffic. Check `egress_siblings_v1` on `/v1/status` and
  the selected host before an API opt-in; absent means unsupported. The CLI checks the server,
  and the fleet checks each host. `conntrack` is a required host package; install the versioned
  bootstrap prerequisites before upgrading an existing host. Do not clear the host's whole
  connection table: the daemon clears only an address at ownership transitions. Warm resume,
  stop/start and adoption retain the owner's existing flows.

- Egress limits (ADR 0018): `briqyard machine get <id>` shows `limits` and `egress_drops`;
  `briqyard machine set-limits <id> --conn-per-min 0` lifts a rate at once. Raw:
  `nft list set inet briqyard dropped_port` (also `dropped_rate`, `dropped_bandwidth`).
- Disk limits (ADR 0030): `briqyard machine get <id>` shows `disk_limits` in force (the `DISK`
  column); `briqyard machine set-disk-limits <id> --disk-bw 0` lifts one on a running machine at
  once. A machine at its limit grows `briqyard_machine_disk_throttled_total`.

## When something is off

| Symptom | Look at |
|---|---|
| A machine stays `creating` | Its image is being pulled (ADR 0048): `briqyard events --machine <id>` shows `pulling`; the host's `image_pulled` ends it. Pulls of four images run at once, the rest wait their turn; a registry silent for 15 minutes fails the pull |
| A machine is `error (pull_failed)` | Its image could not be pulled: the reference, the registry's credentials (`registries:`), the registry or its mirror. `error` says which; nothing is tried again: destroy it and create again |
| A machine is `error (create_failed)` | Its disks could not be made (`zfs` in `error` and the log, at `error`), its create's start was refused (its quota, its `via`), or the daemon restarted during a fork's or a restore's create (one from an image is taken up again). No disks: destroy it and create again |
| A start or a create's `/wait` answers 409 `boot_failed` | The image's fault: the machine is kept in `state: error`, `error` holds the init's reason (`start "/run.sh": …`) or else the last console lines. `briqyard machine logs`, then destroy it |
| A start after `machine set --image` answers 409 `boot_failed`, `error: image …` | The new image could not be pulled or built; the change is still `pending`. `machine set` another image (or the one it runs, which drops the change) and start again |
| A start after `machine set --memory` answers 503 `capacity` | The host has no room for the new size; the change is still `pending`. Through a fleet, the namespace stays on its host: move it (backups, `namespace unpin`, restores) |
| A machine is `stopped (host)` | The daemon stopped it: its stop, or a crashed daemon's leftover. The next start boots it again unless its sleep window had run out; else the next use wakes it |
| `upgrade to … failed` in a host's note, the host `draining` | The step and the reason are in the note: SSH (the key, the pinned host key), the script's last lines, no heartbeat from the new version (`journalctl -u briqyardd` on the host), or a start that stopped machines it could not take over (`briqyard events --machine …`). Fix, then `briqyard host undrain` |
| `the host now runs …, newer than this fleet` | Upgrade the fleet, then `host undrain` the host |
| A machine stays `destroying` | Its disks could not be destroyed (`zfs destroy` in the log), or, its disks gone, the backup store did not list its backups within 30 s (`resume destroy`); the daemon tries again every 15 s |
| `record of a destroyed machine, written back after its destroy: removed` (`warn` at start) | A daemon up to v0.1.2 could write a destroyed machine's record back (a call that waited on the machine during its destroy); the next start destroyed it again. A `destroying` record whose address another machine holds is now deleted at start, nothing else done; another one is finished as a destroy, its holder made from what the backup store lists (30 s at most, else tried again) |
| The process exits at once (`stopped`, `exit.code`) | `briqyard machine logs`: the image's own output. `restart.policy: on-failure` tries three times, 10 s, 20 s, 40 s apart (`restarting_at`); `crash_loop` events from the third |
| `/wait` answers 409 `not_ready`, or the ingress 502 after a wait | The program runs but its readiness or startup probe does not pass: `briqyard machine describe` shows each probe's last result. A TCP or HTTP probe needs the program on the machine's address, not only `127.0.0.1` |
| `startup_failed` then `error` | The startup probe did not pass within `failure_threshold` × `period_sec` of a start: the boot failed, as `boot_failed` does. On a restart it is a crash instead, restarted by the policy |
| `the guest did not come up` | The kernel booted but the init did not answer on vsock within `boot_timeout_sec`: console log, then the kernel (`kernel`) and init (`init`) paths |
| `no host has room` (fleet) | `briqyard host ls`: fill, free memory, free disk, conditions, and per region what ran out (`UNSCHEDULABLE`, ADR 0042). `used` counts the creates placement sent that the host has not reported yet (ADR 0044) |
| `no host in region … has room` (fleet) | No ready host of that region under the ceiling: `briqyard host ls`, the `REGION` column; add one there |
| `namespace … is in region …, not …` (fleet, 400) | The namespace lives on a host of another region. A team that changes region moves: backups, destroy, `namespace unpin`, restores with the new region |
| 403 `quota` | The namespace is at a limit of its quota: `briqyard namespace quota <namespace>` shows the limit and the use |
| `host h_… is under disk_pressure` (fleet, 503 `capacity`) | The namespace's host takes nothing new until the condition clears. Disk: `zfs list -o space byard`; unused images go by themselves, then backups and destroys of what is left. Memory: stop machines, or move the namespace (below) |
| `host h_… is down` (fleet, 503) | The host missed its heartbeats for `placement.down_after_sec`: its machines answer again once it is back. `briqyard host ls`, then the host's `journalctl -u briqyardd` |
| `fleet heartbeat refused` in a host's log | `unknown_host`: the fleet has no record at the host's `fleet.advertise` address (list it under `hosts:`). `unauthorized`: the host's `token` is not the one the fleet holds for it. `tls_mismatch`: its certificate is not the pinned one, or none is pinned (set `tls_fingerprint`); a host just added gets this until its bootstrap has pinned it |
| `host …: … is not the pinned …` (fleet, 502 `host_unreachable`) | The host presents another certificate than its record's `tls_fingerprint`: reinstalled (pin the new one), or not the host |
| `write registry …` (fleet, 500 `registry`) | The fleet's `state_dir` is full or not writable; nothing is recorded until it is |
| `provisioner.bootstrap is read as bootstrap:` (fleet, `warn` at start), a `provisioner.…` error (the fleet does not start) | A v0.1.1 configuration: move `provisioner.bootstrap` to a top-level `bootstrap:` and delete `provisioner:` with all else under it (ADR 0042). A `dry-run` host left by an older fleet: `briqyard host rm <id>` |
| `registry backup` (fleet, `error`), 503 `backup` on `/v1/hosts/key` | The registry could not be written to `backup.store`: credentials, endpoint, the bucket. Hosts whose key the store holds are served; new keys wait for the store |
| `read the registry …` (the fleet does not start) | `registry.json` does not parse: restore the file (fields a fleet does not know are kept, not refused). Never remove it: every host's pool key is in it (ADR 0026) |
| `bootstrap attempt N: … host key …` in a host's note | The server's SSH key is not the one pinned in `<state_dir>/known_hosts`: reinstalled, remove its line; not reinstalled, do not connect |
| `bootstrap attempt N: … is in use (mounted at …)`, `… holds ext4` | `pool_device` names something in use: the OS's disks are named whole (their free space is taken), never the OS's partitions; a disk meant for the pool is wiped by you (`wipefs -a`) |
| `… has under 10 GB free` | The install filled the disk: reinstall with the layout of "First OVH host", step 2 |
| `no interface has 10.42.…: set PRIVATE_INTERFACE`, `… did not come up` | `private_interface` is not this server's vRack interface (`ip -br link`, the MAC the manager shows as Private), or the server is not in the vRack yet |
| `release … has no …`, `digest differs from the release's SHA256SUMS` | `release` names a tag without this architecture's files, or the token cannot read the repository |
| An endpoint connects but the service refuses | The machine was waking: clients retry, as connection pools do. Postgres accepts TCP before it is ready |
| `dataset is busy` | A zvol a Firecracker just released; the daemon retries for ten seconds |
| `storage_stalled` (a host condition) | A `zfs` command has run for over a minute; the fleet places nothing new on the host. If `/proc/$(pgrep z_zvol)/stack` shows `zvol_remove_minors_impl`, a removed zvol's device is still open: find the `/dev/zdN` that `/usr/lib/udev/zvol_id` cannot name among the processes' open files (`ls -l /proc/*/fd`) and kill its holder (ADR 0046) |
| `zvol device of byard/m/…: … after 15 s` | The disk's link never named its device, even after the change events the daemon sent: `udevadm settle`, `ls -l /dev/zvol/byard/m/<id>/`, `/usr/lib/udev/zvol_id /dev/zdN`, and `journalctl -u systemd-udevd` for `Failed to process device` |
| A machine with `sleep` set never sleeps | A session is open on it (`session_opened` without its `exec session ended` line): it is in use until its client leaves |
| `-t needs a terminal on stdin` | `machine exec -t` from a script or a pipe: use `-i` alone |
| `host call refused: not from the host's address` (fleet), `unknown_host` `…'s calls come from …` | The host's heartbeat or key request reached the fleet from another address than its `url` (NAT, another route): list the host by the address it calls from. Behind a local proxy (`tls: off`, loopback `listen`): the proxy must set `X-Forwarded-For` |
| `pool locked: its key could not be loaded` | The daemon waits for the pool's key (ADR 0026), `err` says why: the fleet unreachable or refusing (`unknown_host`, `unauthorized`: as for a heartbeat), the key file missing, `Incorrect key provided` (the fleet's registry lost or restored from before the host: the pool cannot be read with another key) |
| `pool … is not encrypted` | A pool made before ADR 0026 or by hand: move what it holds, destroy it, run the bootstrap again |
| `… holds files and byard/… is not mounted there` | The daemon's directories hold files on `/` (a host from before ADR 0026): stop the daemon, move the contents onto the dataset (mount it elsewhere, copy, empty the directory) |
| A jail refuses to start | `<run>/<machine>/console.log` holds the jailer's own messages |

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

## Monitoring (ADR 0054)

Optional: Prometheus and Grafana on the fleet's server, both on loopback, Grafana served by
your reverse proxy. Prometheus asks the fleet for its targets (`GET /v1/metrics/targets`: the
fleet's `/metrics` and every host that may run a daemon) and scrapes each host through the
fleet (`GET /v1/hosts/{id}/metrics`, over the host's pinned TLS with its token). Hosts added or
retired come and go within 30 s; nothing to edit.

```bash
ssh root@<public ip> mkdir -p /root/briqyard && scp -r hack root@<public ip>:/root/briqyard/   # the script, hack/monitoring
ssh root@<public ip>
install -m 0600 /dev/null /root/grafana-password && nano /root/grafana-password   # one line
GRAFANA_URL=https://grafana.example.com bash /root/briqyard/hack/install-monitoring.sh < /root/grafana-password
rm /root/grafana-password
```

| Setting | Default | |
|---|---|---|
| `FLEET_URL` | `http://127.0.0.1:7430` | the fleet as Prometheus reaches it; the targets are at that address |
| `FLEET_TOKEN_FILE` | `metrics_token`, else `token`, from `/etc/briqyard/fleet.yaml` | a `0600` file with the token Prometheus presents (kept in `/etc/briqyard-monitoring/fleet-token`, `0600`) |
| `RETENTION` | `90d` | how long Prometheus keeps samples (`/var/lib/briqyard-monitoring/prometheus`; about 20 GB for 10 hosts of 200 machines) |
| `GRAFANA_URL` | `http://127.0.0.1:3000` | where the proxy serves Grafana (its `root_url`; `https://` makes its cookies secure) |
| `GRAFANA_PASSWORD_FILE` | stdin | the admin password, needed the first time; given again, it is changed |
| `PROMETHEUS_LISTEN`, `GRAFANA_LISTEN` | `127.0.0.1:9090`, `127.0.0.1:3000` | loopback only |
| `LARGEST_SLOT_MB` | `16384` | the alert when a region's largest slot is under it: the largest size you offer |

It takes about 1.5 GB of disk and 700 MB of memory with a few hosts: Grafana 600 MB, Prometheus
70 MB, growing with series (about 12 per machine). On a server that also runs machines, add the
memory to `capacity.reserved_memory_mb`.

Grafana, signed in as `admin`: the `briqyard` folder, a fleet overview (hosts by state,
machines running, asleep and stopped, room per region, events), a host (its machines, memory
and CPU against capacity, the pool, disks, network, boot times, restarts) and machines and
namespaces (the busiest, each machine's series, crash loops, egress drops, use per namespace). No
anonymous access, no sign-up; the dashboards are the repository's (`hack/monitoring/dashboards`),
read-only in Grafana. Point the reverse proxy at `GRAFANA_LISTEN` only after the first run: Grafana
starts with its default `admin` password, which the script replaces seconds later, on loopback.

**Alerts to Slack**: a webhook in `/etc/briqyard-monitoring/alerting.env` (root's, `0600`,
written with an editor), then the script again:

```bash
install -m 0600 /dev/null /etc/briqyard-monitoring/alerting.env && nano /etc/briqyard-monitoring/alerting.env  # SLACK_WEBHOOK_URL=https://hooks.slack.com/services/…
GRAFANA_URL=https://grafana.example.com bash /root/briqyard/hack/install-monitoring.sh
```

| Alert | When |
|---|---|
| Not answering | a target's `up == 0` for 2 minutes: a host down, or the fleet itself |
| Host condition | a host condition true for a minute (`memory_pressure`, `disk_pressure`…) |
| Pool over 80 % | for 5 minutes |
| Machine in a crash loop | restarted 3 times in 10 minutes by its policy |
| Creates refused: no room | `briqyard_fleet_unschedulable_total{resource=~"memory\|disk"}` grew: add a host in the region |
| Creates refused: host under pressure | `{resource="pressure"}` grew: free the namespace's host |
| Largest slot too small | a region's largest memory slot under `LARGEST_SLOT_MB` for 10 minutes |

**The proxy**, beside the fleet's site (step 6 of First OVH host), with a DNS record for the
name:

```
grafana.example.com {
	reverse_proxy 127.0.0.1:3000
}
```

**Upgrade**: a release of briqyard that pins newer Prometheus or Grafana versions, or changes
the dashboards: the script again, from that release's `hack/`. It installs what changed and
restarts only what needs it; samples, the password and Grafana's database stay. Give it the
same settings each time: they are read from the environment, never remembered. **Check**:
`PROMETHEUS_URL=http://127.0.0.1:9090 BRIQYARD_TOKEN=… bash hack/monitoring-check.sh` (with
`GRAFANA_URL=http://127.0.0.1:3000 GRAFANA_PASSWORD_FILE=…`, every panel's queries).
**Undo**: `systemctl disable --now briqyard-grafana briqyard-prometheus`, then
`rm -rf /opt/briqyard-monitoring /etc/briqyard-monitoring /var/lib/briqyard-monitoring
/etc/systemd/system/briqyard-{grafana,prometheus}.service` and `userdel` both users.

## First OVH host

One server: the host, the fleet and an edge on it (a reverse proxy in front of the fleet and
the endpoints, ADR 0028). The API and the endpoints on the vRack; the public interface takes
SSH, 80, 443 and the edge's TCP listener ports; the fleet behind the edge. The values below
(`10.42.0.0/16`, `10.42.0.11`, `enp3s0f1`, `gra`, `fleet.example.com`) are examples: write
yours.

**1. Order** (OVH manager, Bare Metal Cloud, Dedicated servers):

| | |
|---|---|
| Range | Rise or Advance: KVM on every dedicated server; the vRack on these (not on Kimsufi or So you Start) |
| Memory | 64 GB or more: machines get memory − 3 GB (the host and the edge) − the ZFS cache's cap (10 %) |
| Disks | 2 × NVMe of one size |
| Options | the vRack (private bandwidth) |
| OS | Ubuntu Server 26.04 LTS (what every suite runs on) |

**2. Install layout** (Install, "Customise the partition configuration"), on both disks:

| Mount | File system | RAID | Size |
|---|---|---|---|
| `/boot` | ext4 | 1 | 1 GiB |
| `/` | ext4 | 1 | 100 GiB |
| swap | removed | | |

No partition fills the disks: the rest of each NVMe stays free for the pool. Add your SSH key
and, from the second server on, the fleet's (`/etc/briqyard/fleet_ssh_key.pub` on its server).
After the install, `sgdisk -p /dev/nvme0n1` ends with the free space (`Total free space is …`).
On a UEFI server (`ls /sys/firmware/efi` lists something), `findmnt /boot/efi` must show the
EFI partition OVH adds on its own; none there: reinstall before going on.
If the manager makes the last partition fill the disk, reinstall through the API console
(`POST /dedicated/server/{serviceName}/reinstall`) with `operatingSystem: ubuntu2604-server_64`,
your key as `customizations.sshKey`, and `storage: [{partitioning: {layout: [{mountPoint:
"/boot", fileSystem: ext4, raidLevel: 1, size: 1024}, {mountPoint: "/", fileSystem: ext4,
raidLevel: 1, size: 102400}]}}]`.

Then, on the server, what the suites ran on:

```bash
grep VERSION= /etc/os-release; uname -r     # 26.04, kernel 7.0
modprobe zfs && zfs version                 # 2.4
ls /dev/kvm && stat -fc %T /sys/fs/cgroup   # cgroup2fs
swapon --show                               # nothing
```

**3. The vRack**: Network, vRack private network, add the server. Its private interface is
the one whose MAC the manager shows as Private (server, Network interfaces): `ip -br link |
grep -i <mac>` names it. Pick the range (`10.42.0.0/16`) and the server's address in it.

**4. The fleet, on this server**, on loopback with `tls: off`: the edge serves its name
(step 6). The fleet checks a pool key request by the caller's address (ADR 0026), which on a
loopback listener it reads from the edge's `X-Forwarded-For`. The
repository is private, so the binaries come from your Mac:

```bash
gh release download v0.1.8 -R briq-cloud/briqyard -p 'briqyard*-linux-x86_64' -p SHA256SUMS-x86_64 -D /tmp/byard
(cd /tmp/byard && shasum -a 256 -c SHA256SUMS-x86_64)
scp /tmp/byard/briqyard-fleet-linux-x86_64 root@<public ip>:/usr/local/bin/briqyard-fleet
scp /tmp/byard/briqyard-linux-x86_64 root@<public ip>:/usr/local/bin/briqyard
scp hack/briqyard-fleet.service root@<public ip>:/etc/systemd/system/
ssh root@<public ip>
chmod 0755 /usr/local/bin/briqyard /usr/local/bin/briqyard-fleet && mkdir -p /etc/briqyard
ssh-keygen -q -t ed25519 -N '' -f /etc/briqyard/fleet_ssh_key && cat /etc/briqyard/fleet_ssh_key.pub >> /root/.ssh/authorized_keys
install -m 0600 /dev/null /etc/briqyard/fleet.env && nano /etc/briqyard/fleet.env   # BRIQYARD_RELEASE_TOKEN=…
install -m 0600 /dev/null /etc/briqyard/fleet.yaml && nano /etc/briqyard/fleet.yaml # below
systemctl daemon-reload && systemctl enable --now briqyard-fleet
```

The release token is a fine-grained GitHub token, read-only on `briq-cloud/briqyard`'s
contents, expiring in 30 days: written with an editor, never with `echo` (it would stay in the
shell's history).

`/etc/briqyard/fleet.yaml`:

```yaml
listen: 127.0.0.1:7430                     # loopback, plain HTTP: the edge terminates TLS
tls: off
token: <openssl rand -hex 24: what the control plane and the CLI present>
state_dir: /var/lib/briqyard-fleet
bootstrap:
  enabled: true
  ssh_key: /etc/briqyard/fleet_ssh_key
  release: https://github.com/briq-cloud/briqyard/releases/download/v0.1.8
  pool_device: /dev/nvme0n1,/dev/nvme1n1
  fleet_url: https://fleet.example.com
  fleet_address: 10.42.0.11                # this server on the vRack: hosts reach fleet_url here
  private_network: 10.42.0.0/16
  private_interface: enp3s0f1
  allowed_clients: [10.42.0.0/16]
  # Hosts without an edge open nothing more than SSH; the edge's host says its own (step 5).
  public_tcp_ports: []
```

v0.1.1 reads these settings only as `provisioner: { kind: static, bootstrap: … }`; later
releases read `bootstrap:`, and the old place for one release with a warning (ADR 0042).

The fleet's state (`/var/lib/briqyard-fleet`: the registry with every host's token and pool
key, the pinned SSH keys) is on this server alone: give the fleet a `backup:` ("The registry's
backup") before the first host, since a registry lost is every host's pool unreadable.

**5. Add the server to the fleet**, on the server (the fleet has no public name yet), once its
kernel has ZFS and KVM, and once cloud-init leaves `/etc/hosts` alone: with
`manage_etc_hosts: true` it rewrites the file at every boot, the fleet's line goes, and after a
reboot the host's key request leaves by the public address and is refused (the pool stays
locked). On every vRack server:

```bash
modprobe zfs && ls /dev/kvm
grep -rs manage_etc_hosts /etc/cloud/   # nothing, or false; else:
echo 'manage_etc_hosts: false' > /etc/cloud/cloud.cfg.d/99-briqyard-hosts.cfg
export BRIQYARD_URL=http://127.0.0.1:7430 BRIQYARD_TOKEN=$(sed -n 's/^token: *//p' /etc/briqyard/fleet.yaml)
briqyard host add <public ip> --address 10.42.0.11 --region gra \
  --public-tcp-ports 80,443,5432,3306,6379,27017,5671,7687,6334
briqyard host ls     # the note: what the last attempt did
```

Steps 5 and 6 interleave on this first server: the fleet is served by the edge, and the edge
goes on after briqyard's firewall. Within two minutes, the first attempt puts the vRack address
on its interface, writes the firewall (SSH and the ports above) and `fleet.example.com` at
`10.42.0.11` in `/etc/hosts`, then fails at the pool's key (`no key for the pool`): nothing
serves the fleet's name yet. Do step 6; the next attempt, two minutes later, gets the key,
makes the pool and installs, and the note says the SSH key pinned (`SHA256:…`: compare it with
`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`), then the API certificate. Every attempt
is in the note; the host is `failed` after `max_attempts` (90, three hours). The host turns
`ready` at its first heartbeat.

The ports are the edge's (HTTP, HTTPS, its TCP listeners): its public interface takes them, and
its machines reach them at its address (`network.host_ports`). They stay on the host's record
(`host ls`: `public tcp:`), so a later bootstrap of it, or another host added, changes nothing
for the other. Putting the vRack address on its interface runs `netplan apply`, which renews
the public interface's DHCP lease too: a second's pause, SSH sessions survive.

**6. The edge**, once the first attempt wrote the firewall (`nft list table inet
briqyard_host`). It must:

- write no firewall of its own: briqyard's (`/etc/briqyard/firewall.nft`) opens its ports, and
  a second table would drop what this one lets in (the vRack, the machines' DNS);
- keep Docker off the rules, when it runs in Docker (`/etc/docker/daemon.json`: `"iptables":
  false, "ip6tables": false, "bridge": "none"`, before Docker is installed): Docker started
  before the daemon sets the forward policy to drop, and machines lose the internet;
- serve the fleet's name on every address, the vRack's included (that is where hosts reach it),
  to `127.0.0.1:7430`, responses streamed (a watch, logs followed), the caller's address in
  `X-Forwarded-For`. With Caddy:

```
fleet.example.com {
	reverse_proxy 127.0.0.1:7430 {
		flush_interval -1
	}
}
```

Then a DNS record for the fleet's name (`A fleet.example.com <public ip>`): the certificate's
HTTP-01 challenge and outside callers come that way; hosts, by `/etc/hosts`, over the vRack.
Once the host is `bootstrapped` or `ready` (`host ls`), keep 3 GB of memory for the host and the edge
(`capacity.reserved_memory_mb`, 2048 by default; in the dev VM the idle edge took 29 MiB,
Docker and containerd 555 MB with their page cache). Not before: a configuration there before
the bootstrap's makes it an upgrade.

```bash
grep -q '^capacity:' /etc/briqyard/config.yaml || printf 'capacity:\n  reserved_memory_mb: 3072\n' >> /etc/briqyard/config.yaml
systemctl restart briqyardd                            # no machine runs yet; later, a hand-over
export BRIQYARD_URL=https://fleet.example.com BRIQYARD_TOKEN=<the fleet's token>
briqyard host ls                                       # ready
```

**7. Smoke checks:**

```bash
ssh root@<public ip> briqyard doctor                   # every line ok
ssh root@<public ip> zpool status byard                # mirror-0, both partitions ONLINE
ssh root@<public ip> zfs get -H encryption,keystatus byard  # aes-256-gcm, available
ssh root@<public ip> nft list tables                   # briqyard_host and briqyard's two: none of the edge's or Docker's
ssh root@<public ip> nft list table inet briqyard_host # tcp 22, 80, 443 and the listeners', then drop
nc -vz -w 3 <public ip> 7420                            # from the Mac: times out
scp hack/e2e.sh root@<public ip>:/root/ && ssh root@<public ip> 'apt-get install -y bc postgresql-client'
ssh root@<public ip> 'export BRIQYARD_URL=https://10.42.0.11:7420 BRIQYARD_TOKEN=$(sed -n "s/^token: \"\(.*\)\"/\1/p" /etc/briqyard/config.yaml) BRIQYARD_TLS_FINGERPRINT=$(briqyardd --config /etc/briqyard/config.yaml tls-fingerprint); bash /root/e2e.sh'
ALLOW_SKIPPED=1 BRIQYARD_URL=https://fleet.example.com BRIQYARD_TOKEN=<the fleet's token> hack/fleet-smoke.sh
```

e2e runs on the host (endpoints are vRack addresses, and it needs GNU tools) and needs a
`backup.store` in the host's config: the real bucket (its test backups go, destroyed machines'
after `keep_destroyed_days`), or `file:///var/lib/briqyard/backups` for this run. With the
bucket, the raw-backups section (it reads and writes the store's files) is skipped: 5 checks
fewer. With `storage.key: fleet`, the encryption section skips the 3 checks of a key file (the
key's absence from files and log, a start without it). On the host it checks the host ports
too (the edge's port 80 from a machine, the API dropped). The fleet
smoke runs from anywhere that reaches the fleet and touches no real host: on a real fleet it
skips the sections that drain, forget or upgrade the dev host `local`, says so, and needs
`ALLOW_SKIPPED=1` to exit 0.

**8. The first day**, what to watch:

| What | Where |
|---|---|
| Errors | `journalctl -u briqyardd -u briqyard-fleet -o cat \| jq -c 'select(.level != "INFO")'`, and the edge's |
| The host | `briqyard host ls`: `ready`, conditions false, last seen within 15 s |
| After a reboot | `getent hosts fleet.example.com` on the host: the fleet's vRack address (`10.42.0.11`), and the host `ready` again |
| The disks | `zpool status -x` says all pools are healthy; `zpool list byard` |
| Memory | `free -g`; `arc_summary \| head -30`: the ARC under its cap; the edge's use |
| Machines | `briqyard top`, `briqyard events --watch` |
| The kernel | `dmesg -T \| grep -iE 'kvm\|oom\|nvme\|mce'` |
| The public interface | `nft list chain inet briqyard_host input`: the drop counter grows with the internet's scans |

Never enable `nftables.service` or ufw: they flush every table, ours and the daemon's. Never
let Docker write rules (step 6). After a kernel upgrade, check that `ip -br link` still names
the public interface as `/etc/briqyard/firewall.nft` does: the rule `iifname != "<public>" accept` lets everything in
once the interface is renamed (fix the name, `systemctl restart briqyard-firewall`).

**9. Undo**: `briqyard host retire <id>` (drained, forgotten once it runs nothing). On the
server: the edge stopped, `systemctl disable --now briqyardd briqyard-firewall`,
`nft delete table inet briqyard_host`, `zpool destroy byard`, `sgdisk -d <n>` the `briqyard-pool` partition of each
disk (`sgdisk -p`), `rm /etc/netplan/60-briqyard-private.yaml && netplan apply`. Or reinstall
it from the OVH manager. Locked out of SSH: Netboot in rescue mode, mount the root RAID
(`mdadm --assemble --scan`), remove `etc/systemd/system/sysinit.target.wants/briqyard-firewall.service`,
reboot from the disk.

### A KVM runner for the suites (later)

On a server of its own, never one that runs customers' machines: a job installs a daemon,
kills it, and runs as root.

1. Bootstrap it as a host without `FLEET_URL` (`hack/bootstrap-host.sh`, a file or one disk
   for the pool), so it has ZFS, Firecracker, the kernel and the unit.
2. `useradd -m runner`, with `runner ALL=(ALL) NOPASSWD:ALL` in `/etc/sudoers.d/runner` (the
   suites install and restart the daemon), and Rust for that user (`rustup`, the musl target).
3. GitHub, briq-cloud/briqyard, Settings, Actions, Runners, New self-hosted runner, Linux x64:
   as `runner`, download it, `./config.sh --url https://github.com/briq-cloud/briqyard --token
   <token> --labels kvm --unattended`, then `sudo ./svc.sh install runner && sudo ./svc.sh start`.
4. A job `runs-on: [self-hosted, kvm]` that builds, installs (as `hack/vm.sh install` does,
   without Lima) and runs `hack/e2e.sh` and `hack/fleet-smoke.sh`.

A self-hosted runner runs whatever a workflow says. On this private repository that is only
us. Never let a public pull request reach it: before the repository goes public, the runner
goes into a runner group limited to this repository, the KVM job runs on `push` to `main`
(never on `pull_request` from forks), and outside contributors' workflows need approval.

### CPU reservations

`size.vcpus` is the guest topology. Optional `size.cpu_millis` limits CPU time in thousandths
of a CPU, between 1 and `vcpus × 1000`; omission keeps the whole-CPU limit. Fractional
limits require the jailer and cgroup v2. The CLI accepts `--cpu-millis` on machine run/set,
namespace gateway set and namespace quota set. Reports expose precise `cpu_millis`
separately from guest CPU count. Both legacy `vcpus × 1000` and explicit `cpu_millis`
quotas apply when both are set.

Upgrade hosts before the fleet: the new fleet will not place work on hosts that do not
report precise CPU reservations. CPU-bearing PATCH requests to old hosts are refused.
A backup records its captured size for restore placement. For older sealed backups without
that metadata, provide an explicit restore size when restoring through the fleet.

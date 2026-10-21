# Operating a briqyard host

What an operator needs: how to install a host, what the configuration means, where things
live, how to upgrade, what to watch, and what to do when something is off.

## Install

A Linux server with KVM (`/dev/kvm`), Ubuntu 24.04 or newer. Through a fleet, `briqyard host
add` runs the script for you (below, and "First OVH host"). By hand, as root:

```bash
curl -fsSLO https://raw.githubusercontent.com/briq-cloud/briqyard/main/hack/bootstrap-host.sh
BRIQYARD_RELEASE=https://github.com/briq-cloud/briqyard/releases/download/v0.1.0 \
BRIQYARD_POOL_DEVICE=/dev/nvme0n1,/dev/nvme1n1 \
BRIQYARD_TOKEN=$(openssl rand -hex 24) \
PRIVATE_ADDRESS=10.42.0.11/16 ALLOWED_CLIENTS=10.42.0.0/16 \
bash bootstrap-host.sh
```

It installs the packages (ZFS, nftables, e2fsprogs, gdisk), caps the ZFS cache, makes the pool
(on the devices given, or on a file for a trial), puts the API on the private network and
closes the public interface when `PRIVATE_ADDRESS` is set, downloads Firecracker, its jailer
and a guest kernel, installs the binaries, writes `/etc/briqyard/config.yaml` and the systemd
unit, and starts `briqyardd`.
Off loopback the API serves TLS with a certificate the daemon makes once (ADR 0020); the script
prints its fingerprint (`== api certificate`, `sha256 <64 hex digits>`).
With `FLEET_URL` and `ADVERTISE` set, the host registers with a fleet, presenting
`BRIQYARD_TOKEN`: the fleet takes the registration only when it expects that token at that
address (the host's `hosts:` entry, below).

| Variable | Default | Meaning |
|---|---|---|
| `BRIQYARD_POOL_DEVICE` | none (a file, `BRIQYARD_POOL_FILE_GB`, 50) | One device, or two comma-separated for a mirror (ADR 0028): a partition, an empty disk, or a disk with the OS on part of it, whose largest free space (10 GB or more) becomes a `briqyard-pool` partition. Mounted, swap, RAID or LVM members and other filesystems are refused |
| `BRIQYARD_RELEASE`, `BRIQYARD_RELEASE_TOKEN` | `./bin` | Where the binaries are; each checked against the release's `SHA256SUMS-<arch>`. The token (contents read) fetches a private GitHub repository's release through its API |
| `BRIQYARD_ARC_GB` | 10 % of memory, 1 to 16 | The ZFS cache's ceiling (`/etc/modprobe.d/briqyard-zfs.conf`); the daemon's default capacity leaves it out |
| `PRIVATE_ADDRESS` | none | The host's address on a private network, with its prefix (`10.42.0.11/16`): `LISTEN`, the endpoints and `ADVERTISE` default to it, and the public interface takes SSH and `PUBLIC_TCP_PORTS` only (`nft list table inet briqyard_host`, loaded by `briqyard-firewall.service` at boot) |
| `PRIVATE_INTERFACE` | none | Where `PRIVATE_ADDRESS` is put (netplan, `/etc/netplan/60-briqyard-private.yaml`) when no interface has it yet |
| `PUBLIC_TCP_PORTS` | none | Ports the public interface takes besides 22, comma-separated (the fleet's, 80 for certbot) |
| `LISTEN` | `PRIVATE_ADDRESS`'s, else `0.0.0.0:7420` | The API's address; TCP endpoints and the HTTP ingress bind the same address |
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
export BRIQYARD_URL=https://<host>:7420 BRIQYARD_TOKEN=<token> BRIQYARD_TLS_FINGERPRINT=<fingerprint>
briqyard status
```

The CLI trusts the daemon's certificate by that fingerprint alone. To read it again on the host:
`briqyardd tls-fingerprint`, or `openssl x509 -in /var/lib/briqyard/api-cert.pem -noout
-fingerprint -sha256` (colons and case do not matter).

## Configuration

`/etc/briqyard/config.yaml`; every field has a default.

| Field | Default | Meaning |
|---|---|---|
| `listen` | `127.0.0.1:7420` | The API. A public address is refused without `ingress.allowed_clients` or `ingress.allow_public` (ADR 0012). TLS unless loopback or `api_tls: false`; `/metrics` and `/healthz` too |
| `api_tls` | `true` | TLS on a non-loopback `listen`, with the daemon's own certificate (`<data_dir>/api-cert.pem`, made once, ADR 0020). `false`: plain HTTP on any address |
| `token` | none | Required as `Authorization: Bearer` on every request when set |
| `metrics_token` | none | A token of its own for `/metrics`, so a scraper never holds the API's. On a loopback `listen`, `/metrics` and `/v1/openapi.yaml` need no token at all |
| `data_dir` | `/var/lib/briqyard` | State (`state/`), run files (`run/`), image metadata (`images/`), jails (`jail/`). All of it `0700`, root's: records and config drives hold tenant secrets |
| `firecracker`, `jailer`, `kernel`, `init` | `/usr/local/bin/...`, `/var/lib/briqyard/vmlinux` | The binaries and the guest kernel. No `jailer`: Firecracker runs as root (development only) |
| `jail_dir`, `jail_uid_base` | `<data_dir>/jail`, `100000` | Where chroots and memory snapshots go: the daemon mounts `<pool>/jail` there, so they land on the pool, not on `/` (ADR 0014). Each machine gets a uid of its own from this base |
| `kernel_args` | none | Appended to the boot arguments |
| `pci` | `false` | Firecracker's PCI transport (needs a guest kernel with PCI) |
| `root_disk_gb` | `8` | Size of every root disk (thin) |
| `image_keep_days` | `14` | An image no machine uses is removed this long after it was built; under disk pressure, sooner (ADR 0021) |
| `usage_keep_days` | `90` | Closed hours of usage (`GET /v1/usage`) are kept this long, then removed by the tick |
| `events_keep_days` | `7` | Events (`GET /v1/events`, ADR 0019) are kept this long, and at most 100,000 per host; whole hours go, the newest always stays |
| `image_resolve_minutes` | `10` | A tag's digest is reused this long before the registry is asked again; when the registry refuses (a rate limit), the image already on the host serves |
| `conditions.memory_pct` | `95` | `memory_pressure` when committed memory is over this share of capacity (ADR 0021): the fleet places nothing new on the host |
| `conditions.disk_free_pct` | `10` | `disk_pressure` when the pool's free space is under this share of its size: the fleet places nothing new, and unused images go, oldest first, until it is back. `0`: never |
| `console_max_mb` | `64` | A running machine's console is rotated past this size; one previous file is kept |
| `boot_timeout_sec` | `120` | How long a guest may take to answer after its process starts |
| `boots_at_once` | half the threads, at least 2 | Boots run at once; the rest wait their turn, each with the whole timeout |
| `backup.store` | none | `s3://bucket/prefix` or `file:///path`; set, `POST /v1/machines/{id}/backups` works. Credentials in `BRIQYARD_S3_ACCESS_KEY` / `BRIQYARD_S3_SECRET_KEY` |
| `backup.endpoint`, `backup.region` | none | The S3 endpoint (`https://s3.fr-par.scw.cloud`) and region |
| `backup.keep_snapshots` | `1` | Backup snapshots kept on the host per machine (the newest is the base of the next incremental send) |
| `backup.default_every`, `backup.default_keep` | none | The schedule of a machine created without `backup` (ADR 0023): both or neither, `every` at least `1h`, `keep` at least 1 |
| `backup.at_once` | `2` | Scheduled backups (and expired holders' deletions) the tick runs at once |
| `backup.keep_destroyed_days` | `30` | A destroyed machine's backups stay this long, then go with its holder |
| `suspend_on_sleep` | `false` | Sleep with a memory snapshot: wakes in a quarter second, costs the machine's memory in disk |
| `storage.pool` | `byard` | The ZFS pool or dataset for every disk |
| `registries[]` | none | `{host, username, password}` for private registries |
| `network.range` | `10.64.0.0/10` | Tenant subnets, one /24 each (16,384 tenants) |
| `network.upstream_dns` | the host's, then `1.1.1.1` | Where the gateway forwards DNS |
| `network.egress` | the default route's interface | Where machines reach the internet |
| `egress_limits.blocked_ports` | `[25]` | Destination ports no machine reaches on the internet, TCP and UDP (ADR 0018). A machine's own `limits` override each field |
| `egress_limits.new_connections_per_minute` | `0` (none) | New internet connections a machine may open a minute, as many at once |
| `egress_limits.bandwidth_mbit` | `0` (none) | A machine's internet bandwidth, in and out together; at most 100000 |
| `ingress.tcp_ports` | `20000-29999` | Host ports handed to TCP endpoints |
| `ingress.bind` | `127.0.0.1` | Where TCP endpoints listen. A public address is refused without `ingress.allowed_clients` or `ingress.allow_public` |
| `ingress.allowed_clients` | none | The IPv4 networks (`a.b.c.d/n`) that may reach the API, the HTTP ingress and the TCP endpoints; rendered into the daemon's nftables table (`nft list table inet briqyard`). Loopback always may. Empty: anyone who can route to the address |
| `ingress.allow_public` | `false` | Start on a public address with `allowed_clients` empty: a firewall of your own keeps the daemon's ports from the internet |
| `ingress.advertise` | the host's primary address | The address endpoints are reported at (`address` on an endpoint): what a router on another machine dials, a private address when the host has one |
| `ingress.http`, `ingress.domain` | off, `byard.localhost` | The shared HTTP listener and the suffix of its host names |
| `capacity.memory_mb`, `capacity.vcpus` | host memory − 2 GB − the ZFS cache's ceiling (`zfs_arc_max`, when set), threads × 4 | What the host hands out; shared vCPUs oversubscribe |
| `fleet.url`, `fleet.advertise`, `fleet.region` | none | Register with a fleet every 15 s, presenting `token` and the certificate's fingerprint. `advertise` has the API's scheme (`https://` for TLS), or the daemon refuses to start |

## Where things live

| Path | What |
|---|---|
| `<data_dir>/state/{machines,tenants,endpoints}/*.json` | The records, one file each, written atomically |
| `<data_dir>/api-cert.pem`, `api-key.pem` | The API's certificate and key (`0600`). Both removed, a new pair is made at the next start: a new fingerprint to pin. The certificate without its key: the daemon refuses to start |
| `<data_dir>/state/usage/<hour>.json` | Each machine's usage in that UTC hour (ADR 0017); the open hour is rewritten once a minute |
| `<data_dir>/state/events/<hour>.ndjson` | The host's events of that hour, one JSON line each, appended and synced (ADR 0019) |
| `<data_dir>/run/<machine>/` | `console.log` (the guest's serial console, timestamped), `console.<offset>.log` (the previous file, rotated at `console_max_mb`, named after where it starts in the console), `config.tar` (the config drive, `0600`), sockets when not jailed |
| `<jail_dir>/firecracker/<machine>/root/` | The chroot, on `byard/jail`: kernel, config drive (`0400`, the jail's user), device nodes, sockets, `snap.state` and `snap.mem` while suspended |
| `<data_dir>/images/meta/*.json` | What each image is |
| `byard/jail` | A filesystem mounted at `jail_dir`: `zfs list byard/jail` is what the jails and the suspended machines hold |
| `byard/images/<key>` | A root disk per image, with its `@base` snapshot |
| `byard/m/<machine>/root`, `.../data` | A machine's disks |

Every disk is a ZFS zvol: `zfs list -t all -r byard` shows them, `zfs get used,referenced` what
they take. A machine's `fork-*` and `s_*` snapshots on its disks are its forks' and its own: a
`fork-*` goes with the last machine cloned from it (the sweep at start catches what a failed
destroy left), an `s_*` with `briqyard machine snapshot rm <id> <snap>`.

## Upgrade

Install the new binaries and `systemctl restart briqyardd`. The daemon suspends every running
machine on the way down (a memory snapshot each) and marks it so; each one resumes on its next
use, in about a quarter of a second. Nothing reboots. A daemon that crashes instead leaves its
machines running (`KillMode=process`), and the next daemon adopts them. A host from before ADR
0014 (jails on `/`): stop the daemon and empty `jail_dir` before the first start that mounts
`byard/jail` there, or the old files stay hidden on `/` and the machines suspended then boot cold.

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
(`state/holders/<id>.json`) keeps them listed (`briqyard backups --tenant T`, each with
`deletes_at`) and counted in the machine's usage buckets (`backup_gb_hours`). Through a fleet,
`backup rm` of a destroyed machine's backup names its tenant (`--tenant`).

In the store, per machine: `backups/<machine>/<id>.json` (the record) and
`backups/<machine>/<disk>/<id>.zfs` (a stream, `root` or `data`). Ids are times to the
millisecond, `20261021T101500.123Z`. A deletion removes the streams first, then the record.

The state itself (`state/`) is small and lives only on the host; a lost host loses the records
of machines that were never backed up, and their disks. A machine's own `POST
/v1/machines/{id}/snapshots` is a local snapshot of its disks: instant, copy-on-write, not a
backup until sent elsewhere.

## Watch

- `GET /healthz`: the daemon is up. `GET /v1/status`: capacity, use, free disk, `conditions`.
- `GET /metrics`: Prometheus text, from the tick's last measure (15 s; a scrape probes
  nothing). `metrics_token` gives the scraper a token of its own.

  | Series | Labels | What |
  |---|---|---|
  | `briqyard_machines`, `_total`, `_suspended` | `state` | machines on the host |
  | `briqyard_memory_mb`, `briqyard_vcpus` | `kind="used\|capacity"` | committed to running machines, handed out |
  | `briqyard_pool_bytes`, `briqyard_disk_free_mb` | `kind="size\|used\|free"` | the pool |
  | `briqyard_host_condition` | `condition` | 1 while true |
  | `briqyard_events_total` | `type`, `reason` | events since the daemon started |
  | `briqyard_{boots,resumes,suspends,execs,starts_failed,backups}_total`, `briqyard_tenants`, `briqyard_endpoints` | | counts |
  | `briqyard_machine_cpu_seconds_total` | `machine`, `tenant`, `name`, `role` (a gateway's) | its cgroup's CPU time |
  | `briqyard_machine_memory_bytes`, `_memory_limit_bytes` | same | its cgroup's memory, its size |
  | `briqyard_machine_disk_used_bytes` | same | its disks, snapshots and memory snapshot |
  | `briqyard_machine_{internet,ingress}_{in,out}_bytes_total`, `_egress_dropped_packets_total` | same | its traffic |
  | `briqyard_machine_restarts_total` | same | restarts by its policy |
  | `briqyard_machine_state` | same, `state` | 1, one series per machine |
  | `briqyard_machine_boot_seconds` | same | its last start, `starting` to `running` |

  Counters count from the daemon's start. Alert on `briqyard_host_condition == 1`.
- `briqyard top [--tenant T]`: running machines by CPU, with memory, disk and network rates over
  the last 15 s (`GET /v1/top`; through the fleet, a tenant's host or every host).
- Conditions (ADR 0021): `memory_pressure`, `disk_pressure` in `/v1/status` and `briqyard host
  ls`; each change is a `host_condition` event (`briqyard events`), a warning when it turns
  true. Under disk pressure the daemon removes unused images itself (`image_removed` events).
- Logs: one JSON line per event on stderr (journald under systemd): `journalctl -u briqyardd
  -o cat | jq`. Level with `BRIQYARD_LOG=debug` (or any `tracing` filter).
- A machine: `briqyard machine get <id>` (state, why it stopped, its process's exit), `briqyard
  machine logs <id>` (its console; `-f` streams each new line until the machine is destroyed).
  `briqyard machine ls -l app=web -l tier` selects by labels (its `metadata`; `run -l K=V` sets them).
- Quotas (ADR 0025): `briqyard tenant quota <tenant>` shows a tenant's limits and use;
  `--machines N --memory-mb N --vcpus N --disk-gb N` puts exactly those (briq sets them from the
  plan). A refusal is a `quota_exceeded` warning in `briqyard events --tenant <tenant>`.
- `briqyard machine stats <id>`: CPU time, memory and disk it uses now, from its cgroup and its
  datasets. `briqyard machine set-sleep <id> 3h|never` changes the window without a restart.
- What a machine runs (ADR 0024): `briqyard machine set <id> --image … --memory … -e K=V -- cmd…`
  is `pending` (in `get`, `describe`, the `PENDING` column) until its next start; `briqyard
  machine restart <id>` applies it now. A new image is pulled at that start and the root disk
  made again from it; the data volume stays.
- `briqyard usage --from <hour> --to <hour> [--tenant T] [--json]`: what each machine used
  per hour (ADR 0017); `nft list set inet briqyard internet_out` shows the raw counters.
- Egress limits (ADR 0018): `briqyard machine get <id>` shows `limits` and `egress_drops`;
  `briqyard machine set-limits <id> --conn-per-min 0` lifts a rate at once. Raw:
  `nft list set inet briqyard dropped_port` (also `dropped_rate`, `dropped_bandwidth`).

## When something is off

| Symptom | Look at |
|---|---|
| A create or start answers 409 `boot_failed` | The image's fault: the machine is kept in `state: error`, `error` holds the last console lines. `briqyard machine logs`, then destroy it |
| A start after `machine set --image` answers 409 `boot_failed`, `error: image …` | The new image could not be pulled or built; the change is still `pending`. `machine set` another image (or the one it runs, which drops the change) and start again |
| A start after `machine set --memory` answers 503 `capacity` | The host has no room for the new size; the change is still `pending`. Through a fleet, the tenant stays on its host: move it (backups, `tenant unpin`, restores) |
| A machine is `stopped (host)` | The daemon stopped it: a restart of `briqyardd` without a suspend, or a crashed daemon's leftover. The next use wakes it |
| A machine stays `destroying` | Its disks could not be destroyed (`zfs destroy` in the log); the daemon tries again every 15 s |
| The process exits at once (`stopped`, `exit.code`) | `briqyard machine logs`: the image's own output. `restart.policy: on-failure` tries three times, 10 s, 20 s, 40 s apart (`restarting_at`); `crash_loop` events from the third |
| `/wait` answers 409 `not_ready`, or the ingress 502 after a wait | The program runs but its readiness or startup probe does not pass: `briqyard machine describe` shows each probe's last result. A TCP or HTTP probe needs the program on the machine's address, not only `127.0.0.1` |
| `startup_failed` then `error` | The startup probe did not pass within `failure_threshold` × `period_sec` of a start: the boot failed, as `boot_failed` does. On a restart it is a crash instead, restarted by the policy |
| `the guest did not come up` | The kernel booted but the init did not answer on vsock within `boot_timeout_sec`: console log, then the kernel (`kernel`) and init (`init`) paths |
| `no host has room` (fleet) | `briqyard host ls`: fill, free memory, free disk, conditions. `used` counts what placement reserved until the next heartbeat |
| `no host in region … has room` (fleet) | No ready host of that region under the ceiling: `briqyard host ls`, the `REGION` column; order or add one there |
| `tenant … is in region …, not …` (fleet, 400) | The tenant lives on a host of another region. A team that changes region moves: backups, destroy, `tenant unpin`, restores with the new region |
| 403 `quota` | The tenant is at a limit of its quota: `briqyard tenant quota <tenant>` shows the limit and the use |
| `host h_… is under disk_pressure` (fleet, 503 `capacity`) | The tenant's host takes nothing new until the condition clears. Disk: `zfs list -o space byard`; unused images go by themselves, then backups and destroys of what is left. Memory: stop machines, or move the tenant (below) |
| `host h_… is down` (fleet, 503) | The host missed its heartbeats for `placement.down_after_sec`: its machines answer again once it is back. `briqyard host ls`, then the host's `journalctl -u briqyardd` |
| `fleet heartbeat refused` in a host's log | `unknown_host`: the fleet has no record at the host's `fleet.advertise` address (list it under `hosts:`). `unauthorized`: the host's `token` is not the one the fleet holds for it. `tls_mismatch`: its certificate is not the pinned one, or none is pinned (set `tls_fingerprint`); a host just ordered gets this until its bootstrap has pinned it |
| `host …: … is not the pinned …` (fleet, 502 `host_unreachable`) | The host presents another certificate than its record's `tls_fingerprint`: reinstalled (pin the new one), or not the host |
| `write registry …` (fleet, 500 `registry`) | The fleet's `state_dir` is full or not writable; nothing is recorded until it is |
| `bootstrap attempt N: … host key …` in a host's note | The server's SSH key is not the one pinned in `<state_dir>/known_hosts`: reinstalled, remove its line; not reinstalled, do not connect |
| `bootstrap attempt N: … is in use (mounted at …)`, `… holds ext4` | `pool_device` names something in use: the OS's disks are named whole (their free space is taken), never the OS's partitions; a disk meant for the pool is wiped by you (`wipefs -a`) |
| `… has under 10 GB free` | The install filled the disk: reinstall with the layout of "First OVH host", step 2 |
| `no interface has 10.42.…: set PRIVATE_INTERFACE`, `… did not come up` | `private_interface` is not this server's vRack interface (`ip -br link`, the MAC the manager shows as Private), or the server is not in the vRack yet |
| `release … has no …`, `digest differs from the release's SHA256SUMS` | `release` names a tag without this architecture's files, or the token cannot read the repository |
| An endpoint connects but the service refuses | The machine was waking: clients retry, as connection pools do. Postgres accepts TCP before it is ready |
| `dataset is busy` | A zvol a Firecracker just released; the daemon retries for ten seconds |
| A jail refuses to start | `<run>/<machine>/console.log` holds the jailer's own messages |

## A fleet

`briqyard-fleet` runs anywhere that reaches every host (`/etc/briqyard/fleet.yaml`, unit in
`hack/briqyard-fleet.service`). Clients use the fleet's URL and `token` as they would a
daemon's; `briqyard host ls` shows the hosts.

A host has one credential, its own API token, and the fleet must hold it before the host can
be anything to it: it forwards with it and takes the host's heartbeats (`fleet:` in the host's
config) only with it. A host the fleet orders or adds (`briqyard host add`) gets its token from
the bootstrap. A host you install yourself is listed under `hosts:` with it:

```yaml
hosts:
  - id: h1
    url: https://10.0.0.5:7420
    token: <the host's token>
    tls_fingerprint: <what the bootstrap script printed>
    region: gra
```

`region` is what a create's `region` names: a new tenant goes to a host of it, and stays in it
(ADR 0025). A host ordered by the fleet takes the region its daemon's `fleet.region` reports.

The fleet polls it every 15 s and accepts its heartbeats; without a `token` it is polled only.
An `https://` URL needs its `tls_fingerprint` and a fingerprint needs `https://` (refused at
start otherwise): the fleet accepts that one certificate from the host and nothing else, no CA,
and refuses a heartbeat reporting another (`tls_mismatch`). A host on plain HTTP (a loopback
daemon you forwarded) has neither.
A heartbeat from an address no entry or order expects is refused (`unknown_host`), so no host
can speak for another. The registry is `<state_dir>/registry.json`; a write that fails is an
`error` in the fleet's log and a 500 `registry` on the request that needed it.

The fleet's own listener serves TLS with a certificate of yours: `tls: { cert, key }`, PEM
files, a chain for the fleet's name (Let's Encrypt in production: `certbot certonly
--standalone -d fleet.example`, then `cert: /etc/letsencrypt/live/fleet.example/fullchain.pem`,
`key: …/privkey.pem`; restart the fleet after a renewal). Without `tls` it serves plain HTTP,
and refuses a non-loopback `listen` unless `tls: off` says something in front terminates TLS.
Hosts check the fleet against the web PKI roots.

### Adding and removing hosts

Hosts come and go through the API, by hand or from the autoscaler; both use the same
provisioner (`kind: hetzner-robot`, `scaleway` or `ovh`, credentials through `HETZNER_ROBOT_USER` /
`HETZNER_ROBOT_PASSWORD`, `SCW_SECRET_KEY`, or `OVH_APPLICATION_KEY` / `OVH_APPLICATION_SECRET` /
`OVH_CONSUMER_KEY`). Every provisioner is `dry_run: true` until the configuration says
otherwise: it records what it would order and orders nothing. Turn it off only once a dry run
has shown the right product, location and count.

```bash
briqyard host add 51.68.1.2 --address 10.42.0.11 --region gra   # POST /v1/hosts: a server you bought, bootstrapped
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
preferred payment method and the retraction period waived, with the cheapest option of each
mandatory family (memory, disks, bandwidth: the plan's base configuration) and no OS.
`ovh.subsidiary` is the OVH company the order is made under (`FR` by default). The credentials
are an API application (`application_key`, `application_secret`) and a consumer key with
rights on `/order/*`, `/me/order/*`, `/me/sshKey/*`, `/dedicated/server/*` and `GET /me`; every
request is signed with them and OVH's own clock (`/auth/time`). The provider id is
`order:<orderId>` until delivery. Every two minutes the fleet reads the order's status; once
it is `delivered`, it assumes one of the order's details (`/me/order/<id>/details/<detail>`)
carries the server's service name as `domain` (a placeholder like `*001` before), checks that
name against the account's server list (`GET /dedicated/server`), reads the server for its
address, and starts an Ubuntu 24.04 install (`POST /dedicated/server/<name>/reinstall`,
`ubuntu2404-server_64`, the OS on a RAID 1 of `/boot` 1 GiB and `/` 100 GiB, the rest of the
disks left for the pool, ADR 0028) with the SSH key named `ovh.ssh_key_name`, which must
already be in the account (`/me/sshKey`); the bootstrap then fails every two minutes until the
install is done, which is expected. A delivered order whose details name no server of the
account is an error in the host's note: add the host by hand. A retire terminates the server
(`POST /dedicated/server/<name>/terminate`): OVH then emails a confirmation to accept, and the
server is billed to the end of its period; a retire before delivery is refused (cancel the
order in the OVH manager). This provisioner has not run against the real API yet: the request
shapes follow OVH's published schemas (ADR 0028 lists what is still assumed), and the delivery
assumption above is the one to check first. An ordered host keeps its public address for its
API: the vRack address of a server is not in OVH's API, so a vRack host is added by hand.

A server the fleet ordered or added becomes a host on its own when
`provisioner.bootstrap.enabled` is set: every two minutes the fleet asks the provider for an
ordered server's address, then runs `hack/bootstrap-host.sh` on it over SSH (`ssh_user`,
`ssh_key`: the key the provider installed, or yours on a server you bought; `release`,
`release_token`, `pool_device`, `fleet_url`, `allowed_clients` for the script), with a token
of its own for the host's API. A host whose API address is in `private_network` (a CIDR, the
vRack) is reached over SSH at its own address (`host add`'s first argument) and told its
private address: `private_interface` gets it when the server does not have it yet, and its
public interface takes SSH and `public_tcp_ports` only (ADR 0028).
Once the script succeeds, a second connection, strict against the pinned SSH key, reads the
daemon's certificate fingerprint (`briqyardd tls-fingerprint`); the fleet pins it in the same
write that marks the host `bootstrapped` (the note says `api certificate … pinned`), and dials
`https://<ip>:7420` with it. A host whose API would be plain HTTP (a loopback `listen`, for
want of `allowed_clients`) fails the attempt.
The host is `bootstrapped` once the script succeeds and `ready` at its first heartbeat; a server
that cannot be installed after `max_attempts` is `failed`, with the last error in its note.
Without the bootstrap, run the script yourself with `FLEET_URL`, `ADVERTISE` and the
`BRIQYARD_TOKEN` the fleet holds for the host (an entry under `hosts:`).

No provider's API returns the server's SSH host key, so the bootstrap pins the key it sees:
the first attempt that succeeds appends it to `<state_dir>/known_hosts` and writes its
fingerprint into the host's note (`ssh host key SHA256:… ed25519 pinned at first connect`);
compare it with the provider's console. Every later connect is strict against that file. A
server reinstalled by the provider has a new key: remove its line from the file.

A retire drains the host first (no new tenant lands on it) and releases it at the provider
once it runs nothing: at once when it is already empty, else from the hourly pass as soon as
its last machine is destroyed. A host from the `hosts:` list is retired by removing it from
the configuration; forgotten through the API, it is back on the next poll.

### Moving a tenant

Machines do not move between hosts on their own: a draining host keeps its tenants until they
are removed. To take a tenant off a host (draining, full, or gone):

```bash
briqyard host drain h_old                          # nothing new lands there
briqyard machine backup <id>                       # each machine of the tenant (ADR 0008)
briqyard machine destroy <id>                      # each one, once its backup is listed
briqyard tenant rm <tenant>                        # its network and gateway on the old host; unpins it
briqyard machine restore --from <id> --tenant <tenant> --name <name>   # placed afresh
```

A tenant's gateway (ADR 0016) is not backed up: `briqyard tenant gateway set` it again once the
tenant is unpinned (the fleet places the tenant with it), before the restores of its
`via:gateway` machines.

`briqyard tenant unpin <tenant>` (`POST /v1/tenants/{id}/unpin`) drops the pin without asking
the host, for a host that is down for good or a pin left on a full host. A tenant unpinned
while it still has machines on a host is pinned back there by the host's next heartbeat, and a
machine created in between lands on another host, where it cannot reach the others: unpin
once the tenant has nothing left on the host, or mean to abandon what is there.

The autoscaler (`provisioner.enabled: true`) orders a host when no ready host has a slot of
`slot_mb` left and releases a provisioned host empty for `idle_grace`, between `min_hosts` and
`max_hosts`, one change a minute.

## First OVH host

One server, the fleet on it, the API and the endpoints on the vRack, the public interface
closed to all but SSH and the fleet's port (ADR 0028). The values below (`10.42.0.0/16`,
`10.42.0.11`, `enp3s0f1`, `fleet.stg.briq.cloud`) are examples: write yours.

**1. Order** (OVH manager, Bare Metal Cloud, Dedicated servers):

| | |
|---|---|
| Range | Rise or Advance: KVM on every dedicated server; the vRack on these (not on Kimsufi or So you Start) |
| Memory | 64 GB or more: machines get memory − 2 GB − the ZFS cache's cap (10 %) |
| Disks | 2 × NVMe of one size |
| Options | the vRack (private bandwidth) |
| OS | Ubuntu Server 24.04 LTS |

**2. Install layout** (Install, "Customise the partition configuration"), on both disks:

| Mount | File system | RAID | Size |
|---|---|---|---|
| `/boot` | ext4 | 1 | 1 GiB |
| `/` | ext4 | 1 | 100 GiB |
| swap | removed | | |

No partition fills the disks: the rest of each NVMe stays free for the pool. Add your SSH key
and, from the second server on, the fleet's (`/etc/briqyard/fleet_ssh_key.pub` on its server).
After the install, `sgdisk -p /dev/nvme0n1` ends with the free space (`Total free space is …`).
If the manager makes the last partition fill the disk, reinstall through the API console
(`POST /dedicated/server/{serviceName}/reinstall`) with `operatingSystem: ubuntu2404-server_64`,
your key as `customizations.sshKey`, and `storage: [{partitioning: {layout: [{mountPoint:
"/boot", fileSystem: ext4, raidLevel: 1, size: 1024}, {mountPoint: "/", fileSystem: ext4,
raidLevel: 1, size: 102400}]}}]`, the provisioner's own body.

**3. The vRack**: Network, vRack private network, add the server. Its private interface is
the one whose MAC the manager shows as Private (server, Network interfaces): `ip -br link |
grep -i <mac>` names it. Pick the range (`10.42.0.0/16`) and the server's address in it.

**4. The fleet, on this server** (it runs nowhere else yet; the repository is private, so the
binaries come from your Mac):

```bash
gh release download v0.1.0 -R briq-cloud/briqyard -p 'briqyard*-linux-x86_64' -p SHA256SUMS-x86_64 -D /tmp/byard
(cd /tmp/byard && shasum -a 256 -c SHA256SUMS-x86_64)
scp /tmp/byard/briqyard-fleet-linux-x86_64 root@<public ip>:/usr/local/bin/briqyard-fleet
scp /tmp/byard/briqyard-linux-x86_64 root@<public ip>:/usr/local/bin/briqyard
scp hack/briqyard-fleet.service root@<public ip>:/etc/systemd/system/
ssh root@<public ip>
chmod 0755 /usr/local/bin/briqyard /usr/local/bin/briqyard-fleet && mkdir -p /etc/briqyard
ssh-keygen -q -t ed25519 -N '' -f /etc/briqyard/fleet_ssh_key && cat /etc/briqyard/fleet_ssh_key.pub >> /root/.ssh/authorized_keys
apt-get install -y certbot && certbot certonly --standalone -d fleet.stg.briq.cloud   # its DNS record first
echo "BRIQYARD_RELEASE_TOKEN=<fine-grained token, contents read on briq-cloud/briqyard>" > /etc/briqyard/fleet.env && chmod 0600 /etc/briqyard/fleet.env
```

`/etc/briqyard/fleet.yaml`:

```yaml
listen: 0.0.0.0:7430
tls: { cert: /etc/letsencrypt/live/fleet.stg.briq.cloud/fullchain.pem, key: /etc/letsencrypt/live/fleet.stg.briq.cloud/privkey.pem }
token: <openssl rand -hex 24: what briq and the CLI present>
state_dir: /var/lib/briqyard-fleet
provisioner:
  kind: static
  bootstrap:
    enabled: true
    ssh_key: /etc/briqyard/fleet_ssh_key
    release: https://github.com/briq-cloud/briqyard/releases/download/v0.1.0
    pool_device: /dev/nvme0n1,/dev/nvme1n1
    fleet_url: https://fleet.stg.briq.cloud:7430
    private_network: 10.42.0.0/16
    private_interface: enp3s0f1
    allowed_clients: [10.42.0.0/16]       # and the edge's addresses
    public_tcp_ports: [7430, 80]          # briq reaches the fleet; certbot renews
```

`systemctl daemon-reload && systemctl enable --now briqyard-fleet`.

**5. Add the server to the fleet**, from your Mac (`cargo build --release -p briqyard`):

```bash
export BRIQYARD_URL=https://fleet.stg.briq.cloud:7430 BRIQYARD_TOKEN=<the fleet's token>
briqyard host add <public ip> --address 10.42.0.11 --region gra
briqyard host ls     # within two minutes: the note, then ready
```

The note names the SSH key pinned (`SHA256:…`): compare it with `ssh-keygen -lf
/etc/ssh/ssh_host_ed25519_key.pub` in your own session. Then the API certificate pinned, then
`ready` at the first heartbeat. A failed attempt is in the note and tried again every two
minutes; fix the cause, nothing to undo.

**6. Smoke checks:**

```bash
ssh root@<public ip> briqyard doctor                   # every line ok
ssh root@<public ip> zpool status byard                # mirror-0, both partitions ONLINE
ssh root@<public ip> nft list table inet briqyard_host # tcp 22, 7430, 80, then drop
nc -vz -w 3 <public ip> 7420                            # from the Mac: times out
scp hack/e2e.sh root@<public ip>:/root/ && ssh root@<public ip> 'apt-get install -y bc postgresql-client'
ssh root@<public ip> 'export BRIQYARD_URL=https://10.42.0.11:7420 BRIQYARD_TOKEN=$(sed -n "s/^token: \"\(.*\)\"/\1/p" /etc/briqyard/config.yaml) BRIQYARD_TLS_FINGERPRINT=$(briqyardd --config /etc/briqyard/config.yaml tls-fingerprint); bash /root/e2e.sh'
BRIQYARD_URL=https://fleet.stg.briq.cloud:7430 BRIQYARD_TOKEN=<the fleet's token> hack/fleet-smoke.sh
```

e2e runs on the host (endpoints are vRack addresses, and it needs GNU tools) and needs a
`backup.store` in the host's config: the real bucket (its test backups go, destroyed machines'
after `keep_destroyed_days`), or `file:///var/lib/briqyard/backups` for this run. The fleet
smoke runs from anywhere that reaches the fleet and touches no real host.

**7. The first day**, what to watch:

| What | Where |
|---|---|
| Errors | `journalctl -u briqyardd -u briqyard-fleet -o cat \| jq -c 'select(.level != "INFO")'` |
| The host | `briqyard host ls`: `ready`, conditions false, last seen within 15 s |
| The disks | `zpool status -x` says all pools are healthy; `zpool list byard` |
| Memory | `free -g`; `arc_summary \| head -30`: the ARC under its cap |
| Machines | `briqyard top`, `briqyard events --watch` |
| The kernel | `dmesg -T \| grep -iE 'kvm\|oom\|nvme\|mce'` |
| The public interface | `nft list chain inet briqyard_host input`: the drop counter grows with the internet's scans |

**8. Undo**: `briqyard host retire <id>` (drained, forgotten once it runs nothing). On the
server: `systemctl disable --now briqyardd briqyard-firewall`, `nft delete table inet
briqyard_host`, `zpool destroy byard`, `sgdisk -d <n>` the `briqyard-pool` partition of each
disk (`sgdisk -p`), `rm /etc/netplan/60-briqyard-private.yaml && netplan apply`. Or reinstall
it from the OVH manager. Locked out of SSH: Netboot in rescue mode, mount the root RAID
(`mdadm --assemble --scan`), remove `etc/systemd/system/sysinit.target.wants/briqyard-firewall.service`,
reboot from the disk.

### A KVM runner for the suites (later, `LEAVING-FLY.md` item 12)

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

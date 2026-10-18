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
bash bootstrap-host.sh
```

It installs the packages (ZFS, nftables, e2fsprogs), makes the pool (on the device given, or on
a file for a trial), downloads Firecracker, its jailer and a guest kernel, installs the
binaries, writes `/etc/briqyard/config.yaml` and the systemd unit, and starts `briqyardd`.
With `FLEET_URL`, `FLEET_TOKEN` and `ADVERTISE` set, the host registers with a fleet.

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
| `suspend_on_sleep` | `false` | Sleep with a memory snapshot: wakes in a quarter second, costs the machine's memory in disk |
| `storage.pool` | `byard` | The ZFS pool or dataset for every disk |
| `registries[]` | none | `{host, username, password}` for private registries |
| `network.range` | `10.64.0.0/10` | Tenant subnets, one /24 each (16,384 tenants) |
| `network.upstream_dns` | the host's, then `1.1.1.1` | Where the gateway forwards DNS |
| `network.egress` | the default route's interface | Where machines reach the internet |
| `ingress.tcp_ports` | `20000-29999` | Host ports handed to TCP endpoints |
| `ingress.bind` | `0.0.0.0` | Where TCP endpoints listen. A public address makes every endpoint public: bind a private one, or firewall the range |
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

The state is the `state/` directory and the ZFS datasets. `zfs snapshot -r byard/m@backup` then
`zfs send -R` to another pool or to object storage (`zfs send | gzip | aws s3 cp - ...`) copies
every machine's disks; the `state/` files say which is which. A machine's own `POST
/v1/machines/{id}/snapshots` is a local snapshot of its disks (instant, copy-on-write); it is
not a backup until sent elsewhere.

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
provisioner (`kind: hetzner-robot` or `scaleway`, credentials through `HETZNER_ROBOT_USER` /
`HETZNER_ROBOT_PASSWORD` or `SCW_SECRET_KEY`). Every provisioner is `dry_run: true` until the
configuration says otherwise: it records what it would order and orders nothing. Turn it off
only once a dry run has shown the right product, location and count.

```bash
briqyard host order --reason "launch week"   # POST /v1/hosts/order: a server, state provisioning
briqyard host ls                             # its note says what the provider and the bootstrap last did
briqyard host retire h_123456                # POST /v1/hosts/{id}/retire: drain, then release once empty
briqyard host drain h_123456                 # place no new tenant on it, keep it
briqyard host rm h_123456                    # forget it (its machines are not touched)
```

A server the fleet ordered becomes a host on its own when `provisioner.bootstrap.enabled` is
set: every two minutes the fleet asks the provider for the server's address, then runs
`hack/bootstrap-host.sh` on it over SSH (`ssh_user`, `ssh_key`: the key the provider installed;
`release`, `pool_device`, `fleet_url` for the script), with a token of its own for the host's API.
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

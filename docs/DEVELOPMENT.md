# Development

briqyard is a Rust workspace. The daemon and the init only run on Linux with KVM; the API
types, the CLI and the unit tests build anywhere.

## On a Linux host with KVM

```bash
apt install zfsutils-linux nftables e2fsprogs build-essential pkg-config
cargo build --release --workspace
```

You also need a Firecracker binary and an uncompressed guest kernel. Firecracker's own CI
publishes both; `hack/bootstrap-host.sh` downloads the pinned release and kernel (checked
against their digests) into `/usr/local/bin/firecracker` and `/var/lib/briqyard/vmlinux` (and
does everything else a host needs: run it on a fresh server).

A ZFS pool for the disks, encrypted as on every host (ADR 0026; the daemon refuses one that is
not). For development, a file-backed one with its key in a file, what `hack/config.dev.yaml`
names (`storage.key: file:/etc/briqyard/pool.key`):

```bash
mkdir -p -m 0700 /etc/briqyard
(umask 077; od -An -tx1 -N32 /dev/urandom | tr -d ' \n' > /etc/briqyard/pool.key)
truncate -s 30G /var/lib/briqyard/pool.img
zpool create -o ashift=12 -O compression=lz4 -O atime=off -O encryption=aes-256-gcm \
  -O keyformat=hex -O keylocation=prompt byard /var/lib/briqyard/pool.img < /etc/briqyard/pool.key
```

A pool made before ADR 0026 is not encrypted and cannot be made so: on a dev VM, destroy every
machine (`briqyard machine ls`, `machine rm`), stop the daemon, `zpool destroy byard`, remove
`pool.img` and `/var/lib/briqyard/{state,run,images,jail,backups}` (the daemon never mounts
its datasets over files), then make the pool as above. `fc2` is made again by the bootstrap
(below) with its key from the fleet: remove its `/etc/briqyard/config.yaml` too, so the script
writes `storage.key: fleet`. The dev fleet is `tls: off` (fc2 reaches it through the Mac's
port forwards, so it sees Lima's forwarder, not fc2): a host's calls are checked by their token
alone there, not by their address (ADR 0026); the address check is in the unit tests. The dev VMs are aarch64, where OpenZFS's AES-GCM has no
accelerated code: their disks are about 3.5 times slower encrypted (ADR 0026).

Then `sudo briqyardd --config hack/config.dev.yaml`, and `briqyard status`.

## On a Mac

Apple silicon M3 or later with macOS 15 or later can run a Linux VM that has `/dev/kvm`:

```bash
brew install lima
limactl start --name=fc --vm-type=vz --nested-virt --cpus=6 --memory=16 --disk=60 template://ubuntu
```

Inside it, follow the Linux steps (Rust, ZFS, Firecracker). The repository is mounted read-only
in the VM at the same path; `hack/vm.sh` builds there, installs the binaries, writes the systemd
unit and restarts the daemon:

```bash
hack/vm.sh install     # build in the VM, install, restart briqyardd
hack/vm.sh logs        # follow the daemon's log
hack/vm.sh e2e         # install, then run hack/e2e.sh inside the VM
```

Everything under nested virtualization is slower than on a real server; the timings are not a
benchmark.

`hack/vm.sh install` also lays out what `hack/fleet-smoke.sh` upgrades the VM's own host to
(ADR 0027): this build's binaries under a release's names in `/var/lib/briqyard-fleet/release`
(`file://` for `--release`), and the fleet's SSH key (`/etc/briqyard/fleet_ssh_key`, made once)
in root's `authorized_keys`, so the fleet runs the bootstrap script on its own VM over SSH. The
version a build says is `0.1.0+<commit>` of the checkout it was built from (`git` in the VM
reads the mount; uncommitted changes say their HEAD's commit).

### Two hosts on the Mac

A second VM is a second host, so the fleet's placement, forwarding and host-down path run
for real. Lima's `vzNAT` network isolates each VM (VMs reach the Mac at 192.168.64.1, not each
other; `socket_vmnet` would fix that but needs root), so the VMs talk through ports the Mac
forwards on every interface: in `~/.lima/fc/lima.yaml`, before `vmType: vz`,

```yaml
portForwards:
- {guestPort: 7420, hostIP: 0.0.0.0, hostPort: 7420}
- {guestPort: 7430, hostIP: 0.0.0.0, hostPort: 7430}
networks:
- vzNAT: true
```

then `limactl stop fc && limactl start fc`. The second VM, with the daemon's port forwarded as
27420 the same way, is installed from the binaries `hack/vm.sh` built (copied out with
`limactl copy` into `bin/`) by the bootstrap script, and registers with the fleet, which takes
a registration only for a host it expects: the `fc2` entry in `hack/fleet.dev.yaml` (its
address and token). fc2's daemon binds loopback, so it serves plain HTTP and the fleet pins no
certificate for it; fc's dev configs say `api_tls: false` and `tls: off` (ADR 0020), so the
suites stay on `http://`. `hack/vm.sh install` copies the fleet's config every time and the
daemon's only when none is there: after a change, copy it by hand and restart the unit. Then

```bash
limactl start --name=fc2 --vm-type=vz --nested-virt --cpus=2 --memory=6 --disk=30 --network=vzNAT template://ubuntu
limactl shell fc2 sudo bash -c 'cd /Users/uplab/projects/briqyard && BRIQYARD_POOL_FILE_GB=15 BRIQYARD_TOKEN=fc2-token \
  FLEET_URL=http://192.168.64.1:7430 ADVERTISE=http://192.168.64.1:27420 bash hack/bootstrap-host.sh'
cargo build --release -p briqyard   # the CLI, on the Mac
PATH=target/release:$PATH BRIQYARD_URL=http://127.0.0.1:7430 \
  SECOND_HOST_STOP="limactl shell fc2 sudo systemctl stop briqyardd" \
  SECOND_HOST_START="limactl shell fc2 sudo systemctl start briqyardd" \
  SECOND_HOST_SH="limactl shell fc2 sudo" bash hack/fleet-two-hosts.sh
```

## Tests

- `cargo test --workspace`: unit tests, which run anywhere (extraction and whiteouts, DNS
  packets, the guest protocol, address allocation, the store, the configuration, the ZFS
  backend against a fake `zfs`, the Firecracker and guest clients against in-test sockets,
  the config drive, restart and sleep decisions, and the manager's transitions through a
  harness over a temp directory, the same fake `zfs` and a mock host (`Vmm`, `Guest`,
  `Net`; ADR 0010): create to running, boot failures, start against destroy, starts past
  capacity, stop and suspend, a caller that hangs up, crash recovery, the orphan sweep,
  the sleeper's tick, the init's exit report, fork snapshots freed, backups (the schedule due
  and not before, at most `at_once`, one per machine, a machine with no process skipped while
  unchanged, retention and its restores, delete and `chain`, a failure and its backoff, a
  refused store leaving nothing, a destroyed machine's held, counted and expired), the tenant's gateway
  (booted once by what needs it, its failure named, slept by the tick, kept while in use),
  usage (hours split, counter resets, suspended and stopped machines, traffic on its machine,
  closed hours, a restart, retention, a destroyed machine, the route's range), egress limits
  (the host's under a machine's own, set at start, swapped on PATCH, withdrawn at stop and
  destroy, none for `via` and `none`, rendered at daemon start, drops in the view and usage), the API's TLS
  (the certificate made once, the pinned verifier against a loopback server, the fleet
  forwarding to a stub daemon over TLS, the heartbeat checked against the pin), events and
  versions (each transition's event and reason, a boot and a start failure, an exit and its
  restart, suspend and resume, the gateway, PATCH, a stale `If-Match`, the seq past the
  records at load, the route's pages, watch and 410; the log itself: seqs across a restart, a
  torn line, retention, a watch's backlog, lag, heartbeat and shutdown), metrics and
  conditions (the exposition of machines in every state checked line by line and against the
  format, no probe per scrape, conditions turning true and clearing with their events, a pool
  that cannot be read, image removal under disk pressure oldest unused first, `top` from two
  ticks, the console rotated while two tasks write with no line lost, logs across the rotated
  file, placement and creates refused on a host under pressure), probes (readiness and
  its events, `/wait` for ready and its `not_ready`, a startup failure that fails the boot and
  one that is a crash, liveness under `on-failure` and `no`, the backoff, its reset and
  `crash_loop`, the ingress waiting for a woken machine, the host's turns, a PATCH on a running
  machine, the gateway waited for ready, an adopted machine; the HTTP client and the TCP
  connect against loopback servers), changes at the next boot (a PATCH on a running machine
  left pending with its events and `If-Match`, applied by a restart into the config drive, a
  new image's root disk cloned again with the volume untouched and a fork promoted, the root
  made from the cache's image and only once no backup runs, a promoted fork backed up whole
  despite its source's snapshots, a new size reserved at the start and refused past the host, a
  memory snapshot dropped by what it holds and kept for ports, an image that cannot be pulled
  failing the boot with the change kept, create and PATCH refusing a bad spec in the same
  words), labels, quotas and logs follow (a listing by labels, the quota at create, fork,
  start and the gateway with its message and event, its use; a follow from the start and
  from a cursor, across rotations, ending at the destroy, its heartbeat and shutdown;
  placement by region and the cross-region refusal through stub hosts in two regions), disk
  limits (the host's per vCPU under a machine's own at boot, a new size's at the next boot, a
  live change and a refused one, a stopped machine's at its start, the drive and metrics
  requests Firecracker gets, metrics lines added per machine across boots, the jail's
  `cpu.weight`), snapshots and restore (ADR 0031: named, both disks at one instant, deleted by
  name; a restore that swaps the disk, a newer snapshot and a fork kept on the retired disk, and
  back again with nothing retired left; a deleted snapshot a retired disk hangs from freed with
  it; a fork's destroy freeing the retired disk it held; a source destroyed under a fork of its
  retired disk; a backup after a restore continuing from an ancestor, or whole, and restorable;
  `If-Match` and a stopped machine left stopped; a restore cut short finished by the daemon and
  by a start; a snapshot with memory resumed while the spec is the same, cold after a change; a
  new image dropping the snapshots' root halves; a wake during a stop), the
  pool's key (an unencrypted pool refused, a loaded key left alone, loaded from a file and from
  a stub fleet as the host, each failed try saying why without the key, the wait ended by a
  stop; `load-key` with the key on stdin; a filesystem never mounted over files; the fleet's
  key route: made at the first ask, the same after, one per host, refused to any other token
  or address, written `0600` before it is answered, in no listing, gone with the host; a
  registry's backup: written sealed and only on a change, read back with its identity and no
  other, a key served only once the store holds it; a
  registry that does not parse refused, never read as empty, and fields it does not know
  written back; a host call from another address than its record's refused unless behind
  `tls: off`; a key whose write failed taken back, never served; a keyed host forgotten only by
  force; a drained host never released, a retiring one once empty), upgrades (the init's and
  the VMM's versions recorded at boot, a snapshot of another VMM booted cold, a hand-over that
  waits for a stop to settle, touches no machine and lets no transition begin, the adoption
  after it with `gone` apart from `stopped`, the daemon's start booting again what the host
  stopped within its window, a record keeping a newer daemon's fields, an old init's unknown op
  named, old and new wire shapes decoding, the fleet's refusals, its wait for a new start and
  its end states, drain apart from retire). What still needs the host: a tenant's first create (its bridge and
  the DNS listener on the gateway), a volume (`mkfs.ext4`), the jailer, real `zfs send` and
  `receive`, an image pull and its event, the API handlers; those stay with the e2e suite).
- `hack/e2e.sh`: the end-to-end suite against a running daemon: boot, exec, files, DNS,
  egress, tenant isolation, stop and start, exit codes, Postgres on a volume, an endpoint,
  sleep on idle, wake on connect, a fork, suspend and resume, the HTTP ingress, a daemon crash,
  backups to a directory store and a restore, egress policies (`via` a gateway machine, `none`,
  back to `open`), a tenant gateway (a forward proxy its consumer's start boots, HTTPS through
  it and nothing around it, stopped by the sleeper, gone with the tenant), iron-proxy as a tenant
  gateway (a stock image with its config and CA as boot files: a header injected and a proxy
  token swapped on the way to a sibling's HTTPS echo, a request without the token and a host off
  its list refused, no secret in the consumer), egress limits (port
  25 refused at once while 443 connects, 6 connections a minute then the 7th dropped, lifted
  live, drops shown, a download capped at 2 Mbit/s), usage (running seconds, internet and
  ingress bytes, a stopped machine's disk hours), events (a watch from before a stop gets it,
  a stale `If-Match` refused, `describe`, the reasons in order, a cursor past the log
  refused), metrics (a running machine's CPU and state series, `top` lists it with rates after
  two ticks, no condition true on a healthy host), probes (an HTTP readiness probe: not ready, then
  ready and its event, `wait`; an exec liveness probe that fails: `liveness_failed`, restarted,
  running again), backups on a schedule (every second backup whole and a kept one's base kept,
  a base not deleted alone, the oldest kept restored from its chain, retention down to 2, its
  event, a destroyed machine's backups listed then deleted with their chain), changes at the
  next boot (env and a boot file set on a running Python server: pending, still the old values; `machine restart`: the new values and `applied`; a
  new image: Python 3.13, the volume's file kept), labels, a quota and a follow (`ls -l` selecting one machine, a
  refused selector, a second create refused 403 `quota` with its use and event, `logs -f`
  receiving a line printed after it began and ending at the destroy), disk limits (a machine's
  own over the host's for 2 vCPUs; at 4 MB/s, 32 MiB written to the volume in 5 s or more and
  16 MiB read from the root disk in 2 s or more, with O_DIRECT; `cpu.weight` 200; lifted live;
  set while suspended and in force after the resume; throttling on `/metrics`), snapshots (files on the volume and the root disk back after a
  restore, a running machine booted again, a fork made after the snapshot still working, a backup
  after the restore continuing from the one before the snapshot and restoring to the machine's
  content, the newer snapshot restored and the next backup whole, a snapshot with memory resumed
  with `/tmp` and the uptime kept), encryption at rest
  (the pool and every dataset under it encrypted, records, runs, images and jails on it, the
  key in none of the daemon's files nor its log; the daemon stopped and the pool locked as a
  reboot leaves it: without its key file no API and the reason logged, the file back and it
  starts, a machine of before runs again), exec sessions (`-i` streaming stdin, stderr apart and the
  code; `-it` driven by `hack/exec-tty.py`: a terminal of the size sent, a resize followed, the
  exit code; the client's close hanging up a tty command and killing a piped one; the
  `session_opened` event; a machine with a session open kept awake past its window, asleep once
  it closed), versions and a hand-over (status and the init say the build, `vmm_version` the
  host's; SIGUSR2 then a start: still running, adopted, no second boot; a stop then a start:
  running again unasked, resumed). 184 checks.

- `hack/fleet-smoke.sh`: the same flow through a fleet (`hack/fleet.dev.yaml` fronts the local
  daemon in the VM, a dry-run provisioner for order and retire), an exec session and a tty
  relayed, drain and undrain, and a `host upgrade` of the VM's own host to this build with a
  machine running (back `ready`, a new start of this version that adopted it, the machine
  answering, never booted again). 31 checks.
- `hack/stress.py` with `hack/stress-invariants.sh`: N tenants through every feature in parallel,
  a daemon SIGKILL, then the races (a client that hangs up mid-create, a start against a
  destroy, more starts at once than the host has memory for), host invariants between phases
  (ADR 0010). `--tenants 6 --per-tenant 4 --rounds 2 --crash`.
- `hack/fleet-two-hosts.sh`: a fleet with two hosts: tenants placed on different hosts, calls
  forwarded to each, a host that stops answering marked down with its tenant's calls refused
  (`host_down`) and its listings refused rather than partial, while the other host goes on, and the host back;
  with `SECOND_HOST_SH`, its pool locked while it is down and back encrypted and unlocked with
  the fleet's key, the key on none of its files, in its log or in the fleet's host list. 21 checks.
- `hack/fleet-restore.sh` (from the Mac, `FLEET_SH="limactl shell fc sudo" SECOND_HOST_SH="limactl
  shell fc2 sudo"`): the dev fleet backed up to `file:///var/lib/briqyard-fleet-backup` for the
  run (an identity in `/etc/briqyard/fleet-backup.key` on fc, development only), the backup
  sealed (no key, no token in it), a restore refused over a registry, the registry lost and
  restored `0600` with the same key for fc2, then fc2's pool locked and fc2 back with the key
  of the restored registry; the config and the registry put back. 10 checks.

## Layout

```
crates/briqyard-api      the API types and the host–guest protocol (shared by everything)
crates/briqyardd         the daemon: config, state, zfs, netw (bridges, nft, dns), fc, image,
                         guestc (vsock client), machine (the manager), ingress, api
crates/briqyard-init     PID 1 inside the guest
crates/briqyard          the CLI
crates/briqyard-fleet    the orchestrator across hosts
crates/briqyard-objstore the object store (S3 or a directory), shared by the daemon and the fleet
api/openapi.yaml         the API description, served at /v1/openapi.yaml
hack/                    dev VM, systemd units, dev configs, the shell suites, the stress driver
docs/adr                 every technical decision; docs/research the numbers behind them
```

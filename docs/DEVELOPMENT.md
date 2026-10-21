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

A ZFS pool for the disks. For development, a file-backed one:

```bash
truncate -s 30G /var/lib/briqyard/pool.img
zpool create -o ashift=12 -O compression=lz4 -O atime=off byard /var/lib/briqyard/pool.img
```

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
  SECOND_HOST_START="limactl shell fc2 sudo systemctl start briqyardd" hack/fleet-two-hosts.sh
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
  made from the cache's image, a new size reserved at the start and refused past the host, a
  memory snapshot dropped by what it holds and kept for ports, an image that cannot be pulled
  failing the boot with the change kept, create and PATCH refusing a bad spec in the same
  words). What still needs the host: a tenant's first create (its bridge and
  the DNS listener on the gateway), a volume (`mkfs.ext4`), the jailer, real `zfs send` and
  `receive`, an image pull and its event, the API handlers; those stay with the e2e suite).
- `hack/e2e.sh`: the end-to-end suite against a running daemon: boot, exec, files, DNS,
  egress, tenant isolation, stop and start, exit codes, Postgres on a volume, an endpoint,
  sleep on idle, wake on connect, a fork, suspend and resume, the HTTP ingress, a daemon crash,
  backups to a directory store and a restore, egress policies (`via` a gateway machine, `none`,
  back to `open`), a tenant gateway (a forward proxy its consumer's start boots, HTTPS through
  it and nothing around it, stopped by the sleeper, gone with the tenant), egress limits (port
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
  new image: Python 3.13, the volume's file kept). 124 checks.
- `hack/fleet-smoke.sh`: the same flow through a fleet (`hack/fleet.dev.yaml` fronts the local
  daemon in the VM, a dry-run provisioner for order and retire). 19 checks.
- `hack/stress.py` with `hack/stress-invariants.sh`: N tenants through every feature in parallel,
  a daemon SIGKILL, then the races (a client that hangs up mid-create, a start against a
  destroy, more starts at once than the host has memory for), host invariants between phases
  (ADR 0010). `--tenants 6 --per-tenant 4 --rounds 2 --crash`.
- `hack/fleet-two-hosts.sh`: a fleet with two hosts: tenants placed on different hosts, calls
  forwarded to each, a host that stops answering marked down with its tenant's calls refused
  (`host_down`) and its listings refused rather than partial, while the other host goes on, and the host back. 16 checks.

## Layout

```
crates/briqyard-api     the API types and the host–guest protocol (shared by everything)
crates/briqyardd        the daemon: config, state, zfs, netw (bridges, nft, dns), fc, image,
                        guestc (vsock client), machine (the manager), ingress, api
crates/briqyard-init    PID 1 inside the guest
crates/briqyard         the CLI
crates/briqyard-fleet   the orchestrator across hosts
api/openapi.yaml        the API description, served at /v1/openapi.yaml
hack/                   dev VM, systemd units, dev configs, the shell suites, the stress driver
docs/adr                every technical decision; docs/research the numbers behind them
```

# Development

briqyard is a Rust workspace. The daemon and the init only run on Linux with KVM; the API
types, the CLI and the unit tests build anywhere; the tests of image extraction and of the init
run on Linux only. The init's test that changes users needs root, so it is `#[ignore]`d: CI
runs its test binary as root (`--ignored run_as`, `.github/workflows/ci.yml`); in the VM, the
same step.

Native PR evidence comes from the `native` GitHub Actions workflow on `ubuntu-24.04`
with KVM and a disposable encrypted ZFS pool. Relevant PRs test their exact head, except a draft (marking it ready starts the run);
manual dispatch accepts a ref. Main's `native-cache` job in `ci.yml` writes the build cache these jobs read ([ADR 0108](adr/0108-ci-builds-once-per-cache.md)). The job summaries contain e2e, fleet-smoke, scale, stress, monitoring, two-hosts and restore counts
and durations; the `native-*-log` artifacts contain their complete output. These checks are
not required checks yet. Stress, monitoring, alerts, qualification, restore and scale run on separate runners in parallel. On a PR, `monitoring` and `alerts` run only when a path they read changed (`hack/native-suites.py` holds the list; a release PR and a dispatch run them, [ADR 0110](adr/0110-select-monitoring-suites-by-diff.md)). The qualification suite (`hack/qualify.sh`, [ADR 0095](adr/0095-qualification-batch.md)) kills the daemon, the fleet and the VMMs mid-operation, checks isolation and OOM containment against real attempts, and fills the pool. The alerts suite drives the production Grafana rules to firing and resolved against a local webhook, and the monitoring suite does so for Not answering ([ADR 0094](adr/0094-alerts-fire-and-resolve-in-ci.md)). Monitoring covers a
ready daemon and an explicitly unreachable registered host (18 checks). The two-host job boots
an independent Ubuntu 24.04 QEMU/KVM host (2 vCPUs, 6 GiB), provisions it through the shared
bootstrap and development installer, and runs all 29 two-host and 10 restore checks.
The parallel restore suite emits JSONL results for files, bytecode, both disks,
Postgres, backup chains and interruption. After the existing two-host suites, the
off-host qualification uses a fleet-held source key, destroys its source machine,
stops that daemon and restores the workload on the second host (ADR 0103).
Both restore runs use three independent Postgres rounds. Their final gates require
interruption and off-host results respectively; a skipped required check fails.
`native-two-host-logs` retains both suites, host journals and boot measurements. Manual
dispatch can select `two_hosts_only` for targeted validation
([ADR 0089](adr/0089-native-suites-in-ci.md)), or `suites_only` (for example `qualification`) to run only the named suites of the matrix and skip the other jobs
([ADR 0110](adr/0110-select-monitoring-suites-by-diff.md)).

The `scale` job of the `more-suites` matrix runs `hack/native-ci-scale.sh` on its own runner (9 checks, [ADR 0099](adr/0099-leaf-goes-with-its-vmm.md), [ADR 0109](adr/0109-scale-on-its-own-runner.md)): 6500 idle machine cgroups with no record and 60 of stopped machines, a daemon restart; the daemon must open its barrier, report memory protection healthy, accept a create and retire the leaves in background after serving within 480 s. It runs from the workflow revision, so a manual dispatch with an older `ref` runs it against that source.

## Bootstrap source

Edit `hack/bootstrap/host.sh` (host setup), `runtime.sh` (installation helpers),
or `install.sh` (installation and activation), then regenerate the standalone artifact:

```sh
python3 hack/assemble-bootstrap.py
python3 hack/assemble-bootstrap.py --check
python3 -m unittest discover -s hack -p 'test_bootstrap*.py'
```

Commit `hack/bootstrap-host.sh` with the fragments. The fleet embeds this file;
SSH, join delivery, raw downloads and native suites require no adjacent files.
The test entry point also checks the assembly, so CI and release checks reject stale output.
Preparation tests in the runtime suite cover stalled downloads before host mutation, local-only artifact activation, receipt integrity and replay refusal (ADR 0135).

Suites live in `hack/bootstrap_tests/` ([ADR 0134](adr/0134-bootstrap-source-fragments.md)).

## Scoped execution native proof

On a fresh disposable native CI runner, build the normal native artifacts plus:

```bash
cargo build --release -p briqyard-testing --features scoped-native --bin scoped-execution-native
cargo test --release -p briqyard-fleet --no-run --message-format=json |
  jq -r 'select(.reason == "compiler-artifact" and .target.name == "briqyard-fleet" and .profile.test and .executable != null) | .executable' > target/scoped-native-fleet-test
bash hack/native-ci.sh "$PWD"
bash hack/scoped-execution-native.sh
```

The native workflow runs this proof after its ordinary suites on the same disposable fixture.
`native-ci.sh` supplies the checked bootstrap/development installer.
It installs separate authenticated TLS host and authority listeners, local signing keys,
and distinct role credentials. Two public Alpine guests and a registered namespace gateway
form the discovered closure. Central-signed grant/allocation installation precedes projection
lookup and synchronous scoped guest execution. A counter, duplicate operation and second
scoped read check no replay; a direct authenticated host-status request checks its journal.
Manual dispatch of older refs without this harness skips only the scoped proof. Wrong pins,
wrong roles and a grant omitting the native gateway must refuse. The trap removes the owned
namespace, stops the authority and restores the daemon configuration. It retains the host's
compatibility floor; the runner must be disposable.

The same gate then runs `execution_service::native::renewable_service_callback_host_guest`
from the compiled fleet test binary. The fixture uses the configured production constructor with an injected callback.
An unconfigured production constructor refuses renewable issuance. The callback re-enters the real
Service to observe, protect and install an exact signed continuation while dispatch is open.
A quiet guest reaches its full 60-second timeout across the original allocation window with
one unit per quota bucket. Duplicate continuations and dispatch IDs are status-only. Source
refusal expires the initial lease; active revocation wakes quiet I/O. An ordinary scoped
fixture counter verifies exactly three guest starts. The gate also runs the original
monotonic-activation and completion-owner regression tests. This exercises the generic
callback port; fixed HTTPS callback delivery has separate transport tests.

A second daemon cannot safely share a development VM: startup requires the official unit
identity and host networking uses fixed tables. Do not run this disposable harness against
an owner's development daemon or override its runner check. Linux unit regressions may run
under the shared VM lock without changing the daemon. The disposable gate is still required
before enabling production renewal.

This finite proof does not replace crash/recovery, lifecycle invalidation, concurrent
revocation, streaming/files or the full qualification suite. A compiled harness alone is
not native qualification evidence.

On failure, the scoped fixture emits fixed installation refusal stages and verifier
categories. The collector reads at most 64 KiB and 128 lines per source, ignores
unknown events and fields, and never forwards raw authority or host logs. Authority
and callback diagnostics remain private until the existing cleanup trap removes them.
Run its parser regressions with `python3 hack/test_scoped_execution_diagnostics.py`.


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

Then install the build with `hack/install-dev.sh` (as `hack/vm.sh install` does) and start `briqyardd.service`, and `briqyard status`. The daemon does not start by hand (`sudo briqyardd --config …` stops with the name of the check that failed): its startup barrier (ADR 0068) accepts only the process of the official unit, the `Id`, `ControlGroup`, `FragmentPath`, `MainPID` and command line that systemd reports for `briqyardd.service`, because a host's recovery after a crash must know that nothing else of the daemon's cgroup can still be running.

## On a Mac

Apple silicon M3 or later with macOS 15 or later can run a Linux VM that has `/dev/kvm`:

```bash
brew install lima
limactl start --name=fc --vm-type=vz --nested-virt --cpus=6 --memory=16 --disk=60 template://ubuntu
```

**The VMs are one shared bench.** Every checkout and session on the Mac installs its build into the same daemons, so a suite run while another tree restarts them fails for nothing (or passes against the wrong build). `hack/vm-lock.sh COMMAND` runs the command under one lock, a kernel lock on `/tmp/briqyard-vm.lock` that the system releases when the command ends, however it ends: it waits while another holder runs, saying who. `hack/vm.sh install|restart|stop|e2e|fleet` take it themselves. A suite run by hand, the stress driver, or a change to fc2 goes inside it:

```bash
hack/vm-lock.sh bash -c 'hack/vm.sh install && limactl shell fc bash hack/e2e.sh && limactl shell fc bash hack/fleet-smoke.sh'
hack/vm-lock.sh limactl shell fc python3 hack/stress.py --crash
cat /tmp/briqyard-vm.lock             # who holds it while it is held: pid, tree, since
```

Build and edit outside the lock; hold it only while the VMs run your build, and leave both hosts `ready` with no machines of yours behind.

`hack/vm.sh install` requires `BRIQYARD_CHECKED_BUNDLE` (a local path also visible in the VM)
and `BRIQYARD_CHECKED_BUNDLE_SHA256` (the digest from a trusted release manifest). Use an
official release whose tag resolves to the successful release workflow's source commit;
check the asset digest and architecture-specific `SHA256SUMS` before supplying it. The
helper checks the bundle against the current source pin and reuses bootstrap's complete
provenance, validation and member checks. It stages the bundle beside the four local
binaries and includes all five assets in the local release manifest. It downloads nothing.
A missing or incompatible bundle fails before build or installation.

Fleet smoke requires every registered host to answer: global listings deliberately fail
when a host is down. Starting a provisioned second VM may suffice; first verify its daemon,
registration and empty dedicated fixture state. The suite can place a test machine there,
and temporarily drains other ready hosts during the local host upgrade. Its upgrade
activates the checked Firecracker and jailer plus immutable init paths; repeat lifecycle
validation against those resulting bindings when they differ from the previous run.


fc's pool is on a Lima disk of its own, so a full root disk can no longer suspend it:

```bash
limactl disk create byard-pool --size 40GiB
limactl stop fc
limactl edit fc --set '.additionalDisks = [{"name":"byard-pool","format":false}]'
limactl start fc
```

then, in fc, the pool as above on the disk instead of a file (`zpool create … byard /dev/vdb
< /etc/briqyard/pool.key`). A restart of fc gives it a new SSH host key, and the dev fleet has
the old one pinned for its own host: `hack/vm.sh install` removes that stale `127.0.0.1` line
from `/var/lib/briqyard-fleet/known_hosts`, so the smoke's `host upgrade` pins the new key.

Inside it, follow the Linux steps (Rust, ZFS, Firecracker). The repository is mounted read-only
in the VM at the same path; `hack/vm.sh` builds there, installs the binaries, writes the systemd
unit and restarts the daemon:

```bash
hack/vm.sh install     # build in the VM, install, restart briqyardd
hack/vm.sh logs        # follow the daemon's log
hack/vm.sh e2e         # install, then run hack/e2e.sh inside the VM
```

One target dir per tree in the VM (`$HOME/target-<tree's directory>`, the unit tests' too):
cargo hashes a path package relative to its workspace, so a shared one hands out another
tree's builds. Delete it when the worktree goes.

Everything under nested virtualization is slower than on a real server; the timings are not a
benchmark.

`hack/vm.sh install` also runs `hack/install-mirror.sh` in fc: Zot on `127.0.0.1:7440`, the
registry mirror of ADR 0036, which `hack/config.dev.yaml` names for Docker Hub. Lima forwards
it to the Mac's loopback, which fc2 reaches as `host.lima.internal` (Lima's user network, no
port forward to add), so fc2's `/etc/briqyard/config.yaml` says
`registry_mirrors: {docker.io: "http://host.lima.internal:7440"}`. A host configured before
then: add the line and hand over (`systemctl kill --kill-whom=main --signal=SIGUSR2 briqyardd`,
then `systemctl start briqyardd`); the e2e suite adds it on fc for its mirror section and takes
it out after.

`hack/vm.sh install` also lays out what `hack/fleet-smoke.sh` upgrades the VM's own host to
(ADR 0027): this build's binaries under a release's names in `/var/lib/briqyard-fleet/release`
(`file://` for `--release`), and the fleet's SSH key (`/etc/briqyard/fleet_ssh_key`, made once)
in root's `authorized_keys`, so the fleet runs the bootstrap script on its own VM over SSH. The
version a build says is `<version>+<commit>` of the checkout it was built from (`git` in the VM
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
limactl start --name=fc2 --vm-type=vz --nested-virt --cpus=2 --memory=8 --disk=30 --network=vzNAT template://ubuntu
limactl shell fc2 sudo bash -c 'cd '"$PWD"' && BRIQYARD_POOL_FILE_GB=15 BRIQYARD_TOKEN=fc2-token \
  FLEET_URL=http://192.168.64.1:7430 ADVERTISE=http://192.168.64.1:27420 bash hack/bootstrap-host.sh'
cargo build --release -p briqyard   # the CLI, on the Mac
PATH=target/release:$PATH BRIQYARD_URL=http://127.0.0.1:7430 \
  SECOND_HOST_STOP="limactl shell fc2 sudo systemctl stop briqyardd" \
  SECOND_HOST_START="limactl shell fc2 sudo systemctl start briqyardd" \
  SECOND_HOST_SH="limactl shell fc2 sudo" bash hack/fleet-two-hosts.sh
```

Without the three variables the run is partial: the sections it leaves out are named in the summary
(`NOT A FULL RUN, skipped: …`) and the status is not 0 (`ALLOW_SKIPPED=1` accepts it). A suite that
ends before its last check says `ENDED EARLY` and exits non-zero.

Run it once the fleet lists fc's host empty: right after another suite, the fleet still counts
what fc held, and placement puts the namespaces the other way round. A VM that dies with Lima's
`VirtualMachineStateError` and a `com.apple.Virtualization.VirtualMachine` report in
`~/Library/Logs/DiagnosticReports` (an assertion in the Hypervisor framework's
`VcpuStateManager::set_pstate`) is macOS's nested virtualization failing, not the guest:
`limactl stop fc2 && limactl start fc2`, and the daemon takes its key from the fleet again.

### fc2 as a real host

fc2 has two interfaces (`lima0`, the default route, and `eth0`), so it stands in for an OVH
server when a bootstrap change needs exercising (ADR 0028). Under the lock, fc2's own host
parked first (`systemctl stop briqyardd`, `zpool export byard`, its empty mountpoints under
`/byard` removed, which `zpool create` will not mount over, `/var/lib/briqyard` and
`/etc/briqyard` moved aside), as root on fc2:

```bash
truncate -s 14G /srv/byt/disk0.img; truncate -s 12G /srv/byt/disk1.img
D0=$(losetup -fP --show /srv/byt/disk0.img); D1=$(losetup -fP --show /srv/byt/disk1.img)
sgdisk -n 1:0:+2G "$D0"; partx -u "$D0"; mkfs.ext4 -q "${D0}p1"; mount "${D0}p1" /mnt/byt-os   # the "OS"
ip link add byvrack0 type dummy && ip link set byvrack0 up                                  # the "vRack"
ssh-keygen -q -t ed25519 -N '' -f /etc/byt-fleet/key && cat /etc/byt-fleet/key.pub >> /root/.ssh/authorized_keys
ln -sfn "$PWD/bin" /root/bin       # the binaries hack/vm.sh built, copied out of fc's target-<tree>
```

A fleet on fc2 itself (`listen: 0.0.0.0:7431` and `tls: off`, the token alone as in `hack/fleet.dev.yaml`: on loopback with no proxy in front, every host call would be refused for want of a caller address; `bootstrap`: `enabled`, `ssh_key:
/etc/byt-fleet/key`, `pool_device: $D0,$D1`, `fleet_url: http://127.0.0.1:7431`,
`private_network: 10.99.0.0/24`, `private_interface: byvrack0`, `allowed_clients`), then
`briqyard host add 192.168.64.2 --address 10.99.0.2`: the fleet bootstraps fc2 over SSH as it
would an OVH server (the free space of `$D0` mirrored with `$D1`, `10.99.0.2` on `byvrack0`,
`lima0` closed but for SSH, both keys pinned), and `hack/e2e.sh` runs on fc2 against
`https://10.99.0.2:7420` with the token and the fingerprint, with `backup.store` and at most
`capacity.memory_mb: 4096` added (fc2 has 6 GB and no swap: more overcommit hangs it). Undo it all after (the firewall
unit and table, the netplan file, the dummy, the pool, the loops, the ARC cap), and put fc2's
host back (`zpool import -d /var/lib/briqyard byard`).

An edge beside it (ADR 0028) is exercised the same way: `hack/bootstrap-host.sh` run on fc2
directly (a file pool, `PRIVATE_ADDRESS` on `byvrack0`, `PUBLIC_TCP_PORTS` the edge's), then
the edge's own bootstrap with dummy secrets, its image built on the Mac and copied in
(`docker save`, `limactl copy`), started with a certificate from a file and a static endpoint
on the host's ingress, and `hack/e2e.sh` on `https://10.99.0.2:7420` beside it. Undo it as above,
plus `apt-get purge docker.io` and the edge's files.

## In a briq kvm sandbox

The suites run in a `kvm-sandbox` briq (`xlarge`: 8 vCPUs, 16 GB, 40 GB at `/work`) on an x86_64 host that serves the `nested` class (ADR 0088). No Lima, no Mac. In the sandbox, as root:

```bash
cd /work
git clone --depth 1 https://github.com/briq-cloud/briqyard src
cp src/hack/native-ci-nested-inner.sh inner.sh
B=https://github.com/briq-cloud/briqyard/releases/download/v0.1.21
curl -fsSL "$B/SHA256SUMS-x86_64" -o sums
curl -fsSL "$B/firecracker-checked-linux-x86_64.tar.gz" -o fc-bundle.tgz
D=$(awk '$2 == "firecracker-checked-linux-x86_64.tar.gz" {print $1}' sums)
echo "$D  fc-bundle.tgz" | sha256sum -c -
echo "BUNDLE_SHA256=$D" > inner.env
```

Then one stage at a time, detached, so that a command's own limit does not end it. Each leaves `/work/logs/STAGE.log` and `/work/logs/STAGE.rc`:

```bash
setsid bash /work/inner.sh run build > /dev/null 2>&1 < /dev/null &
```

| Stage | What it does | Result, 2026-11-05, source `1d3e76c7`, AMD EPYC, one level of nesting, to within 15 s |
|---|---|---|
| `build` | release workspace and the musl init | 95 s, from nothing |
| `systemd` | systemd as PID 1 of namespaces of its own, for the units and the startup barrier (ADR 0068) | 15 s |
| `host` | `hack/bootstrap-host.sh`, `hack/install-dev.sh`, `briqyardd` under its unit | 15 s |
| `fleet` | `hack/fleet-smoke.sh` | 33 passed, 61 s |
| `cargotest` | `cargo test --workspace` and the init's root tests | 1434 passed, 197 s |
| `e2e` | `hack/e2e.sh` | 294 passed, 561 s |

`hack/native-ci-more.sh stress` passed 635 of 635 checks with no invariant break in 501 s, `alerts` 45 checks in 880 s and `qualification` 134 in 611 s; `monitoring` passed its 18 and 9 checks in 455 s at 4 vCPUs on 2026-11-04. Run them inside the namespaces with `nsenter -t "$(cat /work/logs/systemd.pid)" -a`, with `capacity` raised to `memory_mb: 12288, vcpus: 24` as in `hack/native-ci.sh`, `RUNNER_ENVIRONMENT=github-hosted` for the script's guard, and each on a fresh host: `monitoring` leaves a second host in `fleet.yaml`. `fleet-two-hosts` and `fleet-restore` need a second host: they stay on `fc` and `fc2` and on the hosted two-hosts job.

- **Not on a hosted runner:** the `native nested` workflow adds a level of virtualization. There a guest took 17 s to start and `e2e` stopped after an hour at 262 ok, 4 failed. It rehearses the install path, by hand; it is not the acceptance.
- **A guest boots cold every time:** a machine of the class has no memory snapshot, so the sandbox's own sleep ends its daemons and guests.
- **`/` is shared in the namespaces:** systemd leaves it private in a container. A sandboxed unit (the mirror) would then keep a copy of a machine's mount, and its destroy answers `dataset is busy`.

## Tests

Every test and suite ends what it starts, however it ends (ADR 0049):

| | On a failure, a panic, a timeout, Ctrl-C or a killed parent |
|---|---|
| a test binary | exits within a second of its parent (`cargo test` killed), and after 6 minutes at most (`briqyard-testing`, installed in each crate) |
| the fake `zfs`, `udevadm`, `zvol_id` | a held one ends with its test (its hold goes with the temp dir) or its parent (`kill -0 "$PPID"`) |
| the stand-in servers | the CLI's and fleet's test clients time out after 10 s; the Firecracker and vsock stand-ins give up after 10 s |
| each shell suite | one trap on EXIT, INT, TERM, HUP: ends the shell's children by pid (`pkill -P $$`: sessions, watches, `logs -f`, their `sleep 600`), starts again a daemon it stopped (fc's, fc2's), undrains the hosts it drained, puts back the config, key and registry it moved, destroys its machines and namespaces |
| `hack/stress.py` | SIGTERM and SIGHUP as Ctrl-C; a `finally` destroys what a failed or interrupted round left |

- `cargo test --workspace`: unit tests, which run anywhere (extraction and whiteouts on Linux, DNS
  packets, the guest protocol, address allocation, the store, the configuration, the ZFS
  backend against a fake `zfs`, `udevadm` and `zvol_id` (a device per volume through renames;
  links udev left wrong, or never made, mended; a wedged udev ending the wait on time; a command
  running past its time stalled; ADR 0046), the Firecracker and guest clients against in-test
  sockets,
  the config drive, restart and sleep decisions, and the manager's transitions through a
  harness over a temp directory, the same fake `zfs` and a mock host (`Vmm`, `Guest`,
  `Net`; ADR 0010): create to running, boot failures, start against destroy, starts past
  capacity, stop and suspend, a caller that hangs up, crash recovery, the orphan sweep,
  the sleeper's tick, the init's exit report and its reason for a program it could not start,
  fork snapshots freed, a machine moved into another namespace (a rename with the address kept,
  a join with a new address and moved counters, a refusal changing nothing, a rename cut short)
  and a fork into one, backups (the schedule due
  and not before, at most `at_once`, one per machine, a machine with no process skipped while
  unchanged, retention and its restores, delete and `chain`, a failure and its backoff, a
  refused store leaving nothing, a destroyed machine's held, counted and expired, a backup racing
  a destroy answered 404), the namespace's gateway
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
  torn line, retention counting lines, a watch's backlog, lag, bookmark and shutdown; repeats
  folded (ADR 0047): a use's at its window's end, a change logging them first, a namespace's
  refusal, the shutdown's, flips taking a seq with no line and the last line the machine's
  state, a due flip leaving uses in their window, a cursor in a gap after retention; a flapping
  readiness probe whose version is on disk once readable, a stale `If-Match` refused, the
  tick's line its version, the tick leaving a machine in a transition alone and never writing
  a destroyed record back), metrics and
  conditions (the exposition of machines in every state checked line by line and against the
  format, the daemon's resident memory read, no probe per scrape, conditions turning true and
  clearing with their events, a stuck
  `zfs` command as `storage_stalled` until it exits, a pool
  that cannot be read, image removal under disk pressure oldest unused first, `top` from two
  ticks, the console rotated while two tasks write with no line lost, logs across the rotated
  file, placement and creates refused on a host under pressure), the ingress closing a removed
  endpoint's listener after it missed the event and opening none for one already gone, probes (readiness and
  its events, `/wait` for ready and its `not_ready`, a startup failure that fails the boot and
  one that is a crash, liveness under `on-failure` and `no`, the backoff, its reset and
  `crash_loop`, the ingress waiting for a woken machine, the host's turns, a PATCH on a running
  machine, the gateway waited for ready, an adopted machine, adopted machines' first probes
  spread over their period on a paused clock, a slow probe keeping its period; the HTTP client
  and the TCP connect against loopback servers), changes at the next boot (a PATCH on a running machine
  left pending with its events and `If-Match`, applied by a restart into the config drive, a
  new image's root disk cloned again with the volume untouched and a fork promoted, the root
  made from the cache's image and only once no backup runs, a promoted fork backed up whole
  despite its source's snapshots, a new size reserved at the start and refused past the host, a
  memory snapshot dropped by what it holds and kept for ports, an image that cannot be pulled
  failing the boot with the change kept, create and PATCH refusing a bad spec in the same
  words), labels, quotas and logs follow (a listing by labels, the quota at create, fork,
  start and the gateway with its message and event, its use; a follow from the start and
  from a cursor, across rotations, ending at the destroy, its heartbeat and shutdown;
  placement by region and the cross-region refusal through stub hosts in two regions), join tokens (reuse and its count, calls at once all counted, expiry and `ttl 0`, revoke, one answer for every refusal, only the address the call came from, the certificate pinned at the first heartbeat, no secret in the registry file or a listing; ADR 0059), disk
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
  new image dropping the snapshots' root halves; a wake during a stop; a restore booting the new
  disk when udev dropped every event), the
  pool's key (an unencrypted pool refused, a loaded key left alone, loaded from a file and from
  a stub fleet as the host, each failed try saying why without the key, the wait ended by a
  stop; `load-key` with the key on stdin; a filesystem never mounted over files; the fleet's
  key route: made at the first ask, the same after, one per host, refused to any other token
  or address, written `0600` before it is answered, in no listing, no longer the host's once
  it is forgotten but kept for its backups, served by its id to the host a restore was forwarded to, once, for that restore
  only, refused to another host, past its deadline, with no restore open and for an unknown id
  (ADR 0035), a host's own by its id at any ask, by the fleet and from the daemon's source
  (ADR 0045); a backup refused under a key that is not the pool's; a backup raw under its key's id with its record sealed (the env in
  no object, a sealed spec that does not open moved to another record), a restore opening it
  with the key of that id and giving its disks the pool's, the key file's own or the fleet's,
  refused with no fleet to ask; a backup in clear restored with no key, the next one whole; a
  registry's backup: written sealed and only on a change, read back with its identity and no
  other, a key served only once the store holds it; a
  registry that does not parse refused, never read as empty, and fields it does not know
  written back; a host call from another address than its record's refused unless behind
  `tls: off`; a key whose write failed taken back, never served; a keyed host forgotten only by
  force; a drained host never forgotten, a retiring one once empty; the registry written by
  300 writers at once, every read of the file parsing and the last write holding every change,
  64 creates at once all in it, a machine the host made answered when the write after it fails
  (ADR 0043); a create's hold given back when the host refuses and when its caller hangs up,
  kept through a report before its answer and dropped by one after, a destroy's room back at
  its answer (ADR 0044); a
  destroyed machine's backup deleted on the host that holds it, a namespace's backups listed from
  every host (ADR 0045); a delete with a query dropping the index entry), upgrades (the init's and
  the VMM's versions recorded at boot, a snapshot of another VMM booted cold, a hand-over that
  waits for a stop to settle, touches no machine and lets no transition begin, the adoption
  after it with `gone` apart from `stopped`, the daemon's start booting again what the host
  stopped within its window, a record keeping a newer daemon's fields, an old init's unknown op
  named, old and new wire shapes decoding, the fleet's refusals, its wait for a new start and
  its end states, drain apart from retire), capacity signals (ADR 0042: each refusal counted by
  what ran out and its region, hosts under a condition named by it, a pinned namespace's host
  under pressure, a region no host is in; the room of the hosts that take a namespace, drained,
  down and pressured ones left out; the fleet's `/metrics` against the format, and its
  token). What still needs the host: a namespace's first create (its bridge and
  the DNS listener on the gateway), a volume (`mkfs.ext4`), the jailer, real `zfs send` and
  `receive`, an image pull and its event, the API handlers; those stay with the e2e suite).
- `hack/e2e.sh`: the end-to-end suite against a running daemon: boot, exec, raw files above the JSON/frame bounds, atomic file replacement and safe paths, a create
  answered at once (ADR 0048: 201 `creating`, running after its pull, `pulling` then `created`,
  sent again a 409 with the first, an image on the host, a pull that fails `pull_failed`), image
  layers (busybox's hard links, Debian's merged `/usr`), an image's user with a supplementary
  group (running, its uid, gid and groups), a program that cannot start (its `/wait` 409
  `boot_failed` with the init's reason), DNS,
  egress, namespace isolation, stop and start, exit codes, Postgres on a volume, an endpoint,
  sleep on idle, wake on connect, a fork, suspend and resume, the HTTP ingress (two `Host` lines
  refused, an absolute-form target routed by its authority and refused when `Host` names
  another), a daemon crash,
  backups to a directory store and a restore, egress policies (`via` a gateway machine, `none`,
  back to `open`), a namespace gateway (a forward proxy its consumer's start boots, HTTPS through
  it and nothing around it, stopped by the sleeper, gone with the namespace), iron-proxy as a namespace
  gateway (a stock image with its config and CA as boot files: a header injected and a proxy
  token swapped on the way to a sibling's HTTPS echo, a request without the token and a host off
  its list refused, no secret in the consumer), egress limits (port
  25 refused at once while 443 connects, 6 connections a minute then the 7th dropped, lifted
  live, drops shown, a download capped at 2 Mbit/s), usage (running seconds, internet and
  ingress bytes, a stopped machine's disk hours), events (a watch from before a stop gets it,
  a stale `If-Match` refused, `describe`, the reasons in order, a cursor past the log
  refused, a quiet watch's bookmark past its cursor), metrics (a running machine's CPU and state series, `top` lists it with rates after
  two ticks, no condition true on a healthy host), probes (an HTTP readiness probe: not ready, then
  ready and its event, `wait`; an exec liveness probe that fails: `liveness_failed`, restarted,
  running again; a readiness probe flipping every 2 s: two lines, the version past them, the
  destroy logging the folded flips with their count), backups on a schedule (every second backup whole and a kept one's base kept,
  a base not deleted alone, the oldest kept restored from its chain, retention down to 2, its
  event, a destroyed machine's backups listed then deleted with their chain), changes at the
  next boot (env and a boot file set on a running Python server: pending, still the old values; `machine restart`: the new values and `applied`; a
  new image: Python 3.13, the volume's file kept), labels, a quota and a follow (`ls -l` selecting one machine, a
  refused selector, a second create refused 403 `quota` with its use and event, `logs -f`
  receiving a line printed after it began and ending at the destroy; the app and runtime views, ADR 0115, and a page of the newest lines with its cursor to the one before, ADR 0116: 6 checks), disk limits (a machine's
  own over the host's for 2 vCPUs; at 4 MB/s, 32 MiB written to the volume in 5 s or more and
  16 MiB read from the root disk in 2 s or more, with O_DIRECT; `cpu.weight` 200; lifted live;
  set while suspended and in force after the resume; throttling on `/metrics`), host ports (on
  the host, when its config lists `network.host_ports`: one reached from a machine with egress,
  dropped for `none` and `via`, the API dropped), snapshots (files on the volume and the root
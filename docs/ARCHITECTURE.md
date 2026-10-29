# briqyard architecture

briqyard runs services for AI agents in Firecracker microVMs on servers you own: any OCI image,
a durable disk, a private network per tenant, sleep when idle and wake on the next use. One
daemon per server (`briqyardd`), an orchestrator across servers (`briqyard-fleet`), a CLI
(`briqyard`) and an init that runs inside every microVM (`briqyard-init`). Rust, one workspace;
the init is a static binary (musl) because the guest has no shared libraries of ours.

Status: v0, in development. The API is not stable yet.

## One server

```
                 HTTP API (:7420)                     TCP / HTTP ingress (:30000-32767, :8080)
                        │                                          │
 ┌──────────────────────┴──────────────────────────────────────────┴─────────────────────┐
 │ briqyardd (root)                                                                        │
 │                                                                                         │
 │  machine manager ── storage (ZFS) ── network (bridge per tenant, TAP per VM, nft, DNS)  │
 │        │                                                                                │
 │  firecracker process per machine ─ serial log ─ vsock to and from briqyard-init         │
 └─────────────────────────────────────────────────────────────────────────────────────────┘
          │ bt<id> (TAP)          │ zvol root (clone of image)   │ zvol data (the volume)
    ┌─────┴──────────────────────┴──────────────────────────────┴───────┐
    │ microVM: guest kernel + briqyard-init (PID 1) → the image's command │
    └─────────────────────────────────────────────────────────────────────┘
```

### Machines

A machine is one microVM running one OCI image. `POST /v1/machines` takes the
image, command, environment, boot files, size (vCPUs, memory), an optional data volume and its
mount path, the ports the image listens on, and the sleep window. The daemon:

1. pulls the image and turns it into a root disk, once per image digest (`image` package);
2. clones that root disk for the machine (ZFS clone: instant, copy-on-write);
3. makes the data volume (a ZFS zvol with an ext4 filesystem), when asked;
4. gives the machine an address on its tenant's bridge and a TAP device;
5. writes a config drive (a tar archive, read raw by the init: `config.json`, the boot files);
6. starts Firecracker with the kernel, the three drives, the TAP and a vsock, and watches it.

States: `created` → `starting` → `running` → `stopping` → `stopped` → (`starting` again) …
→ `destroying` → gone. A `stopped` machine keeps both disks. `stopped_reason` says why it
stopped: `user`, `idle` (went to sleep), `exit` (its process ended; `exit` says how), `host`
(the daemon stopped it: a shutdown, or a leftover of a crashed daemon; the next daemon start
boots it again unless its sleep window ran out, and it is wakeable like `idle`).
`state_changed_at` moves only with `state`; `updated_at` with every change to the machine (a
state, a setting), never with a use: `last_used_at` is kept in memory and reaches the record
with the next change or the sleeper's tick, so a busy machine does not rewrite its record on
every connection. The record on disk says what the machine is, not when it was last touched.

A boot the guest does not survive (the image's fault: no init to run, a command the init
cannot start) leaves the machine in `error` with the console's last lines, and the request answers
409 `boot_failed` with the machine in the body; nothing restarts it, the caller reads and
destroys it. The host's own faults answer 500. Every transition (create, start, stop, destroy,
backup) runs in a task of its own that the request only waits on: a client that hangs up
never leaves a machine half-moved (ADR 0011). One lock per machine orders its transitions;
a start takes the host's memory and moves to `starting` in one step under the machines map's
lock, so starts that race never oversubscribe it; a destroy holds the machine's lock from the
state check to the record's removal and, when it fails, is tried again every 15 s. Every write
of a record checks, under the lock the destroy deletes it under, that the machine is still
there: a call that took the machine before its destroy and went on after it writes nothing
back. A destroy tried again that finds no disks holds the backups the store lists, not those
the record names; a store that has not listed them within 30 s fails it, for the next tick.

A PATCH of what a machine runs (`image`, `entrypoint`, `cmd`, `env`, `files`, `size`, `ports`,
`restart`; ADR 0024), checked by the same `SpecChange::check` as a create, is kept as `pending`
and applied at the next start, never to a running process: a start or wake after a stop, a
restart by the policy, or `POST /restart`. A new image is pulled and built before anything
moves (a failure is `boot_failed`, the change kept); the change goes onto the record in the
step that reserves the memory, so a new size is reserved there (`capacity` past the host);
then a new image's root disk is cloned again from its `@base` (forks of the old one promoted,
as at a destroy) and the boot reads the record. The data volume is never touched. A change to
anything a memory snapshot holds (all but `ports` and `restart`) makes that start cold.
`updated` (`pending: true`) marks the PATCH, `applied` the start. A larger `volume` (ADR 0040) is
the exception that moves at once: its zvol grows at the PATCH (the quota and the pool checked,
never smaller), the record with it, and it is `pending` until the next boot, cold, where the
init grows the ext4 filesystem online.

### Probes and restarts

A machine may have a startup, a readiness and a liveness probe (ADR 0022, `machine/probes.rs`),
Kubernetes's: `exec` through the guest's init, `tcp` and `http` from the host to the machine's
address. One task per running machine with probes, ended with its process; 32 executions at
once per host. Each probe runs on a fixed period, a slow run skipping the ticks it ran over;
while the daemon is younger than a probe's period, its first run is at a random point of one
period after its initial delay, so a start that adopts every machine does not probe them all at
once (ADR 0047). Startup runs first and gates the others; `ready` is true at `running` without a
startup or readiness probe, else when they pass; liveness failures end the process as a failure
for the restart policy. A startup failure on a run a caller asked for is a failed boot (`error`,
ADR 0011); on a run the policy started, a crash. `/wait` waits for `ready` (`?for=running`
otherwise), and so do the ingress before it proxies and a start that needs the tenant's gateway
when the gateway has probes. Create and start answer at `running`. A restart waits 10 s,
doubling to 5 minutes, reset by a run of 10 minutes; `restarting_at` says when, and the third
in a row is a `crash_loop` event. Probes are not use: they never keep a machine awake.

### Disks

Every disk is a ZFS zvol in one pool (`byard` by default; on a real host a mirror of the free
space of its two NVMe disks, the OS on a small RAID 1 beside it, ADR 0028), encrypted from its
creation with the host's key (ADR 0026), and everything the daemon writes about a machine is
on it:

| Dataset | What |
|---|---|
| `byard/images/<digest>` | A root disk built from an image, with a `@base` snapshot |
| `byard/m/<id>/root` | The machine's root disk, a clone of `@base` |
| `byard/m/<id>/data` | The machine's data volume, when it has one |
| `byard/m/<id>/root.<n>`, `data.<n>` | A disk a restore retired, while a newer snapshot or a fork needs it |
| `byard/jail` | A filesystem mounted at `jail_dir`: the chroots and the memory snapshots |
| `byard/images` | A filesystem mounted at `<data_dir>/images`: the images' metadata and extraction scratch |
| `byard/state`, `byard/run` | Filesystems mounted at `<data_dir>/state` (records, events, usage) and `<data_dir>/run` (config drives, consoles) |

After a reboot the pool's key is not loaded: the daemon loads it (`zfs load-key`, the key on
stdin) before it reads or mounts anything, from `storage.key`: the fleet, which keeps one key
per host in its registry and serves it to that host alone, or a file on a single host. Until it
has the key the daemon serves nothing and says why in its log. A dataset is never mounted
over files. Hosts run without swap, and a Firecracker never dumps core.

A disk's device is `/dev/zdN`, never udev's link: ZFS renames and removes devices after `zfs`
returned and udev can drop the event that moves a link, so the daemon takes the device the link
names only once `zvol_id` says it is that disk, and sends a change event for a device whose link
is wrong. A rename waits for the kernel to rename the device, then for its link (ADR 0046).

The root disk outlives restarts and stops. Boot files are rewritten at every cold
start from the config drive, so an edit inside the machine lasts until then. The data volume is
attached with Firecracker's `Writeback` cache mode, so a guest `fsync` reaches the host's disk:
a database on it is as safe as the host's drive. Both disks the guest writes take its discards,
and both are mounted with `discard` (the root by the kernel, the volume by the init): what a guest
deletes goes back to the pool, unless a snapshot still holds it (ADR 0037). A fork is a clone of a snapshot of both disks,
taken while the source runs (crash-consistent for the data volume). That snapshot (`@fork-<id>`
on the source) pins every block the source has since rewritten, so it goes with the last machine
cloned from it.

### Snapshots and restore

`POST /machines/{id}/snapshots` snapshots both disks in one `zfs snapshot` (ADR 0031); the record
lists it, with an optional name (`before-migration`) that finds it again. `POST
.../snapshots/{snap}/restore` takes the disks back to it: under the machine's backup turn and
lock, a running machine is stopped, then each disk is swapped for a clone of its snapshot
(`clone`, the disk renamed aside to `<disk>.<n>`, the clone renamed into place, `promote` until
its origin is outside the machine), and the machine boots again; any other stays as it is. The
disk in use owns its whole history, so the next backup's base (its newest `bk-*`) is always an
ancestor of what it holds. The disk it replaced is retired: it keeps the snapshots newer than the
one restored and whatever clones them (a fork), and `tidy` (after a restore, a deletion, a fork's
destroy, a new root disk, the daemon's start) removes it once neither is left, with any snapshot
nothing names or clones. `memory: true` also keeps a running machine's memory (paused, written by
Firecracker, the disks flushed and snapshotted, resumed, then the files synced, ADR 0037): a restore of it resumes the processes
where they were, while the machine's spec is the one it was taken with. A restore writes its
intent first; one cut short is finished by the next restore, start or daemon start. A new image's
root disk (ADR 0024) is the same swap, from the image's `@base`.

Each disk the guest writes (the root disk and the volume) has Firecracker's rate limiter
(ADR 0030): MB a second and requests a second, by default a rate per vCPU of the machine's size
(`disk_limits` in the config), a machine's own `disk_limits` over it; a burst of `burst_sec` at
those rates once per start. Given at boot, set again after a resume (the snapshot holds the old
run's), changed on a running machine by `PATCH /drives` at once. Firecracker's metrics come
through a pipe in the jail, a line a minute: disk bytes and throttled requests per machine on
`/metrics`. CPU is bounded by the jail's cgroup: `cpu.max` at the machine's vCPUs, `cpu.weight`
100 per vCPU, so a host short of CPU shares it by size.

The root disk is not mounted by the host, ever: the host writes nothing into guest filesystems.
Image extraction happens once per image into a directory the host controls: layers in manifest
order, whiteouts applied, every path resolved inside the directory by the kernel (`openat2` with
`RESOLVE_IN_ROOT` from the directory held open, then `*at` writes, ADR 0039: a symlink in a layer
never leads outside, and the last component is never followed, so a rewritten link replaces the
link rather than its target), devices skipped; then `mkfs.ext4 -d` builds the disk.

A tag is resolved by its registry (a `HEAD`, remembered 10 minutes, ADR 0009); the content is
then pulled by that digest, from the registry's mirror first when `registry_mirrors` names one
(Zot, one per region, ADR 0036) and from the registry when the mirror fails. Every manifest and
blob is checked against its digest, so a mirror can fail a pull, never change what it runs.

### Network

One Linux bridge per tenant (`by<n>`), one /24 from `10.64.0.0/10` per tenant, the host as
gateway (`.1`), one TAP per machine (`bt` + the machine id's 12 hex digits). nftables, two tables
rendered at start (`nft list table inet briqyard`, `nft list table bridge briqyard`, ADR 0012):
the forward chain drops by default and accepts only a tenant's way to the internet through the
egress interface, never to a private network, another tenant or in IPv6; the input chain lets a
tenant reach its gateway's DNS and ping and nothing else of the host, and lets only
`ingress.allowed_clients` reach the API, the HTTP ingress and the TCP endpoints; a `bridge`
family chain pins every TAP to its machine's address (IP and ARP), so a guest that changes its
address sends nothing. A machine start adds its pin, a stop removes it; a tenant changes no rule.
The daemon answers DNS on every gateway: `<alias>.internal` follows the machine's alias (what a sibling's
env holds), `<id>.vm.internal` is that exact machine; everything else is forwarded upstream.
Packets are decoded and encoded by `hickory-proto` (ADR 0033); one that does not parse is dropped.
The guest configures its interface from the config drive (`briqyard-init`), so the guest kernel
needs no `ip=` support.

Each machine has an egress policy (`egress` on create and PATCH, ADR 0015): `open` (the
default), `none` (its tenant, no internet: `egress_none` in the inet forward chain) or
`via: <machine>` (only that sibling, any port, and the gateway's DNS: `via_sources` and
`via_allowed` in the bridge chain, IP and ARP, before the pins). Under `via` and `none` the
resolver answers internal names only, NXDOMAIN for the rest. An `open` machine's policy is its
limits on internet traffic (`limits`, ADR 0018: blocked ports, new connections a minute, Mbit/s;
the host's `egress_limits` under the machine's own): `blocked_ports` (address . port, TCP reset,
UDP unreachable), and a named `limit` per rate found through `conn_limits` and
`bandwidth_limits`, in the inet forward chain before the reply accept and the internet counters;
three counter sets count what they drop. The policy is set at every start
right after the pin, taken out with it, swapped live on a running machine in one transaction, and rendered from
the running records at daemon start.

A tenant may have a gateway (ADR 0016): `PUT /v1/tenants/{id}/gateway` (an image, its command,
env and boot files, a port) makes a machine of the daemon (`role: gateway` on its record) on the tenant's bridge, named `gateway.internal`, absent
from the tenant's listing and counts, destroyed with the tenant. `via: gateway` names it. A
start of such a machine (a wake too) first starts the gateway and waits for its port, under the
tenant's lock, held until the machine is `starting`; the sleeper stops the gateway once no such
machine runs or starts. A gateway that does not come up fails that start with `boot_failed`,
the machine unmoved, the gateway's reason and console in its `error`. Its program is restarted
whenever it ends on its own (`restart: always`), and a daemon start that adopts a machine
needing it starts it again. The PUT's `start` runs it before anything needs it (a program that
makes its CA on first boot). The machine routes read it (GET, logs, stats) and refuse the rest
with 409 `gateway`: one resolver, `own_entry`, for every call that changes or runs something.

No machine has a public address. Something outside reaches a port through the ingress, which is
how sleep works: a connection to a sleeping machine's endpoint starts it, waits for the port and
then proxies. Two kinds of endpoints: a TCP port on the host (Postgres, Redis), and an HTTP host
name on the shared HTTP port (`<endpoint>.<domain>`), both allocated by the API. The HTTP
port reads the first request head with `httparse` and routes by its one `Host` (ADR 0033).

### Inside the microVM

`briqyard-init` is PID 1. It mounts `/proc`, `/sys`, `/dev` (plus `/dev/fd` and friends, which
bash's `<(...)` needs), reads the config drive (`/dev/vdb`, a tar stream), mounts the data
volume (`/dev/vdc`) at its mount path (a fresh one gets the image directory's owner and content
and loses `lost+found`, so a database accepts it; a grown one's filesystem is grown to the disk,
`EXT4_IOC_RESIZE_FS`), writes the boot files, sets the hostname,
`/etc/hosts` and `/etc/resolv.conf`, configures `eth0` over netlink, then runs the image's
entrypoint and command with its environment and user. It listens on vsock port 7421 for the
host: `exec` (a command with stdin, streamed stdout and stderr, exit code, timeout; on a
terminal of its own with `tty`, its input as frames after the request, the host's close ending
it, ADR 0029), `put` and
`get` (files), `ping`, `shutdown`. PID 1 inherits every orphan on the system; the init reaps
them with `waitid(WNOWAIT)` and leaves alone the children it waits for itself, so a command's
exit status is never stolen. When the main process exits, the init connects out to the host
(vsock port 7422, which Firecracker brings to the daemon as `<vsock socket>_7422`), sends one
`ExitReport` frame (code, oom, requested; with a program it could not start, its reason), waits for the daemon's close, and resets the machine,
which ends Firecracker; the daemon settles the machine from the report and applies the restart
policy (ADR 0004). The `[briqyard] exit …` line on the serial console is a trace for a person;
nothing reads it, so nothing a guest prints can set its exit.

### Backups

A backup is a ZFS snapshot of each disk streamed to an object store (`briqyard-objstore` on
Apache Arrow's `object_store`: S3 or a directory, ADR 0034), incremental after the first; the
record beside it holds the machine's spec, so a restore is a create that receives the chain of
streams into fresh datasets on any host that reaches the store. Local snapshots stay only as the base of the next incremental send.

A machine's `backup: {every, keep}` is run by the daemon (ADR 0023, `machine/backups.rs`):
the tick starts each due backup detached, through a semaphore (`backup.at_once`), and every
backup or deletion of a machine's backups takes the machine's turn, so one runs at a time. A
backup is whole every `keep`-th, else from the last one's snapshot when that backup is in the
store; after it, retention deletes whole chains: whatever is neither among the newest `keep`
nor a base of one. A destroy hands the backups and the turn to a holder (`state/holders/`),
which lists them, meters them into the machine's usage buckets, and deletes them
`keep_destroyed_days` later.

### Usage

The daemon measures what each machine uses, per UTC hour, and never prices it (ADR 0017,
`usage.rs`). Each machine has a meter: time in its state is accrued at every state change and
every tick, split at the hour (running is `starting` to `stopping`; suspended is stopped with a
memory snapshot); the tick (15 s) adds what its counters grew by, a smaller value counting as
a counter begun again. The sources: the cgroup's `cpu.stat`; one `zfs list` of the pool for
allocated sizes, used bytes and snapshots, plus the memory snapshot files; the record's
`backup_bytes`, what its backups in the store take, set at each backup and deletion (a
destroyed machine's holder carries it on); two counter sets in the inet table (`internet_out`,
`internet_in`, an element per machine address for the machine's life, matched in the forward
chain on the egress interface); and the ingress proxy, which adds the bytes it passes as they
pass. The open hours live in memory, written to `state/usage/<hour>.json` once a minute and at
the hour's close; a closed hour is never written again (what a late meter brings for it lands
in the open hour), and a destroyed machine's buckets stay. `GET /v1/usage` answers a range of
at most 31 days; the fleet asks every host and fails whole.

### Events and versions

Each host keeps one event log (ADR 0019, `events.rs`): a JSON line per event in
`state/events/<hour>.ndjson`, appended and synced under the log's lock, then sent to watchers.
`seq` counts one more per event and never goes back: at start it goes on from the larger of the
log's last line and every record's version. A state change says what happened through
`Entry::set_state`, whose closure returns the event; the other facts (a create, a restart, a
PATCH, a backup, a destroy, the gateway serving or put to sleep, an image pull, the daemon's
start, an adoption) are logged where they happen. The seq of the last event about a machine is
its `version`; `PATCH`, `DELETE`, `start`, `stop`, `wake` and `restart` take `If-Match` and answer 409
`conflict` with the machine when it moved. `GET /v1/events` reads from a cursor (`since`, 410
`gone` when it is pruned or past the log); `watch=true` subscribes, sends the backlog, then each
new event as NDJSON with a bookmark (`{"bookmark": seq}`, the last seq it looked at) every 30 s
of quiet, and closes a watcher that falls 1,024 events behind. Repeats of `session_opened`,
`quota_exceeded`, `ready` and `not_ready` within 10 minutes of their line are folded (ADR 0047):
the log keeps the first and, at the window's end (the tick, the next one, any other line about
the machine, the shutdown), one line with `count` and `first_at`; a folded flip still takes a
seq, its machine's version, with no line. Retention is `events_keep_days` and 100,000 lines. The fleet sends a tenant's or a machine's
read to its host and merges a read of every host, never partial, with a cursor per host.

### Metrics and conditions

The tick's measure is also what the host shows (ADR 0021): each machine's meter keeps its
counters' totals since the daemon started, the cgroup's memory and the last two readings, and
`/metrics` formats them with each machine's `machine`, `tenant`, `name` and `role` labels, so a
scrape probes nothing. `GET /v1/top` takes CPU percent and network rates from the last two
readings, 15 s apart. After the measure the tick reads the pool once and decides the host's
conditions (`conditions.rs`): `memory_pressure`, committed memory over `memory_pct` of
capacity; `disk_pressure`, the pool's free space under `disk_free_pct`. A task of its own
decides `storage_stalled` every 15 s, a `zfs` command running for over a minute (ADR 0046):
the tick would wait on the same pool. A change is a
`host_condition` event; `/v1/status` and the heartbeat carry them. Under disk pressure the tick
removes unused images (no clone, no record naming them), oldest first, counting what each took
as freed, until the pool is back over the threshold. The console is written by the daemon's
`console::Writer`, line by line under one lock, each line flushed, and rotated past
`console_max_mb` to `console.<offset>.log`, named after where it starts: a `/logs` cursor is an
offset in the whole console and reads across both files. `?follow=true` keeps the read open
(ADR 0025): the follower waits on the console's notifier (`console::grown`, one per run dir,
woken by the writer after each line), reads from its cursor, and ends at the machine's
`destroyed` event or the daemon's shutdown, with `{}` every 30 s meanwhile.

An exec session (`GET /v1/machines/{id}/exec` upgraded to a WebSocket, ADR 0029) is the same
guest connection as a JSON exec, kept open: the client's messages (a channel byte, as
Kubernetes') become the init's `stdin`, `resize` and `close_stdin` frames, its `stdout`,
`stderr` and `exit` become messages (`session.rs`). With `tty` the init runs the command on a
pseudo-terminal of its own as the leader of a new session. The host's close ends any exec's
command (SIGKILL to its group; SIGHUP first on a terminal); the daemon pings the client every
30 s and drops one silent for 90 s. A machine with a session open is in use and does not sleep.

### Labels and quotas

A machine's `metadata` is its labels: `GET /v1/machines?label=k=v&label=k` keeps the machines
every selector matches (`api::Label`, equality and existence, ADR 0025). A tenant's quota
(`TenantRec.quota`, `PUT /v1/tenants/{id}/quota`) limits its machines and the volumes' sizes,
checked in `add_machine` under the map's lock (a create, a fork, a restore, the gateway) and in
`grow_volume` (a volume's growth, ADR 0040), and
its machines' memory and vCPUs, checked in `reserve` with the host's own memory, so two starts
cannot pass it together. A refusal is 403 `quota` and a `quota_exceeded` event.

### Sleep

Use is an exec or an exec session for as long as it runs (ADR 0029), an ingress connection
until it reaches the program (through a wake, readiness and the port's opening, ADR 0053), or
an explicit `POST /machines/{id}/touch`. An open connection after that is not use. After the
machine's `sleep` window with no use, the daemon stops it (`stopped_reason: idle`; idle machines
are stopped together, a few at a time, never one after another). A start, an
ingress connection or an exec on an idle machine wakes it; one that arrives while the machine is
being stopped waits for the stop, then starts it. `sleep: "never"` keeps it on. `PATCH
/machines/{id} {"sleep": "3h"}` changes the window in any state, without a restart.

A stop can keep a memory snapshot instead (`POST /machines/{id}/stop {"suspend": true}`, or
`suspend_on_sleep: true` for the sleeper): the machine is paused, Firecracker writes its memory
and state into its jail (on the pool), and the next start loads them into a fresh Firecracker and
resumes, in about a quarter of a second under nested virtualization, without a boot: processes,
connections and uptime carry on. The snapshot is used once; if it cannot be loaded, or was taken
under another Firecracker or host kernel (the machine's `vmm_version`), the start is a cold boot.

### Versions and upgrades

Every binary says its version, the release and the commit (`0.1.0+fdad892eeefa`, ADR 0027):
`/v1/status`, the heartbeat, `host ls`; the init in its `pong`, kept as the machine's
`init_version`. The wire between versions is additive: a field added has a default, nothing is
renamed or removed, unknown fields and values are ignored. The daemon's stop (SIGTERM) suspends
every running machine, and its next start boots each one again; SIGUSR2 hands them over instead,
once every transition under way has ended:
the daemon exits and leaves them running, and the next one adopts them. `host upgrade` through
the fleet (`upgrade.rs`) marks the host `upgrading`, runs the bootstrap script on it again with
the release (whose last step is that hand-over), waits for a heartbeat from a new start of the
installed version that stopped no machine, and puts the host back; the fleet is upgraded first.

## Several servers

`briqyard-fleet` offers the same machine API as a daemon and forwards each request to the host
that runs the machine. It places each tenant on one host: a tenant's machines share a host, so
its private network needs no overlay. Placement picks, among ready hosts under the fill
ceiling, with no condition true and of the create's `region` when it names one, the one with the
most free memory; a fork lands where its source is, and a tenant's host or a fork's source's
with a condition true answers 503 `capacity` before it is asked. A tenant's region is its host's:
a create naming another answers 400 (ADR 0025). What a placement
puts on a host is held there (counted as used) until a report of the host counts it, so a burst
of creates spreads; a create the host refuses gives its hold back at once, and a destroy's
answer waits for the host's figures, so the room it freed is there for the next create (ADR
0044); a host that answers `capacity` for a tenant's first machine loses the pin, so the
retry is placed afresh. A tenant's gateway goes to the tenant's host (`GET /v1/tenants/{id}`
and `/gateway` are forwarded there); a PUT for a tenant with no host places it as a first machine
would, the gateway's size as the need, in `?region=`; a quota PUT does the same with no need.
A logs follow is streamed through as an events watch is; an exec session's WebSocket is
relayed as bytes once the host answered its upgrade (ADR 0029). `POST /v1/tenants/{id}/unpin` releases a tenant by hand (ADR 0013).

Hosts report their capacity and tenants (`POST /v1/hosts/register`, every 15 s, from the
daemon's `fleet:` configuration) or are listed in the fleet's configuration and polled. A host
has one credential, its own API token: the fleet forwards with it and the host's heartbeat
presents it, and a heartbeat is taken only for the host record that expects that token at that
address (the record of a `host add`, or a `hosts:` entry); any other is refused. A host silent for
a minute is `down`: its machines' calls answer 503 `host_down` until it is back, and a listing
of machines or endpoints is never partial (a tenant's listing asks its host alone; a host that
is down or does not answer fails the listing), since a control plane reads a machine missing
from a listing as gone. `POST /v1/hosts/{id}/drain` stops placing on a host (`draining`),
`undrain` resumes it; a host `upgrading` or `retiring` takes nothing new either. The registry
(hosts, tenant → host, machine → host, endpoint → host) is one JSON file, written one write at
a time, each with the registry as it is when its turn comes; a write that fails before a host is
asked fails the request, one after the host acted is logged and the host's answer stands (ADR
0043). A destroyed machine's backups are reached on the host that holds them, wherever its
tenant is now (ADR 0045). It is written to the object store once a minute when it
changed, encrypted with age to a key kept off the fleet's host, and before any pool key is
served; `briqyard-fleet restore` brings it back (ADR 0032).

The fleet buys no server (ADR 0042). As Kubernetes's scheduler does for the Cluster
Autoscaler, placement counts each create it refuses for want of room by what ran out (`memory`,
`disk`, `pressure`) and region, and the fleet's `/metrics` and `/v1/status` show each region's
free room and largest slot (`signals.rs`); a scaler outside reads them, buys a server and adds
it. `POST /v1/hosts/{id}/retire` makes a host `retiring` and forgets it once empty; the server
is the operator's to give back.

A server becomes a host in three steps: it is added (`POST /v1/hosts`, `briqyard host add`, its
SSH and API addresses), the fleet runs `hack/bootstrap-host.sh` on it over SSH (the script on
stdin, the fleet's URL and a fresh API token in the environment, the fleet's `bootstrap:`
settings) until it succeeds, and the host turns `ready` on its first heartbeat, taken for the
record made at the add. A host's API may live on a private network (OVH's vRack, the fleet's `private_network`) while SSH
reaches its public address: the script binds the API and the endpoints to the private address
and closes the public interface to all but SSH (ADR 0028). The fleet is given no SSH host key with the server:
the key seen at the first successful bootstrap is pinned in `<state_dir>/known_hosts`, its
fingerprint in the host's note, and later connects are strict against it. An upgrade runs the
same script over the same connection with another release (ADR 0027).

The control path is TLS (ADR 0020). Each daemon makes a self-signed certificate once and
serves its API with it on any non-loopback address; the fleet trusts that certificate by its
SHA-256 alone, pinned in the host record: read by the bootstrap over the pinned SSH connection,
or written in `hosts:` by the operator. Every forwarded call verifies the pin; a heartbeat
reporting another fingerprint, or reporting one for a host with none pinned, is refused. The
CLI pins a daemon the same way (`--tls-fingerprint`, the same verifier in `briqyard-api`). The
ingress and TCP endpoints are not covered by TLS: they ride the private network (ADR 0028; across networks, `MESH.md`).

A WireGuard mesh between hosts, so a tenant can span several, is the next step after that: `MESH.md` is its design.

## Security

Every machine is a KVM virtual machine: its own kernel, its own memory, three virtio devices and
a vsock. With `jailer` configured (every deployment; only development runs without it), the
daemon launches Firecracker through Firecracker's jailer: a chroot per machine under `jail_dir`
holding only the kernel, the config drive, the machine's block device nodes and its sockets; a
uid and gid of its own (`jail_uid_base` plus its place in the tenant's network, so no two
machines share one); a new pid namespace; a cgroup v2 of its own; and Firecracker's seccomp
filters. The daemon never mounts a guest filesystem. Guests reach only their tenant's bridge,
the gateway's DNS, and the internet through NAT; nothing reaches a guest but the ingress.
Secrets reach the guest on its config drive and never through the API's responses. At rest
everything of a machine (disks, records, config drives, consoles, memory snapshots) is on the
encrypted pool: a disk or a server that leaves our hands is unreadable once the fleet forgets
the host (ADR 0026).

The daemon runs as root (ZFS, TAP devices, nftables, mknod in the jails). Its API and its
endpoints listen on loopback unless told otherwise; on an address the internet could reach it
refuses to start until `ingress.allowed_clients` says who may connect (ADR 0012). Off
loopback the API is TLS with the host's own certificate (ADR 0020). Every id a caller sends (a tenant, a machine id
in a path) is checked (`a-z`, `0-9`, `_`, `-`, 64 at most) before it names a file or an object.
A pid in a record is signalled only when `/proc` shows it is the Firecracker of that machine:
after a reboot, the number is someone else's. What it writes is its own: umask `077`,
`data_dir` and everything under it `0700`, records and config drives `0600`, the drive's copy
in the jail `0400` for the jail's user, so no other local uid (another machine's Firecracker
included) reads a tenant's secrets (ADR 0014). A state key is a file name: `Store::path`
refuses a key that would leave its directory, behind the API's own validation of ids.

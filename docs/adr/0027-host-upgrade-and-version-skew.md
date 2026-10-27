# ADR 0027: Host upgrade and version skew: versions everywhere, an additive wire, a daemon that hands its machines over

Date: 2026-10-21 · Status: accepted; amends ADR 0005 (what a daemon's stop and start do with machines) and ADR 0013 (drain is not retire)

## Context

Real hosts are about to carry real tenants, and their binaries will change under them. Before this, an upgrade was by hand (`OPERATIONS.md`): install the binaries, `systemctl restart briqyardd`. What that did and what it risked:

| Found | Effect |
|---|---|
| A clean stop suspends every running machine; a `host`-stopped machine waits for its next use | A worker, a bot, anything nobody calls stayed stopped after every restart |
| `bootstrap-host.sh` wrote the release's binaries with `curl -o` over `/usr/local/bin` | `Text file busy` on a running daemon: "run it again to upgrade" did not work from a release |
| Every binary said `0.1.0` | Two builds could not be told apart; nothing said which init a machine runs |
| A memory snapshot was loaded by whatever Firecracker the host had | Firecracker promises no snapshot across its versions and calls one across host kernels unstable ([its versioning doc](https://github.com/firecracker-microvm/firecracker/blob/main/docs/snapshotting/versioning.md)) |
| `drain` and `retire` were one state, `draining`: the scaler releases an empty `draining` host | Draining an empty host to work on it released it at the provider |
| No rule for skew | The protocol happened to survive most of it (below), by luck |

What a skew breaks, read from the code:

| Path | Today | Breaks on |
|---|---|---|
| host ↔ init (vsock frames, the config drive) | serde ignores unknown fields; `op` and `type` are strings; only `op`, `type` and the drive's fields of the first version are required; an unknown op is answered `error "unknown op …"`; an exec stream skips a type it does not know | a removed or renamed field, a new required field |
| fleet ↔ host (heartbeat, status, forwarded calls) | every field added since the first version has a default; states, reasons, condition types are strings | the same; and the fleet re-types endpoints, backups, usage, `top` and events when it merges them, dropping fields it does not know |
| records, the event log | serde defaults, `Record::migrate` | an older daemon rewriting a newer record drops the newer fields |
| configuration files | `deny_unknown_fields` | an older binary refuses a field it does not know (on purpose: a typo is not ignored) |

## Decisions

**Every binary says its version: `0.1.0+fdad892eeefa`**, the workspace version and the commit it was built from (`briqyard_api::VERSION`, set by `briqyard-api`'s `build.rs`: `git rev-parse --short=12 HEAD`, or `BRIQYARD_COMMIT` for a build outside a checkout). `--version` of the daemon, the fleet and the CLI; `version` in `/v1/status`, the heartbeat, `host ls` (VERSION) and the `host_started` event. A build with uncommitted changes says its HEAD's commit.

**The init says its version in `pong`** (`Response.version`, written only there). The daemon keeps what the init said at the last boot on the record: the machine's `init_version`, empty before its first boot under this ADR. The init lives in the root disk (ADR 0004), so a machine runs the init its root disk was made with until the root disk is made again (an image change, ADR 0024), not until its next boot. That is why the protocol rule below has no end date.

**The machine says what ran its last boot: `vmm_version`**, Firecracker's version and the host kernel's release (`v1.17.0/6.8.0-45-generic`, `Vmm::version`, read once at the daemon's start); `/v1/status` says the host's current one. A machine whose `vmm_version` is not the host's still runs a Firecracker process of the previous version.

**One rule for the wire, both paths: additive.** A field is added with a default that means what its absence meant; never renamed, retyped or removed. Readers ignore fields they do not know; a closed set (a state, a reason, an op, a frame type) is a string, read and shown as it comes. A peer that sends what the other lacks finds out by its version: the daemon from the machine's `init_version` (an old init answers `unknown op`), a caller from `host ls`. An op an old init does not know comes back as an error naming the machine's `init_version`. A field an old init would ignore is checked by the daemon before it sends it: an exec session (ADR 0029) on a machine whose init is of a release before sessions (`version::SESSIONS`; an init that reports no version counts as before) is refused 409, its init named, since that init would run it as a plain exec without input or terminal. `guest.rs` and `types.rs` test the oldest shapes and newer ones (unknown fields, an unknown op and type) decoding.

**A request field that restricts (egress, limits) is refused, never ignored, by a host older than it.** When such a field is added, the fleet refuses to forward a request carrying it to a host whose version predates the field, so an older host never runs a machine without a restriction it was asked for. None does yet: every restricting field is older than the version report.

**The fleet is upgraded first, then the hosts.** The fleet re-types some host answers (above), so a fleet older than a host would drop that host's newer fields. Kubernetes's rule: the control plane first, nodes never newer. `host upgrade` checks it: a host that comes back with a later release than the fleet's (`api::version::newer`, the numbers before `+`) fails the upgrade, which stops a roll.

**A daemon hands its machines over on SIGUSR2.** It stops serving, takes every machine's lock (a start, stop or suspend under way ends first; none begins after), writes the last uses and the usage, and exits with the locks held, leaving every Firecracker running (`KillMode=process`); the next daemon adopts them, as after a crash, and its start says what it did with them (`started: {at, adopted, stopped, gone}` in the status and the heartbeat, absent from a daemon older than this ADR): `stopped` is a process still there that it could not take over, `gone` one that ended while no daemon ran. SIGTERM is unchanged: a stop (`systemctl stop`, a host shutdown) suspends every machine. `bootstrap-host.sh` hands over when a daemon runs (`systemctl kill --kill-whom=main -s SIGUSR2`, waits for it to exit, `systemctl start`), and puts every binary in place by a rename (`install` to `<name>.new`, `mv`), never by writing into a running one.

**A machine the host stopped is started again at the daemon's start**, when its sleep window has not run out (`sleep: never` always): suspended by the last stop, or left running by a daemon that could not hand it over. What ran before the daemon went down runs once it is back, used or not. Amends ADR 0005, where it waited for its next use. Through the boot gate, detached; a gateway is started by what needs it.

**A memory snapshot resumes only under the `vmm_version` that took it**; another one drops it and the start is cold (`starting` says so, `snapshot_vmm` in its data). A snapshot taken with its memory (ADR 0031) records the `vmm_version` it was taken under, and a restore puts it on the record with the memory, so the same rule applies to it. An upgrade that changes Firecracker or the host kernel therefore leaves running machines on their old Firecracker process until their next start, and boots the suspended ones cold. Refusing the upgrade while machines are suspended would gain nothing: a snapshot that cannot be loaded is what a cold boot already covers.

**`host upgrade` through the fleet** (`POST /v1/hosts/{id}/upgrade {"release"}`, `briqyard host upgrade <id> --release <url-or-version>`): a release URL, or a version of the project's releases (`0.2.0`). On a `ready` or `draining` host, one upgrade at a time (409 `conflict`):

1. the host is `upgrading`: placement stops, its machines are served;
2. `bootstrap-host.sh` runs on it over SSH with the release, as the bootstrap does (`bootstrap::install`, the same key, the pinned host key): one install path;
3. `briqyardd --version` over SSH says what was installed;
4. the fleet waits up to 5 minutes for a heartbeat (or a poll of a static host) from a new start (`started.at` moved) of that version; a heartbeat with no `started` (a daemon older than this ADR) is never it;
5. a start that stopped a machine instead of adopting it fails the upgrade (`stopped`; a `gone` one exited by itself in the gap and does not);
6. the host is back in its state (`ready` or `draining`), its note `upgraded to <version> at <time>; machines handed over: N`.

A failure leaves the host `draining`, the reason in its note, for `host undrain` once fixed. The request waits for the upgrade, which runs in a task of its own (ADR 0011): a caller that hangs up never leaves a host half-moved. A fleet that restarts mid-upgrade finds the host `upgrading` and makes it `draining`. **`--all`** is the CLI's loop over the one-host call: every `ready` or `draining` host by id, one at a time, stopping at the first failure and naming the hosts left.

**Drain is not retire.** `draining` takes nothing new and nothing more (Kubernetes's cordon); `retiring` takes nothing new and is released once empty (the scaler's `retirable`); `POST /v1/hosts/{id}/undrain` (`host undrain`) puts a drained or retiring host back to `ready`. A heartbeat keeps `draining`, `retiring` and `upgrading`.

**A reboot (an OS or host kernel upgrade)**: `systemctl stop briqyardd` suspends every machine, the reboot, and the daemon's start boots each one again (cold when the kernel changed, by the rule above). Through the fleet that is `host drain`, the reboot by hand, `host undrain`; the fleet does not reboot hosts.

Rejected, one line each:

- Re-exec in place on SIGHUP (`systemctl reload`): the pid stays, but the Firecracker processes stay the daemon's children, zombies the new image's adopter never reaps, and a failed exec leaves no daemon.
- Hand-over on SIGTERM: a host shutdown would end every guest hard instead of suspending it.
- A protocol version number checked at connect: it would refuse an old init that can still serve; the additive rule and the version strings say what a number would.
- Refusing unknown request fields (Kubernetes's strict field validation): serde cannot with the `flatten` in `UpdateMachineRequest`, and it would fail every call a newer caller makes to an older host; a caller checks `host ls` instead.
- A fleet task rolling over every host: it needs a roll object to report on; the CLI's loop over the one-host call stops at the first failure the same way, and a lost terminal stops it between hosts, never inside one.
- 202 and a poll: no result to poll for; a request that waits on a detached task is as safe.
- The fleet passing host answers through untyped, so the order would not matter: kept for later; fleet first is Kubernetes's rule and costs nothing.
- An initramfs carrying the init, so every cold boot runs the host's init: open (below).

## Consequences

- A daemon restart resets the connections through its ingress (the proxy is the daemon's): TCP endpoints and HTTP requests in flight, execs, log follows and watches; new connections are refused for the gap, a few seconds. Clients reconnect; guests see nothing. A backup upload cut by a hand-over is tried again by the next daemon and leaves an orphaned multipart upload in the bucket until a lifecycle rule removes it. A request still running 30 s after a stop or a hand-over is cut (the server waited for it without end before, until systemd killed the daemon); the next daemon takes up what its transitions left, as after a crash.
- A machine whose process exits during the hand-over's gap (a second or two) has its exit report lost: the new daemon finds it gone, marks it stopped and boots it again, whatever its restart policy.
- The daemon's records keep the fields a newer daemon wrote (`Record.rest`), so a rollback that rewrites a record does not drop them.
- Machines suspended by a daemon from before this ADR carry no `vmm_version`: their next start is cold, once. A daemon from before this ADR does not catch SIGUSR2 and dies of it, which is a crash: the new daemon adopts its machines all the same (the last minute of usage and of last uses is lost, as in any crash).
- A rollback is an upgrade to the older release (`host upgrade` refuses nothing older). The older daemon refuses a configuration field it does not know: remove such fields first. A daemon older than this ADR also drops the newer fields of the records it rewrites. The bootstrap script runs the downloaded daemon against the configuration before any binary lands, so a configuration it refuses stops the upgrade with the host as it was. A shutdown past its 60 s cap ends with a warning; what it had not done is found by the next daemon as after a crash.
- The fleet reaches every host it upgrades over SSH with `provisioner.bootstrap.ssh_key`; a static host's key is pinned at its first upgrade, as an ordered host's at its bootstrap.
- After a roll, `provisioner.bootstrap.release` is what new hosts get: set it to the same release.
- Open: the init in an initramfs (every cold boot on the host's init, so the daemon could drop support for old inits); release digests (the script fetches the binaries over HTTPS without a checksum, the next step is a `SHA256SUMS` in the release, checked); OS patching through the fleet (drain, reboot, undrain in one call); evacuating a host before a reboot.

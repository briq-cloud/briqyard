# 0068 — Retire machine cgroups under lifecycle ownership

Date: 2026-10-31. Status: accepted.

## Decision

Destroy a machine's cgroup leaf synchronously under its existing lifecycle lock, after
positive process death, local OOM evidence capture and final metering, and before disk
teardown or record removal. Remove exactly one directory with `unlinkat(AT_REMOVEDIR)`.
Never recurse, unlink controller files, kill other members or change limits to make removal
succeed. An error keeps the machine destroying, its disks and its reservation for retry.
Destroying machines retain their physical charge and block incremental admission while
ownership is unresolved. A failed boot also retains its conservative charge and admission
fence when its launch outcome is unproven, even when the record says `error` with PID0 and
no managed VM handle. Set the pending hold before entering the factory; only a positive
settled result can clear it. A successful managed live handle uses the normal reservation.
Reconciliation takes the entry lock so it cannot consume the previous launch's receipt while
a new start is invalidating it. Proven no-launch failures do not charge every error record. An empty leaf alone does not release memory reservations.

Hold directory descriptors opened without following symlinks. Use the original machine ID,
check its reversible Firecracker encoding and refuse collisions in the machine registry.
Require the canonical root, parent and leaf to remain the held inodes with the expected owner
and permissions. Require cgroup v2, no direct PIDs, `populated 0`, `frozen 0`, and no child
directories or symlinks. Hold `cgroup.procs` and `cgroup.threads` for each relevant root,
service, fixed-parent and leaf directory; require regular root0:0 files without group/other
write permission and recheck named-to-held inode joins. Directory permissions alone do not
exclude delegated membership. Missing, replaced, symlinked, unreadable or writable membership
files refuse proof, including existing ancestors of an absent leaf. Never repair ownership
or permissions automatically. Read control files with fixed bounds. A missing leaf needs the same
process-death proof as a present leaf.

Before removal, capture one checked final CPU/memory reading and readable local OOM totals
from the existing leaf. Feed that exact CPU reading to the existing ledger and baseline;
never reread after removal or substitute missing data for a failed read. Only authoritative
absence can represent no leaf. A failed or ambiguous final read retains destroying, the
leaf and its charge. Periodic metering remains best-effort. Final OOM totals do not invent a
historical per-incarnation delta when its baseline was unavailable. Ledger persistence and
acknowledgement durability retain their existing separate contract.

## Process settlement

A direct child's successful reap proves that child exited. A detached jailed or adopted VMM
requires readiness of a retained pidfd for its positively identified incarnation. Console EOF,
PID/name lookup failure, a closed false watch channel and an expired termination deadline do
not prove death. Checked termination signals the retained pidfd. Capture local OOM evidence
before publishing the factory's settled receipt. Never publish a receipt for a spawned attempt
merely because its owner was dropped. Register each new original identity before spawning;
a next launch invalidates the previous receipt before it can create a process. The entry lock
excludes a new incarnation during destruction. An old receipt cannot settle a later launch.

Factory receipts survive a failed destroy and are forgotten only after record removal.
Startup failures before spawning can settle immediately; failures after spawning must
positively settle the launcher and VMM. If the exact approved launcher has been reaped before
a VMM identity could be captured, its attach-before-fork contract plus a checked empty/absent
canonical leaf closes post-join descendants for that exclusive launch epoch. A missing
pidfile, empty leaf or attempted kill alone remains unresolved. Remaining live or unknown
members refuse settlement.

## Supported supervision and first upgrade

Protected native recovery supports the official `briqyardd.service`, directly executing
`/usr/local/bin/briqyardd --config /etc/briqyard/config.yaml`, under systemd on cgroup v2.
Wrappers, creator hooks, delegation, alternate supervisors and unrecognized provenance do
not grant recovery authority. Manual native development launches are outside this supported
recovery contract. The `tls-fingerprint` subcommand remains available before this barrier.

Acquire a root-private, no-follow, permanent `/run/briqyard/cgroup-domain.lock` inode before
host helpers. Hold its exclusive flock for the factory's lifetime; never unlink it. This is
one lock for `/sys/fs/cgroup/firecracker`, independent of the configured data directory.
Recheck its inode and ownership before using launch or retirement authority.

The new lock serializes new compliant daemons. It does **not** assert that an old binary held
that lock. First-upgrade recovery instead relies on the supported single-domain lineage:
managed launchers originated from this official service, inherited its cgroup before exec,
and only its trusted jailer moved them into the fixed machine domain. Systemd starts the new
official main process after the previous main terminated. Arbitrary historical administrative
customization or a creator escaping both domains is not discovered or authorized here.

Bind the held `/proc/<self>` start identity and unified membership to the effective unit's
MainPID, ControlGroup and stable InvocationID from the local system manager. Environment
variables and listening-socket handover metadata do not confer this authority. Require the
loaded official direct command, simple service type, root identity, `KillMode=process`, no
pending daemon reload, no drop-ins, no delegation and no creator hooks.

`systemctl show` omits empty Exec arrays even with `--all`: absence is unresolved. Read the six
hooks with fixed local D-Bus `busctl` get-property calls. Require the closed JSON shape,
exact signature `a(sasbttttuii)` and empty `data` array, rejecting missing, duplicate, unknown
or nonempty values. Other fixed unit properties are checked separately. Helpers have bounded
output/deadlines, discard stderr and are positively reaped; they inherit no application
environment. No helper runs after the final unit identity recheck.

Keep managed spawning closed before record recovery, orphan teardown, create resumption,
gateway starts, background workers or HTTP mutations. Inventory at most 4096 original machine
identities and bounded service/domain members without skipping read failures. Retain pidfds
and original command/start/leaf joins for live VMM candidates. Unknown launchers, multiple
members, unreadable state, child cgroups, ownership changes or collisions refuse startup.
A nonroot four-UID equality and zero effective/permitted/ambient capabilities are additional
candidate checks; confinement also depends on trusted lineage and root-only, nondelegated
cgroup permissions.

After inventory and reaping every barrier helper, recheck the effective unit and held cgroup
identities, then require service `cgroup.procs` to be exactly the current daemon and no child
cgroups. Recheck the complete machine-domain membership and each held target leaf afterward.
A pre-exec or pre-join survivor remains in the service; a post-join descendant remains in its
leaf. The trusted jailer attaches before clone/fork and drops privilege before VMM execution.
This closes the legacy launch window without an empty snapshot or quiet-time heuristic.

Retain the service/root/ancestor membership guards with the factory and each launch attempt;
recheck them at retirement and known-launch settlement, not only at startup.

Only this barrier constructs the non-deserializable recovered authority. Empty known records
receive a settled epoch and can be destroyed normally. Live known candidates can be adopted
through their retained identity or positively terminated before being marked stopped. Empty
orphan leaves are retired, with final counters, under the still-closed startup gate before
artifact teardown. An adopted VM's native pidfd monitor can run, but defer its manager exit
watcher, probes and restart dispatch until the managed-spawn gate opens. An exit reported
during recovery is then consumed without losing its restart intent. Then dispatch
create/gateway/background work.
Recovery settlement cannot run after that gate opens. Unknown outcomes retain ownership.

## Executable provenance

A version string alone does not prove attach-before-fork ordering. Open the configured jailer
without following symlinks, require a root-owned non-writable executable ELF, hash the held
file, and require an exact architecture/build match below. Execute that held inode for the
version check and each new launch. Retain its inode, metadata and digest and recheck them before use. Unknown
custom builds and version overrides remain unsupported.

The approved release members come from Firecracker v1.17.0, source commit
`95f868c8e345b1cc8faccd1a3c910b4989dc3f58`: jailer `env.rs` attaches at line659 before its
clone/fork paths and drops privilege before execution. The pre-exec OOM-score hook performs
only open/write/close, with no fork or cgroup migration.

| Architecture | Jailer ELF SHA-256 | Bytes |
|---|---|---:|
| x86_64 | `65ef226e96f0ceda55ba643f445801ef2cc0ea667ef67cad8ac4f406c9c8434f` | 2243000 |
| aarch64 | `4d8d2dd4dfc1d47932b2bd261479181dd0c54f0a2f32714421a7e7f9f07ddec8` | 2012584 |

Each exact `release-v1.17.0-<arch>/jailer-v1.17.0-<arch>` member was hashed only after its
complete official archive matched the bootstrap pin:

- [x86_64 archive](https://github.com/firecracker-microvm/firecracker/releases/download/v1.17.0/firecracker-v1.17.0-x86_64.tgz): `06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558`.
- [aarch64 archive](https://github.com/firecracker-microvm/firecracker/releases/download/v1.17.0/firecracker-v1.17.0-aarch64.tgz): `e351ebe4f7a16b5873bbd51005d2e6767103cff4d5ebc829df2d3f95a93e2256`.
- [Pinned jailer source](https://github.com/firecracker-microvm/firecracker/blob/95f868c8e345b1cc8faccd1a3c910b4989dc3f58/src/jailer/src/env.rs#L659).

The configured VMM and jailer must also report the matching supported version. Approving
another build requires its exact bytes and source ordering, not an inherited version label.

## Validation boundary

Source fixtures cover unresolved/cancelled epochs, concurrent domain ownership, stale PID
records and surviving owned children, closed false exit channels, timeout reservation
retention, typed unit/hook identity, unsupported/custom builds, bounded reads, lifecycle
ordering, ordinary recovered-stopped deletion and orphan retirement. Ordinary files model
controls explicitly: real nonrecursive removal refuses their nonempty directories rather
than deleting synthetic controller files. They do not prove a real cgroup kernel removal.

Actual supported-unit restart/adoption/preboot recovery, exact Linux pidfd/cgroup behavior,
lifecycle, fleet, stress and chaos checks remain separate validation gates. No deployment or
real-host proof follows solely from source fixtures or property-format compatibility.

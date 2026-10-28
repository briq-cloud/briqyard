# zvol links after a rename, and a VMM on a destroyed zvol (2026-10-28)

What ADR 0043 is decided on. Hosts: two OVH servers (x86_64, Ubuntu 26.04, kernel 7.0.0-38,
OpenZFS 2.4.1, systemd 259, briqyard v0.1.1) and the dev VM `fc2` (aarch64, the same kernel,
OpenZFS and systemd).

## On the real host (RISE-M, chaos run straight to the daemon)

6 tenants × 3 machines and 8 racers for 14 minutes: snapshot restores, forks, restarts and
backups in quick succession. The first failure came 50 s in; besides those, a backup racing a
destroy answered 500 (`dataset does not exist`, 10) and an exec on a guest that was exiting 500
(`vsock …: Connection refused`, 7).

| What the API answered | Count |
|---|---|
| a start or restart: 500 `root disk: zvol device …/root did not appear` (after 15 s; the machine then `error` for good) | 45 |
| the same for the data volume | 14 |
| a restore: 500 `Drive config error … backing file: No such file or directory` | 5 |
| a restore: 409 `boot_failed`, the guest kernel `Rebooting in 1 seconds` or `reboot: machine restart` | 12 |

At 18:43, 5 volumes had no link, 5 links named `….next` datasets that no longer existed, and
1 link named a destroyed volume. For one of them `/lib/udev/zvol_id /dev/zd608` already
answered the new name (`…/root`) while the link was still `…/root.next`;
`udevadm trigger --action=change --settle /dev/zd608` made the `root` link at once. The kernel
had renamed the device; udev had not moved the link.

Then the whole pool hung. 18:44:47.59 a restore with memory on `m_85d21b648dad`; .63 "retired
disk destroyed root.r_b593e2b91c75"; .76 the machine resumed, Firecracker pid 263071. That
process held `/dev/zd128`, whose `zvol_id` answered "No such device or address": the destroyed
disk. The kernel's `z_zvol` thread waited in `zvol_remove_minors_impl` for its last opener;
every later `zfs create`, `clone` and `snapshot` went into D state behind it
(`zvol_create_minors`, from `dsl_dataset_clone`, `dsl_dataset_snapshot`,
`dmu_objset_create`); a stop could not run, its turn held by a stuck `zfs snapshot`.
`kill -9 263071` at 18:58:27 freed every D-state process within 2 s.

## On the dev VM

**Where the link points when `zfs rename` returns.** The swap of a restore, on raw zfs:
clone `x@s` to `x.next`, wait for its link, `zfs rename x x.r`, `zfs rename x.next x`, then
read where `/dev/zvol/<pool>/x` points, before and after `udevadm settle`.

| Run | Right at once | Old device at once | Old device after settle |
|---|---|---|---|
| one at a time, 30 swaps | 12 | 18 | 0 |
| four at once, 60 | 15 | 45 | 0 |
| four at once while 8 workers clone and destroy volumes, 60 | 37 | 23 | 2 |

ZFS renames a zvol's device in a task after `zfs rename` returned, then udev moves the link
when it works the change event. `udevadm settle` waits only for events udev already holds. The
daemon's wait accepted any link that existed, so it took the old disk's device in those 2.

**Events udev drops.** Under the same churn udev logged `zd400: Failed to process device,
ignoring: Unknown error 512` (512 is `ERESTARTSYS`: opening a zvol gives up when the pool's
namespace lock stays taken) and `zd4960: … Bad file descriptor` (a device being removed). A
dropped change event leaves the link where it was until another event for that device.

**Destroying an open zvol, opening a destroyed one.**

| Test | Result |
|---|---|
| `zfs destroy` of a zvol a process holds open | refused: `dataset is busy` |
| the destroyed zvol's device node opened right after `zfs destroy` returned, under churn | accepted 4 times out of 30 |
| `zfs clone` while that node is held | waits in `zvol_create_minors` → `taskq_wait_id`: minors are made in the same task queue as removals |

So ZFS never destroys a zvol something holds; the hazard is the other order: a destroy, then
an open of its device before ZFS removed it. The removal then waits for that holder, and every
minor after it waits too. That is the RISE-M hang.

**The daemon on the VM.** 45 snapshot restores of three running machines (one loop each) and
a chaos run on `fc2` (2 vCPUs) did not reproduce the failures; the chaos run took the VM down
(macOS's nested virtualization, `DEVELOPMENT.md`). The VM has fewer cores and slower disks than
the RISE-M, so fewer operations overlap. The unit tests make the lost events deterministic
instead (a fake udev that drops them).

## Scripts

`lag.sh N PAR`, as root on a host with a pool `byard` (datasets under `byard/zvtest`):

```bash
P=byard/zvtest; zfs create -p $P
one() {
  d=$P/s$1
  zfs list $d >/dev/null 2>&1 || { zfs create -s -V 64M $d; zfs snapshot $d@s; udevadm settle; }
  zfs clone $d@s $d.next; udevadm settle
  for t in $(seq 1 50); do [ -e /dev/zvol/$d.next ] && break; sleep 0.1; done
  B=$(readlink -f /dev/zvol/$d.next)
  zfs rename $d $d.r; zfs rename $d.next $d
  a=$(readlink -f /dev/zvol/$d); udevadm settle; b=$(readlink -f /dev/zvol/$d)
  echo "$([ "$a" = "$B" ] && echo right || echo stale) $([ "$b" = "$B" ] && echo right || echo stale)"
  zfs promote $d; zfs destroy -r $d.r
}
for i in $(seq 1 $1); do for p in $(seq 1 $2); do one $p & done; wait; done | sort | uniq -c
```

The churn beside it: 8 loops of `zfs clone $P/base@s $P/cK-N; zfs destroy $P/cK-N`. The open
after a destroy: `mknod` a copy of the device node, `zfs destroy`, then `exec 3<>` the copy.

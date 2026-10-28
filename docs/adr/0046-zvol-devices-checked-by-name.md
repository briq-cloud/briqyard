# ADR 0046: A zvol's device is checked by name before use; a stuck `zfs` is a host condition

Date: 2026-10-28 · Status: accepted

## Context

The daemon found a disk's block device through udev's link, `/dev/zvol/<pool>/m/<id>/root`,
and waited only for the link to exist. A restore swaps a disk by two renames (ADR 0031:
`root` to `root.r_<n>`, then `root.next` to `root`) and may then destroy the retired disk.

On a real host under a chaos run (`docs/research/2026-10-28-zvol-links.md`), links went wrong
within a minute: 45 starts failed for good on `…/root did not appear`, restores booted on the
wrong disk (`boot_failed`) or on none (`Drive config error`), and links named datasets that no
longer existed. Then one restore resumed a machine on the device of the disk it had just
destroyed: ZFS's removal of that device waited for Firecracker to close it, every later
`zfs create`, `clone` and `snapshot` waited behind the removal, and the host's storage hung
until the process was killed by hand.

Measured on the dev VM (the same kernel 7.0, OpenZFS 2.4.1, systemd 259):

| Fact | Measure |
|---|---|
| ZFS renames, makes and removes a zvol's device after `zfs` returned | right after the swap's renames the link named the old disk's device in 18 of 30 swaps, 45 of 60 four at once |
| `udevadm settle` does not cover it | under clone and destroy churn, 2 of 60 links still named the old disk after `settle` |
| udev drops events | `Failed to process device, ignoring: Unknown error 512` (`ERESTARTSYS` opening a busy zvol): the link stays where it was |
| ZFS refuses to destroy an open zvol | `dataset is busy` |
| a destroyed zvol's device can still be opened | right after `zfs destroy` returned, 4 of 30 under churn |
| minors are made in the queue removals wait in | `zfs clone` waits in `zvol_create_minors` → `taskq_wait_id` |

`zvol_id` (OpenZFS's, the program udev's own rule runs) asks the kernel which dataset a device
is now; a device being removed answers "No such device or address". On the host it already
named the new dataset while the link still had the old name, and a change event for the device
made the right link at once.

## Decisions

**A device is handed out only once the kernel names it the volume.** `Zfs::device`, `create`
and `clone_snapshot` resolve the link to `/dev/zdN` and run `zvol_id` on it. The answer is the
volume: `/dev/zdN` is returned, and the jail's node or Firecracker's drive is made from it,
never from the link. Another dataset, or none: that device gets a change event of its own
(`udevadm trigger --action=change --settle /dev/zdN`), which makes udev move its links, every
500 ms while it stays wrong. A link still not right after one such repair (the volume's own
event was lost too), or missing at the end of the wait, has every zvol's change event replayed
once (`--subsystem-match=block --sysname-match=zd*`). Still not right after 15 s: an error that names
the link and what its device is.

**A rename follows its device.** `Zfs::rename` finds the volume's device first, renames, waits
until `zvol_id` names it `to` (the kernel's rename lands after `zfs` returned), then sends its
change event until the link at `to` names it. The old name's link goes with that event. Only
volumes are renamed (the swap).

**No holder check before destroying a retired disk.** ZFS already refuses to destroy an open
zvol. The hazard is the reverse order, an open after the destroy, and the check above closes
it: the destroyed disk's device answers `zvol_id` with no name. The check and the VMM's open
happen under the machine's lock, and nothing renames or destroys a machine's disks without it,
so the device cannot change between them. Rejected: scanning `/proc/*/fd` for holders (a cost on
every destroy for a case ZFS refuses already), keeping retired disks until the VMM restarts
(more disk held, the wrong-device boot still possible).

**`storage_stalled`, a third host condition.** The backend counts each `zfs` command it runs
until it exits. A task apart from the tick (which a stuck command would hold too) looks every
15 s: a command running for over 60 s makes `storage_stalled` true, its message the command and
how long; it clears when no command is past that. It is in `/v1/status`, the heartbeat and
`/metrics`, a `host_condition` event, and the fleet places nothing new on the host, as for any
condition (ADR 0021). Commands are not timed out: one stuck in the kernel cannot be killed, and
one that is only slow would finish after its caller was told it failed, leaving the record and
the pool apart.

**Two races answer what happened.** A backup whose disks a destroy took answers 404 (the
machine is gone) or 409 `destroying`, not 500, and is not a failed backup. A guest that cannot
be reached (Firecracker's socket refuses, or the init's port does) is a machine not running:
an exec, a session or a file call answers 409 `not_running`, not 500.

## Consequences

- Each device lookup runs `zvol_id` once, and a rename waits for the kernel and udev: a few
  milliseconds a disk on a host, the swap of a restore about 50 ms more.
- A stuck `zfs` command still holds the turns behind it; the host says so and takes nothing new.
  The operator's fix is the holder (`OPERATIONS.md`): with the device check, the daemon should
  never make one.
- `zvol_id` is `/usr/lib/udev/zvol_id`, from the ZFS packages (Ubuntu's `zfsutils-linux`).
- The unit tests' udev is a script over the fake's state that can drop events
  (`udev.drop`): a device per volume file, kept through a rename, outliving a destroy until
  udev next looks. `real_pool_links_follow_renames_and_wrong_ones_are_mended` runs the same
  repair against the kernel and udev (ignored; a host with ZFS, as root).
- Not reproduced on the dev VMs through the daemon (main and this change alike: no wrong link in
  8 minutes of chaos on `fc`); the mechanism is measured on raw `zfs` instead. The first real
  host's chaos run is the check that counts.

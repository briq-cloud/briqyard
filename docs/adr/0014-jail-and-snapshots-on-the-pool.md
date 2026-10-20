# ADR 0014: Machine files: jails and memory snapshots on the pool, everything the daemon writes for itself alone

Date: 2026-10-20 · Status: accepted

## Context

Two findings of the 2026-10-20 review (C3, B9). A memory snapshot (ADR 0005) is written by Firecracker into its jail, and the jail was a directory on the host's root filesystem: a suspended 32 GB machine wrote 32 GB to `/`, and the shutdown path, which suspends every running machine, needed the memory of every guest free on the root disk. And every file the daemon wrote was world-readable under the default umask: the records (a machine's `env`, resolved secrets included), the config drives, the consoles. Any local uid on the host could read every tenant's secrets, including the uid of every other machine's Firecracker.

## Decisions

**The jails are a ZFS filesystem of the pool.** `Zfs::new` makes `<pool>/jail` and mounts it at `jail_dir` (made, moved or mounted as needed, nothing when it is already there). The config keeps saying where the jails are; the bytes land on the pool, next to the disks they belong with. A per-machine zvol for the snapshot would have cost a block device and a filesystem per machine for the same result.

**The daemon's umask is `077`, and the modes are explicit where it matters.** `data_dir`, `state/`, `run/`, `jail/` and the image cache are made `0700`. Records and config drives are written `0600` through one helper (`store::write_private`, atomic as before); consoles are opened `0600`. A file placed in a jail (the kernel, the config drive) is owned by the jail's user and loses its write bits: the drive is `0400` for Firecracker, which only reads it. Secrets are in files the daemon's user and the one jailed Firecracker can read, nobody else.

**A state key is a file name.** `Store::path` refuses a key with `/`, `\` or `..`, or starting with `.`: behind the API's validation of ids, no request shapes a path under `state/`.

## Consequences

- `zfs list byard/jail` shows what the suspended machines hold; the root disk no longer needs it. A host upgraded from before this ADR mounts the dataset over its old `jail/` directory, hiding it: stop the daemon and remove the old directory's contents first, or the suspended machines of that time boot cold and the old files stay on `/`.
- The kernel and the config drive are copied into each jail rather than hard-linked (another filesystem now): about 30 MB on the pool per running machine, removed with the jail.
- A jailed Firecracker runs after `chroot`, so a `0700` `jail_dir` above its root is not in its way; the jail root itself stays owned by the jail's user.
- The image cache's scratch directory (`images/extract-*`) is still on `/`: an image's layers and its extracted tree pass through the root disk, one layer at a time. Move it to the pool when a host runs short there.

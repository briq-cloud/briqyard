# ADR 0039: Image layers written through one root descriptor, resolved by the kernel

Date: 2026-10-27 · Status: accepted; amends ADR 0002 (how a layer's paths are resolved)

## Context

The daemon extracts image layers, as root, into a directory it controls (ADR 0002). Each path of a layer was resolved in user space (`secure_join`: an `lstat` per component, links followed by hand inside the directory, `..` clamped at it), then written by path. That is safe only while our resolution matches the walk the kernel does again at every write; each mismatch found so far (a name ending in `..`, a hard link resolved before a later entry changed its path) was a write outside the directory.

## Decisions

**One descriptor for the root; the kernel resolves every path inside it.** The directory is opened once (`O_PATH | O_DIRECTORY`). A path's directory is `openat2(root, dir, O_PATH | O_DIRECTORY, RESOLVE_IN_ROOT)`: `..` stops at the root, an absolute path or link target starts from it, as the guest reads them in its own root. A missing directory is made one component at a time, `mkdirat` on the descriptor of the one before; a link to a directory not made yet (`sbin -> usr/sbin` before `usr/sbin`) has its target walked instead, at most 40 links. The last name is never resolved: it is the argument of an `*at` call on that directory.

**Every write is an `*at` call on that directory, the last name never followed.**

| Entry | Calls |
|---|---|
| Regular file | `unlinkat`, `openat(O_WRONLY \| O_CREAT \| O_EXCL \| O_NOFOLLOW)`; owner (`fchownat`), mode and mtime on the descriptor |
| Directory | `mkdirat` unless a directory is there, opened `O_NOFOLLOW`; owner and mode through it |
| Symlink | `unlinkat`, `symlinkat` (target kept as is), `fchownat(AT_SYMLINK_NOFOLLOW)` |
| Hard link | `linkat` without `AT_SYMLINK_FOLLOW`, after every other entry, its source's directory resolved the same way then |
| Whiteout, opaque whiteout | `unlinkat`; a directory emptied through descriptors opened `O_NOFOLLOW` |
| `a/..`, empty | a directory with no name: a directory entry sets its mode and owner, anything else is skipped |

`prepare_root` (the init, the mount points, the name files) uses the same root and calls.

**`EAGAIN` is tried again, up to 64 times.** openat2(2) returns it under `RESOLVE_IN_ROOT` when a rename or a mount anywhere on the host raced a `..` step, and says the caller may retry; the daemon's store renames files all the time.

**Linux only.** `openat2` is Linux 5.6 (the hosts run 6.x), through rustix 1.1 (already in the lock file) with its `fs` feature, a Linux-only dependency of the daemon. On macOS the daemon still builds: `apply_layer` and `prepare_root` refuse ("image extraction needs Linux"), and the extraction tests run in the VM, like the init's.

**Measured**: postgres:17 (linux/arm64, 14 layers, 153 MB compressed, 9,924 entries), the layers applied from files by a release build as root, ext4 in the dev VM, median of 14 runs (the two builds alternated):

| | before | after |
|---|---|---|
| layers as pulled (gzip) | 1.27 s | 1.19 s |
| the same layers decompressed (the file system's share) | 0.25 s | 0.19 s |

Decompression is most of a build's extraction; the file system's share is a quarter shorter: one `openat2` for a path whose directories exist, where the resolver made an `lstat` per component.

| Rejected | Why |
|---|---|
| `RESOLVE_BENEATH` or `RESOLVE_NO_SYMLINKS` | refuse the in-root links images rely on (`bin -> usr/bin`, absolute links to `/etc/alternatives/…`) |
| A capability-style crate with beneath semantics | the same refusal, and a large dependency for a few calls |
| Extraction in a chroot or a mount-namespace child | a re-exec of the daemon, and errors carried back from another process |
| An unprivileged extractor | cannot set the owners `mkfs.ext4 -d` copies into the disk |

## Consequences

- Containment no longer rests on our resolver matching the kernel's: the kernel resolves the path it writes, from the root's descriptor.
- What changes for a layer: a hard link to a symlink links the symlink, as link(2) and tar do (it linked the symlink's target); an entry that is skipped (a device) or made later (a hard link) no longer makes its directories when read; `prepare_root` replaces whatever a layer left at a mount point (`/tmp`, `/etc`…), not only a symlink.
- `RESOLVE_IN_ROOT` needs Linux 5.6; a host below it fails every build with `ENOSYS`.

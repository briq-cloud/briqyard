# Guest kernel of the `nested` runtime class

The kernel and ZFS modules a `nested` machine boots (ADR 0088). x86_64 only.

| File | What |
|---|---|
| `base-x86_64.config` | the pinned Firecracker CI kernel's own config (`vmlinux-6.18.54`, the one `hack/bootstrap-host.sh` installs) |
| `nested.config` | options added to it |
| `build.sh` | fetch, configure, build, package |
| `smoke.sh`, `smoke-init.sh` | boot the result in Firecracker |

Built by `.github/workflows/nested-kernel.yml` (every change here; the release workflow calls it).
The release attaches `nested-vmlinux-x86_64`, `nested-modules-x86_64.ext4` and
`nested-versions-x86_64.json` and adds them to `SHA256SUMS-x86_64`.

## Why each option

| Option | Why |
|---|---|
| `VIRTUALIZATION`, `KVM`, `KVM_AMD`, `KVM_INTEL` | Firecracker runs inside the guest. Built in: the guest has no initramfs to load them from. |
| `NF_TABLES_INET`, `NF_TABLES_BRIDGE`, `NF_TABLES_ARP`, `NFT_BRIDGE_META` | the daemon's `inet` and `bridge` tables; ARP matches and `meta ibrname`/`obrname` in the bridge one |
| `NFT_MASQ`, `NFT_REJECT`, `NFT_REJECT_INET`, `NFT_BRIDGE_REJECT` | `masquerade`; `reject` and `reject with tcp reset` |
| `NFT_LIMIT` | the named `limit` objects behind the egress limits |
| `NF_TABLES_IPV6`, `NFT_FIB_IPV4`, `NFT_FIB_IPV6`, `NFT_FIB_INET` | `fib` in an `inet` table needs both families |
| `NF_CT_NETLINK` | conntrack over netlink |
| `TRIM_UNUSED_KSYMS` off | the base config exports only the symbols its own modules use (it has none): zfs.ko would not resolve |
| `MODULE_UNLOAD` | a failed or replaced module can be removed |
| `LOCALVERSION=-briqyard-nested` | the release `6.18.54-briqyard-nested` names the modules directory |

Already in the base config: `TUN`, `BRIDGE`, `VETH`, `NFT_CT`, `NFT_NAT`, `NF_CONNTRACK`,
`BRIDGE_NETFILTER`, `EXT4_FS`. Sets (with concatenations, intervals and counters) and
`ct state` need nothing more. `build.sh` fails when an option of `nested.config` does not end
up as written, so an unmet dependency cannot drop one silently.

## OpenZFS

OpenZFS 2.4.1, the release of the guest image's `zfsutils-linux` (the userland must match the
module). Its `META` says `Linux-Maximum: 6.19`. It is built against this tree as `spl.ko` and
`zfs.ko`, never into the kernel (CDDL and GPL code in one binary is not distributable).
`modules.ext4` holds `lib/modules/<release>` with the `depmod` files; the daemon attaches it
read-only (ADR 0088). `nested-versions-x86_64.json` records the kernel release and the OpenZFS
version.

## Source

`vmlinux` is GPL-2.0 and `zfs.ko` is CDDL-1.0. The release notes link the exact Linux and OpenZFS
source tarballs and their SHA-256 (also in `nested-versions-x86_64.json`); the kernel
configuration is `base-x86_64.config` plus `nested.config` here, at the release tag.

## Rebuild

Sources are pinned by SHA-256 in `build.sh`; the build identity (`KBUILD_BUILD_*`, file times,
filesystem UUID) is fixed. With the same toolchain, `vmlinux`, `zfs.ko` and `spl.ko` come out
byte for byte the same on every run (the log prints the module hashes; the runner image's
compiler is not pinned, so an update of it changes them); `modules.ext4` does not, `mke2fs`
records inode times of the build. On a security release of the kernel or OpenZFS:

1. Change `LINUX_VERSION`, `LINUX_SHA256` (`https://cdn.kernel.org/pub/linux/kernel/v6.x/sha256sums.asc`).
   Staying on `6.18.x` keeps `base-x86_64.config`; a new series needs the new Firecracker CI
   kernel config (extract it with `scripts/extract-ikconfig`, record its SHA-256 in the header
   and in `BASE_SHA256`) and a check of the option names.
2. For OpenZFS: `ZFS_VERSION`, `ZFS_SHA256`, after reading `META` (`Linux-Maximum`) for the
   kernel series and checking the version against the guest image's `zfsutils-linux`.
3. Open a PR: the workflow builds and boots the result. Read the `SMOKE` lines in its summary.

Locally, on x86_64 Linux with the packages named in `build.sh`: `hack/kernel/build.sh`
(`build.sh config` only merges and checks the configuration), then `hack/kernel/smoke.sh
build/out` with `/dev/kvm` writable.

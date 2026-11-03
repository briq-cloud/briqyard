#!/usr/bin/env bash
# Boots the built nested kernel in Firecracker with an Alpine rootfs and the modules image as a
# second, read-only drive, and prints what the guest reports (lines starting with SMOKE):
#   smoke.sh <dir with nested-vmlinux-x86_64 and nested-modules-x86_64.ext4> [work dir]
# Needs /dev/kvm on this machine, curl, e2fsprogs. Exit 0 when the guest booted, mounted the
# modules, loaded the pinned OpenZFS with `modprobe zfs` and took the nftables ruleset; the
# SMOKE lines are in $WORK/console.log. Any download or checksum failure fails the script.
# Whether the guest sees VMX or SVM depends on the machine under it: when it does, /dev/kvm
# must be there too.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
DIR=$(cd "$1" && pwd)
WORK=${2:-$PWD/smoke}
mkdir -p "$WORK/dl"
WORK=$(cd "$WORK" && pwd)

FIRECRACKER_VERSION=v1.17.0   # as hack/bootstrap-host.sh
FIRECRACKER_SHA256=06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558
ALPINE=https://dl-cdn.alpinelinux.org/alpine/v3.24
ALPINE_ROOTFS=alpine-minirootfs-3.24.3-x86_64.tar.gz
ALPINE_ROOTFS_SHA256=f8e1cafba9b1b283b5d30d06f9885c8d2bc161ffe9083ade8e2e157813a53407
# nftables 1.1.6 and what it links to, from Alpine's main repository.
APKS="
85323ef5bce8ff234736dc2d6592ea37aebdc6348a531e27430bdfe38364d256 gmp-6.3.0-r4
7681b41486e1f2b2efce11875c839533464ae8857d30fc49130f0039c6585fdb jansson-2.15.0-r0
3693162ff7c27998dbbb2da1c4bd9072079cd55af1fa3d6d2ade51d276e20157 libmnl-1.0.5-r2
cf8caa8a88bc4ce9d9e395567fefaf9ef7fbd55c50ae6155b35c1b58f3755023 libncursesw-6.6_p20260516-r0
2f4cf35959fde00fdba0dd35ef12a6739739b504e8319c97e30bd4834f98d924 libnftnl-1.3.1-r0
ce83be6d0bd10584a53c3a5868cc1595ce5f0f8e0b621f8f7f70b6144e521fc9 ncurses-terminfo-base-6.6_p20260516-r0
edca96e6160479bd734bb6cdb8412f84f689c6a771fdec75ce2c1c18f3e7cf42 nftables-1.1.6-r1
766911ecb986a6c5cf0841a6b556cd1e9dbbf22b3559726de32416486cd15c81 readline-8.3.3-r1
"

fetch() { # url sha256 file
  curl -fsSL --retry 3 -o "$3" "$1"
  echo "$2  $3" | sha256sum -c -
}

[ -w /dev/kvm ] || { echo "no usable /dev/kvm: nothing to boot Firecracker with" >&2; exit 2; }

fetch "https://github.com/firecracker-microvm/firecracker/releases/download/$FIRECRACKER_VERSION/firecracker-$FIRECRACKER_VERSION-x86_64.tgz" \
  "$FIRECRACKER_SHA256" "$WORK/dl/firecracker.tgz"
tar -xzf "$WORK/dl/firecracker.tgz" -C "$WORK/dl"
FC=$WORK/dl/release-$FIRECRACKER_VERSION-x86_64/firecracker-$FIRECRACKER_VERSION-x86_64

fetch "$ALPINE/releases/x86_64/$ALPINE_ROOTFS" "$ALPINE_ROOTFS_SHA256" "$WORK/dl/$ALPINE_ROOTFS"
ROOT=$WORK/rootfs
rm -rf "$ROOT"; mkdir -p "$ROOT"
tar -xzf "$WORK/dl/$ALPINE_ROOTFS" -C "$ROOT"
while read -r sum name; do
  [ -n "$name" ] || continue
  fetch "$ALPINE/main/x86_64/$name.apk" "$sum" "$WORK/dl/$name.apk"
  tar -xzf "$WORK/dl/$name.apk" -C "$ROOT" --exclude='.*' 2>/dev/null || tar -xzf "$WORK/dl/$name.apk" -C "$ROOT"
done <<<"$APKS"
rm -f "$ROOT"/.PKGINFO "$ROOT"/.SIGN.* "$ROOT"/.post-* "$ROOT"/.pre-* 2>/dev/null || true
cp "$HERE/smoke-init.sh" "$ROOT/init"
chmod 0755 "$ROOT/init"
mkdir -p "$ROOT/lib/modules"

truncate -s 192M "$WORK/rootfs.ext4"
mkfs.ext4 -F -q -O ^has_journal -E root_owner=0:0 -d "$ROOT" "$WORK/rootfs.ext4"

RELEASE=$(sed -n 's/.*"kernel_release": "\(.*\)".*/\1/p' "$DIR/nested-versions-x86_64.json")
OPENZFS=$(sed -n 's/.*"openzfs": "\(.*\)".*/\1/p' "$DIR/nested-versions-x86_64.json")
[ -n "$RELEASE" ] && [ -n "$OPENZFS" ] || { echo "nested-versions-x86_64.json names no kernel release or OpenZFS version" >&2; exit 1; }
cat > "$WORK/vm.json" <<JSON
{
  "boot-source": {
    "kernel_image_path": "$DIR/nested-vmlinux-x86_64",
    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off init=/init briqyard.release=$RELEASE"
  },
  "drives": [
    {"drive_id": "rootfs", "path_on_host": "$WORK/rootfs.ext4", "is_root_device": true, "is_read_only": false},
    {"drive_id": "modules", "path_on_host": "$DIR/nested-modules-x86_64.ext4", "is_root_device": false, "is_read_only": true}
  ],
  "machine-config": {"vcpu_count": 2, "mem_size_mib": 1024}
}
JSON

status=0
timeout 180 "$FC" --no-api --config-file "$WORK/vm.json" >"$WORK/console.log" 2>&1 || status=$?
echo "firecracker exited with $status"
grep -a -E '^SMOKE' "$WORK/console.log" | tr -d '\r' || true

# The assertions: the kernel booted, the drive mounted, zfs loaded, the ruleset went in.
log=$(tr -d '\r' < "$WORK/console.log")
fail=0
want() { grep -a -q -F -x "$1" <<<"$log" || { echo "missing: $1"; fail=1; }; }
want "SMOKE kernel=$RELEASE"
want "SMOKE modules_mount=ok"
want "SMOKE zfs=loaded"
want "SMOKE zfs_version=$OPENZFS-1"   # the module is the pinned release: the userland must match it
want "SMOKE nft=ok"
want "SMOKE done"
cpus=$(sed -n 's/^SMOKE vmx_svm_cpus=//p' <<<"$log")
if [ "${cpus:-0}" -gt 0 ]; then want "SMOKE kvm_dev=present"; fi
if [ "$fail" = 1 ]; then echo "--- console tail"; tail -n 80 "$WORK/console.log"; exit 1; fi

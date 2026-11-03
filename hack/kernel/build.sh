#!/usr/bin/env bash
# Builds the `nested` runtime class's guest kernel and its ZFS modules (ADR 0088):
#   build.sh [config|all]
# `config` stops after the kernel configuration is merged and checked. Output, in $OUT:
#   nested-vmlinux-x86_64  nested-modules-x86_64.ext4  nested-versions-x86_64.json  SHA256SUMS
# Needs: curl xz-utils gcc make flex bison bc libelf-dev libssl-dev kmod e2fsprogs fakeroot.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
BUILD=${BUILD:-$PWD/build}
OUT=${OUT:-$BUILD/out}
JOBS=${JOBS:-$(nproc)}

# Pinned sources. The kernel is the version of the pinned Firecracker CI kernel
# (hack/bootstrap-host.sh). OpenZFS 2.4.1 is the release of the guest image's zfsutils-linux;
# its META says Linux-Maximum: 6.19.
LINUX_VERSION=6.18.54
LINUX_SHA256=9df30b02dd8102bbd0be52556288ef6889ddbe7f1ddb96fbf847d0becf3eacac
LINUX_URL=https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$LINUX_VERSION.tar.xz
ZFS_VERSION=2.4.1
ZFS_SHA256=c17b69770f0023154f578eb8c7536a70f07d6a3bb0bd38f04fa0e8811c3c1390
ZFS_URL=https://github.com/openzfs/zfs/releases/download/zfs-$ZFS_VERSION/zfs-$ZFS_VERSION.tar.gz
# The base config is the pinned kernel's own; its first 5 lines are our header.
BASE_SHA256=7dbdc7445d01d3dd049b1e653534bde71266d59afaf9c1de50a8a6b8a8c138d0

# Fixed identity, so the same sources build the same bytes.
export KBUILD_BUILD_TIMESTAMP='Thu Jan  1 00:00:00 UTC 1970'
export KBUILD_BUILD_USER=briqyard KBUILD_BUILD_HOST=briqyard KBUILD_BUILD_VERSION=1
export SOURCE_DATE_EPOCH=0 E2FSPROGS_FAKE_TIME=0 ARCH=x86_64 LC_ALL=C TZ=UTC

[ "$(uname -m)" = x86_64 ] || { echo "build.sh builds x86_64 on x86_64, this is $(uname -m)" >&2; exit 1; }

step() { printf '\n== %s (%ss)\n' "$1" "$SECONDS"; }

fetch() { # url sha256 file
  [ -f "$3" ] && echo "$2  $3" | sha256sum -c --status 2>/dev/null && return 0
  curl -fsSL --retry 3 -o "$3" "$1"
  echo "$2  $3" | sha256sum -c -
}

mkdir -p "$BUILD/dl" "$OUT"
KDIR=$BUILD/linux-$LINUX_VERSION

step "base config"
[ "$(tail -n +6 "$HERE/base-x86_64.config" | sha256sum | cut -d' ' -f1)" = "$BASE_SHA256" ] \
  || { echo "base-x86_64.config does not match its recorded SHA-256" >&2; exit 1; }

step "kernel source"
fetch "$LINUX_URL" "$LINUX_SHA256" "$BUILD/dl/linux-$LINUX_VERSION.tar.xz"
if [ ! -f "$KDIR/Makefile" ]; then tar -xJf "$BUILD/dl/linux-$LINUX_VERSION.tar.xz" -C "$BUILD"; fi

step "kernel config"
cd "$KDIR"
rm -f .config
scripts/kconfig/merge_config.sh -m -O . "$HERE/base-x86_64.config" "$HERE/nested.config" >/dev/null
make olddefconfig
# Every option of the fragment must end up as written; olddefconfig drops, silently, what an
# unmet dependency or a renamed option leaves out.
bad=0
while IFS= read -r line; do
  case "$line" in
    CONFIG_*=*) grep -qxF "$line" .config || { echo "not as asked: $line (got: $(grep "^${line%%=*}[= ]" .config || echo absent))"; bad=1; } ;;
    "# CONFIG_"*" is not set")
      opt=${line#\# }; opt=${opt%% *}
      if grep -q "^$opt=" .config; then echo "not as asked: $line (got: $(grep "^$opt=" .config))"; bad=1; fi ;;
  esac
done < "$HERE/nested.config"
[ "$bad" = 0 ] || exit 1
echo "all options of nested.config are as asked"
RELEASE=$(make -s kernelrelease)
echo "kernel release $RELEASE"
[ "$RELEASE" = "$LINUX_VERSION-briqyard-nested" ] || { echo "unexpected release $RELEASE" >&2; exit 1; }
[ "${1:-all}" = config ] && exit 0

step "kernel build"
make -j"$JOBS" vmlinux modules
install -m 0644 vmlinux "$OUT/nested-vmlinux-x86_64"

step "OpenZFS $ZFS_VERSION"
fetch "$ZFS_URL" "$ZFS_SHA256" "$BUILD/dl/zfs-$ZFS_VERSION.tar.gz"
ZDIR=$BUILD/zfs-$ZFS_VERSION
rm -rf "$ZDIR"
tar -xzf "$BUILD/dl/zfs-$ZFS_VERSION.tar.gz" -C "$BUILD"
cd "$ZDIR"
./configure --with-config=kernel --with-linux="$KDIR" --with-linux-obj="$KDIR" >"$BUILD/zfs-configure.log" 2>&1 \
  || { tail -40 "$BUILD/zfs-configure.log"; exit 1; }
make -j"$JOBS"

step "modules tree"
STAGE=$BUILD/stage
rm -rf "$STAGE"
make -C "$KDIR" modules_install INSTALL_MOD_PATH="$STAGE" INSTALL_MOD_STRIP=1 DEPMOD=true
TREE=$STAGE/lib/modules/$RELEASE
rm -f "$TREE/build" "$TREE/source"
find "$ZDIR/module" -name '*.ko' | sort | while read -r ko; do
  install -D -m 0644 "$ko" "$TREE/extra/$(basename "$ko")"
  strip --strip-debug "$TREE/extra/$(basename "$ko")"
done
depmod -e -F "$KDIR/System.map" -b "$STAGE" "$RELEASE"
(cd "$TREE" && sha256sum extra/*.ko modules.dep)
grep -q '^extra/zfs.ko:' "$TREE/modules.dep" || { echo "zfs.ko is not in modules.dep" >&2; exit 1; }

step "modules.ext4"
find "$TREE" -exec touch -h -d @0 {} +
bytes=$(du -sb "$TREE" | cut -f1)
mib=$(( (bytes * 5 / 4) / 1048576 + 8 ))
rm -f "$OUT/nested-modules-x86_64.ext4"
truncate -s "${mib}M" "$OUT/nested-modules-x86_64.ext4"
fakeroot sh -c "chown -R 0:0 '$TREE' && mkfs.ext4 -F -q -L briqyard-modules \
  -U 8c1a3c5e-3b1d-4d1e-9d0a-6a1f0b1d0001 -E hash_seed=8c1a3c5e-3b1d-4d1e-9d0a-6a1f0b1d0002 \
  -O ^has_journal -m 0 -d '$TREE' '$OUT/nested-modules-x86_64.ext4'"
# mke2fs copies each file's change time, which is when it was last touched: zero them.
{
  (cd "$TREE" && find . -mindepth 1 | sed 's|^\.||') | while read -r p; do
    echo "sif \"$p\" ctime 0"; echo "sif \"$p\" ctime_extra 0"
  done
  echo "sif <2> ctime 0"; echo "sif <2> ctime_extra 0"
} | debugfs -w -f - "$OUT/nested-modules-x86_64.ext4" >/dev/null
e2fsck -fn "$OUT/nested-modules-x86_64.ext4"

step "versions and sums"
cat > "$OUT/nested-versions-x86_64.json" <<JSON
{
  "kernel_release": "$RELEASE",
  "kernel": "$LINUX_VERSION",
  "openzfs": "$ZFS_VERSION",
  "arch": "x86_64"
}
JSON
(cd "$OUT" && sha256sum nested-vmlinux-x86_64 nested-modules-x86_64.ext4 nested-versions-x86_64.json > SHA256SUMS && cat SHA256SUMS)
echo "built in ${SECONDS}s"

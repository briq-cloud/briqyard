#!/usr/bin/env bash
# Who holds a machine's datasets when its destroy answers "dataset is busy", for the nested
# rehearsal (hack/native-ci-nested-inner.sh): processes with a zvol open, mount namespaces that
# mount one, the datasets and their devices. Reads only.
#   native-ci-nested-holders.sh MACHINE_ID
set -u
id=${1:?machine id}
pool=${BRIQYARD_POOL:-byard}
echo "== $(date +%T) holders of $pool/m/$id"
zfs list -r -t all -o name,type,mounted,mountpoint,origin "$pool/m/$id" 2>&1 | cut -c1-200
echo "-- /dev/zvol links"
find "/dev/zvol/$pool/m/$id" -type l -exec sh -c 'for l; do echo "$l -> $(readlink -f "$l")"; done' sh {} + 2>&1 | head -n 10
devs=$(find "/dev/zvol/$pool/m/$id" -type l -exec readlink -f {} + 2>/dev/null | sed 's|/dev/||' | paste -sd'|' -)
echo "-- processes with one of them open (pid, comm, mount namespace, device)"
if [ -n "$devs" ]; then
  for p in /proc/[0-9]*; do
    for f in "$p"/fd/*; do
      t=$(readlink "$f" 2>/dev/null) || continue
      case "$t" in /dev/*) echo "${t#/dev/}" | grep -qE "^($devs)\$" && echo "${p#/proc/} $(cat "$p/comm" 2>/dev/null) $(readlink "$p/ns/mnt" 2>/dev/null) $t";; esac
    done
  done | sort -u | head -n 20
fi
echo "-- mount namespaces that mention the machine or its devices"
for p in /proc/[0-9]*; do
  if grep -qE "$id${devs:+|/dev/($devs)}" "$p/mountinfo" 2>/dev/null; then echo "${p#/proc/} $(cat "$p/comm" 2>/dev/null) $(readlink "$p/ns/mnt" 2>/dev/null)"; fi
done | sort -k3 -u | head -n 20
echo "-- holders in sysfs"
for d in $(echo "$devs" | tr '|' ' '); do echo "$d: $(ls "/sys/class/block/$d/holders" 2>&1 | paste -sd' ' -)"; done
echo "-- firecracker, jailer, udev, blkid processes"
ps -eo pid,ppid,stat,etime,comm,args | grep -E 'firecracker|jailer|udev|blkid|mkfs|e2fsck|resize2fs|mount' | grep -v grep | cut -c1-200 | head -n 20

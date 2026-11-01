#!/usr/bin/env bash
# Turns a fresh Ubuntu 26.04 server with KVM into a briqyard host: packages, a ZFS pool on one
# or two drives (or a file), Firecracker and a guest kernel, the briqyard binaries, the config,
# the systemd unit. Idempotent: run again with another BRIQYARD_RELEASE, it is the upgrade (the
# fleet's `host upgrade` does that, ADR 0027): a running daemon hands its machines over to the new
# one, which adopts them; nothing stops.
#
#   BRIQYARD_RELEASE=https://github.com/briq-cloud/briqyard/releases/download/v0.1.8 \
#   BRIQYARD_POOL_DEVICE=/dev/nvme0n1,/dev/nvme1n1 BRIQYARD_TOKEN=... FLEET_URL=https://fleet.example \
#   PRIVATE_ADDRESS=10.42.0.11/16 PRIVATE_INTERFACE=enp3s0f1 ALLOWED_CLIENTS=10.42.0.0/16 bash bootstrap-host.sh
#
# With FLEET_URL the host registers with the fleet, presenting BRIQYARD_TOKEN: the fleet must
# expect that token at ADVERTISE's address (the host's order, `host add`, or `hosts:` entry).
# Without BRIQYARD_RELEASE, the binaries are expected in ./bin (built with `make`);
# BRIQYARD_RELEASE_TOKEN reads a private repository's release through GitHub's API.
#
# The pool (ADR 0028): one device, or two as a mirror. A device is a whole disk, a partition, or
# a disk the OS is installed on, whose largest free space becomes a partition for the pool.
# A device that holds a mounted filesystem, swap, any filesystem or a pool not imported is
# refused: nothing is overwritten.
#
# The API and the endpoints listen on LISTEN's address: PRIVATE_ADDRESS's when it is set (a
# private network such as OVH's vRack), else 0.0.0.0:7420. A public address needs
# ALLOWED_CLIENTS (comma-separated IPv4 CIDRs: the fleet's and the routers' networks) or
# ALLOW_PUBLIC=1 (a firewall of your own); with neither, they bind loopback. With
# PRIVATE_ADDRESS, the public interface takes SSH and PUBLIC_TCP_PORTS only. Machines reach
# PUBLIC_TCP_PORTS on the host as the internet does (`network.host_ports`: an edge beside it).
# FLEET_ADDRESS, the fleet's private address: FLEET_URL's name resolves to it here (/etc/hosts),
# so the host's calls reach the fleet from the private address the fleet knows it by.
# Off loopback the API serves TLS with a certificate of its own (ADR 0020): the script prints
# its fingerprint, which the fleet pins (`tls_fingerprint` in the host's `hosts:` entry).
#
# The pool is encrypted at its creation (ADR 0026), with the host's key: with FLEET_URL the
# fleet's, asked with BRIQYARD_TOKEN and never written here; without, a key made into
# BRIQYARD_KEY_FILE (/etc/briqyard/pool.key, 0600). Swap is turned off for good: guest memory
# paged out would reach a disk in clear.
set -euo pipefail
POOL=${BRIQYARD_POOL:-byard}
POOL_DEVICE=${BRIQYARD_POOL_DEVICE:-}
POOL_FILE_GB=${BRIQYARD_POOL_FILE_GB:-50}
RELEASE=${BRIQYARD_RELEASE:-}
RELEASE_TOKEN=${BRIQYARD_RELEASE_TOKEN:-}
FLEET_URL=${FLEET_URL:-}
ADVERTISE=${ADVERTISE:-}
API_TOKEN=${BRIQYARD_TOKEN:-}
PRIVATE_ADDRESS=${PRIVATE_ADDRESS:-}
PRIVATE_INTERFACE=${PRIVATE_INTERFACE:-}
PUBLIC_TCP_PORTS=${PUBLIC_TCP_PORTS:-}
FLEET_ADDRESS=${FLEET_ADDRESS:-}
if [ -n "$PRIVATE_ADDRESS" ]; then LISTEN=${LISTEN:-${PRIVATE_ADDRESS%/*}:7420}; else LISTEN=${LISTEN:-0.0.0.0:7420}; fi
ALLOWED_CLIENTS=${ALLOWED_CLIENTS:-}
ALLOW_PUBLIC=${ALLOW_PUBLIC:-}
ARC_GB=${BRIQYARD_ARC_GB:-}
KEY_FILE=${BRIQYARD_KEY_FILE:-/etc/briqyard/pool.key}
ARCH=$(uname -m)

# Release installs use their checked Firecracker bundle. Local ./bin installs use the pinned
# upstream archive below. Boot identity includes binary and kernel digests: version equality
# alone cannot establish snapshot compatibility. The kernel comes from Firecracker's CI bucket.
FIRECRACKER_VERSION=${FIRECRACKER_VERSION:-v1.17.0}
KERNEL_URL=${KERNEL_URL:-https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/20261016-5732b8331e1e-0/$ARCH/vmlinux-6.18.54}
case "$ARCH" in
  x86_64)
    FIRECRACKER_SHA256=${FIRECRACKER_SHA256:-06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558}
    KERNEL_SHA256=${KERNEL_SHA256:-445b3d0ed9650869e854656308d60e6cca773190526b037b45941cbf61910f0d}
    ;;
  aarch64)
    FIRECRACKER_SHA256=${FIRECRACKER_SHA256:-e351ebe4f7a16b5873bbd51005d2e6767103cff4d5ebc829df2d3f95a93e2256}
    KERNEL_SHA256=${KERNEL_SHA256:-cfbfd2028adfd76e8ede9e56f18034c40f206c3afb2a529c04755bd17c144ba1}
    ;;
  *) echo "no Firecracker build for $ARCH"; exit 1 ;;
esac

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
[ -e /dev/kvm ] || { echo "/dev/kvm is missing: this server has no KVM"; exit 1; }
[ -n "$KERNEL_SHA256" ] || { echo "KERNEL_SHA256 is not pinned for $ARCH: set it to the sha256sum of $KERNEL_URL"; exit 1; }
# The token goes into a configuration written now, and asks the fleet for the pool's key; an
# upgrade (a configuration there, the pool open) needs neither (ADR 0027).
[ -z "$FLEET_URL" ] || [ -n "$API_TOKEN" ] || [ -f /etc/briqyard/config.yaml ] || { echo "FLEET_URL needs BRIQYARD_TOKEN: the host's own, which the fleet expects"; exit 1; }

# Loopback or RFC 1918: reachable from this host or its private network only.
private() {
  case "${1#[}" in 127.*|10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|::1]*|::1|f[cd]*:*|fe80:*) return 0 ;; esac
  return 1
}
# Where the API and the endpoints listen, who may reach them, and the URL the fleet knows the
# host at, with the scheme the API serves (TLS off loopback).
bind=${LISTEN%:*}
clients=""
if [ -n "$ALLOWED_CLIENTS" ]; then
  clients="  allowed_clients: [${ALLOWED_CLIENTS//,/, }]"
elif [ "$ALLOW_PUBLIC" = 1 ]; then
  clients="  allow_public: true"
elif ! private "$bind"; then
  # A host nobody can reach over a public bind, until the operator says who may.
  echo "   LISTEN=$LISTEN is public and neither ALLOWED_CLIENTS nor ALLOW_PUBLIC is set: binding loopback"
  bind=127.0.0.1
fi
scheme=https
case "$bind" in 127.*) scheme=http ;; esac
# The address the fleet knows the host at: the bound one, or the first one when bound to all.
# The fleet's key route matches it against the host's record.
advertise=${ADVERTISE:-$scheme://$([ "$bind" = 0.0.0.0 ] && hostname -I | awk '{print $1}' || echo "$bind"):7420}
# The token and the pool's key cross the link to the fleet (ADR 0026): plain HTTP only to a
# loopback or private address, as the daemon checks.
case "$FLEET_URL" in
  http://*)
    fleet_host=${FLEET_URL#http://}; fleet_host=${fleet_host%%/*}
    case "$fleet_host" in \[*) fleet_host=${fleet_host%%]*}] ;; *) fleet_host=${fleet_host%:*} ;; esac
    private "$fleet_host" || { echo "FLEET_URL=$FLEET_URL is plain HTTP to an address the internet could reach: write https://, or a private address"; exit 1; }
    ;;
esac

# Puts an executable in place by a rename: a running binary (the daemon, the fleet, Firecracker)
# is replaced, never written into.
put() {
  install -m 0755 "$1" "$2.new"
  mv -f "$2.new" "$2"
}

fail() { echo "   $*" >&2; exit 1; }

# Downloads a file and checks its digest against the pin before it lands anywhere.
fetch() {
  local url=$1 sha=$2 dest=$3 tmp
  tmp=$(mktemp)
  curl -fsSL -o "$tmp" "$url"
  echo "$sha  $tmp" | sha256sum -c --quiet - || { rm -f "$tmp"; echo "   $url: digest differs from the pin"; exit 1; }
  mv "$tmp" "$dest"
}

echo "== packages"
# needrestart, run by apt's hook (unattended upgrades included), restarts a service that maps a
# library just updated: the daemon's restart suspends every machine (ADR 0050). Written always
# (needrestart installed later reads it too), before the install below, which can update a
# library the running daemon maps.
mkdir -p /etc/needrestart/conf.d
cat > /etc/needrestart/conf.d/briqyard.conf <<'EOF'
# briqyard (ADR 0050): never restarted after a library update; a hand-over (`briqyard host
# upgrade`) or a reboot picks the update up.
$nrconf{override_rc}{qr(^briqyardd\.service$)} = 0;
$nrconf{override_rc}{qr(^briqyard-fleet\.service$)} = 0;
EOF
echo "   needrestart leaves briqyardd and briqyard-fleet running"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq zfsutils-linux nftables conntrack e2fsprogs gdisk curl jq ca-certificates python3 python3-yaml >/dev/null
modprobe zfs

# The ARC is a cache the kernel must shrink when a machine touches its memory: capped, it
# does not compete with the machines, and the daemon leaves the cap out of its capacity.
echo "== zfs cache"
if [ -z "$ARC_GB" ]; then
  ARC_GB=$(( $(awk '/^MemTotal:/ {print $2}' /proc/meminfo) / 1048576 / 10 ))
  [ "$ARC_GB" -ge 1 ] || ARC_GB=1
  [ "$ARC_GB" -le 16 ] || ARC_GB=16
fi
echo "options zfs zfs_arc_max=$((ARC_GB << 30))" > /etc/modprobe.d/briqyard-zfs.conf
echo "$((ARC_GB << 30))" > /sys/module/zfs/parameters/zfs_arc_max
echo "   at most $ARC_GB GB"

echo "== no swap"
# Guest memory the kernel pages out would land on a disk in clear (ADR 0026): swap goes, and
# stays gone across reboots (fstab lines commented out, swap units masked).
swapoff -a
sed -i -E 's|^([^#].*[[:space:]]swap[[:space:]].*)$|# briqyard, no swap: \1|' /etc/fstab
for unit in $(systemctl list-units --type swap --all --plain --no-legend | awk '{print $1}'); do
  systemctl mask "$unit" >/dev/null
done

echo "== no crash dumps"
# A kernel crash dump is the whole memory, guests' included, written to /var/crash in clear.
if dpkg -s kdump-tools >/dev/null 2>&1; then
  apt-get purge -y -qq kdump-tools >/dev/null
fi
if [ "$(cat /sys/kernel/kexec_crash_loaded 2>/dev/null || echo 0)" = 1 ]; then
  kexec -p -u 2>/dev/null || true
  if [ "$(cat /sys/kernel/kexec_crash_loaded)" = 1 ]; then
    echo "   a crash kernel is loaded (kdump) and could not be unloaded: its dump would hold guest memory in clear"
    exit 1
  fi
fi

# A private network (OVH's vRack): the API and the endpoints live on it; the public interface
# takes SSH and PUBLIC_TCP_PORTS only, and machines still reach the internet through it. Up
# before the pool: the fleet's key for it comes over this network.
if [ -n "$PRIVATE_ADDRESS" ]; then
  echo "== private network $PRIVATE_ADDRESS"
  case "$PRIVATE_ADDRESS" in */*) ;; *) fail "PRIVATE_ADDRESS=$PRIVATE_ADDRESS: with its prefix, as 10.42.0.11/16" ;; esac
  has_address() { ip -4 -o addr show | awk -v a="$PRIVATE_ADDRESS" '$4 == a {found = 1} END {exit !found}'; }
  if ! has_address; then
    [ -n "$PRIVATE_INTERFACE" ] || fail "no interface has $PRIVATE_ADDRESS: set PRIVATE_INTERFACE (the private network's, by its MAC in the provider's console)"
    ip link show "$PRIVATE_INTERFACE" >/dev/null || fail "no interface $PRIVATE_INTERFACE"
    command -v netplan >/dev/null || fail "no netplan: put $PRIVATE_ADDRESS on $PRIVATE_INTERFACE yourself"
    printf 'network:\n  version: 2\n  ethernets:\n    %s:\n      addresses: [%s]\n' "$PRIVATE_INTERFACE" "$PRIVATE_ADDRESS" > /etc/netplan/60-briqyard-private.yaml
    chmod 0600 /etc/netplan/60-briqyard-private.yaml
    netplan apply
    for _ in $(seq 1 30); do has_address && break; sleep 1; done
    has_address || fail "$PRIVATE_ADDRESS did not come up on $PRIVATE_INTERFACE"
  fi
  fleet_name=${FLEET_URL#*://}; fleet_name=${fleet_name%%/*}; fleet_name=${fleet_name%:*}
  sed -i '/# briqyard: the fleet$/d' /etc/hosts
  # A name only: an address in FLEET_URL (IPv6 in brackets, whose hex has letters) is dialled
  # as it is.
  case "$fleet_name" in
    \[*) ;;
    *[a-zA-Z]*)
      if [ -n "$FLEET_ADDRESS" ]; then
        printf '%s %s # briqyard: the fleet\n' "$FLEET_ADDRESS" "$fleet_name" >> /etc/hosts
        echo "   $fleet_name at $FLEET_ADDRESS"
      fi
      ;;
  esac
  private_dev=$(ip -4 -o addr show | awk -v a="$PRIVATE_ADDRESS" '$4 == a {print $2; exit}')
  public_dev=$(ip -4 route show default | awk '{for (i = 1; i < NF; i++) if ($i == "dev") {print $(i + 1); exit}}')
  [ -n "$public_dev" ] || fail "no default route: machines would have no way to the internet"
  [ "$public_dev" != "$private_dev" ] || fail "the default route goes through $private_dev, the private interface"
  # One firewall owner per host (ADR 0028): an edge on this host runs its bootstrap after.
  ! nft list table inet briq_edge >/dev/null 2>&1 || fail "an edge's firewall (table inet briq_edge) is loaded: run its bootstrap after this one"
  # A table of its own, loaded before the network at every boot; the daemon's are apart.
  # SSH's own ports, as sshd runs them: a literal 22 would lock out a server on another.
  ssh_ports=$(sshd -T 2>/dev/null | awk '$1 == "port" {print $2}' | paste -sd, -)
  [ -n "$ssh_ports" ] || fail "sshd -T names no port: closing the public interface would close SSH"
  ports=$ssh_ports${PUBLIC_TCP_PORTS:+,$PUBLIC_TCP_PORTS}
  mkdir -p /etc/briqyard
  cat > /etc/briqyard/firewall.nft <<EOF
table inet briqyard_host
delete table inet briqyard_host
table inet briqyard_host {
	chain input {
		type filter hook input priority 0; policy accept;
		iifname != "$public_dev" accept
		ct state established,related accept
		meta l4proto { icmp, ipv6-icmp } accept
		udp sport 67 udp dport 68 accept
		udp sport 547 udp dport 546 accept
		tcp dport { ${ports//,/, } } accept
		counter drop
	}
}
EOF
  cat > /etc/systemd/system/briqyard-firewall.service <<'EOF'
[Unit]
Description=briqyard: the public interface takes SSH and the ports named
DefaultDependencies=no
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/briqyard/firewall.nft

[Install]
WantedBy=sysinit.target
EOF
  systemctl daemon-reload
  systemctl enable briqyard-firewall >/dev/null 2>&1
  systemctl restart briqyard-firewall
  echo "   public $public_dev: tcp $ports in, nothing else; private $private_dev"
fi

# The partition labelled briqyard-pool on a disk, if it has one.
pool_partition() { lsblk -nro PATH,PARTLABEL "$1" | awk '$2 == "briqyard-pool" {print $1; exit}'; }

# The device a pool member is: a partition as it is; a disk as it is when nothing is on it; a
# disk with partitions (the OS on part of it) gets one in its largest free space, labelled
# briqyard-pool and found by that label on a later run. Never a device in use.
pool_device() {
  local dev start end sector out used sig uuid
  dev=$(readlink -f "$1")
  [ -b "$dev" ] || fail "$1 is not a block device"
  if [ "$(lsblk -dno TYPE "$dev")" != part ] && [ -n "$(lsblk -nro TYPE "$dev" | awk '$1 == "part"')" ]; then
    if [ -z "$(pool_partition "$dev")" ]; then
      [ "$(blkid -p -o value -s PTTYPE "$dev")" = gpt ] || fail "$1 has partitions but no GPT: name a partition for the pool"
      start=$(sgdisk -F "$dev"); end=$(sgdisk -E "$dev"); sector=$(blockdev --getss "$dev")
      [ $(( (end - start) * sector )) -ge $((10 << 30)) ] || fail "$1 has under 10 GB free: leave the rest of the disk unpartitioned at install, or name a partition"
      # The kernel takes the new partition alone (partx): the OS's stay in use meanwhile.
      out=$(sgdisk -n "0:$start:$end" -t 0:bf01 -c 0:briqyard-pool "$dev" 2>&1) || echo "   sgdisk: $out" >&2
      partx -u "$dev" 2>/dev/null || true
      udevadm settle
      [ -n "$(pool_partition "$dev")" ] || fail "$1: no briqyard-pool partition after sgdisk"
      echo "   $1: $(pool_partition "$dev"), $(( (end - start) * sector >> 30 )) GB of free space" >&2
    fi
    dev=$(pool_partition "$dev")
  fi
  used=$(lsblk -nro MOUNTPOINTS "$dev" | grep . | paste -sd, - || true)
  [ -z "$used" ] || fail "$1 is in use (mounted at $used): the pool takes a device nothing uses"
  [ "$(lsblk -nro NAME "$dev" | wc -l)" = 1 ] || fail "$1 is in use by $(lsblk -nro NAME "$dev" | sed 1d | paste -sd, -) (RAID, LVM, partitions)"
  # Nothing is overwritten: a pool there is one not imported (a re-run, a reinstalled OS).
  sig=$(blkid -p -o value -s TYPE "$dev" 2>/dev/null || true)
  [ "$sig" != zfs_member ] || fail "$1 holds a pool: zpool import $POOL, or wipefs -a it if it is meant for a new one"
  [ -z "$sig" ] || fail "$1 holds $sig: wipefs -a it if it is meant for the pool"
  # A partition by its id: disk names may change order across reboots.
  uuid=$(lsblk -dno PARTUUID "$dev")
  if [ -n "$uuid" ] && [ -e "/dev/disk/by-partuuid/$uuid" ]; then echo "/dev/disk/by-partuuid/$uuid"; else echo "$dev"; fi
}

# The pool's key on stdout: the fleet's for this host, or the key file's. `pool_key make`
# makes the file when it is missing (a pool about to be created), never otherwise.
pool_key() {
  if [ -n "$FLEET_URL" ]; then
    [ -n "$API_TOKEN" ] || { echo "   the fleet's key needs BRIQYARD_TOKEN: the host's own" >&2; return 1; }
    # The token goes in on stdin, off the command line.
    printf 'Authorization: Bearer %s\n' "$API_TOKEN" |
      curl -fsS --max-time 20 -H @- -H 'Content-Type: application/json' \
        -d "{\"url\": \"$advertise\"}" "${FLEET_URL%/}/v1/hosts/key" | jq -er .key
  else
    if [ ! -f "$KEY_FILE" ] && [ "${1:-}" = make ]; then
      (umask 077; mkdir -p "$(dirname "$KEY_FILE")"; od -An -tx1 -N32 /dev/urandom | tr -d ' \n' > "$KEY_FILE")
      echo "   key made in $KEY_FILE: keep a copy off this host, the pool is unreadable without it" >&2
    fi
    tr -d ' \n' < "$KEY_FILE"
  fi
}

echo "== pool $POOL, encrypted"
if ! zpool list "$POOL" >/dev/null 2>&1; then
  vdevs=()
  if [ -n "$POOL_DEVICE" ]; then
    for d in ${POOL_DEVICE//,/ }; do
      dev=$(pool_device "$d") || exit 1
      vdevs+=("$dev")
    done
    # -f for a mirror of two sizes alone (a disk's free space beside a whole disk): every
    # member was checked to hold nothing above.
    case ${#vdevs[@]} in
      1) ;;
      2) vdevs=(-f mirror "${vdevs[@]}") ;;
      *) fail "BRIQYARD_POOL_DEVICE names ${#vdevs[@]} devices: one, or two for a mirror" ;;
    esac
  else
    mkdir -p /var/lib/briqyard
    truncate -s "${POOL_FILE_GB}G" /var/lib/briqyard/pool.img
    vdevs=(/var/lib/briqyard/pool.img)
    echo "   (a file-backed pool: fine for a trial, not for production)"
  fi
  key=$(pool_key make) || fail "no key for the pool (${FLEET_URL:-$KEY_FILE})"
  [ "${#key}" = 64 ] || fail "the pool's key is not 64 hex digits"
  # The key on stdin: in no file, on no command line.
  printf '%s\n' "$key" | zpool create -o ashift=12 -O compression=lz4 -O atime=off \
    -O encryption=aes-256-gcm -O keyformat=hex -O keylocation=prompt "$POOL" "${vdevs[@]}"
  unset key
  echo "   ${vdevs[*]}"
fi
if [ "$(zfs get -H -o value encryption "$POOL")" = off ]; then
  echo "   pool $POOL is not encrypted (ADR 0026): ZFS cannot encrypt a pool after its creation."
  echo "   Move what it holds elsewhere, destroy it, and run this script again."
  exit 1
fi
# A pool that exists, locked (a reboot): its key from the same source, checked now rather
# than at the daemon's start.
if [ "$(zfs get -H -o value keystatus "$POOL")" = unavailable ] && [ -z "$FLEET_URL" ] &&
  grep -qx '  key: fleet' /etc/briqyard/config.yaml 2>/dev/null; then
  echo "   pool $POOL is locked: the daemon asks the fleet for its key at its start"
elif [ "$(zfs get -H -o value keystatus "$POOL")" = unavailable ]; then
  root=$(zfs get -H -o value encryptionroot "$POOL")
  key=$(pool_key) || { echo "   pool $POOL is locked and its key could not be read (${FLEET_URL:-$KEY_FILE})"; exit 1; }
  if ! out=$(printf '%s\n' "$key" | zfs load-key -L prompt "$root" 2>&1); then
    echo "   pool $POOL is locked and its key (${FLEET_URL:-$KEY_FILE}) does not open it: $out"
    echo "   The pool was made with another key: the fleet's registry lost or replaced, or another key file."
    exit 1
  fi
  unset key
  echo "   key loaded"
fi

# Runtime installation helpers. Kept here because the fleet embeds this standalone script.
checked_bundle() {
  python3 - "$@" <<'PY'
import hashlib
import json
from pathlib import Path
import re
import sys
import tarfile

bundle, arch, destination = sys.argv[1:]
with tarfile.open(bundle, "r:gz") as archive:
    members = archive.getmembers()
    files = {}
    for member in members:
        if not member.isfile() or member.name in files or not re.fullmatch(r"[A-Za-z0-9_.-]+", member.name):
            raise ValueError("unsafe or duplicate runtime package member")
        files[member.name] = archive.extractfile(member).read()
    pin = json.loads(files["pin.json"])
    provenance = json.loads(files["provenance.json"])
    receipt = json.loads(files["receipt.json"])
    required = {"firecracker", "jailer", "seccomp_filter.bpf", "seccomp-source.json",
                "provenance.json", "receipt.json", "pin.json", "series", "uapi-inputs.json",
                "LICENSE", "NOTICE", "THIRD-PARTY"} | {p["path"] for p in pin["series"]}
    if set(files) != required or any(not data for data in files.values()):
        raise ValueError("incomplete runtime package")
    if (provenance["status"] != "static-cli-candidate-built"
            or provenance["architecture"] != arch
            or provenance["target"] != arch + "-unknown-linux-musl"
            or provenance["base"] != pin["base"] or provenance["tree"] != pin["tree"]
            or provenance["series_sha256"] != pin["series_concatenated_sha256"]
            or receipt["status"] != "portable-validation-passed"
            or receipt["architecture"] != arch or receipt["base"] != pin["base"]
            or receipt["tree"] != pin["tree"] or receipt["toolchain"] != pin["toolchain"]):
        raise ValueError("runtime provenance or validation mismatch")
    expected = {name: provenance["binaries"][name] for name in ("firecracker", "jailer")}
    expected.update({"seccomp_filter.bpf": provenance["seccomp"]["compiled"],
                     "seccomp-source.json": provenance["seccomp"]["source"],
                     "uapi-inputs.json": provenance["uapi_inputs"],
                     "series": {"sha256": pin["series_file_sha256"]}})
    expected.update({p["path"]: p for p in pin["series"]})
    for name, record in expected.items():
        data = files[name]
        if hashlib.sha256(data).hexdigest() != record["sha256"] or len(data) != record.get("bytes", len(data)):
            raise ValueError("runtime digest mismatch: " + name)
    patches = pin["series"]
    if (files["series"].decode("ascii").splitlines() != [p["path"] for p in patches]
            or hashlib.sha256(b"".join(files[p["path"]] for p in patches)).hexdigest() != pin["series_concatenated_sha256"]):
        raise ValueError("runtime patch series mismatch")
    # No archive paths, links or modes are used. All checks precede the first write.
    root = Path(destination)
    root.mkdir(mode=0o700)
    for name, data in files.items():
        (root / name).write_bytes(data)
PY
}

# Each cached hash keeps referring to these bytes while an old daemon or builder finishes.
# Never overwrite an existing digest path, even on a same-version reinstall.
immutable_runtime() {
  local source=$1 name=$2 digest target temporary
  digest=$(sha256sum "$source" | awk '{print $1}') || fail "cannot hash runtime input"
  target="$runtime_root/$digest/$name"
  mkdir -p "$runtime_root/$digest" || fail "cannot create runtime directory"
  if [ -e "$target" ] || [ -L "$target" ]; then
    [ ! -L "$target" ] && echo "$digest  $target" | sha256sum -c --quiet - || fail "immutable runtime input differs: $target"
  else
    temporary=$(mktemp "$runtime_root/$digest/.stage.XXXXXX") || fail "cannot stage runtime input"
    install -m 0555 "$source" "$temporary" || { rm -f "$temporary"; fail "cannot install runtime input"; }
    echo "$digest  $temporary" | sha256sum -c --quiet - || { rm -f "$temporary"; fail "staged runtime digest differs"; }
    # A concurrent staging attempt may have installed the same bytes. Never replace them.
    if ! ln "$temporary" "$target" 2>/dev/null; then
      [ ! -L "$target" ] && echo "$digest  $target" | sha256sum -c --quiet - || { rm -f "$temporary"; fail "immutable runtime input differs"; }
    fi
    rm -f "$temporary"
  fi
  echo "$target"
}

runtime_config() {
  python3 - "$@" <<'PY'
from pathlib import Path
import sys
import yaml

path = Path(sys.argv[1])
config = yaml.safe_load(path.read_text())
if not isinstance(config, dict):
    raise ValueError("configuration must be a mapping")
config.update(zip(("firecracker", "jailer", "kernel", "init"), sys.argv[2:]))
path.write_text(yaml.safe_dump(config, sort_keys=False))
PY
}
# End runtime installation helpers.

# A request to GitHub's API with BRIQYARD_RELEASE_TOKEN, the token on stdin, off the command line.
github() { printf 'Authorization: Bearer %s\n' "$RELEASE_TOKEN" | curl -fsSL -H @- "$@"; }

# A file of the release. With BRIQYARD_RELEASE_TOKEN, through GitHub's API: a private
# repository's assets are not served at their download URL.
# `assets` is the release's JSON from GitHub's API, read once below when there is a token.
release_file() {
  local name=$1 dest=$2 id
  if [ -z "$RELEASE_TOKEN" ]; then curl -fsSL -o "$dest" "$RELEASE/$name"; return; fi
  id=$(jq -r --arg n "$name" '.assets[] | select(.name == $n) | .id' <<<"$assets")
  [ -n "$id" ] || fail "release $tag of $repo has no $name"
  github -H "Accept: application/octet-stream" -o "$dest" "https://api.github.com/repos/$repo/releases/assets/$id"
}

echo "== binaries${RELEASE:+ from $RELEASE}"
new=$(mktemp -d)
candidate=""
trap 'rm -rf "$new"; [ -z "$candidate" ] || rm -f "$candidate"' EXIT
if [ -n "$RELEASE" ]; then
  if [ -n "$RELEASE_TOKEN" ]; then
    repo=${RELEASE#https://github.com/}; tag=${repo##*/releases/download/}; repo=${repo%%/releases/download/*}
    [ "$repo" != "$tag" ] || fail "BRIQYARD_RELEASE=$RELEASE: with a token, a GitHub release (https://github.com/<owner>/<repo>/releases/download/<tag>)"
    assets=$(github "https://api.github.com/repos/$repo/releases/tags/$tag")
  fi
  release_file "SHA256SUMS-$ARCH" "$new/SHA256SUMS"
  # Check the complete release before staging any executable or changing configuration.
  for b in briqyardd briqyard-init briqyard briqyard-fleet firecracker-checked; do
    asset="$b-linux-$ARCH"
    [ "$b" != firecracker-checked ] || asset="$asset.tar.gz"
    release_file "$asset" "$new/$b"
    sha=$(awk -v f="$asset" '$2 == f {print $1}' "$new/SHA256SUMS")
    [[ "$sha" =~ ^[a-f0-9]{64}$ ]] && echo "$sha  $new/$b" | sha256sum -c --quiet - 2>/dev/null || fail "$asset: digest differs from the release's SHA256SUMS-$ARCH"
  done
  checked_bundle "$new/firecracker-checked" "$ARCH" "$new/checked"
  cp "$new/checked/firecracker" "$new/firecracker"
  cp "$new/checked/jailer" "$new/jailer"
else
  for b in briqyardd briqyard-init briqyard briqyard-fleet; do cp "bin/$b" "$new/$b"; done
  # Local development keeps the pinned upstream runtime; release installs require checked assets.
  fetch "https://github.com/firecracker-microvm/firecracker/releases/download/${FIRECRACKER_VERSION}/firecracker-${FIRECRACKER_VERSION}-${ARCH}.tgz" "$FIRECRACKER_SHA256" "$new/firecracker.tgz"
  tar -xz -C "$new" -f "$new/firecracker.tgz"
  cp "$new/release-${FIRECRACKER_VERSION}-${ARCH}/firecracker-${FIRECRACKER_VERSION}-${ARCH}" "$new/firecracker"
  cp "$new/release-${FIRECRACKER_VERSION}-${ARCH}/jailer-${FIRECRACKER_VERSION}-${ARCH}" "$new/jailer"
fi
chmod 0755 "$new"/briq*
runtime_root=/usr/local/lib/briqyard/runtime
firecracker=$(immutable_runtime "$new/firecracker" firecracker)
jailer=$(immutable_runtime "$new/jailer" jailer)
init=$(immutable_runtime "$new/briqyard-init" briqyard-init)
# Keep the configured kernel path when its digest is unchanged. Never replace its bytes.
kernel=/var/lib/briqyard/vmlinux
if [ -f /etc/briqyard/config.yaml ]; then
  kernel=$(python3 -c 'import sys,yaml; print(yaml.safe_load(open(sys.argv[1])).get("kernel", "/var/lib/briqyard/vmlinux"))' /etc/briqyard/config.yaml)
fi
if ! echo "$KERNEL_SHA256  $kernel" | sha256sum -c --quiet - 2>/dev/null; then
  fetch "$KERNEL_URL" "$KERNEL_SHA256" "$new/vmlinux"
  kernel=$(immutable_runtime "$new/vmlinux" vmlinux)
fi

echo "== config"
mkdir -p /etc/briqyard
chmod 0700 /etc/briqyard
candidate=$(mktemp /etc/briqyard/.config.XXXXXX)
if [ -f /etc/briqyard/config.yaml ]; then
  cp /etc/briqyard/config.yaml "$candidate"
else
  key_source=fleet
  [ -n "$FLEET_URL" ] || key_source="file:$KEY_FILE"
  cat > "$candidate" <<EOF
listen: $bind:${LISTEN##*:}
token: "$API_TOKEN"
data_dir: /var/lib/briqyard
firecracker: $firecracker
jailer: $jailer
kernel: $kernel
init: $init
root_disk_gb: 8
storage:
  backend: zfs
  pool: $POOL
  key: $key_source
network:
  range: 10.64.0.0/10
${PUBLIC_TCP_PORTS:+  host_ports: [${PUBLIC_TCP_PORTS//,/, }]}
ingress:
  bind: $bind
  http: $bind:8080
  domain: byard.localhost
EOF
  [ -z "$clients" ] || echo "$clients" >> "$candidate"
  if [ -n "$FLEET_URL" ]; then
    cat >> "$candidate" <<EOF
fleet:
  url: $FLEET_URL
  advertise: $advertise
EOF
  fi
fi
# One candidate contains all changed launch paths. Validate it with the staged daemon.
runtime_config "$candidate" "$firecracker" "$jailer" "$kernel" "$init"
chmod 0600 "$candidate"
fingerprint=$("$new/briqyardd" --config "$candidate" tls-fingerprint) || fail "the new briqyardd refuses the staged configuration: nothing activated"
# Init and the runtime inputs stay at immutable paths. The old daemon may still read them.
for b in briqyard briqyard-fleet briqyardd; do put "$new/$b" "/usr/local/bin/$b"; done
if [ -f /etc/briqyard/config.yaml ]; then
  config_sha=$(sha256sum /etc/briqyard/config.yaml | awk '{print $1}')
  backup="/etc/briqyard/config.yaml.before-$config_sha"
  [ -e "$backup" ] || cp -p /etc/briqyard/config.yaml "$backup"
fi
# The rename is on the configuration filesystem, before the existing SIGUSR2 handover.
mv -f "$candidate" /etc/briqyard/config.yaml
candidate=""

echo "== api certificate"
# Made here, before the daemon starts, so it is there to read; kept across runs. It is also the
# new binary reading the configuration: one it refuses stops here, before any hand-over, and the
# running daemon goes on (ADR 0027).

if [ -n "$fingerprint" ]; then
  echo "   sha256 $fingerprint: the fleet pins it (tls_fingerprint)"
else
  echo "   none: the API is plain HTTP (a loopback listen, or api_tls: false)"
fi
# The store of listening sockets holds the API's, the HTTP ingress's and one per TCP endpoint
# (ADR 0051): the endpoint range and two. A range made larger later needs this run again: past
# the store's size systemd refuses a socket, and that endpoint is refused while no daemon runs.
range=$(awk '/^  tcp_ports:/ {gsub(/["\047 ]/, "", $2); print $2}' /etc/briqyard/config.yaml)
range=${range:-30000-32767}
store_max=$(( ${range#*-} - ${range%-*} + 3 ))
cat > /etc/systemd/system/briqyardd.service <<EOF
[Unit]
Description=briqyard host daemon
After=network-online.target zfs.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/briqyardd --config /etc/briqyard/config.yaml
# Only the daemon gets the signal: the machines (Firecracker processes in this cgroup) outlive
# it. A stop (SIGTERM) suspends them, and the next start boots them again; SIGUSR2 (an upgrade)
# leaves them running for the next daemon to adopt; a crash leaves them too (ADR 0027).
KillMode=process
Restart=on-failure
# At once: a crash loop still ends at StartLimitBurst (5 starts in 10 s), which releases the
# store below, and the clients it queued are reset.
RestartSec=0
# A hand-over exits 75: started again at once, not a failure. systemd keeps the store of
# listening sockets across a restart, so the kernel queues what arrives in between (ADR 0051).
SuccessExitStatus=75
RestartForceExitStatus=75
NotifyAccess=main
FileDescriptorStoreMax=$store_max
LimitNOFILE=65536
# A core dump of a Firecracker would be its guest's memory, on / in clear (ADR 0026).
LimitCORE=0
Environment=BRIQYARD_LOG=info
# Credentials (BRIQYARD_S3_ACCESS_KEY, BRIQYARD_S3_SECRET_KEY), root's alone, when there is one;
# written by the operator, read at the next start: a hand-over, never a restart (ADR 0041).
EnvironmentFile=-/etc/briqyard/briqyardd.env

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable briqyardd >/dev/null
# A running daemon hands its machines over (SIGUSR2, ADR 0027) and exits 75, on which the unit
# starts the new one at once, the listeners kept (ADR 0051); the new one adopts the machines. The
# start below covers a daemon from before ADR 0051, which exits 0. `systemctl restart` would
# suspend every machine instead.
pid=$(systemctl show -p MainPID --value briqyardd)
if [ "${pid:-0}" != 0 ]; then
  echo "== handing the machines over to the new daemon"
  systemctl kill --kill-whom=main --signal=SIGUSR2 briqyardd
  for _ in $(seq 1 120); do [ "$(systemctl show -p MainPID --value briqyardd)" = "$pid" ] || break; sleep 1; done
  [ "$(systemctl show -p MainPID --value briqyardd)" != "$pid" ] || { echo "   briqyardd (pid $pid) did not exit within 120 s"; exit 1; }
fi
systemctl start briqyardd
sleep 1
systemctl --no-pager --lines=2 status briqyardd | grep -E "Active|listening" || true
echo "== done: $(/usr/local/bin/briqyardd --version)"

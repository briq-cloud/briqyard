#!/usr/bin/env bash
# Turns a fresh Ubuntu 24.04+ server with KVM into a briqyard host: packages, a ZFS pool on the
# second drive (or a file), Firecracker and a guest kernel, the briqyard binaries, the config,
# the systemd unit. Idempotent: run it again to upgrade.
#
#   BRIQYARD_RELEASE=https://github.com/briq-cloud/briqyard/releases/download/v0.1.0 \
#   BRIQYARD_POOL_DEVICE=/dev/nvme1n1 BRIQYARD_TOKEN=... FLEET_URL=https://fleet.example \
#   ADVERTISE=https://10.0.0.5:7420 ALLOWED_CLIENTS=10.0.0.0/8 bash bootstrap-host.sh
#
# With FLEET_URL the host registers with the fleet, presenting BRIQYARD_TOKEN: the fleet must
# expect that token at ADVERTISE's address (the host's order, or its `hosts:` entry).
# Without BRIQYARD_RELEASE, the binaries are expected in ./bin (built with `make`).
#
# The API and the endpoints listen on LISTEN's address (0.0.0.0:7420 by default). A public
# address needs ALLOWED_CLIENTS (comma-separated IPv4 CIDRs: the fleet's and the routers'
# networks) or ALLOW_PUBLIC=1 (a firewall of your own); with neither, they bind loopback.
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
FLEET_URL=${FLEET_URL:-}
ADVERTISE=${ADVERTISE:-}
API_TOKEN=${BRIQYARD_TOKEN:-}
LISTEN=${LISTEN:-0.0.0.0:7420}
ALLOWED_CLIENTS=${ALLOWED_CLIENTS:-}
ALLOW_PUBLIC=${ALLOW_PUBLIC:-}
KEY_FILE=${BRIQYARD_KEY_FILE:-/etc/briqyard/pool.key}
ARCH=$(uname -m)

# Every host runs the same Firecracker and guest kernel: a memory snapshot only resumes under
# the Firecracker that wrote it, and the CI kernel's config is not ours. Bump the three
# together, with their digests. The kernel comes from Firecracker's CI bucket until we host it.
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
[ -z "$FLEET_URL" ] || [ -n "$API_TOKEN" ] || { echo "FLEET_URL needs BRIQYARD_TOKEN: the host's own, which the fleet expects"; exit 1; }

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
advertise=${ADVERTISE:-$scheme://$(hostname -I | awk '{print $1}'):7420}
# The token and the pool's key cross the link to the fleet (ADR 0026): plain HTTP only to a
# loopback or private address, as the daemon checks.
case "$FLEET_URL" in
  http://*)
    fleet_host=${FLEET_URL#http://}; fleet_host=${fleet_host%%/*}
    case "$fleet_host" in \[*) fleet_host=${fleet_host%%]*}] ;; *) fleet_host=${fleet_host%:*} ;; esac
    private "$fleet_host" || { echo "FLEET_URL=$FLEET_URL is plain HTTP to an address the internet could reach: write https://, or a private address"; exit 1; }
    ;;
esac

# Downloads a file and checks its digest against the pin before it lands anywhere.
fetch() {
  local url=$1 sha=$2 dest=$3 tmp
  tmp=$(mktemp)
  curl -fsSL -o "$tmp" "$url"
  echo "$sha  $tmp" | sha256sum -c --quiet - || { rm -f "$tmp"; echo "   $url: digest differs from the pin"; exit 1; }
  mv "$tmp" "$dest"
}

echo "== packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq zfsutils-linux nftables e2fsprogs curl jq ca-certificates >/dev/null
modprobe zfs

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

# The pool's key on stdout: the fleet's for this host, or the key file's. `pool_key make`
# makes the file when it is missing (a pool about to be created), never otherwise.
pool_key() {
  if [ -n "$FLEET_URL" ]; then
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
  key=$(pool_key make) || { echo "   no key for the pool (${FLEET_URL:-$KEY_FILE})"; exit 1; }
  [ "${#key}" = 64 ] || { echo "   the pool's key is not 64 hex digits"; exit 1; }
  if [ -n "$POOL_DEVICE" ]; then
    vdev=$POOL_DEVICE
  else
    mkdir -p /var/lib/briqyard
    truncate -s "${POOL_FILE_GB}G" /var/lib/briqyard/pool.img
    vdev=/var/lib/briqyard/pool.img
    echo "   (a file-backed pool: fine for a trial, not for production)"
  fi
  # The key on stdin: in no file, on no command line.
  printf '%s\n' "$key" | zpool create -f -o ashift=12 -O compression=lz4 -O atime=off \
    -O encryption=aes-256-gcm -O keyformat=hex -O keylocation=prompt "$POOL" "$vdev"
  unset key
fi
if [ "$(zfs get -H -o value encryption "$POOL")" = off ]; then
  echo "   pool $POOL is not encrypted (ADR 0026): ZFS cannot encrypt a pool after its creation."
  echo "   Move what it holds elsewhere, destroy it, and run this script again."
  exit 1
fi
# A pool that exists, locked (a reboot): its key from the same source, checked now rather
# than at the daemon's start.
if [ "$(zfs get -H -o value keystatus "$POOL")" = unavailable ]; then
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

echo "== firecracker $FIRECRACKER_VERSION and a guest kernel"
mkdir -p /var/lib/briqyard
if [ "$(/usr/local/bin/firecracker --version 2>/dev/null | head -1)" != "Firecracker $FIRECRACKER_VERSION" ]; then
  fetch "https://github.com/firecracker-microvm/firecracker/releases/download/${FIRECRACKER_VERSION}/firecracker-${FIRECRACKER_VERSION}-${ARCH}.tgz" "$FIRECRACKER_SHA256" /tmp/firecracker.tgz
  tar -xz -C /tmp -f /tmp/firecracker.tgz
  rm -f /tmp/firecracker.tgz
  install -m 0755 "/tmp/release-${FIRECRACKER_VERSION}-${ARCH}/firecracker-${FIRECRACKER_VERSION}-${ARCH}" /usr/local/bin/firecracker
  install -m 0755 "/tmp/release-${FIRECRACKER_VERSION}-${ARCH}/jailer-${FIRECRACKER_VERSION}-${ARCH}" /usr/local/bin/jailer
  rm -rf "/tmp/release-${FIRECRACKER_VERSION}-${ARCH}"
fi
if ! echo "$KERNEL_SHA256  /var/lib/briqyard/vmlinux" | sha256sum -c --quiet - 2>/dev/null; then
  fetch "$KERNEL_URL" "$KERNEL_SHA256" /var/lib/briqyard/vmlinux
  chmod 0644 /var/lib/briqyard/vmlinux
  echo "   kernel ${KERNEL_URL##*/}"
fi

echo "== binaries"
if [ -n "$RELEASE" ]; then
  for b in briqyardd briqyard-init briqyard briqyard-fleet; do
    curl -fsSL -o "/usr/local/bin/$b" "$RELEASE/$b-linux-$ARCH"
    chmod 0755 "/usr/local/bin/$b"
  done
else
  for b in briqyardd briqyard-init briqyard briqyard-fleet; do
    install -m 0755 "bin/$b" "/usr/local/bin/$b"
  done
fi

echo "== config"
mkdir -p /etc/briqyard
chmod 0700 /etc/briqyard
if [ ! -f /etc/briqyard/config.yaml ]; then
  key_source=fleet
  [ -n "$FLEET_URL" ] || key_source="file:$KEY_FILE"
  cat > /etc/briqyard/config.yaml <<EOF
listen: $bind:${LISTEN##*:}
token: "$API_TOKEN"
data_dir: /var/lib/briqyard
firecracker: /usr/local/bin/firecracker
jailer: /usr/local/bin/jailer
kernel: /var/lib/briqyard/vmlinux
init: /usr/local/bin/briqyard-init
root_disk_gb: 8
storage:
  backend: zfs
  pool: $POOL
  key: $key_source
network:
  range: 10.64.0.0/10
ingress:
  tcp_ports: 20000-29999
  bind: $bind
  http: $bind:8080
  domain: byard.localhost
EOF
  [ -z "$clients" ] || echo "$clients" >> /etc/briqyard/config.yaml
  if [ -n "$FLEET_URL" ]; then
    cat >> /etc/briqyard/config.yaml <<EOF
fleet:
  url: $FLEET_URL
  advertise: $advertise
EOF
  fi
fi
# The host's token is in it.
chmod 0600 /etc/briqyard/config.yaml

echo "== api certificate"
# Made here, before the daemon starts, so it is there to read; kept across runs.
fingerprint=$(/usr/local/bin/briqyardd --config /etc/briqyard/config.yaml tls-fingerprint)
if [ -n "$fingerprint" ]; then
  echo "   sha256 $fingerprint: the fleet pins it (tls_fingerprint)"
else
  echo "   none: the API is plain HTTP (a loopback listen, or api_tls: false)"
fi
cat > /etc/systemd/system/briqyardd.service <<'EOF'
[Unit]
Description=briqyard host daemon
After=network-online.target zfs.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/briqyardd --config /etc/briqyard/config.yaml
# Only the daemon gets the signal: the machines (Firecracker processes in this cgroup) must
# outlive a daemon crash, and a clean stop suspends them itself.
KillMode=process
Restart=on-failure
RestartSec=2
LimitNOFILE=65536
# A core dump of a Firecracker would be its guest's memory, on / in clear (ADR 0026).
LimitCORE=0
Environment=BRIQYARD_LOG=info

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable briqyardd >/dev/null
systemctl restart briqyardd
sleep 1
systemctl --no-pager --lines=2 status briqyardd | grep -E "Active|listening" || true
echo "== done: briqyard status"

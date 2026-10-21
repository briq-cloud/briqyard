#!/usr/bin/env bash
# Turns a fresh Ubuntu 24.04+ server with KVM into a briqyard host: packages, a ZFS pool on the
# second drive (or a file), Firecracker and a guest kernel, the briqyard binaries, the config,
# the systemd unit. Idempotent: run again with another BRIQYARD_RELEASE, it is the upgrade (the
# fleet's `host upgrade` does that, ADR 0027): a running daemon hands its machines over to the new
# one, which adopts them; nothing stops.
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

# Puts an executable in place by a rename: a running binary (the daemon, the fleet, Firecracker)
# is replaced, never written into.
put() {
  install -m 0755 "$1" "$2.new"
  mv -f "$2.new" "$2"
}

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

echo "== pool $POOL"
if ! zpool list "$POOL" >/dev/null 2>&1; then
  if [ -n "$POOL_DEVICE" ]; then
    zpool create -f -o ashift=12 -O compression=lz4 -O atime=off "$POOL" "$POOL_DEVICE"
  else
    mkdir -p /var/lib/briqyard
    truncate -s "${POOL_FILE_GB}G" /var/lib/briqyard/pool.img
    zpool create -f -o ashift=12 -O compression=lz4 -O atime=off "$POOL" /var/lib/briqyard/pool.img
    echo "   (a file-backed pool: fine for a trial, not for production)"
  fi
fi

echo "== firecracker $FIRECRACKER_VERSION and a guest kernel"
mkdir -p /var/lib/briqyard
if [ "$(/usr/local/bin/firecracker --version 2>/dev/null | head -1)" != "Firecracker $FIRECRACKER_VERSION" ]; then
  fetch "https://github.com/firecracker-microvm/firecracker/releases/download/${FIRECRACKER_VERSION}/firecracker-${FIRECRACKER_VERSION}-${ARCH}.tgz" "$FIRECRACKER_SHA256" /tmp/firecracker.tgz
  tar -xz -C /tmp -f /tmp/firecracker.tgz
  rm -f /tmp/firecracker.tgz
  put "/tmp/release-${FIRECRACKER_VERSION}-${ARCH}/firecracker-${FIRECRACKER_VERSION}-${ARCH}" /usr/local/bin/firecracker
  put "/tmp/release-${FIRECRACKER_VERSION}-${ARCH}/jailer-${FIRECRACKER_VERSION}-${ARCH}" /usr/local/bin/jailer
  rm -rf "/tmp/release-${FIRECRACKER_VERSION}-${ARCH}"
fi
if ! echo "$KERNEL_SHA256  /var/lib/briqyard/vmlinux" | sha256sum -c --quiet - 2>/dev/null; then
  fetch "$KERNEL_URL" "$KERNEL_SHA256" /var/lib/briqyard/vmlinux
  chmod 0644 /var/lib/briqyard/vmlinux
  echo "   kernel ${KERNEL_URL##*/}"
fi

echo "== binaries${RELEASE:+ from $RELEASE}"
for b in briqyardd briqyard-init briqyard briqyard-fleet; do
  if [ -n "$RELEASE" ]; then
    tmp=$(mktemp)
    curl -fsSL -o "$tmp" "$RELEASE/$b-linux-$ARCH"
    put "$tmp" "/usr/local/bin/$b"
    rm -f "$tmp"
  else
    put "bin/$b" "/usr/local/bin/$b"
  fi
done

echo "== config"
mkdir -p /etc/briqyard
# Loopback or RFC 1918: reachable from this host or its private network only.
private() {
  case "$1" in 127.*|10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;; esac
  return 1
}
if [ ! -f /etc/briqyard/config.yaml ]; then
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
    # The API serves TLS off loopback: advertised with the scheme it serves.
    scheme=https
    case "$bind" in 127.*) scheme=http ;; esac
    cat >> /etc/briqyard/config.yaml <<EOF
fleet:
  url: $FLEET_URL
  advertise: ${ADVERTISE:-$scheme://$(hostname -I | awk '{print $1}'):7420}
EOF
  fi
fi

echo "== api certificate"
# Made here, before the daemon starts, so it is there to read; kept across runs. It is also the
# new binary reading the configuration: one it refuses stops here, before any hand-over, and the
# running daemon goes on (ADR 0027).
fingerprint=$(/usr/local/bin/briqyardd --config /etc/briqyard/config.yaml tls-fingerprint) || {
  echo "   the new briqyardd refuses /etc/briqyard/config.yaml: nothing handed over"; exit 1; }
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
# Only the daemon gets the signal: the machines (Firecracker processes in this cgroup) outlive
# it. A stop (SIGTERM) suspends them, and the next start boots them again; SIGUSR2 (an upgrade)
# leaves them running for the next daemon to adopt; a crash leaves them too (ADR 0027).
KillMode=process
Restart=on-failure
RestartSec=2
LimitNOFILE=65536
Environment=BRIQYARD_LOG=info

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable briqyardd >/dev/null
# A running daemon hands its machines over (SIGUSR2, ADR 0027) and exits; the new one adopts them.
# `systemctl restart` would suspend every machine instead.
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

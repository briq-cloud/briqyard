#!/usr/bin/env bash
# Turns a fresh Ubuntu 24.04+ server with KVM into a briqyard host: packages, a ZFS pool on the
# second drive (or a file), Firecracker and a guest kernel, the briqyard binaries, the config,
# the systemd unit. Idempotent: run it again to upgrade.
#
#   BRIQYARD_RELEASE=https://github.com/briq-cloud/briqyard/releases/download/v0.1.0 \
#   BRIQYARD_POOL_DEVICE=/dev/nvme1n1 FLEET_URL=https://fleet.example FLEET_TOKEN=... \
#   ADVERTISE=http://10.0.0.5:7420 bash bootstrap-host.sh
#
# Without BRIQYARD_RELEASE, the binaries are expected in ./bin (built with `make`).
set -euo pipefail
POOL=${BRIQYARD_POOL:-byard}
POOL_DEVICE=${BRIQYARD_POOL_DEVICE:-}
POOL_FILE_GB=${BRIQYARD_POOL_FILE_GB:-50}
RELEASE=${BRIQYARD_RELEASE:-}
FLEET_URL=${FLEET_URL:-}
FLEET_TOKEN=${FLEET_TOKEN:-}
ADVERTISE=${ADVERTISE:-}
API_TOKEN=${BRIQYARD_TOKEN:-}
ARCH=$(uname -m)

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
[ -e /dev/kvm ] || { echo "/dev/kvm is missing: this server has no KVM"; exit 1; }

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

echo "== firecracker and a guest kernel"
mkdir -p /var/lib/briqyard
if [ ! -x /usr/local/bin/firecracker ]; then
  latest=$(basename "$(curl -fsSLI -o /dev/null -w '%{url_effective}' https://github.com/firecracker-microvm/firecracker/releases/latest)")
  curl -fsSL "https://github.com/firecracker-microvm/firecracker/releases/download/${latest}/firecracker-${latest}-${ARCH}.tgz" | tar -xz -C /tmp
  install -m 0755 "/tmp/release-${latest}-${ARCH}/firecracker-${latest}-${ARCH}" /usr/local/bin/firecracker
  install -m 0755 "/tmp/release-${latest}-${ARCH}/jailer-${latest}-${ARCH}" /usr/local/bin/jailer || true
fi
if [ ! -f /var/lib/briqyard/vmlinux ]; then
  S3="https://s3.amazonaws.com/spec.ccfc.min"
  CI=$(curl -fsSL "$S3?list-type=2&prefix=firecracker-ci/&delimiter=/" | grep -oP "(?<=<Prefix>)firecracker-ci/[0-9]{8}-[^/]+/(?=</Prefix>)" | sort | tail -1)
  K=$(curl -fsSL "$S3?list-type=2&prefix=${CI}${ARCH}/vmlinux-" | grep -oP "(?<=<Key>)(${CI}${ARCH}/vmlinux-[0-9]+\.[0-9]+\.[0-9]{1,3})(?=</Key>)" | sort -V | tail -1)
  curl -fsSL -o /var/lib/briqyard/vmlinux "$S3/$K"
  echo "   kernel $K"
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
if [ ! -f /etc/briqyard/config.yaml ]; then
  cat > /etc/briqyard/config.yaml <<EOF
listen: 0.0.0.0:7420
token: "$API_TOKEN"
data_dir: /var/lib/briqyard
firecracker: /usr/local/bin/firecracker
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
  http: 0.0.0.0:8080
  domain: byard.localhost
EOF
  if [ -n "$FLEET_URL" ]; then
    cat >> /etc/briqyard/config.yaml <<EOF
fleet:
  url: $FLEET_URL
  token: "$FLEET_TOKEN"
  advertise: ${ADVERTISE:-http://$(hostname -I | awk '{print $1}'):7420}
EOF
  fi
fi
cat > /etc/systemd/system/briqyardd.service <<'EOF'
[Unit]
Description=briqyard host daemon
After=network-online.target zfs.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/briqyardd --config /etc/briqyard/config.yaml
Restart=on-failure
RestartSec=2
LimitNOFILE=65536
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

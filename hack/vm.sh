#!/usr/bin/env bash
# Build for the Lima VM "fc", install briqyardd there and (re)start it. macOS development.
# Usage: hack/vm.sh [install|restart|logs|stop|e2e|shell]
set -euo pipefail
cd "$(dirname "$0")/.."
VM=${VM:-fc}
ARCH=$(limactl shell "$VM" uname -m | tr -d '\r')
case "$ARCH" in aarch64) GOARCH=arm64 ;; x86_64) GOARCH=amd64 ;; *) echo "unknown arch $ARCH"; exit 1 ;; esac
cmd=${1:-install}
VMHOME=$(limactl shell "$VM" sh -c 'echo $HOME' | tr -d '\r')

build() {
  GOARCH=$GOARCH make -s build
}

install() {
  build
  # The home directory is mounted read-only in the VM; copy through it.
  limactl shell "$VM" sudo bash -s <<EOF
set -e
install -m 0755 "$PWD/bin/briqyardd" /usr/local/bin/briqyardd
install -m 0755 "$PWD/bin/briqyard-init" /usr/local/bin/briqyard-init
install -m 0755 "$PWD/bin/briqyard" /usr/local/bin/briqyard
install -m 0755 "$PWD/bin/briqyard-fleet" /usr/local/bin/briqyard-fleet
mkdir -p /etc/briqyard /var/lib/briqyard
if [ ! -f /usr/local/bin/firecracker ]; then install -m 0755 "$VMHOME/fc/firecracker" /usr/local/bin/firecracker; fi
if [ ! -f /var/lib/briqyard/vmlinux ]; then cp "$VMHOME/fc/vmlinux" /var/lib/briqyard/vmlinux; fi
if [ ! -f /etc/briqyard/config.yaml ]; then cp "$PWD/hack/config.dev.yaml" /etc/briqyard/config.yaml; fi
cp "$PWD/hack/briqyardd.service" /etc/systemd/system/briqyardd.service
systemctl daemon-reload
systemctl enable briqyardd >/dev/null 2>&1 || true
systemctl restart briqyardd
sleep 1
systemctl --no-pager --lines=5 status briqyardd || true
EOF
}

case "$cmd" in
  build) build ;;
  install|restart) install ;;
  logs) limactl shell "$VM" sudo journalctl -u briqyardd -f -o cat ;;
  stop) limactl shell "$VM" sudo systemctl stop briqyardd ;;
  shell) limactl shell "$VM" ;;
  e2e) install; limactl shell "$VM" bash "$PWD/hack/e2e.sh" ;;
  *) echo "usage: hack/vm.sh [build|install|restart|logs|stop|shell|e2e]"; exit 2 ;;
esac

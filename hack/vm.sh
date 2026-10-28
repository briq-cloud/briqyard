#!/usr/bin/env bash
# Build inside the Lima VM "fc" (the source tree is mounted there, read-only), install briqyardd
# and (re)start it. macOS development.
# Usage: hack/vm.sh [build|install|restart|logs|stop|shell|e2e|fleet]
set -euo pipefail
cd "$(dirname "$0")/.."
VM=${VM:-fc}
SRC=$PWD
cmd=${1:-install}
VMHOME=$(limactl shell "$VM" sh -c 'echo $HOME' | tr -d '\r')
# A target dir per tree: cargo hashes a path package relative to its workspace, so trees that
# shared one would reuse each other's builds. Remove it when the worktree goes.
TARGET=$VMHOME/target-$(basename "$SRC")

# cargo cannot write into the read-only mount: lock file resolved here, target dir in the VM.
build() {
  cargo generate-lockfile --offline 2>/dev/null || cargo generate-lockfile >/dev/null
  # The init must be static: the guest has no shared libraries of ours. musl gives that.
  limactl shell "$VM" bash -lc "set -o pipefail; export PATH=\$HOME/.cargo/bin:\$PATH CARGO_TARGET_DIR=$TARGET; cd '$SRC' && cargo build --release --workspace --exclude briqyard-init 2>&1 | tail -3 && cargo build --release -p briqyard-init --target \$(uname -m)-unknown-linux-musl 2>&1 | tail -3"
}

install() {
  build
  limactl shell "$VM" sudo bash -s <<EOF
set -e
T=$TARGET/release
install -m 0755 "\$T/briqyardd" /usr/local/bin/briqyardd
install -m 0755 "$TARGET/$(limactl shell "$VM" uname -m | tr -d "\r")-unknown-linux-musl/release/briqyard-init" /usr/local/bin/briqyard-init
install -m 0755 "\$T/briqyard" /usr/local/bin/briqyard
install -m 0755 "\$T/briqyard-fleet" /usr/local/bin/briqyard-fleet
mkdir -p /etc/briqyard /var/lib/briqyard
H=$VMHOME
[ -f /usr/local/bin/firecracker ] || install -m 0755 "\$H/fc/firecracker" /usr/local/bin/firecracker
[ -f /var/lib/briqyard/vmlinux ] || cp "\$H/fc/vmlinux" /var/lib/briqyard/vmlinux
[ -f /etc/briqyard/config.yaml ] || cp "$SRC/hack/config.dev.yaml" /etc/briqyard/config.yaml
cp "$SRC/hack/briqyardd.service" /etc/systemd/system/briqyardd.service
cp "$SRC/hack/fleet.dev.yaml" /etc/briqyard/fleet.yaml
cp "$SRC/hack/briqyard-fleet.service" /etc/systemd/system/briqyard-fleet.service
# What hack/fleet-smoke.sh upgrades the VM's host to (ADR 0027): this build under a release's
# names with its digests, and the fleet's SSH key, authorized for root on the VM itself.
R=/var/lib/briqyard-fleet/release
mkdir -p "\$R"
for b in briqyardd briqyard-init briqyard briqyard-fleet; do cp "/usr/local/bin/\$b" "\$R/\$b-linux-\$(uname -m)"; done
(cd "\$R" && sha256sum briq*-linux-* > "SHA256SUMS-\$(uname -m)")
[ -f /etc/briqyard/fleet_ssh_key ] || ssh-keygen -q -t ed25519 -N "" -C briqyard-fleet -f /etc/briqyard/fleet_ssh_key
install -d -m 0700 /root/.ssh
grep -qxF "\$(cat /etc/briqyard/fleet_ssh_key.pub)" /root/.ssh/authorized_keys 2>/dev/null || cat /etc/briqyard/fleet_ssh_key.pub >> /root/.ssh/authorized_keys
# A restart of the VM makes it a new SSH host key, and the dev fleet pinned the old one for
# 127.0.0.1: its line goes when it no longer matches, so the next upgrade pins the new key.
K=/var/lib/briqyard-fleet/known_hosts
if [ -f "\$K" ] && ! grep -qF "\$(cut -d' ' -f1,2 /etc/ssh/ssh_host_ed25519_key.pub)" "\$K"; then
  sed -i '/^127\.0\.0\.1 /d' "\$K"
fi
# The registry mirror both VMs pull through (ADR 0036): fc2 reaches it at host.lima.internal.
bash "$SRC/hack/install-mirror.sh" >/dev/null
systemctl daemon-reload
systemctl enable briqyardd briqyard-fleet >/dev/null 2>&1 || true
systemctl restart briqyardd briqyard-fleet
sleep 1
systemctl --no-pager --lines=3 status briqyardd | grep -E "Active|msg" || true
EOF
}

case "$cmd" in
  build) build ;;
  install|restart) install ;;
  logs) limactl shell "$VM" sudo journalctl -u briqyardd -f -o cat ;;
  stop) limactl shell "$VM" sudo systemctl stop briqyardd ;;
  shell) limactl shell "$VM" ;;
  e2e) install; limactl shell "$VM" bash "$SRC/hack/e2e.sh" ;;
  fleet) install; limactl shell "$VM" bash "$SRC/hack/fleet-smoke.sh" ;;
  *) echo "usage: hack/vm.sh [build|install|restart|logs|stop|shell|e2e|fleet]"; exit 2 ;;
esac

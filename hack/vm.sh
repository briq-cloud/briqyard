#!/usr/bin/env bash
# Build inside the Lima VM "fc" (the source tree is mounted there, read-only), install briqyardd
# and (re)start it. macOS development.
# Usage: hack/vm.sh [build|install|restart|logs|stop|shell|e2e|fleet]
set -euo pipefail
cd "$(dirname "$0")/.."
VM=${VM:-fc}
SRC=$PWD
cmd=${1:-install}
# What changes the VMs' daemons runs under the shared lock (hack/vm-lock.sh): another session's
# suite would otherwise run against a daemon restarted under it.
case "$cmd" in
  install|restart|stop|e2e|fleet)
    [ -n "${BRIQYARD_VM_LOCK:-}" ] || exec "$PWD/hack/vm-lock.sh" "$PWD/hack/vm.sh" "$@" ;;
esac
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
  limactl shell "$VM" sudo bash -s -- "$VMHOME" "$SRC" "$TARGET" <<'EOF'
set -e
H=$1 SRC=$2 TARGET=$3
mkdir -p /var/lib/briqyard
[ -f /usr/local/bin/firecracker ] || install -m 0755 "$H/fc/firecracker" /usr/local/bin/firecracker
[ -f /var/lib/briqyard/vmlinux ] || cp "$H/fc/vmlinux" /var/lib/briqyard/vmlinux
exec bash "$SRC/hack/install-dev.sh" "$TARGET"
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

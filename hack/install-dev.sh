#!/usr/bin/env bash
# Install a development build on Linux; shared by Lima and native CI. Run as root.
set -euo pipefail
TARGET=${1:?target directory}
SRC=$(cd "$(dirname "$0")/.." && pwd)
set -e
command -v conntrack >/dev/null || { apt-get update -qq; apt-get install -y -qq conntrack; }
T=$TARGET/release
install -m 0755 "$T/briqyardd" /usr/local/bin/briqyardd
install -m 0755 "$TARGET/$(uname -m)-unknown-linux-musl/release/briqyard-init" /usr/local/bin/briqyard-init
install -m 0755 "$T/briqyard" /usr/local/bin/briqyard
install -m 0755 "$T/briqyard-fleet" /usr/local/bin/briqyard-fleet
mkdir -p /etc/briqyard /var/lib/briqyard
H=${VMHOME:-$HOME}
[ -f /usr/local/bin/firecracker ] || install -m 0755 "$H/fc/firecracker" /usr/local/bin/firecracker
[ -f /var/lib/briqyard/vmlinux ] || cp "$H/fc/vmlinux" /var/lib/briqyard/vmlinux
[ -f /etc/briqyard/config.yaml ] || cp "$SRC/hack/config.dev.yaml" /etc/briqyard/config.yaml
cp "$SRC/hack/briqyardd.service" /etc/systemd/system/briqyardd.service
cp "${FLEET_CONFIG:-$SRC/hack/fleet.dev.yaml}" /etc/briqyard/fleet.yaml
cp "$SRC/hack/briqyard-fleet.service" /etc/systemd/system/briqyard-fleet.service
# What hack/fleet-smoke.sh upgrades the VM's host to (ADR 0027): this build under a release's
# names with its digests, and the fleet's SSH key, authorized for root on the VM itself.
R=/var/lib/briqyard-fleet/release
mkdir -p "$R"
for b in briqyardd briqyard-init briqyard briqyard-fleet; do cp "/usr/local/bin/$b" "$R/$b-linux-$(uname -m)"; done
(cd "$R" && sha256sum briq*-linux-* > "SHA256SUMS-$(uname -m)")
[ -f /etc/briqyard/fleet_ssh_key ] || ssh-keygen -q -t ed25519 -N "" -C briqyard-fleet -f /etc/briqyard/fleet_ssh_key
install -d -m 0700 /root/.ssh
grep -qxF "$(cat /etc/briqyard/fleet_ssh_key.pub)" /root/.ssh/authorized_keys 2>/dev/null || cat /etc/briqyard/fleet_ssh_key.pub >> /root/.ssh/authorized_keys
# A restart of the VM makes it a new SSH host key, and the dev fleet pinned the old one for
# 127.0.0.1: its line goes when it no longer matches, so the next upgrade pins the new key.
K=/var/lib/briqyard-fleet/known_hosts
if [ -f "$K" ] && ! grep -qF "$(cut -d' ' -f1,2 /etc/ssh/ssh_host_ed25519_key.pub)" "$K"; then
  sed -i '/^127\.0\.0\.1 /d' "$K"
fi
# The registry mirror both VMs pull through (ADR 0036): fc2 reaches it at host.lima.internal.
bash "$SRC/hack/install-mirror.sh" >/dev/null
systemctl daemon-reload
systemctl enable briqyardd briqyard-fleet >/dev/null 2>&1 || true
systemctl restart briqyardd briqyard-fleet
sleep 1
systemctl --no-pager --lines=3 status briqyardd | grep -E "Active|msg" || true

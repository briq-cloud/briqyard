#!/usr/bin/env bash
# Fresh, disposable Linux KVM host only. No Lima or shared host state.
set -euo pipefail
[ "${RUNNER_ENVIRONMENT:-}" = github-hosted ] || { echo 'native-ci.sh requires a disposable GitHub-hosted runner' >&2; exit 2; }
HARNESS=$(cd "$(dirname "$0")" && pwd)
cd "${1:-$HARNESS/..}"
# Docker's host-wide FORWARD drop policy also sees packets accepted by briqyard's
# own nftables chains. This disposable runner is exclusively a briqyard host.
sudo iptables -S FORWARD
sudo systemctl stop docker.service docker.socket
sudo iptables -P FORWARD ACCEPT
TARGET=${CARGO_TARGET_DIR:-$PWD/target}
R=$PWD/native-release
mkdir -p "$R"
for b in briqyardd briqyard briqyard-fleet; do cp "$TARGET/release/$b" "$R/$b-linux-x86_64"; done
cp "$TARGET/x86_64-unknown-linux-musl/release/briqyard-init" "$R/briqyard-init-linux-x86_64"
# Published checked bundle; bootstrap verifies its internal source, patch and binary evidence.
B=firecracker-checked-linux-x86_64.tar.gz
curl -fsSL "https://github.com/briq-cloud/briqyard/releases/download/v0.1.17/$B" -o "$R/$B"
BSHA=2e410f2e852d9898fc0193afe28f3c4606421cef58b30fb64bbb69618ec1a65c
echo "$BSHA  $R/$B" | sha256sum -c -
(cd "$R" && sha256sum -- briq*-linux-* firecracker-checked-linux-*.tar.gz > SHA256SUMS-x86_64)
# Use the real checked release installation path with this head's binaries.
sudo env BRIQYARD_RELEASE="file://$R" BRIQYARD_POOL_FILE_GB=40 BRIQYARD_ARC_GB=1 LISTEN=127.0.0.1:7420 bash hack/bootstrap-host.sh
sudo python3 - <<'PY'
from pathlib import Path
import yaml
p=Path('/etc/briqyard/config.yaml')
c=yaml.safe_load(p.read_text())
c['backup']={'store':'file:///var/lib/briqyard/backups'}
c['network']['host_ports']=[9443]
c['ingress'].update(tcp_ports='30000-32767', http='127.0.0.1:8080', advertise='127.0.0.1')
c['registry_mirrors']={'docker.io':'http://127.0.0.1:7440'}
c['capacity']={'memory_mb':12288,'vcpus':24}
import hashlib
init = hashlib.sha256(Path('native-release/briqyard-init-linux-x86_64').read_bytes()).hexdigest()
c['templates'] = {'enabled': True, 'init_ready_init_sha256': init, 'sandbox_recipes': [
    {'image': 'docker.io/library/alpine@sha256:85f2b723e106c34644cd5851d7e81ee87da98ac54672b29947c052a45d31dc2f',
     'image_config_digest': 'sha256:706db57fb2063f39f69632c5b5c9c439633fda35110e65587c5d85553fd1cc38',
     'init_sha256': init, 'size': {'vcpus': 1, 'memory_mb': 256}, 'volume_gb': gb}
    for gb in [0, 1]]}
p.write_text(yaml.safe_dump(c,sort_keys=False).replace('  host_ports:\n  - 9443\n', '  host_ports: [9443]\n'))
PY
cat > "$RUNNER_TEMP/native-fleet.yaml" <<'YAML'
listen: 127.0.0.1:7430
tls: off
state_dir: /var/lib/briqyard-fleet
hosts:
  - id: local
    url: http://127.0.0.1:7420
    region: dev
placement:
  fill_ceiling: 0.85
  down_after_sec: 60
YAML
sudo systemctl stop briqyardd
sudo systemctl start ssh
sudo env FLEET_CONFIG="$RUNNER_TEMP/native-fleet.yaml" bash "$HARNESS/install-dev.sh" "$TARGET" "$R/$B" "$BSHA" "$PWD"
for _ in $(seq 1 60); do
  briqyard status >/dev/null 2>&1 && curl -fsS http://127.0.0.1:7430/v1/hosts | jq -e 'length == 1 and all(.state == "ready")' >/dev/null && exit 0
  sleep 1
done
echo 'native daemons did not become ready' >&2
exit 1

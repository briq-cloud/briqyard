#!/usr/bin/env bash
# Disposable native CI host after native-ci.sh installation. Builds must match this source.
# cargo build --release -p briqyard-testing --features scoped-native --bin scoped-execution-native
# Reuses native-ci.sh's checked bootstrap and install-dev.sh; never a shared dev host.
set -euo pipefail
[ "${RUNNER_ENVIRONMENT:-}" = github-hosted ] || { echo 'requires a disposable GitHub-hosted runner' >&2; exit 2; }
[ "$(uname -s)" = Linux ] && [ -c /dev/kvm ] || { echo 'requires Linux KVM' >&2; exit 2; }
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
TARGET=${CARGO_TARGET_DIR:-$ROOT/target}
DRIVER=$TARGET/release/scoped-execution-native
[ -x "$DRIVER" ] || { echo 'build scoped-execution-native first' >&2; exit 2; }
export BRIQYARD_URL=http://127.0.0.1:7420
# No arbitrary endpoint overrides: this fixture owns the disposable local host.
unset BRIQYARD_TOKEN BRIQYARD_TLS_FINGERPRINT
T=scoped-native-$$
D=$(sudo mktemp -d /var/lib/briqyard/scoped-native.XXXXXX)
AUTHORITY_PID=
CONFIG_SAVED=0
PHASE=save_config
# Report only a fixed phase, never the command or its expanded credentials.
trap 'printf "scoped native: failed phase=%s\n" "$PHASE" >&2' ERR
cleanup() {
  local rc=$?
  set +e
  if [ -n "$AUTHORITY_PID" ]; then
    local authority_child
    authority_child=$(sudo cat "$D/authority.pid" 2>/dev/null)
    if [[ "$authority_child" =~ ^[0-9]+$ ]]; then sudo kill -TERM "$authority_child" 2>/dev/null; fi
    sudo kill -TERM "$AUTHORITY_PID" 2>/dev/null
    wait "$AUTHORITY_PID" 2>/dev/null
  fi
  for id in $(briqyard machine ls --namespace "$T" 2>/dev/null | awk 'NR>1{print $1}'); do
    timeout 90 briqyard machine rm "$id" >/dev/null 2>&1 || rc=1
  done
  timeout 90 briqyard namespace gateway rm "$T" >/dev/null 2>&1 || true
  briqyard namespace rm "$T" >/dev/null 2>&1 || rc=1
  if briqyard namespace ls | jq -e --arg ns "$T" 'any(.[]; .id == $ns)' >/dev/null; then rc=1; fi
  # The retained compatibility floor belongs to this disposable fixture and is never removed.
  if [ "$CONFIG_SAVED" = 1 ]; then
    sudo cp "$D/host-original.yaml" /etc/briqyard/config.yaml
    sudo systemctl restart briqyardd || rc=1
  fi
  sudo rm -rf "$D"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP
sudo cp /etc/briqyard/config.yaml "$D/host-original.yaml"
CONFIG_SAVED=1
PHASE=provision_keys
sudo "$DRIVER" provision "$D"
PHASE=certificate
sudo openssl req -x509 -newkey ed25519 -nodes -keyout "$D/key.pem" -out "$D/cert.pem" -days 1 -subj /CN=scoped-native >/dev/null 2>&1
PHASE=configure
sudo python3 - "$D" <<'PY'
import json, os, secrets, sys
from pathlib import Path
import yaml
p=Path(sys.argv[1]); config=Path('/etc/briqyard/config.yaml')
host=yaml.safe_load(config.read_text())
credentials={role:secrets.token_hex(32) for role in ('host_installer','host_execution','central_installer','gateway','fleet_administrator')}
credentials['host_administrator']=host.get('token','')
# Administrator references are distinct and never used by the scoped driver.
if not credentials['host_administrator']:
    credentials['host_administrator']=secrets.token_hex(32)
    host['token']=credentials['host_administrator']
(p/'credentials.json').write_text(json.dumps(credentials))
(p/'host-admin').write_text(credentials['host_administrator'])
(p/'fleet-admin').write_text(credentials['fleet_administrator'])
channel=dict(listen='127.0.0.1:7441',cert=str(p/'cert.pem'),key=str(p/'key.pem'),journal=str(p/'host-journal'),credentials=str(p/'credentials.json'),verification_keys=str(p/'verification.json'),central_issuer='central',authority_issuer='authority',audience='runtime')
host['execution']=channel
config.write_text(yaml.safe_dump(host,sort_keys=False))
# Host identity comes from the daemon's persisted operator-owned metadata, not the request.
host_id=(Path(host['data_dir'])/'state/meta/host_id.json').read_text()
import subprocess
fingerprint=subprocess.check_output(['openssl','x509','-in',str(p/'cert.pem'),'-noout','-fingerprint','-sha256'],text=True).strip().split('=',1)[1].replace(':','').lower()
authority_channel=dict(channel,listen='127.0.0.1:7442',journal=str(p/'authority-journal'))
authority=dict(execution=dict(channel=authority_channel,host_id=host_id,host_url='https://127.0.0.1:7441',authority='native',key_id='native-authority',signing_key=str(p/'authority.pk8')),host_tls_fingerprint=fingerprint,host_administrator_file=str(p/'host-admin'),fleet_administrator_file=str(p/'fleet-admin'))
(p/'authority.yaml').write_text(yaml.safe_dump(authority,sort_keys=False))
for file in p.iterdir():
    os.chmod(file,0o600)
PY
# CLI setup and cleanup use the ordinary local API; guest commands below use only scoped TLS.
PHASE=host_start
BRIQYARD_TOKEN=$(sudo cat "$D/host-admin")
export BRIQYARD_TOKEN
sudo systemctl restart briqyardd
PHASE=authority_start
sudo bash -c 'echo "$$" > "$1/authority.pid"; exec /usr/local/bin/briqyard-fleet --config "$1/authority.yaml" authority' _ "$D" > /dev/null 2>&1 &
AUTHORITY_PID=$!
# A single bounded startup observation; no exec request is retried.
PHASE=host_ready
timeout 75 bash -c 'until briqyard status >/dev/null 2>&1; do sleep 1; done'
PHASE=gateway
briqyard namespace gateway set "$T" --image alpine:3.20 --memory 128 --port 3128 -- httpd -f -p 3128 >/dev/null
PHASE=primary
M=$(briqyard machine run --namespace "$T" --name primary --image alpine:3.20 --memory 128 --egress via:gateway+siblings -l briq_id=native-primary -l "team=$T" -- sleep 3600 | jq -er .id)
PHASE=sibling
S=$(briqyard machine run --namespace "$T" --name sibling --image alpine:3.20 --memory 128 -l briq_id=native-sibling -l "team=$T" -- sleep 3600 | jq -er .id)
PHASE=scoped_dispatch
sudo "$DRIVER" run "$D" "$T" "$M" "$S"

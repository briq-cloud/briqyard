#!/usr/bin/env bash
# Previous published daemons, candidate fleet: disposable native-upgrade fixture only.
set -euo pipefail
[ "${RUNNER_ENVIRONMENT:-}" = github-hosted ] || exit 2
PREV=${1:?previous tag}
PREVIOUS=$(cd "${2:?previous checkout}" && pwd)
HEAD_DIR=$(cd "${3:?candidate assets}" && pwd)
SUMS=${4:?previous checksums}
[[ "$PREV" =~ ^v[0-9]+[.][0-9]+[.][0-9]+(-[0-9A-Za-z.]+)?$ ]] || exit 2
HARNESS=$(cd "$(dirname "$0")" && pwd)
PROBE=$RUNNER_TEMP/two-host-probe
SECOND=$PROBE/second-host
[ -x "$SECOND" ] || exit 2
WORK=$(mktemp -d)
RECEIPT=$PWD/native-logs/mixed-two-host-contract.json
changed=0
sudo cp /etc/briqyard/fleet.yaml "$WORK/fleet.yaml"
sudo python3 "$HARNESS/native-mixed-contract.py" --capture > "$WORK/original.json"
cleanup() {
  rc=$?
  trap - EXIT
  set +e
  restored=1
  if [ "$changed" = 1 ]; then
    restored=0
    # Static hosts survive config removal in the durable registry. Observe the owned
    # second host empty while it is still polled, then remove its configuration.
    empty=0
    python3 "$HARNESS/native-mixed-two-host-contract.py" --fixture-empty && empty=1
    if sudo install -m 0644 "$WORK/fleet.yaml" /etc/briqyard/fleet.yaml && sudo systemctl restart briqyard-fleet &&
      [ "$empty" = 1 ]; then
      # Wait only on reads before the one-shot retirement POST.
      available=0
      for _ in $(seq 1 30); do
        if curl -fsS -H "Authorization: Bearer $BRIQYARD_TOKEN" http://127.0.0.1:7430/v1/hosts |
          jq -e 'any(.id == "local" and .state == "ready")' >/dev/null; then available=1; break; fi
        sleep 1
      done
      if [ "$available" = 1 ] && python3 "$HARNESS/native-mixed-two-host-contract.py" --retire-fixture-host; then
        for _ in $(seq 1 60); do
          if curl -fsS -H "Authorization: Bearer $BRIQYARD_TOKEN" http://127.0.0.1:7430/v1/hosts |
            jq -e 'length == 1 and .[0].id == "local" and .[0].state == "ready"' >/dev/null; then restored=1; break; fi
          sleep 1
        done
      fi
    fi
    if [ "$restored" = 1 ]; then
      sudo python3 "$HARNESS/native-mixed-contract.py" --capture > "$WORK/restored.json" || restored=0
      if [ "$restored" = 1 ]; then
        python3 - "$WORK/original.json" "$WORK/restored.json" <<'PY' || restored=0
import json,sys
from pathlib import Path
if json.loads(Path(sys.argv[1]).read_bytes()) != json.loads(Path(sys.argv[2]).read_bytes()):
    raise SystemExit(1)
PY
      fi
    fi
  fi
  python3 - "$RECEIPT" "$restored" <<'PY' || rc=1
import json,sys
from pathlib import Path
p=Path(sys.argv[1])
v=json.loads(p.read_bytes()) if p.exists() else {'schema':1,'passed':False,'cleanup':'not-started'}
v['fleetConfigurationRestored']=sys.argv[2]=='1'
v['passed']=v['passed'] and v['fleetConfigurationRestored']
p.write_text(json.dumps(v,sort_keys=True,indent=2)+'\n')
PY
  [ "$restored" = 1 ] || rc=1
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP

# The candidate must know the second host before the old bootstrap requests its pool key.
changed=1
sudo python3 - <<'PY'
from pathlib import Path
import yaml
p=Path('/etc/briqyard/fleet.yaml'); c=yaml.safe_load(p.read_text())
if len(c['hosts']) != 1 or c['hosts'][0]['id'] != 'local': raise SystemExit(1)
c['listen']='0.0.0.0:7430'; c['tls']='off'
c['hosts'].append({'id':'fc2','url':'http://127.0.0.2:27420','token':'mixed-fc2-token','region':'mixed-second'})
p.write_text(yaml.safe_dump(c,sort_keys=False))
PY
sudo systemctl restart briqyard-fleet
git -C "$PREVIOUS" archive HEAD > "$WORK/previous.tar"
scp_opts=(-i "$PROBE/key" -P 2222 -o UserKnownHostsFile="$PROBE/known_hosts" -o StrictHostKeyChecking=yes -o BatchMode=yes)
scp "${scp_opts[@]}" "$WORK/previous.tar" ubuntu@127.0.0.1:/tmp/mixed-previous.tar
"$SECOND" install -d -m 0755 -o ubuntu -g ubuntu /tmp/mixed-contract
scp "${scp_opts[@]}" "$HARNESS/native-clone-contract.py" "$HARNESS/native-mixed-contract.py" \
  "$HARNESS/native-mixed-two-host-contract.py" ubuntu@127.0.0.1:/tmp/mixed-contract/
"$SECOND" bash -s -- "$PREV" <<'GUEST'
set -euo pipefail
PREV=$1
mkdir -p /srv/mixed-previous
tar -C /srv/mixed-previous -xf /tmp/mixed-previous.tar
cd /srv/mixed-previous
env BRIQYARD_RELEASE="https://github.com/briq-cloud/briqyard/releases/download/$PREV" \
  BRIQYARD_POOL_FILE_GB=15 BRIQYARD_ARC_GB=1 BRIQYARD_TOKEN=mixed-fc2-token \
  FLEET_URL=http://10.0.2.2:7430 ADVERTISE=http://127.0.0.2:27420 \
  LISTEN=127.0.0.1:7420 ALLOWED_CLIENTS=10.0.2.0/24,127.0.0.1/32 bash hack/bootstrap-host.sh
python3 - <<'PY'
from pathlib import Path
import yaml
p=Path('/etc/briqyard/config.yaml'); c=yaml.safe_load(p.read_text())
c['registry_mirrors']={'docker.io':'http://10.0.2.2:7440'}
c['api_tls']=False; c['listen']='0.0.0.0:7420'
c['ingress']['bind']='0.0.0.0'; c['ingress']['http']='0.0.0.0:8080'
c['capacity']={'memory_mb':3840,'reserved_memory_mb':512,'vcpus':8}
p.write_text(yaml.safe_dump(c,sort_keys=False))
PY
systemctl restart briqyardd
GUEST
ready=0
for _ in $(seq 1 90); do
  if curl -fsS -H "Authorization: Bearer $BRIQYARD_TOKEN" http://127.0.0.1:7430/v1/hosts |
    jq -e 'length == 2 and all(.state == "ready" and .capacity.memory_mb > 0)' >/dev/null; then ready=1; break; fi
  sleep 1
done
[ "$ready" = 1 ] || exit 1
sudo python3 "$HARNESS/native-mixed-contract.py" --capture > "$WORK/local.json"
"$SECOND" python3 /tmp/mixed-contract/native-mixed-two-host-contract.py --capture-daemon > "$WORK/second.json"
python3 "$HARNESS/native-mixed-two-host-contract.py" "$WORK/local.json" "$WORK/second.json" \
  "$PREV" "$HEAD_DIR" "$SUMS" "$SECOND" "$RECEIPT"

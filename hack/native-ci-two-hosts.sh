#!/usr/bin/env bash
# Harness from workflow revision; runtime, bootstrap and suites from tested source.
set -euo pipefail
[ "${RUNNER_ENVIRONMENT:-}" = github-hosted ] || exit 2
HARNESS=$(cd "$(dirname "$0")" && pwd)
WORK=$RUNNER_TEMP/two-host-probe
mkdir -p native-logs
# shellcheck disable=SC2329
cleanup() {
  rc=$?
  trap - EXIT
  # The artifact directory belongs to the runner, not root.
  # shellcheck disable=SC2024
  sudo journalctl -u briqyardd -u briqyard-fleet --no-pager > native-logs/local-journal.log || true
  if [ -x "$WORK/second-host" ]; then
    "$WORK/second-host" journalctl -u briqyardd --no-pager > native-logs/second-journal.log || true
  fi
  if [ -f "$WORK/pid" ]; then sudo kill "$(cat "$WORK/pid")" || true; fi
  cp "$WORK/serial.log" native-logs/qemu-serial.log 2>/dev/null || true
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP
KEEP_SECOND_HOST=1 bash "$HARNESS/native-two-host-probe.sh"
bash "$HARNESS/native-ci.sh" "$PWD"
# Preserve native-ci's one-host setup; add the second static host before its bootstrap
# asks this fleet for the key. Plain HTTP on the private QEMU user network, as on fc2.
sudo python3 - <<'PY'
from pathlib import Path
import yaml
p=Path('/etc/briqyard/config.yaml'); c=yaml.safe_load(p.read_text())
c['capacity']={'memory_mb':4608,'vcpus':8}
p.write_text(yaml.safe_dump(c,sort_keys=False))
p=Path('/etc/briqyard/fleet.yaml'); c=yaml.safe_load(p.read_text())
c['listen']='0.0.0.0:7430'; c['tls']='off'
c['hosts'].append({'id':'fc2','url':'http://127.0.0.2:27420','token':'fc2-token','region':'dev'})
p.write_text(yaml.safe_dump(c,sort_keys=False))
PY
sudo systemctl restart briqyardd briqyard-fleet
# Transfer only tracked source and the locally verified release assets; never credentials.
git archive HEAD > "$WORK/source.tar"
tar -C native-release -cf "$WORK/release.tar" .
scp_opts=(-i "$WORK/key" -P 2222 -o UserKnownHostsFile="$WORK/known_hosts" -o StrictHostKeyChecking=yes -o BatchMode=yes)
scp "${scp_opts[@]}" "$WORK/source.tar" "$WORK/release.tar" "$HARNESS/install-dev.sh" ubuntu@127.0.0.1:/tmp/
"$WORK/second-host" bash -s <<'GUEST'
set -euo pipefail
mkdir -p /srv/fixture /srv/release
cd /srv/fixture
tar -xf /tmp/source.tar
tar -C /srv/release -xf /tmp/release.tar
# Same bootstrap as fc2; its pool key comes from the fleet, never a file.
env BRIQYARD_RELEASE=file:///srv/release BRIQYARD_POOL_FILE_GB=15 BRIQYARD_ARC_GB=1 \
  BRIQYARD_TOKEN=fc2-token FLEET_URL=http://10.0.2.2:7430 \
  ADVERTISE=http://127.0.0.2:27420 LISTEN=127.0.0.1:7420 ALLOWED_CLIENTS=10.0.2.0/24,127.0.0.1/32 bash hack/bootstrap-host.sh
python3 - <<'PY'
from pathlib import Path
import yaml
p=Path('/etc/briqyard/config.yaml'); c=yaml.safe_load(p.read_text())
c['api_tls']=False
c['listen']='0.0.0.0:7420'
c['ingress']['bind']='0.0.0.0'
c['ingress']['http']='0.0.0.0:8080'
c['capacity']={'memory_mb':4096,'vcpus':8}
p.write_text(yaml.safe_dump(c,sort_keys=False))
# The suites parse these scalars as in the bootstrap output.
s=p.read_text().replace('token: fc2-token','token: "fc2-token"')
p.write_text(s)
PY
mkdir -p /srv/target/release /srv/target/x86_64-unknown-linux-musl/release
for b in briqyardd briqyard briqyard-fleet; do cp "/srv/release/$b-linux-x86_64" "/srv/target/release/$b"; done
cp /srv/release/briqyard-init-linux-x86_64 /srv/target/x86_64-unknown-linux-musl/release/briqyard-init
bash /tmp/install-dev.sh /srv/target /srv/release/firecracker-checked-linux-x86_64.tar.gz \
  2e410f2e852d9898fc0193afe28f3c4606421cef58b30fb64bbb69618ec1a65c /srv/fixture
systemctl disable --now briqyard-fleet
GUEST
ready=0
for _ in $(seq 1 90); do
  if curl -fsS http://127.0.0.1:7430/v1/hosts | jq -e 'length == 2 and all(.state == "ready" and .capacity.memory_mb > 0 and .used.memory_mb == 0)' >/dev/null; then ready=1; break; fi
  sleep 1
done
[ "$ready" = 1 ] || { echo 'two hosts did not become ready and empty'; exit 1; }
# The fleet's view can still be the daemon from before install-dev restarted it: ask the daemon.
ready=0
for _ in $(seq 1 60); do
  if "$WORK/second-host" env BRIQYARD_TOKEN=fc2-token briqyard status >/dev/null 2>&1; then ready=1; break; fi
  sleep 1
done
[ "$ready" = 1 ] || { echo 'the second host daemon did not answer'; exit 1; }
# Measure real nested Firecracker boot through the daemon (includes cold image pull).
start=$SECONDS
id=$("$WORK/second-host" env BRIQYARD_TOKEN=fc2-token briqyard machine run --image alpine:3.20 --name boot-probe --namespace native-boot --memory 128 -- sleep 3600 | jq -r .id)
"$WORK/second-host" env BRIQYARD_TOKEN=fc2-token briqyard machine exec "$id" -- hostname
printf 'Nested Firecracker create+exec seconds: %s\n' "$((SECONDS-start))" | tee native-logs/boot-time.log
"$WORK/second-host" env BRIQYARD_TOKEN=fc2-token briqyard machine destroy "$id"
"$WORK/second-host" env BRIQYARD_TOKEN=fc2-token briqyard namespace rm native-boot
# The fleet must observe the empty host before placement in the suite.
for _ in $(seq 1 45); do
  curl -fsS http://127.0.0.1:7430/v1/hosts | jq -e 'all(.used.memory_mb == 0)' >/dev/null && break
  sleep 1
done
export SECOND_HOST_SH="$WORK/second-host"
export SECOND_HOST_STOP="$WORK/second-host systemctl stop briqyardd"
export SECOND_HOST_START="$WORK/second-host systemctl start briqyardd"
export FLEET_SH=sudo
rc=0
for suite in fleet-two-hosts fleet-restore; do
  start=$SECONDS
  set +e
  bash "hack/$suite.sh" 2>&1 | tee "native-logs/$suite.log"
  statuses=("${PIPESTATUS[@]}")
  set -e
  printf '%s duration seconds: %s\n' "$suite" "$((SECONDS-start))" | tee -a native-logs/durations.log
  if [ "${statuses[0]}" != 0 ] || [ "${statuses[1]}" != 0 ]; then rc=1; fi
done
exit "$rc"

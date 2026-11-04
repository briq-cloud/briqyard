#!/usr/bin/env bash
# The upgrade a production host goes through (ADR 0105): install the previous published release's
# own artifacts through its own bootstrap, give the host state and history, upgrade it in place
# to this head through the fleet's `host upgrade` (ADR 0027), and check what came through.
#
#   hack/native-ci-upgrade.sh <previous tag, v0.1.23> <head release directory>
#
# The head directory holds what a release holds for x86_64: briqyardd, briqyard, briqyard-fleet,
# briqyard-init (each `<name>-linux-x86_64`), firecracker-checked-linux-x86_64.tar.gz and
# SHA256SUMS-x86_64 covering them. Disposable GitHub-hosted runner only: it replaces the host's
# briqyard, stops Docker and leaves thousands of cgroups behind. Needs git, curl, jq, python3-yaml, sshd.
#   NATIVE_UPGRADE_API_DOWN_MAX   longest time the daemon's API may be silent (default 30 s)
#   NATIVE_UPGRADE_ENDPOINT_GAP_MAX  longest gap in an endpoint served throughout (default 10 s)
#   NATIVE_UPGRADE_LEAVES         idle machine cgroups left on the host before the upgrade (default 6500)
set -uo pipefail
[ "${RUNNER_ENVIRONMENT:-}" = github-hosted ] || { echo 'requires a disposable GitHub-hosted runner' >&2; exit 2; }
PREV=${1:?previous release tag}
HEAD_DIR=$(cd "${2:?head release directory}" && pwd)
[[ "$PREV" =~ ^v[0-9]+[.][0-9]+[.][0-9]+(-[0-9A-Za-z.]+)?$ ]] || { echo "previous: $PREV is not a release tag" >&2; exit 2; }
HARNESS=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
API_DOWN_MAX=${NATIVE_UPGRADE_API_DOWN_MAX:-30}
GAP_MAX=${NATIVE_UPGRADE_ENDPOINT_GAP_MAX:-10}
LEAVES=${NATIVE_UPGRADE_LEAVES:-6500}
NS=upgrade-ci
PARENT=/sys/fs/cgroup/firecracker
TOKEN=upgrade-ci-token
REPO=https://github.com/briq-cloud/briqyard
REL_URL=$REPO/releases/download/$PREV
FLEET=http://127.0.0.1:7430
export BRIQYARD_TOKEN=$TOKEN   # the daemon's; the fleet takes no token here (see `fleet`)
pass=0; fail=0
ok()   { pass=$((pass+1)); echo "  ok   $1"; }
bad()  { fail=$((fail+1)); echo "  FAIL $1"; }
check(){ if eval "$2"; then ok "$1"; else bad "$1"; fi; }
. "$HARNESS/suite-end.sh"
die() { echo "SETUP FAILED: $*" >&2; exit 1; }
fleet() { env -u BRIQYARD_TOKEN BRIQYARD_URL=$FLEET briqyard "$@"; }
dapi() { curl -fsS -H "Authorization: Bearer $TOKEN" "$@"; }
hostf() { curl -fsS "$FLEET/v1/hosts" | jq -r ".[] | select(.id == \"local\") | $1"; }
leaves() { sudo find "$PARENT" -mindepth 1 -maxdepth 1 -type d -name 'm-*' | wc -l; }
made() { sudo find "$PARENT" -mindepth 1 -maxdepth 1 -type d -name 'm-5ca1*' | wc -l; }
cgdir() { echo "$PARENT/${1//_/-}"; }
# A machine's VMM, by what outlives a pid: the pid and its start time, from the machine's cgroup.
vmm() {
  local p
  for p in $(sudo cat "$(cgdir "$1")/cgroup.procs" 2>/dev/null | sort -n); do
    echo "$p:$(awk '{print $22}' "/proc/$p/stat" 2>/dev/null)"
  done | paste -sd, -
}
wait_running() { briqyard machine wait --for running "$1" >/dev/null; }
ready() { for _ in $(seq 1 90); do briqyard machine exec "$1" -- pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }
PROBES=()
cleanup() {
  local rc=$?
  set +e
  for p in "${PROBES[@]}"; do kill "$p" 2>/dev/null; done
  sudo sh -c "cd $PARENT 2>/dev/null && find . -mindepth 1 -maxdepth 1 -type d -name 'm-5ca1*' | xargs -r rmdir 2>/dev/null"
  sudo journalctl -u briqyardd -u briqyard-fleet --no-pager -n 80 > "$WORK/journal-tail.log" 2>&1
  if [ "$rc" != 0 ]; then echo '--- journal tail'; cat "$WORK/journal-tail.log"; fi
  suite_early_end "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP

echo "== the previous release, $PREV, installed from its published artifacts"
git -c advice.detachedHead=false clone -q --depth 1 --branch "$PREV" "$REPO" "$WORK/previous" || die "cannot clone $PREV"
curl -fsSL "$REL_URL/SHA256SUMS-x86_64" -o "$WORK/prev.sums" || die "$PREV has no SHA256SUMS-x86_64"
OLD_INIT=$(awk '$2 == "briqyard-init-linux-x86_64" {print $1}' "$WORK/prev.sums")
NEW_INIT=$(awk '$2 == "briqyard-init-linux-x86_64" {print $1}' "$HEAD_DIR/SHA256SUMS-x86_64")
[[ "$OLD_INIT" =~ ^[a-f0-9]{64}$ && "$NEW_INIT" =~ ^[a-f0-9]{64}$ ]] || die "an init digest is missing from a SHA256SUMS"
echo "   init digest: previous ${OLD_INIT:0:12}, head ${NEW_INIT:0:12}"
sudo iptables -P FORWARD ACCEPT 2>/dev/null; sudo systemctl stop docker.service docker.socket 2>/dev/null; sudo iptables -P FORWARD ACCEPT
command -v conntrack >/dev/null || { sudo apt-get update -qq; sudo apt-get install -y -qq conntrack; }
# Its own bootstrap, over HTTPS from the release, every binary checked against its SHA256SUMS.
sudo env BRIQYARD_RELEASE="$REL_URL" BRIQYARD_POOL_FILE_GB=40 BRIQYARD_ARC_GB=1 LISTEN=127.0.0.1:7420 \
  bash "$WORK/previous/hack/bootstrap-host.sh" || die "the previous release's bootstrap failed"
PREV_VER=$(briqyardd --version | awk '{print $2}')
echo "   installed: $(briqyardd --version)"
sudo systemctl stop briqyardd
sudo env TOKEN=$TOKEN OLD_INIT=$OLD_INIT python3 - <<'PY' || die "configuration"
import os
from pathlib import Path
import yaml
p = Path('/etc/briqyard/config.yaml')
c = yaml.safe_load(p.read_text())
c['token'] = os.environ['TOKEN']
c['backup'] = {'store': 'file:///var/lib/briqyard/backups'}
c['network']['host_ports'] = [9443]
c['ingress'].update(tcp_ports='30000-32767', http='127.0.0.1:8080', advertise='127.0.0.1')
c['registry_mirrors'] = {'docker.io': 'http://127.0.0.1:7440'}
c['capacity'] = {'memory_mb': 12288, 'vcpus': 24}
init = os.environ['OLD_INIT']
c['templates'] = {'enabled': True, 'init_ready_init_sha256': init, 'sandbox_recipes': [
    {'image': 'docker.io/library/alpine@sha256:85f2b723e106c34644cd5851d7e81ee87da98ac54672b29947c052a45d31dc2f',
     'image_config_digest': 'sha256:706db57fb2063f39f69632c5b5c9c439633fda35110e65587c5d85553fd1cc38',
     'init_sha256': init, 'size': {'vcpus': 1, 'memory_mb': 256}, 'volume_gb': 0}]}
p.write_text(yaml.safe_dump(c, sort_keys=False).replace('  host_ports:\n  - 9443\n', '  host_ports: [9443]\n'))
PY
# The previous fleet, from the same release, with the unit and the SSH key the real setup has.
sudo systemctl start ssh
cat > "$WORK/fleet.yaml" <<YAML
listen: 127.0.0.1:7430
tls: off
state_dir: /var/lib/briqyard-fleet
hosts:
  - id: local
    url: http://127.0.0.1:7420
    token: $TOKEN
    region: dev
placement:
  fill_ceiling: 0.85
  down_after_sec: 60
YAML
sudo install -m 0644 "$WORK/fleet.yaml" /etc/briqyard/fleet.yaml
sudo cp "$WORK/previous/hack/briqyard-fleet.service" /etc/systemd/system/briqyard-fleet.service
[ -f /etc/briqyard/fleet_ssh_key ] || sudo ssh-keygen -q -t ed25519 -N "" -C briqyard-fleet -f /etc/briqyard/fleet_ssh_key
sudo install -d -m 0700 /root/.ssh
sudo sh -c 'grep -qxF "$(cat /etc/briqyard/fleet_ssh_key.pub)" /root/.ssh/authorized_keys 2>/dev/null || cat /etc/briqyard/fleet_ssh_key.pub >> /root/.ssh/authorized_keys'
sudo bash "$HARNESS/install-mirror.sh" >/dev/null || die "registry mirror"
sudo systemctl daemon-reload
sudo systemctl enable briqyardd briqyard-fleet >/dev/null 2>&1
sudo systemctl restart briqyardd briqyard-fleet
for _ in $(seq 1 60); do briqyard status >/dev/null 2>&1 && curl -fsS $FLEET/v1/hosts | jq -e 'length == 1 and all(.state == "ready")' >/dev/null 2>&1 && break; sleep 1; done
curl -fsS $FLEET/v1/hosts | jq -e 'all(.state == "ready")' >/dev/null || die "the previous fleet and host did not become ready"
echo "   fleet: $(briqyard-fleet --version)"
for _ in $(seq 1 60); do [ -n "$(hostf .version)" ] && break; sleep 1; done
echo "   host version: $(hostf .version), installed: $PREV_VER"
check "the host runs the previous release" '[ "$(hostf .version)" = "$PREV_VER" ] && [[ "$PREV_VER" == "${PREV#v}"* ]]'

echo "== state: machines of every kind"
IMG=alpine:3.20
# Volume, sleep never: the shapes a production host holds.
PG=$(briqyard machine run --image postgres:16-alpine --name pg --namespace $NS --memory 512 --volume 2G:/var/lib/postgresql/data -e POSTGRES_PASSWORD=secret --port 5432 --sleep never | jq -r .id) || die pg
WEB=$(briqyard machine run --image python:3.12-alpine --name web --namespace $NS --memory 128 --port 8080 --sleep never -- sh -c 'mkdir -p /www; echo upgrade-ci-page > /www/index.html; exec python3 -m http.server 8080 -d /www' | jq -r .id) || die web
VOL=$(briqyard machine run --image $IMG --name vol --namespace $NS --memory 128 --volume 1G:/data --sleep never -- sleep 86400 | jq -r .id) || die vol
STP=$(briqyard machine run --image $IMG --name stopped --namespace $NS --memory 128 --sleep never -- sleep 86400 | jq -r .id) || die stopped
SUS=$(briqyard machine run --image $IMG --name suspended --namespace $NS --memory 128 --sleep never -- sleep 86400 | jq -r .id) || die suspended
for id in $PG $WEB $VOL $STP $SUS; do wait_running "$id" || die "$id did not run"; done
ready "$PG" || die "postgres did not become ready"
briqyard machine exec "$PG" -- psql -U postgres -c "create table t(x int); insert into t select generate_series(1,100);" >/dev/null || die "pg data"
briqyard machine exec "$VOL" -- sh -c 'echo volume-mark > /data/mark; sync' || die "volume mark"
briqyard machine exec "$SUS" -- sh -c 'echo memory-mark > /dev/shm/mark' || die "memory mark"
briqyard machine stop "$STP" >/dev/null || die "stop"
briqyard machine stop --suspend "$SUS" >/dev/null || die "suspend"
PGADDR=$(briqyard endpoint add "$PG" 5432 | jq -r .address)
WEBADDR=$(briqyard endpoint add "$WEB" 8080 | jq -r .address)
[ -n "$PGADDR" ] && [ -n "$WEBADDR" ] || die "endpoints"
for _ in $(seq 1 60); do curl -fsS -m 3 "http://$WEBADDR/" 2>/dev/null | grep -q upgrade-ci-page && break; sleep 1; done
curl -fsS -m 5 "http://$WEBADDR/" | grep -q upgrade-ci-page || die "the endpoint does not serve"
# A backup of the database, then more rows: the restore must give the earlier ones.
BK=$(briqyard machine backup "$PG" | jq -r .id) || die backup
briqyard machine exec "$PG" -- psql -U postgres -c "insert into t select generate_series(101,150);" >/dev/null || die "pg more data"
# A sealed seed (its builder stays, with its snapshot) and a clone made from it.
seal_machine() { # <name> -> create JSON for a clone of the seed
  jq -n --arg ns "$NS" --arg image docker.io/library/alpine@sha256:85f2b723e106c34644cd5851d7e81ee87da98ac54672b29947c052a45d31dc2f --arg name "$1" --arg source "$SEED" --arg snap "$SNAP" --arg gen "$GEN" \
    '{namespace:$ns,name:$name,image:$image,size:{vcpus:1,memory_mb:256},sleep:"never",start:true,cmd:["/bin/sh","-ec","sleep infinity"],sandbox_seed:{machine_id:$source,snapshot:$snap,generation:$gen,request_id:$name}}'
}
SEED=$(jq -n --arg ns "$NS" --arg image docker.io/library/alpine@sha256:85f2b723e106c34644cd5851d7e81ee87da98ac54672b29947c052a45d31dc2f \
  '{namespace:$ns,name:"seed-builder",image:$image,size:{vcpus:1,memory_mb:256},sleep:"never",start:true,egress:{mode:"none"},template_build:"sandbox-ready-v1"}' |
  dapi -H 'Content-Type: application/json' -d @- http://127.0.0.1:7420/v1/machines | jq -er .id) || die "seed builder"
dapi -X POST "http://127.0.0.1:7420/v1/machines/$SEED/wait?for=running&timeout=120" >/dev/null || die "seed builder did not run"
SNAPJSON=$(dapi -H 'Content-Type: application/json' -d '{"memory":true,"template":true}' "http://127.0.0.1:7420/v1/machines/$SEED/snapshots") || die "seal"
SNAP=$(echo "$SNAPJSON" | jq -r .id); GEN=$(echo "$SNAPJSON" | jq -r .clone_generation)
[ "$GEN" != null ] || die "the seed was not sealed"
C0=$(seal_machine pre-clone | dapi -H 'Content-Type: application/json' -d @- http://127.0.0.1:7420/v1/machines | jq -er .id) || die "a clone of the seed, before the upgrade"
dapi -X POST "http://127.0.0.1:7420/v1/machines/$C0/wait?for=running&timeout=120" >/dev/null || die "the clone did not run"
check "state: a seed's clone runs on $PREV" '[ "$(briqyard machine exec "$C0" -- echo sealed)" = sealed ]'
briqyard machine rm "$C0" >/dev/null

echo "== history: machines made and destroyed, VMMs killed, idle cgroups left"
for i in $(seq 1 20); do
  h=$(briqyard machine run --image $IMG --name "hist$i" --namespace $NS --memory 128 -- sleep 3600 | jq -r .id) && wait_running "$h" && briqyard machine rm "$h" >/dev/null
done
for i in 1 2 3 4 5; do
  k=$(briqyard machine run --image $IMG --name "killed$i" --namespace $NS --memory 128 -- sleep 3600 | jq -r .id) || die killed
  wait_running "$k" || die "killed$i did not run"
  for p in $(sudo cat "$(cgdir "$k")/cgroup.procs"); do sudo kill -9 "$p"; done
  # Down before the restart policy brings it back (10 s): the killed VMM stays behind it.
  briqyard machine stop "$k" >/dev/null 2>&1
  for _ in $(seq 1 30); do [ "$(briqyard machine get "$k" | jq -r .state)" = stopped ] && break; sleep 1; done
  [ $i -le 2 ] && briqyard machine rm "$k" >/dev/null
done
sudo sh -c "cd $PARENT && awk 'BEGIN{for(i=0;i<$LEAVES;i++)printf \"m-5ca1%08x\\n\", i}' | xargs mkdir"
check "state: $LEAVES idle cgroups beside the machines' own" '[ "$(made)" = "$LEAVES" ]'
echo "   cgroup leaves before the upgrade: $(leaves)"

RUNNING="$PG $WEB $VOL $SEED"
: > "$WORK/before"
for id in $RUNNING; do
  v=$(vmm "$id"); [ -n "$v" ] || die "no VMM found in the cgroup of $id"
  echo "$id $v" >> "$WORK/before"
done
sed 's/^/   VMM before: /' "$WORK/before"
for id in $PG $WEB $VOL; do briqyard machine exec "$id" -- true >/dev/null 2>&1 || die "$id does not answer before the upgrade"; done

echo "== upgrade in place to the head, through the fleet (ADR 0027)"
# Probes: the web endpoint and the daemon's API, every 50 ms, from before the upgrade to after it.
probe() { # <name> <curl args...>: lines of "<epoch seconds> ok|fail"
  local name=$1; shift
  ( while :; do
      if curl -fsS -m 2 -o /dev/null "$@" 2>/dev/null; then r=ok; else r=fail; fi
      echo "$(date +%s.%N) $r"; sleep 0.05
    done ) > "$WORK/$name.probe" &
  PROBES+=($!)
}
probe endpoint "http://$WEBADDR/"
probe api -H "Authorization: Bearer $TOKEN" http://127.0.0.1:7420/v1/status
sleep 5
BEFORE_START=$(hostf .started.at)
SINCE=$(date '+%Y-%m-%d %H:%M:%S')
# The fleet first, then the host (docs/OPERATIONS.md#upgrade).
sudo install -m 0755 "$HEAD_DIR/briqyard-fleet-linux-x86_64" /usr/local/bin/briqyard-fleet
sudo install -m 0755 "$HEAD_DIR/briqyard-linux-x86_64" /usr/local/bin/briqyard
sudo systemctl restart briqyard-fleet
for _ in $(seq 1 60); do curl -fsS $FLEET/v1/hosts 2>/dev/null | jq -e 'length == 1 and all(.state == "ready")' >/dev/null && break; sleep 1; done
curl -fsS $FLEET/v1/hosts | jq -e 'all(.state == "ready")' >/dev/null || die "the head fleet did not see the host ready"
R=/var/lib/briqyard-fleet/release
sudo rm -rf $R && sudo mkdir -p $R && sudo cp "$HEAD_DIR"/* $R/
HEAD_VER=$(briqyard --version | awk '{print $2}')
t0=$SECONDS
out=$(fleet host upgrade local --release "file://$R" 2>&1); urc=$?
UPGRADE_SECONDS=$((SECONDS - t0))
echo "$out" | sed 's/^/       /'
echo "   host upgrade took ${UPGRADE_SECONDS} s (rc $urc)"
sleep 10
echo '--- the daemon journal through the upgrade (requests left out)'
sudo journalctl -u briqyardd --since "$SINCE" --no-pager -o cat | grep -v '"message":"request"\|Got notification' | cut -c1-330 | head -150
echo '---'
for p in "${PROBES[@]}"; do kill "$p" 2>/dev/null; done; PROBES=()
sleep 1

# The longest silence of a probe and its failures, from its log; seconds with milliseconds.
gap() { awk '$2 == "ok" { if (last && $1 - last > g) g = $1 - last; last = $1 } END { printf "%.2f", g }' "$WORK/$1.probe"; }
fails() { grep -c ' fail$' "$WORK/$1.probe"; }
total() { wc -l < "$WORK/$1.probe"; }
API_GAP=$(gap api); EP_GAP=$(gap endpoint)
echo "   API: longest silence ${API_GAP} s, $(fails api) failed of $(total api) polls"
echo "   endpoint: longest gap ${EP_GAP} s, $(fails endpoint) failed of $(total endpoint) polls"
{
  echo "upgrade ${PREV} -> ${HEAD_VER}: host upgrade ${UPGRADE_SECONDS} s; API down ${API_GAP} s ($(fails api) failed polls); endpoint gap ${EP_GAP} s ($(fails endpoint) failed polls)"
} >> "${GITHUB_STEP_SUMMARY:-/dev/null}"

echo "== after the upgrade"
check "the upgrade reported success" '[ "$urc" = 0 ] && echo "$out" | grep -q "local: upgraded to $HEAD_VER"'
check "the host is ready on the head, a new daemon start" '[ "$(hostf .state)" = ready ] && [ "$(hostf .version)" = "$HEAD_VER" ] && [ "$(hostf .started.at)" != "$BEFORE_START" ]'
check "nothing stopped, every running machine adopted" '[ "$(hostf .started.stopped)" = 0 ] && [ "$(hostf .started.adopted)" -ge 4 ]'
check "memory_protection is clear" 'briqyard status | jq -e "all(.conditions[] | select(.type == \"memory_protection\"); .status == false)" >/dev/null'
check "no condition says recovery_unresolved" '! briqyard status | grep -q recovery_unresolved'
echo "   status: $(briqyard status | jq -c '[.conditions[] | select(.status) | .type]')"
check "the API was silent at most ${API_DOWN_MAX} s" 'awk -v g="$API_GAP" -v m="$API_DOWN_MAX" "BEGIN{exit !(g <= m)}"'
check "the endpoint served throughout, no gap over ${GAP_MAX} s" 'awk -v g="$EP_GAP" -v m="$GAP_MAX" "BEGIN{exit !(g <= m && g > 0)}"'
for id in $RUNNING; do
  was=$(awk -v i="$id" '$1 == i {print $2}' "$WORK/before")
  check "the VMM of $id is the same process (pid:start $was)" '[ "$(vmm "$id")" = "$was" ] && [ "$(briqyard machine get "$id" | jq -r .state)" = running ]'
done
boots() { briqyard machine logs "$1" --limit 5000 | grep -c "\[briqyard\] started"; }
check "never booted again" '[ "$(boots "$PG")" = 1 ] && [ "$(boots "$WEB")" = 1 ] && [ "$(boots "$VOL")" = 1 ]'
check "data: postgres has its rows" '[ "$(briqyard machine exec "$PG" -- psql -U postgres -tAc "select sum(x) from t")" = 11325 ]'
check "data: through the postgres endpoint" '[ "$(PGPASSWORD=secret psql -h ${PGADDR%:*} -p ${PGADDR#*:} -U postgres -tAc "select count(*) from t")" = 150 ]'
check "data: the volume's file" '[ "$(briqyard machine exec "$VOL" -- cat /data/mark)" = volume-mark ]'
check "data: the web machine serves its page through its endpoint" '[ "$(curl -fsS -m 5 "http://$WEBADDR/")" = upgrade-ci-page ]'
check "the stopped machine stays stopped" '[ "$(briqyard machine get "$STP" | jq -r .state)" = stopped ]'
briqyard machine start "$STP" >/dev/null 2>&1
check "the stopped machine starts and answers" 'wait_running "$STP" && [ "$(briqyard machine exec "$STP" -- echo up)" = up ]'
check "the suspended machine stays suspended" '[ "$(briqyard machine get "$SUS" | jq -r .suspended)" = true ]'
briqyard machine start "$SUS" >/dev/null 2>&1
check "the suspended machine resumes with its memory" 'wait_running "$SUS" && [ "$(briqyard machine exec "$SUS" -- cat /dev/shm/mark)" = memory-mark ] && [ "$(briqyard events --machine "$SUS" | awk "\$4 == \"resumed\"" | wc -l)" = 1 ]'

# ADR 0101: a seed is bound to the init's digest. Same digest: the clone is accepted. Another: the
# templates are off and the clone is refused, with a client error that says so, never a 5xx.
echo "   init digest previous ${OLD_INIT:0:12}, head ${NEW_INIT:0:12}"
code=$(seal_machine post-clone | curl -sS -o "$WORK/clone.out" -w '%{http_code}' -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d @- http://127.0.0.1:7420/v1/machines)
if [ "$OLD_INIT" = "$NEW_INIT" ]; then
  check "seed: the init is unchanged, so the clone is accepted" '[ "$code" = 200 ] || [ "$code" = 201 ]'
  [ -z "$(jq -r '.id // empty' "$WORK/clone.out" 2>/dev/null)" ] || briqyard machine rm "$(jq -r .id "$WORK/clone.out")" >/dev/null 2>&1
else
  check "seed: the init changed, so the clone is refused (HTTP $code) by a client error" '[ "$code" -ge 400 ] && [ "$code" -lt 500 ]'
  echo "       refusal: $(head -c 300 "$WORK/clone.out")"
fi

BR=$(briqyard machine restore --from "$PG" --backup "$BK" --namespace $NS --name restored-after | jq -r .id)
check "a backup from before the upgrade restores, with the earlier rows" '[ -n "$BR" ] && ready "$BR" && [ "$(briqyard machine exec "$BR" -- psql -U postgres -tAc "select count(*) from t")" = 100 ]'
NEW=$(briqyard machine run --image $IMG --name after --namespace $NS --memory 128 -- sleep 3600 | jq -r .id)
check "a new create runs" '[ -n "$NEW" ] && wait_running "$NEW" && [ "$(briqyard machine exec "$NEW" -- echo made)" = made ]'
a=0; for _ in $(seq 1 120); do [ "$(made)" = 0 ] && a=1 && break; sleep 1; done
check "the idle cgroups were retired" '[ "$a" = 1 ]'
echo "   cgroup leaves after: $(leaves)"
check "a second backup works on the head" '[ -n "$(briqyard machine backup "$PG" | jq -r .id)" ]'

for id in $(briqyard machine ls --namespace $NS 2>/dev/null | awk 'NR>1{print $1}'); do briqyard machine rm "$id" >/dev/null 2>&1; done
briqyard namespace rm $NS >/dev/null 2>&1
echo "result: ${PREV} -> ${HEAD_VER}: API down ${API_GAP} s, endpoint gap ${EP_GAP} s, host upgrade ${UPGRADE_SECONDS} s"
suite_summary

#!/usr/bin/env bash
# Drives the whole machine flow through a briqyard-fleet ($BRIQYARD_URL, default
# http://127.0.0.1:7430, with $BRIQYARD_TOKEN) that fronts at least one daemon. Makes and removes
# one machine in the tenant "fleet-smoke". The hosts part drains and forgets only the dev fleet's
# own host `local` (it comes back on the next poll): against a real fleet, it leaves its hosts
# alone. `/metrics` is read with $BRIQYARD_METRICS_TOKEN when the fleet has a metrics_token.
# With the release directory hack/vm.sh installs, it also upgrades the VM's own host through the
# fleet (the same build again, over SSH to itself) with a machine running.
set -euo pipefail
export BRIQYARD_URL=${BRIQYARD_URL:-http://127.0.0.1:7430}
auth=(); [ -n "${BRIQYARD_TOKEN:-}" ] && auth=(-H "Authorization: Bearer $BRIQYARD_TOKEN")
api() { curl -fsS ${auth[@]+"${auth[@]}"} "$BRIQYARD_URL$1"; }
T=fleet-smoke
pass=0; fail=0
ok()   { pass=$((pass+1)); echo "  ok   $1"; }
bad()  { fail=$((fail+1)); echo "  FAIL $1"; }
check(){ if eval "$2"; then ok "$1"; else bad "$1"; fi; }
hosts() { api /v1/hosts; }
host_field() { hosts | jq -r ".[] | select(.id == \"$1\") | $2"; }
# Run on any exit, a failed check, Ctrl-C or a kill included: the hosts it drained are undrained,
# what it made is destroyed.
DRAINED=
cleanup() {
  # Every step best-effort: one that fails leaves the others to run and the exit status as it was.
  set +e
  for h in $DRAINED; do briqyard host undrain "$h" >/dev/null 2>&1 || true; done
  for t in "$T" "$T-2" "$T-up"; do
    for id in $(briqyard machine ls --tenant "$t" 2>/dev/null | awk 'NR>1{print $1}'); do briqyard machine destroy "$id" >/dev/null 2>&1 || true; done
    briqyard tenant rm "$t" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT
trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP

echo "== fleet"
check "status"          'api "/v1/status" | jq -e ".hosts >= 1" >/dev/null'
# Every listed host ready first: a fleet just restarted is still hearing from its hosts, and a
# listing fails whole while one does not answer (ADR 0006).
for i in $(seq 1 60); do api "/v1/hosts" | jq -e 'length > 0 and all(.state == "ready" and .capacity.memory_mb > 0)' >/dev/null 2>&1 && break; sleep 1; done
check "a ready host"    'api "/v1/hosts" | jq -e ".[] | select(.state == \"ready\" and .capacity.memory_mb > 0)" >/dev/null'
# The capacity signals (ADR 0042): every region a host is in has the room and the refusals.
mtoken=${BRIQYARD_METRICS_TOKEN:-${BRIQYARD_TOKEN:-}}
mauth=(); [ -n "$mtoken" ] && mauth=(-H "Authorization: Bearer $mtoken")
metrics=$(curl -sS ${mauth[@]+"${mauth[@]}"} -w '\n%{http_code}' "$BRIQYARD_URL/metrics" || true)
check "metrics: 200, ready hosts" '[ "$(tail -n1 <<<"$metrics")" = 200 ] && grep -Eq "^briqyard_fleet_hosts\{state=\"ready\"\} [1-9]" <<<"$metrics"'
check "metrics: the room" 'grep -q "^briqyard_fleet_free_mb{resource=\"memory\"" <<<"$metrics" && grep -q "^briqyard_fleet_largest_slot_mb{resource=\"memory\"" <<<"$metrics"'
check "metrics: the refusals" 'grep -q "^briqyard_fleet_unschedulable_total{resource=\"memory\"" <<<"$metrics"'
# A fleet that asks a token for its API and is reached over TLS asks one for /metrics too (on
# a loopback listener with tls unset, /metrics is open, as the daemon's).
if [[ $BRIQYARD_URL == https://* ]] && [ "$(curl -s -o /dev/null -w '%{http_code}' "$BRIQYARD_URL/v1/status")" = 401 ]; then
  check "metrics: 401 without a token" '[ "$(curl -s -o /dev/null -w "%{http_code}" "$BRIQYARD_URL/metrics")" = 401 ]'
fi
M=$(briqyard machine run --image alpine:3.20 --name viafleet --tenant "$T" --memory 256 --volume 1G:/data -- sleep 3600 | jq -r .id)
check "created, placed" '[ -n "$(briqyard machine get "$M" | jq -r .host)" ]'
check "running"         '[ "$(briqyard machine get "$M" | jq -r .state)" = running ]'
check "exec forwarded"  '[ "$(briqyard machine exec "$M" -- hostname)" = viafleet ]'
check "session forwarded" '[ "$(echo hi | briqyard machine exec -i "$M" -- cat)" = hi ]'
check "tty forwarded"   'python3 "$(dirname "$0")/exec-tty.py" 30x100 "send:stty size; exit 3\n" "expect:30 100" -- briqyard machine exec -it "$M" -- sh >/dev/null; [ $? = 3 ]'
check "listed with host" 'briqyard machine ls | grep "$M" | grep -q "[a-z]"'
EP=$(briqyard endpoint add "$M" 80 | jq -r .id)
check "endpoint forwarded" 'briqyard endpoint ls | grep -q "$EP"'
check "endpoint by id"  'api "/v1/endpoints/$EP" | jq -e .address >/dev/null'
check "tenant pinned"   'briqyard tenant ls | jq -e ".[] | select(.id == \"$T\") | .host" >/dev/null'
check "logs forwarded"  'briqyard machine logs "$M" --limit 5000 | grep -q "\[briqyard\] started"'
check "a volume's growth forwarded" '[ "$(briqyard machine set "$M" --volume-gb 2 | jq -r "[.volume.size_gb, .pending.fields[0]] | join(\" \")")" = "2 volume" ]'
briqyard machine stop "$M" >/dev/null
check "stop forwarded"  '[ "$(briqyard machine get "$M" | jq -r .state)" = stopped ]'
briqyard machine destroy "$M"
check "destroyed"       '! briqyard machine get "$M" >/dev/null 2>&1'
briqyard tenant rm "$T"
check "tenant unpinned" '! briqyard tenant ls | jq -e ".[] | select(.id == \"$T\")" >/dev/null 2>&1'
# The fleet's own static host of hack/fleet.dev.yaml, never another: forgetting a host drops
# its pool key with its record (ADR 0026); a second host (fc2) is refused, and drained it would
# take no tenant.
LOCAL=$(api /v1/hosts | jq -r '.[] | select(.id == "local" and .state == "ready" and .provider == "static") | .id')
if [ -z "$LOCAL" ]; then
  echo
  echo "passed $pass, failed $fail (no host local to drain)"
  [ "$fail" = 0 ]; exit
fi
echo "== hosts: drain and forget the host local"
DRAINED=$LOCAL
briqyard host drain "$LOCAL"
check "draining"          '[ "$(host_field "$LOCAL" .state)" = draining ]'
# One host: the create is refused. Several: it lands on another one. Never on the draining host.
check "no placement on a draining host" '[ "$(briqyard machine run --image alpine:3.20 --name nohost --tenant "$T-2" --memory 256 -- true 2>/dev/null | jq -r .host)" != "$LOCAL" ]'
briqyard host undrain "$LOCAL"
check "undrained"         '[ "$(host_field "$LOCAL" .state)" = ready ]'
briqyard host drain "$LOCAL"
briqyard host rm "$LOCAL"
DRAINED=
sleep 16
check "back after rm (a static host is polled again)" 'briqyard host ls | awk "NR>1" | grep -q ready'

REL=/var/lib/briqyard-fleet/release
# The fleet keeps its state directory to itself: root looks.
if sudo -n test -d "$REL" 2>/dev/null; then
  echo "== host upgrade: this build again, a machine running (ADR 0027)"
  # The VM's own host, the one the fleet reaches over SSH; the machine is placed there.
  UP=$(hosts | jq -r '.[] | select(.url | test("//127[.]0[.]0[.]1:")) | .id')
  OTHERS=$(hosts | jq -r ".[] | select(.state == \"ready\" and .id != \"$UP\") | .id")
  DRAINED=$OTHERS
  for h in $OTHERS; do briqyard host drain "$h"; done
  U=$(briqyard machine run --image alpine:3.20 --name up --tenant "$T-up" --memory 128 -- sleep 3600 | jq -r .id)
  for h in $OTHERS; do briqyard host undrain "$h"; done
  DRAINED=
  before=$(host_field "$UP" .started.at)
  build=$(briqyard --version | awk '{print $2}')
  out=$(briqyard host upgrade "$UP" --release "file://$REL" 2>&1) || true
  echo "$out" | sed 's/^/       /'
  check "upgraded"              'echo "$out" | grep -q "$UP: upgraded to $build"'
  check "host ready (undrained)" '[ "$(host_field "$UP" .state)" = ready ]'
  check "a new daemon start"    '[ "$(host_field "$UP" .started.at)" != "$before" ]'
  check "it runs this build"    '[ "$(host_field "$UP" .version)" = "$build" ]'
  check "the machine handed over" '[ "$(host_field "$UP" .started.stopped)" = 0 ] && [ "$(host_field "$UP" .started.adopted)" -ge 1 ]'
  check "it still answers"      '[ "$(briqyard machine exec "$U" -- hostname)" = up ]'
  check "never booted again"    '[ "$(briqyard machine logs "$U" --limit 5000 | grep -c "\[briqyard\] started")" = 1 ]'
  check "its init says its version" '[ "$(briqyard machine get "$U" | jq -r .init_version)" = "$build" ]'
  check "a release neither URL nor version refused" '! briqyard host upgrade "$UP" --release "not a release" >/dev/null 2>&1'
fi
echo
echo "passed $pass, failed $fail"
[ "$fail" = 0 ]

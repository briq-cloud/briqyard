#!/usr/bin/env bash
# Drives the whole machine flow through a briqyard-fleet ($BRIQYARD_URL, default
# http://127.0.0.1:7430, with $BRIQYARD_TOKEN) that fronts at least one daemon. Makes and removes
# one machine in the tenant "fleet-smoke". The hosts part orders and retires only through a
# dry-run provisioner, and drains and forgets only a host of the fleet's `hosts:` (it comes back
# on the next poll): against a real fleet, it leaves its hosts alone.
set -euo pipefail
export BRIQYARD_URL=${BRIQYARD_URL:-http://127.0.0.1:7430}
auth=(); [ -n "${BRIQYARD_TOKEN:-}" ] && auth=(-H "Authorization: Bearer $BRIQYARD_TOKEN")
api() { curl -fsS ${auth[@]+"${auth[@]}"} "$BRIQYARD_URL$1"; }
T=fleet-smoke
pass=0; fail=0
ok()   { pass=$((pass+1)); echo "  ok   $1"; }
bad()  { fail=$((fail+1)); echo "  FAIL $1"; }
check(){ if eval "$2"; then ok "$1"; else bad "$1"; fi; }
cleanup() {
  for t in "$T" "$T-2"; do
    for id in $(briqyard machine ls --tenant "$t" 2>/dev/null | awk 'NR>1{print $1}'); do briqyard machine destroy "$id" >/dev/null 2>&1 || true; done
    briqyard tenant rm "$t" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

echo "== fleet"
check "status"          'api "/v1/status" | jq -e ".hosts >= 1" >/dev/null'
# Every listed host ready first: a fleet just restarted is still hearing from its hosts, and a
# listing fails whole while one does not answer (ADR 0006).
for i in $(seq 1 60); do api "/v1/hosts" | jq -e 'length > 0 and all(.state == "ready" and .capacity.memory_mb > 0)' >/dev/null 2>&1 && break; sleep 1; done
check "a ready host"    'api "/v1/hosts" | jq -e ".[] | select(.state == \"ready\" and .capacity.memory_mb > 0)" >/dev/null'
M=$(briqyard machine run --image alpine:3.20 --name viafleet --tenant "$T" --memory 256 -- sleep 3600 | jq -r .id)
check "created, placed" '[ -n "$(briqyard machine get "$M" | jq -r .host)" ]'
check "running"         '[ "$(briqyard machine get "$M" | jq -r .state)" = running ]'
check "exec forwarded"  '[ "$(briqyard machine exec "$M" -- hostname)" = viafleet ]'
check "listed with host" 'briqyard machine ls | grep "$M" | grep -q "[a-z]"'
EP=$(briqyard endpoint add "$M" 80 | jq -r .id)
check "endpoint forwarded" 'briqyard endpoint ls | grep -q "$EP"'
check "endpoint by id"  'api "/v1/endpoints/$EP" | jq -e .address >/dev/null'
check "tenant pinned"   'briqyard tenant ls | jq -e ".[] | select(.id == \"$T\") | .host" >/dev/null'
check "logs forwarded"  'briqyard machine logs "$M" --limit 5000 | grep -q "\[briqyard\] started"'
briqyard machine stop "$M" >/dev/null
check "stop forwarded"  '[ "$(briqyard machine get "$M" | jq -r .state)" = stopped ]'
briqyard machine destroy "$M"
check "destroyed"       '! briqyard machine get "$M" >/dev/null 2>&1'
briqyard tenant rm "$T"
check "tenant unpinned" '! briqyard tenant ls | jq -e ".[] | select(.id == \"$T\")" >/dev/null 2>&1'
if [ "$(api /v1/status | jq -r '.dry_run and .provisioner != "static"')" = true ]; then
  echo "== hosts: order and retire (dry run)"
  H=$(briqyard host order --reason smoke | jq -r .id)
  check "ordered (dry-run)" '[ "$(api "/v1/hosts" | jq -r ".[] | select(.id == \"$H\") | .state")" = dry-run ]'
  check "retired at once"   '[ "$(briqyard host retire "$H" | jq -r .state)" = released ]'
  check "gone"              '! briqyard host ls | grep -q "$H"'
fi
LOCAL=$(api /v1/hosts | jq -r '[.[] | select(.state == "ready" and .provider == "static")][0].id // empty')
if [ -z "$LOCAL" ]; then
  echo
  echo "passed $pass, failed $fail (no host of hosts: to drain)"
  [ "$fail" = 0 ]; exit
fi
echo "== hosts: drain and forget a host of hosts:"
briqyard host drain "$LOCAL"
check "draining"          '[ "$(api "/v1/hosts" | jq -r ".[] | select(.id == \"$LOCAL\") | .state")" = draining ]'
# One host: the create is refused. Several: it lands on another one. Never on the draining host.
check "no placement on a draining host" '[ "$(briqyard machine run --image alpine:3.20 --name nohost --tenant "$T-2" --memory 256 -- true 2>/dev/null | jq -r .host)" != "$LOCAL" ]'
briqyard host rm "$LOCAL"
sleep 16
check "back after rm (a static host is polled again)" 'briqyard host ls | awk "NR>1" | grep -q ready'
echo
echo "passed $pass, failed $fail"
[ "$fail" = 0 ]

#!/usr/bin/env bash
# Checks a fleet (default http://127.0.0.1:7430) that fronts at least two ready hosts: tenants
# land on different hosts, every call is forwarded to the right one, a host that stops
# answering is marked down and its tenant's calls fail cleanly while the other goes on.
# With SECOND_HOST_SH (a root shell on the second host), its pool is locked while it is down,
# as a reboot leaves it, and must come back with its key from the fleet (ADR 0026).
#   SECOND_HOST_STOP="limactl shell fc2 sudo systemctl stop briqyardd" \
#   SECOND_HOST_START="limactl shell fc2 sudo systemctl start briqyardd" \
#   SECOND_HOST_SH="limactl shell fc2 sudo" hack/fleet-two-hosts.sh
set -euo pipefail
export BRIQYARD_URL=${BRIQYARD_URL:-http://127.0.0.1:7430}
T=two-hosts
pass=0; fail=0
ok()   { pass=$((pass+1)); echo "  ok   $1"; }
bad()  { fail=$((fail+1)); echo "  FAIL $1"; }
check(){ if eval "$2"; then ok "$1"; else bad "$1"; fi; }
hosts() { curl -fsS "$BRIQYARD_URL/v1/hosts"; }
cleanup() {
  for t in "$T-a" "$T-b"; do
    for id in $(briqyard machine ls --tenant "$t" 2>/dev/null | awk 'NR>1{print $1}'); do briqyard machine destroy "$id" >/dev/null 2>&1 || true; done
    briqyard tenant rm "$t" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

echo "== two hosts"
for i in $(seq 1 30); do [ "$(hosts | jq '[.[] | select(.state == "ready" and .capacity.memory_mb > 0)] | length')" -ge 2 ] && break; sleep 2; done
check "two ready hosts" '[ "$(hosts | jq "[.[] | select(.state == \"ready\")] | length")" -ge 2 ]'
hosts | jq -r '.[] | "       \(.id)\t\(.state)\t\(.used.memory_mb)/\(.capacity.memory_mb) MB\t\(.url)"'

echo "== placement"
# Placement picks the host with the most free memory. The first tenant's machine takes enough
# of the emptiest host that the second tenant lands on the other one: the memory asked is
# whatever makes the two hosts' free memory cross (a guest that touches little of it costs
# little; Firecracker maps pages as they are used).
free_mb() { hosts | jq "[.[] | select(.state == \"ready\") | .capacity.memory_mb - .used.memory_mb] | sort | reverse | .[$1]"; }
BIG=$(( $(free_mb 0) - $(free_mb 1) + 512 )); [ "$BIG" -lt 256 ] && BIG=256
echo "       first machine asks ${BIG} MB so that the second tenant lands elsewhere"
A=$(briqyard machine run --image alpine:3.20 --name a --tenant "$T-a" --memory "$BIG" -- sleep 3600 | jq -r .id)
HA=$(briqyard machine get "$A" | jq -r .host)
B=$(briqyard machine run --image alpine:3.20 --name b --tenant "$T-b" --memory 256 -- sleep 3600 | jq -r .id)
HB=$(briqyard machine get "$B" | jq -r .host)
echo "       a on $HA, b on $HB"
check "tenants on different hosts" '[ "$HA" != "$HB" ] && [ -n "$HA" ] && [ -n "$HB" ]'
check "exec forwarded to a"  '[ "$(briqyard machine exec "$A" -- hostname)" = a ]'
check "exec forwarded to b"  '[ "$(briqyard machine exec "$B" -- hostname)" = b ]'
A2=$(briqyard machine run --image alpine:3.20 --name a2 --tenant "$T-a" --memory 256 -- sleep 3600 | jq -r .id)
check "a tenant stays on its host" '[ "$(briqyard machine get "$A2" | jq -r .host)" = "$HA" ]'
check "a2 reaches a by name"  'briqyard machine exec "$A2" -- ping -c1 -W2 a.internal >/dev/null'
check "machines listed with hosts" '[ "$(briqyard machine ls | awk "NR>1" | wc -l | tr -d " ")" -ge 3 ]'

if [ -n "${SECOND_HOST_STOP:-}" ]; then
  echo "== a host goes silent"
  # Whichever host holds b is the one we stop: the variables name the second host's commands,
  # so the caller makes sure b landed there (two equal hosts: b is on the second one).
  eval "$SECOND_HOST_STOP"
  for i in $(seq 1 45); do [ "$(hosts | jq -r ".[] | select(.id == \"$HB\") | .state")" = down ] && break; sleep 2; done
  check "host marked down"      '[ "$(hosts | jq -r ".[] | select(.id == \"$HB\") | .state")" = down ]'
  check "b fails cleanly"       '! briqyard machine exec "$B" -- hostname >/dev/null 2>&1'
  check "a still answers"       '[ "$(briqyard machine exec "$A" -- hostname)" = a ]'
  # A listing is never partial: the down host's tenant and the fleet-wide list refuse.
  check "listing b's tenant refuses" '! briqyard machine ls --tenant "$T-b" >/dev/null 2>&1'
  check "listing everything refuses" '! briqyard machine ls >/dev/null 2>&1'
  check "listing a's tenant works"   'briqyard machine ls --tenant "$T-a" | grep -q "$A"'
  check "no placement on a down host" '[ "$(briqyard machine run --image alpine:3.20 --name c --tenant "$T-b" --memory 256 -- true 2>&1 | grep -c "no host\|down\|unavailable")" -ge 1 ]'
  if [ -n "${SECOND_HOST_SH:-}" ]; then
    # Its pool's filesystems unmounted and its key unloaded: what a reboot leaves.
    on_second() { $SECOND_HOST_SH sh -c "$1"; }
    on_second 'zfs list -H -o name,mounted -t filesystem -r byard | awk '"'"'$2 == "yes" { print $1 }'"'"' | tac | xargs -r -n1 zfs unmount && zfs unload-key byard'
    check "its pool locked"       '[ "$(on_second "zfs get -H -o value keystatus byard")" = unavailable ]'
  fi
  eval "$SECOND_HOST_START"
  for i in $(seq 1 45); do [ "$(hosts | jq -r ".[] | select(.id == \"$HB\") | .state")" = ready ] && break; sleep 2; done
  check "host back"             '[ "$(hosts | jq -r ".[] | select(.id == \"$HB\") | .state")" = ready ]'
  if [ -n "${SECOND_HOST_SH:-}" ]; then
    check "with its pool encrypted and unlocked" '[ "$(on_second "zfs get -H -o value encryption,keystatus byard" | tr "\n" " ")" = "aes-256-gcm available " ]'
    check "by the fleet's key"    'on_second "journalctl -u briqyardd -b -o cat" | grep "pool key loaded" | tail -1 | grep -q "\"from\":\"fleet\""'
    # The key, asked of the fleet as the host does; it must be nowhere on the host's disk or
    # in its log, and in none of the fleet's answers but this one.
    conf=$(on_second "cat /etc/briqyard/config.yaml")
    token=$(echo "$conf" | sed -n 's/^token: "\(.*\)"$/\1/p')
    advertise=$(echo "$conf" | sed -n 's/^  advertise: //p')
    key=$(curl -fsS -X POST -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
      -d "{\"url\": \"$advertise\"}" "$BRIQYARD_URL/v1/hosts/key" | jq -r .key)
    found() { echo "$key" | $SECOND_HOST_SH sh -c 'k=$(cat); grep -rlsF -D skip "$k" /etc/briqyard /var/lib/briqyard --exclude=pool.img; journalctl -u briqyardd -b -o cat | grep -cF "$k"'; }
    check "its key on none of its files nor in its log" '[ "${#key}" = 64 ] && [ "$(found)" = 0 ]'
    check "nor in the fleet host list" '! hosts | grep -qF "$key"'
  fi
  for i in $(seq 1 30); do briqyard machine exec "$B" -- hostname >/dev/null 2>&1 && break; sleep 2; done
  check "b answers again"       '[ "$(briqyard machine exec "$B" -- hostname)" = b ]'
fi
echo
echo "passed $pass, failed $fail"
[ "$fail" = 0 ]

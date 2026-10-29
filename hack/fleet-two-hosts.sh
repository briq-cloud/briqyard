#!/usr/bin/env bash
# Checks a fleet ($BRIQYARD_URL, default http://127.0.0.1:7430, with $BRIQYARD_TOKEN) that
# fronts at least two ready hosts: tenants
# land on different hosts, every call is forwarded to the right one, a host that stops
# answering is marked down and its tenant's calls fail cleanly while the other goes on.
# With SECOND_HOST_SH (a root shell on the second host), its pool is locked while it is down,
# as a reboot leaves it, and must come back with its key from the fleet (ADR 0026); and a
# backup there is ciphertext and restores through the fleet (ADR 0035).
#   SECOND_HOST_STOP="limactl shell fc2 sudo systemctl stop briqyardd" \
#   SECOND_HOST_START="limactl shell fc2 sudo systemctl start briqyardd" \
#   SECOND_HOST_SH="limactl shell fc2 sudo" bash hack/fleet-two-hosts.sh
set -euo pipefail
export BRIQYARD_URL=${BRIQYARD_URL:-http://127.0.0.1:7430}
T=two-hosts
pass=0; fail=0
ok()   { pass=$((pass+1)); echo "  ok   $1"; }
bad()  { fail=$((fail+1)); echo "  FAIL $1"; }
check(){ if eval "$2"; then ok "$1"; else bad "$1"; fi; }
auth=(); [ -n "${BRIQYARD_TOKEN:-}" ] && auth=(-H "Authorization: Bearer $BRIQYARD_TOKEN")
hosts() { curl -fsS ${auth[@]+"${auth[@]}"} "$BRIQYARD_URL/v1/hosts"; }
CONF2=/etc/briqyard/config.yaml
# A script run on the second host as root with `ask_key BODY` (a POST /v1/hosts/key to the
# fleet in its config, with its token) and `$adv` (its advertised URL); stdin and arguments
# passed on.
as_second() {
  $SECOND_HOST_SH bash -c 'c='"$CONF2"'
    tok=$(sed -n "s/^token: *\"\{0,1\}\([^\"]*\)\"\{0,1\}$/\1/p" $c); adv=$(sed -n "s/^  advertise: //p" $c)
    fleet=$(sed -n "/^fleet:/,/^[^ ]/s/^  url: //p" $c)
    ask_key() { curl -fsS -X POST -H "Authorization: Bearer $tok" -H "Content-Type: application/json" -d "$1" "$fleet/v1/hosts/key"; }
    '"$1" _ "${@:2}"
}
# Run on any exit, a failed check, Ctrl-C or a kill included: the second host is started again
# when the run stopped it, what it made is destroyed, the second host's config put back.
STOPPED=
cleanup() {
  # Every step best-effort: one that fails leaves the others to run and the exit status as it was.
  set +e
  if [ -n "$STOPPED" ]; then
    eval "$SECOND_HOST_START" || true
    for i in $(seq 1 45); do [ "$(hosts | jq -r ".[] | select(.id == \"$HB\") | .state")" = ready ] && break; sleep 2; done
  fi
  for t in "$T-a" "$T-b"; do
    for id in $(briqyard machine ls --tenant "$t" 2>/dev/null | awk 'NR>1{print $1}'); do briqyard machine destroy "$id" >/dev/null 2>&1 || true; done
    briqyard tenant rm "$t" >/dev/null 2>&1 || true
  done
  # The second host as it was, when the backup section gave it a store for the run.
  if [ -n "${SECOND_HOST_SH:-}" ] && $SECOND_HOST_SH test -f "$CONF2.two-hosts"; then
    $SECOND_HOST_SH sh -c "mv $CONF2.two-hosts $CONF2 && rm -rf /var/lib/briqyard/backups && systemctl restart briqyardd" || true
    for i in $(seq 1 45); do [ "$(hosts | jq -r ".[] | select(.id == \"$HB\") | .state")" = ready ] && break; sleep 2; done
  fi
}
trap cleanup EXIT
trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP

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
  STOPPED=1
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
    started=$(on_second "date +%s")
  fi
  eval "$SECOND_HOST_START"
  STOPPED=
  for i in $(seq 1 45); do [ "$(hosts | jq -r ".[] | select(.id == \"$HB\") | .state")" = ready ] && break; sleep 2; done
  check "host back"             '[ "$(hosts | jq -r ".[] | select(.id == \"$HB\") | .state")" = ready ]'
  if [ -n "${SECOND_HOST_SH:-}" ]; then
    check "with its pool encrypted and unlocked" '[ "$(on_second "zfs get -H -o value encryption,keystatus byard" | tr "\n" " ")" = "aes-256-gcm available " ]'
    check "by the fleet's key"    'on_second "journalctl -u briqyardd --since @$started -o cat" | grep "pool key loaded" | grep -q "\"from\":\"fleet\""'
    # The key, asked of the fleet as the host does, from the host (the fleet checks a host's
    # calls by its address): nowhere on its disk or in its log, in none of the fleet's answers
    # but this one. Only counts leave the host.
    seen=$(hosts | as_second 'list=$(cat); key=$(ask_key "{\"url\": \"$adv\"}" | jq -r .key)
      echo "${#key} $(grep -rlsF -D skip "$key" /etc/briqyard /var/lib/briqyard --exclude=pool.img | wc -l) $(journalctl -u briqyardd -b -o cat | grep -cF "$key") $(echo "$list" | grep -cF "$key")"')
    check "its key on none of its files nor in its log" '[ "$(echo "$seen" | cut -d" " -f1-3)" = "64 0 0" ]'
    check "nor in the fleet host list" '[ "$(echo "$seen" | cut -d" " -f4)" = 0 ]'
  fi
  for i in $(seq 1 30); do briqyard machine exec "$B" -- hostname >/dev/null 2>&1 && break; sleep 2; done
  check "b answers again"       '[ "$(briqyard machine exec "$B" -- hostname)" = b ]'
fi
if [ -n "${SECOND_HOST_SH:-}" ]; then
  echo "== a backup on the second host: ciphertext, restored through the fleet (ADR 0035)"
  # The second host's key comes from the fleet, so its restore asks the fleet for the key of
  # the backup's id. Without a store it gets a directory for the run (put back at the end).
  on_second() { $SECOND_HOST_SH sh -c "$1"; }
  if ! on_second "grep -q '^backup:' $CONF2"; then
    on_second "cp $CONF2 $CONF2.two-hosts && printf 'backup:\n  store: file:///var/lib/briqyard/backups\n' >> $CONF2 && systemctl restart briqyardd"
    for i in $(seq 1 45); do briqyard machine exec "$B" -- hostname >/dev/null 2>&1 && break; sleep 2; done
  fi
  STORE2=$(on_second "sed -n 's|^  store: file://||p' $CONF2")
  # Random text lz4 cannot shrink, so only encryption can hide it (as in hack/e2e.sh).
  briqyard machine exec "$B" -- sh -c "head -c 98304 /dev/urandom | base64 -w 0 > /root/mark; sync" >/dev/null
  MARK=$(briqyard machine exec "$B" -- head -c 48 /root/mark)
  BK=$(briqyard machine backup "$B" | jq -r .id)
  check "backed up with its key's id" '[ "$(briqyard machine backups "$B" | jq -r ".[-1].key_id | length")" = 32 ]'
  check "its stream holds no plaintext" 'on_second "test -s $STORE2/backups/$B/root/$BK.zfs && ! grep -qaF -- $MARK $STORE2/backups/$B/root/$BK.zfs"'
  RB=$(briqyard machine restore --from "$B" --backup "$BK" --tenant "$T-b" --name b-back | jq -r .id)
  for i in $(seq 1 45); do [ "$(briqyard machine get "$RB" | jq -r .state)" = running ] && break; sleep 2; done
  check "restored through the fleet, on the second host" '[ "$(briqyard machine get "$RB" | jq -r .host)" = "$HB" ] && [ "$(briqyard machine exec "$RB" -- head -c 48 /root/mark)" = "$MARK" ]'
  check "its disk on the host's pool key" '[ "$(on_second "zfs get -H -o value encryptionroot byard/m/$RB/root")" = byard ]'
  # Its own key by the backup's id, asked from the host with no restore forwarded: served,
  # as without the id (ADR 0045). Another host's needs a restore the fleet forwarded (the
  # fleet's unit tests).
  KID=$(briqyard machine backups "$B" | jq -r '.[-1].key_id')
  own=$(as_second 'ask_key "{\"url\": \"$adv\", \"key_id\": \"$1\"}" | jq -r ".key | length"' "$KID")
  check "its own key served by its id outside a restore" '[ "$own" = 64 ]'
  briqyard machine destroy "$RB" >/dev/null
  briqyard backup rm "$B" "$BK" >/dev/null
fi
echo
echo "passed $pass, failed $fail"
[ "$fail" = 0 ]

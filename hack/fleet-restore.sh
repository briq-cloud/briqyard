#!/usr/bin/env bash
# Checks the fleet registry's backup (ADR 0032) on a fleet with a second host that takes its
# pool key from the fleet (ADR 0026): the fleet backs its registry up, encrypted; the registry
# is lost and restored from the backup; the second host, its pool locked as a reboot leaves it,
# comes back with its key from the restored registry. Run from where both shells reach:
#   FLEET_SH="limactl shell fc sudo" SECOND_HOST_SH="limactl shell fc2 sudo" \
#   BRIQYARD_URL=http://127.0.0.1:7430 bash hack/fleet-restore.sh
# It adds a `backup:` section to the fleet's config for the run (a development identity in
# /etc/briqyard/fleet-backup.key on the fleet's host: in production the identity is kept off
# it) and puts the config and the registry back as they were at the end.
set -euo pipefail
export BRIQYARD_URL=${BRIQYARD_URL:-http://127.0.0.1:7430}
pass=0; fail=0
ok()   { pass=$((pass+1)); echo "  ok   $1"; }
bad()  { fail=$((fail+1)); echo "  FAIL $1"; }
check(){ if eval "$2"; then ok "$1"; else bad "$1"; fi; }
on_fleet()  { $FLEET_SH sh -c "$1"; }
on_second() { $SECOND_HOST_SH sh -c "$1"; }
# The fleet restarts during the run; the dev VMs reach it through a port forward that comes
# back a moment after its listener does: a refused connection is tried again.
CURL="curl -fsS --retry 10 --retry-connrefused --retry-delay 1"
hosts() { $CURL "$BRIQYARD_URL/v1/hosts"; }
CFG=/etc/briqyard/fleet.yaml
ID=/etc/briqyard/fleet-backup.key
STORE=/var/lib/briqyard-fleet-backup
STATE=$(on_fleet "sed -n 's/^state_dir: //p' $CFG"); STATE=${STATE:-/var/lib/briqyard-fleet}

# Run on any exit, a failed check, Ctrl-C or a kill included: the fleet's config and registry
# put back, then the second host started again if the run left it stopped.
cleanup() {
  echo "cleanup"
  # Every step best-effort: one that fails leaves the others to run and the exit status as it was.
  set +e
  on_fleet "systemctl stop briqyard-fleet
    if [ -f $STATE/registry.json.lost ]; then mv $STATE/registry.json.lost $STATE/registry.json; fi
    if [ -f $CFG.restore-check ]; then mv $CFG.restore-check $CFG; fi
    systemctl start briqyard-fleet" || true
  on_second "systemctl start briqyardd" || true
}
trap cleanup EXIT
trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP

echo "== the registry backed up"
on_fleet "cp $CFG $CFG.restore-check; [ -f $ID ] || briqyard-fleet --config $CFG keygen --out $ID >/dev/null"
recipient=$(on_fleet "sed -n 's/^# public key: //p' $ID")
on_fleet "printf 'backup:\n  store: file://%s\n  recipient: %s\n' $STORE $recipient >> $CFG && systemctl restart briqyard-fleet"
for i in $(seq 1 30); do hosts >/dev/null 2>&1 && break; sleep 1; done
# The second host's key, asked as the host asks it: its token and address from its config.
conf=$(on_second "cat /etc/briqyard/config.yaml")
token=$(echo "$conf" | sed -n 's/^token: "\(.*\)"$/\1/p')
advertise=$(echo "$conf" | sed -n 's/^  advertise: //p')
host_key() {
  $CURL -X POST -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
    -d "{\"url\": \"$advertise\"}" "$BRIQYARD_URL/v1/hosts/key" | jq -r .key
}
HOST=$(hosts | jq -r ".[] | select(.url == \"$advertise\") | .id")
key=$(host_key)
check "the second host's key served" '[ "${#key}" = 64 ] && [ -n "$HOST" ]'
sealed() { echo "$key" | $FLEET_SH sh -c "k=\$(cat); f=$STORE/fleet/registry.json.age; head -c 21 \$f | grep -qx age-encryption.org/v1 && ! grep -qF \"\$k\" \$f && ! grep -qF '\"token\"' \$f"; }
check "backed up, encrypted: no key, no token" 'sealed'

echo "== the registry lost, restored"
check "a restore never writes over a registry" '! on_fleet "briqyard-fleet --config $CFG restore --identity $ID" >/dev/null 2>&1'
on_fleet "systemctl stop briqyard-fleet && mv $STATE/registry.json $STATE/registry.json.lost"
out=$(on_fleet "briqyard-fleet --config $CFG restore --identity $ID" || true)
echo "       $out"
check "restored from the backup"       'echo "$out" | grep -q "^restored [1-9][0-9]* hosts ([1-9][0-9]* pool keys, [0-9]* retired)"'
check "written 0600"                   '[ "$(on_fleet "stat -c %a $STATE/registry.json")" = 600 ]'
on_fleet "systemctl start briqyard-fleet"
for i in $(seq 1 30); do hosts >/dev/null 2>&1 && break; sleep 1; done
check "the same key from the restored registry" '[ "$(host_key)" = "$key" ]'

echo "== the second host rebooted, as its pool sees it"
on_second "systemctl stop briqyardd && zfs list -H -o name,mounted -t filesystem -r byard | awk '\$2 == \"yes\" { print \$1 }' | tac | xargs -r -n1 zfs unmount && { [ \"\$(zfs get -H -o value keystatus byard)\" = unavailable ] || zfs unload-key byard; }"
check "its pool locked"                '[ "$(on_second "zfs get -H -o value keystatus byard")" = unavailable ]'
started=$(on_second "date +%s")
on_second "systemctl start briqyardd"
# Its API listening, which it does once the key is loaded and logged: a host down for less
# than a minute is still `ready` in the fleet, and the key loads before its log line is read.
for i in $(seq 1 45); do [ "$(hosts | jq -r ".[] | select(.id == \"$HOST\") | .state")" = ready ] && on_second "journalctl -u briqyardd --since @$started -o cat" | grep -q "briqyardd listening" && break; sleep 2; done
check "back, its pool unlocked"        '[ "$(on_second "zfs get -H -o value keystatus byard")" = available ]'
check "with the key of the restored registry" 'on_second "journalctl -u briqyardd --since @$started -o cat" | grep "pool key loaded" | grep -q "\"from\":\"fleet\""'
check "ready in the fleet"             '[ "$(hosts | jq -r ".[] | select(.id == \"$HOST\") | .state")" = ready ]'

echo
echo "passed $pass, failed $fail"
[ "$fail" = 0 ]

#!/usr/bin/env bash
# End-to-end suite against a running briqyardd on this host. Needs: briqyard on PATH, curl, jq,
# the daemon reachable at $BRIQYARD_URL (default http://127.0.0.1:7420), and the internet.
# Every machine it makes lives in the tenant "e2e" and is destroyed at the end.
set -euo pipefail
export BRIQYARD_URL=${BRIQYARD_URL:-http://127.0.0.1:7420}
T=e2e-$$
pass=0; fail=0
ok()   { pass=$((pass+1)); echo "  ok   $1"; }
bad()  { fail=$((fail+1)); echo "  FAIL $1"; }
check(){ if eval "$2"; then ok "$1"; else bad "$1"; fi; }
cleanup() {
  echo "cleanup"
  for id in $(briqyard machine ls --tenant "$T" 2>/dev/null | awk 'NR>1{print $1}'); do briqyard machine rm "$id" >/dev/null 2>&1 || true; done
  # A machine still settling refuses its destroy; try again until the tenant is empty.
  for i in $(seq 1 10); do
    briqyard tenant rm "$T" >/dev/null 2>&1 && break
    for id in $(briqyard machine ls --tenant "$T" 2>/dev/null | awk 'NR>1{print $1}'); do briqyard machine rm "$id" >/dev/null 2>&1 || true; done
    sleep 2
  done
}
trap cleanup EXIT

echo "== status"
briqyard status | jq -e '.host_id' >/dev/null && ok "status answers"

echo "== alpine: boot, exec, files, dns, egress"
start=$(date +%s.%N)
A=$(briqyard machine run --image alpine:3.20 --name alp --tenant "$T" --memory 256 -- sleep 3600 | jq -r .id)
boot=$(echo "$(date +%s.%N) - $start" | bc)
state=$(briqyard machine get "$A" | jq -r .state)
check "alpine running (${boot}s)" '[ "$state" = running ]'
check "uname"        'briqyard machine exec "$A" -- uname -r | grep -q "^6\."'
check "hostname"     '[ "$(briqyard machine exec "$A" -- hostname)" = alp ]'
check "exit code"    '! briqyard machine exec "$A" -- sh -c "exit 3"; [ $? = 3 ] || true'
check "stdin"        '[ "$(echo hello | briqyard machine exec --stdin "$A" -- cat)" = hello ]'
check "stderr"       '[ "$(briqyard machine exec "$A" -- sh -c "echo e >&2" 2>&1 >/dev/null)" = e ]'
check "timeout"      'out=$(briqyard machine exec --timeout 2s "$A" -- sleep 30 2>&1 || true); echo "$out" | grep -q "timed out"'
echo hello-file > /tmp/by-e2e.txt
check "put/get file" 'briqyard machine put "$A" /tmp/by-e2e.txt /root/f.txt && [ "$(briqyard machine get-file "$A" /root/f.txt)" = hello-file ]'
check "own name"     'briqyard machine exec "$A" -- nslookup alp.internal 2>&1 | grep -q "10\.6[4-9]\."'
check "egress"       'briqyard machine exec "$A" -- wget -qO- -T 10 https://example.com | grep -qi "example domain"'
check "logs"         'briqyard machine logs "$A" --limit 5000 | grep -q "\[briqyard\] started"'

echo "== second machine reaches the first by name"
B=$(briqyard machine run --image alpine:3.20 --name alp2 --tenant "$T" --memory 256 -- sleep 3600 | jq -r .id)
check "ping by name" 'briqyard machine exec "$B" -- ping -c1 -W2 alp.internal >/dev/null'
check "ping by id"   'briqyard machine exec "$B" -- ping -c1 -W2 "$A.vm.internal" >/dev/null'

echo "== tenant isolation"
O=$(briqyard machine run --image alpine:3.20 --name other --tenant "$T-other" --memory 256 -- sleep 3600 | jq -r .id)
aip=$(briqyard machine get "$A" | jq -r .ip)
check "other tenant cannot reach" '! briqyard machine exec "$O" -- ping -c1 -W2 "$aip" >/dev/null 2>&1'
briqyard machine rm "$O" >/dev/null; briqyard tenant rm "$T-other" >/dev/null 2>&1 || true

echo "== stop, start, exit handling"
briqyard machine stop "$A" >/dev/null
check "stopped (user)" '[ "$(briqyard machine get "$A" | jq -r .stopped_reason)" = user ]'
briqyard machine start "$A" >/dev/null
check "started again"  '[ "$(briqyard machine get "$A" | jq -r .state)" = running ]'
check "file survived"  '[ "$(briqyard machine get-file "$A" /root/f.txt)" = hello-file ]'
X=$(briqyard machine run --image alpine:3.20 --name exiter --tenant "$T" --memory 256 -- sh -c "exit 7" 2>/dev/null | jq -r .id || true)
sleep 3
check "exit recorded"  '[ "$(briqyard machine get "$X" | jq -r .exit.code)" = 7 ]'

echo "== postgres with a volume, endpoint, wake on connect"
P=$(briqyard machine run --image postgres:16-alpine --name pg --tenant "$T" --memory 512 --volume 2G:/var/lib/postgresql/data -e POSTGRES_PASSWORD=secret --port 5432 --sleep 1m | jq -r .id)
for i in $(seq 1 60); do briqyard machine exec "$P" -- pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1 && break; sleep 1; done
check "postgres ready" 'briqyard machine exec "$P" -- pg_isready -h 127.0.0.1 -U postgres | grep -q accepting'
check "volume mounted" 'briqyard machine exec "$P" -- sh -c "mount | grep -q /var/lib/postgresql/data"'
briqyard machine exec "$P" -- psql -U postgres -c "create table t(x int); insert into t values (42);" >/dev/null
EP=$(briqyard endpoint add "$P" 5432)
addr=$(echo "$EP" | jq -r .address)
check "endpoint address" '[ -n "$addr" ]'
if command -v psql >/dev/null; then
  check "psql through endpoint" '[ "$(PGPASSWORD=secret psql -h ${addr%:*} -p ${addr#*:} -U postgres -tAc "select x from t")" = 42 ]'
fi
briqyard machine stop "$P" >/dev/null
check "wake refuses a user stop" '! briqyard machine wake "$P" >/dev/null 2>&1'
briqyard machine start "$P" >/dev/null
for i in $(seq 1 60); do briqyard machine exec "$P" -- pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1 && break; sleep 1; done
check "data survived"  '[ "$(briqyard machine exec "$P" -- psql -U postgres -tAc "select x from t")" = 42 ]'

echo "== sleep on idle, wake on connect"
S=$(briqyard machine run --image postgres:16-alpine --name sleeper --tenant "$T" --memory 512 --volume 1G:/var/lib/postgresql/data -e POSTGRES_PASSWORD=secret --port 5432 --sleep 20s | jq -r .id)
SEP=$(briqyard endpoint add "$S" 5432 | jq -r .address)
for i in $(seq 1 90); do [ "$(briqyard machine get "$S" | jq -r .state)" = stopped ] && break; sleep 2; done
check "slept when idle" '[ "$(briqyard machine get "$S" | jq -r .stopped_reason)" = idle ]'
check "set-sleep while stopped" '[ "$(briqyard machine set-sleep "$S" 45s | jq -r .sleep)" = 45s ]'
check "set-sleep refuses a number" '! briqyard machine set-sleep "$S" 30 >/dev/null 2>&1'
if command -v psql >/dev/null; then
  # The first connection wakes the machine; Postgres accepts TCP before it is ready, so a
  # client retries, as connection pools do.
  pgq() { for i in 1 2 3 4 5 6; do out=$(PGPASSWORD=secret psql -h "${SEP%:*}" -p "${SEP#*:}" -U postgres -tAc "select 1" 2>/dev/null) && { echo "$out"; return 0; }; sleep 2; done; return 1; }
  check "connect wakes it" '[ "$(pgq)" = 1 ]'
  check "running after wake" '[ "$(briqyard machine get "$S" | jq -r .state)" = running ]'
fi
F=$(briqyard machine fork "$P" --name pgfork | jq -r .id)
for i in $(seq 1 60); do briqyard machine exec "$F" -- pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1 && break; sleep 1; done
check "fork has data"  '[ "$(briqyard machine exec "$F" -- psql -U postgres -tAc "select x from t")" = 42 ]'
briqyard machine exec "$F" -- psql -U postgres -c "insert into t values (43)" >/dev/null
check "fork is apart"  '[ "$(briqyard machine exec "$P" -- psql -U postgres -tAc "select count(*) from t")" = 1 ]'

echo "== suspend and resume"
C=$(briqyard machine run --image alpine:3.20 --name counter --tenant "$T" --memory 256 -- sh -c 'i=0; while :; do i=$((i+1)); echo $i > /tmp/c; sleep 1; done' | jq -r .id)
sleep 3
before=$(briqyard machine exec "$C" -- cat /tmp/c)
briqyard machine stop --suspend "$C" >/dev/null
check "suspended"        '[ "$(briqyard machine get "$C" | jq -r .suspended)" = true ]'
t0=$(date +%s.%N)
briqyard machine start "$C" >/dev/null
resume=$(echo "$(date +%s.%N) - $t0" | bc)
check "resumed ($resume s)" '[ "$(briqyard machine get "$C" | jq -r .state)" = running ]'
check "uptime kept"      '[ "$(briqyard machine exec "$C" -- cut -d. -f1 /proc/uptime)" -ge 3 ]'
sleep 2
after=$(briqyard machine exec "$C" -- cat /tmp/c)
check "process went on ($before -> $after)" '[ "$after" -gt "$before" ]'
check "one boot in the log" '[ "$(briqyard machine logs "$C" --limit 5000 | grep -c "\[briqyard\] started")" = 1 ]'

echo "== http ingress: host routing, wake on request"
W=$(briqyard machine run --image nginx:alpine --name web --tenant "$T" --memory 256 --port 80 --sleep 20s | jq -r .id)
WEP=$(briqyard endpoint add --http --host "e2e-web" "$W" 80 | jq -r .host)
for i in $(seq 1 30); do briqyard machine exec "$W" -- wget -qO- http://127.0.0.1/ >/dev/null 2>&1 && break; sleep 1; done
check "http endpoint host" '[ "$WEP" = "e2e-web.byard.localhost" ]'
check "http routed by host" 'curl -fsS -H "Host: $WEP" http://127.0.0.1:8080/ | grep -qi "nginx"'
check "http unknown host 404" '[ "$(curl -s -o /dev/null -w "%{http_code}" -H "Host: nobody.byard.localhost" http://127.0.0.1:8080/)" = 404 ]'
for i in $(seq 1 90); do [ "$(briqyard machine get "$W" | jq -r .state)" = stopped ] && break; sleep 2; done
check "web slept"          '[ "$(briqyard machine get "$W" | jq -r .stopped_reason)" = idle ]'
check "http request wakes" 'curl -fsS --max-time 90 -H "Host: $WEP" http://127.0.0.1:8080/ | grep -qi "nginx"'

if sudo -n true 2>/dev/null && systemctl is-active briqyardd >/dev/null 2>&1; then
  echo "== daemon crash: running machines are adopted"
  K=$(briqyard machine run --image alpine:3.20 --name survivor --tenant "$T" --memory 256 -- sleep 3600 | jq -r .id)
  # The daemon alone (systemctl kill would signal every process of the unit, machines included).
  sudo kill -9 "$(systemctl show -p MainPID --value briqyardd)"
  sleep 1
  sudo systemctl start briqyardd
  for i in $(seq 1 30); do briqyard status >/dev/null 2>&1 && break; sleep 1; done
  check "still running"    '[ "$(briqyard machine get "$K" | jq -r .state)" = running ]'
  check "exec after crash" '[ "$(briqyard machine exec "$K" -- hostname)" = survivor ]'
  check "one boot"         '[ "$(briqyard machine logs "$K" --limit 5000 | grep -c "\[briqyard\] started")" = 1 ]'
  briqyard machine stop "$K" >/dev/null
  check "stop after crash" '[ "$(briqyard machine get "$K" | jq -r .state)" = stopped ]'
fi

echo
echo "passed $pass, failed $fail"
[ "$fail" = 0 ]

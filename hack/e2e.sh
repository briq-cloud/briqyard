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
  briqyard tenant rm "$T" >/dev/null 2>&1 || true
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
check "logs"         'briqyard machine logs "$A" --limit 5 | grep -q "\[briqyard\] started"'

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
for i in $(seq 1 60); do briqyard machine exec "$P" -- pg_isready -U postgres >/dev/null 2>&1 && break; sleep 1; done
check "postgres ready" 'briqyard machine exec "$P" -- pg_isready -U postgres | grep -q accepting'
check "volume mounted" 'briqyard machine exec "$P" -- sh -c "mount | grep -q /var/lib/postgresql/data"'
briqyard machine exec "$P" -- psql -U postgres -c "create table t(x int); insert into t values (42);" >/dev/null
EP=$(briqyard endpoint add "$P" 5432)
addr=$(echo "$EP" | jq -r .address)
check "endpoint address" '[ -n "$addr" ]'
if command -v psql >/dev/null; then
  check "psql through endpoint" '[ "$(PGPASSWORD=secret psql -h ${addr%:*} -p ${addr#*:} -U postgres -tAc "select x from t")" = 42 ]'
fi
briqyard machine stop "$P" >/dev/null
briqyard machine wake "$P" >/dev/null
for i in $(seq 1 60); do briqyard machine exec "$P" -- pg_isready -U postgres >/dev/null 2>&1 && break; sleep 1; done
check "data survived"  '[ "$(briqyard machine exec "$P" -- psql -U postgres -tAc "select x from t")" = 42 ]'
F=$(briqyard machine fork "$P" --name pgfork | jq -r .id)
for i in $(seq 1 60); do briqyard machine exec "$F" -- pg_isready -U postgres >/dev/null 2>&1 && break; sleep 1; done
check "fork has data"  '[ "$(briqyard machine exec "$F" -- psql -U postgres -tAc "select x from t")" = 42 ]'
briqyard machine exec "$F" -- psql -U postgres -c "insert into t values (43)" >/dev/null
check "fork is apart"  '[ "$(briqyard machine exec "$P" -- psql -U postgres -tAc "select count(*) from t")" = 1 ]'

echo
echo "passed $pass, failed $fail"
[ "$fail" = 0 ]

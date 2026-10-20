#!/usr/bin/env bash
# End-to-end suite against a running briqyardd on this host. Needs: briqyard on PATH, curl, jq,
# the daemon reachable at $BRIQYARD_URL (default http://127.0.0.1:7420), and the internet.
# Every machine it makes lives in a tenant "e2e-<pid>…" and is destroyed at the end.
set -euo pipefail
export BRIQYARD_URL=${BRIQYARD_URL:-http://127.0.0.1:7420}
T=e2e-$$
pass=0; fail=0
ok()   { pass=$((pass+1)); echo "  ok   $1"; }
bad()  { fail=$((fail+1)); echo "  FAIL $1"; }
check(){ if eval "$2"; then ok "$1"; else bad "$1"; fi; }
cleanup() {
  echo "cleanup"
  for t in "$T" "$T-eg" "$T-gw"; do
    for id in $(briqyard machine ls --tenant "$t" 2>/dev/null | awk 'NR>1{print $1}'); do briqyard machine rm "$id" >/dev/null 2>&1 || true; done
    # A machine still settling refuses its destroy; try again until the tenant is empty.
    for i in $(seq 1 10); do
      briqyard tenant rm "$t" >/dev/null 2>&1 && break
      for id in $(briqyard machine ls --tenant "$t" 2>/dev/null | awk 'NR>1{print $1}'); do briqyard machine rm "$id" >/dev/null 2>&1 || true; done
      sleep 2
    done
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
check "exit code"    'briqyard machine exec "$A" -- sh -c "exit 3"; [ $? = 3 ]'
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

echo "== egress: via a gateway machine, none, open again"
E="$T-eg"
serve() { briqyard machine run --image python:3.12-alpine --name "$1" --tenant "$E" --memory 256 -- python3 -m http.server 8080 | jq -r .id; }
G=$(serve egw); SIB=$(serve eside)
for m in "$G" "$SIB"; do
  for i in $(seq 1 30); do briqyard machine exec "$m" -- wget -qO- -T 2 http://127.0.0.1:8080/ >/dev/null 2>&1 && break; sleep 1; done
done
V=$(briqyard machine run --image alpine:3.20 --name evia --tenant "$E" --memory 256 --egress "via:$G" -- sleep 3600 | jq -r .id)
N=$(briqyard machine run --image alpine:3.20 --name enone --tenant "$E" --memory 256 --egress none -- sleep 3600 | jq -r .id)
reach() { briqyard machine exec "$1" -- wget -qO- -T 3 "$2" >/dev/null 2>&1; }
# The internet by address, so a refused name is not what makes it fail; "open again" below
# reaches the same address from the same machine, so the refusals mean something.
NET=$(getent ahostsv4 example.com | awk 'NR == 1 { print $1 }')
connects() { briqyard machine exec "$1" -- nc -z -w 3 "$2" 443 >/dev/null 2>&1; }
# nslookup exits 1 on NXDOMAIN; its output is what is checked.
lookup() { briqyard machine exec "$1" -- nslookup "$2" 2>&1 || true; }
check "via shown"                 '[ "$(briqyard machine get "$V" | jq -r .egress.via)" = "$G" ]'
check "via reaches its gateway"   'reach "$V" http://egw.internal:8080/'
check "via: no sibling"           '! reach "$V" http://eside.internal:8080/'
check "via: no internet"          '! connects "$V" "$NET"'
check "via: outside name refused" 'lookup "$V" example.com | grep -q NXDOMAIN'
check "via: gateway name resolves" 'lookup "$V" egw.internal | grep -q "10\.6[4-9]\."'
check "none reaches a sibling"    'reach "$N" http://eside.internal:8080/'
check "none: no internet"         '! connects "$N" "$NET"'
check "none: outside name refused" 'lookup "$N" example.com | grep -q NXDOMAIN'
briqyard machine set-egress "$N" open >/dev/null
check "open again: internet"      'connects "$N" "$NET"'
for m in "$V" "$N" "$SIB" "$G"; do briqyard machine rm "$m" >/dev/null; done
briqyard tenant rm "$E" >/dev/null 2>&1 || true

echo "== tenant gateway: started by what needs it, stopped once nothing does"
GT="$T-gw"
# A forward proxy: CONNECT host:port, then bytes both ways. On the image the egress section
# pulled, so nothing is installed at boot.
PROXY='
import asyncio
async def pipe(r, w):
    try:
        while data := await r.read(65536):
            w.write(data)
            await w.drain()
    finally:
        w.close()
async def handle(r, w):
    target = (await r.readline()).split()[1].decode()
    while (await r.readline()) not in (b"\r\n", b""):
        pass
    host, port = target.rsplit(":", 1)
    ur, uw = await asyncio.open_connection(host, int(port))
    w.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
    await w.drain()
    await asyncio.gather(pipe(r, uw), pipe(ur, w))
async def main():
    await (await asyncio.start_server(handle, "0.0.0.0", 3128)).serve_forever()
asyncio.run(main())
'
gw() { briqyard tenant get "$GT" | jq -r ".gateway.$1"; }
setgw() { briqyard tenant gateway set "$GT" --image python:3.12-alpine --port 3128 -- python3 -c "$PROXY" | jq -r .gateway.machine_id; }
GW=$(setgw)
check "gateway made, not started"   '[ "$(gw state)" = created ]'
check "via:gateway needs a gateway" '! briqyard machine run --image alpine:3.20 --name nogw --tenant "$T-nogw" --memory 128 --egress via:gateway -- sleep 60 >/dev/null 2>&1'
C=$(briqyard machine run --image python:3.12-alpine --name gwc --tenant "$GT" --memory 256 --egress via:gateway -- sleep 3600 | jq -r .id)
check "its start boots the gateway" '[ "$(gw state)" = running ]'
check "gateway not in machine ls"   '! briqyard machine ls | grep -q "$GW" && [ "$(briqyard tenant get "$GT" | jq .machines)" = 1 ]'
check "gateway console readable"    'briqyard machine logs "$GW" --limit 5000 | grep -q "\[briqyard\] started"'
# busybox wget sends a proxy a plain GET, not CONNECT: Python's client does what any SDK does.
fetch='import urllib.request; print(urllib.request.urlopen("https://example.com", timeout=10).read().decode())'
check "https through the gateway"   'briqyard machine exec "$C" -- env https_proxy=http://gateway.internal:3128 python3 -c "$fetch" | grep -qi "example domain"'
check "no way around it"            '! connects "$C" "$NET"'
check "rm refused while in use"     '! briqyard tenant gateway rm "$GT" >/dev/null 2>&1'
briqyard machine stop "$C" >/dev/null
# The sleeper looks every 15 s.
for i in $(seq 1 30); do [ "$(gw state)" = stopped ] && break; sleep 2; done
check "sleeper stops the gateway"   '[ "$(gw state)" = stopped ]'
check "rm once nothing uses it"     'briqyard tenant gateway rm "$GT" && [ "$(gw state)" = null ] && ! briqyard machine get "$GW" >/dev/null 2>&1'
GW=$(setgw)
briqyard machine rm "$C" >/dev/null
check "tenant removed"              'briqyard tenant rm "$GT" && ! briqyard tenant get "$GT" >/dev/null 2>&1'
check "gateway gone with it"        '! briqyard machine get "$GW" >/dev/null 2>&1'

echo "== stop, start, exit handling"
briqyard machine stop "$A" >/dev/null
check "stopped (user)" '[ "$(briqyard machine get "$A" | jq -r .stopped_reason)" = user ]'
briqyard machine start "$A" >/dev/null
check "started again"  '[ "$(briqyard machine get "$A" | jq -r .state)" = running ]'
check "file survived"  '[ "$(briqyard machine get-file "$A" /root/f.txt)" = hello-file ]'
X=$(briqyard machine run --image alpine:3.20 --name exiter --tenant "$T" --memory 256 -- sh -c "exit 7" 2>/dev/null | jq -r .id || true)
for i in $(seq 1 30); do [ "$(briqyard machine get "$X" | jq -r .exit.code)" != null ] && break; sleep 1; done
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
# The fork outlives its source: the clone is promoted, the source's disks go.
briqyard machine destroy "$P" >/dev/null
check "source destroyed under its fork" '! briqyard machine get "$P" >/dev/null 2>&1'
# The fork holds 42 and its own 43 by now.
fork_out=$(briqyard machine exec "$F" -- psql -U postgres -tAc "select sum(x) from t" 2>&1)
check "fork still answers"  '[ "$fork_out" = 85 ] || { echo "       fork said: $(echo "$fork_out" | head -3 | tr "\n" "|")"; false; }'

echo "== backup and restore"
B1=$(briqyard machine backup "$F" | jq -r .id)
check "first backup is whole"   '[ "$(briqyard machine backups "$F" | jq -r ".[0].incremental")" = false ]'
briqyard machine exec "$F" -- psql -U postgres -c "insert into t values (44)" >/dev/null
briqyard machine exec "$F" -- sh -c "sync" >/dev/null
B2=$(briqyard machine backup "$F" | jq -r .id)
check "second backup is a change" '[ "$(briqyard machine backups "$F" | jq -r ".[1].incremental")" = true ]'
briqyard machine destroy "$F" >/dev/null
R=$(briqyard machine restore --from "$F" --tenant "$T" --name restored | jq -r .id)
for i in $(seq 1 60); do briqyard machine exec "$R" -- pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1 && break; sleep 1; done
check "restored from the chain" '[ "$(briqyard machine exec "$R" -- psql -U postgres -tAc "select sum(x) from t")" = 129 ]'
R1=$(briqyard machine restore --from "$F" --backup "$B1" --tenant "$T" --name restored1 | jq -r .id)
for i in $(seq 1 60); do briqyard machine exec "$R1" -- pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1 && break; sleep 1; done
check "restored the first backup" '[ "$(briqyard machine exec "$R1" -- psql -U postgres -tAc "select sum(x) from t")" = 85 ]'
briqyard machine destroy "$R1" >/dev/null


echo "== tenants made together get bridges of their own"
for i in 1 2 3; do briqyard machine run --image alpine:3.20 --name par --tenant "$T-par$i" --memory 128 -- sleep 600 > /tmp/by-par$i.json & done; wait
check "three tenants at once"  '[ "$(briqyard tenant ls | jq -r "[.[] | select(.id | startswith(\"$T-par\")) | .subnet] | unique | length")" = 3 ]'
for i in 1 2 3; do briqyard machine destroy "$(jq -r .id /tmp/by-par$i.json)" >/dev/null 2>&1; briqyard tenant rm "$T-par$i" >/dev/null 2>&1 || true; done

echo "== suspend and resume"
C=$(briqyard machine run --image alpine:3.20 --name counter --tenant "$T" --memory 256 -- sh -c 'i=0; while :; do i=$((i+1)); echo $i > /tmp/c; sleep 1; done' | jq -r .id)
for i in $(seq 1 30); do before=$(briqyard machine exec "$C" -- cat /tmp/c 2>/dev/null) && [ -n "$before" ] && break; sleep 1; done
up_before=$(briqyard machine exec "$C" -- cut -d. -f1 /proc/uptime)
t_susp=$(date +%s.%N)
briqyard machine stop --suspend "$C" >/dev/null
susp_s=$(echo "$(date +%s.%N) - $t_susp" | bc)
check "suspend under 3 s (${susp_s}s)" '[ "$(echo "$susp_s < 3" | bc)" = 1 ]'
check "suspended"        '[ "$(briqyard machine get "$C" | jq -r .suspended)" = true ]'
t0=$(date +%s.%N)
briqyard machine start "$C" >/dev/null
resume=$(echo "$(date +%s.%N) - $t0" | bc)
check "resumed ($resume s)" '[ "$(briqyard machine get "$C" | jq -r .state)" = running ]'
check "uptime kept"      '[ "$(briqyard machine exec "$C" -- cut -d. -f1 /proc/uptime)" -ge "$up_before" ]'
for i in $(seq 1 30); do after=$(briqyard machine exec "$C" -- cat /tmp/c) && [ "$after" -gt "$before" ] && break; sleep 1; done
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

echo "== usage: compute, internet, ingress, a stopped machine's disks"
from=$(date -u +%Y-%m-%dT%H:00:00Z)
U=$(briqyard machine run --image nginx:alpine --name use --tenant "$T" --memory 256 --port 80 | jq -r .id)
for i in $(seq 1 30); do briqyard machine exec "$U" -- wget -qO- http://127.0.0.1/ >/dev/null 2>&1 && break; sleep 1; done
briqyard machine exec "$U" -- wget -qO /dev/null -T 10 https://example.com >/dev/null 2>&1 || true
UEP=$(briqyard endpoint add --http --host e2e-use "$U" 80 | jq -r .host)
curl -fsS -H "Host: $UEP" http://127.0.0.1:8080/ >/dev/null || true
# The sum of a field over the machine's buckets since $from (the hour may turn meanwhile).
usage_of() { briqyard usage --from "$from" --to "$(date -u -d '+1 hour' +%Y-%m-%dT%H:00:00Z)" --json | jq "[.[] | select(.machine_id == \"$1\") | .$2] | add // 0"; }
# The tick measures every 15 s: wait on the values, at most a minute.
above() { jq -en --argjson v "$(usage_of "$1" "$2")" --argjson min "$3" '$v > $min' >/dev/null; }
for i in $(seq 1 30); do above "$U" running_seconds 0 && above "$U" internet_in_bytes 0 && above "$U" ingress_out_bytes 0 && break; sleep 2; done
check "usage: running seconds"   'above "$U" running_seconds 0'
check "usage: internet in"       'above "$U" internet_in_bytes 0'
check "usage: ingress out"       'above "$U" ingress_out_bytes 0'
check "usage: a line in the table" 'briqyard usage --from "$from" --to "$(date -u -d "+1 hour" +%Y-%m-%dT%H:00:00Z)" | grep -q "$U"'
briqyard machine stop "$U" >/dev/null
d0=$(usage_of "$U" root_gb_hours)
for i in $(seq 1 30); do above "$U" root_gb_hours "$d0" && break; sleep 2; done
check "usage: stopped, disk hours go on" 'above "$U" root_gb_hours "$d0"'
check "usage: a range off the hour is refused" '! briqyard usage --from "${from%:00:00Z}:30:00Z" --to "$(date -u -d "+1 hour" +%Y-%m-%dT%H:00:00Z)" >/dev/null 2>&1'
briqyard machine rm "$U" >/dev/null

if sudo -n true 2>/dev/null && systemctl is-active briqyardd >/dev/null 2>&1; then
  echo "== daemon crash: running machines are adopted"
  K=$(briqyard machine run --image alpine:3.20 --name survivor --tenant "$T" --memory 256 -- sleep 3600 | jq -r .id)
  # The daemon alone (systemctl kill would signal every process of the unit, machines included).
  pid=$(systemctl show -p MainPID --value briqyardd)
  sudo kill -9 "$pid"
  # Once systemd has reaped it, a start brings it back now rather than after RestartSec.
  for i in $(seq 1 50); do [ "$(systemctl show -p MainPID --value briqyardd)" != "$pid" ] && break; sleep 0.1; done
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

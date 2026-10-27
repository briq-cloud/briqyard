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
  # The encryption section moves the pool's key away for a moment: put it back first.
  if [ -n "${KEY_FILE:-}" ] && sudo test -f "$KEY_FILE.e2e"; then
    sudo mv "$KEY_FILE.e2e" "$KEY_FILE"
    for i in $(seq 1 60); do briqyard status >/dev/null 2>&1 && break; sleep 1; done
  fi
  # The mirror section stops the mirror and names it in the configuration for a moment.
  if [ -n "${MIRROR:-}" ]; then
    sudo systemctl start briqyard-mirror || true
    if sudo test -f /etc/briqyard/config.yaml.e2e; then
      sudo mv /etc/briqyard/config.yaml.e2e /etc/briqyard/config.yaml
      handover
    fi
  fi
  for t in "$T" "$T-eg" "$T-gw" "$T-q"; do
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
check "stdin"        '[ "$(echo hello | briqyard machine exec -i "$A" -- cat)" = hello ]'
check "stderr"       '[ "$(briqyard machine exec "$A" -- sh -c "echo e >&2" 2>&1 >/dev/null)" = e ]'
check "timeout"      'out=$(briqyard machine exec --timeout 2s "$A" -- sleep 30 2>&1 || true); echo "$out" | grep -q "timed out"'
echo hello-file > /tmp/by-e2e.txt
check "put/get file" 'briqyard machine put "$A" /tmp/by-e2e.txt /root/f.txt && [ "$(briqyard machine get-file "$A" /root/f.txt)" = hello-file ]'
check "own name"     'briqyard machine exec "$A" -- nslookup alp.internal 2>&1 | grep -q "10\.6[4-9]\."'
check "egress"       'briqyard machine exec "$A" -- wget -qO- -T 10 https://example.com | grep -qi "example domain"'
check "logs"         'briqyard machine logs "$A" --limit 5000 | grep -q "\[briqyard\] started"'

echo "== exec sessions: stdin streamed, a terminal, the client's close (ADR 0029)"
TTY="python3 $(dirname "$0")/exec-tty.py"
running() { briqyard machine exec "$A" -- pgrep -f "$1" >/dev/null 2>&1; }
ended() { for i in $(seq 1 20); do running "$1" || return 0; sleep 0.5; done; return 1; }
check "session: stdin streams"          '[ "$(printf "one\ntwo\n" | briqyard machine exec -i "$A" -- cat)" = "$(printf "one\ntwo")" ]'
check "session: stderr apart, the code" 'err=$(echo | briqyard machine exec -i "$A" -- sh -c "echo e >&2; exit 4" 2>&1 >/dev/null); [ $? = 4 ] && [ "$err" = e ]'
check "tty: a terminal of the size sent" '$TTY 30x100 "send:tty; stty size\n" "expect:/dev/pts/[0-9]+" "expect:30 100" "send:exit\n" -- briqyard machine exec -it "$A" -- sh >/dev/null'
check "tty: a resize follows"           '$TTY 30x100 "send:stty size\n" "expect:30 100" "resize:40x120" "ask:stty size\n=>40 120" "send:exit\n" -- briqyard machine exec -it "$A" -- sh >/dev/null'
check "tty: the exit code comes back"   '$TTY 24x80 "send:exit 7\n" -- briqyard machine exec -it "$A" -- sh >/dev/null; [ $? = 7 ]'
$TTY 24x80 "send:exec sleep 6061\n" "expect:never printed" -- briqyard machine exec -it "$A" -- sh >/dev/null 2>&1 &
held=$!
for i in $(seq 1 40); do running "sleep 6061" && break; sleep 0.5; done
check "tty: the command runs"           'running "sleep 6061"'
pkill -9 -f "machine exec -it $A -- sh" || true
check "tty: the client's close hangs it up" 'ended "sleep 6061"'
wait "$held" 2>/dev/null || true
sleep 600 | briqyard machine exec -i "$A" -- sleep 6062 >/dev/null 2>&1 &
for i in $(seq 1 40); do running "sleep 6062" && break; sleep 0.5; done
check "session: the command runs"       'running "sleep 6062"'
pkill -9 -f "machine exec -i $A -- sleep 6062" || true
check "session: the client's close kills it" 'ended "sleep 6062"'
check "session: an event"               'briqyard events --machine "$A" | awk "\$4 == \"session_opened\"" | grep -q .'

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

echo "== egress limits: port 25 blocked by default, a connection rate, a bandwidth cap"
L=$(briqyard machine run --image alpine:3.20 --name lim --tenant "$T" --memory 256 -- sleep 3600 | jq -r .id)
lim() { briqyard machine get "$L" | jq -c "$1"; }
# A connect to $NET's port $1 from the machine: refused (not 0) within a second, where a
# dropped SYN would wait out the 5 s.
refused_at_once() {
  set -- $(briqyard machine exec "$L" -- sh -c 's=$(date +%s); nc -z -w 5 "$1" "$2"; echo $? $(($(date +%s) - s))' _ "$NET" "$1")
  [ "${1:-0}" != 0 ] && [ "${2:-9}" -le 1 ]
}
# Seven connections in a row: y for each that connects.
seven() { briqyard machine exec "$L" -- sh -c 'for i in 1 2 3 4 5 6 7; do nc -z -w 2 "$1" 443 && printf y || printf n; done' _ "$NET"; }
# 2 MiB from the internet, cut at 2 MiB so the server's range support does not matter:
# at 2 Mbit/s it takes over 7 s (a second of burst), unlimited a moment.
capped() {
  set -- $(briqyard machine exec "$L" -- sh -c 's=$(date +%s); n=$(wget -qO- -T 30 https://proof.ovh.net/files/10Mb.dat | head -c 2097152 | wc -c); echo $n $(($(date +%s) - s))')
  [ "${1:-}" = 2097152 ] && [ "${2:-0}" -ge 6 ]
}
check "limits: the host's shown"   '[ "$(lim .limits)" = "{\"blocked_ports\":[25],\"new_connections_per_minute\":0,\"bandwidth_mbit\":0}" ]'
check "port 25 refused at once"    'refused_at_once 25'
check "port 443 connects"          'connects "$L" "$NET"'
briqyard machine set-limits "$L" --conn-per-min 6 >/dev/null
check "set-limits shown"           '[ "$(lim .limits.new_connections_per_minute)" = 6 ]'
check "6 a minute: the 7th dropped" '[ "$(seven)" = yyyyyyn ]'
briqyard machine set-limits "$L" --conn-per-min 0 >/dev/null
check "rate lifted at once"        'connects "$L" "$NET"'
# The tick reads the counters every 15 s.
both='.egress_drops.blocked_port > 0 and .egress_drops.rate > 0'
for i in $(seq 1 20); do [ "$(lim "$both")" = true ] && break; sleep 2; done
check "drops shown"                '[ "$(lim "$both")" = true ]'
briqyard machine set-limits "$L" --bandwidth 2 >/dev/null
check "2 Mbit/s: a download capped" 'capped'
briqyard machine rm "$L" >/dev/null

echo "== disk limits: the host's for the size under its own, a slow disk, changed live and at a resume"
DK=$(briqyard machine run --image alpine:3.20 --name disk --tenant "$T" --memory 256 --vcpus 2 --volume 1G:/data --disk-bw 4 --disk-burst 0 -- sleep 3600 | jq -r .id)
dk() { briqyard machine get "$DK" | jq -c "$1"; }
# Whole seconds for `dd` in the machine, with O_DIRECT so the guest's page cache takes none of it.
took() {
  s=$(date +%s.%N)
  briqyard machine exec "$DK" -- dd bs=1M "$@" 2>/dev/null
  awk -v s="$s" -v e="$(date +%s.%N)" 'BEGIN { printf "%d", e - s }'
}
# A bucket holds a second at the rate and Firecracker's limiter runs a little ahead of it:
# 32 MiB at 4 MB/s is 7 s nominal, checked at 5; 16 MiB, 3 s nominal, at 2.
check "disk limits: its own over the host's for 2 vCPUs" '[ "$(dk .disk_limits)" = "{\"bandwidth_mb\":4,\"iops\":8000,\"burst_sec\":0}" ]'
check "4 MB/s: the volume writes 32 MiB in 5 s or more" '[ "$(took if=/dev/zero of=/data/f count=32 oflag=direct)" -ge 5 ]'
check "4 MB/s: the root disk reads 16 MiB in 2 s or more" '[ "$(took if=/dev/vda of=/dev/null count=16 iflag=direct)" -ge 2 ]'
check "cgroup: CPU weight by size"   '[ "$(sudo -n cat /sys/fs/cgroup/firecracker/${DK//_/-}/cpu.weight)" = 200 ]'
briqyard machine set-disk-limits "$DK" --disk-bw 0 >/dev/null
check "lifted at once: 32 MiB read in under 3 s" '[ "$(took if=/dev/vdc of=/dev/null count=32 iflag=direct)" -lt 3 ]'
briqyard machine stop --suspend "$DK" >/dev/null
briqyard machine set-disk-limits "$DK" --disk-bw 4 >/dev/null
briqyard machine start "$DK" >/dev/null
check "resumed with the limit set while it slept" '[ "$(briqyard events --machine "$DK" | awk "\$4 == \"resumed\"" | wc -l)" = 1 ] && [ "$(took if=/dev/zero of=/data/f count=32 oflag=direct)" -ge 5 ]'
# Kept until the metrics section: Firecracker writes its metrics a line a minute.

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

echo "== events, versions and a watch"
auth=(); [ -n "${BRIQYARD_TOKEN:-}" ] && auth=(-H "Authorization: Bearer $BRIQYARD_TOKEN")
EV=$(briqyard machine run --image alpine:3.20 --name evts --tenant "$T" --memory 128 -- sleep 3600 | jq -r .id)
# A watch from the machine's version: started before the stop, bounded, in the background.
timeout 60 briqyard events --machine "$EV" --since "$(briqyard machine get "$EV" | jq -r .version)" --watch > /tmp/by-e2e-watch.txt 2>&1 &
WATCH=$!
briqyard machine stop "$EV" >/dev/null
for i in $(seq 1 30); do awk '$4 == "stopped"' /tmp/by-e2e-watch.txt | grep -q . && break; sleep 1; done
check "a watch from before the stop gets it" 'awk "\$4 == \"stopped\"" /tmp/by-e2e-watch.txt | grep -q "$EV"'
kill "$WATCH" 2>/dev/null || true; wait "$WATCH" 2>/dev/null || true
patch_sleep() { curl -s -o /dev/null -w '%{http_code}' -X PATCH ${auth[@]+"${auth[@]}"} -H 'content-type: application/json' -H "If-Match: $1" -d '{"sleep":"3h"}' "$BRIQYARD_URL/v1/machines/$EV"; }
ver=$(briqyard machine get "$EV" | jq -r .version)
check "a stale If-Match is 409"      '[ "$(patch_sleep $((ver - 1)))" = 409 ]'
check "the current If-Match passes"  '[ "$(patch_sleep "$ver")" = 200 ]'
briqyard machine start "$EV" >/dev/null
check "describe shows its events"    'briqyard machine describe "$EV" | sed -n "/^Events:/,\$p" | grep -q "stopped (user)"'
briqyard machine rm "$EV" >/dev/null
reasons=$(briqyard events --machine "$EV" 2>/dev/null | awk 'NR > 1 && $4 ~ /^(created|started|stopped|destroyed)$/ { print $4 }' | paste -sd, -)
check "events in order ($reasons)"   '[ "$reasons" = created,started,stopped,started,destroyed ]'
check "a cursor past the log is gone" '! briqyard events --since 999999999 >/dev/null 2>&1'

echo "== probes: readiness decides ready, liveness restarts"
# The program serves 5 s after its boot: ready only then, its probe every 10 s.
RD=$(briqyard machine run --image python:3.12-alpine --name ready --tenant "$T" --memory 256 --readiness http:8080/ -- sh -c 'sleep 5; exec python3 -m http.server 8080' | jq -r .id)
check "running, not ready at first"  '[ "$(briqyard machine get "$RD" | jq -r .state,.ready | paste -sd, -)" = running,false ]'
for i in $(seq 1 30); do [ "$(briqyard machine get "$RD" | jq -r .ready)" = true ] && break; sleep 1; done
check "ready once it serves"         '[ "$(briqyard machine get "$RD" | jq -r .ready)" = true ]'
check "the ready event listed"       'briqyard events --machine "$RD" | awk "\$4 == \"ready\"" | grep -q .'
check "wait answers ready"           'briqyard machine wait "$RD" | jq -e .ready >/dev/null'
briqyard machine rm "$RD" >/dev/null
# The file goes after 5 s: three failed probes (30 s), the process ended, restarted 10 s later.
LV=$(briqyard machine run --image alpine:3.20 --name alive --tenant "$T" --memory 128 --liveness "exec:test -f /tmp/alive" -- sh -c 'touch /tmp/alive; sleep 5; rm /tmp/alive; exec sleep 3600' | jq -r .id)
for i in $(seq 1 60); do [ "$(briqyard machine get "$LV" | jq -r .restarts)" -ge 1 ] && break; sleep 2; done
check "a failing liveness restarts it" '[ "$(briqyard machine get "$LV" | jq -r .restarts)" -ge 1 ]'
check "the liveness_failed event"    'briqyard events --machine "$LV" | awk "\$4 == \"liveness_failed\"" | grep -q .'
for i in $(seq 1 30); do [ "$(briqyard machine get "$LV" | jq -r .state)" = running ] && break; sleep 2; done
check "running again"                '[ "$(briqyard machine get "$LV" | jq -r .state)" = running ]'
briqyard machine rm "$LV" >/dev/null

echo "== labels, a quota, logs follow"
LW=$(briqyard machine run --image alpine:3.20 --name lweb --tenant "$T" --memory 128 -l app=web -- sleep 3600 | jq -r .id)
briqyard machine run --image alpine:3.20 --name ldb --tenant "$T" --memory 128 -l app=db --no-start >/dev/null
selected() { briqyard machine ls --tenant "$T" "$@" | awk 'NR > 1 { print $1 }'; }
check "ls -l app=web lists one"      '[ "$(selected -l app=web)" = "$LW" ]'
check "ls -l app lists both"         '[ "$(selected -l app | wc -l)" -eq 2 ]'
check "a != selector is refused"     '! briqyard machine ls -l "app!=web" >/dev/null 2>&1'
Q="$T-q"
briqyard tenant quota "$Q" --machines 1 >/dev/null
briqyard machine run --image alpine:3.20 --name q1 --tenant "$Q" --memory 128 --no-start >/dev/null
second=$(curl -s -w ' %{http_code}' -X POST ${auth[@]+"${auth[@]}"} -H 'content-type: application/json' -d "{\"tenant\":\"$Q\",\"name\":\"q2\",\"image\":\"alpine:3.20\",\"size\":{\"vcpus\":1,\"memory_mb\":128}}" "$BRIQYARD_URL/v1/machines")
check "quota: the second create is 403 quota" '[ "${second##* }" = 403 ] && [ "$(echo "${second% *}" | jq -r .code)" = quota ]'
check "quota: its use shown"         '[ "$(briqyard tenant quota "$Q" | jq -c "[.quota.machines, .used.machines]")" = "[1,1]" ]'
check "quota: the refusal is an event" 'briqyard events --tenant "$Q" | awk "\$4 == \"quota_exceeded\"" | grep -q .'
FL=$(briqyard machine run --image alpine:3.20 --name follow --tenant "$T" --memory 128 -- sleep 3600 | jq -r .id)
timeout 60 briqyard machine logs -f "$FL" > /tmp/by-e2e-follow.txt 2>&1 &
FOLLOW=$!
# Connected once it printed the boot's lines; the next line is printed after that.
for i in $(seq 1 30); do grep -q "\[briqyard\] started" /tmp/by-e2e-follow.txt && break; sleep 1; done
briqyard machine exec "$FL" -- sh -c 'echo e2e-followed > /dev/console'
for i in $(seq 1 30); do grep -q e2e-followed /tmp/by-e2e-follow.txt && break; sleep 1; done
check "logs -f gets a line printed after it began" 'grep -q e2e-followed /tmp/by-e2e-follow.txt'
briqyard machine rm "$FL" >/dev/null
for i in $(seq 1 10); do kill -0 "$FOLLOW" 2>/dev/null || break; sleep 1; done
check "logs -f ends at the destroy"  '! kill -0 "$FOLLOW" 2>/dev/null && grep -q "was destroyed" /tmp/by-e2e-follow.txt'
kill "$FOLLOW" 2>/dev/null || true; wait "$FOLLOW" 2>/dev/null || true

echo "== changes at the next boot: env, files, then the image (ADR 0024)"
# The program serves its boot file and the env it booted with; the volume holds a mark.
printf v1 > /tmp/by-e2e-page.txt
AP=$(briqyard machine run --image python:3.12-alpine --name apply --tenant "$T" --memory 256 --volume 1G:/data -e V=1 --file /srv/page.txt=/tmp/by-e2e-page.txt -- sh -c 'cd /srv && echo "$V" > v.txt && exec python3 -m http.server 8080' | jq -r .id)
page() { briqyard machine exec "$AP" -- wget -qO- -T 2 "http://127.0.0.1:8080/$1" 2>/dev/null; }
serving() { for i in $(seq 1 30); do page v.txt >/dev/null && return 0; sleep 1; done; return 1; }
serving || true
check "serves V=1 and its file"        '[ "$(page v.txt)" = 1 ] && [ "$(page page.txt)" = v1 ]'
briqyard machine exec "$AP" -- sh -c 'echo kept > /data/mark' >/dev/null
printf v2 > /tmp/by-e2e-page.txt
briqyard machine set "$AP" -e V=2 --file /srv/page.txt=/tmp/by-e2e-page.txt >/dev/null
check "set: pending shown"             '[ "$(briqyard machine get "$AP" | jq -r ".state, (.pending.fields | join(\",\"))" | paste -sd " " -)" = "running env,files" ]'
check "set: still the old values"      '[ "$(page v.txt)" = 1 ] && [ "$(page page.txt)" = v1 ]'
briqyard machine restart "$AP" >/dev/null
serving || true
check "restart: the new values"        '[ "$(page v.txt)" = 2 ] && [ "$(page page.txt)" = v2 ]'
check "restart: nothing pending"       '[ "$(briqyard machine get "$AP" | jq -r .pending)" = null ]'
check "the applied event"              'briqyard events --machine "$AP" | awk "\$4 == \"applied\"" | grep -q .'
briqyard machine set "$AP" --image python:3.13-alpine >/dev/null
briqyard machine restart "$AP" >/dev/null
serving || true
check "a new image: python 3.13"       'briqyard machine exec "$AP" -- python3 --version | grep -q "^Python 3\.13\."'
check "a new image: the volume kept"   '[ "$(briqyard machine exec "$AP" -- cat /data/mark)" = kept ]'
briqyard machine rm "$AP" >/dev/null

echo "== postgres with a volume, endpoint, wake on connect"
P=$(briqyard machine run --image postgres:16-alpine --name pg --tenant "$T" --memory 512 --volume 2G:/var/lib/postgresql/data -e POSTGRES_PASSWORD=secret --port 5432 --sleep 1m --readiness "exec:pg_isready -h 127.0.0.1 -U postgres" | jq -r .id)
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
# A machine with a session open is in use: it stays up while the sleeper below goes down.
W=$(briqyard machine run --image alpine:3.20 --name awake --tenant "$T" --memory 128 --sleep 20s -- sleep 3600 | jq -r .id)
sleep 600 | briqyard machine exec -i "$W" -- cat >/dev/null 2>&1 &
S=$(briqyard machine run --image postgres:16-alpine --name sleeper --tenant "$T" --memory 512 --volume 1G:/var/lib/postgresql/data -e POSTGRES_PASSWORD=secret --port 5432 --sleep 20s | jq -r .id)
SEP=$(briqyard endpoint add "$S" 5432 | jq -r .address)
for i in $(seq 1 90); do [ "$(briqyard machine get "$S" | jq -r .state)" = stopped ] && break; sleep 2; done
check "slept when idle" '[ "$(briqyard machine get "$S" | jq -r .stopped_reason)" = idle ]'
check "awake while a session is open" '[ "$(briqyard machine get "$W" | jq -r .state)" = running ]'
pkill -9 -f "machine exec -i $W -- cat" || true
for i in $(seq 1 45); do [ "$(briqyard machine get "$W" | jq -r .state)" = stopped ] && break; sleep 2; done
check "asleep once it closed" '[ "$(briqyard machine get "$W" | jq -r .stopped_reason)" = idle ]'
briqyard machine rm "$W" >/dev/null
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
# The source has slept by now (its window is a minute); the exec wakes it and runs once its
# readiness probe says Postgres accepts (ADR 0022).
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

echo "== backups on a schedule: retention, delete, a destroyed machine's"
# The schedule's own backups are an hour apart: the API's make the points, and retention
# is the same after either.
SB=$(briqyard machine run --image alpine:3.20 --name sched --tenant "$T" --memory 128 --backup-every 1h --backup-keep 2 -- sleep 3600 | jq -r .id)
check "schedule shown" '[ "$(briqyard machine get "$SB" | jq -c "[.backup, (.next_backup_at != null)]")" = "[{\"every\":\"1h\",\"keep\":2},true]" ]'
point() { briqyard machine exec "$SB" -- sh -c "echo $1 > /root/n; sync" >/dev/null && briqyard machine backup "$SB" | jq -r .id; }
S1=$(point 1); S2=$(point 2); S3=$(point 3)
kinds=$(briqyard machine backups "$SB" | jq -r '[.[] | "\(.id):\(.incremental)"] | join(",")')
# keep 2: the third is whole, and the second (kept) needs the first.
check "every 2nd whole, a kept one's base kept" '[ "$kinds" = "$S1:false,$S2:true,$S3:false" ]'
check "a base is not deleted alone" '! briqyard backup rm "$SB" "$S1" >/dev/null 2>&1'
RS=$(briqyard machine restore --from "$SB" --backup "$S2" --tenant "$T" --name sched-r | jq -r .id)
for i in $(seq 1 30); do briqyard machine exec "$RS" -- true >/dev/null 2>&1 && break; sleep 1; done
check "the oldest kept restores from its chain" '[ "$(briqyard machine exec "$RS" -- cat /root/n)" = 2 ]'
briqyard machine destroy "$RS" >/dev/null
S4=$(point 4)
check "retention leaves 2 restorable" '[ "$(briqyard machine backups "$SB" | jq -r "[.[].id] | join(\",\")")" = "$S3,$S4" ]'
check "retention is an event" 'briqyard events --tenant "$T" --machine "$SB" 2>/dev/null | grep -q backup_deleted'
briqyard machine destroy "$SB" >/dev/null
check "a destroyed machine's backups listed" '[ "$(briqyard backups --tenant "$T" | jq "[.[] | select(.machine_id == \"$SB\" and .deletes_at != null)] | length")" = 2 ]'
check "deleted with what continues from it" 'briqyard backup rm "$SB" "$S3" --chain && [ "$(briqyard machine backups "$SB" | jq length)" = 0 ]'


echo "== snapshots: restore in place, a fork and backups around it, memory (ADR 0031)"
CK=$(briqyard machine run --image alpine:3.20 --name ckpt --tenant "$T" --memory 256 --volume 1G:/data -- sleep 3600 | jq -r .id)
on() { briqyard machine exec "$CK" -- sh -c "$1"; }
on 'echo v1 > /data/f; echo r1 > /root/r; sync' >/dev/null
CB1=$(briqyard machine backup "$CK" | jq -r .id)
briqyard machine snapshot create --name before "$CK" >/dev/null
check "snapshot listed by name, both disks" '[ "$(briqyard machine snapshot ls "$CK" | awk "NR == 2 {print \$2, \$5, \$6}")" = "before root,data no" ]'
FK=$(briqyard machine fork "$CK" --name ckfork | jq -r .id)
# A fork takes the disks, not the command: alpine's own (`sh`) would end at once.
briqyard machine set "$FK" -- sleep 3600 >/dev/null && briqyard machine restart "$FK" >/dev/null
on 'echo v2 > /data/f; rm /root/r; sync' >/dev/null
S2=$(briqyard machine snapshot create "$CK" | jq -r .id)
on 'rm /data/f; sync' >/dev/null
t0=$(date +%s.%N)
briqyard machine snapshot restore "$CK" before >/dev/null
took=$(echo "$(date +%s.%N) - $t0" | bc)
check "restore of a running machine boots it again (${took}s)" '[ "$(briqyard machine get "$CK" | jq -r .state)" = running ] && [ "$(briqyard machine logs "$CK" --limit 5000 | grep -c "\[briqyard\] started")" = 2 ]'
check "the volume's file back, its content too" '[ "$(on "cat /data/f")" = v1 ]'
check "the root disk's file back"     '[ "$(on "cat /root/r")" = r1 ]'
check "the restored event"            'briqyard events --machine "$CK" | awk "\$4 == \"restored\"" | grep -q .'
check "a fork made after the snapshot still works" '[ "$(briqyard machine exec "$FK" -- cat /data/f)" = v1 ] && briqyard machine exec "$FK" -- sh -c "echo w > /data/g" >/dev/null'
on 'echo v3 > /data/f; sync' >/dev/null
CB2=$(briqyard machine backup "$CK" | jq -r .id)
check "a backup after it continues from the one before the snapshot" '[ "$(briqyard machine backups "$CK" | jq -r ".[] | select(.id == \"$CB2\") | .disks[0].from")" = "$CB1" ]'
RK=$(briqyard machine restore --from "$CK" --backup "$CB2" --tenant "$T" --name ckback | jq -r .id)
check "and restores to what the machine had" '[ "$(briqyard machine exec "$RK" -- cat /data/f /root/r | paste -sd, -)" = v3,r1 ]'
briqyard machine destroy "$RK" >/dev/null
briqyard machine snapshot restore "$CK" "$S2" >/dev/null
check "the newer snapshot kept, restored" '[ "$(on "cat /data/f")" = v2 ] && ! on "test -e /root/r"'
CB3=$(briqyard machine backup "$CK" | jq -r .id)
check "its base gone with the restore: whole" '[ "$(briqyard machine backups "$CK" | jq -r ".[] | select(.id == \"$CB3\") | .incremental")" = false ]'
RK=$(briqyard machine restore --from "$CK" --backup "$CB3" --tenant "$T" --name ckback3 | jq -r .id)
check "and restores to what the machine had"  '[ "$(briqyard machine exec "$RK" -- cat /data/f)" = v2 ]'
briqyard machine destroy "$RK" >/dev/null
# Memory: /tmp is a tmpfs, only in memory; a resume keeps it, a boot would not.
on 'echo m1 > /tmp/mark; echo v4 > /data/f' >/dev/null
up=$(on 'cut -d. -f1 /proc/uptime')
t0=$(date +%s.%N)
briqyard machine snapshot create --name warm --memory "$CK" >/dev/null
took=$(echo "$(date +%s.%N) - $t0" | bc)
check "a snapshot with memory (${took}s), the machine running on" '[ "$(briqyard machine get "$CK" | jq -r .state)" = running ] && [ "$(on "cat /tmp/mark")" = m1 ]'
on 'echo m2 > /tmp/mark; echo v5 > /data/f; sync' >/dev/null
t0=$(date +%s.%N)
briqyard machine snapshot restore "$CK" warm >/dev/null
took=$(echo "$(date +%s.%N) - $t0" | bc)
check "restored with memory (${took}s): resumed, not booted" '[ "$(briqyard events --machine "$CK" | awk "{print \$4}" | tail -1)" = resumed ] && [ "$(briqyard machine logs "$CK" --limit 5000 | grep -c "\[briqyard\] started")" = 3 ]'
check "memory and disks as they were"  '[ "$(on "cat /tmp/mark /data/f" | paste -sd, -)" = m1,v4 ] && [ "$(on "cut -d. -f1 /proc/uptime")" -ge "$up" ]'
briqyard machine snapshot rm "$CK" before
check "deleted by name" '! briqyard machine snapshot ls "$CK" | grep -q " before "'
briqyard machine destroy "$FK" >/dev/null
briqyard machine destroy "$CK" >/dev/null

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

echo "== metrics, top, conditions"
M=$(briqyard machine run --image alpine:3.20 --name top --tenant "$T" --memory 128 -- sleep 3600 | jq -r .id)
metrics=$(curl -fsS ${auth[@]+"${auth[@]}"} "$BRIQYARD_URL/metrics")
check "metrics: the machine's CPU series" 'echo "$metrics" | grep -q "^briqyard_machine_cpu_seconds_total{machine=\"$M\",tenant=\"$T\",name=\"top\"} "'
check "metrics: its state, running"      'echo "$metrics" | grep -qx "briqyard_machine_state{machine=\"$M\",tenant=\"$T\",name=\"top\",state=\"running\"} 1"'
check "top lists it"                      'briqyard top --tenant "$T" | grep -q "^$M "'
# Rates need two ticks, 15 s apart.
windowed() { briqyard top --tenant "$T" --json | jq -e ".[] | select(.machine_id == \"$M\") | .window_sec > 0" >/dev/null; }
for i in $(seq 1 25); do windowed && break; sleep 2; done
check "top: rates over the last window"   'windowed'
# The slow writes above, held back by the disk limit: in the next line Firecracker writes.
throttled() { curl -fsS ${auth[@]+"${auth[@]}"} "$BRIQYARD_URL/metrics" | awk -v m="machine=\"$DK\"" 'index($0, "briqyard_machine_disk_throttled_total{") == 1 && index($0, m) && $2 > 0' | grep -q .; }
for i in $(seq 1 35); do throttled && break; sleep 2; done
check "metrics: the disk's throttling counted" 'throttled'
briqyard machine rm "$DK" >/dev/null
check "status: no condition true"         'briqyard status | jq -e "(.conditions | map(.type) | sort) == [\"disk_pressure\", \"memory_pressure\"] and all(.conditions[]; .status == false)" >/dev/null'
briqyard machine rm "$M" >/dev/null

# What bootstrap-host.sh does on an upgrade: SIGUSR2 to the daemon alone, then a start. The
# machines carry on; the new daemon reads the configuration again.
handover() {
  local pid
  pid=$(systemctl show -p MainPID --value briqyardd)
  sudo systemctl kill --kill-whom=main --signal=SIGUSR2 briqyardd
  for i in $(seq 1 100); do [ "$(systemctl show -p MainPID --value briqyardd)" != "$pid" ] && break; sleep 0.1; done
  sudo systemctl start briqyardd
  for i in $(seq 1 30); do briqyard status >/dev/null 2>&1 && break; sleep 1; done
}

if sudo -n true 2>/dev/null && systemctl is-active briqyardd >/dev/null 2>&1 && systemctl is-active briqyard-mirror >/dev/null 2>&1; then
  echo "== a registry mirror: pulls through it, from the registry when it is down (ADR 0036)"
  MIRROR=127.0.0.1:7440 IMG=busybox:1.37.0-musl
  # The dev host's configuration names the mirror, or names it for this section.
  if ! sudo grep -q '^registry_mirrors:' /etc/briqyard/config.yaml; then
    sudo cp /etc/briqyard/config.yaml /etc/briqyard/config.yaml.e2e
    printf 'registry_mirrors:\n  docker.io: http://%s\n' "$MIRROR" | sudo tee -a /etc/briqyard/config.yaml >/dev/null
    handover
  fi
  drop_image() { for k in $(briqyard image ls | awk -v r="$IMG" '$2 == r { print $1 }'); do briqyard image rm "$k" >/dev/null; done; }
  last_pull() { briqyard events | awk '$4 == "image_pulled"' | grep -F "pulled $IMG " | tail -1; }
  drop_image
  MR=$(briqyard machine run --image "$IMG" --name mirrored --tenant "$T" --memory 128 -- sleep 3600 | jq -r .id)
  digest=$(curl -fsS ${auth[@]+"${auth[@]}"} "$BRIQYARD_URL/v1/images" | jq -r --arg r "$IMG" '.[] | select(.ref == $r) | .digest')
  check "mirror: a pull goes through it"      '[ "$(briqyard machine get "$MR" | jq -r .state)" = running ] && last_pull | grep -qF "through $MIRROR"'
  check "mirror: it holds the image by digest" 'curl -fsS -o /dev/null -I -H "Accept: application/vnd.oci.image.index.v1+json" "http://$MIRROR/v2/library/busybox/manifests/$digest"'
  briqyard machine rm "$MR" >/dev/null
  drop_image
  sudo systemctl stop briqyard-mirror
  since=$(date +%s)
  MR=$(briqyard machine run --image "$IMG" --name unmirrored --tenant "$T" --memory 128 -- sleep 3600 | jq -r .id)
  check "mirror down: the registry serves the pull" '[ "$(briqyard machine get "$MR" | jq -r .state)" = running ] && last_pull | grep -q . && ! last_pull | grep -qF through'
  check "mirror down: the same digest"        '[ "$(curl -fsS ${auth[@]+"${auth[@]}"} "$BRIQYARD_URL/v1/images" | jq -r --arg r "$IMG" ".[] | select(.ref == \$r) | .digest")" = "$digest" ]'
  check "mirror down: the fallback logged"    'sudo journalctl -u briqyardd --since "@$since" -o cat | grep -F "mirror failed" | grep -qF "$IMG"'
  sudo systemctl start briqyard-mirror
  briqyard machine rm "$MR" >/dev/null
  if sudo test -f /etc/briqyard/config.yaml.e2e; then
    sudo mv /etc/briqyard/config.yaml.e2e /etc/briqyard/config.yaml
    handover
  fi
fi

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

  echo "== versions, a hand-over (an upgrade) and a stop (a reboot): ADR 0027"
  V=$(briqyard machine run --image alpine:3.20 --name handover --tenant "$T" --memory 256 -- sleep 3600 | jq -r .id)
  build=$(briqyardd --version | awk '{print $2}')
  check "status says the build"      '[ "$(briqyard status | jq -r .version)" = "$build" ]'
  check "the init says its version"  '[ "$(briqyard machine get "$V" | jq -r .init_version)" = "$build" ]'
  check "what ran it is the host's"  '[ "$(briqyard machine get "$V" | jq -r .vmm_version)" = "$(briqyard status | jq -r .vmm_version)" ]'
  handover
  check "handed over: still running" '[ "$(briqyard machine get "$V" | jq -r .state)" = running ]'
  check "the new daemon adopted it"  'briqyard status | jq -e ".started.adopted >= 1 and .started.stopped == 0" >/dev/null'
  check "exec after the hand-over"   '[ "$(briqyard machine exec "$V" -- hostname)" = handover ]'
  check "never booted again"         '[ "$(briqyard machine logs "$V" --limit 5000 | grep -c "\[briqyard\] started")" = 1 ]'
  # A stop suspends it; the next start brings it back unasked, from its memory snapshot.
  sudo systemctl stop briqyardd
  sudo systemctl start briqyardd
  for i in $(seq 1 60); do [ "$(briqyard machine get "$V" 2>/dev/null | jq -r .state)" = running ] && break; sleep 1; done
  check "running again after a stop and a start" '[ "$(briqyard machine get "$V" | jq -r .state)" = running ]'
  check "resumed, not booted"        '[ "$(briqyard machine logs "$V" --limit 5000 | grep -c "\[briqyard\] started")" = 1 ]'
  briqyard machine rm "$V" >/dev/null
  echo "== encryption at rest: the pool, the daemon's files on it, its key loaded at start"
  cfg() { sudo sed -n "s/^$1//p" /etc/briqyard/config.yaml; }
  POOL=$(cfg '  pool: '); POOL=${POOL:-byard}
  DATA=$(cfg 'data_dir: '); DATA=${DATA:-/var/lib/briqyard}
  KEY_FILE=$(cfg '  key: file:'); KEY_FILE=${KEY_FILE:-/etc/briqyard/pool.key}
  key=$(sudo cat "$KEY_FILE" | tr -d ' \n')
  zget() { sudo zfs get -H -o value "$@"; }
  check "the pool is encrypted"          '[ "$(zget encryption "$POOL")" = aes-256-gcm ] && [ "$(zget encryptionroot "$POOL")" = "$POOL" ]'
  check "every dataset under it is"      '! zget -r -t filesystem,volume encryption "$POOL" | grep -qvx aes-256-gcm'
  on_pool() { for d in state run images jail; do [ "$(findmnt -n -o SOURCE --target "$DATA/$d")" = "$POOL/$d" ] || return 1; done; }
  check "records, runs, images, jails on the pool" 'on_pool'
  check "the key in none of the daemon's files"    '! sudo grep -rqsF -D skip "$key" "$DATA" --exclude=pool.img'
  check "nor in its log"                 '! sudo journalctl -u briqyardd -b -o cat | grep -qF "$key"'
  # A reboot, as the pool sees it: the daemon stopped, the pool's filesystems unmounted and
  # its key unloaded. The key file away, the daemon waits and says why; back, it starts.
  # The machines still running are stopped first: the daemon's stop then suspends nothing.
  for id in $(briqyard machine ls | awk 'NR > 1 && $5 == "running" { print $1 }'); do briqyard machine stop "$id" >/dev/null; done
  lock() {
    sudo systemctl stop briqyardd &&
      sudo zfs list -H -o name,mounted -t filesystem -r "$POOL" | awk '$2 == "yes" { print $1 }' | tac | xargs -r -n1 sudo zfs unmount &&
      sudo zfs unload-key "$POOL"
  }
  check "stopped and locked"             'lock && [ "$(zget keystatus "$POOL")" = unavailable ]'
  sudo mv "$KEY_FILE" "$KEY_FILE.e2e"
  since=$(date +%s)
  sudo systemctl start briqyardd
  for i in $(seq 1 20); do sudo journalctl -u briqyardd --since "@$since" -o cat | grep -q "pool locked" && break; sleep 1; done
  check "without its key: no API, the reason logged" '! briqyard status >/dev/null 2>&1 && sudo journalctl -u briqyardd --since "@$since" -o cat | grep "pool locked" | grep -qF "$KEY_FILE"'
  sudo mv "$KEY_FILE.e2e" "$KEY_FILE"
  for i in $(seq 1 60); do briqyard status >/dev/null 2>&1 && break; sleep 1; done
  check "the key back: unlocked, started" 'briqyard status >/dev/null && [ "$(zget keystatus "$POOL")" = available ]'
  briqyard machine start "$K" >/dev/null
  check "a machine of before runs again" '[ "$(briqyard machine exec "$K" -- hostname)" = survivor ]'
  briqyard machine stop "$K" >/dev/null
fi

echo
echo "passed $pass, failed $fail"
[ "$fail" = 0 ]

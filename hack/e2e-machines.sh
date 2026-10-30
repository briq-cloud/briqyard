echo "== status"
briqyard status | jq -e '.host_id' >/dev/null && ok "status answers"

echo "== alpine: boot, exec, files, dns, egress"
start=$(date +%s.%N)
A=$(briqyard machine run --image alpine:3.20 --name alp --namespace "$T" --memory 256 -- sleep 3600 | jq -r .id)
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
# Raw streams exceed both the JSON request bound and the guest frame bound (ADR 0061).
STREAM_FILES=$(mktemp -d)
dd if=/dev/urandom of="$STREAM_FILES/input" bs=1M count=5 status=none
: > "$STREAM_FILES/empty"
check "raw file: 5 MiB binary and an encoded path" 'briqyard machine put "$A" "$STREAM_FILES/input" "/root/a & b.bin" && briqyard machine get-file "$A" "/root/a & b.bin" > "$STREAM_FILES/output" && cmp "$STREAM_FILES/input" "$STREAM_FILES/output"'
check "raw file: empty replaces nonempty" 'briqyard machine put "$A" "$STREAM_FILES/empty" "/root/a & b.bin" && [ -z "$(briqyard machine get-file "$A" "/root/a & b.bin")" ]'
check "raw file: mode applied" '[ "$("${CURL[@]}" -s -o /dev/null -w "%{http_code}" -X PUT ${auth[@]+"${auth[@]}"} --data-binary @"$STREAM_FILES/empty" "$BRIQYARD_URL/v1/machines/$A/files/content?path=%2Froot%2Fmode&mode=0600")" = 200 ] && [ "$(briqyard machine exec "$A" -- stat -c %a /root/mode)" = 600 ]'
check "raw file: unknown length, guest hash and preserved mode" '"${CURL[@]}" -fsS -X PUT ${auth[@]+"${auth[@]}"} -H "Transfer-Encoding: chunked" --data-binary @"$STREAM_FILES/input" "$BRIQYARD_URL/v1/machines/$A/files/content?path=%2Froot%2Fmode" > "$STREAM_FILES/result" && [ "$(jq -r .size "$STREAM_FILES/result")" = 5242880 ] && [ "$(jq -r .sha256 "$STREAM_FILES/result")" = "$(sha256sum "$STREAM_FILES/input" | cut -d " " -f1)" ] && [ "$(briqyard machine exec "$A" -- stat -c %a /root/mode)" = 600 ]'
briqyard machine exec "$A" -- ln -s /root /tmp/stream-link
check "raw file: parent symlink refused" '! briqyard machine put "$A" "$STREAM_FILES/empty" /tmp/stream-link/escaped 2>/dev/null && briqyard machine exec "$A" -- test ! -e /root/escaped'
check "raw file: traversal refused" '! briqyard machine put "$A" "$STREAM_FILES/empty" /root/../escape 2>/dev/null'
check "own name"     'briqyard machine exec "$A" -- nslookup alp.internal 2>&1 | grep -q "10\.6[4-9]\."'
check "egress"       'briqyard machine exec "$A" -- wget -qO- -T 10 https://example.com | grep -qi "example domain"'
check "logs"         'briqyard machine logs "$A" --limit 5000 | grep -q "\[briqyard\] started"'

echo "== a create answers once recorded; the pull and the boot follow (ADR 0048)"
IMG2=busybox:1.36.1-musl
for k in $(briqyard image ls | awk -v r="$IMG2" '$2 == r { print $1 }'); do briqyard image rm "$k" >/dev/null; done
post() { "${CURL[@]}" -s -w ' %{http_code}' -X POST ${auth[@]+"${auth[@]}"} -H 'content-type: application/json' -d "$1" "$BRIQYARD_URL/v1/machines"; }
body="{\"namespace\":\"$T\",\"name\":\"pulled\",\"image\":\"$IMG2\",\"cmd\":[\"sleep\",\"3600\"],\"size\":{\"vcpus\":1,\"memory_mb\":128}}"
start=$(date +%s.%N); made=$(post "$body"); answered=$(echo "$(date +%s.%N) - $start" | bc)
PL=$(echo "${made% *}" | jq -r .id)
waited=$("${CURL[@]}" -fsS -X POST ${auth[@]+"${auth[@]}"} "$BRIQYARD_URL/v1/machines/$PL/wait?for=running&timeout=600" | jq -r .state)
ran=$(echo "$(date +%s.%N) - $start" | bc)
check "create: 201 creating (${answered}s), running after its pull (${ran}s)" '[ "${made##* }" = 201 ] && [ "$(echo "${made% *}" | jq -r .state)" = creating ] && [ "$waited" = running ]'
check "create: pulling, then created" '[ "$(briqyard events --machine "$PL" | awk "\$4 == \"pulling\" || \$4 == \"created\" { print \$4 }" | xargs)" = "pulling created" ]'
again=$(post "$body")
check "create: sent again, 409 conflict with the first" '[ "${again##* }" = 409 ] && [ "$(echo "${again% *}" | jq -r .machine.id)" = "$PL" ]'
start=$(date +%s.%N); cached=$(post "${body/pulled/cached}"); answered=$(echo "$(date +%s.%N) - $start" | bc)
CA=$(echo "${cached% *}" | jq -r .id)
"${CURL[@]}" -fsS -X POST ${auth[@]+"${auth[@]}"} "$BRIQYARD_URL/v1/machines/$CA/wait?for=running&timeout=120" >/dev/null || true
ran=$(echo "$(date +%s.%N) - $start" | bc)
check "create: the image on the host (${answered}s, running ${ran}s)" '[ "$(briqyard machine get "$CA" | jq -r .state)" = running ]'
bad=$(post "{\"namespace\":\"$T\",\"name\":\"badpull\",\"image\":\"127.0.0.1:1/nope:1\",\"size\":{\"vcpus\":1,\"memory_mb\":128}}")
BP=$(echo "${bad% *}" | jq -r .id)
failed=$("${CURL[@]}" -s -w ' %{http_code}' -X POST ${auth[@]+"${auth[@]}"} "$BRIQYARD_URL/v1/machines/$BP/wait?timeout=120")
check "create: a pull that fails is 409 pull_failed, the machine in error" '[ "${failed##* }" = 409 ] && [ "$(echo "${failed% *}" | jq -r .code)" = pull_failed ] && [ "$(briqyard machine get "$BP" | jq -r .error_reason)" = pull_failed ]'
briqyard machine rm "$PL" >/dev/null; briqyard machine rm "$CA" >/dev/null; briqyard machine rm "$BP" >/dev/null

echo "== image layers: hard links, merged /usr (ADR 0039)"
BB=$(briqyard machine run --image busybox:1.37 --name bb --namespace "$T" --memory 128 -- sleep 3600 | jq -r .id)
check "busybox: 400 applets, one file"   '[ "$(briqyard machine exec "$BB" -- stat -c %h /bin/busybox)" -gt 400 ]'
DB=$(briqyard machine run --image debian:bookworm-slim --name deb --namespace "$T" --memory 128 -- sleep 3600 | jq -r .id)
check "debian: /bin a link to usr/bin"   '[ "$(briqyard machine exec "$DB" -- readlink /bin)" = usr/bin ]'
check "debian: a command through it"     '[ "$(briqyard machine exec "$DB" -- /bin/sh -c "echo ok")" = ok ]'
briqyard machine rm "$BB" >/dev/null; briqyard machine rm "$DB" >/dev/null

echo "== an image's user, and a program that cannot start"
# USER 101, listed in its own group in /etc/group: the groups are set before the user (v0.1.1
# could not start such an image).
NU=$(briqyard machine run --image nginxinc/nginx-unprivileged:1.28-alpine-slim --name nginxu --namespace "$T" --memory 128 2>/dev/null | jq -r .id || true)
check "a user with a supplementary group: running" '[ "$(briqyard machine get "$NU" | jq -r .state)" = running ]'
IDS='s=$(grep -lE "^Uid:[[:space:]]+101[[:space:]]" /proc/[0-9]*/status | head -1); grep -E "^(Uid|Gid|Groups):" "$s" | awk "{print \$2}" | xargs'
check "its uid, gid and groups" '[ "$(briqyard machine exec "$NU" -- sh -c "$IDS")" = "101 101 101" ]'
briqyard machine rm "$NU" >/dev/null 2>&1 || true
NS=$("${CURL[@]}" -fsS -X POST ${auth[@]+"${auth[@]}"} -H 'content-type: application/json' -d "{\"namespace\":\"$T\",\"name\":\"nostart\",\"image\":\"alpine:3.20\",\"cmd\":[\"/no/such/program\"],\"size\":{\"vcpus\":1,\"memory_mb\":128}}" "$BRIQYARD_URL/v1/machines" | jq -r .id)
nostart=$("${CURL[@]}" -s -w ' %{http_code}' -X POST ${auth[@]+"${auth[@]}"} "$BRIQYARD_URL/v1/machines/$NS/wait?timeout=120")
check "no program: its wait is 409 boot_failed" '[ "${nostart##* }" = 409 ] && [ "$(echo "${nostart% *}" | jq -r .code)" = boot_failed ]'
check "no program: the init's reason" '[ "$(echo "${nostart% *}" | jq -r .machine.error)" = "the machine exited during boot: start \"/no/such/program\": No such file or directory (os error 2)" ]'
briqyard machine rm "$(echo "${nostart% *}" | jq -r .machine.id)" >/dev/null 2>&1 || true

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
pkill -9 -P "$held" || true
check "tty: the client's close hangs it up" 'ended "sleep 6061"'
wait "$held" 2>/dev/null || true
exec {session_input}< <(sleep 600)
session_feeder=$!
briqyard machine exec -i "$A" -- sleep 6062 <&$session_input >/dev/null 2>&1 &
held=$!
for i in $(seq 1 40); do running "sleep 6062" && break; sleep 0.5; done
check "session: the command runs"       'running "sleep 6062"'
kill -9 "$held" || true
check "session: the client's close kills it" 'ended "sleep 6062"'
kill "$session_feeder" 2>/dev/null || true
wait "$held" 2>/dev/null || true
wait "$session_feeder" 2>/dev/null || true
exec {session_input}<&-

check "session: an event"               'briqyard events --machine "$A" | awk "\$4 == \"session_opened\"" | grep -q .'

echo "== second machine reaches the first by name"
B=$(briqyard machine run --image alpine:3.20 --name alp2 --namespace "$T" --memory 256 -- sleep 3600 | jq -r .id)
check "ping by name" 'briqyard machine exec "$B" -- ping -c1 -W2 alp.internal >/dev/null'
check "ping by id"   'briqyard machine exec "$B" -- ping -c1 -W2 "$A.vm.internal" >/dev/null'

echo "== namespace isolation"
O=$(briqyard machine run --image alpine:3.20 --name other --namespace "$T-other" --memory 256 -- sleep 3600 | jq -r .id)
aip=$(briqyard machine get "$A" | jq -r .ip)
check "other namespace cannot reach" '! briqyard machine exec "$O" -- ping -c1 -W2 "$aip" >/dev/null 2>&1'
briqyard machine rm "$O" >/dev/null; briqyard namespace rm "$T-other" >/dev/null 2>&1 || true

echo "== move into another namespace, a fork into one (ADR 0056)"
MV=$(briqyard machine run --image alpine:3.20 --name mv --namespace "$T-mv1" --memory 256 -- sleep 3600 | jq -r .id)
briqyard machine exec "$MV" -- sh -c "touch /run/moved-marker; echo kept > /root/moved" >/dev/null
mvip=$(briqyard machine get "$MV" | jq -r .ip)
moved=$(briqyard machine move "$MV" --namespace "$T-mv2")
check "move alone: a rename, same address, no restart" '[ "$(echo "$moved" | jq -r "[.restarted, .from, .machine.namespace, .machine.ip] | join(\" \")")" = "false $T-mv1 $T-mv2 $mvip" ]'
check "move alone: not booted again" 'briqyard machine exec "$MV" -- test -e /run/moved-marker'
check "move alone: listed in the new namespace only" 'briqyard machine ls --namespace "$T-mv2" | grep -q "$MV" && ! briqyard machine ls --namespace "$T-mv1" | grep -q "$MV"'
check "move alone: the old namespace is gone" '! briqyard namespace ls | jq -e --arg t "$T-mv1" ".[] | select(.id == \$t)" >/dev/null'
MN=$(briqyard machine run --image alpine:3.20 --name mvnext --namespace "$T-mv3" --memory 256 -- sleep 3600 | jq -r .id)
moved=$(briqyard machine move "$MV" --namespace "$T-mv3")
check "move into a namespace that exists: restarted, a new address" '[ "$(echo "$moved" | jq -r "[.restarted, .previous_ip == \"$mvip\", .machine.ip != \"$mvip\"] | join(\" \")")" = "true true true" ]'
check "move: it reaches its new neighbour by name" 'briqyard machine exec "$MV" -- ping -c1 -W2 mvnext.internal >/dev/null'
check "move: booted again, its disk kept" '! briqyard machine exec "$MV" -- test -e /run/moved-marker && [ "$(briqyard machine exec "$MV" -- cat /root/moved)" = kept ]'
check "move: a moved event in each namespace" 'for t in "$T-mv2" "$T-mv3"; do briqyard events --namespace "$t" --machine "$MV" | awk "\$4 == \"moved\"" | grep -q . || exit 1; done'
MF=$(briqyard machine fork "$MV" --name mvfork --namespace "$T-mv4" | jq -r .id)
check "fork into another namespace: in it, on a network of its own" '[ "$(briqyard machine get "$MF" | jq -r .namespace)" = "$T-mv4" ] && [ "$(briqyard machine get "$MF" | jq -r .ip | cut -d. -f3)" != "$(briqyard machine get "$MV" | jq -r .ip | cut -d. -f3)" ]'
briqyard machine set "$MF" -- sleep 3600 >/dev/null && briqyard machine restart "$MF" >/dev/null   # a fork takes the disks, not the command
check "fork into another namespace: its source's disk" '[ "$(briqyard machine exec "$MF" -- cat /root/moved)" = kept ]'
for id in "$MF" "$MV" "$MN"; do briqyard machine rm "$id" >/dev/null; done
for t in mv2 mv3 mv4; do briqyard namespace rm "$T-$t" >/dev/null 2>&1 || true; done

echo "== egress: via a gateway machine, none, open again"
E="$T-eg"
serve() { briqyard machine run --image python:3.12-alpine --name "$1" --namespace "$E" --memory 256 -- python3 -m http.server 8080 | jq -r .id; }
G=$(serve egw); SIB=$(serve eside)
for m in "$G" "$SIB"; do
  for i in $(seq 1 30); do briqyard machine exec "$m" -- wget -qO- -T 2 http://127.0.0.1:8080/ >/dev/null 2>&1 && break; sleep 1; done
done
V=$(briqyard machine run --image alpine:3.20 --name evia --namespace "$E" --memory 256 --egress "via:$G" -- sleep 3600 | jq -r .id)
N=$(briqyard machine run --image alpine:3.20 --name enone --namespace "$E" --memory 256 --egress none -- sleep 3600 | jq -r .id)
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
# The host's own services (network.host_ports, ADR 0028), checked where the suite runs on the
# host and its config lists one: reached at the host's address by a machine with egress
# (connected, or refused at once), dropped for none and via; the daemon's API dropped for all.
HP=$(sudo -n awk '/^  host_ports:/ {gsub(/[^0-9,]/, ""); split($0, p, ","); print p[1]}' /etc/briqyard/config.yaml 2>/dev/null || true)
if [ -n "$HP" ]; then
  HOST=$(ip -4 route get 1.1.1.1 | awk '{for (i = 1; i < NF; i++) if ($i == "src") print $(i + 1)}')
  api_port=${BRIQYARD_URL##*:}; api_port=${api_port%%/*}
  # "dropped" when the connect waits out its 3 s, "reached" when it ends sooner either way.
  knock() { briqyard machine exec "$1" -- sh -c 's=$(date +%s); nc -z -w 3 "$1" "$2"; [ $(($(date +%s) - s)) -ge 3 ] && echo dropped || echo reached' _ "$HOST" "$2" 2>/dev/null; }
  check "host port $HP reached"     '[ "$(knock "$SIB" "$HP")" = reached ]'
  check "none: host port dropped"   '[ "$(knock "$N" "$HP")" = dropped ]'
  check "via: host port dropped"    '[ "$(knock "$V" "$HP")" = dropped ]'
  check "the API dropped"           '[ "$(knock "$SIB" "$api_port")" = dropped ]'
fi
briqyard machine set-egress "$N" open >/dev/null
check "open again: internet"      'connects "$N" "$NET"'
for m in "$V" "$N" "$SIB" "$G"; do briqyard machine rm "$m" >/dev/null; done
briqyard namespace rm "$E" >/dev/null 2>&1 || true

echo "== egress limits: port 25 blocked by default, a connection rate, a bandwidth cap"
L=$(briqyard machine run --image alpine:3.20 --name lim --namespace "$T" --memory 256 -- sleep 3600 | jq -r .id)
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
DK=$(briqyard machine run --image alpine:3.20 --name disk --namespace "$T" --memory 256 --vcpus 2 --volume 1G:/data --disk-bw 4 --disk-burst 0 -- sleep 3600 | jq -r .id)
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

echo "== namespace gateway: started by what needs it, stopped once nothing does"
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
gw() { briqyard namespace get "$GT" | jq -r ".gateway.$1"; }
setgw() { briqyard namespace gateway set "$GT" --image python:3.12-alpine --port 3128 --vcpus 1 --memory 128 --cpu-millis 250 -- python3 -c "$PROXY" | jq -r .gateway.machine_id; }
GW=$(setgw)
check "gateway made, not started"   '[ "$(gw state)" = created ]'
check "via:gateway needs a gateway" '! briqyard machine run --image alpine:3.20 --name nogw --namespace "$T-nogw" --memory 128 --egress via:gateway -- sleep 60 >/dev/null 2>&1'
GWCPU_BEFORE=$(briqyard status | jq .used.cpu_millis)
C=$(briqyard machine run --image python:3.12-alpine --name gwc --namespace "$GT" --memory 256 --egress via:gateway -- sleep 3600 | jq -r .id)
check "its start boots the gateway" '[ "$(gw state)" = running ]'
check "gateway: fractional size"    '[ "$(briqyard machine get "$GW" | jq -c "[.size.vcpus,.size.memory_mb,.size.cpu_millis]")" = "[1,128,250]" ]'
check "gateway: CPU quota enforced" '[ "$(sudo -n cat /sys/fs/cgroup/firecracker/${GW//_/-}/cpu.max)" = "25000 100000" ]'
check "gateway: CPU reservation"    '[ "$(( $(briqyard status | jq .used.cpu_millis) - GWCPU_BEFORE ))" = 1250 ]'

check "gateway not in machine ls"   '! briqyard machine ls | grep -q "$GW" && [ "$(briqyard namespace get "$GT" | jq .machines)" = 1 ]'
check "gateway console readable"    'briqyard machine logs "$GW" --limit 5000 | grep -q "\[briqyard\] started"'
# busybox wget sends a proxy a plain GET, not CONNECT: Python's client does what any SDK does.
fetch='import urllib.request; print(urllib.request.urlopen("https://example.com", timeout=10).read().decode())'
check "https through the gateway"   'briqyard machine exec "$C" -- env https_proxy=http://gateway.internal:3128 python3 -c "$fetch" | grep -qi "example domain"'
check "no way around it"            '! connects "$C" "$NET"'
check "rm refused while in use"     '! briqyard namespace gateway rm "$GT" >/dev/null 2>&1'
briqyard machine stop "$C" >/dev/null
# The sleeper looks every 15 s.
for i in $(seq 1 30); do [ "$(gw state)" = stopped ] && break; sleep 2; done
check "sleeper stops the gateway"   '[ "$(gw state)" = stopped ]'
check "rm once nothing uses it"     'briqyard namespace gateway rm "$GT" && [ "$(gw state)" = null ] && ! briqyard machine get "$GW" >/dev/null 2>&1'
GW=$(setgw)
briqyard machine rm "$C" >/dev/null
check "namespace removed"              'briqyard namespace rm "$GT" && ! briqyard namespace get "$GT" >/dev/null 2>&1'
check "gateway gone with it"        '! briqyard machine get "$GW" >/dev/null 2>&1'

echo "== iron-proxy as the namespace gateway: a stock image, a header injected, a token swapped (ADR 0016)"
IT="$T-ip" IRON=ironsh/iron-proxy:0.54.0@sha256:6d074be2de9188f88d08013788d5500fb4de8557f16c2e5b27af4d8d2cb1e3fb
D=$(mktemp -d)
# One CA: iron-proxy signs its leaves with it, and it signed the echo server's certificate, which
# iron-proxy trusts upstream (SSL_CERT_FILE). The echo server is a sibling: no third party.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=e2e iron CA" -keyout "$D/ca.key" -out "$D/ca.crt" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=echo.internal" -keyout "$D/echo.key" -out "$D/echo.csr" 2>/dev/null
printf 'subjectAltName=DNS:echo.internal\n' > "$D/san"
openssl x509 -req -in "$D/echo.csr" -CA "$D/ca.crt" -CAkey "$D/ca.key" -CAcreateserial -days 1 -extfile "$D/san" -out "$D/echo.crt" 2>/dev/null
cat > "$D/echo.py" <<'PY'
import http.server, json, ssl
class Echo(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({k.lower(): v for k, v in self.headers.items()}).encode()
        self.send_response(200)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
s = http.server.HTTPServer(("0.0.0.0", 443), Echo)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/srv/echo.crt", "/srv/echo.key")
s.socket = ctx.wrap_socket(s.socket, server_side=True)
s.serve_forever()
PY
cat > "$D/proxy.yaml" <<'YAML'
dns:
  enabled: false
proxy:
  tunnel_listen: ":3128"
tls:
  ca_cert: /etc/iron-proxy/ca.crt
  ca_key: /etc/iron-proxy/ca.key
transforms:
  - name: allowlist
    config:
      domains: ["echo.internal"]
  - name: secrets
    config:
      secrets:
        - source: { type: env, var: INJECTED }
          inject: { header: X-Injected }
          rules: [{ host: echo.internal, methods: [GET] }]
        # The CONNECT carries no header: a rule on every method would refuse the tunnel itself.
        - source: { type: env, var: API_KEY }
          replace: { proxy_value: proxy-tok, match_headers: [X-Api-Key], require: true }
          rules: [{ host: echo.internal, methods: [GET] }]
YAML
ECHO=$(briqyard machine run --image python:3.12-alpine --name echo --namespace "$IT" --memory 128 --file /srv/echo.py="$D/echo.py" \
  --file /srv/echo.crt="$D/echo.crt" --file /srv/echo.key="$D/echo.key" -- python3 /srv/echo.py | jq -r .id)
check "iron: the gateway set, a stock image with its files" 'briqyard namespace gateway set "$IT" --image "$IRON" --port 3128 -e INJECTED=inj-s3cret -e API_KEY=real-s3cret -e SSL_CERT_FILE=/etc/iron-proxy/ca.crt \
  --file /etc/iron-proxy/proxy.yaml="$D/proxy.yaml" --file /etc/iron-proxy/ca.crt="$D/ca.crt" --file /etc/iron-proxy/ca.key="$D/ca.key" -- -config /etc/iron-proxy/proxy.yaml >/dev/null'
IC=$(briqyard machine run --image python:3.12-alpine --name agent --namespace "$IT" --memory 128 --egress via:gateway --file /etc/ca.crt="$D/ca.crt" -- sleep 3600 | jq -r .id)
check "iron: its consumer's start runs it" '[ "$(briqyard namespace get "$IT" | jq -r .gateway.state)" = running ]'
get='import sys, urllib.request; print(urllib.request.urlopen(urllib.request.Request(sys.argv[1], headers={"X-Api-Key": sys.argv[2]}), timeout=10).read().decode())'
through() { briqyard machine exec "$IC" -- env https_proxy=http://gateway.internal:3128 SSL_CERT_FILE=/etc/ca.crt python3 -c "$get" "$1" "${2:-proxy-tok}" 2>&1; }
seen=$(through https://echo.internal/ || true)
check "iron: an allowed host through it, the header injected" 'echo "$seen" | jq -e ".[\"x-injected\"] == \"inj-s3cret\"" >/dev/null'
check "iron: the proxy token swapped for the secret" 'echo "$seen" | jq -e ".[\"x-api-key\"] == \"real-s3cret\"" >/dev/null'
check "iron: a request without the proxy token refused" 'out=$(through https://echo.internal/ another-key); echo "$out" | grep -q "HTTP Error 403"'
check "iron: a host off its list refused" 'out=$(through https://example.com/); echo "$out" | grep -q "Tunnel connection failed: 403"'
check "iron: the consumer holds no secret" '! briqyard machine exec "$IC" -- env | grep -q s3cret'
briqyard machine rm "$IC" >/dev/null
briqyard machine rm "$ECHO" >/dev/null
briqyard namespace rm "$IT" >/dev/null 2>&1 || true
check "iron: gone with its namespace" '! briqyard namespace get "$IT" >/dev/null 2>&1'
rm -rf "$D"

echo "== stop, start, exit handling"
briqyard machine stop "$A" >/dev/null
check "stopped (user)" '[ "$(briqyard machine get "$A" | jq -r .stopped_reason)" = user ]'
briqyard machine start "$A" >/dev/null
check "started again"  '[ "$(briqyard machine get "$A" | jq -r .state)" = running ]'
check "file survived"  '[ "$(briqyard machine get-file "$A" /root/f.txt)" = hello-file ]'
X=$(briqyard machine run --image alpine:3.20 --name exiter --namespace "$T" --memory 256 -- sh -c "exit 7" 2>/dev/null | jq -r .id || true)
for i in $(seq 1 30); do [ "$(briqyard machine get "$X" | jq -r .exit.code)" != null ] && break; sleep 1; done
check "exit recorded"  '[ "$(briqyard machine get "$X" | jq -r .exit.code)" = 7 ]'

echo "== events, versions and a watch"
EV=$(briqyard machine run --image alpine:3.20 --name evts --namespace "$T" --memory 128 -- sleep 3600 | jq -r .id)
# A watch from the machine's version: started before the stop, bounded, in the background.
timeout 60 briqyard events --machine "$EV" --since "$(briqyard machine get "$EV" | jq -r .version)" --watch > /tmp/by-e2e-watch.txt 2>&1 &
WATCH=$!
briqyard machine stop "$EV" >/dev/null
for i in $(seq 1 30); do awk '$4 == "stopped"' /tmp/by-e2e-watch.txt | grep -q . && break; sleep 1; done
check "a watch from before the stop gets it" 'awk "\$4 == \"stopped\"" /tmp/by-e2e-watch.txt | grep -q "$EV"'
kill "$WATCH" 2>/dev/null || true; wait "$WATCH" 2>/dev/null || true
patch_sleep() { "${CURL[@]}" -s -o /dev/null -w '%{http_code}' -X PATCH ${auth[@]+"${auth[@]}"} -H 'content-type: application/json' -H "If-Match: $1" -d '{"sleep":"3h"}' "$BRIQYARD_URL/v1/machines/$EV"; }
ver=$(briqyard machine get "$EV" | jq -r .version)
check "a stale If-Match is 409"      '[ "$(patch_sleep $((ver - 1)))" = 409 ]'
check "the current If-Match passes"  '[ "$(patch_sleep "$ver")" = 200 ]'
briqyard machine start "$EV" >/dev/null
check "describe shows its events"    'briqyard machine describe "$EV" | sed -n "/^Events:/,\$p" | grep -q "stopped (user)"'
briqyard machine rm "$EV" >/dev/null
reasons=$(briqyard events --machine "$EV" 2>/dev/null | awk 'NR > 1 && $4 ~ /^(created|started|stopped|destroyed)$/ { print $4 }' | paste -sd, -)
check "events in order ($reasons)"   '[ "$reasons" = created,started,stopped,started,destroyed ]'
check "a cursor past the log is gone" '! briqyard events --since 999999999 >/dev/null 2>&1'
# A watch of the destroyed machine stays quiet: a bookmark past its cursor, checked after the probes.
BM_SINCE=$("${CURL[@]}" -s ${auth[@]+"${auth[@]}"} "$BRIQYARD_URL/v1/events?machine=$EV" | jq -r .next)
timeout 40 "${CURL[@]}" -sN ${auth[@]+"${auth[@]}"} "$BRIQYARD_URL/v1/events?machine=$EV&since=$BM_SINCE&watch=true" > /tmp/by-e2e-bookmark.txt 2>&1 &
BOOKMARK=$!

echo "== probes: readiness decides ready, liveness restarts"
# The program serves 5 s after its boot: ready only then, its probe every 10 s.
RD=$(briqyard machine run --image python:3.12-alpine --name ready --namespace "$T" --memory 256 --readiness http:8080/ -- sh -c 'sleep 5; exec python3 -m http.server 8080' | jq -r .id)
check "running, not ready at first"  '[ "$(briqyard machine get "$RD" | jq -r .state,.ready | paste -sd, -)" = running,false ]'
for i in $(seq 1 30); do [ "$(briqyard machine get "$RD" | jq -r .ready)" = true ] && break; sleep 1; done
check "ready once it serves"         '[ "$(briqyard machine get "$RD" | jq -r .ready)" = true ]'
check "the ready event listed"       'briqyard events --machine "$RD" | awk "\$4 == \"ready\"" | grep -q .'
check "wait answers ready"           'briqyard machine wait "$RD" | jq -e .ready >/dev/null'
briqyard machine rm "$RD" >/dev/null
# The file goes after 5 s: three failed probes (30 s), the process ended, restarted 10 s later.
LV=$(briqyard machine run --image alpine:3.20 --name alive --namespace "$T" --memory 128 --liveness "exec:test -f /tmp/alive" -- sh -c 'touch /tmp/alive; sleep 5; rm /tmp/alive; exec sleep 3600' | jq -r .id)
for i in $(seq 1 60); do [ "$(briqyard machine get "$LV" | jq -r .restarts)" -ge 1 ] && break; sleep 2; done
check "a failing liveness restarts it" '[ "$(briqyard machine get "$LV" | jq -r .restarts)" -ge 1 ]'
check "the liveness_failed event"    'briqyard events --machine "$LV" | awk "\$4 == \"liveness_failed\"" | grep -q .'
for i in $(seq 1 30); do [ "$(briqyard machine get "$LV" | jq -r .state)" = running ] && break; sleep 2; done
check "running again"                '[ "$(briqyard machine get "$LV" | jq -r .state)" = running ]'
briqyard machine rm "$LV" >/dev/null
# Ready for 2 s, not for 2 s, probed every second: about ten flips in 20 s, two lines (ADR 0047).
flap='{"namespace":"'$T'","name":"flap","image":"alpine:3.20","cmd":["sh","-c","while :; do touch /tmp/up; sleep 2; rm -f /tmp/up; sleep 2; done"],"size":{"vcpus":1,"memory_mb":128},"probes":{"readiness":{"exec":["test","-f","/tmp/up"],"period_sec":1,"failure_threshold":1}}}'
FL=$("${CURL[@]}" -s -X POST ${auth[@]+"${auth[@]}"} -H 'content-type: application/json' -d "$flap" "$BRIQYARD_URL/v1/machines" | jq -r .id)
sleep 20
flips() { briqyard events --machine "$FL" 2>/dev/null | awk 'NR > 1 && ($4 == "ready" || $4 == "not_ready")'; }
last_seq=$("${CURL[@]}" -s ${auth[@]+"${auth[@]}"} "$BRIQYARD_URL/v1/events?machine=$FL" | jq -r '.events[-1].seq')
check "a flapping readiness probe: two lines"   '[ "$(flips | wc -l)" -le 2 ]'
check "its version moved past its last line"   '[ "$(briqyard machine get "$FL" | jq -r .version)" -gt $((last_seq + 2)) ]'
briqyard machine rm "$FL" >/dev/null
check "the destroy logs the folded flips, counted" '[ -n "$(flips | awk "\$6 > 1")" ]'
wait "$BOOKMARK" 2>/dev/null || true
check "a quiet watch sends a bookmark past its cursor" 'jq -se --argjson s "$BM_SINCE" "map(select(has(\"seq\"))) == [] and (map(.bookmark // empty) | last > \$s)" /tmp/by-e2e-bookmark.txt >/dev/null'

echo "== labels, a quota, logs follow"
LW=$(briqyard machine run --image alpine:3.20 --name lweb --namespace "$T" --memory 128 -l app=web -- sleep 3600 | jq -r .id)
briqyard machine run --image alpine:3.20 --name ldb --namespace "$T" --memory 128 -l app=db --no-start >/dev/null
selected() { briqyard machine ls --namespace "$T" "$@" | awk 'NR > 1 { print $1 }'; }
check "ls -l app=web lists one"      '[ "$(selected -l app=web)" = "$LW" ]'
check "ls -l app lists both"         '[ "$(selected -l app | wc -l)" -eq 2 ]'
check "a != selector is refused"     '! briqyard machine ls -l "app!=web" >/dev/null 2>&1'
Q="$T-q"
briqyard namespace quota "$Q" --machines 1 >/dev/null
briqyard machine run --image alpine:3.20 --name q1 --namespace "$Q" --memory 128 --no-start >/dev/null
second=$("${CURL[@]}" -s -w ' %{http_code}' -X POST ${auth[@]+"${auth[@]}"} -H 'content-type: application/json' -d "{\"namespace\":\"$Q\",\"name\":\"q2\",\"image\":\"alpine:3.20\",\"size\":{\"vcpus\":1,\"memory_mb\":128}}" "$BRIQYARD_URL/v1/machines")
check "quota: the second create is 403 quota" '[ "${second##* }" = 403 ] && [ "$(echo "${second% *}" | jq -r .code)" = quota ]'
check "quota: its use shown"         '[ "$(briqyard namespace quota "$Q" | jq -c "[.quota.machines, .used.machines]")" = "[1,1]" ]'
check "quota: the refusal is an event" 'briqyard events --namespace "$Q" | awk "\$4 == \"quota_exceeded\"" | grep -q .'
FL=$(briqyard machine run --image alpine:3.20 --name follow --namespace "$T" --memory 128 -- sleep 3600 | jq -r .id)
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
AP=$(briqyard machine run --image python:3.12-alpine --name apply --namespace "$T" --memory 256 --volume 1G:/data -e V=1 --file /srv/page.txt=/tmp/by-e2e-page.txt -- sh -c 'cd /srv && echo "$V" > v.txt && exec python3 -m http.server 8080' | jq -r .id)
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

echo "== a volume grows: its disk at once, its filesystem at the next boot (ADR 0040)"
VG=$(briqyard machine run --image alpine:3.20 --name grow --namespace "$T" --memory 256 --volume 1G:/data -- sleep 3600 | jq -r .id)
fs_mb() { briqyard machine exec "$1" -- df -m /data | awk 'NR == 2 { print $2 }'; }
VPOOL=$(sudo sed -n 's/^  pool: //p' /etc/briqyard/config.yaml); VPOOL=${VPOOL:-byard}
briqyard machine exec "$VG" -- sh -c 'echo kept > /data/mark; sync' >/dev/null
small=$(fs_mb "$VG")
VB1=$(briqyard machine backup "$VG" | jq -r .id)
check "grown to 3 GB, its filesystem pending" '[ "$(briqyard machine set "$VG" --volume-gb 3 | jq -r "[.volume.size_gb, (.pending.fields | join(\",\")), .pending.volume.size_gb] | join(\" \")")" = "3 volume 3" ]'
check "the disk grew at once"            '[ "$(sudo zfs get -Hp -o value volsize "$VPOOL/m/$VG/data")" = $((3 << 30)) ]'
check "the running guest keeps its size" '[ "$(fs_mb "$VG")" = "$small" ]'
check "the same size is no change"       'v=$(briqyard machine get "$VG" | jq .version); [ "$(briqyard machine set "$VG" --volume-gb 3 | jq .version)" = "$v" ]'
check "a smaller size is refused"        'out=$(briqyard machine set "$VG" --volume-gb 2 2>&1); [ $? != 0 ] && echo "$out" | grep -q "a volume never shrinks"'
briqyard machine stop --suspend "$VG" >/dev/null
check "suspended with the growth pending" '[ "$(briqyard machine get "$VG" | jq -r "[.suspended, .pending.fields[0]] | join(\" \")")" = "true volume" ]'
briqyard machine start "$VG" >/dev/null
check "the start boots it cold"          '[ "$(briqyard machine logs "$VG" --limit 5000 | grep -c "\[briqyard\] started")" = 2 ] && [ "$(briqyard machine get "$VG" | jq -r .pending)" = null ]'
grown=$(fs_mb "$VG")
check "its filesystem fills the disk ($small -> $grown MB)" '[ "$grown" -gt $((small * 2)) ]'
check "the init says it grew it"         'briqyard machine logs "$VG" --limit 5000 | grep -q "volume /data: grown from"'
check "the data kept"                    '[ "$(briqyard machine exec "$VG" -- cat /data/mark)" = kept ]'
VB2=$(briqyard machine backup "$VG" | jq -r .id)
check "the next backup continues the chain" '[ "$(briqyard machine backups "$VG" | jq -r ".[] | select(.id == \"$VB2\") | .disks[] | select(.disk == \"data\") | .from")" = "$VB1" ]'
VR=$(briqyard machine restore --from "$VG" --backup "$VB2" --namespace "$T" --name growback | jq -r .id)
check "restored from the chain: 3 GB, the data" '[ "$(briqyard machine get "$VR" | jq .volume.size_gb)" = 3 ] && [ "$(fs_mb "$VR")" = "$grown" ] && [ "$(briqyard machine exec "$VR" -- cat /data/mark)" = kept ]'
briqyard machine destroy "$VR" >/dev/null
briqyard machine destroy "$VG" >/dev/null

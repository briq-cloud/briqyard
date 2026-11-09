#!/usr/bin/env bash
# The qualification batch (ADR 0095): what no other suite does on purpose, with real causes.
# Isolation between namespaces and from the host, a guest's OOM and a VMM's, physical
# admission, then the daemon, the fleet, a VMM and the host's power killed with SIGKILL in the
# middle of a create, a fork, a backup, a snapshot and a suspend, and a full pool. After every
# crash: nothing stuck, nothing leaked (hack/stress-invariants.sh), the data on the disks
# intact. An attempt that must fail is checked for the reason it fails, beside a positive
# control that succeeds the same way.
#
# DISPOSABLE HOST ONLY. It kills the daemon, the fleet and every Firecracker, fills the pool
# and lowers a VMM's cgroup ceiling. Needs a running briqyardd (7420), briqyard-fleet (7430),
# sudo, a `backup.store`, `capacity.memory_mb: 12288`, the internet, python3 and the tools of
# hack/e2e.sh. Every namespace it makes is "qual-<pid>…" and is destroyed at the end.
set -euo pipefail
export BRIQYARD_URL=${BRIQYARD_URL:-http://127.0.0.1:7420}
FLEET_URL=${FLEET_URL:-http://127.0.0.1:7430}
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
for c in briqyard curl jq sudo python3 journalctl pgrep; do command -v "$c" >/dev/null || { echo "qualify needs $c"; exit 2; }; done
sudo -n true || { echo 'qualify needs sudo without a password'; exit 2; }
systemctl is-active briqyardd >/dev/null || { echo 'qualify needs the briqyardd unit running'; exit 2; }
T=qual-$$
LOGS=${QUAL_LOGS:-/tmp/qual-$$}; mkdir -p "$LOGS"
POOL=$(sudo sed -n 's/^  pool: //p' /etc/briqyard/config.yaml); POOL=${POOL:-byard}
JAIL=$(sudo sed -n 's/^jail_dir: //p' /etc/briqyard/config.yaml); JAIL=${JAIL:-/var/lib/briqyard/jail}
# Images pinned by digest (the manifest lists on Docker Hub, checked 2026-11-04): a moved tag
# changes nothing here, and the pulls go through the host's registry mirror.
ALPINE=alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
PY=python:3.12-alpine@sha256:e6dae589c1c05976188fd3bd019afd091445fc533ed2ea29001beddc7368a9c8
PYSLIM=python:3.12-slim@sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30
NODE=node:22-bookworm-slim@sha256:4b150b48b4116e2a22f2c39cc27025fbf4f153e2078fd3b14d159fdb5c7279da
NGINX=nginx:alpine@sha256:785835ea65db4bba6f021acc0f3be91b0fef76a53fe41f8588c6698d2aed0606
STORE=$(sudo sed -n 's|^  store: file://||p' /etc/briqyard/config.yaml); STORE=${STORE:-/var/lib/briqyard/backups}
pass=0; fail=0
ok()   { pass=$((pass+1)); echo "  ok   $1"; }
bad()  { fail=$((fail+1)); echo "  FAIL $1"; }
# A check runs in a subshell: an `exit` in a polling loop ends the check, not the suite.
check(){ if ( eval "$2" ); then ok "$1"; else bad "$1"; fi; }
. "$HERE/suite-end.sh"

api()  { curl -fsS -m 20 ${BRIQYARD_TOKEN:+-H "Authorization: Bearer $BRIQYARD_TOKEN"} "$BRIQYARD_URL$1"; }
fleet(){ BRIQYARD_URL=$FLEET_URL briqyard "$@"; }
on()   { briqyard machine exec --timeout 120s "$1" -- sh -c "$2"; }
mstate(){ briqyard machine get "$1" | jq -r .state; }
daemon_pid() { systemctl show -p MainPID --value briqyardd; }
fleet_pid()  { systemctl show -p MainPID --value briqyard-fleet; }
id_dash() { echo "${1//_/-}"; }
leaf() { echo "/sys/fs/cgroup/firecracker/$(id_dash "$1")"; }
# The Firecracker of a machine, by the id on its command line (fields compared, no patterns).
fc_pid() {
  local want; want=$(id_dash "$1")
  pgrep -a firecracker | awk -v want="$want" '{ for (i = 1; i < NF; i++) if ($i == "--id" && $(i+1) == want) { print $1; exit } }'
}
statusq() { briqyard status | jq -r "$1"; }
run() { briqyard machine run --sleep never "$@" | jq -r .id; }
rm_all() { local m; for m in "$@"; do briqyard machine rm "$m" >/dev/null; done; }

BGPIDS=()
FILLED=
cleanup() {
  local rc=$?
  echo "cleanup"
  set +e
  for p in "${BGPIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
  [ -z "$FILLED" ] || sudo zfs destroy -f "$FILLED" 2>/dev/null
  # A run that ended while a service was down starts it again.
  sudo systemctl start briqyardd briqyard-fleet
  for i in $(seq 1 60); do briqyard status >/dev/null 2>&1 && break; sleep 1; done
  for t in $(briqyard namespace ls 2>/dev/null | jq -r --arg t "$T" '.[].id | select(. == $t or startswith($t + "-"))'); do
    for id in $(briqyard machine ls --namespace "$t" 2>/dev/null | awk 'NR>1{print $1}'); do briqyard machine rm "$id" >/dev/null 2>&1; done
    for i in $(seq 1 10); do
      briqyard namespace rm "$t" >/dev/null 2>&1 && break
      for id in $(briqyard machine ls --namespace "$t" 2>/dev/null | awk 'NR>1{print $1}'); do briqyard machine rm "$id" >/dev/null 2>&1; done
      sleep 2
    done
  done
  suite_early_end "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP

# ---- recovery helpers ----
wait_api() { local i; for i in $(seq 1 90); do briqyard status >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }
# SIGKILL to the daemon alone (a systemctl kill would take the machines with it), then a start
# now rather than after RestartSec.
crash_daemon() {
  local pid i; pid=$(daemon_pid)
  sudo kill -9 "$pid"
  for i in $(seq 1 50); do [ "$(daemon_pid)" != "$pid" ] && break; sleep 0.1; done
  # A `zfs send` paused by a check outlives the daemon; it must be gone before recovery runs.
  sudo pkill -KILL -f '[z]fs send -w' || true
  sudo systemctl start briqyardd
  wait_api
}
# Nothing in motion: every machine out of creating, starting, stopping and destroying.
settle() {
  local i n
  for i in $(seq 1 240); do
    n=$(api /v1/machines | jq '[.[] | select(.state == "creating" or .state == "starting" or .state == "stopping" or .state == "destroying")] | length') || n=1
    [ "$n" = 0 ] && return 0
    sleep 1
  done
  return 1
}
# kill_during DELAY CMD...: CMD runs in the background and the daemon is killed DELAY seconds
# later. True only when the client then failed: the operation was cut short, not finished.
kill_during() {
  local delay=$1; shift
  "$@" >"$LOGS/bg.out" 2>&1 &
  local bg=$!
  sleep "$delay"
  if ! kill -0 "$bg" 2>/dev/null; then wait "$bg" 2>/dev/null || true; return 1; fi
  crash_daemon
  if wait "$bg" 2>/dev/null; then return 1; fi
  return 0
}
# kill_when PREDICATE CMD...: CMD runs in the background and the daemon is killed the moment
# PREDICATE (a function reading the API) says the work is under way; for what answers at once
# and finishes after (a fork). True when the predicate was seen within 20 s.
kill_when() {
  local pred=$1; shift
  "$@" >"$LOGS/bg.out" 2>&1 &
  local bg=$! i hit=1
  for i in $(seq 1 400); do
    if "$pred"; then crash_daemon; hit=0; break; fi
    sleep 0.05
  done
  local rc=0
  wait "$bg" 2>/dev/null || rc=$?
  # KILL_NEEDS_FAILURE=1: the kill counts only when the client then failed, work was cut and not finished.
  [ "${KILL_NEEDS_FAILURE:-0}" = 1 ] && [ "$rc" = 0 ] && hit=1
  return "$hit"
}
fork_in_motion() { case "$(settled_state "$T-c" fk)" in creating|starting) true;; *) false;; esac; }
invariants() {
  bash "$HERE/stress-invariants.sh" >"$LOGS/inv.out" 2>&1 && return 0
  grep -E '^BAD|^info' "$LOGS/inv.out" | head -8
  if grep -qF "without a cgroup leaf" "$LOGS/inv.out"; then
    local p
    for p in $(pgrep -x firecracker); do echo "      pid $p: cgroup $(sudo cat /proc/$p/cgroup), score $(sudo cat /proc/$p/oom_score_adj), args $(tr '\0' ' ' </proc/$p/cmdline | cut -c1-120)"; done
    echo "      leaves: $(sudo ls /sys/fs/cgroup/firecracker | tr '\n' ' ')"
    echo "      conditions: $(briqyard status | jq -c '[.conditions[] | select(.status)]')"
    sudo journalctl -u briqyardd --no-pager -n 3000 | grep -iE 'memory_protection|cgroup|containment' | tail -5 | cut -c1-320 | sed 's/^/      /'
  fi
  return 1
}
# No machine in error with an empty error: a failure is reported, never silent.
errors_reported() { [ "$(api /v1/machines | jq '[.[] | select(.state == "error" and (.error // "") == "")] | length')" = 0 ]; }
destroy_named() { # NAMESPACE NAME: whatever record a cut-short create left
  local id; id=$(api /v1/machines | jq -r --arg n "$2" --arg t "$1" '.[] | select(.name == $n and .namespace == $t) | .id')
  [ -z "$id" ] || briqyard machine rm "$id" >/dev/null 2>&1 || true
}
settled_state() { api /v1/machines | jq -r --arg n "$2" --arg t "$1" '[.[] | select(.name == $n and .namespace == $t)][0].state // "none"'; }
# The fleet refuses a create for REASON (a host under pressure), polled while its view catches up.
fleet_refuses() { # REASON NAME NAMESPACE
  local i out=
  for i in $(seq 1 60); do
    if ! out=$(fleet machine run --sleep never --image $ALPINE --name "$2" --namespace "$3" --memory 128 -- sleep 60 2>&1); then
      grep -qiF "$1" <<<"$out" && return 0
    fi
    sleep 2
  done
  echo "   last answer: $(echo "$out" | head -c 300)"
  return 1
}
# What the daemon and the events say about a machine, printed when a check on it is about to run.
diag() {
  echo "   -- $1: $(briqyard machine get "$1" 2>&1 | jq -c '{state, error, error_reason, stopped_reason}' 2>/dev/null)"
  briqyard events --machine "$1" 2>&1 | tail -6 | cut -c1-240 | sed 's/^/      /'
  sudo journalctl -u briqyardd --no-pager -n 600 | grep -F "$1" | tail -6 | cut -c1-300 | sed 's/^/      /'
}
fleet_places() { # NAME NAMESPACE: a create through the fleet is accepted again, polled while its view catches up
  local i id
  for i in $(seq 1 60); do
    if id=$(fleet machine run --sleep never --image $ALPINE --name "$1" --namespace "$2" --memory 128 -- sleep 600 2>/dev/null | jq -r .id) && [ -n "$id" ]; then
      [ "$(on "$id" hostname)" = "$1" ] && { briqyard machine rm "$id" >/dev/null; return 0; }
    fi
    sleep 2
  done
  return 1
}
wait_cond() { # TYPE: the host condition is true within two minutes
  local i; for i in $(seq 1 120); do [ "$(statusq "[.conditions[] | select(.type == \"$1\")][0].status")" = true ] && return 0; sleep 1; done; return 1
}

echo "== the host is protected before anything is tried"
check "no host condition is true (memory_protection and accounting included)" '[ "$(statusq "[.conditions[] | select(.status)] | length")" = 0 ]'

# ======================================================================================
echo "== isolation: namespaces, the host, the metadata address (a failure for its reason, a control beside it)"
A=$(run --image $PY --name iso-a --namespace "$T-n1" --memory 256 --volume 1G:/data -e "SECRET_A=tok-a-7f3c" -- sh -c 'mkdir -p /www && echo secret-a > /www/s && exec python3 -m http.server 8000 --directory /www')
A2=$(run --image $PY --name iso-a2 --namespace "$T-n1" --memory 256 --cpu-millis 500 -e "SECRET_A2=tok-a2-91be" -- sleep 7200)
O=$(run --image $PY --name iso-o --namespace "$T-n2" --memory 256 -- sh -c 'mkdir -p /www && echo secret-o > /www/s && exec python3 -m http.server 8000 --directory /www')
NN=$(run --image $PY --name iso-none --namespace "$T-n1" --memory 256 --egress none -- sleep 7200)
aip=$(briqyard machine get "$A" | jq -r .ip); oip=$(briqyard machine get "$O" | jq -r .ip)
a2ip=$(briqyard machine get "$A2" | jq -r .ip)
gw1=${aip%.*}.1; gw2=${oip%.*}.1
mkdir -p "$LOGS/www" && echo host-secret > "$LOGS/www/s"
python3 -m http.server 9999 --bind 0.0.0.0 --directory "$LOGS/www" >"$LOGS/hostsrv.out" 2>&1 &
BGPIDS+=($!)
for i in $(seq 1 30); do curl -fsS -m 2 http://127.0.0.1:9999/s >/dev/null 2>&1 && break; sleep 0.5; done
# get ADDRESS: the body, then the client's exit status; its own words are kept for why not.
get() { on "$1" "wget -qO- -T 4 $2 2>&1; echo rc=\$?" || true; }
blocks() { on "$1" 'ls /sys/block' | grep -v -e '^loop' -e '^ram' | tr '\n' ' '; }
seccomp_all() { sudo sh -c "cat /proc/$1/task/*/status" | awk '/^Seccomp:/ {print $2}' | sort -u | tr -d '\n'; }
cap_eff() { sudo awk '/^CapEff:/ {print $2}' "/proc/$1/status"; }
check "control: a sibling of the namespace reads the server" '[ "$(get "$A2" http://$aip:8000/s)" = "$(printf "secret-a\nrc=0")" ]'
out=$(get "$O" http://$aip:8000/s)
check "another namespace: the connection times out, no byte read" 'grep -qF "timed out" <<<"$out" && ! grep -qF secret-a <<<"$out" && grep -qF "rc=1" <<<"$out"'
out=$(on "$O" "ping -c2 -W2 $aip 2>&1; echo rc=\$?" || true)
check "another namespace: ping is 100% loss" 'grep -qF "100% packet loss" <<<"$out"'
out=$(on "$A2" "ping -c2 -W2 $aip 2>&1; echo rc=\$?" || true)
check "control: the sibling answers ping" 'grep -qF " 0% packet loss" <<<"$out"'
out=$(get "$A2" http://$oip:8000/s)
check "the other direction, too" 'grep -qF "timed out" <<<"$out" && ! grep -qF secret-o <<<"$out"'
check "control: the host answers its own server" '[ "$(curl -fsS -m 3 http://127.0.0.1:9999/s)" = host-secret ]'
out=$(get "$A2" http://$gw1:9999/s)
check "the host through its bridge address: times out, not read" 'grep -qF "timed out" <<<"$out" && ! grep -qF host-secret <<<"$out"'
out=$(get "$A2" http://$gw2:9999/s)
check "the host through another namespace's bridge address: times out" 'grep -qF "timed out" <<<"$out" && ! grep -qF host-secret <<<"$out"'
for port in 7420 8080 7430; do
  out=$(get "$A2" http://$gw1:$port/)
  check "the daemon's API and ingress ports ($port) on the gateway address: no answer" '! grep -qF rc=0 <<<"$out" && grep -qF "timed out" <<<"$out"'
done
check "control: the gateway answers DNS" 'on "$A2" "nslookup iso-a.internal 2>&1" | grep -qF "$aip"'
check "control: the gateway answers ping" 'on "$A2" "ping -c1 -W2 $gw1" >/dev/null'
hostip=$(ip -4 route get 1.1.1.1 | awk '{ for (i = 1; i < NF; i++) if ($i == "src") { print $(i+1); exit } }')
check "control: the host answers on its uplink address ($hostip)" '[ -n "$hostip" ] && [ "$(curl -fsS -m 3 http://$hostip:9999/s)" = host-secret ]'
out=$(get "$A2" http://$hostip:9999/s)
check "the host's uplink address: times out, not read" 'grep -qF "timed out" <<<"$out" && ! grep -qF host-secret <<<"$out"'
out=$(on "$A2" "nslookup iso-o.internal 2>&1" || true)
check "DNS: another namespace's machine name does not resolve (NXDOMAIN), its address is not given" '! grep -qF "$oip" <<<"$out" && grep -qiE "NXDOMAIN|can.t find|not found" <<<"$out"'
nft_fwd=$(sudo nft list chain inet briqyard forward)
check "IPv6 from a bridge: the forward chain drops it (policy drop and the nfproto ipv6 rule)" 'grep -qF "policy drop" <<<"$nft_fwd" && grep -qF "meta nfproto ipv6 iifname \"by*\" drop" <<<"$nft_fwd"'
out=$(on "$A2" "wget -qO- -T 4 'http://[2606:4700:4700::1111]/' 2>&1; echo rc=\$?" || true)
echo "   an IPv6 address from the guest: $(echo "$out" | head -c 120) (the runner has no IPv6 route: this proves a guest cannot reach one, the rule above proves why)"
br=$(ip -o -4 addr show | awk -v g="$gw1" '{ split($4, a, "/"); if (a[1] == g) { print $2; exit } }')
hostll=$(ip -6 -o addr show dev "$br" scope link | awk '{ split($4, a, "/"); print a[1]; exit }')
nft_in=$(sudo nft list chain inet briqyard input)
dev=$(on "$A2" 'ls /sys/class/net | grep -v "^lo$" | head -1')
out=$(on "$A2" "ip -6 addr show dev $dev | grep -c 'inet6 fe80'; ping -6 -c2 -W2 -I $dev $hostll 2>&1 || ping6 -c2 -W2 -I $dev $hostll 2>&1; echo rc=\$?" || true)
echo "   link-local ping from the guest to the bridge $br ($hostll): $(echo "$out" | tr '\n' '|' | head -c 220)"
echo "   input chain, ICMP rules: $(grep -i icmp <<<"$nft_in" | tr -s ' \t' ' ' | tr '\n' ';')"
check "IPv6 on the input path: only IPv4 echo is accepted from a bridge (icmp, not icmpv6), then everything else is dropped" '[ -n "$hostll" ] && grep -qF "icmp type echo-request accept" <<<"$nft_in" && grep -qF "iifname \"by*\" drop" <<<"$nft_in"'
check "IPv6 on the input path: a link-local ping to the host's bridge address gets no answer (100% loss)" 'grep -qF "100% packet loss" <<<"$out"'
check "IPv6 from the guest: nothing is read" '! grep -qF rc=0 <<<"$out"'
out=$(get "$A2" http://169.254.169.254/latest/meta-data/)
check "the metadata address: times out" 'grep -qF "timed out" <<<"$out" && grep -qF "rc=1" <<<"$out"'
out=$(get "$A2" http://10.0.0.1/)
check "a private range (10/8): times out" 'grep -qF "timed out" <<<"$out"'
out=$(get "$A2" http://192.168.1.1/)
check "a private range (192.168/16): times out" 'grep -qF "timed out" <<<"$out"'
check "control: the internet answers an open machine (example.com, else one.one.one.one)" 'on "$A2" "wget -q -O /dev/null -T 10 http://example.com || wget -q -O /dev/null -T 10 http://one.one.one.one/"'
# Identity: a guest that changes its MAC or takes an address sends nothing.
dev=$(on "$A2" 'ls /sys/class/net | grep -v "^lo$" | head -1')
mac=$(on "$A2" "cat /sys/class/net/$dev/address")
on "$A2" "ip link set $dev address 02:00:00:aa:bb:cc" >/dev/null
out=$(on "$A2" "ping -c2 -W2 $gw1 2>&1; echo rc=\$?" || true)
check "a changed MAC sends nothing (100% loss)" 'grep -qF "100% packet loss" <<<"$out"'
on "$A2" "ip link set $dev address $mac" >/dev/null
check "control: the real MAC again, the gateway answers" 'on "$A2" "ping -c2 -W2 $gw1" >/dev/null'
spare=${a2ip%.*}.200
on "$A2" "ip addr add $spare/24 dev $dev" >/dev/null
out=$(on "$A2" "ping -c2 -W2 -I $spare $gw1 2>&1; echo rc=\$?" || true)
check "an address that is not its own sends nothing (100% loss)" 'grep -qF "100% packet loss" <<<"$out"'
check "control: its own address still answers" 'on "$A2" "ping -c2 -W2 -I $a2ip $gw1" >/dev/null'
# Egress none.
out=$(on "$NN" "wget -qO- -T 4 http://1.1.1.1/ 2>&1; echo rc=\$?" || true)
check "egress none: an address on the internet times out" 'grep -qF "timed out" <<<"$out" && grep -qF rc=1 <<<"$out"'
out=$(on "$NN" "nslookup example.com 2>&1; echo rc=\$?" || true)
check "egress none: names outside the namespace do not resolve (NXDOMAIN)" 'grep -qiE "NXDOMAIN|can.t find|not found" <<<"$out"'
check "egress none: control, its namespace and internal names answer" 'on "$NN" "ping -c1 -W2 $aip" >/dev/null && on "$NN" "nslookup iso-a.internal 2>&1" | grep -qF "$aip"'
# Disks, files and the guest's view of its devices.
seen=$(blocks "$A")
check "a guest sees its own three disks only: root, config drive, volume (sees: $seen)" '[ "$seen" = "vda vdb vdc " ]'
on "$A" 'echo mark-a > /root/mark; sync'
out=$(on "$A2" 'cat /root/mark 2>&1' || true)
check "a file of one machine is absent from its sibling on the same image" 'on "$A" "cat /root/mark" | grep -qx mark-a && grep -qF "No such file" <<<"$out"'
out=$(on "$A2" 'ls -l /dev/kvm 2>&1' || true)
check "/dev/kvm is absent in the default class" 'grep -qF "No such file" <<<"$out" && on "$A2" "test -c /dev/null"'
# vsock: a connect from the guest to the host's CID is refused, to another guest's is not made.
vs='import socket,sys
s=socket.socket(socket.AF_VSOCK,socket.SOCK_STREAM); s.settimeout(5)
try:
    s.connect((int(sys.argv[1]),int(sys.argv[2]))); print("connected")
except OSError as e:
    print("errno", e.errno)'
out=$(briqyard machine exec "$A2" -- python3 -c "$vs" 2 5000 || true)
check "vsock: a connect to the host is refused (ECONNRESET)" '[ "$out" = "errno 104" ]'
out=$(briqyard machine exec "$A2" -- python3 -c "$vs" 3 5000 || true)
check "vsock: a connect to another guest's CID is not made" '! grep -qF connected <<<"$out" && grep -qF errno <<<"$out"'
# The jail, as the host sees it.
pa=$(fc_pid "$A"); pa2=$(fc_pid "$A2")
check "a Firecracker per machine, found by its own id" '[ -n "$pa" ] && [ -n "$pa2" ] && [ "$pa" != "$pa2" ]'
ua=$(sudo awk '/^Uid:/ {print $2}' /proc/$pa/status); ua2=$(sudo awk '/^Uid:/ {print $2}' /proc/$pa2/status)
check "jailer: not root, and a uid of its own per machine ($ua, $ua2)" '[ "$ua" != 0 ] && [ "$ua2" != 0 ] && [ "$ua" != "$ua2" ]'
ga=$(sudo awk '/^Gid:/ {print $2}' /proc/$pa/status); ga2=$(sudo awk '/^Gid:/ {print $2}' /proc/$pa2/status)
check "jailer: a gid of its own per machine, not root ($ga, $ga2)" '[ "$ga" != 0 ] && [ "$ga2" != 0 ] && [ "$ga" != "$ga2" ]'
echo "   pids.max of a VMM leaf: $(sudo cat "$(leaf "$A")/pids.max" 2>&1)"
th0=$(sudo awk '/^Threads:/ {print $2}' /proc/$pa2/status)
n=$(on "$A2" 'i=0; while [ $i -lt 300 ]; do sleep 60 >/dev/null 2>&1 & i=$((i+1)); done; ls /proc | grep -c "^[0-9]"')
th1=$(sudo awk '/^Threads:/ {print $2}' /proc/$pa2/status)
check "a guest's processes are not host processes (guest runs $n, its VMM threads $th0 -> $th1)" '[ "$n" -ge 300 ] && [ "$th1" -le $((th0 + 2)) ]'
# Read before the kill below: it ends the machine's own `sleep` too, and a stopped machine keeps no leaf (ADR 0099).
cpumax=$(sudo cat "$(leaf "$A2")/cpu.max" 2>&1)
on "$A2" 'kill $(pidof sleep)' || true
check "jailer: no capabilities, no new privileges" '[ "$(cap_eff $pa)" = 0000000000000000 ] && [ "$(sudo awk "/^NoNewPrivs:/ {print \$2}" /proc/$pa/status)" = 1 ]'
check "jailer: a seccomp filter on every thread" '[ "$(seccomp_all $pa)" = 2 ]'
check "jailer: chrooted (its root holds the VMM socket, not the host's /usr or /etc/passwd)" 'sudo test -S /proc/$pa/root/run/firecracker.socket && ! sudo test -e /proc/$pa/root/usr/bin && ! sudo test -e /proc/$pa/root/etc/passwd'
check "jailer: its own pid namespace" '[ "$(sudo awk "/^NSpid:/ {print NF - 1}" /proc/$pa/status)" -ge 2 ]'
check "its own cgroup, and only its process in it" '[ "$(sudo cat /proc/$pa/cgroup)" = "0::/firecracker/$(id_dash "$A")" ] && [ "$(sudo cat $(leaf "$A")/cgroup.procs)" = "$pa" ]'
f=$(sudo find "$JAIL/firecracker/$(id_dash "$A")/root" -type f -size -2000k 2>/dev/null | head -1)
check "control: the host reads a file in a machine's jail" '[ -n "$f" ] && sudo cat "$f" >/dev/null'
out=$(sudo setpriv --reuid "$ua2" --regid "$ua2" --clear-groups cat "$f" 2>&1 || true)
echo "   uid $ua2 reading $f: $(echo "$out" | head -c 120)"
check "another machine's uid cannot read it (Permission denied)" 'grep -qF "Permission denied" <<<"$out"'
out=$(sudo setpriv --reuid "$ua2" --regid "$ua2" --clear-groups ls "$JAIL/firecracker/$(id_dash "$A")/root" 2>&1 || true)
echo "   uid $ua2 listing the jail: $(echo "$out" | head -c 120)"
check "nor list its jail (Permission denied)" 'grep -qF "Permission denied" <<<"$out"'
# Limits the cgroup holds.
mlim=$(( (256 + 256) * 1048576 ))
check "VMM ceiling is guest MiB + 256 MiB, no swap, a group kill" '[ "$(sudo cat $(leaf "$A")/memory.max)" = "$mlim" ] && [ "$(sudo cat $(leaf "$A")/memory.swap.max)" = 0 ] && [ "$(sudo cat $(leaf "$A")/memory.oom.group)" = 1 ]'
check "CPU quota of 500 millis is 50000 per 100000" '[ "$cpumax" = "50000 100000" ]'
dpid=$(daemon_pid); fpid=$(fleet_pid)
check "OOM preferences: VMM +500, daemon and fleet -900" '[ "$(sudo cat /proc/$pa/oom_score_adj)" = 500 ] && [ "$(sudo cat /proc/$dpid/oom_score_adj)" = -900 ] && [ "$(sudo cat /proc/$fpid/oom_score_adj)" = -900 ]'
# Secrets stay with their machine.
procs=$(ps -eo args)
check "control: a machine holds its own secret" 'on "$A" "printenv SECRET_A" | grep -qx tok-a-7f3c'
out=$(on "$A2" 'printenv; cat /proc/*/environ /proc/*/cmdline 2>/dev/null | tr "\\0" "\\n"; grep -r tok-a- /etc /root /tmp 2>/dev/null' || true)
check "a sibling does not hold it (env, process list, files)" '! grep -qF tok-a-7f3c <<<"$out"'
check "the host process list never shows it" '! grep -qF tok-a-7f3c <<<"$procs"'
out=$(on "$A2" 'cat /proc/cmdline /proc/1/environ 2>/dev/null; printenv' | tr '\0' '\n' || true)
check "the guest holds no host credential or daemon address" '! grep -qiE "BRIQYARD_TOKEN|BRIQYARD_URL" <<<"$out"'
rm_all "$A" "$A2" "$O" "$NN"

# ======================================================================================
echo "== OOM: a guest's, a VMM's, and the host's physical room"
hog='python3 -c "l = []; [l.append(b\"x\" * (16 << 20)) for _ in iter(int, 1)]"'
G=$(run --image $PY --name oom-g --namespace "$T-o" --memory 256 -- sleep 7200)
S=$(run --image $PY --name oom-s --namespace "$T-o" --memory 256 -- sleep 7200)
on "$S" 'echo alive > /root/s; sync'
gpid=$(fc_pid "$G"); spid=$(fc_pid "$S"); dpid=$(daemon_pid)
ev0=$(sudo cat "$(leaf "$G")/memory.events.local")
set +e; on "$G" "$hog" >"$LOGS/hog.out" 2>&1; rc=$?; set -e
echo "   the hog: exit $rc, said: $(head -c 150 "$LOGS/hog.out")"
check "guest OOM: the hog was killed in the guest (exit $rc)" '[ "$rc" = 137 ] || grep -qF Killed "$LOGS/hog.out"'
check "guest OOM: the kernel says so on the console" 'briqyard machine logs "$G" --limit 1000 --view runtime | grep -qiE "out of memory|oom-kill"'
check "guest OOM: the machine runs on, same VMM, exec answers" '[ "$(mstate "$G")" = running ] && [ "$(fc_pid "$G")" = "$gpid" ] && [ "$(on "$G" hostname)" = oom-g ]'
check "guest OOM: it was not the VMM's cgroup (no local oom_kill)" '[ "$(sudo cat "$(leaf "$G")/memory.events.local")" = "$ev0" ]'
check "guest OOM: the sibling and the daemon are untouched" '[ "$(on "$S" "cat /root/s")" = alive ] && [ "$(fc_pid "$S")" = "$spid" ] && [ "$(daemon_pid)" = "$dpid" ]'
H=$(briqyard machine run --detach --name oom-main --namespace "$T-o" --memory 256 --image $PY -- python3 -c 'l = []; [l.append(b"x" * (16 << 20)) for _ in iter(int, 1)]' | jq -r .id)
for i in $(seq 1 90); do [ "$(mstate "$H")" = stopped ] && break; sleep 1; done
check "guest OOM of the main process: stopped, exit reported oom_killed" '[ "$(mstate "$H")" = stopped ] && [ "$(briqyard machine get "$H" | jq -r .exit.oom_killed)" = true ]'
check "guest OOM of the main process: the sibling still runs" '[ "$(on "$S" "cat /root/s")" = alive ]'
rm_all "$H" "$G"
# A VMM over its containment. A guest cannot push Firecracker past guest + 256 MiB, so the
# ceiling of one leaf is lowered under what its VMM holds: the kernel's own cgroup OOM kill.
V=$(run --image $PY --name oom-v --namespace "$T-o" --memory 1024 -- sleep 7200)
on "$V" 'dd if=/dev/urandom of=/dev/shm/fill bs=1M count=300 2>/dev/null; sync'
vpid=$(fc_pid "$V"); dpid=$(daemon_pid); mark=$(date '+%Y-%m-%d %H:%M:%S')
rss=$(( $(sudo awk '/^VmRSS:/ {print $2}' /proc/$vpid/status) / 1024 ))
check "the VMM holds the guest's pages ($rss MiB resident)" '[ "$rss" -ge 250 ]'
echo 150M | sudo tee "$(leaf "$V")/memory.max" >/dev/null
for i in $(seq 1 60); do [ "$(mstate "$V")" = stopped ] && break; sleep 1; done
check "VMM over its ceiling: the VMM is gone, the machine stopped, exit 255" '[ "$(mstate "$V")" = stopped ] && [ -z "$(fc_pid "$V")" ] && [ "$(briqyard machine get "$V" | jq -r .exit.code)" = 255 ]'
check "VMM over its ceiling: the daemon logged the cgroup OOM evidence for it" 'sudo journalctl -u briqyardd --no-pager --since "$mark" | grep -F vmm_cgroup_oom_evidence | grep -qF "$V"'
check "VMM over its ceiling: the exit says so (vmm_oom_killed, ADR 0096), and it is not the guest's word (oom_killed false)" '[ "$(briqyard machine get "$V" | jq -r .exit.vmm_oom_killed)" = true ] && [ "$(briqyard machine get "$V" | jq -r .exit.oom_killed)" = false ]'
check "VMM over its ceiling: same daemon, sibling alive, daemon answers" '[ "$(daemon_pid)" = "$dpid" ] && [ "$(on "$S" "cat /root/s")" = alive ] && [ "$(fc_pid "$S")" = "$spid" ] && briqyard status >/dev/null'
briqyard machine start "$V" >/dev/null; briqyard machine wait --for running "$V" >/dev/null
check "VMM over its ceiling: the next start has the policy ceiling again" '[ "$(sudo cat $(leaf "$V")/memory.max)" = "$(( (1024 + 256) * 1048576 ))" ] && [ "$(on "$V" hostname)" = oom-v ]'
rm_all "$V" "$S"
check "OOM: nothing leaked" 'invariants'

echo "== physical admission: guest memory plus 256 MiB, to the megabyte"
cap=$(statusq .capacity.memory_mb); used0=$(statusq .used.memory_mb)
check "an empty host commits nothing ($used0 of $cap MB)" '[ "$used0" = 0 ] && [ "$cap" = 12288 ]'
# P1 is placed through the fleet, which pins the namespace to the host. A refusal for a host under
# pressure is for a namespace bound to it (ADR 0042); a new namespace is told "no host has room"
# (counted as memory), which is right and not what this check is about.
P1=$(fleet machine run --sleep never --image $ALPINE --name adm-1 --namespace "$T-adm" --memory 4096 -- sleep 7200 | jq -r .id)
briqyard machine wait --for running "$P1" >/dev/null
P2=$(run --image $ALPINE --name adm-2 --namespace "$T-adm" --memory 4096 -- sleep 7200)
check "two 4096 MB machines commit 2 x (4096 + 256) MB" '[ "$(statusq .used.memory_mb)" = 8704 ]'
before=$(api /v1/machines | jq length)
set +e; out=$(briqyard machine run --sleep never --image $ALPINE --name adm-3 --namespace "$T-adm" --memory 4096 -- sleep 7200 2>&1); rc=$?; set -e
check "a third is refused as capacity, naming it" '[ "$rc" != 0 ] && grep -qi capacity <<<"$out"'
check "the refusal made nothing and changed nothing committed" '[ "$(api /v1/machines | jq length)" = "$before" ] && [ "$(statusq .used.memory_mb)" = 8704 ]'
fit=$(( cap - 8704 - 256 ))
P3=$(run --image $ALPINE --name adm-fit --namespace "$T-adm" --memory "$fit" -- sleep 7200)
check "the exact remainder ($fit + 256 MB) is admitted: committed == capacity" '[ "$(statusq .used.memory_mb)" = "$cap" ]'
set +e; out=$(briqyard machine run --sleep never --image $ALPINE --name adm-4 --namespace "$T-adm" --memory 128 -- sleep 60 2>&1); rc=$?; set -e
check "one machine of 128 MB (384 MB charged) more is refused" '[ "$rc" != 0 ] && grep -qi capacity <<<"$out"'
check "memory_pressure turns true on the host" 'wait_cond memory_pressure'
check "memory pressure: the fleet places nothing new in a namespace on the host, for that reason" 'fleet_refuses memory_pressure adm-5 "$T-adm"'
check "memory pressure: a new namespace finds no host with room" 'fleet_refuses "no host has room" adm-7 "$T-adm-new"'
briqyard machine stop "$P1" >/dev/null
check "a stop releases its memory at once" '[ "$(statusq .used.memory_mb)" = $(( cap - 4096 - 256 )) ]'
P4=$(run --image $ALPINE --name adm-6 --namespace "$T-adm" --memory 128 -- sleep 7200)
check "the released room is taken again" '[ "$(mstate "$P4")" = running ]'
rm_all "$P1" "$P2" "$P3" "$P4"
check "admission: nothing leaked, nothing committed" 'invariants && [ "$(statusq .used.memory_mb)" = 0 ]'

# ======================================================================================
echo "== chaos: SIGKILL in the middle of an operation, then recovery"
# Owners with a counter on both disks; the counter is what must survive.
mkowner() { # NAME MEMORY [IMAGE: one whose own command keeps running, since a fork starts the image's, not the source's]
  local id
  if [ -n "${3:-}" ]; then id=$(run --image "$3" --name "$1" --namespace "$T-c" --memory "$2" --volume 2G:/data)
  else id=$(run --image $ALPINE --name "$1" --namespace "$T-c" --memory "$2" --volume 2G:/data -- sleep 7200); fi
  on "$id" 'echo 7 > /root/n; echo 7 > /data/n; sync' && echo "$id"
}
ctr() { on "$1" 'cat /root/n /data/n' | tr '\n' ' '; }
recovered() { # ID: settled, nothing silent, running again, its counter whole
  settle && errors_reported && [ "$(mstate "$1")" = running ] && [ "$(ctr "$1")" = "7 7 " ]
}
restore_running() { briqyard machine start "$1" >/dev/null 2>&1 || true; briqyard machine wait --for running "$1" >/dev/null 2>&1 || true; }

echo "-- mid-create"
caught=0
for d in 1 2.5 0.5 4; do
  destroy_named "$T-c" cr; settle || true
  if kill_during "$d" briqyard machine run --sleep never --image $PYSLIM --name cr --namespace "$T-c" --memory 256 -- sleep 7200; then caught=1; break; fi
done
check "a create was cut short (client failed, delay $d s)" '[ "$caught" = 1 ]'
check "the daemon is back and the host settles" 'wait_api && settle'
st=$(settled_state "$T-c" cr); echo "   the machine is: $st"
check "mid-create: a machine settles running, or in error with its reason, or was never recorded" 'case "$st" in running|none) true;; error) errors_reported;; *) false;; esac'
check "mid-create: invariants hold with what is left" 'invariants || [ "$st" = error ]'
destroy_named "$T-c" cr; settle || true
check "mid-create: destroyed, nothing leaked" 'invariants'
CR=$(run --image $PYSLIM --name cr --namespace "$T-c" --memory 256 -- sleep 7200)
check "mid-create: the same create again succeeds" '[ "$(on "$CR" hostname)" = cr ]'
rm_all "$CR"

echo "-- mid-fork"
SRC=$(mkowner src 256 $NGINX)
caught=0
for attempt in 1 2 3; do
  destroy_named "$T-c" fk; settle || true
  if kill_when fork_in_motion briqyard machine fork "$SRC" --name fk --namespace "$T-c"; then caught=1; break; fi
done
check "a fork was killed while creating or starting (attempt $attempt)" '[ "$caught" = 1 ]'
settle || true
st=$(settled_state "$T-c" fk); echo "   the fork is: $st"
check "mid-fork: the source runs on, its counter whole" 'recovered "$SRC"'
check "mid-fork: the fork is whole or reported, never half" 'case "$st" in running|none|stopped) true;; error) errors_reported;; *) false;; esac'
if [ "$st" = running ]; then
  FKID=$(api /v1/machines | jq -r --arg t "$T-c" '.[] | select(.name == "fk" and .namespace == $t) | .id')
  check "mid-fork: a fork that runs holds the counter" '[ "$(ctr "$FKID")" = "7 7 " ]'
fi
destroy_named "$T-c" fk; settle || true
check "mid-fork: destroyed, invariants hold, nothing leaked" 'invariants'
FK=$(briqyard machine fork "$SRC" --name fk2 --namespace "$T-c" | jq -r .id)
briqyard machine wait --for running "$FK" >/dev/null
check "mid-fork: a fork again works and holds the counter" '[ "$(ctr "$FK")" = "7 7 " ]'
rm_all "$FK"

echo "-- mid-backup"
BK=$(mkowner bk 256)
on "$BK" 'head -c 500000000 /dev/urandom > /data/blob; sync' || true
B0=$(briqyard machine backup "$BK" | jq -r .id)
check "real helper: crash, timeout traffic and automatic recovery, hand-over control" 'sudo -E python3 "$HERE/recovery-helper-check.py"'
bkdir=$STORE/backups/$BK
store_ids() { sudo find "$bkdir" -name "*.$1" 2>/dev/null | sed 's|.*/||; s|\.[a-z]*$||' | sort -u; }
# The second backup is under way once a stream newer than the first is on disk and its record is not.
backup_streaming() { sudo find "$bkdir" -name '*.zfs' -newer "$LOGS/b0.mark" 2>/dev/null | grep -q . && ! sudo find "$bkdir" -name '*.json' -newer "$LOGS/b0.mark" 2>/dev/null | grep -q .; }
# The second backup is incremental: it sends what changed since the first, and on a volume that
# changed by a few KB that stream lasts a few milliseconds, shorter than the poll that waits for it.
# So each attempt first writes 300 MB of new data (a stream of that size), and the moment the stream
# is seen the `zfs send` is paused (SIGSTOP), so the stream cannot finish before the kill lands. The
# kill is real, on the daemon; the paused send is killed afterwards.
backup_streaming_paused() { backup_streaming && { sudo pkill -STOP -f '[z]fs send -w' || true; }; }
caught=0
for attempt in 1 2 3; do
  on "$BK" "head -c 300000000 /dev/urandom > /data/cut$attempt; sync" || true
  touch "$LOGS/b0.mark"; sleep 1
  if KILL_NEEDS_FAILURE=1 kill_when backup_streaming_paused briqyard machine backup "$BK"; then caught=1; fi
  sudo pkill -KILL -f '[z]fs send -w' || true
  [ "$caught" = 1 ] && break
done
check "a backup was cut: killed while its stream was being written, its client failed (attempt $attempt)" '[ "$caught" = 1 ]'
check "mid-backup: the source runs on, its counter whole" 'recovered "$BK"'
listed=$(briqyard machine backups "$BK" | jq -r '.[].id' | sort -u)
echo "   listed after the crash: $(echo $listed); records in the store: $(echo $(store_ids json)); streams: $(echo $(store_ids zfs))"
check "mid-backup: the first backup is still listed" 'grep -qx "$B0" <<<"$listed"'
check "mid-backup: what is listed is exactly what the store has a record for" '[ "$listed" = "$(store_ids json)" ]'
orphans=$(comm -13 <(store_ids json) <(store_ids zfs))
echo "   streams with no record: ${orphans:-none}"
# KNOWN DEFECT (reported with ADR 0095): a backup killed mid-stream leaves its stream in the store
# with no record, and nothing removes it, not even the next successful backup. It is listed by
# nothing and restorable by nothing; the census (ADR 0083) only counts. Bound it here: at most the
# interrupted backup's one id, never listed. When the daemon cleans it, this prints FIXED and the
# check below becomes `[ -z "$orphans" ]`.
check "mid-backup: an interrupted backup leaves at most its own stream behind, unlisted (known defect: not removed)" '[ "$(echo $orphans | wc -w)" -le 1 ] && ! grep -qxF "$orphans" <<<"$listed"'
[ "$caught" = 1 ] && [ -z "$orphans" ] && echo "   FIXED: a kill cut a backup (its client failed) and no orphan stream is left; tighten the check above"
[ -z "$orphans" ] || echo "   KNOWN DEFECT: stream $orphans has no record in the store"
for b in $listed; do
  RB=$(briqyard machine restore --from "$BK" --backup "$b" --namespace "$T-c" --name "bk-r-${b//[^0-9]/}" | jq -r .id)
  check "mid-backup: listed backup $b restores, counter and 500 MB blob whole" '[ "$(ctr "$RB")" = "7 7 " ] && [ "$(on "$RB" "wc -c < /data/blob")" = 500000000 ]'
  rm_all "$RB"
done
B2=$(briqyard machine backup "$BK" | jq -r .id)
RB=$(briqyard machine restore --from "$BK" --backup "$B2" --namespace "$T-c" --name bk-r2 | jq -r .id)
check "mid-backup: a backup again works and restores whole" '[ "$(ctr "$RB")" = "7 7 " ] && [ "$(on "$RB" "wc -c < /data/blob")" = 500000000 ]'
rm_all "$RB"
orphans=$(comm -13 <(store_ids json) <(store_ids zfs))
echo "   streams with no record after the next backup: ${orphans:-none}"
check "mid-backup: invariants hold" 'invariants'
rm_all "$BK"

echo "-- mid-snapshot (with memory)"
SN=$(mkowner sn 1024)
on "$SN" 'dd if=/dev/urandom of=/dev/shm/fill bs=1M count=400 2>/dev/null; sync' || true
caught=0
for d in 0.5 1 2 0.2 3; do
  if kill_during "$d" briqyard machine snapshot create --memory "$SN"; then caught=1; break; fi
done
check "a snapshot was cut short (delay $d s)" '[ "$caught" = 1 ]'
check "mid-snapshot: the machine is running again, not left paused, its counter whole" 'recovered "$SN"'
SID=$(briqyard machine snapshot create --memory "$SN" | jq -r .id)
on "$SN" 'echo 8 > /root/n; sync'
briqyard machine snapshot restore "$SN" "$SID" >/dev/null || true
briqyard machine wait --for running "$SN" >/dev/null 2>&1 || true
check "mid-snapshot: a snapshot again works and restores to its counter" '[ "$(on "$SN" "cat /root/n")" = 7 ]'
check "mid-snapshot: invariants hold" 'invariants'
rm_all "$SN"

echo "-- mid-suspend"
SU=$(mkowner su 1024)
on "$SU" 'dd if=/dev/urandom of=/dev/shm/fill bs=1M count=500 2>/dev/null; sync' || true
su_stopping() { [ "$(mstate "$SU")" = stopping ]; }
caught=0
for attempt in 1 2 3; do
  if kill_when su_stopping briqyard machine stop --suspend "$SU"; then caught=1; break; fi
  restore_running "$SU"
done
check "a suspend was killed while the machine was stopping (attempt $attempt)" '[ "$caught" = 1 ]'
settle || true
st=$(mstate "$SU"); echo "   the machine is: $st"
check "mid-suspend: stopped or running, never stuck in stopping" 'case "$st" in running|stopped) true;; *) false;; esac'
[ "$st" = stopped ] && restore_running "$SU"
check "mid-suspend: it starts, its counter whole" 'recovered "$SU"'
briqyard machine stop --suspend "$SU" >/dev/null; briqyard machine start "$SU" >/dev/null; briqyard machine wait --for running "$SU" >/dev/null
check "mid-suspend: a suspend and resume again works, counter whole" '[ "$(ctr "$SU")" = "7 7 " ]'
check "mid-suspend: invariants hold" 'invariants'
rm_all "$SU" "$SRC"

echo "-- a VMM killed"
K1=$(mkowner vk1 256); K2=$(mkowner vk2 256)
k1pid=$(fc_pid "$K1"); k2pid=$(fc_pid "$K2"); dpid=$(daemon_pid)
sudo kill -9 "$k1pid"
for i in $(seq 1 60); do [ "$(mstate "$K1")" != running ] && break; sleep 1; done
check "VMM killed: only that machine stops (stopped, exit 255, not reported as a memory kill)" '[ "$(mstate "$K1")" = stopped ] && [ "$(briqyard machine get "$K1" | jq -r .exit.code)" = 255 ] && [ "$(briqyard machine get "$K1" | jq -r ".exit.vmm_oom_killed // false")" = false ]'
check "VMM killed: the other machine, its VMM and the daemon are untouched" '[ "$(fc_pid "$K2")" = "$k2pid" ] && [ "$(daemon_pid)" = "$dpid" ] && [ "$(ctr "$K2")" = "7 7 " ]'
# The invariants allow the one open defect, the empty cgroup leaf of a machine whose VMM was lost, and print it.
check "VMM killed: nothing leaked while it is stopped (the open leaf defect is printed by the invariants)" 'invariants && { grep -h "KNOWN DEFECT\|FIXED" "$LOGS/inv.out" | sed "s/^/   /" || true; }'
briqyard machine start "$K1" >/dev/null; briqyard machine wait --for running "$K1" >/dev/null
check "VMM killed: it starts again with its disks whole" '[ "$(ctr "$K1")" = "7 7 " ]'

echo "-- the fleet killed"
fp=$(fleet_pid)
sudo kill -9 "$fp"
for i in $(seq 1 50); do [ "$(fleet_pid)" != "$fp" ] && break; sleep 0.1; done
check "fleet killed: the machines run on without it" '[ "$(mstate "$K1")" = running ] && [ "$(ctr "$K2")" = "7 7 " ]'
sudo systemctl start briqyard-fleet
check "fleet killed: it comes back, its host ready" 'for i in $(seq 1 90); do curl -fsS -m 3 $FLEET_URL/v1/hosts 2>/dev/null | jq -e "length == 1 and all(.state == \"ready\")" >/dev/null && exit 0; sleep 1; done; exit 1'
check "fleet killed: it lists the machines again" '[ "$(fleet machine ls --namespace "$T-c" | awk "NR>1" | wc -l)" = 2 ]'
check "fleet killed: and creates through it" 'F=$(fleet machine run --sleep never --image $ALPINE --name viafleet --namespace "$T-c" --memory 128 -- sleep 600 | jq -r .id) && [ "$(on "$F" hostname)" = viafleet ] && briqyard machine rm "$F" >/dev/null'

echo "-- power cut: the daemon and every VMM at once"
CUT=($(pgrep -x firecracker) "$(daemon_pid)")
sudo kill -9 "${CUT[@]}"
for i in $(seq 1 50); do [ -z "$(pgrep -x firecracker || true)" ] && break; sleep 0.1; done
sudo systemctl start briqyardd
wait_api
check "power cut: the host settles, nothing stuck, no silent error" 'settle && errors_reported'
check "power cut: no machine claims to run without a VMM" 'for id in $K1 $K2; do [ "$(mstate "$id")" != running ] || [ -n "$(fc_pid "$id")" ] || exit 1; done'
restore_running "$K1"; restore_running "$K2"
check "power cut: both machines run again with their counters whole" '[ "$(ctr "$K1")" = "7 7 " ] && [ "$(ctr "$K2")" = "7 7 " ]'
check "power cut: invariants hold" 'invariants'
rm_all "$K1" "$K2"

echo "-- a full pool"
W=$(mkowner full 256)
avail=$(sudo zfs get -Hp -o value available "$POOL")
FILLED="$POOL/qual-fill"
sudo zfs create -o reservation=$(( avail - 64 * 1048576 )) "$FILLED"
left=$(sudo zfs get -Hp -o value available "$POOL")
check "the pool is full ($left bytes left)" '[ "$left" -lt $(( 100 * 1048576 )) ]'
dpid=$(daemon_pid)
set +e; out=$(briqyard machine run --sleep never --image $NODE --name full-new --namespace "$T-c" --memory 256 -- sleep 600 2>&1); rc=$?; set -e
echo "   refused with: $(echo "$out" | head -c 300)"
check "full pool: a create fails and says so, the client does not hang" '[ "$rc" != 0 ] && [ -n "$out" ]'
settle || true
st=$(settled_state "$T-c" full-new)
check "full pool: the failed create is in error with its reason (or never recorded), not running" 'case "$st" in error) errors_reported;; none) true;; *) false;; esac'
check "full pool: the daemon lives, the running machine too" '[ "$(daemon_pid)" = "$dpid" ] && [ "$(mstate "$W")" = running ] && briqyard status >/dev/null && [ "$(on "$W" hostname)" = full ]'
check "full pool: disk_pressure is reported" 'wait_cond disk_pressure'
check "full pool: the fleet places nothing new on the host (503 capacity)" 'fleet_refuses "no host has room" full-fleet "$T-full-fleet"'
sudo zfs destroy -f "$FILLED"; FILLED=
destroy_named "$T-c" full-new; settle || true
check "pool freed: the fleet places a machine again" 'fleet_places full-fleet2 "$T-full-fleet"'
check "pool freed: a create works again" 'N=$(run --image $ALPINE --name after-full --namespace "$T-c" --memory 256 -- sleep 600) && [ "$(on "$N" hostname)" = after-full ] && briqyard machine rm "$N" >/dev/null'
check "pool freed: the machine kept its counter, nothing leaked" '[ "$(ctr "$W")" = "7 7 " ] && invariants'
rm_all "$W"

echo "-- chaos.py: owners and racers, four minutes"
check "no integrity error, no unexpected answer" 'python3 -u "$HERE/chaos.py" --minutes 4 --namespaces 3 --per-namespace 2 --racers 3 --backups --prefix "$T-ch" >"$LOGS/chaos.out" 2>&1 || { tail -30 "$LOGS/chaos.out"; exit 1; }'
tail -8 "$LOGS/chaos.out" | sed 's/^/   /'
check "after it: invariants hold" 'settle && invariants'

suite_summary

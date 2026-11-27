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
  # The gateway-policy section's diagnostics, when the run ended inside it.
  [ -z "${GWP_DIAG_PENDING:-}" ] || gwp_diag_end
  for p in "${BGPIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
  [ -z "$FILLED" ] || sudo zfs destroy -f "$FILLED" 2>/dev/null
  # A run that ended while a service was down starts it again.
  sudo systemctl start briqyardd briqyard-fleet
  for i in $(seq 1 60); do briqyard status >/dev/null 2>&1 && break; sleep 1; done
  for t in $(briqyard namespace ls 2>/dev/null | jq -r --arg t "$T" '.[].id | select(. == $t or startswith($t + "-"))'); do
    for id in $(briqyard machine ls --namespace "$t" 2>/dev/null | awk 'NR>1{print $1}'); do briqyard machine rm "$id" >/dev/null 2>&1; done
    for i in $(seq 1 10); do
      # A gateway is not removed with its machines (ADR 0143): the namespace's, explicitly.
      briqyard namespace gateway rm "$t" >/dev/null 2>&1
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
RECOVERY_SINCE=$(date +%s)
wait_api() {
  if ! python3 "$HERE/qualification-readiness.py" "$LOGS" "$RECOVERY_SINCE"; then
    if [ -n "${WAIT_API_RETURN:-}" ]; then
      bad "daemon recovery readiness: observation and protected machine list"
      return 1
    fi
    bad "daemon recovery readiness: observation and protected machine list"
    exit 1
  fi
}
# SIGKILL to the daemon alone (a systemctl kill would take the machines with it), then a start
# now rather than after RestartSec.
crash_daemon() {
  local pid i; pid=$(daemon_pid)
  RECOVERY_SINCE=$(date +%s)
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
echo "== gateway policy: a bound machine opens HTTPS only to its listed hosts, the gate opens only on a readback (ADR 0143)"
# Raw outputs are classified, and every check judged, by hack/gateway-policy-qual.py (its tests:
# hack/test_gateway_policy_qual.py); an inconclusive check counts as failed here. The receipt is
# $LOGS/gateway-policy-receipt.json. The fake API's files (the gateways' CA certificates, its
# request log, the set outputs) stay in a private directory outside $LOGS, which CI uploads.
# The credential gateway as main published it from e5203d2e (credential-gateway #5).
GWP_IMAGE=ghcr.io/briq-cloud/credential-gateway@sha256:a9c2a13b03d256c50a0eb166d771cceb797f2f4078f960e33e736bbab793b352
GWP_SOURCE=e5203d2e4522243355a3280e47343ee8c631222a
GWQ=$HERE/gateway-policy-qual.py
GWP=$(mktemp -d /tmp/qual-gwp-XXXXXX); chmod 700 "$GWP"
GWP_OBS=$GWP/observations.jsonl; : >"$GWP_OBS"
# The section's diagnostics, uploaded: every row from the helper's writer (gq diag), never text.
GWP_DIAG=$LOGS/gateway-policy-diag.jsonl; : >"$GWP_DIAG"
GWP_NS=$T-gp; GWP_NSM=$T-gpm; GWP_NSL=$T-gpl
# Public test names only. The allowed host serves HTTPS; the unlisted one too, so that its
# denial is the gateway's and not the target's.
GWP_ALLOWED=example.com; GWP_UNLISTED=one.one.one.one; GWP_LITERAL=1.1.1.1; GWP_SSH=github.com
# Synthetic values: the fake API accepts this token and nothing else.
GWP_TOKEN=qual-synthetic-gateway-token; GWP_TEAM=qual-team
# The daemon's refusal of a gateway whose loaded policy is not its binding (gateway_policy.rs).
GWP_MISMATCH_REFUSAL="gateway loaded policy not verified: the loaded policy is not the gateway's binding"
gwp_policy() { printf '{"policy_format":1,"namespace":"%s","team_id":"%s","briq_id":"qual-briq","hosts":["%s"]}' "$1" "$GWP_TEAM" "$2"; }
gq() { python3 -I "$GWQ" "$@"; }
now_ms() { date +%s%3N; }
obs() { local c=$1 k=$2 cls=$3 role=$4 b=$5; shift 5; gq obs --file "$GWP_OBS" --check "$c" --criterion "$k" --cls "$cls" --role "$role" --batch "$b" "$@"; }
mark() { obs "mark.$1" "$([ "$1" = boot ] && echo C2 || echo C5)" mark sample "$1" --set "value=$2" --set "t0=${3:-$(now_ms)}"; }
bool() { if eval "$1"; then echo true; else echo false; fi; }
# The limits the owner accepted for this runner (BRIQ-768 review round 3): on these names, and
# only these, a limit is printed and not counted as a failure, here and in the receipt.
GWP_ACCEPTED_LIMITS="c5.isolation_unconfirmed c6.warm_claim c6.template c5.daemon_kill.no_traffic_while_closed c5.daemon_kill.direct_while_closed"
GWP_ACCEPT=(); for _n in $GWP_ACCEPTED_LIMITS; do GWP_ACCEPT+=(--accept-limit "$_n"); done
judge() { gq judge --file "$GWP_OBS" --check "$1" "${GWP_ACCEPT[@]}"; }
judged() { local c; for c in "$@"; do check "gateway policy: $c" "judge $c"; done; }
# curl from a machine: "http_code http_connect time_total time_connect rc"; an exec that fails is rc -1.
probe() { on "$1" "curl -sS -o /dev/null --connect-timeout 5 --max-time 15 -w '%{http_code} %{http_connect} %{time_total} %{time_connect}' $2 2>/dev/null; echo \" \$?\"" 2>/dev/null | tail -1 || echo "000 000 0 0 -1"; }
# A DNS query from a machine to SERVER, classified: answer, timeout or other.
# dnsq MACHINE SERVER [NAME]: NAME (the allowed host by default) to SERVER, classified.
dnsq() { { on "$1" "timeout 20 nslookup ${3:-$GWP_ALLOWED} $2 2>&1; echo rc=\$?" 2>/dev/null || echo rc=-1; } | gq classify dns; }
# ARP and ICMP from a machine to IP, at once, classified: ARP-ICMP, each reached, blocked or unknown.
l2probe() { on "$1" "d=\$(ls /sys/class/net | grep -v '^lo\$' | head -1); arping -c 2 -w 3 -I \$d $2 2>&1 & ping -c 2 -W 2 $2 2>&1 & wait" 2>/dev/null | gq classify l2; }
gate_read() { local s; s=$(sudo nft list set bridge briqyard gateway_gate 2>/dev/null) || { echo null; return; }; grep -qwF "$1" <<<"$s" && echo true || echo false; }
gw_view() { briqyard namespace get "$1" 2>/dev/null | jq -r ".gateway.$2 // empty"; }
# Every process naming the machine, as pid:start_ticks:boot_id (the daemon's incarnation fields).
incarnations() {
  local p st boot; boot=$(cat /proc/sys/kernel/random/boot_id)
  for p in $(pgrep -f -- "$(id_dash "$1")" || true); do
    st=$(sudo sed 's/.*) //' "/proc/$p/stat" 2>/dev/null | awk '{print $20}') && [ -n "$st" ] && echo "$p:$st:$boot"
  done
}
challenge() { python3 -I -c 'import secrets; print(secrets.token_hex(32))'; }
readback() { briqyard namespace gateway policy-status "$1" --challenge "$2"; }
# readback_refusal OUTPUT RC: true when the daemon refused the readback for the policy or the
# readback itself, false when it answered, null for a usage error, a timeout or a daemon down.
readback_refusal() { case "$(printf '%s' "$1" | gq classify cause --rc "$2" --ignore "$T gp-")" in policy) echo true;; ok) echo false;; *) echo null;; esac; }
inc_of() { jq -r '.native_incarnation | "\(.pid):\(.start_ticks):\(.host_boot_id)"' <<<"$1" 2>/dev/null; }
live_inc() { local p=${1%%:*} rest=${1#*:}; local st=${rest%%:*}; [ -n "$1" ] && [ "$(sudo sed 's/.*) //' "/proc/$p/stat" 2>/dev/null | awk '{print $20}')" = "$st" ] && [ "${rest#*:}" = "$(cat /proc/sys/kernel/random/boot_id)" ]; }
api_mark() { jq -r --arg ev "$1" --arg peer "$2" 'select(.event == $ev and .method == "PUT" and .peer == $peer) | .t' "$GWP/api.jsonl" 2>/dev/null | tail -1; }
api_count() { jq -r --arg ev "$1" --arg peer "$2" 'select(.event == $ev and .method == "PUT" and .peer == $peer) | .t' "$GWP/api.jsonl" 2>/dev/null | wc -l | tr -d ' '; }
api_config_after() { jq -r --arg p "$1" --argjson t "$2" 'select(.event == "done" and .method == "GET" and .peer == $p and .t > $t) | .t' "$GWP/api.jsonl" 2>/dev/null | wc -l | tr -d ' '; }
wait_for() { local i n=$1; shift; for i in $(seq 1 "$n"); do eval "$1" && return 0; sleep "${2:-1}"; done; return 1; }
# gdiag KIND --set K=V...: one diag row. Its notices are dropped: a step's captured output is
# classified (refused, readback_refusal), and the row lists what it refused anyway.
gdiag() { local k=$1; shift; gq diag --file "$GWP_DIAG" --kind "$k" "$@" 2>/dev/null; }
# wait_set NAME N PID COND [STOP] [SLEEP]: as wait_for, and once PID (a background set; none
# when empty) has exited, COND is tried once more and the wait ends if STOP holds (by default
# at once). Its iterations and its end (met, set_exited, exhausted) go to the diag.
wait_set() {
  local _wi=0 _wend=exhausted _wrc=1
  while [ "$_wi" -lt "$2" ]; do
    _wi=$((_wi + 1))
    if eval "$4"; then _wend=met; _wrc=0; break; fi
    if [ -n "$3" ] && ! kill -0 "$3" 2>/dev/null; then
      if eval "$4"; then _wend=met; _wrc=0; break; fi
      if eval "${5:-true}"; then _wend=set_exited; break; fi
    fi
    sleep "${6:-1}"
  done
  gdiag loop --set "name=$1" --set "iterations=$_wi" --set "end=$_wend"
  return "$_wrc"
}
# gwp_view STEP NSROLE: the namespace's gateway as the daemon shows it after STEP: its state,
# its machine's error_reason, its error as a class (never its text: it carries console lines),
# its address, its gate and its incarnations.
gwp_view() {
  local ns v ip mid er a=()
  case $2 in main) ns=$GWP_NS;; legacy) ns=$GWP_NSL;; mismatch) ns=$GWP_NSM;; *) return 0;; esac
  v=$(briqyard namespace get "$ns" 2>/dev/null)
  ip=$(jq -r '.gateway.ip // empty' <<<"$v" 2>/dev/null); mid=$(jq -r '.gateway.machine_id // empty' <<<"$v" 2>/dev/null)
  if [ -n "$mid" ]; then
    echo "$2 gateway $mid" >>"$GWP/gw-ids"
    er=$(briqyard machine get "$mid" 2>/dev/null | jq -r '.error_reason // empty' 2>/dev/null)
    a+=(--set "incarnations=$(incarnations "$mid" | wc -l | tr -d ' ')")
  fi
  [ -z "$ip" ] || a+=(--set "ip=$ip" --set "gate=$(gate_read "$ip")")
  gdiag gateway --set "step=$1" --set "ns=$2" --set "state=$(jq -r '.gateway.state // "none"' <<<"$v" 2>/dev/null)" \
    --set "error_reason=${er:-none}" --set "error=$(jq -r '.gateway.error // empty' <<<"$v" 2>/dev/null | gq classify gwerror)" "${a[@]}"
}
# gstep NAME NSROLE CMD...: CMD as it is, its stdout and stderr passed on and its rc returned;
# its rc, its times from the section's start and its cause class go to the diag, then the
# namespace's gateway as it stands.
gstep() {
  local _sn=$1 _sr=$2 _st0 _src _se; shift 2
  _se=$(mktemp "$GWP/step-XXXXXX")
  _st0=$(now_ms); "$@" 2>"$_se"; _src=$?
  gdiag step --set "name=$_sn" --set "ns=$_sr" --set "rc=$_src" --set "t0=$((_st0 - GWP_T0))" --set "t1=$(( $(now_ms) - GWP_T0 ))" \
    --set "cause=$(gq classify cause --rc "$_src" --ignore "$T gp-" <"$_se" 2>/dev/null)"
  cat "$_se" >&2; rm -f "$_se"
  gwp_view "$_sn" "$_sr" 2>/dev/null
  return "$_src"
}
# gwp_diag_end: the fake API's log as counts, its health and the size of its output, and each
# machine's events by reason. Once, at the section's end or at the run's exit.
gwp_diag_end() {
  GWP_DIAG_PENDING=
  local p=() r k m ns ip n
  while read -r r ip; do
    case $r in main) p+=(--peer "gateway=$ip");; legacy|mismatch) p+=(--peer "$r=$ip");; esac
  done < <(jq -r 'select(.kind == "gateway" and .ip != null) | "\(.ns) \(.ip)"' "$GWP_DIAG" 2>/dev/null | sort -u)
  for ip in $GWIP; do p+=(--peer "gateway=$ip"); done
  for ip in $LGWIP; do p+=(--peer "legacy=$ip"); done
  for ip in $MGWIP; do p+=(--peer "mismatch=$ip"); done
  for m in $U $UL $UM; do ip=$(briqyard machine get "$m" 2>/dev/null | jq -r '.ip // empty'); [ -z "$ip" ] || p+=(--peer "open=$ip"); done
  for m in $BC $LC; do ip=$(briqyard machine get "$m" 2>/dev/null | jq -r '.ip // empty'); [ -z "$ip" ] || p+=(--peer "bound=$ip"); done
  gq diag-api --file "$GWP_DIAG" --dir "$GWP" --since "${GWP_T0:-0}" "${p[@]}"
  curl -fsS -m 2 http://127.0.0.1:9443/healthz >/dev/null 2>&1; r=$?
  gdiag end --set "healthz_rc=$r" --set "api_out_bytes=$([ -f "$GWP/api.out" ] && wc -c <"$GWP/api.out" | tr -d ' ')"
  { sort -u "$GWP/gw-ids" 2>/dev/null; echo "main open $U"; echo "main bound $BC"; echo "legacy open $UL"; echo "legacy bound $LC"; echo "mismatch open $UM"; } |
  while read -r r k m; do
    [ -n "$m" ] || continue
    case $r in main) ns=$GWP_NS;; legacy) ns=$GWP_NSL;; mismatch) ns=$GWP_NSM;; *) continue;; esac
    api "/v1/events?namespace=$ns&machine=$m" 2>/dev/null |
      jq -r '(if type == "array" then . else (.events // []) end) | group_by(.reason)[] | "\(.[0].reason) \(map(.count // 1) | add)"' 2>/dev/null |
      while read -r ip n; do gdiag events --set "ns=$r" --set "machine=$k" --set "reason=$ip" --set "count=$n"; done
  done
  return 0
}
# gwargs NAMESPACE POLICY_JSON|"" [DIGEST]: the gateway as briq would put it, against the
# fake API at the host's uplink address (GWP_API), as the argv GWA (an argv, so that timeout
# can run it).
gwargs() {
  local ns=$1 pol=$2 dig=${3:-}
  GWA=(briqyard namespace gateway set "$ns" --image "$GWP_IMAGE" --port 3128)
  [ -z "$dig" ] || GWA+=(--policy-digest "$dig")
  GWA+=(-e "BRIQ_API_URL=$GWP_API" -e "BRIQ_GATEWAY_TOKEN=$GWP_TOKEN" -e "BRIQ_TEAM=$GWP_TEAM"
        -e GATEWAY_STATE_DIR=/var/lib/qual-gateway -e GATEWAY_REFRESH_MS=1000)
  [ -z "$pol" ] || GWA+=(-e "BRIQ_EGRESS_POLICY=$pol")
  GWA+=(--start)
}
# The fake API's config: every consumer by its current address, so that no request waits out the
# gateway's ten seconds for an unknown address. Synthetic ids, no secret.
gwp_config() {
  local m ip e=
  for m in $BC $LC; do
    ip=$(briqyard machine get "$m" 2>/dev/null | jq -r '.ip // empty')
    [ -n "$ip" ] && e="${e:+$e,}{\"id\":\"qual-$(id_dash "$m" | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9-' | cut -c1-40)\",\"host\":\"$ip\"}"
  done
  printf '{"briqs":[%s]}\n' "$e" >"$GWP/config.json.tmp" && mv "$GWP/config.json.tmp" "$GWP/config.json"
}
# What a refused operation must leave as it was: machines, namespaces, events, volumes.
listing() {
  api /v1/machines | jq -S '[.[] | {id, name, namespace, state, egress}] | sort_by(.id)'
  briqyard namespace ls | jq -S '[.[].id] | sort'
  local m; for m in $BC $GWID; do briqyard events --machine "$m" 2>/dev/null | grep -vi cursor; done
  sudo zfs list -H -o name -r "$POOL"
}
# refused CHECK CRITERION LIMIT CMD...: refused before effects, the listing unchanged and readable.
# The refusal must name the policy, a binding or the gateway; a refusal for another cause is
# inconclusive, or, with LIMIT=limit, the limit refused-for-other-cause (the cause is recorded).
refused() {
  local c=$1 k=$2 lim=$3; shift 3
  local before after out rc cause
  before=$(listing 2>/dev/null)
  out=$(gstep "${c//./_}" main timeout 150 "$@" 2>&1); rc=$?
  sleep 2; after=$(listing 2>/dev/null)
  cause=$(printf '%s' "$out" | gq classify cause --rc "$rc" --ignore "$T $BC $GWID $U gp-")
  echo "   $c: rc $rc, cause $cause"
  case "$cause" in
    ok) obs "$c" "$k" assert subject "" --set value=false ;;
    policy) obs "$c" "$k" assert subject "" --set value=true --set "rc=$rc" ;;
    other) if [ "$lim" = limit ]; then obs "$c" "$k" limit subject "" --set value=refused-for-other-cause; else obs "$c" "$k" observed subject "" --set value=false; fi ;;
    *) obs "$c" "$k" observed subject "" --set value=false --set "rc=$rc" ;;
  esac
  obs "$c" "$k" observed subject "" --set "value=$(bool '[ -n "$BC" ] && grep -qF "$BC" <<<"$before" && grep -qF "\"$GWP_NS\"" <<<"$before"')"
  obs "$c" "$k" assert subject "" --set "value=$([ "$before" = "$after" ] && echo true || echo false)"
  obs "$c" "$k" measure control "" --set "value=$cause"
}
gate_sampler() { # PHASE: the gate set every 0.2 s, the gateway's address read again each time
  local ip=$GWIP n
  while :; do
    n=$(gw_view "$GWP_NS" ip); [ -n "$n" ] && ip=$n
    obs "gate.$1" "$([ "$1" = boot ] && echo C2 || echo C5)" gate sample "$1" --set "value=$(gate_read "$ip")" --set "t0=$(now_ms)"
    sleep 0.2
  done
}
# gate_burst FILE: the gate set about every 20 ms, as "t0 value" lines; the daemon's restart closes
# the gate for a fraction of a second, shorter than gate_sampler's period.
gate_burst() { while :; do echo "$(now_ms) $(gate_read "$GWIP")" >>"$1"; sleep 0.02; done; }
# gate_record PHASE FILE: each complete line gate_burst wrote, as a gate sample of PHASE.
gate_record() { local t v; while read -r t v; do [ -n "$v" ] && obs "gate.$1" C5 gate sample "$1" --set "value=$v" --set "t0=$t"; done <"$2"; }
admit_sampler() { # PHASE NAME NAMESPACE: a consumer's record (none when absent, unknown when unread)
  local st
  while :; do
    st=$(api /v1/machines 2>/dev/null | jq -r --arg n "$2" --arg t "$3" '[.[] | select(.name == $n and .namespace == $t)][0].state // "none"' 2>/dev/null)
    obs "admit.$1" C2 admit sample "$1" --set "value=${st:-unknown}" --set "t0=$(now_ms)"
    sleep 0.3
  done
}
# probe_loop PHASE: allowed and a direct denial every second from the bound machine, each
# probe with its own host times; their kinds are decided by the helper.
probe_loop() {
  local t0 t1 r
  while :; do
    t0=$(now_ms); r=$(probe "$BC" "$PX --max-time 3 https://$GWP_ALLOWED/"); t1=$(now_ms)
    obs "loop.$1" C5 loop_allowed sample "$1" --curl "$r" --set "t0=$t0" --set "t1=$t1"
    t0=$(now_ms); r=$(probe "$BC" "--noproxy '*' --connect-timeout 2 --max-time 3 --resolve $GWP_ALLOWED:443:$ALLOWED_IP https://$GWP_ALLOWED/"); t1=$(now_ms)
    obs "loop.$1" C5 loop_direct sample "$1" --curl "$r" --set "t0=$t0" --set "t1=$t1"
    sleep 1
  done
}
loop_alive_since() { # PHASE SINCE: six of each good kind since SINCE
  [ "$(gq count --file "$GWP_OBS" --phase "$1" --kind allowed_ok --since "$2")" -ge 6 ] &&
    [ "$(gq count --file "$GWP_OBS" --phase "$1" --kind direct_denied --since "$2")" -ge 6 ]
}
stop_bg() { local p; for p in "$@"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done; for p in "$@"; do [ -n "$p" ] && wait "$p" 2>/dev/null; done; return 0; }
bracket() { obs "bracket.$1" C3 allowed "$2" "$1" --curl "$(probe "$BC" "$PX https://$GWP_ALLOWED/")"; }
# c3_batch BATCH CRITERION PREFIX [full]: the subset C4 repeats, or every C3 probe.
c3_batch() {
  local b=$1 k=$2 p=$3 lit=literal dir=direct port ok=true out
  [ "$p" = c3 ] && lit=ip_literal_proxied dir=direct_allowed_ip
  bracket "$b" bracket_before
  obs "$p.allowed" "$k" allowed subject "$b" --curl "$(probe "$BC" "$PX https://$GWP_ALLOWED/")"
  obs "$p.unlisted" "$k" proxied_denial subject "$b" --curl "$(probe "$BC" "$PX https://$GWP_UNLISTED/")"
  obs "$p.unlisted" "$k" reach control "$b" --curl "$(probe "$U" "https://$GWP_UNLISTED/")"
  obs "$p.$lit" "$k" proxied_denial subject "$b" --curl "$(probe "$BC" "$PX https://$GWP_LITERAL/")"
  obs "$p.$lit" "$k" reach control "$b" --curl "$(probe "$U" "https://$GWP_LITERAL/")"
  obs "$p.$dir" "$k" direct_denial subject "$b" --curl "$(probe "$BC" "--noproxy '*' --resolve $GWP_ALLOWED:443:$ALLOWED_IP https://$GWP_ALLOWED/")"
  obs "$p.$dir" "$k" reach control "$b" --curl "$(probe "$U" "--noproxy '*' --resolve $GWP_ALLOWED:443:$ALLOWED_IP https://$GWP_ALLOWED/")"
  if [ "${4:-}" = full ]; then
    obs c3.other_port_proxied C3 proxied_denial subject "$b" --curl "$(probe "$BC" "$PX --proxytunnel http://$GWP_ALLOWED:80/")"
    obs c3.other_port_proxied C3 reach control "$b" --curl "$(probe "$U" "http://$GWP_ALLOWED:80/")"
    obs c3.plain_http_proxied C3 plain_denial subject "$b" --curl "$(probe "$BC" "--proxy http://$GWIP:3128 http://$GWP_ALLOWED/")"
    obs c3.plain_http_proxied C3 reach_not403 control "$b" --curl "$(probe "$U" "http://$GWP_ALLOWED/")"
    obs c3.direct_tcp80 C3 direct_denial subject "$b" --curl "$(probe "$BC" "--noproxy '*' http://$GWP_LITERAL/")"
    obs c3.direct_tcp80 C3 reach control "$b" --curl "$(probe "$U" "--noproxy '*' http://$GWP_LITERAL/")"
    obs c3.direct_tcp22 C3 direct_denial subject "$b" --curl "$(probe "$BC" "--noproxy '*' -m 6 telnet://$SSH_IP:22 </dev/null")"
    obs c3.direct_tcp22 C3 reach control "$b" --curl "$(probe "$U" "--noproxy '*' -m 6 telnet://$SSH_IP:22 </dev/null")"
    obs c3.direct_udp_dns C3 udp_denial subject "$b" --set "value=$(dnsq "$BC" "$GWP_LITERAL")"
    obs c3.direct_udp_dns C3 dns_answer control "$b" --set "value=$(dnsq "$U" "$GWP_LITERAL")"
    # A via source gets internal answers only, NXDOMAIN for any outside name (ADR 0015):
    # its own resolver is proven on a name of its namespace, another namespace's on one of that
    # namespace and on an outside name, neither answered.
    obs c3.dns_other_namespace C3 udp_denial subject "$b" --set "value=$(dnsq "$BC" "$brl" gpl-open.internal)"
    obs c3.dns_other_namespace C3 udp_denial subject "$b" --set "value=$(dnsq "$BC" "$brl")"
    obs c3.dns_other_namespace C3 dns_answer control "$b" --set "value=$(dnsq "$BC" "$br" gp-open.internal)"
    obs c3.dns_own_resolver C3 observed subject "$b" --set "value=$(bool '[ -n "$uip" ] && on "$BC" "nslookup gp-open.internal $br 2>&1" | grep -qwF "$uip"')"
    out=$(get "$BC" "http://$br:9999/s")
    obs c3.iso_host_bridge C3 assert subject "$b" --set "value=$(bool 'grep -qF "timed out" <<<"$out" && ! grep -qF host-secret <<<"$out"')"
    out=$(get "$BC" "http://$brl:9999/s")
    obs c3.iso_other_bridge C3 assert subject "$b" --set "value=$(bool 'grep -qF "timed out" <<<"$out" && ! grep -qF host-secret <<<"$out"')"
    for port in 7420 8080 7430; do out=$(get "$BC" "http://$br:$port/"); grep -qF rc=0 <<<"$out" && ok=false; grep -qF "timed out" <<<"$out" || ok=false; done
    obs c3.iso_daemon_ports C3 assert subject "$b" --set "value=$ok"
    # Measurements for Q7, not verdicts: the host's host_ports, and what the resolver gives.
    obs q7.host_ports_9443 Q7 measure subject "$b" --curl "$(probe "$BC" "--noproxy '*' http://$br:9443/")"
    obs q7.getent_allowed Q7 measure subject "$b" --set "rc=$(on "$BC" "getent hosts $GWP_ALLOWED >/dev/null; echo \$?" 2>/dev/null || echo -1)"
  fi
  bracket "$b" bracket_after
}
c4_after() { # OP OK: the binding and the C3 subset after a lifecycle step that did (OK) or did not run
  [ "$2" = true ] || obs "c4.$1.binding" C4 observed subject "" --set value=false
  gwp_config
  obs "c4.$1.binding" C4 assert subject "" --set "value=$(bool '[ "$(briqyard machine get "$BC" | jq -cS .egress.gateway_policy)" = "$BIND0" ] && [ -n "$BIND0" ] && [ "$BIND0" != null ]')"
  c3_batch "c4_$1" C4 "c4.$1"
  local k; for k in binding allowed unlisted literal direct; do check "gateway policy: c4.$1.$k" "judge c4.$1.$k"; done
}
lc_step() { "$@" >/dev/null 2>&1 && briqyard machine wait --for running "$BC" >/dev/null 2>&1 && echo true || echo false; }

gateway_policy() {
  local t_start; t_start=$(date +%s)
  U=; UL=; UM=; BC=; LC=; GWIP=; GWID=; MGWIP=; LGWIP=; ALLOWED_IP=; SSH_IP=; BIND0=; br=; brl=; PX=
  GWP_T0=$(now_ms); GWP_DIAG_PENDING=1; GWP_UPLINK=failed; : >"$GWP/gw-ids"
  # The fake control API on host_ports (9443), the only host port a guest reaches, and only at
  # an address outside network.range (the input chain's accept, ADR 0028): the host's uplink
  # address (hostip, as at the control check above), never a namespace's .1, where it is dropped.
  GWP_API=http://$hostip:9443
  python3 -I "$GWQ" serve --port 9443 --hold 8 --dir "$GWP" --token "$GWP_TOKEN" >"$GWP/api.out" 2>&1 &
  BGPIDS+=("$!")
  : >"$GWP/api.jsonl"; gwp_config
  obs c2.fake_api_listening C2 observed subject "" --set "value=$(bool 'wait_for 30 "curl -fsS -m 2 http://127.0.0.1:9443/healthz >/dev/null 2>&1" 0.5')"
  judged c2.fake_api_listening
  boot_timeout=$(sudo sed -n 's/^boot_timeout_sec: *//p' /etc/briqyard/config.yaml); boot_timeout=${boot_timeout:-120}
  echo "   boot_timeout_sec: $boot_timeout"

  # -- C2 and C1: the boot of a policy gateway, its gate held closed by the CA reply
  # An open machine of the namespace, made before the gateway: the packet probe and the
  # unrestricted control of every denial. Its image has curl and busybox (arping, nslookup).
  U=$(gstep run_open main run --image $NGINX --name gp-open --namespace "$GWP_NS" --memory 256 -- sleep 7200 2>/dev/null)
  uip=$(briqyard machine get "$U" 2>/dev/null | jq -r '.ip // empty'); br=${uip%.*}.1
  # The fake API from a guest, before any gateway boots: at GWP_API it answers 401 to a request
  # without the token; at the namespace's .1 it times out. No gateway boots without the first.
  local up='' bp='' upc='' uprc='' bpc='' bprc='' nftin rule range
  if [ -n "$uip" ] && [ -n "$hostip" ]; then
    up=$(probe "$U" "--noproxy '*' $GWP_API/"); bp=$(probe "$U" "--noproxy '*' http://$br:9443/")
    read -r upc _ _ _ uprc <<<"$up"; read -r bpc _ _ _ bprc <<<"$bp"
  fi
  nftin=$(sudo nft list chain inet briqyard input 2>/dev/null)
  rule=$(grep -E 'ip daddr != [0-9./]+ tcp dport .*9443.* accept' <<<"$nftin" | head -1)
  range=$(sed -nE 's/.*ip daddr != ([0-9./]+) .*/\1/p' <<<"$rule")
  gdiag reach --set "uplink_code=$upc" --set "uplink_rc=$uprc" --set "bridge_code=$bpc" --set "bridge_rc=$bprc" \
    --set "accept_rule=$(if [ -z "$nftin" ]; then echo unknown; elif [ -n "$rule" ]; then echo present; else echo absent; fi)" \
    --set "hostip_in_range=$(if [ -n "$range" ] && [ -n "$hostip" ]; then gq inrange "$hostip" "$range"; else echo null; fi)"
  if [ "$upc" = 401 ] && [ "$uprc" = 0 ]; then GWP_UPLINK=ok; fi
  echo "   fake API from a guest: uplink ${upc:-none} rc ${uprc:-none}, bridge ${bpc:-none} rc ${bprc:-none}"
  obs c2.api_reachable_preflight C2 assert subject "" --set "value=$(if [ -z "$up" ]; then echo null; elif [ "$GWP_UPLINK" = ok ] && [ "$bpc" = 000 ] && [ "$bprc" = 28 ]; then echo true; else echo false; fi)"
  judged c2.api_reachable_preflight
  POL=$(gwp_policy "$GWP_NS" "$GWP_ALLOWED"); DIG=$(gq digest "$POL")
  echo "   policy digest $DIG"
  local setpid='' bcpid='' gsp='' asp='' held='' l2='' t0 t1 c1='' rb='' rbinc=''
  if [ "$GWP_UPLINK" = ok ]; then
    gwargs "$GWP_NS" "$POL" "$DIG"; gstep set_boot main "${GWA[@]}" >"$GWP/set.out" 2>&1 &
    setpid=$!; BGPIDS+=("$setpid")
    if wait_set boot_recv 900 "$setpid" '[ -n "$(gw_view "$GWP_NS" ip)" ] && [ -n "$(api_mark recv "$(gw_view "$GWP_NS" ip)")" ]' true 0.2; then
      GWIP=$(gw_view "$GWP_NS" ip); GWID=$(gw_view "$GWP_NS" machine_id)
      mark boot hold_recv "$(api_mark recv "$GWIP")"
      held=$(incarnations "$GWID" | tr '\n' ' ')
      gate_sampler boot & gsp=$!; BGPIDS+=("$gsp")
      admit_sampler boot gp-bound "$GWP_NS" & asp=$!; BGPIDS+=("$asp")
      t0=$(now_ms); l2=$(l2probe "$U" "$GWIP"); t1=$(now_ms)
      obs l2.boot C2 l2 sample boot --set "value=$l2" --set "t0=$t0" --set "t1=$t1"
      # A bound consumer asked for during the hold: its record is sampled until the readback.
      cp "$GWP/ca-$GWIP.pem" "$GWP/ca.pem" 2>/dev/null
      ( id=$(gstep run_bound main run --image $NGINX --name gp-bound --namespace "$GWP_NS" --memory 256 --egress "via:gateway+policy=$DIG" \
          --file "/etc/qual-ca.pem=$GWP/ca.pem" -- sleep 7200) && echo "$id" >"$GWP/bound.out" ) >/dev/null 2>&1 &
      bcpid=$!; BGPIDS+=("$bcpid")
      wait_set boot_release 60 "" '[ -n "$(api_mark "done" "$GWIP")" ]' true 0.2 && mark boot release "$(api_mark "done" "$GWIP")"
      wait_set boot_readback 120 "" 'c1=$(challenge); rb=$(readback "$GWP_NS" "$c1" 2>/dev/null)' && mark boot readback
      gwp_view boot_readback main
      rbinc=$(inc_of "$rb")
      wait_set boot_bound 300 "" '[ -s "$GWP/bound.out" ] || ! kill -0 "$bcpid" 2>/dev/null'
      sleep 2
      stop_bg "$gsp" "$asp"
    fi
    wait "$setpid" 2>/dev/null
  else
    gdiag loop --set name=boot_recv --set iterations=0 --set end=skipped
  fi
  BC=$(cat "$GWP/bound.out" 2>/dev/null)
  echo "   CA reply held for gateway $GWIP; bound consumer: ${BC:-none}"
  gq derive --file "$GWP_OBS" --phase boot
  obs c1.readback_challenge C1 assert subject "" --set "value=$(bool '[ -n "$rb" ] && [ "$(jq -r .report.challenge <<<"$rb")" = "$c1" ] && [ "$(jq -r .report.ready <<<"$rb")" = true ]')"
  obs c1.readback_digest C1 assert subject "" --set "value=$(bool '[ -n "$rb" ] && [ "$(jq -r .report.policy_digest <<<"$rb")" = "$DIG" ] && [ "$(jq -c "[.report.policy_format, .report.enforcement_version]" <<<"$rb")" = "[1,1]" ]')"
  obs c1.readback_identity C1 assert subject "" --set "value=$(bool '[ -n "$rb" ] && [ -n "$GWID" ] && [ "$(jq -r .machine_id <<<"$rb")" = "$GWID" ] && [ "$(jq -r .namespace <<<"$rb")" = "$GWP_NS" ]')"
  obs c1.readback_live_incarnation C1 assert subject "" --set "value=$(bool 'live_inc "$rbinc"')"
  obs c2.held_is_readback C2 observed subject "" --set "value=$(bool '[ -n "$rbinc" ] && grep -qwF "$rbinc" <<<"$held"')"
  local c1b rb2; c1b=$(challenge); rb2=$(readback "$GWP_NS" "$c1b" 2>/dev/null)
  obs c1.fresh_challenge C1 assert subject "" --set "value=$(bool '[ -n "$rb2" ] && [ "$(jq -r .report.challenge <<<"$rb2")" = "$c1b" ] && [ "$(inc_of "$rb2")" = "$rbinc" ]')"
  l2=$([ -n "$GWIP" ] && l2probe "$U" "$GWIP" || echo unknown-unknown)
  obs c2.open_arp_reached C2 observed subject "" --set "value=$([ "${l2%-*}" = reached ] && echo true || echo false)"
  obs c2.open_icmp_reached C2 observed subject "" --set "value=$([ "${l2#*-}" = reached ] && echo true || echo false)"
  judged c2.closed_observed c2.hold_arp_blocked c2.hold_icmp_blocked c2.no_admission_during_hold c2.held_is_readback c2.open_arp_reached c2.open_icmp_reached \
         c1.readback_challenge c1.readback_digest c1.readback_identity c1.readback_live_incarnation c1.fresh_challenge
  [ -z "$BC" ] || BIND0=$(briqyard machine get "$BC" | jq -cS .egress.gateway_policy)
  PX="--proxy http://$GWIP:3128 --cacert /etc/qual-ca.pem"

  # -- the unbound and legacy control (C1, C8): a gateway with no policy, a via:gateway consumer
  UL=$(gstep run_open legacy run --image $NGINX --name gpl-open --namespace "$GWP_NSL" --memory 256 -- sleep 7200 2>/dev/null)
  ulip=$(briqyard machine get "$UL" 2>/dev/null | jq -r '.ip // empty'); brl=${ulip%.*}.1
  local lmark; lmark=$(now_ms)
  if [ -n "$ulip" ] && [ "$GWP_UPLINK" = ok ]; then gwargs "$GWP_NSL" ""; gstep set_legacy legacy timeout 900 "${GWA[@]}" >"$GWP/set-legacy.out" 2>&1; fi
  LC=$(gstep run_bound legacy run --image $NGINX --name gpl-bound --namespace "$GWP_NSL" --memory 256 --egress via:gateway -- sleep 7200 2>/dev/null)
  gwp_config
  LGWIP=$(gw_view "$GWP_NSL" ip)
  obs c1.legacy_gateway_alive C1 observed subject "" --set "value=$(bool '[ -n "$LGWIP" ] && [ "$(gw_view "$GWP_NSL" state)" = running ] && [ "$(api_config_after "$LGWIP" "$lmark")" -ge 1 ]')"
  local out rc
  out=$(gstep readback_legacy legacy readback "$GWP_NSL" "$(challenge)" 2>&1); rc=$?
  obs c1.legacy_readback_refused C1 assert subject "" --set "value=$(readback_refusal "$out" "$rc")"
  obs c8.legacy_gate_empty C8 assert subject "" --set "value=$([ -n "$LGWIP" ] && { r=$(gate_read "$LGWIP"); [ "$r" = null ] && echo null || { [ "$r" = false ] && echo true || echo false; }; } || echo null)"
  obs c8.legacy_unbound_reaches C8 assert subject "" --set "value=$(bool '[ -n "$LC" ] && [ "$(probe "$LC" "--proxy http://$LGWIP:3128 -k https://$GWP_UNLISTED/" | awk "{print \$2, \$5}")" = "200 0" ]')"
  judged c1.legacy_gateway_alive c1.legacy_readback_refused c8.legacy_gate_empty c8.legacy_unbound_reaches

  # -- the mismatch case (C2): a gateway bound to a digest its loaded policy does not produce
  UM=$(gstep run_open mismatch run --image $NGINX --name gpm-open --namespace "$GWP_NSM" --memory 256 -- sleep 7200 2>/dev/null)
  umip=$(briqyard machine get "$UM" 2>/dev/null | jq -r '.ip // empty')
  local POLM DIGM DIGM_LOADED mjmark jout jrc st msetpid='' msrc='' mtry mpre mpost mrb='' mrbrc='' ml2=unknown-unknown mwin='' mopen='' mend='' mg=''
  POLM=$(gwp_policy "$GWP_NSM" "$GWP_ALLOWED"); DIGM=$(gq digest "$(gwp_policy "$GWP_NSM" example.org)")
  DIGM_LOADED=$(gq digest "$POLM")
  # From before its boot: the daemon's own boot readback of the mismatch gateway is inside it.
  mjmark=$(date '+%Y-%m-%d %H:%M:%S'); sleep 1
  if [ -n "$umip" ] && [ "$GWP_UPLINK" = ok ]; then
    gwargs "$GWP_NSM" "$POLM" "$DIGM"; gstep set_mismatch mismatch timeout 900 "${GWA[@]}" >"$GWP/set-mismatch.out" 2>&1 &
    msetpid=$!; BGPIDS+=("$msetpid")
    # Once its set has exited, waited on only while its CA reply is still to be released.
    wait_set mismatch_done 900 "$msetpid" '[ -n "$(gw_view "$GWP_NSM" ip)" ] && [ -n "$(api_mark "done" "$(gw_view "$GWP_NSM" ip)")" ]' \
      '[ -z "$(api_mark recv "$(gw_view "$GWP_NSM" ip)")" ]' 0.5 && MGWIP=$(gw_view "$GWP_NSM" ip)
  else
    gdiag loop --set name=mismatch_done --set iterations=0 --set end=skipped
  fi
  # Its set is refused for the mismatch itself: the daemon's readback finds a loaded policy that
  # is not the gateway's binding (gateway_policy.rs, read_gateway_policy), after the gateway
  # booted and served (its config fetched).
  [ -z "$msetpid" ] || { wait "$msetpid" 2>/dev/null; msrc=$?; }
  obs c2.mismatch_gateway_refused C2 assert subject "" --set "value=$(if [ -z "$MGWIP" ] || [ -z "$msrc" ]; then echo null; elif [ "$msrc" = 0 ]; then echo false; elif grep -qF "$GWP_MISMATCH_REFUSAL" "$GWP/set-mismatch.out" 2>/dev/null && [ "$(api_config_after "$MGWIP" 0)" -ge 1 ]; then echo true; else echo null; fi)"
  # Nothing is admitted through it, so the sleeper stops it at its next tick (ADR 0016, every
  # 15 s, gateway.rs sleep_gateway): the readback and the probes run in a window where it is
  # put again (refused again) and seen running with its gate closed before and after them.
  # Each pair is read gate first: a stopped gateway's address leaves the gate set.
  for mtry in 1 2 3 4 5 6; do
    [ -n "$MGWIP" ] || { mtry=0; break; }
    gwargs "$GWP_NSM" "$POLM" "$DIGM"; gstep put_mismatch mismatch timeout 300 "${GWA[@]}" >"$GWP/put-mismatch.out" 2>&1
    mpre=$(gate_read "$MGWIP"):$(gw_view "$GWP_NSM" state)
    ml2=$(l2probe "$UM" "$MGWIP")
    mrb=$(gstep readback_mismatch mismatch readback "$GWP_NSM" "$(challenge)" 2>&1); mrbrc=$?
    mpost=$(gate_read "$MGWIP"):$(gw_view "$GWP_NSM" state)
    [ "$mpre" != false:running ] && [ "$mpost" != false:running ] || mopen=1
    if [ "$mpre" = true:running ] && [ "$mpost" = true:running ]; then mwin=$mtry; break; fi
  done
  gdiag loop --set name=mismatch_window --set "iterations=$mtry" --set "end=$([ -n "$mwin" ] && echo met || echo exhausted)"
  obs c2.mismatch_running_gate_closed C2 assert subject "" --set "value=$(if [ -n "$mopen" ]; then echo false; elif [ -n "$mwin" ]; then echo true; else echo null; fi)"
  obs c2.mismatch_readback_refused C2 assert subject "" --set "value=$(if [ -z "$mwin" ]; then echo null; elif [ "$mrbrc" = 0 ]; then echo false; elif grep -qF "$GWP_MISMATCH_REFUSAL" <<<"$mrb"; then echo true; else echo null; fi)"
  jout=$(sudo journalctl -u briqyardd --no-pager --since "$mjmark" 2>/dev/null); jrc=$?
  obs c1.no_guest_output_in_errors C1 assert subject "" --set "value=$([ "$jrc" = 0 ] && [ -n "$jout" ] && [ -n "$mwin" ] && { ! grep -qF "${DIGM_LOADED#sha256:}" <<<"$mrb$jout$(cat "$GWP/set-mismatch.out" "$GWP/put-mismatch.out" 2>/dev/null)" && echo true || echo false; } || echo null)"
  obs c2.mismatch_arp_blocked C2 assert subject "" --set "value=$([ -z "$mwin" ] && echo null || case "${ml2%-*}" in (blocked) echo true;; (reached) echo false;; (*) echo null;; esac)"
  obs c2.mismatch_icmp_blocked C2 assert subject "" --set "value=$([ -z "$mwin" ] && echo null || case "${ml2#*-}" in (blocked) echo true;; (reached) echo false;; (*) echo null;; esac)"
  # Sampled throughout: a refused create may stay in error (create.rs, create_failed_locked) but
  # is never starting or running.
  local msp
  if [ -n "$MGWIP" ]; then
    admit_sampler mismatch gpm-bound "$GWP_NSM" & msp=$!; BGPIDS+=("$msp")
    out=$(timeout 180 briqyard machine run --sleep never --image $NGINX --name gpm-bound --namespace "$GWP_NSM" --memory 256 --egress "via:gateway+policy=$DIGM" -- sleep 600 2>&1); rc=$?
    sleep 2; stop_bg "$msp"
    obs mark.mismatch C2 mark sample mismatch --set value=create --set "rc=$rc" --set "t0=$(now_ms)"
    destroy_named "$GWP_NSM" gpm-bound
    # Then stopped, readably, and never seen open while it ran.
    wait_set mismatch_sleep 45 "" 'mg=$(gate_read "$MGWIP"); mend=$(gw_view "$GWP_NSM" state); [ "$mg:$mend" != false:running ] || mopen=1; [ "$mend" != running ] && [ "$mend" != starting ] && [ "$mend" != stopping ]' true 1
  fi
  obs c2.mismatch_gateway_stopped C2 assert subject "" --set "value=$(if [ -n "$mopen" ]; then echo false; elif [ -z "$MGWIP" ]; then echo null; elif [ "$mend" = stopped ]; then echo true; elif [ "$mend" = running ] || [ "$mend" = starting ]; then echo false; else echo null; fi)"
  gq derive --file "$GWP_OBS" --phase mismatch
  judged c2.mismatch_gateway_refused c2.mismatch_readback_refused c1.no_guest_output_in_errors c2.mismatch_arp_blocked c2.mismatch_icmp_blocked \
         c2.mismatch_running_gate_closed c2.mismatch_not_admitted c2.mismatch_gateway_stopped

  if [ -n "$BC" ] && [ -n "$U" ]; then
  # -- C3: what the bound machine reaches, each denial beside an unrestricted control
  ALLOWED_IP=$(on "$U" "curl -4 -sS -o /dev/null -m 10 -w '%{remote_ip}' https://$GWP_ALLOWED/" 2>/dev/null | grep -xE '[0-9.]{7,15}')
  SSH_IP=$(on "$U" "curl -4 -sS -o /dev/null --connect-timeout 5 -m 3 -w '%{remote_ip}' telnet://$GWP_SSH:22 </dev/null" 2>/dev/null | grep -xE '[0-9.]{7,15}')
  echo "   pre-resolved by the open machine: allowed $ALLOWED_IP, ssh $SSH_IP"
  obs c3.preresolved C3 observed subject "" --set "value=$(bool '[ -n "$ALLOWED_IP" ] && [ -n "$SSH_IP" ]')"
  c3_batch c3 C3 c3 full
  judged c3.preresolved c3.allowed c3.unlisted c3.ip_literal_proxied c3.other_port_proxied c3.plain_http_proxied c3.direct_allowed_ip c3.direct_tcp80 \
         c3.direct_tcp22 c3.direct_udp_dns c3.dns_other_namespace c3.dns_own_resolver c3.iso_host_bridge c3.iso_other_bridge c3.iso_daemon_ports

  # -- C4: supported lifecycle keeps the binding and the verdicts
  local okr slept
  okr=$(lc_step eval 'briqyard machine stop "$BC" && briqyard machine start "$BC"'); c4_after stop_start "$okr"
  briqyard machine set-sleep "$BC" 1m >/dev/null 2>&1
  slept=$(bool 'wait_for 240 "s=\$(mstate \"$BC\" 2>/dev/null); [ -n \"\$s\" ] && [ \"\$s\" != running ]"')
  echo "   asleep: $slept ($(briqyard machine get "$BC" 2>/dev/null | jq -c '{state, stopped_reason}'))"
  okr=$(lc_step briqyard machine wake "$BC"); briqyard machine set-sleep "$BC" never >/dev/null 2>&1
  [ "$slept" = true ] || okr=false
  c4_after sleep_wake "$okr"
  okr=$(lc_step eval 'briqyard machine set "$BC" --memory 384 && briqyard machine restart "$BC"'); c4_after resize "$okr"
  okr=$(lc_step eval 'briqyard machine stop --suspend "$BC" && briqyard machine start "$BC"'); c4_after suspend_resume "$okr"

  # -- C6a: derived operations on a bound source or the policy gateway, refused before effects
  briqyard machine backup "$BC" >/dev/null 2>&1
  refused c6.fork_bound C6 "" briqyard machine fork "$BC" --name gp-fork --namespace "$GWP_NS"
  refused c6.fork_gateway C6 "" briqyard machine fork "$GWID" --name gp-fork-gw --namespace "$GWP_NS"
  refused c6.template C6 limit briqyard machine run --sleep never --template-build init-ready-v1 --image $ALPINE --name gp-tpl --namespace "$GWP_NS" --memory 256 --egress "via:gateway+policy=$DIG"
  refused c6.warm_claim C6 limit briqyard warm-pool claim "$GWP_NS" qual-pool --name gp-warm --request-id "qual-$$-warm"
  refused c6.restore_from_backup C6 "" briqyard machine restore --from "$BC" --namespace "$GWP_NS" --name gp-restore
  refused c6.move C6 "" briqyard machine move "$BC" --namespace "$T-gpx"
  refused c6.patch_remove_open C6 "" briqyard machine set-egress "$BC" open
  refused c6.patch_remove_plain C6 "" briqyard machine set-egress "$BC" via:gateway
  refused c6.patch_change C6 "" briqyard machine set-egress "$BC" "via:gateway+policy=$DIGM"
  refused c6.patch_add C6 "" briqyard machine set-egress "$U" "via:gateway+policy=$DIG"
  judged c6.fork_bound c6.fork_gateway c6.template c6.warm_claim c6.restore_from_backup c6.move c6.patch_remove_open c6.patch_remove_plain c6.patch_change c6.patch_add

  # -- C7: a bound gateway is neither replaced nor deleted while a bound record exists
  local pre post
  pre=$(inc_of "$(readback "$GWP_NS" "$(challenge)" 2>/dev/null)")
  gwargs "$GWP_NS" "$(gwp_policy "$GWP_NS" example.org)" "$DIGM"; refused c7.replace_other_spec C7 "" "${GWA[@]}"
  gwargs "$GWP_NS" ""; refused c7.replace_no_policy C7 "" "${GWA[@]}"
  refused c7.rm_running C7 "" briqyard namespace gateway rm "$GWP_NS"
  gwargs "$GWP_NS" "$POL" "$DIG"; gstep set_same_spec main timeout 300 "${GWA[@]}" >"$GWP/same.out" 2>&1; rc=$?
  post=$(inc_of "$(readback "$GWP_NS" "$(challenge)" 2>/dev/null)")
  obs c7.same_spec_noop C7 assert subject "" --set "value=$(if [ -z "$pre" ]; then echo null; elif [ "$rc" = 0 ] && [ "$pre" = "$post" ]; then echo true; else echo false; fi)"
  judged c7.replace_other_spec c7.replace_no_policy c7.rm_running c7.same_spec_noop

  # -- C5: a gateway killed, the daemon killed; a probe loop proven alive around each
  local lp gp oldinc newinc nrecv reopen newip drb
  # The gateway's process, SIGKILL: its restart closes the gate before its TAP, and opens it only
  # on a readback of the new incarnation (its CA reply is held again, as at the first boot; the CA
  # is on its root disk, which a VMM's death keeps).
  probe_loop gateway_kill & lp=$!; BGPIDS+=("$lp")
  gate_sampler gateway_kill & gp=$!; BGPIDS+=("$gp")
  wait_set gateway_kill_alive 90 "" 'loop_alive_since gateway_kill 0'
  oldinc=$(inc_of "$(readback "$GWP_NS" "$(challenge)" 2>/dev/null)"); nrecv=$(api_count recv "$GWIP")
  if [ -n "$oldinc" ]; then mark gateway_kill kill; sudo kill -9 "${oldinc%%:*}"; fi
  # The restarted gateway's address is read again on every poll: its CA registration names it.
  local oldip=$GWIP base
  if wait_set gateway_kill_recv 1200 "" 'newip=$(gw_view "$GWP_NS" ip); base=$([ "$newip" = "$oldip" ] && echo "$nrecv" || echo 0); [ -n "$newip" ] && [ "$(api_count recv "$newip")" -gt "$base" ]' true 0.2; then
    [ "$newip" = "$GWIP" ] || { echo "   the gateway's address changed: $GWIP -> $newip"; GWIP=$newip; PX="--proxy http://$GWIP:3128 --cacert /etc/qual-ca.pem"; }
    mark gateway_kill hold_recv "$(api_mark recv "$GWIP")"
    wait_set gateway_kill_release 60 "" '[ "$(api_count "done" "$GWIP")" -gt "$base" ]' true 0.5 && mark gateway_kill release "$(api_mark "done" "$GWIP")"
  fi
  newrb=; wait_set gateway_kill_readback 120 "" 'newrb=$(readback "$GWP_NS" "$(challenge)" 2>/dev/null)' && { reopen=$(now_ms); mark gateway_kill reopen "$reopen"; }
  newinc=$(inc_of "$newrb")
  newip=$(gw_view "$GWP_NS" ip)
  [ -z "$newip" ] || [ "$newip" = "$GWIP" ] || { echo "   the gateway's address changed: $GWIP -> $newip"; GWIP=$newip; PX="--proxy http://$GWIP:3128 --cacert /etc/qual-ca.pem"; }
  [ -z "${reopen:-}" ] || wait_set gateway_kill_alive_after 120 "" 'loop_alive_since gateway_kill "$reopen"'
  stop_bg "$lp" "$gp"
  gq derive --file "$GWP_OBS" --phase gateway_kill
  obs c5.gateway_kill.readback_new_incarnation C5 assert subject "" --set "value=$(if [ -z "$oldinc" ]; then echo null; else bool '! live_inc "$oldinc" && [ -n "$newinc" ] && [ "$newinc" != "$oldinc" ] && live_inc "$newinc"'; fi)"
  obs c1.restart_new_incarnation C1 assert subject "" --set "value=$(if [ -z "$oldinc" ]; then echo null; else bool '[ -n "$newinc" ] && [ "$newinc" != "$oldinc" ]'; fi)"
  judged c5.gateway_kill.alive_before c5.gateway_kill.alive_after c5.gateway_kill.direct_never_open c5.gateway_kill.no_traffic_while_closed \
         c5.gateway_kill.closed_observed c5.gateway_kill.direct_while_closed c5.gateway_kill.hold_gate_closed c5.gateway_kill.readback_new_incarnation c1.restart_new_incarnation
  # The daemon, SIGKILL: the gateway runs on; the tables come back with its gate closed, and it
  # opens on adoption and a readback. Exec needs the daemon, so a probe that falls in the closed
  # stretch may not exist: that is a limit in the receipt, never a pass.
  reopen=
  local burst=$GWP/gate-daemon-kill.txt bp; : >"$burst"
  probe_loop daemon_kill & lp=$!; BGPIDS+=("$lp")
  gate_sampler daemon_kill & gp=$!; BGPIDS+=("$gp")
  wait_set daemon_kill_alive 90 "" 'loop_alive_since daemon_kill 0'
  gate_burst "$burst" & bp=$!; BGPIDS+=("$bp")
  mark daemon_kill kill; WAIT_API_RETURN=1 crash_daemon || echo "   the daemon did not recover: its checks stay unproven"
  drb=; wait_set daemon_kill_readback 120 "" 'drb=$(readback "$GWP_NS" "$(challenge)" 2>/dev/null)' && { reopen=$(now_ms); mark daemon_kill reopen "$reopen"; }
  stop_bg "$bp"
  [ -z "$reopen" ] || wait_set daemon_kill_alive_after 120 "" 'loop_alive_since daemon_kill "$reopen"'
  stop_bg "$lp" "$gp"
  gate_record daemon_kill "$burst"
  gq derive --file "$GWP_OBS" --phase daemon_kill
  obs c5.daemon_kill.readback_live_incarnation C5 assert subject "" --set "value=$(bool '[ -n "$drb" ] && live_inc "$(inc_of "$drb")"')"
  judged c5.daemon_kill.alive_before c5.daemon_kill.alive_after c5.daemon_kill.direct_never_open c5.daemon_kill.no_traffic_while_closed \
         c5.daemon_kill.closed_observed c5.daemon_kill.direct_while_closed c5.daemon_kill.readback_live_incarnation
  # Failed closure is not caused here: observed, it is a valid outcome so long as nothing new is
  # admitted; not observed, it is a limit.
  local gv
  if ! gv=$(briqyard namespace get "$GWP_NS" 2>/dev/null) || ! jq -e . >/dev/null 2>&1 <<<"$gv"; then
    obs c5.isolation_unconfirmed C5 assert subject "" --set value=null
  elif grep -qF "isolation unconfirmed" <<<"$(jq -r '.gateway.error // empty' <<<"$gv")"; then
    timeout 120 briqyard machine run --sleep never --image $NGINX --name gp-after --namespace "$GWP_NS" --memory 256 --egress "via:gateway+policy=$DIG" -- sleep 60 >/dev/null 2>&1; rc=$?
    obs c5.isolation_unconfirmed C5 assert subject "" --set "value=$([ "$rc" != 0 ] && [ "$rc" != 124 ] && echo true || echo false)"
    echo "   gateway isolation unconfirmed: recorded, the gateway is left to the runner's teardown"
  else
    obs c5.isolation_unconfirmed C5 limit subject "" --set value=failed-closure-not-induced
  fi
  judged c5.isolation_unconfirmed

  # -- C7 again: a stopped bound record still holds the gateway; once destroyed, rm succeeds
  briqyard machine stop "$BC" >/dev/null 2>&1
  refused c7.rm_stopped C7 "" briqyard namespace gateway rm "$GWP_NS"
  judged c7.rm_stopped
  briqyard machine rm "$BC" >/dev/null 2>&1
  out=$(gstep rm_after_destroy main timeout 300 briqyard namespace gateway rm "$GWP_NS" 2>&1); rc=$?
  local nsv nsrc
  nsv=$(briqyard namespace get "$GWP_NS" 2>&1); nsrc=$?
  obs c7.rm_after_destroy C7 assert subject "" --set "value=$(if [ "$rc" != 0 ]; then echo false; elif [ "$nsrc" = 0 ] && jq -e . >/dev/null 2>&1 <<<"$nsv"; then [ -z "$(jq -r '.gateway.machine_id // empty' <<<"$nsv")" ] && echo true || echo false; elif grep -qiE 'not found|404|no such' <<<"$nsv"; then echo true; else echo null; fi)"
  judged c7.rm_after_destroy
  fi

  # Teardown, whatever happened above: consumers first, then the gateways, then the proof.
  local m ns ms gv cv=true
  for m in $BC $LC $U $UL $UM; do briqyard machine rm "$m" >/dev/null 2>&1; done
  local nr
  for nr in "$GWP_NS main" "$GWP_NSL legacy" "$GWP_NSM mismatch"; do gstep rm_teardown "${nr#* }" timeout 300 briqyard namespace gateway rm "${nr%% *}" >/dev/null 2>&1; done
  for ns in $GWP_NS $GWP_NSL $GWP_NSM; do
    if gv=$(briqyard namespace get "$ns" 2>&1); then
      [ -z "$(jq -r '.gateway.machine_id // empty' <<<"$gv" 2>/dev/null)" ] || cv=false
    elif ! grep -qiE 'not found|404|no such' <<<"$gv"; then
      [ "$cv" = false ] || cv=null
    fi
  done
  if ms=$(api /v1/machines 2>/dev/null) && jq -e 'type == "array"' <<<"$ms" >/dev/null 2>&1; then
    [ -z "$(jq -r --arg t "$T-gp" '.[] | select(.namespace | startswith($t)) | .id' <<<"$ms")" ] || cv=false
  else
    [ "$cv" = false ] || cv=null
  fi
  obs c7.cleanup_verified C7 assert subject "" --set "value=$cv"
  judged c7.cleanup_verified

  # The receipt: fixed fields, no secret, no CA, no config; it fails when a named check is absent.
  jq -n --arg native "$(git -C "$HERE/.." rev-parse HEAD 2>/dev/null)" \
    --arg harness "$(sha256sum "$HERE/qualify.sh" | cut -c1-64)" --arg helper "$(sha256sum "$GWQ" | cut -c1-64)" \
    --arg image "$GWP_IMAGE" --arg gsrc "$GWP_SOURCE" --arg briq "${QUAL_BRIQ_SHA:-}" --arg run "${GITHUB_RUN_ID:-}" \
    --arg kernel "$(uname -r)" --arg bt "$boot_timeout" --arg el "$(( $(date +%s) - t_start ))" \
    '{native_sha: $native, harness_sha256: $harness, helper_sha256: $helper, gateway_image: $image, gateway_source_sha: $gsrc,
      briq_sha: $briq, run_id: $run, kernel: $kernel, boot_timeout_sec: $bt, elapsed_sec: $el}' >"$GWP/meta.json"
  cp "$GWP_OBS" "$LOGS/gateway-policy-observations.jsonl"
  gwp_diag_end
  check "gateway policy: the receipt names every required check and each C1-C7 one passed" 'gq receipt --file "$GWP_OBS" --meta "$GWP/meta.json" --out "$LOGS/gateway-policy-receipt.json" "${GWP_ACCEPT[@]}"'
  return 0
}
# errexit does not apply inside a function run as the left of ||: a step that fails is recorded
# by the checks that depend on it, the section still tears down and writes its receipt, and the
# suite goes on.
gateway_policy || bad "gateway policy: the section ended on an error"

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
wait_api
check "the daemon is back and the host settles" 'settle'
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
RECOVERY_SINCE=$(date +%s)
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

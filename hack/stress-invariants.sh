#!/usr/bin/env bash
# What must hold on a host whatever the machines are doing: every resource on the host belongs
# to a machine the daemon knows, every running machine has its resources, and nothing leaks
# between phases. Reads the daemon's API and the host (sudo for zfs, the jail and the state).
# Prints one line per check, exits 1 when one fails. Run by hack/stress.py between phases.
set -uo pipefail
URL=${BRIQYARD_URL:-http://127.0.0.1:7420}
DATA=${BRIQYARD_DATA_DIR:-/var/lib/briqyard}
POOL=${BRIQYARD_POOL:-byard}
bad=0
ok()  { echo "ok   $1"; }
fail(){ echo "BAD  $1"; bad=1; }
check_eq() { if [ "$2" = "$3" ]; then ok "$1: $2"; else fail "$1: $2 != $3"; fi; }

api() { curl -fsS -m 20 ${BRIQYARD_TOKEN:+-H "Authorization: Bearer $BRIQYARD_TOKEN"} "$URL$1"; }
M=$(api /v1/machines) || { fail "api unreachable"; exit 1; }
E=$(api /v1/endpoints) || E="[]"
T=$(api /v1/tenants) || T="[]"
# Tenants' gateways are machines of the daemon, not in /v1/machines: their disks, processes
# and TAPs are counted with the rest.
for g in $(echo "$T" | jq -r '.[].gateway.machine_id // empty'); do
  # One destroyed since the tenants were read is gone from both.
  m=$(api "/v1/machines/$g") && M=$(echo "$M" | jq --argjson g "$m" '. + [$g]')
done

ids=$(echo "$M" | jq -r '.[].id' | sort)
running=$(echo "$M" | jq -r '.[] | select(.state == "running" or .state == "starting" or .state == "stopping") | .id' | sort)
with_volume=$(echo "$M" | jq -r '.[] | select(.volume != null) | .id' | sort)
n_machines=$(echo "$ids" | grep -c . || true)
n_running=$(echo "$running" | grep -c . || true)
n_endpoints=$(echo "$E" | jq 'length')
n_tenants=$(echo "$T" | jq 'length')
errored=$(echo "$M" | jq -r '.[] | select(.state == "error") | "\(.id) \(.error)"')
[ -z "$errored" ] && ok "no machine in error" || fail "machines in error: $(echo "$errored" | head -3 | tr '\n' ';')"

# --- disks: a root zvol per machine, a data zvol per volume, nothing else under m/ ---
zv=$(sudo zfs list -H -o name -t volume -r "$POOL/m" 2>/dev/null | sed "s|^$POOL/m/||" | sort)
roots=$(echo "$zv" | grep '/root$' | sed 's|/root$||' | sort)
datas=$(echo "$zv" | grep '/data$' | sed 's|/data$||' | sort)
others=$(echo "$zv" | grep -v '/root$\|/data$' || true)
check_eq "root disks == machines" "$(echo "$roots" | grep -c . || true)" "$n_machines"
leaked=$(comm -23 <(echo "$roots") <(echo "$ids"))
[ -z "$leaked" ] && ok "no root disk without a machine" || fail "root disks without a machine: $(echo "$leaked" | tr '\n' ' ')"
missing=$(comm -13 <(echo "$roots") <(echo "$ids"))
[ -z "$missing" ] && ok "every machine has its root disk" || fail "machines without a root disk: $(echo "$missing" | tr '\n' ' ')"
check_eq "data disks == machines with a volume" "$(echo "$datas" | grep -c . || true)" "$(echo "$with_volume" | grep -c . || true)"
[ -z "$others" ] && ok "no stray dataset under m/" || fail "stray datasets: $(echo "$others" | tr '\n' ' ')"

# --- processes and taps: one Firecracker and one TAP per live machine, none for unknown ids ---
pending=$(echo "$M" | jq '[.[] | select(.state == "starting" or .state == "stopping")] | length')
fcs=$(pgrep -a firecracker 2>/dev/null | grep -o -- '--id [a-z0-9_-]*' | awk '{print $2}' | sed 's/^m-/m_/; s/-/_/g' | sort -u)
if [ "$pending" = 0 ]; then
  check_eq "firecracker processes == live machines" "$(echo "$fcs" | grep -c . || true)" "$n_running"
else
  echo "info $pending machine(s) in motion: process and tap counts not compared"
fi
stray=$(comm -23 <(echo "$fcs") <(echo "$ids"))
[ -z "$stray" ] && ok "no firecracker for an unknown machine" || fail "firecracker for unknown ids: $(echo "$stray" | tr '\n' ' ')"
taps=$(ip -o link show type tun 2>/dev/null | awk -F': ' '{print $2}' | grep '^bt' | sort)
[ "$pending" = 0 ] && check_eq "taps == live machines" "$(echo "$taps" | grep -c . || true)" "$n_running"

# --- tenants: a bridge per tenant the daemon knows, none else ---
bridges=$(ip -o link show type bridge 2>/dev/null | awk -F': ' '{print $2}' | grep '^by' | grep -c . || true)
check_eq "bridges == tenants" "$bridges" "$n_tenants"

# --- ingress: one listening host port per TCP endpoint ---
lo=20000; hi=29999
ports=$(ss -ltnH 2>/dev/null | awk '{print $4}' | sed 's/.*://' | awk -v lo=$lo -v hi=$hi '$1>=lo && $1<=hi' | sort -u | grep -c . || true)
tcp_eps=$(echo "$E" | jq '[.[] | select(.protocol == "tcp")] | length')
check_eq "listening endpoint ports == tcp endpoints" "$ports" "$tcp_eps"

# --- files: run dirs and jails only for known machines ---
if [ -d "$DATA/run" ]; then
  runs=$(sudo ls "$DATA/run" 2>/dev/null | sort)
  stray=$(comm -23 <(echo "$runs") <(echo "$ids"))
  [ -z "$stray" ] && ok "no run dir without a machine" || fail "run dirs without a machine: $(echo "$stray" | tr '\n' ' ')"
fi
if [ -d "$DATA/jail/firecracker" ]; then
  jails=$(sudo ls "$DATA/jail/firecracker" 2>/dev/null | sed 's/^m-/m_/; s/-/_/g' | sort)
  stray=$(comm -23 <(echo "$jails") <(echo "$ids"))
  [ -z "$stray" ] && ok "no jail without a machine" || fail "jails without a machine: $(echo "$stray" | tr '\n' ' ')"
fi

# --- the daemon itself: memory and open files, as a trend ---
pid=$(systemctl show -p MainPID --value briqyardd 2>/dev/null || true)
if [ -n "$pid" ] && [ "$pid" != 0 ]; then
  rss=$(awk '/VmRSS/{print $2}' /proc/$pid/status 2>/dev/null || echo 0)
  fds=$(sudo ls /proc/$pid/fd 2>/dev/null | wc -l | tr -d ' ')
  threads=$(awk '/Threads/{print $2}' /proc/$pid/status 2>/dev/null || echo 0)
  echo "info daemon rss ${rss} kB, ${fds} fds, ${threads} threads; machines ${n_machines} (${n_running} live), endpoints ${n_endpoints}, tenants ${n_tenants}"
fi
exit $bad

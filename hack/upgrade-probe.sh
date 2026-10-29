#!/usr/bin/env bash
# What a host upgrade and a fleet restart cost the traffic through them: hack/upgrade-probe.py
# runs through a machine's endpoints and against both APIs while `host upgrade` (the same build
# again, as hack/fleet-smoke.sh does, with and without long-held connections) and then `systemctl restart briqyard-fleet` run, and each
# phase prints what failed and how. Runs in the dev VM, through the fleet ($BRIQYARD_URL, default
# http://127.0.0.1:7430) and its host whose URL is loopback, with the release directory
# hack/vm.sh installs. Endpoints are dialled at PROBE_ADDR (default: the VM's own address, not
# loopback). Makes one machine in a tenant "probe-<pid>" and removes it.
#
#   hack/vm-lock.sh bash -c 'hack/vm.sh install && limactl shell fc bash hack/upgrade-probe.sh'
set -euo pipefail
export BRIQYARD_URL=${BRIQYARD_URL:-http://127.0.0.1:7430}
DAEMON=${BRIQYARD_DAEMON_URL:-http://127.0.0.1:7420}
HERE=$(cd "$(dirname "$0")" && pwd)
REL=/var/lib/briqyard-fleet/release
SETTLE=${PROBE_SETTLE_SEC:-5}
auth=(); [ -n "${BRIQYARD_TOKEN:-}" ] && auth=(-H "Authorization: Bearer $BRIQYARD_TOKEN")
api() { curl -fsS ${auth[@]+"${auth[@]}"} "$BRIQYARD_URL$1"; }
sudo -n test -d "$REL" || { echo "no release at $REL: run hack/vm.sh install first"; exit 2; }
ADDR=${PROBE_ADDR:-$(ip -4 route get 1.1.1.1 | awk '{for (i = 1; i < NF; i++) if ($i == "src") {print $(i + 1); exit}}')}
T=probe-$$
# A fleet just restarted is still hearing from its hosts: wait for the loopback one's room.
up_ready='.[] | select((.url | test("//127[.]0[.]0[.]1:")) and .state == "ready" and .capacity.memory_mb > 0)'
for i in $(seq 1 60); do api /v1/hosts 2>/dev/null | jq -e "$up_ready" >/dev/null && break; sleep 1; done
UP=$(api /v1/hosts | jq -r "$up_ready | .id")
[ -n "$UP" ] || { echo "the fleet has no host at a loopback URL"; exit 2; }
probe=""
cleanup() {
  [ -z "$probe" ] || kill "$probe" 2>/dev/null || true
  for id in $(briqyard machine ls --tenant "$T" 2>/dev/null | awk 'NR>1{print $1}'); do briqyard machine destroy "$id" >/dev/null 2>&1 || true; done
  briqyard tenant rm "$T" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# An HTTP server on 8080 and a line echo server on 9000, both reached by a TCP and an HTTP
# endpoint; on the host `local`, the one the fleet upgrades.
OTHERS=$(api /v1/hosts | jq -r ".[] | select(.state == \"ready\" and .id != \"$UP\") | .id")
for h in $OTHERS; do briqyard host drain "$h" >/dev/null; done
ECHO='import socketserver as s
class H(s.StreamRequestHandler):
    def handle(self):
        for line in self.rfile:
            self.wfile.write(line)
s.ThreadingTCPServer.allow_reuse_address = True
s.ThreadingTCPServer(("", 9000), H).serve_forever()'
M=$(briqyard machine run --image python:3.12-alpine --name probe --tenant "$T" --memory 256 --sleep 1h \
  -e "ECHO=$ECHO" --readiness tcp:9000 -- sh -c 'python3 -m http.server 8080 >/dev/null 2>&1 & exec python3 -c "$ECHO"' | jq -r .id)
for h in $OTHERS; do briqyard host undrain "$h" >/dev/null; done
port() { briqyard endpoint add "$M" "$1" | jq -r .address | sed 's/.*://'; }
WEB_PORT=$(port 8080)
ECHO_PORT=$(port 9000)
WEB=$(briqyard endpoint add --http --host "probe-web-$$" "$M" 8080 | jq -r .host)
ECHO_HOST=$(briqyard endpoint add --http --host "probe-echo-$$" "$M" 9000 | jq -r .host)
for i in $(seq 1 60); do
  curl -fsS -o /dev/null -H "Host: $WEB" "http://$ADDR:8080/" 2>/dev/null && curl -fsS -o /dev/null "http://$ADDR:$WEB_PORT/" 2>/dev/null && break
  sleep 1
done
echo "machine $M on $UP; endpoints at $ADDR: tcp $WEB_PORT (http), $ECHO_PORT (echo); http $WEB, $ECHO_HOST"

# Runs the probe with LONG long-held connections while "$@" runs, SETTLE seconds on each side,
# and prints its counts.
phase() {
  local name=$1 long=$2 out started took; shift 2
  out=$(mktemp)
  python3 "$HERE/upgrade-probe.py" --long "$long" --tcp "$ADDR:$WEB_PORT" --echo "$ADDR:$ECHO_PORT" \
    --http "$ADDR:8080" --web-host "$WEB" --echo-host "$ECHO_HOST" \
    --api "$BRIQYARD_URL/v1/machines/$M" --api "$DAEMON/v1/status" > "$out" &
  probe=$!
  sleep "$SETTLE"
  started=$(date +%s.%N)
  "$@" 2>&1 | sed 's/^/       /'
  took=$(echo "$(date +%s.%N) - $started" | bc)
  sleep "$SETTLE"
  kill -TERM "$probe"; wait "$probe" || true; probe=""
  echo "== $name: $(printf '%.1f' "$took") s"
  jq -r 'to_entries[] | select(.value | type == "object") |
    "  \(.key | .[0:44] | . + " " * (44 - length)) attempts \(.value.attempts) ok \(.value.ok) refused \(.value.refused) reset \(.value.reset) timeout \(.value.timeout) failed \(.value.failed) cut \(.value.cut) outage \(.value.outage_ms) ms slowest \(.value.slowest_ms) ms\(if .value.first_failure then "\n      first: " + .value.first_failure else "" end)"' "$out"
  rm -f "$out"
}

# Without long-held connections, a hand-over's drain ends as soon as the short ones do; with
# them, it runs to its bound.
phase "host upgrade, new connections only" 0 briqyard host upgrade "$UP" --release "file://$REL"
phase "host upgrade, 4 connections held each way" 4 briqyard host upgrade "$UP" --release "file://$REL"
phase "fleet restart" 4 sudo -n systemctl restart briqyard-fleet

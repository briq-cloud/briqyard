#!/usr/bin/env bash
# End-to-end suite against a running briqyardd. Needs: briqyard on PATH, curl, jq, bc, openssl,
# GNU date and timeout (run it on the host, or on any Linux that reaches the host's private
# address), the daemon at $BRIQYARD_URL (default http://127.0.0.1:7420) with $BRIQYARD_TOKEN and,
# over TLS, $BRIQYARD_TLS_FINGERPRINT; its HTTP ingress at $BRIQYARD_INGRESS (default the API's
# address, port 8080); a `backup.store`; and the internet. psql, when present, adds checks.
# Every machine it makes lives in a namespace "e2e-<pid>…" and is destroyed at the end.
set -euo pipefail
export BRIQYARD_URL=${BRIQYARD_URL:-http://127.0.0.1:7420}
for c in briqyard curl jq bc openssl timeout; do command -v "$c" >/dev/null || { echo "e2e needs $c"; exit 2; }; done
api_host=${BRIQYARD_URL#*://}; api_host=${api_host%%/*}; api_host=${api_host%:*}
INGRESS=${BRIQYARD_INGRESS:-http://$api_host:8080}
auth=(); [ -n "${BRIQYARD_TOKEN:-}" ] && auth=(-H "Authorization: Bearer $BRIQYARD_TOKEN")
# curl to the API trusts what the CLI trusts: with a pin, the daemon's own certificate once its
# SHA-256 matches, and nothing else.
CURL=(curl)
if [ -n "${BRIQYARD_TLS_FINGERPRINT:-}" ]; then
  CERT=$(mktemp)
  hostport=${BRIQYARD_URL#https://}; hostport=${hostport%%/*}
  openssl s_client -connect "$hostport" </dev/null 2>/dev/null | openssl x509 > "$CERT"
  seen=$(openssl x509 -in "$CERT" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d : | tr 'A-F' 'a-f')
  [ "$seen" = "$(echo "$BRIQYARD_TLS_FINGERPRINT" | tr -d : | tr 'A-F' 'a-f')" ] || { echo "$hostport presents $seen, not the pinned certificate"; exit 2; }
  CURL=(curl --cacert "$CERT")
fi
T=e2e-$$
pass=0; fail=0
ok()   { pass=$((pass+1)); echo "  ok   $1"; }
bad()  { fail=$((fail+1)); echo "  FAIL $1"; }
check(){ if eval "$2"; then ok "$1"; else bad "$1"; fi; }
. "$(dirname "${BASH_SOURCE[0]}")/suite-end.sh"
# The daemon's own unit on this host, which some sections stop, kill or lock for a moment.
UNIT=; if sudo -n true 2>/dev/null && systemctl is-active briqyardd >/dev/null 2>&1; then UNIT=briqyardd; fi
# Run on any exit, a failed check, Ctrl-C or a kill included: what the run started ends, what
# it changed is put back, what it made is destroyed.
cleanup() {
  local rc=$?
  echo "cleanup"
  # Every step best-effort: one that fails leaves the others to run and the exit status as it was.
  set +e
  # The background sessions, watches and their stdin: this shell's children, by its pid.
  pkill -P $$ || true
  # The encryption section moves the pool's key away for a moment: put it back first.
  if [ -n "${KEY_FILE:-}" ] && sudo test -f "$KEY_FILE.e2e"; then
    sudo mv "$KEY_FILE.e2e" "$KEY_FILE"
  fi
  # A run that ended while the daemon was down starts it again.
  if [ -n "$UNIT" ]; then
    sudo systemctl start "$UNIT"
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
  # Every namespace of the run: "$T" and "$T-<section>" (-eg, -gw, -other, -par1…).
  for t in $(briqyard namespace ls 2>/dev/null | jq -r --arg t "$T" '.[].id | select(. == $t or startswith($t + "-"))'); do
    for id in $(briqyard machine ls --namespace "$t" 2>/dev/null | awk 'NR>1{print $1}'); do briqyard machine rm "$id" >/dev/null 2>&1 || true; done
    # A machine still settling refuses its destroy; try again until the namespace is empty.
    for i in $(seq 1 10); do
      briqyard namespace rm "$t" >/dev/null 2>&1 && break
      for id in $(briqyard machine ls --namespace "$t" 2>/dev/null | awk 'NR>1{print $1}'); do briqyard machine rm "$id" >/dev/null 2>&1 || true; done
      sleep 2
    done
  done
  [ -z "${STREAM_FILES:-}" ] || rm -rf "$STREAM_FILES"
  suite_early_end "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP

. "$(dirname "${BASH_SOURCE[0]}")/e2e-machines.sh"
. "$(dirname "${BASH_SOURCE[0]}")/e2e-storage.sh"

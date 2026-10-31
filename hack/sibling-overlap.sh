#!/usr/bin/env bash
# A real SQL query completes while a controlled gateway response is held open. No public
# endpoint: e2e-siblings.sh owns the database/gateway fixtures and their fixed test inputs.
set -euo pipefail
client=${1:?usage: sibling-overlap.sh CONSUMER_ID}
work=$(mktemp -d)
pids=()
phase=database-ready
cleanup() {
  local rc=$?
  trap - EXIT INT TERM HUP
  set +e
  # Each pid is our timeout supervisor, which forwards TERM to its own command and escalates.
  for pid in "${pids[@]}"; do kill -TERM "$pid" 2>/dev/null || true; done
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
  exec 3>&- 4>&- 5>&-
  if [ "$rc" != 0 ]; then printf 'sibling overlap failed: %s\n' "$phase" >&2; fi
  rm -rf "$work"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP
mkfifo "$work/sql.in" "$work/sql.out" "$work/http.out"
# Read/write opens cannot block before their child starts. Every marker read shares one bound.
exec 3<>"$work/sql.in" 4<>"$work/sql.out" 5<>"$work/http.out"
deadline=$((SECONDS + 20))
marker() {
  local fd=$1 expected=$2 line remaining
  while :; do
    remaining=$((deadline - SECONDS))
    [ "$remaining" -gt 0 ] || return 1
    IFS= read -r -t "$remaining" -u "$fd" line || return 1
    [ "$line" != "$expected" ] || return 0
  done
}
wait_owned() {
  local wanted=$1 status=0 pid
  local active=()
  wait "$wanted" || status=$?
  for pid in "${pids[@]}"; do [ "$pid" = "$wanted" ] || active+=("$pid"); done
  pids=("${active[@]}")
  return "$status"
}
timeout --kill-after=2 20 briqyard machine exec -i "$client" -- env \
  PGPASSWORD=fixture PGCONNECT_TIMEOUT=2 psql -h database.internal -U postgres \
  -AtX -v ON_ERROR_STOP=1 <"$work/sql.in" >"$work/sql.out" 2>"$work/sql.err" &
sql=$!; pids+=("$sql")
printf 'BEGIN;\nSELECT 42;\n\\echo database-ready\n' >&3
marker 4 database-ready
phase=gateway-ready
# -i selects streaming exec; EOF closes only guest stdin, leaving response output live.
timeout --kill-after=2 20 briqyard machine exec -i "$client" -- wget -qO- -T 18 \
  --header 'X-Fixture-Token: placeholder' http://gateway.internal:3128/overlap \
  </dev/null >"$work/http.out" 2>"$work/http.err" &
http=$!; pids+=("$http")
marker 5 gateway-ready
# The gateway has flushed its first bytes and is blocked on its release event. Query the
# peer over the still-open SQL connection before allowing that HTTP response to finish.
phase=database-overlap
printf 'SELECT 43;\n\\echo database-overlap\n' >&3
marker 4 43
marker 4 database-overlap
phase=gateway-release
timeout --kill-after=2 5 briqyard machine exec "$client" -- wget -qO- -T 3 \
  --header 'X-Fixture-Token: placeholder' http://gateway.internal:3128/release >"$work/released" &
release=$!; pids+=("$release")
wait_owned "$release"
[ "$(cat "$work/released")" = released ]
phase=gateway-complete
marker 5 injected=True
phase=database-complete
printf 'COMMIT;\n\\q\n' >&3
wait_owned "$sql"
phase='http-exit'
wait_owned "$http"
pids=()

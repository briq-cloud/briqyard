#!/usr/bin/env bash
# Checks what a Prometheus beside the fleet reads (ADR 0054), against a fleet ($BRIQYARD_URL,
# default http://127.0.0.1:7430, with $BRIQYARD_METRICS_TOKEN, else $BRIQYARD_TOKEN): the
# targets name every host that may run a daemon, each serving host's metrics come through the relay.
# With $PROMETHEUS_URL, that Prometheus scrapes every target, up exactly when its host answers.
# With $GRAFANA_URL and $GRAFANA_PASSWORD_FILE (the admin's) too, every query of every panel of
# hack/monitoring/dashboards returns data over the last 30 minutes, the host dashboard's for
# $CHECK_HOST (default: the first host up). Unobserved warm data may be absent, checked
# against the host's explicit accounting/pool/probe counters. Changes nothing.
set -euo pipefail
cd "$(dirname "$0")/.."
BRIQYARD_URL=${BRIQYARD_URL:-http://127.0.0.1:7430}
token=${BRIQYARD_METRICS_TOKEN:-${BRIQYARD_TOKEN:-}}
auth=(); [ -n "$token" ] && auth=(-H "Authorization: Bearer $token")
api_auth=(); [ -n "${BRIQYARD_TOKEN:-}" ] && api_auth=(-H "Authorization: Bearer $BRIQYARD_TOKEN")
get() { curl -fsS ${auth[@]+"${auth[@]}"} "$BRIQYARD_URL$1"; }
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
# A host in these states runs its daemon: its metrics come through and it is up.
serving='select(.state | test("^(ready|draining|retiring|upgrading)$"))'
pass=0; fail=0
ok()   { pass=$((pass+1)); echo "  ok   $1"; }
bad()  { fail=$((fail+1)); echo "  FAIL $1"; }
check(){ if eval "$2"; then ok "$1"; else bad "$1"; fi; }

# Only explicit host evidence permits absent warm observations. Missing support,
# unavailable accounting and malformed queries must still fail the check.
warm_optional() {
  local successful_operations="sum(briqyard_warm_operations_total{host=\"$host\",outcome=\"success\"})"
  [[ "$1" == *briqyard_warm_* ]] || return 1
  [ "$(up "briqyard_warm_accounting_available{host=\"$host\"}")" = 1 ] || return 1
  case "$1" in
    *briqyard_warm_pool_*) [ "$(up "briqyard_warm_pools{host=\"$host\"}")" = 0 ] && return 0 ;;
  esac
  case "$1" in
    *briqyard_warm_probe_age_seconds*|*briqyard_warm_memory_available_bytes*|*briqyard_warm_disk_free_bytes*)
      [ "$(up "briqyard_warm_probe_available{host=\"$host\"}")" = 0 ] &&
        [ "$(up "briqyard_warm_desired{host=\"$host\"}")" = 0 ] && return 0 ;;
  esac
  case "$1" in
    *briqyard_warm_operation_seconds_total*)
      [ "$(up "$successful_operations")" = 0 ] && return 0 ;;
  esac
  return 1
}

echo "== discovery"
targets=$(get /v1/metrics/targets)
hosts=$(curl -fsS ${api_auth[@]+"${api_auth[@]}"} "$BRIQYARD_URL/v1/hosts")
# What a target list must hold: the hosts that serve or are down, by id, with their regions.
want=$(jq -c '[.[] | select(.state | test("^(ready|draining|retiring|upgrading|down)$")) | {host: .id, region}] | sort' <<<"$hosts")
check "the fleet's own /metrics first" 'jq -e ".[0].labels == {instance: \"fleet\"}" <<<"$targets" >/dev/null'
check "one target per host that may run a daemon" '[ "$(jq -c "[.[1:][] | .labels | {host, region}] | sort" <<<"$targets")" = "$want" ]'
check "each through its relay, instance its id" 'jq -e "all(.[1:][]; .labels.__metrics_path__ == \"/v1/hosts/\(.labels.host)/metrics\" and .labels.instance == .labels.host)" <<<"$targets" >/dev/null'
check "every target at the address asked" '[ "$(jq -r "[.[].targets[]] | unique | .[]" <<<"$targets")" = "${BRIQYARD_URL#*://}" ]'
if [ -n "$token" ]; then
  check "the targets: 401 without a token" '[ "$(code "$BRIQYARD_URL/v1/metrics/targets")" = 401 ]'
fi

echo "== relay"
for id in $(jq -r ".[] | $serving | .id" <<<"$hosts"); do
  check "$id: its metrics, relayed" 'get "/v1/hosts/$id/metrics" | grep -q "^# TYPE briqyard_machines_total gauge$"'
  if [ -n "$token" ]; then
    check "$id: 401 without a token" '[ "$(code "$BRIQYARD_URL/v1/hosts/$id/metrics")" = 401 ]'
  fi
done
for id in $(jq -r '.[] | select(.state == "down") | .id' <<<"$hosts"); do
  check "$id: down, 503" '[ "$(code ${auth[@]+"${auth[@]}"} "$BRIQYARD_URL/v1/hosts/$id/metrics")" = 503 ]'
done
check "an unknown host: 404" '[ "$(code ${auth[@]+"${auth[@]}"} "$BRIQYARD_URL/v1/hosts/no-such-host/metrics")" = 404 ]'
fleet_metrics=$(get /metrics)
check "each host's state on the fleet's /metrics" '[ "$(grep -c "^briqyard_fleet_host_state{" <<<"$fleet_metrics")" = "$(jq length <<<"$hosts")" ]'

if [ -n "${PROMETHEUS_URL:-}" ]; then
  echo "== prometheus"
  n=$(jq length <<<"$targets")
  scraped() { curl -fsS "$PROMETHEUS_URL/api/v1/targets?state=active" | jq '[.data.activeTargets[] | select(.health != "unknown")] | length'; }
  for _ in $(seq 1 60); do [ "$(scraped)" = "$n" ] && break; sleep 1; done
  check "every target scraped ($n)" '[ "$(scraped)" = "$n" ]'
  up() { curl -fsS "$PROMETHEUS_URL/api/v1/query" --data-urlencode "query=$1" | jq -r '[.data.result[].value[1]] | join(",")'; }
  check "the fleet: up" '[ "$(up "up{instance=\"fleet\"}")" = 1 ]'
  for id in $(jq -r ".[] | $serving | .id" <<<"$hosts"); do
    check "$id: up" '[ "$(up "up{host=\"$id\"}")" = 1 ]'
  done
  for id in $(jq -r '.[] | select(.state == "down") | .id' <<<"$hosts"); do
    check "$id: down, up == 0" '[ "$(up "up{host=\"$id\"}")" = 0 ]'
  done
fi

if [ -n "${PROMETHEUS_URL:-}" ] && [ -n "${GRAFANA_URL:-}" ] && [ -n "${GRAFANA_PASSWORD_FILE:-}" ]; then
  echo "== dashboards: every query returns data"
  gauth=(-u "admin:$(head -n1 "$GRAFANA_PASSWORD_FILE")")
  host=${CHECK_HOST:-$(curl -fsS "$PROMETHEUS_URL/api/v1/query" --data-urlencode 'query=up{host!=""} == 1' | jq -r '[.data.result[].metric.host] | sort | .[0]')}
  for f in hack/monitoring/dashboards/*.json; do
    uid=$(jq -r .uid "$f")
    check "$uid: provisioned" '[ "$(curl -fsS "${gauth[@]}" "$GRAFANA_URL/api/dashboards/uid/$uid" | jq -r .meta.provisioned)" = true ]'
    empty=()
    total=0
    optional=0
    while IFS=$'\t' read -r title ref instant expr; do
      total=$((total+1))
      expr=${expr//\$__rate_interval/1m}; expr=${expr//\$__range/30m}; expr=${expr//\$host/$host}
      expr=${expr//\$region/.*}; expr=${expr//\$namespace/.*}; expr=${expr//\$machine/.*}
      body=$(jq -n --arg e "$expr" --argjson i "$instant" '{from: "now-30m", to: "now", queries: [{refId: "A",
        datasource: {type: "prometheus", uid: "briqyard-prometheus"}, expr: $e, instant: $i, range: ($i | not),
        intervalMs: 60000, maxDataPoints: 100}]}')
      answer=$(curl -fsS "${gauth[@]}" -H 'Content-Type: application/json' -d "$body" "$GRAFANA_URL/api/ds/query")
      if jq -e '.results.A.error // empty' <<<"$answer" >/dev/null; then
        empty+=("$title ($ref): query error")
        continue
      fi
      n=$(jq '[.results.A.frames[]?.data.values[1]? // [] | length] | add // 0' <<<"$answer")
      if [ "$n" -eq 0 ] && warm_optional "$expr"; then
        optional=$((optional+1))
      elif [ "$n" -eq 0 ]; then
        empty+=("$title ($ref)")
      fi
    done < <(jq -r '.panels[] | select(.targets) | .title as $t | .targets[] | [$t, .refId, (.instant // false), .expr] | @tsv' "$f")
    check "$uid: $total valid queries, applicable data ($optional unobserved warm queries; host $host)" '[ ${#empty[@]} = 0 ] || { printf "       no data: %s\n" "${empty[@]}"; false; }'
  done
fi

echo
echo "passed $pass, failed $fail"
[ "$fail" = 0 ]

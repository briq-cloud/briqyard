#!/usr/bin/env bash
# Keep authenticated curl configuration out of process arguments and shell tracing.
monitoring_auth_script_dir=${BASH_SOURCE[0]%/*}
curl_auth_dir=

monitoring_auth_cleanup() {
  [ -n "$curl_auth_dir" ] || return 0
  python3 "$monitoring_auth_script_dir/monitoring-auth.py" cleanup --dir "$curl_auth_dir"
  curl_auth_dir=
}

monitoring_auth_init() {
  set +x
  local metrics_token=${BRIQYARD_METRICS_TOKEN:-${BRIQYARD_TOKEN:-}}
  local api_token=${BRIQYARD_TOKEN:-}
  local password_file=${GRAFANA_PASSWORD_FILE:-}
  export -n metrics_token api_token password_file
  unset BRIQYARD_METRICS_TOKEN BRIQYARD_TOKEN
  curl_auth_dir=$(mktemp -d "${TMPDIR:-/tmp}/briqyard-monitoring-auth.XXXXXX")
  chmod 700 "$curl_auth_dir"
  if ! {
    printf '%s\0' "$metrics_token"
    printf '%s\0' "$api_token"
    printf '%s\0' "$password_file"
  } | env -u BRIQYARD_METRICS_TOKEN -u BRIQYARD_TOKEN \
      python3 "$monitoring_auth_script_dir/monitoring-auth.py" init --dir "$curl_auth_dir"; then
    monitoring_auth_cleanup || true
    return 1
  fi
  trap monitoring_auth_cleanup EXIT
}

curl_with_auth_config() {
  local config=$1
  shift
  if [ -s "$config" ]; then
    command curl --config "$config" "$@"
  else
    command curl "$@"
  fi
}

curl_metrics() { curl_with_auth_config "$curl_auth_dir/metrics.curl" "$@"; }
curl_api() { curl_with_auth_config "$curl_auth_dir/api.curl" "$@"; }
curl_grafana() { curl_with_auth_config "$curl_auth_dir/grafana.curl" "$@"; }

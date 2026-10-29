#!/usr/bin/env bash
# Prometheus and Grafana beside the fleet (ADR 0048), on the fleet's server: the pinned
# releases, checked against their digests; a systemd unit each, as a user of its own, both on
# loopback (your reverse proxy serves Grafana, OPERATIONS.md). Prometheus finds the hosts at
# the fleet's /v1/metrics/targets and scrapes each through the fleet; Grafana has the
# dashboards of hack/monitoring/dashboards and, when /etc/briqyard-monitoring/alerting.env sets
# SLACK_WEBHOOK_URL, the alerts of hack/monitoring/grafana/alerting.yaml. Idempotent: run it
# again to upgrade (new pins) or change a setting.
#
#   bash hack/install-monitoring.sh < grafana-password    # the first time: the admin password
#   bash hack/install-monitoring.sh                       # later: the password stays
#
# Settings, from the environment:
#   FLEET_URL              the fleet as Prometheus reaches it (http://127.0.0.1:7430)
#   FLEET_TOKEN_FILE       a 0600 file with the token Prometheus presents; by default the
#                          fleet's metrics_token, else its token, from /etc/briqyard/fleet.yaml
#   RETENTION              how long Prometheus keeps samples (90d)
#   PROMETHEUS_LISTEN      127.0.0.1:9090; GRAFANA_LISTEN 127.0.0.1:3000 (loopback only)
#   GRAFANA_URL            where your proxy serves Grafana (root_url), e.g. https://grafana.example.com
#   GRAFANA_PASSWORD_FILE  a 0600 file with the admin password, instead of stdin
#   LARGEST_SLOT_MB        the alert when a region's largest slot is under it (16384)
#
# Memory: about 700 MB for both with a few hosts, Grafana 600 MB of it (Prometheus grows with
# series: about 12 per machine). On a server that also runs machines, add it to
# capacity.reserved_memory_mb.
set -euo pipefail
cd "$(dirname "$0")/.."
FLEET_URL=${FLEET_URL:-http://127.0.0.1:7430}
RETENTION=${RETENTION:-90d}
PROMETHEUS_LISTEN=${PROMETHEUS_LISTEN:-127.0.0.1:9090}
GRAFANA_LISTEN=${GRAFANA_LISTEN:-127.0.0.1:3000}
GRAFANA_URL=${GRAFANA_URL:-http://$GRAFANA_LISTEN}
LARGEST_SLOT_MB=${LARGEST_SLOT_MB:-16384}
PROMETHEUS_VERSION=3.15.1
GRAFANA_VERSION=13.2.5
case "$(uname -m)" in
  x86_64) arch=amd64
    PROMETHEUS_SHA256=6a726885328ad9efebbf36e876ce2fb6225468a71fd1e7ce3ba666d5f4d97a84
    GRAFANA_SHA256=e15a869cc550ee74fb64063c3420cf1763252e271866ae06f2030a0ee39bb7af ;;
  aarch64) arch=arm64
    PROMETHEUS_SHA256=ceb6d21493c37ca0b4513b147642797c68cf39a0f50a444d50e1e80c74f21b26
    GRAFANA_SHA256=db59ae73946e7b9a5f51aa21ceacbc9093f0e3e632ffcf304c3069f46f4df8a2 ;;
  *) echo "no Prometheus or Grafana build for $(uname -m)"; exit 1 ;;
esac
OPT=/opt/briqyard-monitoring
ETC=/etc/briqyard-monitoring
VAR=/var/lib/briqyard-monitoring

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
for l in "$PROMETHEUS_LISTEN" "$GRAFANA_LISTEN"; do
  case "${l%:*}" in 127.*) ;; *) echo "$l is not a loopback address: serve Grafana through your proxy"; exit 1 ;; esac
done
# Owned by root alone, readable by no one else: a token or a password.
private() { [ "$(stat -c '%u %a' "$1")" = "0 600" ] || { echo "$1 must be root's and 0600"; exit 1; }; }

# The admin password, read before anything changes: from the file, else from stdin.
password=
if [ -n "${GRAFANA_PASSWORD_FILE:-}" ]; then
  private "$GRAFANA_PASSWORD_FILE"
  password=$(head -n1 "$GRAFANA_PASSWORD_FILE")
elif [ ! -t 0 ]; then
  IFS= read -r password || true
fi
if [ -z "$password" ] && [ ! -f "$VAR/grafana/grafana.db" ]; then
  echo "the first install needs Grafana's admin password: on stdin, or GRAFANA_PASSWORD_FILE"; exit 1
fi

# fetch NAME URL SHA256 DIR: the archive checked against its pin, unpacked into DIR.
fetch() {
  local tmp; tmp=$(mktemp)
  curl -fsSL -o "$tmp" "$2"
  echo "$3  $tmp" | sha256sum -c --quiet - || { rm -f "$tmp"; echo "   $1: digest differs from the pin"; exit 1; }
  rm -rf "$4.new" && mkdir -p "$4.new"
  tar -xzf "$tmp" -C "$4.new" --strip-components=1
  rm -f "$tmp"
  rm -rf "$4" && mv "$4.new" "$4"
}

restart_prometheus=0 restart_grafana=0
# install SRC DST MODE OWNER FLAG: DST written when it differs, FLAG set to 1 then.
put() {
  if ! cmp -s "$1" "$2" || [ "$(stat -c '%a %U' "$2")" != "$3 $4" ]; then
    install -m "$3" -o "$4" -g "$4" "$1" "$2"
    eval "$5=1"
  fi
}

echo "== prometheus $PROMETHEUS_VERSION, grafana $GRAFANA_VERSION"
mkdir -p "$OPT"
if [ "$(cat "$OPT/prometheus/VERSION" 2>/dev/null)" != "$PROMETHEUS_VERSION" ]; then
  fetch prometheus "https://github.com/prometheus/prometheus/releases/download/v$PROMETHEUS_VERSION/prometheus-$PROMETHEUS_VERSION.linux-$arch.tar.gz" "$PROMETHEUS_SHA256" "$OPT/prometheus"
  rm -f "$OPT"/prometheus/prometheus.yml
  restart_prometheus=1
fi
if [ "$(cat "$OPT/grafana/VERSION" 2>/dev/null)" != "$GRAFANA_VERSION" ]; then
  fetch grafana "https://dl.grafana.com/oss/release/grafana-$GRAFANA_VERSION.linux-$arch.tar.gz" "$GRAFANA_SHA256" "$OPT/grafana"
  restart_grafana=1
fi

echo "== users and directories"
for u in briqyard-prometheus briqyard-grafana; do
  id "$u" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$u"
done
install -d -m 0755 "$ETC" "$ETC/grafana" "$ETC/dashboards"
for d in datasources dashboards alerting plugins; do install -d -m 0755 "$ETC/grafana/$d"; done
install -d -m 0750 -o briqyard-prometheus -g briqyard-prometheus "$VAR/prometheus"
install -d -m 0750 -o briqyard-grafana -g briqyard-grafana "$VAR/grafana"

echo "== prometheus: scrapes $FLEET_URL"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
if [ -n "${FLEET_TOKEN_FILE:-}" ]; then
  private "$FLEET_TOKEN_FILE"
  head -n1 "$FLEET_TOKEN_FILE" > "$tmp/token"
elif [ -f /etc/briqyard/fleet.yaml ]; then
  t=$(sed -n 's/^metrics_token: *//p' /etc/briqyard/fleet.yaml | tr -d '"'"'")
  [ -n "$t" ] || t=$(sed -n 's/^token: *//p' /etc/briqyard/fleet.yaml | tr -d '"'"'")
  printf '%s\n' "$t" > "$tmp/token"
else
  : > "$tmp/token"
fi
auth=
if [ -s "$tmp/token" ] && [ -n "$(tr -d '[:space:]' < "$tmp/token")" ]; then
  put "$tmp/token" "$ETC/fleet-token" 600 briqyard-prometheus restart_prometheus
  auth="authorization: { credentials_file: $ETC/fleet-token }"
else
  rm -f "$ETC/fleet-token"
fi
cat > "$tmp/prometheus.yml" <<EOF
# Written by hack/install-monitoring.sh: a change here goes at its next run.
global:
  scrape_interval: 15s
  scrape_timeout: 10s
  evaluation_interval: 1m
scrape_configs:
  # Every host, through the fleet's relay, and the fleet itself (ADR 0048).
  - job_name: briqyard
    scheme: ${FLEET_URL%%://*}
    ${auth}
    http_sd_configs:
      - url: ${FLEET_URL%/}/v1/metrics/targets
        refresh_interval: 30s
        ${auth}
EOF
"$OPT/prometheus/promtool" check config --syntax-only "$tmp/prometheus.yml" >/dev/null
put "$tmp/prometheus.yml" "$ETC/prometheus.yml" 644 root restart_prometheus

cat > "$tmp/briqyard-prometheus.service" <<EOF
[Unit]
Description=briqyard monitoring: Prometheus
After=network-online.target
Wants=network-online.target

[Service]
User=briqyard-prometheus
ExecStart=$OPT/prometheus/prometheus --config.file=$ETC/prometheus.yml --storage.tsdb.path=$VAR/prometheus --storage.tsdb.retention.time=$RETENTION --web.listen-address=$PROMETHEUS_LISTEN
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$VAR/prometheus

[Install]
WantedBy=multi-user.target
EOF
put "$tmp/briqyard-prometheus.service" /etc/systemd/system/briqyard-prometheus.service 644 root restart_prometheus

echo "== grafana: $GRAFANA_URL"
secure=false; [[ $GRAFANA_URL == https://* ]] && secure=true
cat > "$tmp/grafana.ini" <<EOF
; Written by hack/install-monitoring.sh: a change here goes at its next run.
[paths]
data = $VAR/grafana
logs = $VAR/grafana/log
plugins = $VAR/grafana/plugins
provisioning = $ETC/grafana
[server]
http_addr = ${GRAFANA_LISTEN%:*}
http_port = ${GRAFANA_LISTEN##*:}
root_url = $GRAFANA_URL
[security]
disable_gravatar = true
cookie_secure = $secure
[users]
allow_sign_up = false
allow_org_create = false
[auth.anonymous]
enabled = false
[analytics]
reporting_enabled = false
check_for_updates = false
check_for_plugin_updates = false
feedback_links_enabled = false
[news]
news_feed_enabled = false
[snapshots]
external_enabled = false
[plugins]
preinstall_disabled = true
[dashboards]
default_home_dashboard_path = $ETC/dashboards/fleet.json
[log]
mode = console
EOF
put "$tmp/grafana.ini" "$ETC/grafana.ini" 644 root restart_grafana
put hack/monitoring/grafana/datasource.yaml "$ETC/grafana/datasources/briqyard.yaml" 644 root restart_grafana
put hack/monitoring/grafana/dashboards.yaml "$ETC/grafana/dashboards/briqyard.yaml" 644 root restart_grafana
# Dashboards are read again by Grafana every 30 s: no restart for them.
for f in hack/monitoring/dashboards/*.json; do install -m 0644 "$f" "$ETC/dashboards/"; done
for f in "$ETC"/dashboards/*.json; do [ -f "hack/monitoring/dashboards/$(basename "$f")" ] || rm -f "$f"; done
# Alerting with a Slack webhook in alerting.env (root's, 0600, written by you).
if [ -f "$ETC/alerting.env" ] && grep -q '^SLACK_WEBHOOK_URL=.' "$ETC/alerting.env"; then
  private "$ETC/alerting.env"
  sed "s/\"@LARGEST_SLOT_MB@\"/$LARGEST_SLOT_MB/; s/@LARGEST_SLOT_MB@/$LARGEST_SLOT_MB/g" hack/monitoring/grafana/alerting.yaml > "$tmp/alerting.yaml"
  put "$tmp/alerting.yaml" "$ETC/grafana/alerting/briqyard.yaml" 644 root restart_grafana
  alerting=on
elif [ -f "$ETC/grafana/alerting/briqyard.yaml" ]; then
  rm -f "$ETC/grafana/alerting/briqyard.yaml"; restart_grafana=1; alerting=off
else
  alerting=off
fi
cat > "$tmp/briqyard-grafana.service" <<EOF
[Unit]
Description=briqyard monitoring: Grafana
After=network-online.target briqyard-prometheus.service
Wants=network-online.target

[Service]
User=briqyard-grafana
Environment=PROMETHEUS_URL=http://$PROMETHEUS_LISTEN
EnvironmentFile=-$ETC/alerting.env
WorkingDirectory=$OPT/grafana
ExecStart=$OPT/grafana/bin/grafana server --homepath $OPT/grafana --config $ETC/grafana.ini
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$VAR/grafana

[Install]
WantedBy=multi-user.target
EOF
put "$tmp/briqyard-grafana.service" /etc/systemd/system/briqyard-grafana.service 644 root restart_grafana

echo "== units"
systemctl daemon-reload
systemctl enable briqyard-prometheus briqyard-grafana >/dev/null 2>&1
{ [ "$restart_prometheus" = 1 ] || ! systemctl is-active -q briqyard-prometheus; } && systemctl restart briqyard-prometheus
{ [ "$restart_grafana" = 1 ] || ! systemctl is-active -q briqyard-grafana; } && systemctl restart briqyard-grafana
# waitfor NAME URL UNIT: up to a minute for the URL to answer.
waitfor() {
  for _ in $(seq 1 60); do curl -fsS -o /dev/null "$2" 2>/dev/null && return; sleep 1; done
  echo "   $1 does not answer at $2"; journalctl -u "$3" -n 20 --no-pager; exit 1
}
waitfor prometheus "http://$PROMETHEUS_LISTEN/-/ready" briqyard-prometheus
waitfor grafana "http://$GRAFANA_LISTEN/api/health" briqyard-grafana
if [ -n "$password" ]; then
  # On stdin, never in argv or a file of ours. Grafana made its admin at its first start.
  printf '%s\n' "$password" | runuser -u briqyard-grafana -- "$OPT/grafana/bin/grafana" cli \
    --homepath "$OPT/grafana" --config "$ETC/grafana.ini" admin reset-admin-password --password-from-stdin >/dev/null
fi
echo "$PROMETHEUS_VERSION" > "$OPT/prometheus/VERSION"
echo "$GRAFANA_VERSION" > "$OPT/grafana/VERSION"
echo "== done: Grafana at http://$GRAFANA_LISTEN (admin), Prometheus at http://$PROMETHEUS_LISTEN, alerting $alerting"

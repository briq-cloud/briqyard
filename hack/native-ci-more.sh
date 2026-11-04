#!/usr/bin/env bash
# Harness from the workflow revision; suites and monitoring stack from the tested source.
set -euo pipefail
[ "${RUNNER_ENVIRONMENT:-}" = github-hosted ] || { echo 'requires a disposable GitHub-hosted runner' >&2; exit 2; }
# The real install's alerting path: alerting.env sets SLACK_WEBHOOK_URL to the check's loopback
# receiver (hack/monitoring-alerts-check.py, port 18199). Grafana's Slack contact point posts there.
alerting_env() {
  sudo install -d -m 0755 /etc/briqyard-monitoring
  sudo sh -c 'umask 077; echo SLACK_WEBHOOK_URL=http://127.0.0.1:18199/ > /etc/briqyard-monitoring/alerting.env'
}

# The fleet's hosts settled and the monitoring stack installed. $1 is "unreachable" to
# register a host nothing listens on beside the real daemon (a host that is down).
monitoring_stack() {
  local extra=$1 hosts=1
  [ "$extra" = unreachable ] && hosts=2
  sudo env EXTRA="$extra" python3 - <<'PY'
from pathlib import Path
import os
import yaml
p = Path('/etc/briqyard/fleet.yaml')
c = yaml.safe_load(p.read_text())
if os.environ['EXTRA'] == 'unreachable':
    c['hosts'].append({'id': 'unreachable', 'url': 'http://127.0.0.1:27420', 'region': 'dev'})
# PyYAML reads `tls: off` as a boolean; restoring the string makes it write `tls: 'off'`, quoted, which the fleet accepts.
if c.get('tls') is False: c['tls'] = 'off'
p.write_text(yaml.safe_dump(c, sort_keys=False))
PY
  sudo systemctl restart briqyard-fleet
  local ready=0
  for _ in $(seq 1 90); do
    if curl -fsS http://127.0.0.1:7430/v1/hosts | jq -e --argjson n "$hosts" 'length == $n and any(.id == "local" and .state == "ready") and all(.id == "local" or (.id == "unreachable" and .state == "down"))' >/dev/null; then ready=1; break; fi
    sleep 1
  done
  if [ "$ready" != 1 ]; then
    echo 'monitoring host states did not settle'
    sudo systemctl --no-pager status briqyard-fleet || true
    sudo journalctl -u briqyard-fleet --no-pager -n 80 || true
    sudo cat /etc/briqyard/fleet.yaml || true
    exit 1
  fi
  # Ephemeral credential stays outside artifacts and command arguments.
  sudo sh -c 'umask 077; openssl rand -hex 24 > /etc/briqyard-monitoring-password'
  sudo env GRAFANA_PASSWORD_FILE=/etc/briqyard-monitoring-password LARGEST_SLOT_MB=8192 bash hack/install-monitoring.sh
}

case "${1:-}" in
  stress)
    # Four physical cores; 8 ordinary guests (1 GiB), plus feature forks and races.
    # Admission race still derives its sizes from the full 12 GiB host capacity.
    set +e
    python3 -u hack/stress.py --namespaces 4 --per-namespace 2 --workers 4 --memory 128 --rounds 2 --crash --churn 8 2>&1 | tee native-logs/stress-driver.log
    statuses=("${PIPESTATUS[@]}")
    set -e
    python3 - <<'PY'
from pathlib import Path
import re
s = Path('native-logs/stress-driver.log').read_text()
passed = len(re.findall(r'^.*?   ok   ', s, re.M))
failed = len(re.findall(r'^.*?   (?:BAD  |FAIL )', s, re.M))
print(f'native stress checks: {passed}/{passed + failed}; logged checks; driver exit remains authoritative')
PY
    [ "${statuses[1]}" = 0 ] || exit "${statuses[1]}"
    exit "${statuses[0]}"
    ;;
  monitoring)
    # A real local daemon and an explicitly unreachable registered host exercise both
    # up and down relay/scrape assertions. This does not stand in for a second daemon.
    monitoring_stack unreachable
    machine=
    cleanup() {
      rc=$?
      trap - EXIT
      if [ -n "$machine" ]; then briqyard machine destroy "$machine" || true; fi
      briqyard namespace rm native-monitoring || true
      sudo rm -f /etc/briqyard-monitoring-password
      exit "$rc"
    }
    trap cleanup EXIT
    trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP
    machine=$(briqyard machine run --namespace native-monitoring --name metrics --image alpine:3.20 --memory 128 --sleep never -- sh -c 'while :; do echo metrics > /root/probe; sync; sleep 1; done' | jq -r .id)
    # Panels query ranges in 60 s steps with 1 m rates: a series younger than a step or two
    # (15 s scrapes) has no point yet. Wait for 12 samples (3 minutes) of this running machine
    # on Prometheus evidence rather than sleeping and hoping the panels have data.
    sampled=0
    for _ in $(seq 1 300); do
      if curl -fsS http://127.0.0.1:9090/api/v1/query --data-urlencode 'query=count_over_time(briqyard_machine_cpu_seconds_total{namespace="native-monitoring"}[10m])' | jq -e '.data.result | length > 0 and all(.[]; (.value[1] | tonumber) >= 12)' >/dev/null; then sampled=1; break; fi
      sleep 1
    done
    [ "$sampled" = 1 ] || { echo 'monitoring machine samples did not arrive'; exit 1; }
    if ! sudo env PROMETHEUS_URL=http://127.0.0.1:9090 GRAFANA_URL=http://127.0.0.1:3000 GRAFANA_PASSWORD_FILE=/etc/briqyard-monitoring-password CHECK_HOST=local bash hack/monitoring-check.sh; then
      echo '== diagnostics (monitoring-check failed)'
      curl -sS http://127.0.0.1:9090/api/v1/query --data-urlencode 'query=count({__name__=~"briqyard_.*"}) by (__name__)' | jq -c '.data.result | length' || true
      curl -sS http://127.0.0.1:9090/api/v1/query --data-urlencode 'query=briqyard_machines' | head -c 600 || true; echo
      curl -sS http://127.0.0.1:9090/api/v1/targets | jq -c '.data.activeTargets[] | {host:.labels.host,health,lastError}' || true
      sudo journalctl -u briqyard-grafana --no-pager -n 30 | cut -c1-300 || true
      exit 1
    fi
    # The install again with alerting on, as an operator does after writing alerting.env; then the
    # daemon stopped and started: Not answering fires and resolves (ADR 0094).
    alerting_env
    sudo env GRAFANA_PASSWORD_FILE=/etc/briqyard-monitoring-password LARGEST_SLOT_MB=8192 bash hack/install-monitoring.sh
    GRAFANA_PASSWORD_FILE=/etc/briqyard-monitoring-password python3 -u hack/monitoring-alerts-check.py host-down
    ;;
  alerts)
    # The production alerts fire and resolve, received by a local webhook (ADR 0094). The
    # backup, capacity, condition and crash-loop causes need the daemon up for the whole
    # run, so the daemon-down alert is in the monitoring suite.
    alerting_env
    monitoring_stack none
    trap 'rc=$?; trap - EXIT; sudo rm -f /etc/briqyard-monitoring-password; exit "$rc"' EXIT
    trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP
    GRAFANA_PASSWORD_FILE=/etc/briqyard-monitoring-password python3 -u hack/monitoring-alerts-check.py rules
    ;;
  restore)
    python3 -m unittest discover -s hack -p test_restore_qualify.py
    set +e
    sudo -E python3 -u hack/restore-qualify.py --allow-daemon-kill --output native-logs/restore
    rc=$?
    set -e
    sudo chown -R "$(id -u):$(id -g)" native-logs/restore
    exit "$rc"
    ;;
  qualification)
    # Chaos, isolation and OOM on the isolated host (ADR 0095). The suite kills the daemon,
    # the fleet and every VMM and fills the pool: only on this disposable runner.
    export QUAL_LOGS=$PWD/native-logs/qualification
    set +e
    bash hack/qualify.sh
    rc=$?
    set -e
    exit "$rc"
    ;;
  *) echo 'expected stress, monitoring, alerts, qualification or restore' >&2; exit 2 ;;
esac

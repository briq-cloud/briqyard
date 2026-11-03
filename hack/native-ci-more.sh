#!/usr/bin/env bash
# Harness from the workflow revision; suites and monitoring stack from the tested source.
set -euo pipefail
[ "${RUNNER_ENVIRONMENT:-}" = github-hosted ] || { echo 'requires a disposable GitHub-hosted runner' >&2; exit 2; }
echo 'ENVIRONMENT GATE: two-hosts (29) and restore (10) require independent root filesystems, systemd and ZFS pools; unavailable on this single hosted runner (ADR 0089).'
case "${1:-}" in
  stress)
    # Four physical cores; 8 ordinary guests (1 GiB), plus feature forks and races.
    # Admission race still derives its sizes from the full 12 GiB host capacity.
    set +e
    python3 -u hack/stress.py --namespaces 4 --per-namespace 2 --workers 4 --memory 128 --rounds 2 --crash --churn 4 2>&1 | tee native-logs/stress-driver.log
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
    sudo python3 - <<'PY'
from pathlib import Path
import yaml
p = Path('/etc/briqyard/fleet.yaml')
c = yaml.safe_load(p.read_text())
c['hosts'].append({'id': 'unreachable', 'url': 'http://127.0.0.1:27420', 'region': 'dev'})
# PyYAML reads `tls: off` as a boolean; restoring the string makes it write `tls: 'off'`, quoted, which the fleet accepts.
if c.get('tls') is False: c['tls'] = 'off'
p.write_text(yaml.safe_dump(c, sort_keys=False))
PY
    sudo systemctl restart briqyard-fleet
    ready=0
    for _ in $(seq 1 90); do
      if curl -fsS http://127.0.0.1:7430/v1/hosts | jq -e 'length == 2 and any(.id == "local" and .state == "ready") and any(.id == "unreachable" and .state == "down")' >/dev/null; then ready=1; break; fi
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
    sudo env GRAFANA_PASSWORD_FILE=/etc/briqyard-monitoring-password bash hack/install-monitoring.sh
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
    ;;
  *) echo 'expected stress or monitoring' >&2; exit 2 ;;
esac

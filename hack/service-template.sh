#!/usr/bin/env bash
# Running-service template checks (ADR 0127) on a disposable host: turns on templates.service_ready,
# runs hack/service_template.py (e2e or bench), and puts the configuration back on every exit.
#   BRIQYARD_TEST_SERVICE=1 hack/service-template.sh [e2e|bench]
set -euo pipefail
[ "${BRIQYARD_TEST_SERVICE:-}" = 1 ] || { echo 'set BRIQYARD_TEST_SERVICE=1: this edits the daemon configuration' >&2; exit 2; }
handover() {
  local prior
  prior=$(systemctl show -p MainPID --value briqyardd)
  sudo systemctl kill --kill-whom=main --signal=SIGUSR2 briqyardd
  for _ in $(seq 1 100); do [ "$(systemctl show -p MainPID --value briqyardd)" != "$prior" ] && break; sleep .1; done
  sudo systemctl start briqyardd
  for _ in $(seq 1 30); do briqyard status >/dev/null 2>&1 && return; sleep 1; done
  return 1
}
saved=$(mktemp)
sudo cp /etc/briqyard/config.yaml "$saved"
cleanup() { local rc=$?; trap - EXIT; sudo cp "$saved" /etc/briqyard/config.yaml; rm -f "$saved"; handover || rc=1; exit "$rc"; }
trap cleanup EXIT
trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP
sudo python3 - <<'CONFIG'
from pathlib import Path
import yaml, hashlib
p = Path('/etc/briqyard/config.yaml'); c = yaml.safe_load(p.read_text())
t = c.setdefault('templates', {})
t.update(enabled=True, service_ready=True, init_ready_init_sha256=hashlib.sha256(Path('/usr/local/bin/briqyard-init').read_bytes()).hexdigest())
p.write_text(yaml.safe_dump(c, sort_keys=False))
CONFIG
handover
python3 "$(dirname "${BASH_SOURCE[0]}")/service_template.py" "${1:-e2e}"

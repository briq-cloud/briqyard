#!/usr/bin/env bash
# Boots one machine on a daemon configured with the jailer and shows what the jail looks like.
set -euo pipefail
export BRIQYARD_URL=${BRIQYARD_URL:-http://127.0.0.1:7420}
T=jail-check
for id in $(briqyard machine ls --tenant "$T" 2>/dev/null | awk 'NR>1{print $1}'); do briqyard machine destroy "$id" >/dev/null 2>&1 || true; done
M=$(briqyard machine run --image alpine:3.20 --name jailed --tenant "$T" --memory 256 -- sleep 3600 2>&1 | jq -r .id)
echo "machine $M"
briqyard machine get "$M" | jq -c '{state, error, ip}'
echo "--- processes"
ps -o user,pid,ppid,comm -C firecracker,jailer || true
echo "--- jail root"
sudo ls -la /var/lib/briqyard/jail/firecracker/*/root/ 2>/dev/null | head -14 || true
echo "--- exec"
briqyard machine exec "$M" -- sh -c 'hostname; wget -qO- -T 5 https://example.com | head -c 60; echo'
echo "--- suspend and resume inside the jail"
briqyard machine stop --suspend "$M" >/dev/null
briqyard machine get "$M" | jq -c '{state, suspended}'
briqyard machine start "$M" >/dev/null
briqyard machine get "$M" | jq -c '{state, suspended}'
briqyard machine exec "$M" -- cut -d. -f1 /proc/uptime
echo "--- journal"
sudo journalctl -u briqyardd --no-pager -o cat -n 12 | grep -iE '"level":"(WARN|ERROR)"' | cut -c1-300 || true
briqyard machine destroy "$M"
briqyard tenant rm "$T" >/dev/null 2>&1 || true
echo "jail root after destroy:"; sudo ls /var/lib/briqyard/jail/firecracker/ 2>/dev/null || echo "(none)"

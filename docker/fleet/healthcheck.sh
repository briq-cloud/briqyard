#!/bin/sh
# Asks the fleet's own /healthz, at the address its configuration listens on (a wildcard
# address is asked on loopback), over TLS when it serves TLS and plain HTTP when not.
cfg=/etc/briqyard/fleet.yaml
listen=$(sed -n 's/^listen:[[:space:]]*"\{0,1\}\([^"#[:space:]]*\).*/\1/p' "$cfg" 2>/dev/null | head -n 1)
listen=${listen:-127.0.0.1:7430}
host=${listen%:*}
port=${listen##*:}
case $host in 0.0.0.0 | '[::]' | '::' | '') host=127.0.0.1 ;; esac
# -k: the probe is on this machine and /healthz holds nothing; the certificate is the operator's.
curl -fsS -m 3 -k "https://$host:$port/healthz" > /dev/null 2>&1 || curl -fsS -m 3 "http://$host:$port/healthz" > /dev/null

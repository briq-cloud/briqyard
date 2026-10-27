#!/usr/bin/env bash
# Runs Zot as the region's pull-through mirror of Docker Hub (ADR 0036): the pinned release,
# checked against its digest; hack/mirror/zot.json with this host's address; a systemd unit,
# `briqyard-mirror`, as a user of its own. Idempotent: run it again to change the address or
# the version.
#
#   MIRROR_LISTEN=10.0.0.5:7440 bash hack/install-mirror.sh
#
# MIRROR_LISTEN is a loopback or private address (the vRack's): the mirror has no
# authentication, and anyone who reaches it pulls through it. The daemons then say
# `registry_mirrors: {docker.io: http://10.0.0.5:7440}` (OPERATIONS.md).
set -euo pipefail
cd "$(dirname "$0")/.."
LISTEN=${MIRROR_LISTEN:-127.0.0.1:7440}
ROOT=${MIRROR_ROOT:-/var/lib/briqyard-mirror}
ZOT_VERSION=${ZOT_VERSION:-v2.1.22}
case "$(uname -m)" in
  x86_64) arch=amd64; ZOT_SHA256=${ZOT_SHA256:-33b9b5bfe05d6788c076de951a01920477dbd6395c330146e23cc2340073e52e} ;;
  aarch64) arch=arm64; ZOT_SHA256=${ZOT_SHA256:-abc9bab13c144a4ee2f9067a6bbbe70ca1c018c49dbf521db28975514ea705da} ;;
  *) echo "no Zot build for $(uname -m)"; exit 1 ;;
esac

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
addr=${LISTEN%:*}; port=${LISTEN##*:}
case "$addr" in
  127.*|10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*) ;;
  *) echo "MIRROR_LISTEN=$LISTEN is not a loopback or private address: the mirror would serve the internet"; exit 1 ;;
esac

changed=0
echo "== zot $ZOT_VERSION"
if [ "$(/usr/local/bin/zot --version 2>&1 | grep -o '"commit":"v[0-9.]*' | cut -d'"' -f4)" != "$ZOT_VERSION" ]; then
  tmp=$(mktemp)
  curl -fsSL -o "$tmp" "https://github.com/project-zot/zot/releases/download/$ZOT_VERSION/zot-linux-$arch"
  echo "$ZOT_SHA256  $tmp" | sha256sum -c --quiet - || { rm -f "$tmp"; echo "   zot-linux-$arch: digest differs from the pin"; exit 1; }
  install -m 0755 "$tmp" /usr/local/bin/zot.new
  mv -f /usr/local/bin/zot.new /usr/local/bin/zot
  rm -f "$tmp"
  changed=1
fi

echo "== config and unit"
id briqyard-mirror >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin briqyard-mirror
install -d -m 0750 -o briqyard-mirror -g briqyard-mirror "$ROOT"
install -d -m 0755 /etc/briqyard-mirror
jq --arg a "$addr" --arg p "$port" --arg r "$ROOT" \
  '.http.address = $a | .http.port = $p | .storage.rootDirectory = $r' hack/mirror/zot.json > /etc/briqyard-mirror/zot.json.new
/usr/local/bin/zot verify /etc/briqyard-mirror/zot.json.new >/dev/null
cmp -s /etc/briqyard-mirror/zot.json.new /etc/briqyard-mirror/zot.json || changed=1
mv -f /etc/briqyard-mirror/zot.json.new /etc/briqyard-mirror/zot.json
cat > /etc/systemd/system/briqyard-mirror.service.new <<EOF
[Unit]
Description=briqyard registry mirror (Zot)
After=network-online.target
Wants=network-online.target

[Service]
User=briqyard-mirror
ExecStart=/usr/local/bin/zot serve /etc/briqyard-mirror/zot.json
Restart=on-failure
RestartSec=2
LimitNOFILE=65536
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$ROOT

[Install]
WantedBy=multi-user.target
EOF
cmp -s /etc/systemd/system/briqyard-mirror.service.new /etc/systemd/system/briqyard-mirror.service || changed=1
mv -f /etc/systemd/system/briqyard-mirror.service.new /etc/systemd/system/briqyard-mirror.service
systemctl daemon-reload
systemctl enable briqyard-mirror >/dev/null 2>&1
if [ "$changed" = 1 ] || ! systemctl is-active briqyard-mirror >/dev/null; then
  systemctl restart briqyard-mirror
fi
for _ in $(seq 1 30); do curl -fsS -o /dev/null "http://$LISTEN/v2/" 2>/dev/null && break; sleep 1; done
curl -fsS -o /dev/null "http://$LISTEN/v2/" || { echo "   zot does not answer on $LISTEN"; journalctl -u briqyard-mirror -n 20 --no-pager; exit 1; }
echo "== done: http://$LISTEN mirrors docker.io"

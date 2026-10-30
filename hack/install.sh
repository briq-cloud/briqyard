#!/bin/sh
# Joins this server to a briqyard fleet and installs it as a host (ADR 0057): the fleet checks
# a one-time join token, records the host and answers with its settings, then this runs the
# fleet's bootstrap script (hack/bootstrap-host.sh) with them. That script downloads the
# release binaries for this architecture and checks them against the release's SHA256SUMS,
# makes the pool, writes the config and the systemd unit, and starts the daemon.
#
#   curl -fsSL https://fleet.example/install.sh | FLEET_URL=https://fleet.example JOIN_TOKEN=<id>.<secret> sh
#
# On the fleet: `briqyard host token create --ttl 1h` prints the token. Run as root, on Ubuntu
# 26.04 with KVM.
#
#   FLEET_URL     the fleet, as this server reaches it. https:// only: the token and the host's
#                 own API token cross this link
#   JOIN_TOKEN    the one-time token, <id>.<secret>
#   HOST_NAME     the id to join as; default: h_ and this server's address
#   ADDRESS       this server's API address (IPv4); the only valid value is the one the fleet
#                 sees the call come from, which is also the default
#   BRIQYARD_POOL_DEVICE   the drives for the pool, comma-separated, two for a mirror; default:
#                 the fleet's bootstrap.pool_device
#   ALLOW_INSECURE_HTTP=1  accept an http:// FLEET_URL: the secrets cross it in clear. For a
#                 network you trust end to end, never the internet
set -eu

fail() { echo "install: $*" >&2; exit 1; }

FLEET_URL=${FLEET_URL:-}
JOIN_TOKEN=${JOIN_TOKEN:-}
[ -n "$FLEET_URL" ] || fail "FLEET_URL is not set"
[ -n "$JOIN_TOKEN" ] || fail "JOIN_TOKEN is not set"
[ "$(id -u)" = 0 ] || fail "run as root"
FLEET_URL=${FLEET_URL%/}

# The token and the host's API token cross this link: TLS, or an explicit word that they may
# not. curl follows no redirect off the scheme it started with.
proto='=https'
case "$FLEET_URL" in
  https://*) ;;
  http://*)
    [ "${ALLOW_INSECURE_HTTP:-}" = 1 ] || fail "FLEET_URL=$FLEET_URL is plain HTTP: the join token and the host's token would cross it in clear. Use https://, or set ALLOW_INSECURE_HTTP=1 on a network you trust end to end"
    echo "install: plain HTTP to $FLEET_URL (ALLOW_INSECURE_HTTP=1): the join token and the host's token cross it in clear" >&2
    proto='=http'
    ;;
  *) fail "FLEET_URL=$FLEET_URL: want https://host[:port]" ;;
esac

arch=$(uname -m)
case "$arch" in
  x86_64|aarch64) ;;
  *) fail "no briqyard build for $arch" ;;
esac

# curl and jq are all this needs before the bootstrap script, which installs the rest.
apt_updated=
for tool in curl jq; do
  command -v "$tool" >/dev/null 2>&1 && continue
  command -v apt-get >/dev/null 2>&1 || fail "$tool is missing and there is no apt-get to install it"
  [ -n "$apt_updated" ] || { DEBIAN_FRONTEND=noninteractive apt-get update -qq; apt_updated=1; }
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$tool" >/dev/null
done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM HUP

echo "== join $FLEET_URL"
facts=$(jq -n \
  --arg name "${HOST_NAME:-}" --arg address "${ADDRESS:-}" --arg arch "$arch" \
  --argjson memory_mb "$(awk '/^MemTotal:/ {print int($2 / 1024)}' /proc/meminfo)" \
  --argjson vcpus "$(nproc)" \
  '{name: $name, address: $address, arch: $arch, memory_mb: $memory_mb, vcpus: $vcpus}')
# The join token goes in on stdin, off the command line. The answer's body lands in a file and
# its status on stdout.
status=$(printf 'Authorization: Bearer %s\n' "$JOIN_TOKEN" |
  curl -sS --proto "$proto" --proto-redir "$proto" --max-time 60 -H @- \
    -H 'Content-Type: application/json' -d "$facts" \
    -o "$work/body" -w '%{http_code}' "$FLEET_URL/v1/hosts/join") ||
  fail "$FLEET_URL did not answer"
if [ "$status" != 201 ]; then
  fail "the fleet refused the join ($status): $(jq -r '.error // empty' "$work/body" 2>/dev/null || true)"
fi
host=$(jq -er .id "$work/body")
echo "   joined as $host"

# The script the SSH bootstrap runs, from the fleet: one install, not a copy of it here.
curl -fsSL --proto "$proto" --proto-redir "$proto" --max-time 60 \
  -o "$work/bootstrap-host.sh" "$FLEET_URL/bootstrap-host.sh" ||
  fail "could not fetch $FLEET_URL/bootstrap-host.sh"

# The settings the fleet answered, by the script's names. The drives are this server's to name,
# so BRIQYARD_POOL_DEVICE here wins; the fleet's URL here is the one this server reached it by,
# and is the fleet's only when the fleet has one set.
jq -r '.env | to_entries[] | "\(.key)=\(.value)"' "$work/body" > "$work/env"
pool_device=${BRIQYARD_POOL_DEVICE:-}
unset JOIN_TOKEN
export FLEET_URL
while IFS= read -r line; do
  name=${line%%=*}
  case "$name" in '' | *[!A-Z_]*) fail "the fleet sent a setting named $name" ;; esac
  export "$name=${line#*=}"
done < "$work/env"
[ -z "$pool_device" ] || export BRIQYARD_POOL_DEVICE="$pool_device"

echo "== install"
bash "$work/bootstrap-host.sh"
echo "== $host is installed; it is ready at its first heartbeat (briqyard host ls)"

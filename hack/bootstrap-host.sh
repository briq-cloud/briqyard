#!/usr/bin/env bash
# Turns a fresh Ubuntu 26.04 server with KVM into a briqyard host: packages, a ZFS pool on one
# or two drives (or a file), Firecracker and a guest kernel, the briqyard binaries, the config,
# the systemd unit. Idempotent: run again with another BRIQYARD_RELEASE, it is the upgrade (the
# fleet's `host upgrade` does that, ADR 0027): a running daemon hands its machines over to the new
# one, which adopts them; nothing stops.
#
#   BRIQYARD_RELEASE=https://github.com/briq-cloud/briqyard/releases/download/v0.1.8 \
#   BRIQYARD_POOL_DEVICE=/dev/nvme0n1,/dev/nvme1n1 BRIQYARD_TOKEN=... FLEET_URL=https://fleet.example \
#   PRIVATE_ADDRESS=10.42.0.11/16 PRIVATE_INTERFACE=enp3s0f1 ALLOWED_CLIENTS=10.42.0.0/16 bash bootstrap-host.sh
#
# With FLEET_URL the host registers with the fleet, presenting BRIQYARD_TOKEN: the fleet must
# expect that token at ADVERTISE's address (the host's order, `host add`, or `hosts:` entry).
# Without BRIQYARD_RELEASE, the binaries are expected in ./bin (built with `make`);
# BRIQYARD_RELEASE_TOKEN reads a private repository's release through GitHub's API.
#
# The pool (ADR 0028): one device, or two as a mirror. A device is a whole disk, a partition, or
# a disk the OS is installed on, whose largest free space becomes a partition for the pool.
# A device that holds a mounted filesystem, swap, any filesystem or a pool not imported is
# refused: nothing is overwritten.
#
# The API and the endpoints listen on LISTEN's address: PRIVATE_ADDRESS's when it is set (a
# private network such as OVH's vRack), else 0.0.0.0:7420. A public address needs
# ALLOWED_CLIENTS (comma-separated IPv4 CIDRs: the fleet's and the routers' networks) or
# ALLOW_PUBLIC=1 (a firewall of your own); with neither, they bind loopback. With
# PRIVATE_ADDRESS, the public interface takes SSH and PUBLIC_TCP_PORTS only. Machines reach
# PUBLIC_TCP_PORTS on the host as the internet does (`network.host_ports`: an edge beside it).
# FLEET_ADDRESS, the fleet's private address: FLEET_URL's name resolves to it here (/etc/hosts),
# so the host's calls reach the fleet from the private address the fleet knows it by.
# Off loopback the API serves TLS with a certificate of its own (ADR 0020): the script prints
# its fingerprint, which the fleet pins (`tls_fingerprint` in the host's `hosts:` entry).
#
# A server with no private network of its own (no vRack) joins 10.42.0.0/16 over WireGuard
# (ADR 0113): PRIVATE_ADDRESS without PRIVATE_INTERFACE, and WIREGUARD_PEERS, comma-separated
# `PUBLIC_KEY|TUNNEL_ADDRESS|ENDPOINT[:PORT]` entries, one per host this one must reach or be
# reached by (the fleet's host). Each peer is a single address (a /32 route, never a range);
# its endpoint is its public address, and the only one the WireGuard port (WIREGUARD_PORT,
# 51820) is open to. The host makes its own key (/etc/wireguard/briqyard0.key, never leaves)
# and prints the public one. WIREGUARD_ONLY=1 sets the peers of a host already installed
# (the fleet's host, when another joins) and changes nothing else; it then checks its own
# result and fails if a peer, a route or a rule differs from what it was given. A full re-run
# of a tunnel host may omit WIREGUARD_PEERS: the installed tunnel, peers and rule stay.
#
# The pool is encrypted at its creation (ADR 0026), with the host's key: with FLEET_URL the
# fleet's, asked with BRIQYARD_TOKEN and never written here; without, a key made into
# BRIQYARD_KEY_FILE (/etc/briqyard/pool.key, 0600). Swap is turned off for good: guest memory
# paged out would reach a disk in clear.
#
# BRIQYARD_RUNTIME_CLASSES=nested (x86_64, with BRIQYARD_RELEASE; set it on every run) makes the
# host serve the `nested` runtime class (ADR 0088): the release's kernel and modules go to
# /var/lib/briqyard/classes/nested, the class is written into the config, and KVM keeps `nested`
# on, so machines of that class can run a hypervisor. Without it KVM loads with `nested` off.
set -euo pipefail
POOL=${BRIQYARD_POOL:-byard}
POOL_DEVICE=${BRIQYARD_POOL_DEVICE:-}
POOL_FILE_GB=${BRIQYARD_POOL_FILE_GB:-50}
RELEASE=${BRIQYARD_RELEASE:-}
RELEASE_TOKEN=${BRIQYARD_RELEASE_TOKEN:-}
FLEET_URL=${FLEET_URL:-}
ADVERTISE=${ADVERTISE:-}
API_TOKEN=${BRIQYARD_TOKEN:-}
PRIVATE_ADDRESS=${PRIVATE_ADDRESS:-}
PRIVATE_INTERFACE=${PRIVATE_INTERFACE:-}
PUBLIC_TCP_PORTS=${PUBLIC_TCP_PORTS:-}
# Unset and empty differ for WIREGUARD_ONLY: empty removes every peer.
WIREGUARD_PEERS_SET=${WIREGUARD_PEERS+set}
WIREGUARD_PEERS=${WIREGUARD_PEERS:-}
WIREGUARD_PORT=${WIREGUARD_PORT:-51820}
WIREGUARD_ONLY=${WIREGUARD_ONLY:-}
FLEET_ADDRESS=${FLEET_ADDRESS:-}
if [ -n "$PRIVATE_ADDRESS" ]; then LISTEN=${LISTEN:-${PRIVATE_ADDRESS%/*}:7420}; else LISTEN=${LISTEN:-0.0.0.0:7420}; fi
ALLOWED_CLIENTS=${ALLOWED_CLIENTS:-}
ALLOW_PUBLIC=${ALLOW_PUBLIC:-}
ARC_GB=${BRIQYARD_ARC_GB:-}
KEY_FILE=${BRIQYARD_KEY_FILE:-/etc/briqyard/pool.key}
ARCH=$(uname -m)
CLASSES=${BRIQYARD_RUNTIME_CLASSES:-}
NESTED=0
for class in ${CLASSES//,/ }; do
  [ "$class" = nested ] || { echo "BRIQYARD_RUNTIME_CLASSES: $class is not a class the release builds (nested)"; exit 1; }
  NESTED=1
done

# Release installs use their checked Firecracker bundle. Local ./bin installs use the pinned
# upstream archive below. Boot identity includes binary and kernel digests: version equality
# alone cannot establish snapshot compatibility. The kernel comes from Firecracker's CI bucket.
FIRECRACKER_VERSION=${FIRECRACKER_VERSION:-v1.17.0}
KERNEL_URL=${KERNEL_URL:-https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/20261016-5732b8331e1e-0/$ARCH/vmlinux-6.18.54}
case "$ARCH" in
  x86_64)
    FIRECRACKER_SHA256=${FIRECRACKER_SHA256:-06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558}
    KERNEL_SHA256=${KERNEL_SHA256:-445b3d0ed9650869e854656308d60e6cca773190526b037b45941cbf61910f0d}
    ;;
  aarch64)
    FIRECRACKER_SHA256=${FIRECRACKER_SHA256:-e351ebe4f7a16b5873bbd51005d2e6767103cff4d5ebc829df2d3f95a93e2256}
    KERNEL_SHA256=${KERNEL_SHA256:-cfbfd2028adfd76e8ede9e56f18034c40f206c3afb2a529c04755bd17c144ba1}
    ;;
  *) echo "no Firecracker build for $ARCH"; exit 1 ;;
esac

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
[ -e /dev/kvm ] || { echo "/dev/kvm is missing: this server has no KVM"; exit 1; }
if [ "$NESTED" = 1 ]; then
  [ "$ARCH" = x86_64 ] || { echo "BRIQYARD_RUNTIME_CLASSES=nested needs an x86_64 host"; exit 1; }
  [ -n "$RELEASE" ] || { echo "BRIQYARD_RUNTIME_CLASSES=nested installs the release's kernel and modules: set BRIQYARD_RELEASE"; exit 1; }
fi
[ -n "$KERNEL_SHA256" ] || { echo "KERNEL_SHA256 is not pinned for $ARCH: set it to the sha256sum of $KERNEL_URL"; exit 1; }
# The token goes into a configuration written now, and asks the fleet for the pool's key; an
# upgrade (a configuration there, the pool open) needs neither (ADR 0027).
[ -z "$FLEET_URL" ] || [ -n "$API_TOKEN" ] || [ -f /etc/briqyard/config.yaml ] || { echo "FLEET_URL needs BRIQYARD_TOKEN: the host's own, which the fleet expects"; exit 1; }

# Loopback or RFC 1918: reachable from this host or its private network only.
private() {
  case "${1#[}" in 127.*|10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|::1]*|::1|f[cd]*:*|fe80:*) return 0 ;; esac
  return 1
}
# Where the API and the endpoints listen, who may reach them, and the URL the fleet knows the
# host at, with the scheme the API serves (TLS off loopback).
bind=${LISTEN%:*}
clients=""
if [ -n "$ALLOWED_CLIENTS" ]; then
  clients="  allowed_clients: [${ALLOWED_CLIENTS//,/, }]"
elif [ "$ALLOW_PUBLIC" = 1 ]; then
  clients="  allow_public: true"
elif ! private "$bind"; then
  # A host nobody can reach over a public bind, until the operator says who may.
  echo "   LISTEN=$LISTEN is public and neither ALLOWED_CLIENTS nor ALLOW_PUBLIC is set: binding loopback"
  bind=127.0.0.1
fi
scheme=https
case "$bind" in 127.*) scheme=http ;; esac
# The address the fleet knows the host at: the bound one, or the first one when bound to all.
# The fleet's key route matches it against the host's record.
advertise=${ADVERTISE:-$scheme://$([ "$bind" = 0.0.0.0 ] && hostname -I | awk '{print $1}' || echo "$bind"):7420}
# The token and the pool's key cross the link to the fleet (ADR 0026): plain HTTP only to a
# loopback or private address, as the daemon checks.
case "$FLEET_URL" in
  http://*)
    fleet_host=${FLEET_URL#http://}; fleet_host=${fleet_host%%/*}
    case "$fleet_host" in \[*) fleet_host=${fleet_host%%]*}] ;; *) fleet_host=${fleet_host%:*} ;; esac
    private "$fleet_host" || { echo "FLEET_URL=$FLEET_URL is plain HTTP to an address the internet could reach: write https://, or a private address"; exit 1; }
    ;;
esac

# Puts an executable in place by a rename: a running binary (the daemon, the fleet, Firecracker)
# is replaced, never written into.
put() {
  install -m 0755 "$1" "$2.new"
  mv -f "$2.new" "$2"
}

fail() { echo "   $*" >&2; exit 1; }

# WireGuard (ADR 0113): the tunnel `briqyard0` carries the private address as a /32 and one /32
# route per peer, so it never shadows a private network the host also has. The firewall's
# rule for the tunnel's port names the peers' public addresses, between two marker comments.
TUNNEL=briqyard0
TUNNEL_CONF=/etc/wireguard/$TUNNEL.conf
FIREWALL=/etc/briqyard/firewall.nft
valid_ipv4() {
  local IFS=. o
  set -- $1
  [ $# = 4 ] || return 1
  for o; do case "$o" in ''|*[!0-9]*) return 1 ;; esac; [ "${#o}" -le 3 ] && [ "$o" -le 255 ] || return 1; done
}
# Checks WIREGUARD_PEERS; prints the entries as `key tunnel_address endpoint_address endpoint_port`.
tunnel_peers() {
  local entry key addr endpoint host port seen=" "
  case "$WIREGUARD_PORT" in ''|*[!0-9]*) fail "WIREGUARD_PORT=$WIREGUARD_PORT: a port number" ;; esac
  for entry in ${WIREGUARD_PEERS//,/ }; do
    IFS='|' read -r key addr endpoint <<< "$entry"
    [[ "$key" =~ ^[A-Za-z0-9+/]{43}=$ ]] || fail "WIREGUARD_PEERS: '$key' is not a WireGuard public key"
    case "$addr" in */*) fail "WIREGUARD_PEERS: $addr is a range: one address per peer, so no route shadows a private network" ;; esac
    valid_ipv4 "$addr" || fail "WIREGUARD_PEERS: '$addr' is not an IPv4 address"
    [ "$addr" != "${PRIVATE_ADDRESS%/*}" ] || fail "WIREGUARD_PEERS: $addr is this host's own address"
    case "$seen" in *" $addr "*|*" $key "*) fail "WIREGUARD_PEERS: $addr or its key is listed twice" ;; esac
    seen="$seen$addr $key "
    host=${endpoint%:*}; port=${endpoint##*:}
    [ "$host" != "$endpoint" ] || port=$WIREGUARD_PORT
    valid_ipv4 "$host" || fail "WIREGUARD_PEERS: the endpoint of $addr is '$endpoint': an IPv4 address and an optional port"
    case "$port" in ''|*[!0-9]*) fail "WIREGUARD_PEERS: the endpoint port of $addr is '$port'" ;; esac
    ! private "$host" || fail "WIREGUARD_PEERS: the endpoint of $addr, $host, is a private address: the tunnel crosses the public network"
    echo "$key $addr $host $port"
  done
}
# The firewall's line for the tunnel's port: the peers' public addresses only.
tunnel_rule() {
  local hosts
  hosts=$(tunnel_peers | awk '{print $3}' | sort -u | paste -sd, - | sed 's/,/, /g')
  [ -n "$hosts" ] && printf '\t\tip saddr { %s } udp dport %s accept # briqyard-tunnel\n' "$hosts" "$WIREGUARD_PORT"
  return 0
}
# Waits for the tunnel to the fleet's host (FLEET_ADDRESS's peer, else the first): a peer that
# does not know this host's key yet is the commonest reason for none. The failure names the
# key; the fleet tries again in two minutes, once the peer has it.
tunnel_wait() {
  local key i
  key=$(tunnel_peers | awk -v a="$FLEET_ADDRESS" 'a == "" || $2 == a {print $1; exit}')
  for i in $(seq 1 30); do
    # A tunnel handshakes when it has something to send.
    ping -c1 -W1 "${FLEET_ADDRESS:-$(tunnel_peers | awk 'NR == 1 {print $2}')}" >/dev/null 2>&1 || true
    wg show $TUNNEL latest-handshakes | awk -v k="$key" '$1 == k && $2 > 0 {found = 1} END {exit !found}' && return 0
    sleep 1
  done
  fail "no handshake with ${FLEET_ADDRESS:-the first peer} through $TUNNEL: that host needs this host's public key $(cat /etc/wireguard/$TUNNEL.pub) (peer ${PRIVATE_ADDRESS%/*}, WIREGUARD_ONLY=1), or its firewall the UDP port $WIREGUARD_PORT from this host's public address"
}
# Installs the tunnel: the key (made once), the configuration from the peers, the unit, the
# firewall's rule. Peers changed on a running tunnel are synced without dropping the others.
tunnel_up() {
  local key addr host port conf own r
  own=${PRIVATE_ADDRESS%/*}
  valid_ipv4 "$own" || fail "WireGuard needs PRIVATE_ADDRESS (the host's address, as 10.42.0.13/16)"
  tunnel_peers >/dev/null
  command -v wg >/dev/null || { apt-get update -qq; apt-get install -y -qq wireguard-tools >/dev/null; }
  install -d -m 0700 /etc/wireguard
  [ -s /etc/wireguard/$TUNNEL.key ] || (umask 077; wg genkey > /etc/wireguard/$TUNNEL.key)
  chmod 0600 /etc/wireguard/$TUNNEL.key
  wg pubkey < /etc/wireguard/$TUNNEL.key > /etc/wireguard/$TUNNEL.pub
  conf=$(umask 077; mktemp /etc/wireguard/.conf.XXXXXX)
  {
    # The key inline: `wg syncconf` takes the configuration as it stands, a key set by a hook
    # would be cleared by it.
    printf '[Interface]\nAddress = %s/32\nListenPort = %s\nPrivateKey = %s\n' "$own" "$WIREGUARD_PORT" "$(cat /etc/wireguard/$TUNNEL.key)"
    tunnel_peers | while read -r key addr host port; do
      printf '\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\nEndpoint = %s:%s\nPersistentKeepalive = 25\n' "$key" "$addr" "$host" "$port"
    done
  } > "$conf"
  chmod 0600 "$conf"
  # Unchanged: nothing to apply.
  if ! cmp -s "$conf" $TUNNEL_CONF; then mv -f "$conf" $TUNNEL_CONF; else rm -f "$conf"; fi
  # The daemon refuses to run under a unit with a drop-in, so the ordering before the pool key
  # request is in the unit itself (written below, from the presence of this configuration).
  rm -rf /etc/systemd/system/briqyardd.service.d/10-tunnel.conf
  systemctl daemon-reload
  systemctl enable "wg-quick@$TUNNEL" >/dev/null 2>&1
  if systemctl is-active --quiet "wg-quick@$TUNNEL"; then
    wg syncconf $TUNNEL <(wg-quick strip $TUNNEL)
    # syncconf leaves routes alone: one /32 per peer. `ip route show` prints a /32 as the bare
    # address, so both sides are compared bare: only a route that differs is touched.
    local want have
    want=" $(tunnel_peers | awk '{printf "%s ", $2}')"
    have=$(ip -4 route show dev $TUNNEL | awk '{sub(/\/32$/, "", $1); print $1}')
    for r in $have; do
      case "$want" in *" $r "*) ;; *) ip route del "$r/32" dev $TUNNEL ;; esac
    done
    for r in $want; do
      case " $(echo $have) " in *" $r "*) ;; *) ip route add "$r/32" dev $TUNNEL ;; esac
    done
  else
    systemctl start "wg-quick@$TUNNEL"
  fi
  echo "   tunnel $TUNNEL: $own, $(tunnel_peers | wc -l) peer(s), udp $WIREGUARD_PORT"
  echo "   wireguard public key $(cat /etc/wireguard/$TUNNEL.pub)"
}

# A tunnel host re-run in full without WIREGUARD_PEERS: the installed tunnel already carries
# PRIVATE_ADDRESS, and its peers and firewall rule stay as they are.
installed_tunnel() {
  [ -z "$WIREGUARD_PEERS" ] && [ -s $TUNNEL_CONF ] || return 1
  ip -4 -o addr show dev $TUNNEL 2>/dev/null | awk -v a="${PRIVATE_ADDRESS%/*}" '{split($4, x, "/"); if (x[1] == a) found = 1} END {exit !found}'
}
# What the tunnel and the firewall hold now is what WIREGUARD_PEERS says: the peers (they are
# what a revocation removes), their routes and the rule, the live firewall's included.
tunnel_verify() {
  local want have rules=0
  want=$(tunnel_peers | awk '{print $1}' | sort)
  have=$(wg show $TUNNEL peers | sort)
  [ "$want" = "$have" ] || fail "$TUNNEL holds $(echo "$have" | grep -c .) peer(s) where WIREGUARD_PEERS names $(echo "$want" | grep -c .): the change did not apply"
  want=$(tunnel_peers | awk '{print $2}' | sort)
  have=$(ip -4 route show dev $TUNNEL | awk '{sub(/\/32$/, "", $1); print $1}' | sort)
  [ "$want" = "$have" ] || fail "$TUNNEL has routes ($(echo $have)) that differ from the peers' ($(echo $want))"
  [ -f $FIREWALL ] || return 0
  [ -z "$(tunnel_rule)" ] || rules=1
  [ "$(grep -c 'briqyard-tunnel$' $FIREWALL)" = "$rules" ] || fail "$FIREWALL holds a different number of tunnel rules than the $rules expected"
  [ "$(nft list table inet briqyard_host | grep -c "dport $WIREGUARD_PORT ")" = "$rules" ] || fail "the loaded firewall holds a different number of rules for udp $WIREGUARD_PORT than the $rules expected"
}
# The firewall's line for the tunnel's port, for a full bootstrap: the peers' when it is given
# them, else the one already installed, so a re-run without WireGuard values keeps the tunnel
# reachable. Only the explicit WIREGUARD_ONLY operation removes it.
host_tunnel_rule() {
  local rule
  rule=$(tunnel_rule)
  if [ -z "$rule" ] && [ -f $FIREWALL ]; then rule=$(grep '# briqyard-tunnel$' $FIREWALL || true); fi
  [ -z "$rule" ] || printf '%s\n' "$rule"
}
# The parent shell keeps fd 9 open until EXIT cleanup finishes. flock is attached
# to its shared open file description, so the Python child can acquire it for us.
# This script requires root; its private directory and lock are therefore root-owned.
runtime_install_lock() {
  # Taken early by the peers operation and by a full run's firewall step, held to exit: asking again is a no-op, not a wait on ourselves.
  [ -z "${install_lock_held:-}" ] || return 0
  python3 - "$1" <<'PYLOCK' || return
import os, pathlib, stat, sys
root = pathlib.Path(sys.argv[1])
root.mkdir(mode=0o700, parents=True, exist_ok=True)
info = root.lstat()
if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
    raise ValueError("runtime install directory must be owned by installer")
root.chmod(0o700)
fd = os.open(root / "runtime-install.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
try:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
        raise ValueError("invalid runtime install lock")
    os.fchmod(fd, 0o600)
finally:
    os.close(fd)
PYLOCK
  exec 9<>"$1/runtime-install.lock" || return
  python3 - <<'PYFLOCK'
import fcntl
try:
    fcntl.flock(9, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    # Held, by a fleet upgrade for instance: say so, then wait for as long as it takes.
    print("waiting for the installer lock", flush=True)
    fcntl.flock(9, fcntl.LOCK_EX)
PYFLOCK
  install_lock_held=1
}
# The peers of a host already installed (WIREGUARD_ONLY): the tunnel and its firewall rule
# only. An empty WIREGUARD_PEERS is the whole set: no peer, no route, no rule.
tunnel_only() {
  [ -n "$WIREGUARD_PEERS_SET" ] || fail "WIREGUARD_ONLY needs WIREGUARD_PEERS (empty, to remove every peer)"
  echo "== wireguard peers"
  tunnel_up
  if [ -f $FIREWALL ]; then
    local rule
    sed -i '/# briqyard-tunnel$/d' $FIREWALL
    rule=$(tunnel_rule)
    # Before the final drop, so the rule is read.
    awk -v rule="$rule" '/^\t\tcounter drop/ && rule != "" {print rule} {print}' $FIREWALL > $FIREWALL.new
    if [ -n "$rule" ] && ! grep -q 'briqyard-tunnel$' $FIREWALL.new; then
      rm -f $FIREWALL.new
      fail "$FIREWALL has no final drop to put the rule before"
    fi
    mv -f $FIREWALL.new $FIREWALL
    systemctl restart briqyard-firewall
    if [ -n "$rule" ]; then echo "   firewall: udp $WIREGUARD_PORT from the peers' public addresses"; else echo "   firewall: no rule for udp $WIREGUARD_PORT"; fi
  else
    echo "   no $FIREWALL: this host's firewall is not ours, set udp $WIREGUARD_PORT for the peers in it"
  fi
  tunnel_verify
}
# The fleet's upgrades rewrite the same firewall file: one writer at a time.
if [ "$WIREGUARD_ONLY" = 1 ]; then runtime_install_lock /etc/briqyard; tunnel_only; exit 0; fi

# Downloads a file and checks its digest against the pin before it lands anywhere.
fetch() {
  local url=$1 sha=$2 dest=$3 tmp
  tmp=$(mktemp)
  curl -fsSL -o "$tmp" "$url"
  echo "$sha  $tmp" | sha256sum -c --quiet - || { rm -f "$tmp"; echo "   $url: digest differs from the pin"; exit 1; }
  mv "$tmp" "$dest"
}

# Read-only safety checks before maintenance which could reclaim host memory.
# Memory ancestor policy preflight.
for property in ManagedOOMSwap ManagedOOMMemoryPressure; do
  ancestor_values=$(systemctl show --value --property="$property" -- -.slice system.slice) || fail "ancestor $property: observation unavailable"
  ancestor_count=0
  while IFS= read -r ancestor_mode; do
    [ -n "$ancestor_mode" ] || continue
    [ "$ancestor_mode" = auto ] || fail "ancestor $property: policy unsafe or unknown; resolve in drained maintenance"
    ancestor_count=$((ancestor_count + 1))
  done <<< "$ancestor_values"
  [ "$ancestor_count" = 2 ] || fail "ancestor $property: incomplete observation"
done
# End memory ancestor policy preflight.
[ "$(stat -fc %T /sys/fs/cgroup)" = cgroup2fs ] || fail "cgroup v2 is required"
grep -qw memory /sys/fs/cgroup/cgroup.controllers || fail "cgroup memory controller is required"
awk 'NR > 1 && $4 > 0 { bad = 1 } END { exit bad }' /proc/swaps || fail "swap holds pages: drain the host before disabling it"
for counter in /sys/kernel/mm/ksm/pages_shared /sys/kernel/mm/ksm/pages_sharing; do
  [ ! -e "$counter" ] || [ "$(cat "$counter")" = 0 ] || fail "KSM holds merged pages: drain the host before maintenance"
done
(
  probe=/sys/fs/cgroup/briqyard-memory-check-$$
  mkdir "$probe" || fail "cannot verify memory cgroup controls"
  trap 'rmdir "$probe" 2>/dev/null || true' EXIT
  for control in memory.max memory.oom.group memory.swap.max memory.events.local; do
    [ -e "$probe/$control" ] || fail "missing memory cgroup control: $control"
  done
)

echo "== packages"
# needrestart, run by apt's hook (unattended upgrades included), restarts a service that maps a
# library just updated: the daemon's restart suspends every machine (ADR 0050). Written always
# (needrestart installed later reads it too), before the install below, which can update a
# library the running daemon maps.
mkdir -p /etc/needrestart/conf.d
cat > /etc/needrestart/conf.d/briqyard.conf <<'EOF'
# briqyard (ADR 0050): never restarted after a library update; a hand-over (`briqyard host
# upgrade`) or a reboot picks the update up.
$nrconf{override_rc}{qr(^briqyardd\.service$)} = 0;
$nrconf{override_rc}{qr(^briqyard-fleet\.service$)} = 0;
EOF
echo "   needrestart leaves briqyardd and briqyard-fleet running"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq zfsutils-linux nftables conntrack e2fsprogs gdisk curl jq ca-certificates python3 python3-yaml >/dev/null
runtime_install_lock /etc/briqyard # before the firewall file is read and rewritten; held to the end
# Every helper the daemon starts runs through choom (ADR 0111).
[ -x /usr/bin/choom ] || fail "/usr/bin/choom is missing: apt install util-linux"
modprobe zfs

# The ARC is a cache the kernel must shrink when a machine touches its memory: capped, it
# does not compete with the machines, and the daemon leaves the cap out of its capacity.
echo "== zfs cache"
if [ -z "$ARC_GB" ]; then
  ARC_GB=$(( $(awk '/^MemTotal:/ {print $2}' /proc/meminfo) / 1048576 / 10 ))
  [ "$ARC_GB" -ge 1 ] || ARC_GB=1
  [ "$ARC_GB" -le 16 ] || ARC_GB=16
fi
echo "options zfs zfs_arc_max=$((ARC_GB << 30))" > /etc/modprobe.d/briqyard-zfs.conf
echo "$((ARC_GB << 30))" > /sys/module/zfs/parameters/zfs_arc_max
echo "   at most $ARC_GB GB"

# A run that does not name the nested class must not turn it off for a host whose configuration
# serves it: KVM would load with `nested` off at the next boot and the daemon would refuse to
# start. It fails before anything is changed; the fleet's upgrade names the class itself.
refuse_dropped_nested() {
  [ "$NESTED" = 0 ] && [ -f "$1" ] || return 0
  python3 - "$1" <<'PYDROPPED' || { echo "$1 serves the nested class: set BRIQYARD_RUNTIME_CLASSES=nested (and BRIQYARD_RELEASE), or remove the class from the configuration first"; exit 1; }
from pathlib import Path
import sys
import yaml

classes = (yaml.safe_load(Path(sys.argv[1]).read_text()) or {}).get("runtime_classes") or {}
sys.exit(1 if any(isinstance(c, dict) and c.get("nested") for c in classes.values()) else 0)
PYDROPPED
}
refuse_dropped_nested /etc/briqyard/config.yaml

# No guest runs a hypervisor of its own (ADR 0087): KVM keeps the extensions out of its
# supported CPUID, and the daemon clears them from every guest as well. Only a host that serves
# the nested class (ADR 0088) loads KVM with `nested` on. The parameter is read-only while the
# module is loaded: it applies from the next boot, or now when no machine runs.
echo "== kvm nested $([ "$NESTED" = 1 ] && echo on || echo off)"
cat > /etc/modprobe.d/briqyard-kvm.conf <<EOF
options kvm_amd nested=$NESTED
options kvm_intel nested=$NESTED
EOF
kvm_nested() { cat /sys/module/kvm_intel/parameters/nested /sys/module/kvm_amd/parameters/nested 2>/dev/null | head -n1 || true; }
if [ "$NESTED" = 1 ] && [[ "$(kvm_nested)" != [Y1] ]]; then
  if ! pgrep -x firecracker >/dev/null; then
    modprobe -r kvm_intel kvm_amd 2>/dev/null || true
    modprobe kvm_intel 2>/dev/null || modprobe kvm_amd 2>/dev/null || true
  fi
  [[ "$(kvm_nested)" == [Y1] ]] || fail "KVM is loaded with nested off and machines run: reboot the host, then run this again (nothing activated)"
fi
echo "   done"

echo "== no swap"
# Guest memory the kernel pages out would land on a disk in clear (ADR 0026): swap goes, and
# stays gone across reboots (fstab lines commented out, swap units masked).
# Package installation may have taken time since the initial read-only check.
awk 'NR > 1 && $4 > 0 { bad = 1 } END { exit bad }' /proc/swaps || fail "swap now holds pages: drain the host before disabling it"
swapoff -a
sed -i -E 's|^([^#].*[[:space:]]swap[[:space:]].*)$|# briqyard, no swap: \1|' /etc/fstab
for unit in $(systemctl list-units --type swap --all --plain --no-legend | awk '{print $1}'); do
  systemctl mask "$unit" >/dev/null
done

echo "== memory-pressure prerequisites"
# Disable merging, never unmerge existing pages. The read-only check above rejects those.
for unit in systemd-oomd.service systemd-oomd.socket ksm.service ksmtuned.service; do
  load=$(systemctl show --value --property=LoadState -- "$unit" 2>/dev/null) || [ "$load" = not-found ] || fail "$unit: load state unavailable"
  case "$load" in
    loaded|masked)
      systemctl stop "$unit" >/dev/null || fail "$unit: stop failed"
      [ "$load" = masked ] || systemctl disable "$unit" >/dev/null || fail "$unit: disable failed"
      systemctl mask "$unit" >/dev/null || fail "$unit: mask failed"
      ;;
    not-found) ;;
    *) fail "$unit: unrecognized load state" ;;
  esac
  # A mask prevents the next activation; it does not stop an already running process/socket.
  load=$(systemctl show --value --property=LoadState -- "$unit" 2>/dev/null) || [ "$load" = not-found ] || fail "$unit: final load state unavailable"
  case "$load" in masked|not-found) ;; *) fail "$unit: not masked" ;; esac
  active=$(systemctl show --value --property=ActiveState -- "$unit" 2>/dev/null) || [ "$load" = not-found ] || fail "$unit: active state unavailable"
  [ "$active" = inactive ] || fail "$unit: not positively inactive"
  if [[ "$unit" = *.service ]]; then
    pid=$(systemctl show --value --property=MainPID -- "$unit" 2>/dev/null) || [ "$load" = not-found ] || fail "$unit: main PID unavailable"
    [ "$pid" = 0 ] || fail "$unit: no positive zero-PID proof"
  fi
done
if [ -e /sys/kernel/mm/ksm/run ]; then
  echo 0 > /sys/kernel/mm/ksm/run
  mkdir -p /etc/tmpfiles.d
  echo 'w /sys/kernel/mm/ksm/run - - - - 0' > /etc/tmpfiles.d/briqyard-memory.conf
fi

echo "== no crash dumps"
# A kernel crash dump is the whole memory, guests' included, written to /var/crash in clear.
if dpkg -s kdump-tools >/dev/null 2>&1; then
  apt-get purge -y -qq kdump-tools >/dev/null
fi
if [ "$(cat /sys/kernel/kexec_crash_loaded 2>/dev/null || echo 0)" = 1 ]; then
  kexec -p -u 2>/dev/null || true
  if [ "$(cat /sys/kernel/kexec_crash_loaded)" = 1 ]; then
    echo "   a crash kernel is loaded (kdump) and could not be unloaded: its dump would hold guest memory in clear"
    exit 1
  fi
fi

# A private network (OVH's vRack): the API and the endpoints live on it; the public interface
# takes SSH and PUBLIC_TCP_PORTS only, and machines still reach the internet through it. Up
# before the pool: the fleet's key for it comes over this network.
if [ -n "$PRIVATE_ADDRESS" ]; then
  echo "== private network $PRIVATE_ADDRESS"
  case "$PRIVATE_ADDRESS" in */*) ;; *) fail "PRIVATE_ADDRESS=$PRIVATE_ADDRESS: with its prefix, as 10.42.0.11/16" ;; esac
  has_address() { ip -4 -o addr show | awk -v a="$PRIVATE_ADDRESS" '$4 == a {found = 1} END {exit !found}'; }
  # Without a private interface of its own, WireGuard carries the address (ADR 0113).
  if ! has_address && ! installed_tunnel && { [ -z "$WIREGUARD_PEERS" ] || [ -n "$PRIVATE_INTERFACE" ]; }; then
    [ -n "$PRIVATE_INTERFACE" ] || fail "no interface has $PRIVATE_ADDRESS: set PRIVATE_INTERFACE (the private network's, by its MAC in the provider's console), or WIREGUARD_PEERS"
    ip link show "$PRIVATE_INTERFACE" >/dev/null || fail "no interface $PRIVATE_INTERFACE"
    command -v netplan >/dev/null || fail "no netplan: put $PRIVATE_ADDRESS on $PRIVATE_INTERFACE yourself"
    printf 'network:\n  version: 2\n  ethernets:\n    %s:\n      addresses: [%s]\n' "$PRIVATE_INTERFACE" "$PRIVATE_ADDRESS" > /etc/netplan/60-briqyard-private.yaml
    chmod 0600 /etc/netplan/60-briqyard-private.yaml
    netplan apply
    for _ in $(seq 1 30); do has_address && break; sleep 1; done
    has_address || fail "$PRIVATE_ADDRESS did not come up on $PRIVATE_INTERFACE"
  fi
  if [ -n "$WIREGUARD_PEERS" ]; then
    tunnel_up
    has_ip() { ip -4 -o addr show | awk -v a="${PRIVATE_ADDRESS%/*}" '{split($4, x, "/"); if (x[1] == a) found = 1} END {exit !found}'; }
    has_ip || fail "${PRIVATE_ADDRESS%/*} did not come up on $TUNNEL"
  fi
  fleet_name=${FLEET_URL#*://}; fleet_name=${fleet_name%%/*}; fleet_name=${fleet_name%:*}
  sed -i '/# briqyard: the fleet$/d' /etc/hosts
  # A name only: an address in FLEET_URL (IPv6 in brackets, whose hex has letters) is dialled
  # as it is.
  case "$fleet_name" in
    \[*) ;;
    *[a-zA-Z]*)
      if [ -n "$FLEET_ADDRESS" ]; then
        printf '%s %s # briqyard: the fleet\n' "$FLEET_ADDRESS" "$fleet_name" >> /etc/hosts
        echo "   $fleet_name at $FLEET_ADDRESS"
      fi
      ;;
  esac
  private_dev=$(ip -4 -o addr show | awk -v a="${PRIVATE_ADDRESS%/*}" '{split($4, x, "/"); if (x[1] == a) {print $2; exit}}')
  public_dev=$(ip -4 route show default | awk '{for (i = 1; i < NF; i++) if ($i == "dev") {print $(i + 1); exit}}')
  [ -n "$public_dev" ] || fail "no default route: machines would have no way to the internet"
  [ "$public_dev" != "$private_dev" ] || fail "the default route goes through $private_dev, the private interface"
  # One firewall owner per host (ADR 0028): an edge on this host runs its bootstrap after.
  ! nft list table inet briq_edge >/dev/null 2>&1 || fail "an edge's firewall (table inet briq_edge) is loaded: run its bootstrap after this one"
  # A table of its own, loaded before the network at every boot; the daemon's are apart.
  # SSH's own ports, as sshd runs them: a literal 22 would lock out a server on another.
  ssh_ports=$(sshd -T 2>/dev/null | awk '$1 == "port" {print $2}' | paste -sd, -)
  [ -n "$ssh_ports" ] || fail "sshd -T names no port: closing the public interface would close SSH"
  ports=$ssh_ports${PUBLIC_TCP_PORTS:+,$PUBLIC_TCP_PORTS}
  mkdir -p /etc/briqyard
  # Read before the file is rewritten.
  tunnel_line=$(host_tunnel_rule)
  cat > /etc/briqyard/firewall.nft <<EOF
table inet briqyard_host
delete table inet briqyard_host
table inet briqyard_host {
	chain input {
		type filter hook input priority 0; policy accept;
		iifname != "$public_dev" accept
		ct state established,related accept
		meta l4proto { icmp, ipv6-icmp } accept
		udp sport 67 udp dport 68 accept
		udp sport 547 udp dport 546 accept
		tcp dport { ${ports//,/, } } accept
$tunnel_line
		counter drop
	}
}
EOF
  cat > /etc/systemd/system/briqyard-firewall.service <<'EOF'
[Unit]
Description=briqyard: the public interface takes SSH and the ports named
DefaultDependencies=no
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/briqyard/firewall.nft

[Install]
WantedBy=sysinit.target
EOF
  systemctl daemon-reload
  systemctl enable briqyard-firewall >/dev/null 2>&1
  systemctl restart briqyard-firewall
  echo "   public $public_dev: tcp $ports in, nothing else; private $private_dev"
  # After the rule for the tunnel's port is in force.
  [ -z "$WIREGUARD_PEERS" ] || tunnel_wait
fi

# The partition labelled briqyard-pool on a disk, if it has one.
pool_partition() { lsblk -nro PATH,PARTLABEL "$1" | awk '$2 == "briqyard-pool" {print $1; exit}'; }

# The device a pool member is: a partition as it is; a disk as it is when nothing is on it; a
# disk with partitions (the OS on part of it) gets one in its largest free space, labelled
# briqyard-pool and found by that label on a later run. Never a device in use.
pool_device() {
  local dev start end sector out used sig uuid
  dev=$(readlink -f "$1")
  [ -b "$dev" ] || fail "$1 is not a block device"
  if [ "$(lsblk -dno TYPE "$dev")" != part ] && [ -n "$(lsblk -nro TYPE "$dev" | awk '$1 == "part"')" ]; then
    if [ -z "$(pool_partition "$dev")" ]; then
      [ "$(blkid -p -o value -s PTTYPE "$dev")" = gpt ] || fail "$1 has partitions but no GPT: name a partition for the pool"
      start=$(sgdisk -F "$dev"); end=$(sgdisk -E "$dev"); sector=$(blockdev --getss "$dev")
      [ $(( (end - start) * sector )) -ge $((10 << 30)) ] || fail "$1 has under 10 GB free: leave the rest of the disk unpartitioned at install, or name a partition"
      # The kernel takes the new partition alone (partx): the OS's stay in use meanwhile.
      out=$(sgdisk -n "0:$start:$end" -t 0:bf01 -c 0:briqyard-pool "$dev" 2>&1) || echo "   sgdisk: $out" >&2
      partx -u "$dev" 2>/dev/null || true
      udevadm settle
      [ -n "$(pool_partition "$dev")" ] || fail "$1: no briqyard-pool partition after sgdisk"
      echo "   $1: $(pool_partition "$dev"), $(( (end - start) * sector >> 30 )) GB of free space" >&2
    fi
    dev=$(pool_partition "$dev")
  fi
  used=$(lsblk -nro MOUNTPOINTS "$dev" | grep . | paste -sd, - || true)
  [ -z "$used" ] || fail "$1 is in use (mounted at $used): the pool takes a device nothing uses"
  [ "$(lsblk -nro NAME "$dev" | wc -l)" = 1 ] || fail "$1 is in use by $(lsblk -nro NAME "$dev" | sed 1d | paste -sd, -) (RAID, LVM, partitions)"
  # Nothing is overwritten: a pool there is one not imported (a re-run, a reinstalled OS).
  sig=$(blkid -p -o value -s TYPE "$dev" 2>/dev/null || true)
  [ "$sig" != zfs_member ] || fail "$1 holds a pool: zpool import $POOL, or wipefs -a it if it is meant for a new one"
  [ -z "$sig" ] || fail "$1 holds $sig: wipefs -a it if it is meant for the pool"
  # A partition by its id: disk names may change order across reboots.
  uuid=$(lsblk -dno PARTUUID "$dev")
  if [ -n "$uuid" ] && [ -e "/dev/disk/by-partuuid/$uuid" ]; then echo "/dev/disk/by-partuuid/$uuid"; else echo "$dev"; fi
}

# The pool's key on stdout: the fleet's for this host, or the key file's. `pool_key make`
# makes the file when it is missing (a pool about to be created), never otherwise.
pool_key() {
  if [ -n "$FLEET_URL" ]; then
    [ -n "$API_TOKEN" ] || { echo "   the fleet's key needs BRIQYARD_TOKEN: the host's own" >&2; return 1; }
    # The token goes in on stdin, off the command line. A bounded retry of what can pass: a
    # timeout, a connection failure, a 5xx. The ask is safe to repeat (the key is made once and
    # served again as it is). A 4xx or any other failure is final, even when curl then failed
    # reading the body.
    # The limit outlasts the fleet's longest wait before its own answer, so its message (a
    # backup that could not be written: 503) reaches this host instead of a curl timeout: the
    # key turn (30 s), the turn to publish (30 s), the write (30 s), crates/briqyard-fleet
    # hosts.rs and backup.rs. 120 s is that 90 s with a margin; 3 tries come to 6 minutes.
    local try out rc code
    for try in 1 2 3; do
      rc=0
      # The status follows the body on its own line; the key never touches the disk.
      out=$(printf 'Authorization: Bearer %s\n' "$API_TOKEN" |
        curl -sS --connect-timeout 20 --max-time 120 -H @- -H 'Content-Type: application/json' -w '\n%{http_code}' \
          -d "{\"url\": \"$advertise\"}" "${FLEET_URL%/}/v1/hosts/key") || rc=$?
      code=${out##*$'\n'}
      # An observed 4xx decides, whatever curl made of the rest of the answer.
      case "$code" in 4??) echo "   the fleet's key: HTTP $code, not retried" >&2; return 1 ;; esac
      if [ "$rc" = 0 ] && [ "${code:0:1}" = 2 ]; then
        printf '%s' "${out%$'\n'*}" | jq -er .key
        return
      fi
      # curl: 6 and 7 cannot resolve or connect, 28 timed out, 35 TLS handshake, 52 empty reply, 55 and 56 send and receive.
      case "$rc" in
        0) case "$code" in 5??) ;; *) echo "   the fleet's key: HTTP $code, not retried" >&2; return 1 ;; esac ;;
        6|7|28|35|52|55|56) ;;
        *) echo "   the fleet's key: curl failed ($rc), not retried" >&2; return 1 ;;
      esac
      echo "   the fleet's key: attempt $try of 3 failed" >&2
      [ "$try" = 3 ] || sleep 3
    done
    return 1
  else
    if [ ! -f "$KEY_FILE" ] && [ "${1:-}" = make ]; then
      (umask 077; mkdir -p "$(dirname "$KEY_FILE")"; od -An -tx1 -N32 /dev/urandom | tr -d ' \n' > "$KEY_FILE")
      echo "   key made in $KEY_FILE: keep a copy off this host, the pool is unreadable without it" >&2
    fi
    tr -d ' \n' < "$KEY_FILE"
  fi
}

echo "== pool $POOL, encrypted"
if ! zpool list "$POOL" >/dev/null 2>&1; then
  vdevs=()
  if [ -n "$POOL_DEVICE" ]; then
    for d in ${POOL_DEVICE//,/ }; do
      dev=$(pool_device "$d") || exit 1
      vdevs+=("$dev")
    done
    # -f for a mirror of two sizes alone (a disk's free space beside a whole disk): every
    # member was checked to hold nothing above.
    case ${#vdevs[@]} in
      1) ;;
      2) vdevs=(-f mirror "${vdevs[@]}") ;;
      *) fail "BRIQYARD_POOL_DEVICE names ${#vdevs[@]} devices: one, or two for a mirror" ;;
    esac
  else
    mkdir -p /var/lib/briqyard
    truncate -s "${POOL_FILE_GB}G" /var/lib/briqyard/pool.img
    vdevs=(/var/lib/briqyard/pool.img)
    echo "   (a file-backed pool: fine for a trial, not for production)"
  fi
  key=$(pool_key make) || fail "no key for the pool (${FLEET_URL:-$KEY_FILE})"
  [ "${#key}" = 64 ] || fail "the pool's key is not 64 hex digits"
  # The key on stdin: in no file, on no command line.
  printf '%s\n' "$key" | zpool create -o ashift=12 -O compression=lz4 -O atime=off \
    -O encryption=aes-256-gcm -O keyformat=hex -O keylocation=prompt "$POOL" "${vdevs[@]}"
  unset key
  echo "   ${vdevs[*]}"
fi
if [ "$(zfs get -H -o value encryption "$POOL")" = off ]; then
  echo "   pool $POOL is not encrypted (ADR 0026): ZFS cannot encrypt a pool after its creation."
  echo "   Move what it holds elsewhere, destroy it, and run this script again."
  exit 1
fi
# A pool that exists, locked (a reboot): its key from the same source, checked now rather
# than at the daemon's start.
if [ "$(zfs get -H -o value keystatus "$POOL")" = unavailable ] && [ -z "$FLEET_URL" ] &&
  grep -qx '  key: fleet' /etc/briqyard/config.yaml 2>/dev/null; then
  echo "   pool $POOL is locked: the daemon asks the fleet for its key at its start"
elif [ "$(zfs get -H -o value keystatus "$POOL")" = unavailable ]; then
  root=$(zfs get -H -o value encryptionroot "$POOL")
  key=$(pool_key) || { echo "   pool $POOL is locked and its key could not be read (${FLEET_URL:-$KEY_FILE})"; exit 1; }
  if ! out=$(printf '%s\n' "$key" | zfs load-key -L prompt "$root" 2>&1); then
    echo "   pool $POOL is locked and its key (${FLEET_URL:-$KEY_FILE}) does not open it: $out"
    echo "   The pool was made with another key: the fleet's registry lost or replaced, or another key file."
    exit 1
  fi
  unset key
  echo "   key loaded"
fi

# Runtime installation helpers. Kept here because the fleet embeds this standalone script.
checked_bundle() {
  python3 - "$@" <<'PY'
import hashlib
import json
from pathlib import Path
import re
import sys
import tarfile

bundle, arch, destination = sys.argv[1:]
with tarfile.open(bundle, "r:gz") as archive:
    members = archive.getmembers()
    files = {}
    for member in members:
        if not member.isfile() or member.name in files or not re.fullmatch(r"[A-Za-z0-9_.-]+", member.name):
            raise ValueError("unsafe or duplicate runtime package member")
        files[member.name] = archive.extractfile(member).read()
    pin = json.loads(files["pin.json"])
    provenance = json.loads(files["provenance.json"])
    receipt = json.loads(files["receipt.json"])
    required = {"firecracker", "jailer", "seccomp_filter.bpf", "seccomp-source.json",
                "provenance.json", "receipt.json", "pin.json", "series", "uapi-inputs.json",
                "LICENSE", "NOTICE", "THIRD-PARTY"} | {p["path"] for p in pin["series"]}
    if set(files) != required or any(not data for data in files.values()):
        raise ValueError("incomplete runtime package")
    if (provenance["status"] != "static-cli-candidate-built"
            or provenance["architecture"] != arch
            or provenance["target"] != arch + "-unknown-linux-musl"
            or provenance["base"] != pin["base"] or provenance["tree"] != pin["tree"]
            or provenance["series_sha256"] != pin["series_concatenated_sha256"]
            or receipt["status"] != "portable-validation-passed"
            or receipt["architecture"] != arch or receipt["base"] != pin["base"]
            or receipt["tree"] != pin["tree"] or receipt["toolchain"] != pin["toolchain"]):
        raise ValueError("runtime provenance or validation mismatch")
    expected = {name: provenance["binaries"][name] for name in ("firecracker", "jailer")}
    expected.update({"seccomp_filter.bpf": provenance["seccomp"]["compiled"],
                     "seccomp-source.json": provenance["seccomp"]["source"],
                     "uapi-inputs.json": provenance["uapi_inputs"],
                     "series": {"sha256": pin["series_file_sha256"]}})
    expected.update({p["path"]: p for p in pin["series"]})
    for name, record in expected.items():
        data = files[name]
        if hashlib.sha256(data).hexdigest() != record["sha256"] or len(data) != record.get("bytes", len(data)):
            raise ValueError("runtime digest mismatch: " + name)
    patches = pin["series"]
    if (files["series"].decode("ascii").splitlines() != [p["path"] for p in patches]
            or hashlib.sha256(b"".join(files[p["path"]] for p in patches)).hexdigest() != pin["series_concatenated_sha256"]):
        raise ValueError("runtime patch series mismatch")
    # No archive paths, links or modes are used. All checks precede the first write.
    root = Path(destination)
    root.mkdir(mode=0o700)
    for name, data in files.items():
        (root / name).write_bytes(data)
PY
}

# Each cached hash keeps referring to these bytes while an old daemon or builder finishes.
# Never overwrite an existing digest path, even on a same-version reinstall.
immutable_runtime() {
  local source=$1 name=$2 digest target temporary
  digest=$(sha256sum "$source" | awk '{print $1}') || fail "cannot hash runtime input"
  target="$runtime_root/$digest/$name"
  mkdir -p "$runtime_root/$digest" || fail "cannot create runtime directory"
  if [ -e "$target" ] || [ -L "$target" ]; then
    [ ! -L "$target" ] && echo "$digest  $target" | sha256sum -c --quiet - || fail "immutable runtime input differs: $target"
  else
    temporary=$(mktemp "$runtime_root/$digest/.stage.XXXXXX") || fail "cannot stage runtime input"
    install -m 0555 "$source" "$temporary" || { rm -f "$temporary"; fail "cannot install runtime input"; }
    echo "$digest  $temporary" | sha256sum -c --quiet - || { rm -f "$temporary"; fail "staged runtime digest differs"; }
    # A concurrent staging attempt may have installed the same bytes. Never replace them.
    if ! ln "$temporary" "$target" 2>/dev/null; then
      [ ! -L "$target" ] && echo "$digest  $target" | sha256sum -c --quiet - || { rm -f "$temporary"; fail "immutable runtime input differs"; }
    fi
    rm -f "$temporary"
  fi
  echo "$target"
}

runtime_config() {
  python3 - "$@" <<'PYCONFIG'
import json
from pathlib import Path
import sys
import yaml

path = Path(sys.argv[1])
text = path.read_bytes().decode("utf-8")
try:
    config = yaml.compose(text)
    tokens = list(yaml.scan(text))
except yaml.YAMLError:
    raise SystemExit("cannot parse runtime configuration") from None
if not isinstance(config, yaml.MappingNode) or config.flow_style:
    raise SystemExit("runtime paths require a block configuration mapping")
paths = dict(zip(("firecracker", "jailer", "kernel", "init"), sys.argv[2:]))
edits = []
seen = set()
for key, value in config.value:
    if not isinstance(key, yaml.ScalarNode):
        raise SystemExit("runtime configuration has a complex mapping key")
    if key.value == "<<":
        raise SystemExit("runtime paths cannot be updated through a root merge")
    if key.value not in paths:
        continue
    if key.value in seen:
        raise SystemExit("duplicate runtime path in configuration")
    seen.add(key.value)
    start, end = value.start_mark.index, value.end_mark.index
    # Aliases point to a different source span; anchors can be referenced by unrelated
    # fields. Refuse those cases rather than silently changing their meaning.
    if (not isinstance(value, yaml.ScalarNode) or start <= key.end_mark.index
            or "\n" in text[start:end] or "\r" in text[start:end]
            or any(isinstance(t, (yaml.AnchorToken, yaml.AliasToken))
                   and key.start_mark.index <= t.start_mark.index < end for t in tokens)):
        raise SystemExit("runtime paths must be unanchored single-line scalars")
    edits.append((start, end, json.dumps(paths[key.value])))
# Insert absent fields before an explicit document end, preserving every other byte.
missing = "".join(name + ": " + json.dumps(value) + "\n"
                  for name, value in paths.items() if name not in seen)
if missing:
    end = next((t.start_mark.index for t in tokens if isinstance(t, yaml.DocumentEndToken)), len(text))
    edits.append((end, end, ("" if end == 0 or text[end - 1] == "\n" else "\n") + missing))
for start, end, replacement in sorted(edits, reverse=True):
    text = text[:start] + replacement + text[end:]
try:
    yaml.compose(text)
except yaml.YAMLError:
    raise SystemExit("cannot preserve runtime configuration syntax") from None
path.write_bytes(text.encode("utf-8"))
PYCONFIG
}

# Writes the class into the config's `runtime_classes`: the whole block is replaced when it is
# there, appended when not. The class's files are immutable, so a new release is a new path.
runtime_class() {
  python3 - "$@" <<'PYCLASS'
import json
from pathlib import Path
import sys
import yaml

path, name, kernel, modules, release, versions = sys.argv[1:]
text = Path(path).read_bytes().decode("utf-8")
try:
    config = yaml.compose(text)
except yaml.YAMLError:
    raise SystemExit("cannot parse runtime configuration") from None
if not isinstance(config, yaml.MappingNode) or config.flow_style:
    raise SystemExit("runtime classes require a block configuration mapping")
block = "runtime_classes:\n  %s:\n" % name + "".join(
    "    %s: %s\n" % (k, json.dumps(v) if isinstance(v, str) else str(v).lower())
    for k, v in (("kernel", kernel), ("modules", modules), ("release", release),
                 ("versions", versions), ("nested", True)))
spans = [(k.start_mark.index, v.end_mark.index) for k, v in config.value
         if isinstance(k, yaml.ScalarNode) and k.value == "runtime_classes"]
if len(spans) > 1:
    raise SystemExit("duplicate runtime_classes in configuration")
if spans:
    start, end = spans[0]
    after = text[end:]
    text = text[:start] + block.rstrip("\n") + ("" if after.startswith("\n") else "\n") + after
else:
    text += ("" if not text or text.endswith("\n") else "\n") + block
try:
    yaml.compose(text)
except yaml.YAMLError:
    raise SystemExit("cannot preserve runtime configuration syntax") from None
Path(path).write_bytes(text.encode("utf-8"))
PYCLASS
}

runtime_kernel() {
  python3 - "$1" <<'PYKERNEL'
from pathlib import Path
import sys
import yaml

try:
    config = yaml.compose(Path(sys.argv[1]).read_text())
except yaml.YAMLError:
    raise SystemExit("cannot parse runtime configuration") from None
if not isinstance(config, yaml.MappingNode):
    raise SystemExit("configuration must be a mapping")
for key, value in config.value:
    if isinstance(key, yaml.ScalarNode) and key.value == "kernel":
        if not isinstance(value, yaml.ScalarNode):
            raise SystemExit("kernel path must be a scalar")
        print(value.value)
        break
else:
    print("/var/lib/briqyard/vmlinux")
PYKERNEL
}
# Inspect both the installed and candidate roots without opening or changing host state.
# Kept standalone: this gate must also protect stopped daemons and custom data_dir.
runtime_assignment_compatible() {
  python3 - "$@" <<'PYASSIGNMENT'
import json, os, pathlib, selectors, subprocess, sys, time
import yaml

def required(config):
    path = pathlib.Path(config)
    try:
        source = path.read_text()
    except FileNotFoundError:
        if path.is_symlink():
            raise ValueError("dangling configuration")
        return False
    value = yaml.safe_load(source)
    if not isinstance(value, dict):
        raise ValueError("invalid configuration mapping")
    # Do not let duplicate data_dir entries select an apparently empty root.
    node = yaml.compose(source)
    if sum(key.value == "data_dir" for key, _ in node.value) > 1:
        raise ValueError("duplicate data_dir")
    data = value.get("data_dir", "/var/lib/briqyard")
    if not isinstance(data, str) or not pathlib.Path(data).is_absolute():
        raise ValueError("invalid data_dir")
    root = pathlib.Path(data) / "state"
    floor = root / "meta/required-assignment-protocol.json"
    needed = 0
    try:
        marker = json.loads(floor.read_bytes())
    except FileNotFoundError:
        if floor.is_symlink():
            raise ValueError("dangling assignment floor")
    else:
        if marker == {"schema": 1, "protocol": "destination-assignment-v1"} and type(marker["schema"]) is int:
            needed = 1
        elif marker == {"schema": 2, "protocol": "assigned-run-v1"} and type(marker["schema"]) is int:
            needed = 2
        elif marker == {"schema": 3, "protocol": "assigned-run-lifecycle-v1"} and type(marker["schema"]) is int:
            needed = 3
        else:
            raise ValueError("invalid assignment protocol floor")
    runs = ("assigned-run-intents", "assigned-runs", "assigned-run-readers")
    for kind in ("unbound-assignments", "unbound-requests", "machines") + runs:
        try:
            entries = list((root / kind).iterdir())
        except FileNotFoundError:
            if (root / kind).is_symlink():
                raise ValueError("dangling assignment state directory")
            continue
        for entry in entries:
            if entry.suffix != ".json":
                continue
            record = json.loads(entry.read_bytes())
            if not isinstance(record, dict):
                raise ValueError("invalid assignment state record")
            if kind in runs:
                if type(record.get("schema")) is not int or record["schema"] not in (1, 3):
                    raise ValueError("unsupported assigned run evidence schema")
                needed = max(needed, 3 if record["schema"] == 3 else 2)
            elif kind != "machines":
                receipt = record.get("receipt") if kind == "unbound-assignments" else record
                if not isinstance(receipt, dict) or type(receipt.get("schema")) is not int or receipt["schema"] != 1:
                    raise ValueError("invalid assignment receipt schema")
                needed = max(needed, 1)
            elif record.get("assigned_run") is not None:
                run = record["assigned_run"]
                if (not isinstance(run, dict) or set(run) != {"schema", "sequence", "phase"}
                        or type(run.get("schema")) is not int or run["schema"] not in (1, 3)
                        or type(run.get("sequence")) is not int or run["sequence"] <= 0
                        or run.get("phase") not in (("reserved", "observed", "settled") if run["schema"] == 3 else ("reserved", "observed"))):
                    raise ValueError("unsupported assigned run record link")
                needed = max(needed, 3 if run["schema"] == 3 else 2)
            elif record.get("launch_identity") is not None:
                warm = record.get("warm_slot")
                if warm is not None and not isinstance(warm, dict):
                    raise ValueError("invalid warm slot")
                if isinstance(warm, dict) and warm.get("claimed") is not None:
                    needed = max(needed, 1)
    return needed

def probe(binary, command, expected):
    child = subprocess.Popen([binary, command], stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        selector = selectors.DefaultSelector()
        selector.register(child.stdout, selectors.EVENT_READ)
        output = b""
        deadline = time.monotonic() + 5
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise ValueError("assignment capability probe timeout")
            chunk = os.read(child.stdout.fileno(), 128 - len(output))
            if not chunk:
                break
            output += chunk
            if len(output) >= 128:
                raise ValueError("assignment capability output too long")
        if output != expected or child.wait(timeout=max(.001, deadline - time.monotonic())) != 0:
            raise ValueError("candidate lacks destination assignment support")
    finally:
        if child.poll() is None:
            child.kill()
        child.wait()
        child.stdout.close()
        selector.close()
try:
    # Evaluate every root even after one requires support: malformed roots fail closed.
    states = [required(config) for config in sys.argv[2:] if config]
    # Every managed replacement needs the complete current protocol. State can
    # advance after this inspection, including while the daemon starts or restarts.
    probe(sys.argv[1], "assignment-capabilities", b"destination-assignment-v1\n")
    probe(sys.argv[1], "assigned-run-capabilities", b"assigned-run-v1\n")
    probe(sys.argv[1], "assigned-run-lifecycle-capabilities", b"assigned-run-lifecycle-v1\n")
except Exception:
    print("assignment compatibility inspection/probe refused replacement", file=sys.stderr)
    sys.exit(1)
PYASSIGNMENT
}
# A failed activation restores installed executables before leaving the old daemon running.
# The verified rollback directory also remains available for an explicit later rollback.
cleanup_runtime_install() {
  local result=$? b restored=1 retained_sha
  trap - EXIT
  if [ "$result" != 0 ] && [ "$activation_pending" = 1 ] && [ "$rollback_ready" = 1 ]; then
    retained_sha=$(sha256sum "$rollback/briqyardd" | awk '{print $1}') || retained_sha=""
    if [ -z "$retained_sha" ] || ! runtime_assignment_compatible "$rollback/briqyardd" "$config_path" "$rollback/config.yaml" ||
       ! echo "$retained_sha  $rollback/briqyardd" | sha256sum -c --quiet -; then
      echo "   activation failed; retained daemon is incompatible with current state; compatible replacement left installed ($rollback)" >&2
      rm -rf "$new"
      [ -z "$candidate" ] || rm -f "$candidate"
      exit "$result"
    fi
    for b in briqyard briqyard-fleet briqyardd; do
      if [ -f "$rollback/$b" ]; then
        cp -p "$rollback/$b" "$binary_dir/$b.rollback" && mv -f "$binary_dir/$b.rollback" "$binary_dir/$b" || restored=0
      fi
    done
    if ! cmp -s "$rollback/config.yaml" "$config_path"; then
      cp -p "$rollback/config.yaml" "$config_path.rollback" && mv -f "$config_path.rollback" "$config_path" || restored=0
    fi
    if [ "$restored" = 0 ]; then
      echo "   activation failed; automatic restoration incomplete: retained rollback at $rollback" >&2
    else
      echo "   activation failed; previous executables and configuration restored ($rollback)" >&2
    fi
  fi
  rm -rf "$new"
  [ -z "$candidate" ] || rm -f "$candidate"
  if [ -n "$rollback" ] && [ "$rollback_ready" = 0 ]; then rm -rf "$rollback"; fi
  exit "$result"
}
# End runtime installation helpers.

# A request to GitHub's API with BRIQYARD_RELEASE_TOKEN, the token on stdin, off the command line.
github() { printf 'Authorization: Bearer %s\n' "$RELEASE_TOKEN" | curl -fsSL -H @- "$@"; }

# A file of the release. With BRIQYARD_RELEASE_TOKEN, through GitHub's API: a private
# repository's assets are not served at their download URL.
# `assets` is the release's JSON from GitHub's API, read once below when there is a token.
release_file() {
  local name=$1 dest=$2 id
  if [ -z "$RELEASE_TOKEN" ]; then curl -fsSL -o "$dest" "$RELEASE/$name"; return; fi
  id=$(jq -r --arg n "$name" '.assets[] | select(.name == $n) | .id' <<<"$assets")
  [ -n "$id" ] || fail "release $tag of $repo has no $name"
  github -H "Accept: application/octet-stream" -o "$dest" "https://api.github.com/repos/$repo/releases/assets/$id"
}

echo "== binaries${RELEASE:+ from $RELEASE}"
# Serialize preflight, rollback capture, replacement, handover and EXIT cleanup.
runtime_install_lock /etc/briqyard
new=$(mktemp -d)
chmod 0700 "$new"
candidate=""
rollback=""
rollback_ready=0
activation_pending=0
config_path=/etc/briqyard/config.yaml
binary_dir=/usr/local/bin
trap cleanup_runtime_install EXIT
if [ -n "$RELEASE" ]; then
  if [ -n "$RELEASE_TOKEN" ]; then
    repo=${RELEASE#https://github.com/}; tag=${repo##*/releases/download/}; repo=${repo%%/releases/download/*}
    [ "$repo" != "$tag" ] || fail "BRIQYARD_RELEASE=$RELEASE: with a token, a GitHub release (https://github.com/<owner>/<repo>/releases/download/<tag>)"
    assets=$(github "https://api.github.com/repos/$repo/releases/tags/$tag")
  fi
  release_file "SHA256SUMS-$ARCH" "$new/SHA256SUMS"
  # Check the complete release before staging any executable or changing configuration.
  for b in briqyardd briqyard-init briqyard briqyard-fleet firecracker-checked; do
    asset="$b-linux-$ARCH"
    [ "$b" != firecracker-checked ] || asset="$asset.tar.gz"
    release_file "$asset" "$new/$b"
    sha=$(awk -v f="$asset" '$2 == f {print $1}' "$new/SHA256SUMS")
    [[ "$sha" =~ ^[a-f0-9]{64}$ ]] && echo "$sha  $new/$b" | sha256sum -c --quiet - 2>/dev/null || fail "$asset: digest differs from the release's SHA256SUMS-$ARCH"
  done
  if [ "$NESTED" = 1 ]; then
    for asset in nested-vmlinux-x86_64 nested-modules-x86_64.ext4 nested-versions-x86_64.json; do
      release_file "$asset" "$new/$asset"
      sha=$(awk -v f="$asset" '$2 == f {print $1}' "$new/SHA256SUMS")
      [[ "$sha" =~ ^[a-f0-9]{64}$ ]] && echo "$sha  $new/$asset" | sha256sum -c --quiet - 2>/dev/null || fail "$asset: digest differs from the release's SHA256SUMS-$ARCH"
    done
  fi
  checked_bundle "$new/firecracker-checked" "$ARCH" "$new/checked"
  cp "$new/checked/firecracker" "$new/firecracker"
  cp "$new/checked/jailer" "$new/jailer"
else
  for b in briqyardd briqyard-init briqyard briqyard-fleet; do cp "bin/$b" "$new/$b"; done
  # Local development keeps the pinned upstream runtime; release installs require checked assets.
  fetch "https://github.com/firecracker-microvm/firecracker/releases/download/${FIRECRACKER_VERSION}/firecracker-${FIRECRACKER_VERSION}-${ARCH}.tgz" "$FIRECRACKER_SHA256" "$new/firecracker.tgz"
  tar -xz -C "$new" -f "$new/firecracker.tgz"
  cp "$new/release-${FIRECRACKER_VERSION}-${ARCH}/firecracker-${FIRECRACKER_VERSION}-${ARCH}" "$new/firecracker"
  cp "$new/release-${FIRECRACKER_VERSION}-${ARCH}/jailer-${FIRECRACKER_VERSION}-${ARCH}" "$new/jailer"
fi
chmod 0755 "$new"/briq*
runtime_root=/usr/local/lib/briqyard/runtime
firecracker=$(immutable_runtime "$new/firecracker" firecracker)
jailer=$(immutable_runtime "$new/jailer" jailer)
init=$(immutable_runtime "$new/briqyard-init" briqyard-init)
# Keep the configured kernel path when its digest is unchanged. Never replace its bytes.
kernel=/var/lib/briqyard/vmlinux
if [ -f /etc/briqyard/config.yaml ]; then
  kernel=$(runtime_kernel /etc/briqyard/config.yaml)
fi
if ! echo "$KERNEL_SHA256  $kernel" | sha256sum -c --quiet - 2>/dev/null; then
  fetch "$KERNEL_URL" "$KERNEL_SHA256" "$new/vmlinux"
  kernel=$(immutable_runtime "$new/vmlinux" vmlinux)
fi

# The nested class's files, immutable like the runtime's: by digest under the class's directory.
if [ "$NESTED" = 1 ]; then
  runtime_root=/var/lib/briqyard/classes/nested
  class_kernel=$(immutable_runtime "$new/nested-vmlinux-x86_64" vmlinux)
  class_modules=$(immutable_runtime "$new/nested-modules-x86_64.ext4" modules.ext4)
  class_versions=$(immutable_runtime "$new/nested-versions-x86_64.json" versions.json)
  runtime_root=/usr/local/lib/briqyard/runtime
  class_release=$(jq -r .kernel_release "$new/nested-versions-x86_64.json")
  [ -n "$class_release" ] && [ "$class_release" != null ] || fail "nested-versions-x86_64.json has no kernel_release"
  echo "   nested: kernel $class_release, OpenZFS $(jq -r .openzfs "$new/nested-versions-x86_64.json")"
fi

echo "== config"
mkdir -p /etc/briqyard
chmod 0700 /etc/briqyard
candidate=$(mktemp /etc/briqyard/.config.XXXXXX)
if [ -f /etc/briqyard/config.yaml ]; then
  cp /etc/briqyard/config.yaml "$candidate"
else
  key_source=fleet
  [ -n "$FLEET_URL" ] || key_source="file:$KEY_FILE"
  cat > "$candidate" <<EOF
listen: $bind:${LISTEN##*:}
token: "$API_TOKEN"
data_dir: /var/lib/briqyard
firecracker: $firecracker
jailer: $jailer
kernel: $kernel
init: $init
root_disk_gb: 8
storage:
  backend: zfs
  pool: $POOL
  key: $key_source
network:
  range: 10.64.0.0/10
${PUBLIC_TCP_PORTS:+  host_ports: [${PUBLIC_TCP_PORTS//,/, }]}
ingress:
  bind: $bind
  http: $bind:8080
  domain: byard.localhost
EOF
  [ -z "$clients" ] || echo "$clients" >> "$candidate"
  if [ -n "$FLEET_URL" ]; then
    cat >> "$candidate" <<EOF
fleet:
  url: $FLEET_URL
  advertise: $advertise
EOF
  fi
fi
# One candidate contains all changed launch paths. Validate it with the staged daemon.
runtime_config "$candidate" "$firecracker" "$jailer" "$kernel" "$init"
[ "$NESTED" = 0 ] || runtime_class "$candidate" nested "$class_kernel" "$class_modules" "$class_release" "$class_versions"
chmod 0600 "$candidate"
daemon_sha=$(sha256sum "$new/briqyardd" | awk '{print $1}')
runtime_assignment_compatible "$new/briqyardd" "$config_path" "$candidate" || fail "assignment state requires a compatible daemon: nothing activated"
fingerprint=$("$new/briqyardd" --config "$candidate" tls-fingerprint) || fail "the new briqyardd refuses the staged configuration: nothing activated"
# Retain a complete rollback set before the first installed executable changes. Its
# checksums cover the exact prior configuration and executables, including the daemon.
if [ -f "$config_path" ]; then
  rollback=$(mktemp -d /etc/briqyard/rollback.XXXXXX)
  retained=(config.yaml)
  cp -p "$config_path" "$rollback/config.yaml"
  cmp -s "$config_path" "$rollback/config.yaml" || fail "configuration changed while retaining rollback"
  for b in briqyard briqyard-fleet briqyardd; do
    if [ -f "$binary_dir/$b" ]; then
      cp -p "$binary_dir/$b" "$rollback/$b"
      cmp -s "$binary_dir/$b" "$rollback/$b" || fail "installed executable changed while retaining rollback"
      retained+=("$b")
    fi
  done
  (cd "$rollback" && sha256sum "${retained[@]}" > SHA256SUMS && sha256sum -c --quiet SHA256SUMS)
  config_sha=$(sha256sum "$rollback/config.yaml" | awk '{print $1}')
  backup="/etc/briqyard/config.yaml.before-$config_sha"
  if [ -e "$backup" ]; then
    cmp -s "$rollback/config.yaml" "$backup" || fail "retained configuration backup differs"
  else
    cp -p "$rollback/config.yaml" "$backup"
  fi
  rollback_ready=1
  echo "   previous executables and configuration retained at $rollback"
fi
# Init and runtime inputs stay immutable. The old daemon may still read them.
echo "$daemon_sha  $new/briqyardd" | sha256sum -c --quiet - || fail "staged daemon changed after compatibility checks: nothing activated"
activation_pending=1
for b in briqyard briqyard-fleet briqyardd; do put "$new/$b" "$binary_dir/$b"; done
# The rename is on the configuration filesystem, before the existing SIGUSR2 handover.
mv -f "$candidate" "$config_path"
candidate=""

echo "== api certificate"
# Made here, before the daemon starts, so it is there to read; kept across runs. It is also the
# new binary reading the configuration: one it refuses stops here, before any hand-over, and the
# running daemon goes on (ADR 0027).

if [ -n "$fingerprint" ]; then
  echo "   sha256 $fingerprint: the fleet pins it (tls_fingerprint)"
else
  echo "   none: the API is plain HTTP (a loopback listen, or api_tls: false)"
fi
# The store of listening sockets holds the API's, the HTTP ingress's and one per TCP endpoint
# (ADR 0051): the endpoint range and two. A range made larger later needs this run again: past
# the store's size systemd refuses a socket, and that endpoint is refused while no daemon runs.
range=$(awk '/^  tcp_ports:/ {gsub(/["\047 ]/, "", $2); print $2}' /etc/briqyard/config.yaml)
range=${range:-30000-32767}
store_max=$(( ${range#*-} - ${range%-*} + 3 ))
# A host with a tunnel starts the daemon after it: the pool key is asked over it (ADR 0113).
tunnel_unit=; [ ! -f $TUNNEL_CONF ] || tunnel_unit=" wg-quick@$TUNNEL.service"
cat > /etc/systemd/system/briqyardd.service <<EOF
[Unit]
Description=briqyard host daemon
After=network-online.target zfs.target$tunnel_unit
Wants=network-online.target$tunnel_unit

[Service]
OOMScoreAdjust=-900
OOMPolicy=continue
ExecStart=/usr/local/bin/briqyardd --config /etc/briqyard/config.yaml
# Only the daemon gets the signal: the machines (Firecracker processes in this cgroup) outlive
# it. A stop (SIGTERM) suspends them, and the next start boots them again; SIGUSR2 (an upgrade)
# leaves them running for the next daemon to adopt; a crash leaves them too (ADR 0027).
KillMode=process
Restart=on-failure
# At once: a crash loop still ends at StartLimitBurst (5 starts in 10 s), which releases the
# store below, and the clients it queued are reset.
RestartSec=0
# A hand-over exits 75: started again at once, not a failure. systemd keeps the store of
# listening sockets across a restart, so the kernel queues what arrives in between (ADR 0051).
SuccessExitStatus=75
RestartForceExitStatus=75
NotifyAccess=main
FileDescriptorStoreMax=$store_max
LimitNOFILE=65536
# A core dump of a Firecracker would be its guest's memory, on / in clear (ADR 0026).
LimitCORE=0
Environment=BRIQYARD_LOG=info
# Credentials (BRIQYARD_S3_ACCESS_KEY, BRIQYARD_S3_SECRET_KEY), root's alone, when there is one;
# written by the operator, read at the next start: a hand-over, never a restart (ADR 0041).
EnvironmentFile=-/etc/briqyard/briqyardd.env

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable briqyardd >/dev/null
# A running daemon hands its machines over (SIGUSR2, ADR 0027) and exits 75, on which the unit
# starts the new one at once, the listeners kept (ADR 0051); the new one adopts the machines. The
# start below covers a daemon from before ADR 0051, which exits 0. `systemctl restart` would
# suspend every machine instead.
# Keep automatic recovery armed until the old daemon exits: a refused handover
# must restore a currently compatible executable before this installer returns.
pid=$(systemctl show -p MainPID --value briqyardd)
if [ "${pid:-0}" != 0 ]; then
  echo "== handing the machines over to the new daemon"
  systemctl kill --kill-whom=main --signal=SIGUSR2 briqyardd
  for _ in $(seq 1 120); do [ "$(systemctl show -p MainPID --value briqyardd)" = "$pid" ] || break; sleep 1; done
  [ "$(systemctl show -p MainPID --value briqyardd)" != "$pid" ] || { echo "   briqyardd (pid $pid) did not exit within 120 s"; exit 1; }
fi
activation_pending=0
systemctl start briqyardd
sleep 1
systemctl --no-pager --lines=2 status briqyardd | grep -E "Active|listening" || true
echo "== done: $(/usr/local/bin/briqyardd --version)"

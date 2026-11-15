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

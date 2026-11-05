#!/usr/bin/env bash
# The part of hack/native-ci-nested.sh that runs inside the `nested` machine, as root. The
# machine's PID 1 is briqyard's init, which stays (exec and files reach it over vsock). The host
# the daemon needs is built beside it: systemd as PID 1 of namespaces of its own, as a privileged
# container runs it (stage systemd), and in there the real install path, hack/bootstrap-host.sh
# then hack/install-dev.sh, so that briqyardd starts under its unit and passes its startup
# barrier (ADR 0068) as on a server.
# By hand in a briq kvm sandbox: docs/DEVELOPMENT.md.
# Stages: build, systemd, host, fleet, e2e, events, cargotest, stop, teardown. `run STAGE` runs one
# detached and leaves its output in /work/logs/STAGE.log and its exit status in STAGE.rc; the
# stages that need the unit enter the namespaces of systemd with nsenter.
set -euo pipefail
export PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export CARGO_HOME=/work/cargo CARGO_TARGET_DIR=/work/target TMPDIR=/work/tmp
L=/work/logs
SRC=/work/src
mkdir -p "$L" "$TMPDIR" "$CARGO_HOME"
# BUNDLE_SHA256, the digest of the checked Firecracker bundle, written by the caller.
[ ! -f /work/inner.env ] || . /work/inner.env
BUNDLE=firecracker-checked-linux-x86_64.tar.gz
# The stages that run in the namespaces of systemd.
IN_UNIT_STAGES=" host fleet e2e events "

# An environment finding: what was looked for and the exact error when it is missing. A probe
# never stops the stage: the daemon's own start is the verdict, the probes say what to fix.
MISSING=0
probe() {
  local name=$1 out; shift
  if out=$("$@" 2>&1); then echo "probe ok       $name"; else
    MISSING=$((MISSING + 1)); echo "probe MISSING  $name: $* -> $(echo "$out" | head -n 3 | tr '\n' ' ')"
  fi
}

# Runs a command in the namespaces of systemd.
in_unit() { nsenter -t "$(cat "$L/systemd.pid")" -a "$@"; }

stage_build() {
  echo $$ > "$L/build.pid"
  cd "$SRC"
  rustc --version; cargo --version; nproc; free -m | sed -n 2p
  cargo build --release --locked --workspace --exclude briqyard-init
  cargo build --release --locked -p briqyard-init --target x86_64-unknown-linux-musl
  ls -l "$CARGO_TARGET_DIR/release/briqyardd" "$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release/briqyard-init"
}

# systemd as PID 1 of its own pid, mount and cgroup namespaces, with /run and /run/lock as tmpfs
# and cgroup2 mounted again at /sys/fs/cgroup, so that systemd sees its own root and a unit's
# ControlGroup reads /system.slice/NAME.service. The network, /dev and /sys are the machine's.
stage_systemd() {
  export DEBIAN_FRONTEND=noninteractive
  echo "== the sandbox before: init, udev, systemd"
  ps -o pid,args -p 1 | cat
  echo "/sbin/init before: $(readlink -f /sbin/init)"
  ps -eo pid,args | grep -E '[u]devd|[s]ystemd' || echo "no udevd or systemd process"
  apt-get update -qq
  # No systemd-sysv: /sbin/init stays what it is. The image has to carry what is installed here.
  apt-get install -y -qq --no-install-recommends systemd dbus dbus-daemon sudo openssh-server bc openssl jq \
    python3 python3-yaml curl ca-certificates > /dev/null
  echo "/sbin/init after: $(readlink -f /sbin/init)"
  test -x /usr/lib/systemd/systemd
  # What a server decides elsewhere and a container has no use for, and what would run apt
  # beside the install.
  for u in systemd-networkd.service systemd-networkd.socket systemd-networkd-wait-online.service systemd-resolved.service \
    systemd-udevd.service systemd-udevd-control.socket systemd-udevd-kernel.socket \
    systemd-timesyncd.service apt-daily.timer apt-daily-upgrade.timer apt-daily.service apt-daily-upgrade.service; do
    ln -sf /dev/null "/etc/systemd/system/$u"
  done
  # The volume holds /var/lib/briqyard: the pool and the daemon's state stay off the root
  # filesystem. Bound in the machine's own mount namespace, not in systemd's: ZFS opens the
  # pool's file from kernel threads, which see only the machine's.
  mkdir -p /work/lib/briqyard /var/lib/briqyard
  mountpoint -q /var/lib/briqyard || mount --bind /work/lib/briqyard /var/lib/briqyard
  # udev answers for the zvols (their links in /dev/zvol): the machine's own udevd does, and its
  # state in /run/udev is bound into the namespaces, where systemd-udevd is masked above (it
  # starts in a container too). One udevd, one database.
  echo "== cgroups the sandbox sees"
  cat /proc/self/cgroup; grep cgroup /proc/self/mountinfo; readlink /proc/self/ns/cgroup /proc/1/ns/cgroup
  rm -f "$L/systemd.pid"
  setsid unshare --pid --fork --mount --cgroup --mount-proc bash -c '
    set -e
    mkdir -p /work/oldrun
    mount --rbind /run /work/oldrun
    mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /run
    mkdir -p /run/lock /run/udev
    mount -t tmpfs tmpfs /run/lock
    mount --bind /work/oldrun/udev /run/udev
    umount -l /work/oldrun
    # The cgroup tree as this namespace sees it, writable, for systemd.
    if ! mount -t cgroup2 none /sys/fs/cgroup; then
      echo "mounting cgroup2 failed; unmounting the sandbox mount and mounting again"
      umount /sys/fs/cgroup
      mount -t cgroup2 none /sys/fs/cgroup
    fi
    # In a container systemd leaves / as it finds it, here private. Shared, as on a server: a
    # sandboxed unit (the mirror) then follows a machine'"'"'s unmount instead of keeping a copy of
    # the mount, which leaves the dataset busy.
    mount --make-rshared /
    exec env container=lxc /usr/lib/systemd/systemd --unit=multi-user.target
  ' > "$L/systemd-start.log" 2>&1 < /dev/null &
  echo $! > "$L/unshare.pid"
  local pid=
  for _ in $(seq 1 60); do
    pid=$(pgrep -o -x systemd || true)
    [ -z "$pid" ] || break
    kill -0 "$(cat "$L/unshare.pid")" 2> /dev/null || break
    sleep 1
  done
  [ -n "$pid" ] || { echo "systemd did not start:"; cat "$L/systemd-start.log"; return 1; }
  grep NSpid "/proc/$pid/status"
  [ "$(awk '/^NSpid/ {print $NF}' "/proc/$pid/status")" = 1 ] || { echo "pid $pid is not the init of a pid namespace"; return 1; }
  echo "$pid" > "$L/systemd.pid"
  # Up when no job is queued: running, or degraded by units a container cannot run.
  local state
  state=$(in_unit timeout 300 systemctl is-system-running --wait || true)
  echo "systemd: $state"
  in_unit systemctl --no-pager --failed || true
  in_unit bash -c 'cat /proc/1/cgroup; systemd-detect-virt; ls -l /run/udev | head -n 5'
  [ "$state" = running ] || [ "$state" = degraded ]
}

# In the namespaces of systemd: the environment probes, then what a server gets: the bootstrap
# with this build's binaries, the configuration the native suites use, install-dev.sh.
stage_host() {
  echo $$ > "$L/host.pid"
  # Whatever stops this stage, the units' own words come out with it.
  trap 'rc=$?; [ "$rc" = 0 ] || { echo "---- journal of the units"; journalctl -u briqyardd -u briqyard-fleet --no-pager -n 50 | cut -c1-400; }' EXIT
  echo "== what a host needs"
  uname -r
  echo "== virtualization the sandbox sees"
  grep -m1 '^model name' /proc/cpuinfo
  grep -m1 '^flags' /proc/cpuinfo | tr ' ' '\n' | grep -E '^(vmx|ept|vpid|ept_ad|ept_1gb|vnmi|flexpriority|tpr_shadow|vmcs_shadowing|apicv|svm|npt|nrip_save|avic|aes|avx2)$' | paste -sd' ' - || true
  echo "kvm: $(for p in /sys/module/kvm_intel/parameters/* /sys/module/kvm_amd/parameters/*; do [ -f "$p" ] && echo "$(basename "$p")=$(cat "$p" 2> /dev/null)"; done | paste -sd' ' - | cut -c1-600 || true)"
  echo "pid_max=$(cat /proc/sys/kernel/pid_max) threads-max=$(cat /proc/sys/kernel/threads-max)"
  probe "/dev/kvm" test -c /dev/kvm
  probe "/dev/net/tun" test -c /dev/net/tun
  probe "zfs module" test -e /sys/module/zfs
  probe "cgroup v2" test -f /sys/fs/cgroup/cgroup.controllers
  for c in cpu cpuset io memory pids; do
    probe "cgroup controller $c available" grep -qw "$c" /sys/fs/cgroup/cgroup.controllers
  done
  probe "a cgroup can be made" bash -c 'mkdir /sys/fs/cgroup/bqprobe && rmdir /sys/fs/cgroup/bqprobe'
  probe "ip_forward can be set" bash -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
  probe "bridge" bash -c 'ip link add bqprobe0 type bridge && ip link del bqprobe0'
  probe "veth" bash -c 'ip link add bqprobe1 type veth peer name bqprobe2 && ip link del bqprobe1'
  probe "tap" bash -c 'ip tuntap add dev bqprobe3 mode tap && ip link del bqprobe3'
  cat > "$TMPDIR/bq-inet.nft" <<'NFT'
table inet bqprobe {
  limit l { rate 10 mbytes/second }
  chain f { type filter hook forward priority 0; policy accept; ct state established,related accept; ip saddr 10.9.9.9 reject with tcp reset; fib saddr . iif oif missing drop; limit name "l" drop; counter; }
  chain n { type nat hook postrouting priority 100; policy accept; ip saddr 10.9.9.0/24 masquerade; }
}
NFT
  cat > "$TMPDIR/bq-bridge.nft" <<'NFT'
table bridge bqprobe {
  chain f { type filter hook forward priority 0; policy accept; meta ibrname "bqx" accept; ether type arp arp operation request accept; }
}
NFT
  probe "nft: inet filter, nat, reject, limit, fib, ct" bash -c "nft -f $TMPDIR/bq-inet.nft && nft delete table inet bqprobe"
  probe "nft: bridge meta ibrname, arp" bash -c "nft -f $TMPDIR/bq-bridge.nft && nft delete table bridge bqprobe"
  probe "namespaces (mount, pid)" unshare --mount --pid --fork true
  probe "mknod" bash -c 'mknod /work/tmp/bqnull c 1 3 && rm /work/tmp/bqnull'
  echo "== probes missing: $MISSING"

  echo "== the release: this build's binaries and the checked Firecracker bundle"
  local R=/work/release T=$CARGO_TARGET_DIR b rc
  rm -rf "$R"; mkdir -p "$R"
  for b in briqyardd briqyard briqyard-fleet; do cp "$T/release/$b" "$R/$b-linux-x86_64"; done
  cp "$T/x86_64-unknown-linux-musl/release/briqyard-init" "$R/briqyard-init-linux-x86_64"
  cp /work/fc-bundle.tgz "$R/$BUNDLE"
  echo "$BUNDLE_SHA256  $R/$BUNDLE" | sha256sum -c -
  (cd "$R" && sha256sum -- briq*-linux-* "$BUNDLE" > SHA256SUMS-x86_64)

  echo "== hack/bootstrap-host.sh"
  cd "$SRC"
  env BRIQYARD_RELEASE="file://$R" BRIQYARD_POOL_FILE_GB=16 BRIQYARD_ARC_GB=1 LISTEN=127.0.0.1:7420 \
    bash hack/bootstrap-host.sh || { rc=$?; journalctl -u briqyardd --no-pager -n 60 | cut -c1-300; return "$rc"; }

  echo "== the configuration the native suites use (hack/native-ci.sh)"
  python3 - <<'PY'
from pathlib import Path
import yaml
p = Path('/etc/briqyard/config.yaml')
c = yaml.safe_load(p.read_text())
c['backup'] = {'store': 'file:///var/lib/briqyard/backups'}
c['network']['host_ports'] = [9443]
# The sandbox's own address is in the host's machine range, 10.64.0.0/10. The inner machines take
# a range inside the 10.64 to 10.69 that hack/e2e*.sh expects, clear of the sandbox's own subnet.
c['network']['range'] = '10.66.0.0/15'
c['ingress'].update(tcp_ports='30000-32767', http='127.0.0.1:8080', advertise='127.0.0.1')
c['registry_mirrors'] = {'docker.io': 'http://127.0.0.1:7440'}
c['capacity'] = {'memory_mb': 6144, 'vcpus': 12}
# Machines of a third level boot far slower than the dev VM's (docs/adr/0089): a boot is bounded at 15 minutes.
c['boot_timeout_sec'] = 900
p.write_text(yaml.safe_dump(c, sort_keys=False).replace('  host_ports:\n  - 9443\n', '  host_ports: [9443]\n'))
PY
  cat > "$TMPDIR/native-fleet.yaml" <<'YAML'
listen: 127.0.0.1:7430
tls: off
state_dir: /var/lib/briqyard-fleet
hosts:
  - id: local
    url: http://127.0.0.1:7420
    region: dev
placement:
  fill_ceiling: 0.85
  down_after_sec: 60
YAML
  systemctl stop briqyardd
  systemctl start ssh
  echo "== hack/install-dev.sh"
  env FLEET_CONFIG="$TMPDIR/native-fleet.yaml" bash hack/install-dev.sh "$CARGO_TARGET_DIR" "$R/$BUNDLE" "$BUNDLE_SHA256" "$SRC"
  local up=0
  for _ in $(seq 1 120); do
    if briqyard status > /dev/null 2>&1 && curl -fsS http://127.0.0.1:7430/v1/hosts | jq -e 'length == 1 and all(.state == "ready")' > /dev/null; then up=1; break; fi
    sleep 1
  done
  if [ "$up" != 1 ]; then
    echo "the daemons did not become ready:"
    systemctl --no-pager status briqyardd briqyard-fleet | cut -c1-300 || true
    journalctl -u briqyardd -u briqyard-fleet --no-pager -n 60 | cut -c1-300
    return 1
  fi
  systemctl show -p Id,ControlGroup,FragmentPath,MainPID briqyardd
  echo "bridge-nf: $(cat /proc/sys/net/bridge/bridge-nf-call-iptables 2>&1)"
  s=$(date +%s.%N); systemctl show --value --property=ManagedOOMSwap -- -.slice system.slice briqyardd.service > /dev/null
  echo "systemctl show, idle: $(awk -v a="$s" -v b="$(date +%s.%N)" 'BEGIN{printf "%.2f", b-a}') s"
  briqyard status | jq -c .
  briqyard doctor || true
}

# The stages below record their pid for `stop`: the suites end what they started on a TERM.
stage_fleet() {
  cd "$SRC"
  echo $$ > "$L/fleet.pid"
  exec bash hack/fleet-smoke.sh
}

stage_e2e() {
  cd "$SRC"
  echo $$ > "$L/e2e.pid"
  # The time a `systemctl show` takes while the suite runs: the daemon gives one 3 s. The
  # same call as the daemon's (memory_host.rs), with its state when it takes long: the bound
  # is the daemon's, a sample past it is not stopped here.
  # The first call is the oomd check's, the second the ancestry's (the daemon makes both, five
  # calls in all).
  ( while kill -0 $$ 2> /dev/null; do
      s=$(date +%s.%N); systemctl show --value --property=LoadState -- systemd-oomd.service systemd-oomd.socket > /dev/null 2>&1; rc=$?
      m=$(date +%s.%N); systemctl show --value --property=ManagedOOMSwap -- -.slice system.slice > /dev/null 2>&1; rc="$rc,$?"
      e=$(date +%s.%N)
      echo "$(date +%T) systemctl show $(awk -v a="$s" -v b="$m" 'BEGIN{printf "%.2f", b-a}') s, $(awk -v a="$m" -v b="$e" 'BEGIN{printf "%.2f", b-a}') s, rc $rc, load $(cut -d' ' -f1-3 /proc/loadavg), systemd $(awk '{print $3}' /proc/1/stat 2>/dev/null)"
      sleep 5
    done > "$L/systemctl-latency.log" 2>&1 ) &
  # The levels' network, for a request that did not answer: the MTU of every interface here
  # and the resolver.
  echo "e2e start: $(ip -o link show | awk '{printf "%s mtu %s; ", $2, $5}')"
  echo "e2e start: resolv.conf $(grep -v '^#' /etc/resolv.conf | paste -sd' ' -)"
  # `briqyard` as the suites call it, timed: every call's start, duration and status in
  # briqyard-calls.log, and the answer of the iron-proxy requests (a machine's exec through
  # the gateway) in iron-answers.log. The suites' assertions are not touched.
  mkdir -p "$TMPDIR/shim"
  cat > "$TMPDIR/shim/briqyard" <<SHIM
#!/bin/bash
real=$(command -v briqyard)
# A session or a stream is the suite's to signal: it takes the client's place (exec), unwatched.
case " \$* " in
  *" -i "* | *" -it "* | *" -t "* | *--watch* | *" -f "* | *" logs "*) exec "\$real" "\$@" ;;
esac
t0=\$EPOCHREALTIME
case "\$*" in
  *https_proxy=http://gateway.internal:3128*)
    out=\$("\$real" "\$@" 2>&1); rc=\$?
    echo "\$(date +%T) rc \$rc: \$(printf '%s' "\$out" | head -c 600 | tr '\n' ' ')" >> "$L/iron-answers.log"
    printf '%s\n' "\$out"
    ;;
  *) "\$real" "\$@"; rc=\$? ;;
esac
echo "\$(date +%T) \$(awk -v a="\$t0" -v b="\$EPOCHREALTIME" 'BEGIN{printf "%.2f", b-a}') s rc \$rc: \${*:1:10}" >> "$L/briqyard-calls.log"
# A destroy that failed: who holds the machine's datasets (until two dumps are kept).
if [ "\$rc" != 0 ] && [ "\${1:-} \${2:-}" = "machine rm" ] && [ "\$(wc -l < "$L/holders.log" 2>/dev/null || echo 0)" -lt 60 ]; then
  bash "$SRC/hack/native-ci-nested-holders.sh" "\$3" >> "$L/holders.log" 2>&1
fi
exit \$rc
SHIM
  chmod +x "$TMPDIR/shim/briqyard"
  export PATH="$TMPDIR/shim:$PATH"
  exec bash hack/e2e.sh
}

# After the e2e: the readiness events of the whole run, the probe checks' timeline (whole
# seconds, folded flips counted).
stage_events() {
  briqyard events 2>&1 | awk 'NR == 1 || $3 == "ready" || $3 == "not_ready" || $3 == "liveness_failed"' | tail -n 150
}

stage_cargotest() {
  cd "$SRC"
  echo $$ > "$L/cargotest.pid"
  local rc=0
  cargo test --workspace --locked --no-fail-fast > "$L/cargotest.out" 2>&1 || rc=$?
  cat "$L/cargotest.out"
  # The init's test that changes users, as CI runs it: its test binary as root.
  "$(cargo test --workspace --locked --no-run --message-format=json | jq -r 'select(.profile.test and .target.name == "briqyard-init") | .executable')" --ignored run_as || rc=$?
  # A test that failed in the full run, run alone: a failure that goes with the load of the run
  # says so.
  for t in $(grep -E '^test .* \.\.\. FAILED$' "$L/cargotest.out" | awk '{print $2}'); do
    if cargo test --workspace --locked -- --exact "$t" > "$L/rerun.out" 2>&1; then echo "RERUN alone: $t ok"; else echo "RERUN alone: $t FAILED"; tail -n 15 "$L/rerun.out"; fi
  done
  # What the held-command test does, by hand: a process whose parent exited, two seconds later.
  printf '#!/bin/sh\nwhile kill -0 "$PPID" 2>/dev/null; do sleep 0.02; done\n' > "$TMPDIR/hold.sh"
  orphan=$(sh -c 'sh "$0" > /dev/null 2>&1 & echo $!' "$TMPDIR/hold.sh")
  sleep 2
  echo "ORPHAN $orphan, 2 s after its parent: $(grep -E '^(State|PPid)' "/proc/$orphan/status" 2>&1 | paste -sd' ' -)"
  echo "ORPHAN zombies in the machine: $(ps -eo stat | grep -c '^Z'); pid_max $(cat /proc/sys/kernel/pid_max); a new pid: $(sh -c 'echo $$')"
  return "$rc"
}

# Ends a stage that is still running, by the pid it recorded: its own traps end what it started.
stage_stop() {
  local stage=$1
  [ -f "$L/$stage.pid" ] || return 0
  if [[ "$IN_UNIT_STAGES" == *" $stage "* ]]; then
    in_unit bash -c "kill -TERM $(cat "$L/$stage.pid")" 2> /dev/null || true
  else
    kill -TERM "$(cat "$L/$stage.pid")" 2> /dev/null || true
  fi
}

# Ends what the stages started: the machines, then systemd, whose namespace takes the daemon,
# the pool's mounts and every process of it along when it ends.
stage_teardown() {
  if [ -f "$L/systemd.pid" ] && kill -0 "$(cat "$L/systemd.pid")" 2> /dev/null; then
    for ns in $(in_unit briqyard namespace ls 2> /dev/null | jq -r '.[].id'); do
      for id in $(in_unit briqyard machine ls --namespace "$ns" 2> /dev/null | awk 'NR>1{print $1}'); do in_unit briqyard machine rm "$id" > /dev/null 2>&1 || true; done
      in_unit briqyard namespace rm "$ns" > /dev/null 2>&1 || true
    done
    kill -KILL "$(cat "$L/systemd.pid")" 2> /dev/null || true
    rm -f "$L/systemd.pid"
  fi
  ! mountpoint -q /var/lib/briqyard || umount /var/lib/briqyard 2> /dev/null || true
}

case ${1:?stage} in
  run)
    stage=${2:?stage}
    rm -f "$L/$stage.rc"
    rc=0
    if [[ "$IN_UNIT_STAGES" == *" $stage "* ]]; then
      in_unit bash "$0" "$stage" > "$L/$stage.log" 2>&1 < /dev/null || rc=$?
    else
      bash "$0" "$stage" > "$L/$stage.log" 2>&1 < /dev/null || rc=$?
    fi
    echo "$rc" > "$L/$stage.rc"
    ;;
  stop) stage_stop "${2:?stage}" ;;
  build | systemd | host | fleet | e2e | events | cargotest | teardown) "stage_$1" ;;
  *) echo "unknown stage $1" >&2; exit 2 ;;
esac

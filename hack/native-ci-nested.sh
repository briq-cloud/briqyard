#!/usr/bin/env bash
# Rehearsal of the acceptance of the `nested` runtime class (ADR 0088) on a disposable
# GitHub-hosted x86_64 runner with /dev/kvm. Three levels: the runner is the host, a `nested`
# machine is the sandbox, and briqyard runs inside the sandbox with Firecracker microVMs of its own.
#   native-ci-nested.sh SOURCE_DIR NESTED_KERNEL_DIR
# SOURCE_DIR holds the built head (target/); NESTED_KERNEL_DIR the three files hack/kernel/build.sh
# makes. Each step is timed and reported in the job summary; a step that fails stops the run,
# after the sandbox's console tail is printed and everything the run started is ended.
set -euo pipefail
[ "${RUNNER_ENVIRONMENT:-}" = github-hosted ] || { echo 'native-ci-nested.sh requires a disposable GitHub-hosted runner' >&2; exit 2; }
HARNESS=$(cd "$(dirname "$0")" && pwd)
SRC=$(cd "${1:?source directory}" && pwd)
KERNEL_DIR=$(cd "${2:?directory of the nested kernel files}" && pwd)
cd "$SRC"
LOGS=$SRC/native-logs
mkdir -p "$LOGS"
WORK=$(mktemp -d)
ROWS=$WORK/rows
DETAILS=$WORK/details
: > "$ROWS"; : > "$DETAILS"
SUMMARY=${GITHUB_STEP_SUMMARY:-/dev/null}

# The image of the sandbox, its size, and the limits of the long steps (seconds).
IMAGE=${NATIVE_SANDBOX_IMAGE:-ghcr.io/briq-cloud/sandbox:kvm}
SB_VCPUS=3 SB_MEMORY=11264 SB_VOLUME=36G:/work
BUILD_LIMIT=${NATIVE_BUILD_LIMIT:-3000}
HOST_LIMIT=${NATIVE_HOST_LIMIT:-2400}
FLEET_LIMIT=${NATIVE_FLEET_LIMIT:-3000}
CARGOTEST_LIMIT=${NATIVE_CARGOTEST_LIMIT:-3600}
# hack/e2e.sh runs last and takes what the job has left: the epoch second the workflow gives as
# NATIVE_DEADLINE (the job's limit less the steps after this one), less a quarter hour for
# ending the suite and the summary; at most NATIVE_E2E_LIMIT.
E2E_LIMIT=${NATIVE_E2E_LIMIT:-5400}
SB_NS=nested-ci
SB=
BUILT_INSIDE=0
FAILED=0
CUR=
CUR_START=0
export BRIQYARD_URL=http://127.0.0.1:7420

# ---- reporting ---------------------------------------------------------------------------
row() { printf '| %s | %s | %s | %s |\n' "$1" "$2" "$3" "$4" >> "$ROWS"; }
detail() { { echo "#### $1"; echo '```'; cat; echo '```'; } >> "$DETAILS"; }
begin() { CUR=$1; CUR_START=$SECONDS; echo "::group::$1"; }
finish() { # note
  echo "::endgroup::"
  row "$CUR" ok "$((SECONDS - CUR_START))" "${1:-}"
  CUR=
}
# A step that went wrong without stopping the run (a suite with failed checks).
soft_fail() { # note
  echo "::endgroup::"
  row "$CUR" FAILED "$((SECONDS - CUR_START))" "${1:-}"
  CUR=; FAILED=1
}

# ---- the sandbox ---------------------------------------------------------------------------
sbx() { briqyard machine exec --timeout 30m "$SB" -- "$@"; }

# A stage of hack/native-ci-nested-inner.sh, detached: the exec that starts it answers at once,
# its output goes to a file in the machine, and its exit status to another.
inner_start() { sbx bash -c "setsid bash /work/inner.sh run $1 > /dev/null 2>&1 < /dev/null &"; }
# Waits for the exit status of a stage: 0 when it succeeded, its status when it did not, 124
# at the limit. The log comes out either way.
inner_wait() { # stage limit
  local stage=$1 end=$((SECONDS + $2)) start=$SECONDS rc=
  while :; do
    if rc=$(sbx cat "/work/logs/$stage.rc" 2> /dev/null); then break; fi
    if [ "$SECONDS" -ge "$end" ]; then
      # Ended by its own traps (they print what ran), then waited for.
      echo "  [$((SECONDS - start))s] limit reached: stopping $stage"
      sbx bash /work/inner.sh stop "$stage" || true
      for _ in $(seq 1 20); do sbx cat "/work/logs/$stage.rc" > /dev/null 2>&1 && break; sleep 30; done
      rc=124; break
    fi
    echo "  [$((SECONDS - start))s] load $(sbx cat /proc/loadavg 2> /dev/null | cut -d' ' -f1-3 || true) | $(sbx tail -n 1 "/work/logs/$stage.log" 2> /dev/null | cut -c1-140 || true)"
    sleep 30
  done
  briqyard machine get-file "$SB" "/work/logs/$stage.log" > "$LOGS/inner-$stage.log" 2> /dev/null || true
  echo "---- $stage: status $rc, last lines of its log"
  tail -n 25 "$LOGS/inner-$stage.log" || true
  return "$rc"
}
inner() { # stage limit
  inner_start "$1"
  inner_wait "$1" "$2"
}

# ---- what ends the run, however it ends ----------------------------------------------------
on_exit() {
  local rc=$?
  set +e
  trap - EXIT
  if [ -n "$CUR" ]; then
    echo "::endgroup::"
    row "$CUR" FAILED "$((SECONDS - CUR_START))" "exit status $rc"
    FAILED=1
  fi
  if [ "$FAILED" != 0 ] || [ "$rc" != 0 ]; then
    if [ -n "$SB" ]; then
      echo "---- the sandbox's console, last 80 lines"
      briqyard machine logs "$SB" --limit 1000000 2>&1 | tail -n 80 | tee "$WORK/console"
      detail "Sandbox console (tail)" < "$WORK/console"
      echo "---- the inner daemon's journal, last 40 lines"
      sbx bash -c 'nsenter -t "$(cat /work/logs/systemd.pid)" -a journalctl -u briqyardd -u briqyard-fleet --no-pager -n 40' 2>&1 | tee "$WORK/innerd" | cut -c1-300
      [ ! -s "$WORK/innerd" ] || detail "Inner daemon journal (tail)" < "$WORK/innerd"
    fi
  fi
  # The machines and the inner daemon, by what this run recorded.
  if [ -n "$SB" ]; then
    sbx bash /work/inner.sh teardown > /dev/null 2>&1
  fi
  for id in $(briqyard machine ls --namespace "$SB_NS" 2> /dev/null | awk 'NR>1{print $1}'); do briqyard machine rm "$id" > /dev/null 2>&1; done
  for t in "$SB_NS" "$CLASS_NS"; do [ -z "$t" ] || briqyard namespace rm "$t" > /dev/null 2>&1; done
  {
    echo '### nested rehearsal'
    echo '| step | result | seconds | detail |'
    echo '|---|---|---:|---|'
    cat "$ROWS"
    echo
    cat "$DETAILS"
  } | tee -a "$SUMMARY"
  if [ "$rc" = 0 ] && [ "$FAILED" != 0 ]; then rc=1; fi
  exit "$rc"
}
CLASS_NS=
trap on_exit EXIT
trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP

# ======================================================================================
begin "1 host: bootstrap with the nested class, status, e2e-classes"
# What hack/native-ci.sh installs, with the class: the pool is larger, the sandbox's
# volume and its image come out of it.
NATIVE_NESTED_DIR=$KERNEL_DIR BRIQYARD_POOL_FILE_GB=64 bash "$HARNESS/native-ci.sh" "$SRC"
grep -m1 '^model name' /proc/cpuinfo
echo "host kvm: $(for p in /sys/module/kvm_intel/parameters/* /sys/module/kvm_amd/parameters/*; do [ -f "$p" ] && echo "$(basename "$p")=$(cat "$p" 2> /dev/null)"; done | paste -sd' ' - || true)"
grep -m1 '^flags' /proc/cpuinfo | tr ' ' '\n' | grep -E '^(vmx|ept|vpid|ept_ad|ept_1gb|vnmi|flexpriority|tpr_shadow|vmcs_shadowing|apicv|svm|npt|nrip_save|avic)$' | paste -sd' ' - || true
briqyard status | jq -c '.runtime_classes' | tee "$WORK/classes"
briqyard status | jq -e '[.runtime_classes[]? | select(.name == "nested" and .nested == true and (.kernel_release | length) > 0 and (.openzfs | length) > 0)] | length == 1' > /dev/null
detail "Host status: runtime classes" < "$WORK/classes"
briqyard status | jq -c . | cut -c1-1500 | detail "Host status"
# hack/e2e.sh sources hack/e2e-classes.sh after hack/e2e-machines.sh made $A; here $A is one machine.
CLASS_NS=nested-ci-classes
T=$CLASS_NS
pass=0; fail=0
ok()   { pass=$((pass+1)); echo "  ok   $1"; }
bad()  { fail=$((fail+1)); echo "  FAIL $1"; }
check(){ if eval "$2"; then ok "$1"; else bad "$1"; fi; }
# shellcheck disable=SC2034 # read by e2e-classes.sh
A=$(briqyard machine run --image alpine:3.20 --name default-a --namespace "$T" --memory 128 -- sleep 3600 | jq -r .id)
if ! . "$SRC/hack/e2e-classes.sh" > "$LOGS/e2e-classes.log" 2>&1; then echo 'e2e-classes.sh stopped early'; fi
cat "$LOGS/e2e-classes.log"
cpass=$pass cfail=$fail
for id in $(briqyard machine ls --namespace "$T" | awk 'NR>1{print $1}'); do briqyard machine rm "$id" > /dev/null; done
briqyard namespace rm "$T" > /dev/null; CLASS_NS=
grep '^  FAIL ' "$LOGS/e2e-classes.log" | detail "e2e-classes failures" || true
# 3 checks of any host and 8 of a host that serves the class.
if [ "$cfail" != 0 ] || [ "$cpass" -lt 11 ]; then
  echo "e2e-classes: passed $cpass, failed $cfail"
  exit 1
fi
finish "nested in status with its kernel release and OpenZFS version; e2e-classes passed $cpass, failed $cfail"

# ======================================================================================
begin "2 sandbox: a nested machine from $IMAGE"
CAPACITY=$(briqyard status | jq -c '.capacity // empty')
echo "host capacity: $CAPACITY"
SB=$(briqyard machine run --image "$IMAGE" --name nested-sandbox --namespace "$SB_NS" --runtime-class nested \
  --vcpus "$SB_VCPUS" --memory "$SB_MEMORY" --volume "$SB_VOLUME" | jq -r .id)
echo "sandbox $SB"
briqyard machine get "$SB" | jq -c '{id, state, runtime_class, size, volume}'
briqyard machine put "$SB" "$HARNESS/native-ci-nested-inner.sh" /work/inner.sh
# The checked Firecracker bundle that hack/native-ci.sh fetched and verified, and its digest: the
# inner install is the real one, hack/bootstrap-host.sh with a release directory.
BUNDLE=firecracker-checked-linux-x86_64.tar.gz
BUNDLE_SHA256=$(awk -v b="$BUNDLE" '$2 == b {print $1}' "$SRC/native-release/SHA256SUMS-x86_64")
[ "${#BUNDLE_SHA256}" = 64 ] || { echo "no digest of $BUNDLE in native-release/SHA256SUMS-x86_64"; exit 1; }
printf 'BUNDLE_SHA256=%s\n' "$BUNDLE_SHA256" > "$WORK/inner.env"
briqyard machine put "$SB" "$WORK/inner.env" /work/inner.env
briqyard machine put "$SB" "$SRC/native-release/$BUNDLE" /work/fc-bundle.tgz
# The agent's first question: does it work at all?
sbx kvm-ready 2>&1 | tee "$WORK/ready"
{
  sbx uname -r
  sbx ls -l /dev/kvm
  echo "CPUs with vmx or svm: $(sbx bash -c "grep -c -E 'vmx|svm' /proc/cpuinfo" || true)"
  sbx bash -c 'df -h / /work | cat; free -m | sed -n 2p; nproc'
} 2>&1 | tee "$WORK/probe"
detail "Sandbox: kvm-ready, /dev/kvm, vmx or svm" < <(cat "$WORK/ready" "$WORK/probe")
finish "$(tail -n 1 "$WORK/ready" | cut -c1-200)"

# ======================================================================================
begin "3 build inside: cargo build --release --workspace and the musl init"
tar -czf "$WORK/src.tgz" -C "$SRC" --exclude=./target --exclude=./.git --exclude=./native-release \
  --exclude=./native-logs --exclude=./.native-harness .
ls -l "$WORK/src.tgz"
briqyard machine put "$SB" "$WORK/src.tgz" /work/src.tgz
sbx bash -c 'rm -rf /work/src && mkdir -p /work/src && tar -xzf /work/src.tgz -C /work/src && ls /work/src | head -n 5'
build_rc=0
inner build "$BUILD_LIMIT" || build_rc=$?
case $build_rc in
  0) BUILT_INSIDE=1; finish "built inside, $((SECONDS - CUR_START)) s on $SB_VCPUS vCPUs" ;;
  124)
    # A 4-vCPU runner under the job's limit: the runner's binaries go in instead.
    sbx bash -c 'pkill -x cargo; pkill -x rustc; true' || true
    sbx bash -c 'mkdir -p /work/target/release /work/target/x86_64-unknown-linux-musl/release'
    for b in briqyardd briqyard briqyard-fleet; do briqyard machine put "$SB" "$SRC/target/release/$b" "/work/target/release/$b"; done
    briqyard machine put "$SB" "$SRC/target/x86_64-unknown-linux-musl/release/briqyard-init" /work/target/x86_64-unknown-linux-musl/release/briqyard-init
    finish "NOT built inside: still running after ${BUILD_LIMIT} s, the runner's binaries were copied in; cargo test is not run inside" ;;
  *) exit "$build_rc" ;;
esac

# ======================================================================================
begin "4a inner systemd: PID 1 of namespaces of its own, as a privileged container runs it"
inner systemd 900 || exit 1
tail -n 40 "$LOGS/inner-systemd.log" | detail "Sandbox: init and udev before, systemd in its namespaces"
finish "$(grep '^systemd: ' "$LOGS/inner-systemd.log"), the sandbox's init unchanged"

# ======================================================================================
begin "4b inner host: hack/bootstrap-host.sh and hack/install-dev.sh, briqyardd under its unit"
inner host "$HOST_LIMIT" || { grep -E '^probe MISSING' "$LOGS/inner-host.log" | detail "Missing in the sandbox" || true; exit 1; }
grep -E '^probe MISSING|^== probes missing' "$LOGS/inner-host.log" | detail "Inner host: what the sandbox lacks" || true
grep -E '^Id=|^ControlGroup=|^FragmentPath=|^MainPID=' "$LOGS/inner-host.log" | detail "Inner daemon's unit"
finish "$(grep '^== probes missing' "$LOGS/inner-host.log"); $(grep '^ControlGroup=' "$LOGS/inner-host.log")"

# ======================================================================================
begin "5 inner microVM: an alpine machine and uname -r"
inner_boot() { # name
  local t0 t1 id
  t0=$(date +%s.%N)
  id=$(sbx briqyard machine run --image alpine:3.20 --name "$1" --namespace inner-boot --memory 128 -- sleep 3600 | jq -r .id)
  t1=$(date +%s.%N)
  echo "$1 $id: machine run answered after $(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.2f", b-a}') s" | tee -a "$WORK/boot"
  echo "$id"
}
: > "$WORK/boot"
first=$(inner_boot inner-a | tail -n 1)
t0=$(date +%s.%N)
sbx briqyard machine exec "$first" -- echo hello | tee -a "$WORK/boot"
echo "inner-a: first machine exec answered after $(awk -v a="$t0" -v b="$(date +%s.%N)" 'BEGIN{printf "%.2f", b-a}') s" | tee -a "$WORK/boot"
second=$(inner_boot inner-b | tail -n 1)
sbx briqyard machine exec "$second" -- uname -r | tee "$WORK/inner-uname"
# The kernel's own timeline of the second boot, from its console.
sbx briqyard machine logs "$second" --limit 100000 2>&1 | grep -E 'Linux version|Freeing unused kernel|Run /|briqyard|init' | cut -c1-160 | head -n 12 > "$WORK/boot-timeline" || true
# Is a failed reach slowness? The same ping with 2 s and with 60 s to answer.
b_name=$(sbx briqyard machine get "$second" | jq -r .name)
a_name=inner-a
for w in 2 60; do
  t0=$(date +%s.%N)
  r=ok; sbx briqyard machine exec "$second" -- ping -c1 -W "$w" "$a_name.internal" > /dev/null 2>&1 || r=FAILED
  echo "$b_name pings $a_name by name, -W $w: $r after $(awk -v a="$t0" -v b="$(date +%s.%N)" 'BEGIN{printf "%.1f", b-a}') s" | tee -a "$WORK/boot"
done
detail "Inner microVM" < <(cat "$WORK/boot" "$WORK/boot-timeline"; echo "guest kernel: $(cat "$WORK/inner-uname")"; echo "sandbox kernel: $(sbx uname -r)")
finish "$(grep ' machine run answered' "$WORK/boot" | sed -n 1p | sed 's/^[^:]*: //') (first, with the image pull); $(grep ' machine run answered' "$WORK/boot" | sed -n 2p | sed 's/^[^:]*: //') (second); uname -r $(cat "$WORK/inner-uname")"

# ======================================================================================
# A suite's counts and failures, from its log: failed checks, and the sections of the suites
# that have no line in it.
suite_detail() { # stage title
  {
    grep -E '^  FAIL ' "$LOGS/inner-$1.log" || true
    echo "---- sections of the suite without a line in this run:"
    grep -h -o '^ *echo "== [^"$]*' "$SRC"/hack/"$3"*.sh | sed 's/^ *echo "== //' | while read -r h; do
      [ -n "$h" ] && ! grep -qF "== ${h:0:30}" "$LOGS/inner-$1.log" && echo "  $h"
    done || true
  } > "$WORK/$1-detail"
  cat "$WORK/$1-detail"
  detail "$2: failures and absent sections" < "$WORK/$1-detail"
}

begin "6a inner suite: hack/fleet-smoke.sh through the inner fleet"
fleet_rc=0
inner fleet "$FLEET_LIMIT" || fleet_rc=$?
summary_line=$(grep -E '^passed |^ENDED EARLY' "$LOGS/inner-fleet.log" | tr '\n' ' ' || true)
suite_detail fleet "Inner fleet-smoke" fleet-smoke
if [ "$fleet_rc" = 0 ]; then finish "$summary_line"; else soft_fail "$summary_line (status $fleet_rc)"; fi

# ======================================================================================
if [ "$BUILT_INSIDE" = 1 ]; then
  begin "6b inner suite: cargo test --workspace (and the init's root test)"
  ct_rc=0
  inner cargotest "$CARGOTEST_LIMIT" || ct_rc=$?
  ct_line=$(grep -E '^test result:' "$LOGS/inner-cargotest.log" | awk '{p+=$4; f+=$6; i+=$8} END{printf "passed %d, failed %d, ignored %d", p, f, i}' || true)
  grep -E '^test .* FAILED$|^RERUN alone' "$LOGS/inner-cargotest.log" | head -n 40 | detail "Inner cargo test: failures" || true
  if [ "$ct_rc" = 0 ]; then finish "$ct_line"; else soft_fail "$ct_line (status $ct_rc)"; fi
else
  row "6b inner suite: cargo test" "not run" 0 "the build was not run inside"
fi

# ======================================================================================
begin "6c inner suite: hack/e2e.sh against the inner daemon"
if [ -n "${NATIVE_DEADLINE:-}" ]; then
  left=$((NATIVE_DEADLINE - $(date +%s) - 900))
  [ "$left" -lt "$E2E_LIMIT" ] && E2E_LIMIT=$left
fi
echo "e2e limit: $E2E_LIMIT s"
e2e_rc=0
[ "$E2E_LIMIT" -gt 300 ] && { inner e2e "$E2E_LIMIT" || e2e_rc=$?; } || { echo "no time left for the suite"; e2e_rc=124; }
summary_line=$(grep -E '^passed |^ENDED EARLY' "$LOGS/inner-e2e.log" | tr '\n' ' ' || true)
suite_detail e2e "Inner e2e" e2e

# What the e2e run measured beside its checks (stage e2e of the inner script): the time of a
# `systemctl show` (the daemon gives one 3 s), the answers of the iron-proxy requests, the
# time of the calls behind the probe checks. Nothing here changes a check.
inner events 300 || true
for f in systemctl-latency iron-answers briqyard-calls holders; do
  briqyard machine get-file "$SB" "/work/logs/$f.log" > "$LOGS/inner-$f.log" 2> /dev/null || : > "$LOGS/inner-$f.log"
done
{
  echo "samples: $(wc -l < "$LOGS/inner-systemctl-latency.log"); past 1 s: $(awk '{m=$4>$6?$4:$6; if (m > 1) n++} END{print n+0}' "$LOGS/inner-systemctl-latency.log"); past 3 s: $(awk '{m=$4>$6?$4:$6; if (m > 3) n++} END{print n+0}' "$LOGS/inner-systemctl-latency.log")"
  echo "slowest ten (time, oomd check s, ancestry s, status, load, state of systemd):"
  awk '{m=$4>$6?$4:$6; print m, $0}' "$LOGS/inner-systemctl-latency.log" | sort -rn | sed -n 1,10p | cut -d' ' -f2-
} | tee "$WORK/systemctl-summary" | detail "systemctl show during the e2e"
cat "$WORK/systemctl-summary"
detail "iron-proxy requests: what the machine's request answered" < "$LOGS/inner-iron-answers.log"
[ ! -s "$LOGS/inner-holders.log" ] || detail "A destroy answered busy: who holds the datasets" < "$LOGS/inner-holders.log"
{
  grep -E ' dd bs=1M' "$LOGS/inner-briqyard-calls.log" || true
  echo "---- calls from the ready machine's start to the liveness one's"
  awk '/--name ready/{p=1} /--name alive/{p=0} p' "$LOGS/inner-briqyard-calls.log" | sed -n 1,60p
  echo "---- ready and liveness events (time, type, reason, machine, count)"
  cat "$LOGS/inner-events.log"
} | detail "Probe checks: elapsed times"
if [ "$e2e_rc" = 0 ]; then finish "$summary_line"; else soft_fail "$summary_line (status $e2e_rc, limit $E2E_LIMIT s)"; fi

[ "$FAILED" = 0 ]

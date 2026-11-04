#!/usr/bin/env bash
# A host upgraded in place holds thousands of idle machine cgroups left by earlier versions
# (ADR 0068, 0098). A fresh runner holds a handful, so only this suite makes the case the
# startup barrier once failed on (a 4096-leaf cap met 6404 and 5234 leaves): more leaves than
# that cap, a daemon restart, and the daemon must come up, report its memory protection healthy,
# retire the leaves and accept a create, within a bound. Harness from the workflow revision, so
# it also runs against an older source ref (workflow_dispatch `ref`), where it must fail.
# Disposable GitHub-hosted runner only; needs the installed native daemon.
set -uo pipefail
[ "${RUNNER_ENVIRONMENT:-}" = github-hosted ] || { echo 'requires a disposable GitHub-hosted runner' >&2; exit 2; }
LEAVES=${SCALE_LEAVES:-6500}   # past the old cap of 4096 with room, below the daemon's 65536
BOUND=${SCALE_BOUND_SECONDS:-300}  # restart to the first accepted create
NS=native-scale-$$
PARENT=/sys/fs/cgroup/firecracker
pass=0; fail=0
ok()   { pass=$((pass+1)); echo "  ok   $1"; }
bad()  { fail=$((fail+1)); echo "  FAIL $1"; }
check(){ if eval "$2"; then ok "$1"; else bad "$1"; fi; }
. "$(dirname "${BASH_SOURCE[0]}")/suite-end.sh"
leaves() { sudo find "$PARENT" -mindepth 1 -maxdepth 1 -type d -name 'm-*' | wc -l; }
made() { sudo find "$PARENT" -mindepth 1 -maxdepth 1 -type d -name 'm-5ca1*' | wc -l; }
cleanup() {
  local rc=$?
  set +e
  # The leaves this run made and the daemon left, then its machines.
  sudo sh -c "cd $PARENT 2>/dev/null && find . -mindepth 1 -maxdepth 1 -type d -name 'm-5ca1*' | xargs -r rmdir 2>/dev/null"
  for id in $(briqyard machine ls --namespace "$NS" 2>/dev/null | awk 'NR>1{print $1}'); do briqyard machine rm "$id" >/dev/null 2>&1; done
  for _ in $(seq 1 10); do briqyard namespace rm "$NS" >/dev/null 2>&1 && break; sleep 2; done
  sudo systemctl start briqyardd
  suite_early_end "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP

echo "== $LEAVES idle machine cgroups, a daemon restart (bound ${BOUND}s)"
# A machine has run: the jailer enabled +memory on the parent, which a leaf's final counters
# need. The fixture's leaves would fail the sweep for that reason, not for the one tested.
first=$(briqyard machine run --namespace "$NS" --name first --image alpine:3.20 --memory 128 -- sleep 3600 | jq -r .id)
check "scale: a machine runs before the leaves exist" '[ -n "$first" ] && briqyard machine wait --for running "$first" >/dev/null'
briqyard machine rm "$first" >/dev/null
before=$(leaves)
sudo sh -c "cd $PARENT && awk 'BEGIN{for(i=0;i<$LEAVES;i++)printf \"m-5ca1%08x\\n\", i}' | xargs mkdir"
check "scale: $LEAVES idle leaves exist, more than the old cap of 4096" '[ "$(made)" -eq "$LEAVES" ] && [ "$(made)" -gt 4096 ]'

start=$SECONDS
sudo systemctl restart briqyardd
up=0
for _ in $(seq 1 "$BOUND"); do
  briqyard status >/dev/null 2>&1 && { up=1; break; }
  sleep 1
done
echo "   the daemon answered after $((SECONDS - start)) s"
check "scale: the daemon answers within ${BOUND}s of its restart" '[ "$up" = 1 ]'
check "scale: memory protection is healthy (the startup barrier opened)" 'briqyard status | jq -e "all(.conditions[] | select(.type == \"memory_protection\"); .status == false)" >/dev/null'
mid=$(briqyard machine run --namespace "$NS" --name after --image alpine:3.20 --memory 128 -- sleep 3600 2>&1 | jq -r .id 2>/dev/null)
check "scale: a create is accepted and runs (${BOUND}s from the restart)" '[ -n "$mid" ] && briqyard machine wait --for running "$mid" >/dev/null && [ $((SECONDS - start)) -le "$BOUND" ]'
echo "   restart to a running create: $((SECONDS - start)) s"
for _ in $(seq 1 60); do [ "$(made)" -eq 0 ] && break; sleep 1; done
check "scale: the startup sweep retired the leaves" '[ "$(made)" -eq 0 ]'
check "scale: nothing else was left behind" '[ "$(leaves)" -le "$((before + 1))" ]'

suite_summary

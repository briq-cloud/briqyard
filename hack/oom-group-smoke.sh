#!/usr/bin/env bash
# Bounded cgroup OOM containment test. Only an exclusive, empty disposable Linux host.
set -euo pipefail
[ "${1:-}" = --disposable-empty-host ] && [ "$#" = 1 ] || { echo 'usage: oom-group-smoke.sh --disposable-empty-host' >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo 'root is required' >&2; exit 2; }
[ "$(stat -fc %T /sys/fs/cgroup)" = cgroup2fs ] || { echo 'cgroup v2 required' >&2; exit 2; }
[ "$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)" -ge 524288 ] || { echo 'at least 512 MiB available required' >&2; exit 2; }
for file in /sys/fs/cgroup/firecracker/*/cgroup.procs; do
  [ ! -e "$file" ] || [ -z "$(cat "$file")" ] || { echo 'host is not empty: live VMM leaf' >&2; exit 2; }
done
work=$(mktemp -d /tmp/briqyard-oom-test.XXXXXX)
scope=/sys/fs/cgroup/briqyard-oom-test-$(date +%s)-$$
owned_scope=0
pids=()
cleanup() {
  status=$?
  trap - EXIT INT TERM HUP
  if [ "$owned_scope" = 1 ] && [ -e "$scope/cgroup.kill" ]; then echo 1 > "$scope/cgroup.kill"; fi
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
  if [ "$owned_scope" = 1 ]; then
    for name in daemon fleet helper gateway sibling victim; do rmdir "$scope/$name" 2>/dev/null || true; done
    rmdir "$scope" 2>/dev/null || { echo 'owned test cgroup cleanup failed' >&2; status=1; }
  fi
  rm -rf -- "$work"
  if [ "$status" = 0 ]; then echo "cleanup: owned actors=0, owned cgroups=0"; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
mkdir "$scope"
owned_scope=1
[ -e "$scope/cgroup.kill" ] || { echo 'cgroup.kill required' >&2; exit 2; }
echo 268435456 > "$scope/memory.max"
echo 0 > "$scope/memory.swap.max"
echo +memory > "$scope/cgroup.subtree_control"
cat > "$work/actor.py" <<'PY'
import os, pathlib, sys, threading, time
leaf, score, name, work, parent = sys.argv[1:]
leaf, work, parent = pathlib.Path(leaf), pathlib.Path(work), int(parent)
(leaf / 'cgroup.procs').write_text(str(os.getpid()))
pathlib.Path('/proc/self/oom_score_adj').write_text(score)
if pathlib.Path('/proc/self/oom_score_adj').read_text().strip() != score:
    raise SystemExit('score readback failed')
if name == 'victim':
    child = os.fork()
    if child == 0:
        name = 'victim-child'
        parent = os.getppid()
deadline = time.monotonic() + 30
def watch():
    while os.getppid() == parent and time.monotonic() < deadline:
        time.sleep(0.05)
    os._exit(124)
threading.Thread(target=watch, daemon=True).start()
stat = pathlib.Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()
(work / name).write_text(f'{os.getpid()} {stat[19]} {score}')
if name == 'victim':
    while not (work / 'load').exists():
        time.sleep(0.01)
    payload = bytearray(80 << 20)  # exceeds only this 32-MiB leaf, not the 256-MiB parent
else:
    payload = bytearray(1 << 20)
while True:
    time.sleep(0.1)
PY
for spec in daemon:-900 fleet:-900 helper:0 gateway:250 sibling:500 victim:500; do
  name=${spec%:*}; score=${spec#*:}
  mkdir "$scope/$name"
  echo 33554432 > "$scope/$name/memory.max"
  echo 0 > "$scope/$name/memory.swap.max"
  echo 1 > "$scope/$name/memory.oom.group"
  python3 "$work/actor.py" "$scope/$name" "$score" "$name" "$work" "$$" &
  pids+=("$!")
done
# Condition waits, bounded to 10 s for readiness and 15 s for the scoped OOM.
python3 - "$work" "$scope" <<'PY'
import pathlib, sys, time
work, scope = map(pathlib.Path, sys.argv[1:])
names = ['daemon', 'fleet', 'helper', 'gateway', 'sibling', 'victim', 'victim-child']
end = time.monotonic() + 10
while not all((work / n).exists() for n in names):
    if time.monotonic() >= end:
        raise SystemExit('owned actor readiness timed out')
    time.sleep(0.02)
(work / 'load').touch()
end = time.monotonic() + 15
while (scope / 'victim/cgroup.procs').read_text().strip():
    if time.monotonic() >= end:
        raise SystemExit('owned victim group did not empty')
    time.sleep(0.02)
counts = dict(line.split() for line in (scope / 'victim/memory.events.local').read_text().splitlines())
assert int(counts['oom']) > 0 and int(counts['oom_kill']) >= 2 and int(counts['oom_group_kill']) >= 1
for name in names[:5]:
    pid, start, score = (work / name).read_text().split()
    current = pathlib.Path('/proc', pid, 'stat').read_text().rsplit(')', 1)[1].split()
    assert current[19] == start and current[0] != 'Z', name
    assert pathlib.Path('/proc', pid, 'oom_score_adj').read_text().strip() == score, name
print('PASS: owned leaf OOM group killed; sibling and supervisor incarnations survived; scores unchanged')
print('local counters:', {k: int(counts[k]) for k in ['oom', 'oom_kill', 'oom_group_kill']})
PY

#!/usr/bin/env bash
# One lock for the development VMs (fc, fc2), shared by every checkout and session on this Mac.
# Anything that restarts their daemons or runs a suite on them goes through it:
#
#   hack/vm-lock.sh hack/vm.sh install
#   hack/vm-lock.sh bash -c 'hack/vm.sh install && limactl shell fc bash hack/e2e.sh'
#
# A kernel lock (flock) on /tmp/briqyard-vm.lock: the system releases it when its holder ends,
# however it ends, so there is no stale lock to clean up. It waits while another holder runs
# (saying who, every minute), then runs the command with BRIQYARD_VM_LOCK set. Only this script
# holds the lock: the command gets no copy of it, since `limactl shell` may start an SSH master
# that outlives it and would keep the lock for good. BRIQYARD_VM_LOCK_OWNER names the holder
# (default: this tree's directory); the file says who holds it while it is held.
set -euo pipefail
[ $# -gt 0 ] || { echo "usage: hack/vm-lock.sh COMMAND [ARGS...]" >&2; exit 2; }
LOCK=/tmp/briqyard-vm.lock
OWNER=${BRIQYARD_VM_LOCK_OWNER:-$(basename "$(cd "$(dirname "$0")/.." && pwd)")}

# Nested use (vm.sh under a held lock) runs at once: a second flock would wait on the first.
if [ -n "${BRIQYARD_VM_LOCK:-}" ]; then exec "$@"; fi

command -v python3 >/dev/null || { echo "vm-lock: python3 is needed (it takes the flock)" >&2; exit 2; }
[ ! -d "$LOCK" ] || { echo "vm-lock: $LOCK is the earlier version's lock directory; wait until its holder ends" >&2; exit 2; }
exec 9>>"$LOCK"
take() { python3 -c 'import fcntl; fcntl.flock(9, fcntl.LOCK_EX | fcntl.LOCK_NB)' 2>/dev/null; }
said=0
until take; do
  if [ $((said % 6)) -eq 0 ]; then echo "vm-lock: waiting for $(cat "$LOCK" 2>/dev/null || echo 'a holder')" >&2; fi
  said=$((said + 1))
  sleep 10
done
echo "$$ $OWNER since $(date '+%H:%M:%S')" > "$LOCK"
BRIQYARD_VM_LOCK=$OWNER "$@" 9>&-

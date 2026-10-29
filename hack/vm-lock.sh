#!/usr/bin/env bash
# One lock for the development VMs (fc, fc2), shared by every checkout and session on this Mac.
# Anything that restarts their daemons or runs a suite on them goes through it:
#
#   hack/vm-lock.sh hack/vm.sh install
#   hack/vm-lock.sh bash -c 'hack/vm.sh install && limactl shell fc bash hack/e2e.sh'
#
# It waits while another holder runs (saying who, every minute), runs the command with
# BRIQYARD_VM_LOCK set, and releases the lock when the command ends, however it ends. A lock
# whose holder is gone (killed, a crashed session) is taken over. It lives in /tmp, which a
# reboot clears. BRIQYARD_VM_LOCK_OWNER names the holder (default: this tree's directory).
set -euo pipefail
[ $# -gt 0 ] || { echo "usage: hack/vm-lock.sh COMMAND [ARGS...]" >&2; exit 2; }
LOCK=/tmp/briqyard-vm.lock
OWNER=${BRIQYARD_VM_LOCK_OWNER:-$(basename "$(cd "$(dirname "$0")/.." && pwd)")}

# Nested use (vm.sh under a held lock) runs at once.
if [ -n "${BRIQYARD_VM_LOCK:-}" ]; then exec "$@"; fi

said=0
until mkdir "$LOCK" 2>/dev/null; do
  holder=$(cat "$LOCK/owner" 2>/dev/null || true)
  pid=${holder%% *}
  if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
    echo "vm-lock: taking over from a holder that is gone ($holder)" >&2
    rm -f "$LOCK/owner"; rmdir "$LOCK" 2>/dev/null || true
    continue
  fi
  if [ $((said % 6)) -eq 0 ]; then echo "vm-lock: waiting for ${holder:-a holder starting}" >&2; fi
  said=$((said + 1))
  sleep 10
done
echo "$$ $OWNER since $(date '+%H:%M:%S')" > "$LOCK/owner"
trap 'rm -f "$LOCK/owner"; rmdir "$LOCK"' EXIT
BRIQYARD_VM_LOCK=$OWNER "$@"

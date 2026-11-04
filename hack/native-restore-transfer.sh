#!/usr/bin/env bash
# Disposable two-host CI only: transfer this machine's store objects, never its disks.
set -euo pipefail
[ "${RUNNER_ENVIRONMENT:-}" = github-hosted ] || exit 2
op=${1:?copy or cleanup}
id=${2:?machine id}
# Literal alphabet check, no input regular expression or shell interpolation of paths.
case "$id" in m_*) ;; *) exit 2 ;; esac
case "$id" in *[!a-zA-Z0-9_]*) exit 2 ;; esac
WORK=$RUNNER_TEMP/two-host-probe
if [ "$op" = cleanup ]; then
  "$WORK/second-host" rm -rf -- "/var/lib/briqyard/backups/backups/$id"
  exit 0
fi
[ "$op" = copy ] || exit 2
archive=$(mktemp "$RUNNER_TEMP/restore-store.XXXXXX")
trap 'rm -f "$archive"' EXIT
sudo tar -C /var/lib/briqyard/backups -cf "$archive" "backups/$id"
"$WORK/second-host" mkdir -p /var/lib/briqyard/backups
"$WORK/second-host" tar -C /var/lib/briqyard/backups -xf - < "$archive"

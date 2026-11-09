# Sourced by e2e.sh; its namespace cleanup owns every builder and destination.
[ "${RUNNER_ENVIRONMENT:-}" = github-hosted ] || { echo 'sealed acceptance requires a disposable CI host' >&2; exit 2; }
seal_handover_projection=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/e2e-handover-evidence.py
# 22 s preflight (7 check-config + 5 PID + 3 timestamp + 7 signal),
# 5 s admission (machine/launch_identity.rs) + 60 s shutdown (main.rs),
# 5 s PID observation + 7 s start + 25 s readiness + 4 s failure evidence.
# Includes command kill grace.
seal_handover_seconds=128
seal_counts=$(mktemp)
(
# Operator seed APIs require authenticated mode. Scope this disposable-runner token
# to the check and restore the original configuration on every exit.
seal_original_token=${BRIQYARD_TOKEN:-}
seal_config=$(mktemp)
seal_saved=0
# Keep failed API responses visible even when a successful response feeds jq.
seal_api() {
  local response rc=0
  response=$("${CURL[@]}" --max-time 135 --fail-with-body -sS "${auth[@]}" "$@") || rc=$?
  if [ "$rc" != 0 ]; then
    printf '%s\n' "$response" >&2
    return "$rc"
  fi
  printf '%s\n' "$response"
}
# Called only after restoring both the file and the original CLI authentication.
# Success requires the new daemon to acknowledge exactly that file's identity.
seal_restore_handover() {
  local expected before=$1 old_pid new_pid observed until status last=unavailable
  local signal_attempted=0 signal_since= evidence=unknown
  local deadline=$((SECONDS + seal_handover_seconds))
  until=$((deadline - 4))
  # Every control call fits the current phase and leaves its two-second kill grace.
  seal_restore_call() {
    local limit=$1 left=$((until - SECONDS - 2)); shift
    [ "$left" -gt 0 ] || return 124
    [ "$limit" -le "$left" ] || limit=$left
    timeout --kill-after=2 "${limit}s" "$@"
  }
  # Only fixed categories cross the native log boundary. Command stderr can contain
  # configuration, credentials or response values, so never forward it here.
  seal_restore_failure() {
    local category=$1 status=${2:-1}
    case "$status" in 124|137) category=${category}_timeout;; esac
    printf 'sealed restoration: %s\n' "$category" >&2
    if [ "$signal_attempted" = 1 ]; then
      # Disposable CI only. Journal metadata selects this daemon and this attempt;
      # the projection accepts only exact structured events, never substring matches.
      if [ "${RUNNER_ENVIRONMENT:-}" = github-hosted ] && [[ "$signal_since" =~ ^[0-9]+\.[0-9]{6}$ ]]; then
        evidence=$(set -o pipefail
          timeout --kill-after=1 3s sudo journalctl -b -u briqyardd --no-pager -o json -n 129 \
            --since="@$signal_since" "_PID=$old_pid" 2>/dev/null |
            timeout --kill-after=1 3s python3 "$seal_handover_projection" "$old_pid" "$signal_since" 2>/dev/null
        ) || evidence=unknown
      fi
      case "$evidence" in
        unknown|refused_unknown|refused_maintenance_outstanding_warm_state|refused_maintenance_state_unknown|refused_maintenance_recovery_unresolved|refused_warm_admission_deadline|refused_namespace_admission_deadline|refused_compatibility_capability|refused_compatibility_command|refused_compatibility_deadline|accepted_shutdown|accepted_shutdown_timeout|accepted_complete) ;;
        *) evidence=unknown;;
      esac
      printf 'sealed restoration handover evidence: %s\n' "$evidence" >&2
    fi
    return 1
  }
  expected=$(seal_restore_call 5 sudo briqyardd --config /etc/briqyard/config.yaml check-config 2>/dev/null) || { seal_restore_failure check_config "$?"; return 1; }
  old_pid=$(seal_restore_call 3 systemctl show -p MainPID --value briqyardd 2>/dev/null) || { seal_restore_failure old_pid_query "$?"; return 1; }
  [[ "$old_pid" =~ ^[1-9][0-9]*$ ]] || { seal_restore_failure old_pid_invalid; return 1; }
  signal_since=$(timeout --kill-after=1 2s date +%s.%6N 2>/dev/null) || signal_since=
  signal_attempted=1
  seal_restore_call 5 sudo kill -USR2 "$old_pid" >/dev/null 2>&1 || { seal_restore_failure signal "$?"; return 1; }
  # Preserve start/readiness/evidence time even if admission and shutdown use their caps.
  until=$((deadline - 7 - 25 - 4))
  while [ "$((SECONDS + 2))" -lt "$until" ]; do
    new_pid=$(seal_restore_call 3 systemctl show -p MainPID --value briqyardd 2>/dev/null) || { seal_restore_failure new_pid_query "$?"; return 1; }
    [ "$SECONDS" -lt "$until" ] && [ "$new_pid" != "$old_pid" ] && break
    sleep 0.1
  done
  [ "$SECONDS" -lt "$until" ] && [ "$new_pid" != "$old_pid" ] || { seal_restore_failure pid_change_exhausted; return 1; }
  until=$((deadline - 4))
  seal_restore_call 5 sudo systemctl start briqyardd >/dev/null 2>&1 || { seal_restore_failure start "$?"; return 1; }
  [ "$((SECONDS + 25))" -ge "$until" ] || until=$((SECONDS + 25))
  while [ "$((SECONDS + 2))" -lt "$until" ]; do
    status=0
    # Restored configuration may have no token; maintenance requires one.
    # Status carries the same identity only after recovery has resolved.
    observed=$(seal_restore_call 3 briqyard status 2>/dev/null) || status=$?
    if [ "$status" = 0 ] && [ "$SECONDS" -lt "$until" ]; then
      if printf '%s' "$observed" | jq -e --arg old "$before" --argjson config "$expected" \
        '.observation.incarnation != $old and (.observation.incarnation | type == "string" and length > 0) and .observation.config == $config' >/dev/null 2>&1; then return 0; fi
      last=identity_mismatch
    else
      case "$status" in 124|137) last=query_timeout;; *) last=query_failed;; esac
    fi
    sleep 0.1
  done
  seal_restore_failure "readiness_exhausted_$last"
  return 1
}
seal_cleanup() {
  local rc=$?
  trap - EXIT
  set +e
  if [ "$seal_saved" = 0 ]; then rm -f "$seal_config"; exit "$rc"; fi
  # Handover refuses outstanding warm authority. Drain and destroy our ownership first,
  # while authentication and the catalog configuration are still installed.
  # One 90-second ownership drain, then at most 10 seconds for restoration and
  # the shared handover budget. Never spend the restoration reserve on API retries.
  local clean=0 restored=0 maintenance namespaces status before=
  seal_cleanup_until=$((SECONDS + 90))
  seal_cleanup_cli() {
    local left=$((seal_cleanup_until - SECONDS))
    [ "$left" -gt 0 ] || return 124
    [ "$left" -le 8 ] || left=8
    timeout --kill-after=2 "${left}s" briqyard "$@"
  }
  seal_cleanup_api() {
    local left=$((seal_cleanup_until - SECONDS))
    [ "$left" -gt 0 ] || return 124
    [ "$left" -le 8 ] || left=8
    seal_api --max-time "$left" "$@"
  }
  if [ -n "${unbound_catalog:-}" ]; then
    seal_cleanup_api -X PUT -H 'Content-Type: application/json' -d '{"desired":0}' "$unbound_catalog" >/dev/null || rc=1
    seal_cleanup_api -X DELETE "$unbound_pools/native-unbound" >/dev/null || rc=1
  fi
  for i in $(seq 1 30); do
    [ "$SECONDS" -lt "$seal_cleanup_until" ] || break
    for ns in "$T-unbound" "$T"; do
      for id in $(seal_cleanup_cli machine ls --namespace "$ns" 2>/dev/null | awk 'NR>1{print $1}'); do
        seal_cleanup_cli machine rm "$id" >/dev/null 2>&1
      done
      seal_cleanup_cli namespace rm "$ns" >/dev/null 2>&1
    done
    maintenance=$(seal_cleanup_api "$BRIQYARD_URL/v1/maintenance/warm-catalog")
    namespaces=$(seal_cleanup_cli namespace ls 2>/dev/null)
    if echo "$namespaces" | jq -e --arg t "$T" 'all(.[]; .id != $t and .id != ($t + "-unbound"))' >/dev/null && echo "$maintenance" | jq -e '.eligible and .reason == "eligible" and (.counts | .desired_slots == 0 and .pool_claims == 0 and .warm_machines == 0 and .launch_holds == 0 and .launch_transitions == 0 and .warm_names == 0 and .pending_assignments == 0 and .run_authorities == 0)' >/dev/null; then clean=1; break; fi
    sleep 1
  done
  if [ "$clean" = 1 ]; then ok 'sealed cleanup leaves no pending warm authority'; else
    echo 'sealed cleanup incomplete; refusing shared SIGUSR2 handover' >&2
    rc=1
  fi
  # The old daemon still uses the fixture token. Capture it before switching CLI
  # authentication; only the replacement is queried using the original token.
  if [ "$clean" = 1 ]; then
    if before=$(seal_cleanup_cli warm-maintenance 2>/dev/null); then
      before=$(printf '%s' "$before" | jq -er '.observation.incarnation | select(type == "string" and length > 0)' 2>/dev/null) || {
        echo 'sealed restoration: previous_incarnation_invalid' >&2
        clean=0; rc=1
      }
    else
      status=$?
      case "$status" in
        124|137) echo 'sealed restoration: previous_incarnation_timeout' >&2;;
        *) echo 'sealed restoration: previous_incarnation_query' >&2;;
      esac
      clean=0; rc=1
    fi
  fi
  if timeout --kill-after=2 10s sudo cp "$seal_config" /etc/briqyard/config.yaml 2>/dev/null; then
    rm -f "$seal_config"
    restored=1
  else
    status=$?
    case "$status" in
      124|137) echo 'sealed restoration: config_restore_timeout' >&2;;
      *) echo 'sealed restoration: config_restore' >&2;;
    esac
    echo 'original configuration restore failed; private backup retained' >&2
    rc=1
  fi
  if [ -n "$seal_original_token" ]; then export BRIQYARD_TOKEN=$seal_original_token; else unset BRIQYARD_TOKEN; fi
  if [ "$clean" = 1 ] && [ "$restored" = 1 ]; then
    export seal_handover_projection seal_handover_seconds
    export -f seal_restore_handover
    timeout --kill-after=2 "${seal_handover_seconds}s" bash -c 'seal_restore_handover "$1"' seal-restoration "$before" || {
      case "$?" in
        124|137) echo 'sealed restoration: overall_timeout' >&2;;
        *) echo 'sealed restoration: handover_failed' >&2;;
      esac
      rc=1
    }
  fi
  printf "%s %s\n" "$pass" "$fail" > "$seal_counts"
  exit "$rc"
}
trap seal_cleanup EXIT
trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP
sudo cp /etc/briqyard/config.yaml "$seal_config"
seal_saved=1
sudo python3 - <<'PYCONFIG'
from pathlib import Path
import yaml
p = Path('/etc/briqyard/config.yaml')
c = yaml.safe_load(p.read_text())
c['token'] = 'native-seal-test'
import hashlib
init = hashlib.sha256(Path('/usr/local/bin/briqyard-init').read_bytes()).hexdigest()
c['templates'] = {'enabled': True, 'init_ready_init_sha256': init, 'sandbox_recipes': [
    {'image': 'docker.io/library/alpine@sha256:85f2b723e106c34644cd5851d7e81ee87da98ac54672b29947c052a45d31dc2f',
     'image_config_digest': 'sha256:706db57fb2063f39f69632c5b5c9c439633fda35110e65587c5d85553fd1cc38',
     'init_sha256': init, 'size': {'vcpus': 1, 'memory_mb': 256}, 'volume_gb': gb}
    for gb in [0, 1]]}
p.write_text(yaml.safe_dump(c, sort_keys=False))
PYCONFIG
export BRIQYARD_TOKEN=native-seal-test
auth=(-H 'Authorization: Bearer native-seal-test')
handover
echo '== sealed seeds: both disk shapes, create and first command'
seal_image=docker.io/library/alpine@sha256:85f2b723e106c34644cd5851d7e81ee87da98ac54672b29947c052a45d31dc2f
for seal_gb in 0 1; do
  seal_volume=null
  if [ "$seal_gb" = 1 ]; then seal_volume='{"size_gb":1,"mount":"/work"}'; fi
  seal_builder=$(jq -n --arg ns "$T" --arg image "$seal_image" --arg name "seal-$seal_gb" --argjson volume "$seal_volume" \
    '{namespace:$ns,name:$name,image:$image,size:{vcpus:1,memory_mb:256},sleep:"never",start:true,egress:{mode:"none"},template_build:"sandbox-ready-v1",volume:$volume}' |
    seal_api -H 'Content-Type: application/json' -d @- "$BRIQYARD_URL/v1/machines" | jq -er .id)
  seal_api -X POST "$BRIQYARD_URL/v1/machines/$seal_builder/wait?for=running&timeout=120" >/dev/null
  seal_snapshot=$(seal_api -H 'Content-Type: application/json' -d '{"memory":true,"template":true}' "$BRIQYARD_URL/v1/machines/$seal_builder/snapshots")
  check "seed $seal_gb sealed" '[ "$(echo "$seal_snapshot" | jq -r .clone_generation)" != null ]'
  seal_machine=$(jq -n --arg ns "$T" --arg image "$seal_image" --arg name "sealed-create-$seal_gb" --arg source "$seal_builder" --arg snap "$(echo "$seal_snapshot" | jq -r .id)" --arg gen "$(echo "$seal_snapshot" | jq -r .clone_generation)" --argjson volume "$seal_volume" \
    '{namespace:$ns,name:$name,image:$image,size:{vcpus:1,memory_mb:256},sleep:"never",start:true,volume:$volume,cmd:["/bin/sh","-ec","sleep infinity"],sandbox_seed:{machine_id:$source,snapshot:$snap,generation:$gen,request_id:$name}}' |
    seal_api -H 'Content-Type: application/json' -d @- "$BRIQYARD_URL/v1/machines" | jq -er .id)
  seal_api -X POST "$BRIQYARD_URL/v1/machines/$seal_machine/wait?for=running&timeout=120" >/dev/null
  check "seed $seal_gb create first command" '[ "$(briqyard machine exec "$seal_machine" -- echo sealed-first-command)" = sealed-first-command ]'
  briqyard machine rm "$seal_machine" >/dev/null
  if [ "$seal_gb" = 1 ]; then . "$(dirname "${BASH_SOURCE[0]}")/e2e-unbound.sh"; fi
  # The cleanup trap destroys the positive-DATA source after its pool and claims.
  if [ "$seal_gb" = 0 ]; then briqyard machine rm "$seal_builder" >/dev/null; fi
done
# Preserve the check counts across the subshell via a small result file.
printf "%s %s\n" "$pass" "$fail" > "$seal_counts"
)
read -r pass fail < "$seal_counts"
rm -f "$seal_counts"

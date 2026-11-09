# Sourced by e2e.sh; its namespace cleanup owns every builder and destination.
[ "${RUNNER_ENVIRONMENT:-}" = github-hosted ] || { echo 'sealed acceptance requires a disposable CI host' >&2; exit 2; }
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
  local expected before=$1 old_pid new_pid observed until
  expected=$(timeout --kill-after=2 5s sudo briqyardd --config /etc/briqyard/config.yaml check-config) || return 1
  old_pid=$(timeout --kill-after=2 3s systemctl show -p MainPID --value briqyardd) || return 1
  [[ "$old_pid" =~ ^[1-9][0-9]*$ ]] || return 1
  timeout --kill-after=2 5s sudo systemctl kill --kill-whom=main --signal=SIGUSR2 briqyardd || return 1
  until=$((SECONDS + 15))
  while [ "$SECONDS" -lt "$until" ]; do
    new_pid=$(timeout --kill-after=2 3s systemctl show -p MainPID --value briqyardd) || return 1
    [ "$new_pid" != "$old_pid" ] && break
    sleep 0.1
  done
  [ "$new_pid" != "$old_pid" ] || return 1
  timeout --kill-after=2 5s sudo systemctl start briqyardd || return 1
  until=$((SECONDS + 25))
  while [ "$SECONDS" -lt "$until" ]; do
    observed=$(timeout --kill-after=2 3s briqyard warm-maintenance) || observed=
    if printf '%s' "$observed" | jq -e --arg old "$before" --argjson config "$expected" \
      '.observation.incarnation != $old and (.observation.incarnation | type == "string" and length > 0) and .observation.config == $config' >/dev/null; then return 0; fi
    sleep 0.1
  done
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
  # 70 seconds for handover. Never spend the restoration reserve on API retries.
  local clean=0 restored=0 maintenance namespaces before=
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
    before=$(seal_cleanup_cli warm-maintenance | jq -er .observation.incarnation) || { clean=0; rc=1; }
  fi
  if timeout --kill-after=2 10s sudo cp "$seal_config" /etc/briqyard/config.yaml; then
    rm -f "$seal_config"
    restored=1
  else
    echo 'original configuration restore failed; private backup retained' >&2
    rc=1
  fi
  if [ -n "$seal_original_token" ]; then export BRIQYARD_TOKEN=$seal_original_token; else unset BRIQYARD_TOKEN; fi
  if [ "$clean" = 1 ] && [ "$restored" = 1 ]; then
    export -f seal_restore_handover
    timeout --kill-after=2 70s bash -c 'seal_restore_handover "$1"' seal-restoration "$before" || rc=1
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

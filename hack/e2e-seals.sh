# Sourced by e2e.sh; its namespace cleanup owns every builder and destination.
seal_counts=$(mktemp)
(
# Operator seed APIs require authenticated mode. Scope this disposable-runner token
# to the check and restore the original configuration on every exit.
seal_config=$(mktemp)
sudo cp /etc/briqyard/config.yaml "$seal_config"
seal_cleanup() {
  local rc=$?
  trap - EXIT
  sudo cp "$seal_config" /etc/briqyard/config.yaml
  rm -f "$seal_config"
  unset BRIQYARD_TOKEN
  handover
  exit "$rc"
}
trap seal_cleanup EXIT
trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP
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
    "${CURL[@]}" -fsS "${auth[@]}" -H 'Content-Type: application/json' -d @- "$BRIQYARD_URL/v1/machines" | jq -er .id)
  "${CURL[@]}" -fsS "${auth[@]}" -X POST "$BRIQYARD_URL/v1/machines/$seal_builder/wait?for=running&timeout=120" >/dev/null
  seal_snapshot=$("${CURL[@]}" -fsS "${auth[@]}" -H 'Content-Type: application/json' -d '{"memory":true,"template":true}' "$BRIQYARD_URL/v1/machines/$seal_builder/snapshots")
  check "seed $seal_gb sealed" '[ "$(echo "$seal_snapshot" | jq -r .clone_generation)" != null ]'
  seal_machine=$(jq -n --arg ns "$T" --arg image "$seal_image" --arg name "sealed-create-$seal_gb" --arg source "$seal_builder" --arg snap "$(echo "$seal_snapshot" | jq -r .id)" --arg gen "$(echo "$seal_snapshot" | jq -r .clone_generation)" --argjson volume "$seal_volume" \
    '{namespace:$ns,name:$name,image:$image,size:{vcpus:1,memory_mb:256},sleep:"never",volume:$volume,cmd:["-ec","sleep infinity"],sandbox_seed:{machine_id:$source,snapshot:$snap,generation:$gen,request_id:$name}}' |
    "${CURL[@]}" -fsS "${auth[@]}" -H 'Content-Type: application/json' -d @- "$BRIQYARD_URL/v1/machines" | jq -er .id)
  "${CURL[@]}" -fsS "${auth[@]}" -X POST "$BRIQYARD_URL/v1/machines/$seal_machine/wait?for=running&timeout=120" >/dev/null
  check "seed $seal_gb create first command" '[ "$(briqyard machine exec "$seal_machine" -- echo sealed-first-command)" = sealed-first-command ]'
  briqyard machine rm "$seal_machine" >/dev/null
  briqyard machine rm "$seal_builder" >/dev/null
done
# Preserve the check counts across the subshell via a small result file.
printf "%s %s\n" "$pass" "$fail" > "$seal_counts"
)
read -r pass fail < "$seal_counts"
rm -f "$seal_counts"

# Sourced inside the authenticated seals fixture, with its positive-DATA builder alive.
# No cold restore may satisfy these checks: every warm create must consume the observed ID.
unbound_catalog=$BRIQYARD_URL/v1/namespaces/$T/warm-catalog/native-unbound
unbound_pools=$BRIQYARD_URL/v1/namespaces/$T/warm-pools
unbound_helper=$(dirname "${BASH_SOURCE[0]}")/e2e-unbound-proof.py
unbound_recipe=$(seal_api "$BRIQYARD_URL/v1/machines/$seal_builder/snapshots/$(echo "$seal_snapshot" | jq -r .id)/sandbox-recipe")
printf '%s' "$unbound_recipe" | sudo python3 -c '
import json, sys, yaml
from pathlib import Path
r = json.load(sys.stdin)
assert r["profile"] == "sandbox-ready-v1"
assert r["data_device"]["bytes"] == 1 << 30 and r["data_device"]["logical_sector_bytes"] == 512
p = Path("/etc/briqyard/config.yaml")
c = yaml.safe_load(p.read_text())
t = c["templates"]
t.update(warm_pools=True, unbound_warm_pools=True)
t["warm_policy"] = {
    "budget": {"memory_mb": 1024, "cpu_millis": 4000, "root_disk_gb": r["root_disk_gb"], "data_disk_gb": 2},
    "headroom": {"memory_mb": 512, "cpu_millis": 1000, "disk_free_gb": 1},
    "min_mem_available_mb": 512, "max_fills": 1,
    "catalog": [{"id": "native-unbound", "namespace": r["namespace"], "type": "sandbox",
                 "source_machine": r["source_machine"], "snapshot": r["snapshot"],
                 "generation": r["generation"], "size": r["size"], "max_ready": 2}]}
p.write_text(yaml.safe_dump(c, sort_keys=False))'
unbound_config=$(sudo briqyardd --config /etc/briqyard/config.yaml check-config)
handover
check 'unbound loaded configuration matches parser' '[ "$(seal_api "$BRIQYARD_URL/v1/maintenance/warm-catalog" | jq -cS .observation.config)" = "$(echo "$unbound_config" | jq -cS .)" ]'
unbound_desired() { seal_api -X PUT -H 'Content-Type: application/json' -d "{\"desired\":$1}" "$unbound_catalog" >/dev/null; }
unbound_request() {
  jq -n --arg ns "$T-unbound" --arg image "$seal_image" --arg source "$seal_builder" --arg snap "$(echo "$seal_snapshot" | jq -r .id)" --arg gen "$(echo "$seal_snapshot" | jq -r .clone_generation)" --arg name "$1" \
    '{namespace:$ns,name:$name,image:$image,size:{vcpus:1,memory_mb:256},sleep:"never",start:true,volume:{size_gb:1,mount:"/work"},env:{NATIVE_BIND:$name},files:[{path:"/native-bind",base64:($name|@base64)}],cmd:["/bin/sh","-ec","test \"$(cat /native-bind)\" = \"$NATIVE_BIND\"; test ! -e /work/first-sentinel; echo \"$NATIVE_BIND\" >> /work/activations; sleep infinity"],sandbox_seed:{machine_id:$source,snapshot:$snap,generation:$gen,request_id:$name}}'
}
unbound_create() { seal_api -H 'Content-Type: application/json' -d "$1" "$BRIQYARD_URL/v1/machines" | jq -er .id; }
unbound_running() { seal_api -X POST "$BRIQYARD_URL/v1/machines/$1/wait?for=running&timeout=120" >/dev/null; }
# Isolate root exhaustion: DATA can hold two slots, root can hold only one.
unbound_desired 2
for i in $(seq 1 120); do
  unbound_status=$(seal_api "$BRIQYARD_URL/v1/namespaces/$T/warm-catalog")
  if echo "$unbound_status" | jq -e '.fills == 0 and any(.blocked[]; .reason == "budget") and ([.pools[].slots[] | select(.status == "ready")] | length) == 1' >/dev/null; then break; fi
  sleep 1
done
check 'root budget alone refuses a second slot' 'echo "$unbound_status" | jq -e --argjson root "$(echo "$unbound_recipe" | jq .root_disk_gb)" '\''.budget.root_disk_gb == $root and .budget.data_disk_gb == 2 and .charged.root_disk_gb == $root and .charged.data_disk_gb == 1 and .fills == 0 and any(.blocked[]; .reason == "budget") and ([.pools[].slots[] | select(.status == "ready")] | length) == 1'\'' >/dev/null'
unbound_desired 0
for i in $(seq 1 120); do
  unbound_status=$(seal_api "$BRIQYARD_URL/v1/maintenance/warm-catalog")
  if echo "$unbound_status" | jq -e '.eligible and .counts.warm_machines == 0 and .counts.launch_holds == 0' >/dev/null; then break; fi
  sleep 1
done
echo "$unbound_status" | jq -e '.eligible and .counts.warm_machines == 0 and .counts.launch_holds == 0' >/dev/null
# Now isolate DATA exhaustion: root can hold two slots, DATA only one.
sudo python3 - <<'PYBUDGET'
from pathlib import Path
import yaml
p = Path('/etc/briqyard/config.yaml')
c = yaml.safe_load(p.read_text())
budget = c['templates']['warm_policy']['budget']
budget['root_disk_gb'] *= 2
budget['data_disk_gb'] = 1
p.write_text(yaml.safe_dump(c, sort_keys=False))
PYBUDGET
handover
unbound_desired 0
unbound_fallback=$(unbound_create "$(unbound_request native-zero)")
unbound_running "$unbound_fallback"
check 'desired zero uses selected seed without a pool slot' '[ "$(seal_api "$unbound_pools" | jq "[.[].slots[]] | length")" = 0 ] && [ "$(briqyard machine exec "$unbound_fallback" -- cat /work/activations)" = native-zero ]'
briqyard machine rm "$unbound_fallback" >/dev/null
unbound_desired 2
unbound_previous=
for unbound_name in native-first native-second; do
  unbound_slot=
  for i in $(seq 1 120); do
    unbound_slot=$(seal_api "$unbound_pools" | jq -r '[.[].slots[] | select(.status == "ready") | .machine_id] | if length == 1 then .[0] else empty end')
    [ -n "$unbound_slot" ] && [ "$unbound_slot" != "$unbound_previous" ] && break
    sleep 1
  done
  [ -n "$unbound_slot" ] && [ "$unbound_slot" != "$unbound_previous" ] || { echo 'unbound refill did not produce a distinct slot' >&2; exit 1; }
  unbound_before=$(sudo python3 "$unbound_helper" /etc/briqyard/config.yaml "$unbound_slot" paused)
  # Wait for the attempted over-budget second fill to settle, rather than sampling
  # the first ready notification before admission has run.
  for i in $(seq 1 30); do
    unbound_status=$(seal_api "$BRIQYARD_URL/v1/namespaces/$T/warm-catalog")
    if echo "$unbound_status" | jq -e '.fills == 0 and any(.blocked[]; .reason == "budget")' >/dev/null; then break; fi
    [ "$unbound_name" != native-first ] && break
    sleep 1
  done
  if [ "$unbound_name" = native-first ]; then
    if echo "$unbound_status" | jq -e --argjson root "$(echo "$unbound_recipe" | jq .root_disk_gb)" '.budget.root_disk_gb == (2 * $root) and .budget.data_disk_gb == 1 and .fills == 0 and any(.blocked[]; .reason == "budget") and ([.pools[].slots[] | select(.status == "ready")] | length) == 1' >/dev/null; then
      ok 'DATA budget alone refuses a second slot with root room for two'
    else bad 'DATA budget alone refuses a second slot with root room for two'; fi
    unbound_desired 1
  fi
  check 'paused slot charges full root and DATA liabilities with bounded fill' 'echo "$unbound_status" | jq -e --argjson root "$(echo "$unbound_recipe" | jq .root_disk_gb)" '\''.charged == {memory_mb:256,cpu_millis:1000,root_disk_gb:$root,data_disk_gb:1} and .fills == 0 and .max_fills == 1'\'' >/dev/null'
  if [ -n "$unbound_previous" ]; then
    check 'refill has independent DATA backing' '[ "$(echo "$unbound_before" | jq -r .devices[1].guid)" != "$unbound_first_data" ]'
  else
    unbound_first_data=$(echo "$unbound_before" | jq -r .devices[1].guid)
  fi
  unbound_body=$(unbound_request "$unbound_name")
  unbound_claim=$(unbound_create "$unbound_body")
  [ "$unbound_claim" = "$unbound_slot" ] || { echo 'warm create did not consume actual slot ID' >&2; exit 1; }
  unbound_running "$unbound_claim"
  unbound_after=$(sudo python3 "$unbound_helper" /etc/briqyard/config.yaml "$unbound_claim" active)
  check 'warm claim preserves actual process boot root and DATA' '[ "$unbound_before" = "$unbound_after" ]'
  unbound_replay=$(unbound_create "$unbound_body")
  check 'exact request replay keeps ID and activates main once after binding' '[ "$unbound_replay" = "$unbound_claim" ] && [ "$(briqyard machine exec "$unbound_claim" -- cat /work/activations)" = "$unbound_name" ]'
  unbound_code=$(echo "$unbound_body" | jq '.env.NATIVE_BIND = "changed"' | "${CURL[@]}" --max-time 15 -sS "${auth[@]}" -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -d @- "$BRIQYARD_URL/v1/machines")
  check 'changed body under same request ID conflicts' '[ "$unbound_code" = 409 ]'
  briqyard machine exec "$unbound_claim" -- touch /work/first-sentinel >/dev/null
  # Keep first claim alive through second claim: distinct DATA must not inherit its sentinel.
  unbound_previous=$unbound_slot
done
unbound_desired 0

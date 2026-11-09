# Sourced by e2e.sh; its namespace cleanup owns every builder and destination.
# shellcheck shell=bash
# Assertions evaluated by check read the fixture variables.
# shellcheck disable=SC2034
seal_counts=$(mktemp)
(
# Operator seed APIs require authenticated mode. Scope this disposable-runner token
# to the check and restore the original configuration on every exit.
seal_original_token=${BRIQYARD_TOKEN:-}
seal_config=$(mktemp)
sudo cp /etc/briqyard/config.yaml "$seal_config"
seal_cleanup() {
  local rc=$?
  trap - EXIT
  set +e
  sudo cp "$seal_config" /etc/briqyard/config.yaml || rc=1
  rm -f "$seal_config" || rc=1
  export BRIQYARD_TOKEN=$seal_original_token
  handover || rc=1
  briqyard status >/dev/null || rc=1
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
init = hashlib.sha256(Path(c['init']).read_bytes()).hexdigest()
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
# Keep failed API responses visible even when a successful response feeds jq.
seal_api() {
  local response rc=0
  response=$("${CURL[@]}" --fail-with-body -sS "${auth[@]}" "$@") || rc=$?
  if [ "$rc" != 0 ]; then
    printf '%s\n' "$response" >&2
    return "$rc"
  fi
  printf '%s\n' "$response"
}
# Compare real guest observations with the public machine identity and namespace network.
seal_network_check() {
  python3 - "$@" <<'PYNETWORK'
import ipaddress, json, sys
source, first, second, namespace = [json.loads(v) for v in sys.argv[1:5]]
subnet = ipaddress.ip_network(namespace['subnet'])
router = str(ipaddress.ip_address(namespace['router']))
source_ip = ipaddress.ip_address(source['ip'])
source_mac = '06:b1:' + ':'.join(f'{v:02x}' for v in source_ip.packed)
seen_ips, seen_macs = {source_ip}, {source_mac}
markers = set()
for machine, observation in zip((first, second), sys.argv[5:]):
    origin = machine['memory_origin']
    assert origin['source_machine'] == source['id'] and origin['stage'] == 'active'
    assert origin['snapshot'] == source['snapshot'] and origin['generation'] == source['generation']
    assert origin['ram_marker'] and origin['identity'] is not None
    markers.add(origin['ram_marker'])
    identity = origin['identity']
    mac, address, hostname, *routes = observation.splitlines()
    ip = ipaddress.ip_interface(address)
    expected_ip = ipaddress.ip_address(machine['ip'])
    assert ip.ip == expected_ip and ip.network == subnet and expected_ip not in seen_ips
    assert identity['ip'] == str(ip) and hostname == machine['hostname'] == identity['hostname']
    expected_mac = ':'.join(f'{v:02x}' for v in identity['mac'])
    assert mac == expected_mac and mac not in seen_macs and identity['mac'][0] & 3 == 2
    # Siblings share the namespace's gateway; their connected route must name their own IP.
    assert len(routes) == 2, routes
    default, connected = sorted((route.split() for route in routes), key=lambda r: r[0] != 'default')
    assert default[:3] == ['default', 'via', router] and default[default.index('dev') + 1] == 'eth0'
    assert connected[0] == str(subnet) and connected[connected.index('dev') + 1] == 'eth0'
    assert connected[connected.index('src') + 1] == str(expected_ip)
    seen_ips.add(expected_ip)
    seen_macs.add(mac)
assert len(seen_ips) == len(seen_macs) == 3
assert len(markers) == 1
PYNETWORK
}
echo '== sealed seeds: both disk shapes, sibling identities and first commands'
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
  # A stale restored wall clock must fall outside the one-second rounding allowance below.
  sleep 5
  seal_source=$(seal_api "$BRIQYARD_URL/v1/machines/$seal_builder" | jq --arg snapshot "$(echo "$seal_snapshot" | jq -r .id)" --arg generation "$(echo "$seal_snapshot" | jq -r .clone_generation)" '{id,ip,snapshot:$snapshot,generation:$generation}')
  seal_namespace=$(seal_api "$BRIQYARD_URL/v1/namespaces/$T" | jq '{subnet,router}')
  seal_siblings=()
  seal_views=()
  seal_observations=()
  for seal_sibling in first second; do
    seal_machine=$(jq -n --arg ns "$T" --arg image "$seal_image" --arg name "sealed-create-$seal_gb-$seal_sibling" --arg source "$seal_builder" --arg snap "$(echo "$seal_snapshot" | jq -r .id)" --arg gen "$(echo "$seal_snapshot" | jq -r .clone_generation)" --argjson volume "$seal_volume" \
    '{namespace:$ns,name:$name,image:$image,size:{vcpus:1,memory_mb:256},sleep:"never",start:true,volume:$volume,cmd:["/bin/sh","-ec","sleep infinity"],sandbox_seed:{machine_id:$source,snapshot:$snap,generation:$gen,request_id:$name}}' |
    seal_api -H 'Content-Type: application/json' -d @- "$BRIQYARD_URL/v1/machines" | jq -er .id)
    seal_api -X POST "$BRIQYARD_URL/v1/machines/$seal_machine/wait?for=running&timeout=120" >/dev/null
    check "seed $seal_gb $seal_sibling first command" '[ "$(briqyard machine exec "$seal_machine" -- echo sealed-first-command)" = sealed-first-command ]'
    seal_before=$(date +%s)
    seal_guest_time=$(briqyard machine exec "$seal_machine" -- date +%s)
    seal_after=$(date +%s)
    check "seed $seal_gb $seal_sibling wall clock matches host after aged restore" '[[ "$seal_guest_time" =~ ^[0-9]+$ ]] && [ "$seal_guest_time" -ge "$((seal_before - 1))" ] && [ "$seal_guest_time" -le "$((seal_after + 1))" ]'
    seal_siblings+=("$seal_machine")
    seal_views+=("$(seal_api "$BRIQYARD_URL/v1/machines/$seal_machine" | jq '{ip,hostname,memory_origin}')")
    seal_observations+=("$(briqyard machine exec "$seal_machine" -- sh -ec 'cat /sys/class/net/eth0/address; ip -4 addr show dev eth0 | awk '\''$1 == "inet" {print $2}'\''; hostname; ip -4 route show')")
    # Write both markers before reading either: a shared control socket would overwrite one.
    briqyard machine exec "$seal_machine" -- sh -ec 'printf "%s\n" "$1" > /tmp/native-seal-nonce' sh "$T-$seal_gb-$seal_sibling" >/dev/null
  done
  check "seed $seal_gb sibling network identities and routes match destinations" 'seal_network_check "$seal_source" "${seal_views[0]}" "${seal_views[1]}" "$seal_namespace" "${seal_observations[0]}" "${seal_observations[1]}"'
  check "seed $seal_gb first vsock reaches only its own nonce" '[ "$(briqyard machine exec "${seal_siblings[0]}" -- cat /tmp/native-seal-nonce)" = "$T-$seal_gb-first" ]'
  check "seed $seal_gb second vsock reaches only its own nonce" '[ "$(briqyard machine exec "${seal_siblings[1]}" -- cat /tmp/native-seal-nonce)" = "$T-$seal_gb-second" ]'
  # The unbound source is deliberately unaddressed and cannot execute a nonce (ADR 0072).
  seal_source_rc=0
  seal_source_reply=$(briqyard machine exec --timeout 10s "$seal_builder" -- echo "$T-$seal_gb-source" 2>&1) || seal_source_rc=$?
  check "seed $seal_gb source keeps its exec barrier across sibling activation" '[ "$seal_source_rc" != 0 ] && [[ "$seal_source_reply" == *"clone barrier: operation unavailable"* ]]'
  for seal_machine in "${seal_siblings[@]}"; do briqyard machine rm "$seal_machine" >/dev/null; done
  briqyard machine rm "$seal_builder" >/dev/null
done
# Preserve the check counts across the subshell via a small result file.
printf "%s %s\n" "$pass" "$fail" > "$seal_counts"
)
read -r pass fail < "$seal_counts"
rm -f "$seal_counts"

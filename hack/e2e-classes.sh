# Sourced by e2e.sh: runtime classes (ADR 0088). The nested class is served only by an x86_64 host
# configured for it (BRIQYARD_RUNTIME_CLASSES=nested at the bootstrap), so its checks run only where
# the daemon lists it; where it does not there is no line for them, as for ADR 0087's check.
echo "== runtime classes"
check "status lists the classes the host serves" 'briqyard status | jq -e "(.runtime_classes // []) | type == \"array\"" >/dev/null'
check "an unknown class is refused by name" 'out=$(briqyard machine run --image alpine:3.20 --name nope --namespace "$T" --runtime-class nonesuch -- sleep 60 2>&1 || true); echo "$out" | grep -q "runtime class nonesuch is not served by this host"'
check "machines are of the default class" '[ "$(briqyard machine get "$A" | jq -r .runtime_class)" = default ] && briqyard machine ls --namespace "$T" | awk "NR==1 { for (i = 1; i <= NF; i++) if (\$i == \"CLASS\") c = i } NR>1 && \$1 == \"$A\" { print \$c }" | grep -qx default'
if briqyard status | jq -e '.runtime_classes[]? | select(.name == "nested")' >/dev/null; then
  NS=$(briqyard machine run --image alpine:3.20 --name nested --namespace "$T" --memory 256 --runtime-class nested -- sleep 3600 | jq -r .id)
  check "nested: its class is shown"          '[ "$(briqyard machine get "$NS" | jq -r .runtime_class)" = nested ]'
  check "nested: /dev/kvm in the guest"       'briqyard machine exec "$NS" -- test -c /dev/kvm'
  check "nested: vmx or svm in the guest"     'briqyard machine exec "$NS" -- grep -Ewq "vmx|svm" /proc/cpuinfo'
  check "nested: its modules at its release"  'briqyard machine exec "$NS" -- sh -c "test -d /lib/modules/\$(uname -r) && grep -q \" /lib/modules/\$(uname -r) .* ro,\" /proc/mounts"'
  check "nested: memory snapshot refused, naming the class" 'out=$(briqyard machine snapshot create --memory "$NS" 2>&1 || true); echo "$out" | grep -q "runtime class nested"'
  briqyard machine stop --suspend "$NS" >/dev/null
  check "nested: a stop with suspend is a plain stop" '[ "$(briqyard machine get "$NS" | jq -r .suspended)" = false ] && briqyard events --machine "$NS" | grep -q "suspend: refused (runtime class nested)"'
  briqyard machine start "$NS" >/dev/null
  briqyard machine wait "$NS" >/dev/null 2>&1 || true
  check "nested: a wake is a cold boot with /dev/kvm" 'briqyard machine exec "$NS" -- test -c /dev/kvm'
  NF=$(briqyard machine fork "$NS" --name nested-fork --namespace "$T" | jq -r .id)
  check "nested: a fork takes its source's class" '[ "$(briqyard machine get "$NF" | jq -r .runtime_class)" = nested ]'
fi

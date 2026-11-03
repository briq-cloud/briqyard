#!/usr/bin/env bash
# Disposable runner only; no daemon or shared development VM is touched.
set -euo pipefail
[ "${RUNNER_ENVIRONMENT:-}" = github-hosted ] || exit 2
WORK=$RUNNER_TEMP/two-host-probe
mkdir -p "$WORK" native-logs
exec > >(tee native-logs/two-host-probe.log) 2>&1
qemu_pid=
cleanup() {
  rc=$?
  trap - EXIT
  if [ -n "$qemu_pid" ] && [ "${KEEP_SECOND_HOST:-0}" != 1 ]; then sudo kill "$qemu_pid" 2>/dev/null || true; wait "$qemu_pid" || true; fi
  cp "$WORK/serial.log" native-logs/qemu-serial.log 2>/dev/null || true
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP
uname -a
lscpu
ls -l /dev/kvm
for module in kvm_intel kvm_amd; do
  param=/sys/module/$module/parameters/nested
  [ -f "$param" ] || continue
  echo "nested before: $module $(cat "$param")"
  case "$(cat "$param")" in
    Y|1) ;;
    *)
      # No VMs have been started by this job. Reload only the vendor module.
      if sudo modprobe -r "$module"; then sudo modprobe "$module" nested=1; fi
      ;;
  esac
  echo "nested after: $module $(cat "$param")"
done
sudo apt-get update -qq
sudo apt-get install -y -qq qemu-system-x86 qemu-utils cloud-image-utils
fetch() { curl -fsSL "$1" -o "$3"; echo "$2  $3" | sha256sum -c -; }
fetch https://cloud-images.ubuntu.com/releases/noble/release-20261017/ubuntu-24.04-server-cloudimg-amd64.img \
  04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94 "$WORK/base.img"
qemu-img create -f qcow2 -F qcow2 -b "$WORK/base.img" "$WORK/root.qcow2" 30G
ssh-keygen -q -t ed25519 -N '' -f "$WORK/key"
ssh-keygen -q -t ed25519 -N '' -f "$WORK/host_key"
cat > "$WORK/user-data" <<YAML
#cloud-config
ssh_pwauth: false
disable_root: false
ssh_authorized_keys:
  - $(cat "$WORK/key.pub")
ssh_keys:
  ed25519_private: |
$(sed 's/^/    /' "$WORK/host_key")
  ed25519_public: $(cat "$WORK/host_key.pub")
YAML
printf 'instance-id: two-host-probe\nlocal-hostname: fc2\n' > "$WORK/meta-data"
cloud-localds "$WORK/seed.img" "$WORK/user-data" "$WORK/meta-data"
printf '[127.0.0.1]:2222 %s\n' "$(cat "$WORK/host_key.pub")" > "$WORK/known_hosts"
ssh_opts=(-i "$WORK/key" -p 2222 -o UserKnownHostsFile="$WORK/known_hosts" -o StrictHostKeyChecking=yes -o BatchMode=yes -o ConnectTimeout=3)
start=$SECONDS
sudo qemu-system-x86_64 -enable-kvm -cpu host -smp 2 -m 6144 -display none \
  -serial "file:$WORK/serial.log" -monitor none \
  -drive "file=$WORK/root.qcow2,if=virtio,format=qcow2" \
  -drive "file=$WORK/seed.img,if=virtio,format=raw,readonly=on" \
  -netdev user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22,hostfwd=tcp:127.0.0.1:27420-:7420 -device virtio-net-pci,netdev=net0 &
qemu_pid=$!
printf '%s\n' "$qemu_pid" > "$WORK/pid"
ready=0
for _ in $(seq 1 180); do
  if ssh "${ssh_opts[@]}" ubuntu@127.0.0.1 true 2>/dev/null; then ready=1; break; fi
  kill -0 "$qemu_pid" || break
  sleep 1
done
echo "QEMU SSH boot seconds: $((SECONDS-start))"
[ "$ready" = 1 ] || { echo 'ENVIRONMENT GATE: QEMU failed to boot'; exit 1; }
ssh "${ssh_opts[@]}" ubuntu@127.0.0.1 'sudo bash -s' <<'GUEST'
set -euo pipefail
uname -a
lscpu
sudo modprobe kvm_intel || true
ls -l /dev/kvm || true
python3 - <<'PY'
import os, fcntl, sys, time
start=time.monotonic()
try:
    kvm=os.open('/dev/kvm',os.O_RDWR)
    print('KVM API version:',fcntl.ioctl(kvm,0xae00,0))
    vm=fcntl.ioctl(kvm,0xae01,0)
    os.close(vm); os.close(kvm)
    print('Nested KVM_CREATE_VM seconds:',time.monotonic()-start)
except OSError as e:
    print('ENVIRONMENT GATE: nested KVM unavailable:',e)
    sys.exit(1)
PY
GUEST

printf '%s\n' "$qemu_pid" > "$WORK/pid"
# Suite shell adapter: preserve every argument through SSH's command string.
cat > "$WORK/second-host" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
WORK=${RUNNER_TEMP:?}/two-host-probe
printf -v remote '%q ' "$@"
exec ssh -i "$WORK/key" -p 2222 -o UserKnownHostsFile="$WORK/known_hosts" -o StrictHostKeyChecking=yes -o BatchMode=yes ubuntu@127.0.0.1 "sudo $remote"
SH
chmod 700 "$WORK/second-host"

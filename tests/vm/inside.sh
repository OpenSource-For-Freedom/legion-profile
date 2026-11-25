#!/usr/bin/env bash
# Runs inside the runner container: boots the VM and drives the test.
set -euo pipefail
W="$(mktemp -d)"
qemu-img create -q -f qcow2 -F qcow2 -b /cache/resolute-server-cloudimg-amd64.img "$W/disk.qcow2" 20G
ssh-keygen -q -t ed25519 -N '' -f "$W/key"
cat >"$W/user-data" <<EOD
#cloud-config
users:
  - name: legion
    groups: [sudo]
    shell: /bin/bash
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    lock_passwd: false
    ssh_authorized_keys: ["$(cat "$W/key.pub")"]
chpasswd:
  expire: false
  users: [{name: legion, password: Correct-Horse-9x, type: text}]
EOD
echo "instance-id: legion-vm" >"$W/meta-data"
cloud-localds "$W/seed.img" "$W/user-data" "$W/meta-data"
boot() {
  qemu-system-x86_64 -enable-kvm -cpu host -m 4096 -smp 4 -display none -monitor none \
    -serial "file:$W/console.log" \
    -drive "file=$W/disk.qcow2,if=virtio" -drive "file=$W/seed.img,if=virtio,format=raw" \
    -netdev user,id=n0,hostfwd=tcp:127.0.0.1:2222-:22 -device virtio-net-pci,netdev=n0 &
  QEMU=$!
}
# One shared SSH connection: the firewall Legion sets up rate-limits new
# SSH connections, as it should.
S=(-i "$W/key" -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes
  -o LogLevel=ERROR -o ControlMaster=auto -o "ControlPath=$W/cm" -o ControlPersist=900 -o ServerAliveInterval=15)
# shellcheck disable=SC2029 # commands are meant to run in the VM
vm() { ssh "${S[@]}" legion@127.0.0.1 "$@"; }
wait_ssh() {

  for _ in $(seq 1 90); do vm true 2>/dev/null && return 0; sleep 5; done
  echo "VM did not come up; console:"; tail -n 40 "$W/console.log"; exit 1
}
boot
wait_ssh
vm cloud-init status --wait >/dev/null || true
echo "VM up: $(vm 'lsb_release -ds; uname -r')"
tar -C /repo -cf - legion.sh legion-remove.sh assets tests/vm/vm-scenario.sh | vm 'mkdir -p ~/legion && tar -C ~/legion -xf -'
P=0 F=0
phase() {
  local out
  out="$(vm "sudo bash ~/legion/tests/vm/vm-scenario.sh $1" 2>&1)" || true
  echo "$out"
  P=$((P + $(grep -c '^PASS' <<<"$out" || true))) F=$((F + $(grep -c '^FAIL' <<<"$out" || true)))
}
phase before
phase install
echo "=== reboot"
vm 'sudo systemctl reboot' || true
ssh "${S[@]}" -O exit legion@127.0.0.1 2>/dev/null || true
sleep 10
wait_ssh
phase after-reboot
phase remove
vm 'sudo systemctl poweroff' || true
wait "$QEMU" 2>/dev/null || true
echo "VM RESULT: $P passed, $F failed"
[ "$F" = 0 ]

#!/usr/bin/env bash
# shellcheck disable=SC2016 # single-quoted commands run in the VM
# Runs inside the runner container: boots the VM and drives the test. The VM
# gets a desktop with the GNOME login screen, so logins are tested the way
# people use them: at the login screen (typed through QEMU), on the text
# console (serial port) and over SSH, across several restarts.
set -euo pipefail
W="$(mktemp -d)"
OUT=/out
trap 'chown -R "${HOST_UID:-0}" "$OUT" 2>/dev/null || true' EXIT
qemu-img create -q -f qcow2 -F qcow2 -b /cache/resolute-server-cloudimg-amd64.img "$W/disk.qcow2" 30G
ssh-keygen -q -t ed25519 -N '' -f "$W/key"
# Attack mode adds an ordinary user who logs in with a password, so password
# guessing over SSH can be tried against it.
victim_user="" victim_pw="" pwauth=false
if [ "${MODE:-full}" = attack ]; then
  victim_user=$'\n  - {name: victim, shell: /bin/bash, lock_passwd: false}'
  victim_pw=", {name: victim, password: Victim-Pass-77, type: text}"
  pwauth=true
fi
cat >"$W/user-data" <<EOD
#cloud-config
users:
  - name: legion
    groups: [sudo]
    shell: /bin/bash
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    lock_passwd: false
    ssh_authorized_keys: ["$(cat "$W/key.pub")"]$victim_user
ssh_pwauth: $pwauth
chpasswd:
  expire: false
  users: [{name: legion, password: Correct-Horse-9x, type: text}$victim_pw]
EOD
echo "instance-id: legion-vm" >"$W/meta-data"
cloud-localds "$W/seed.img" "$W/user-data" "$W/meta-data"
boot() {
  rm -f "$W/qmp.sock" "$W/serial.sock"
  qemu-system-x86_64 -enable-kvm -cpu host -m 4096 -smp 4 -vga virtio -display none -monitor none \
    -qmp "unix:$W/qmp.sock,server=on,wait=off" \
    -chardev "socket,id=s0,path=$W/serial.sock,server=on,wait=off,logfile=$W/console.log,logappend=on" -serial chardev:s0 \
    -drive "file=$W/disk.qcow2,if=virtio" -drive "file=$W/seed.img,if=virtio,format=raw" \
    -netdev user,id=n0,hostfwd=tcp:127.0.0.1:2222-:22,hostfwd=tcp:127.0.0.1:2280-:8080 -device virtio-net-pci,netdev=n0 &
  QEMU=$!
}
# One shared SSH connection: the firewall Legion sets up rate-limits new
# SSH connections, as it should.
S=(-i "$W/key" -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes
  -o LogLevel=ERROR -o ControlMaster=auto -o "ControlPath=$W/cm" -o ControlPersist=900 -o ServerAliveInterval=15)
# shellcheck disable=SC2029 # commands are meant to run in the VM
vm() { ssh "${S[@]}" legion@127.0.0.1 "$@"; }
wait_ssh() {
  for _ in $(seq 1 120); do vm true 2>/dev/null && return 0; sleep 5; done
  echo "VM did not come up; console:"; tail -n 40 "$W/console.log"; exit 1
}
P=0 F=0
t() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then echo "PASS  $d"; P=$((P + 1)); else echo "FAIL  $d"; F=$((F + 1)); fi; }
phase() {
  local out
  out="$(vm "sudo bash ~/legion/tests/vm/vm-scenario.sh $*" 2>&1)" || true
  echo "$out"
  P=$((P + $(grep -c '^PASS' <<<"$out" || true))) F=$((F + $(grep -c '^FAIL' <<<"$out" || true)))
}
restart() {
  echo "=== restart ($1)"
  local start=$SECONDS
  vm 'sudo systemctl reboot' || true
  ssh "${S[@]}" -O exit legion@127.0.0.1 2>/dev/null || true
  sleep 15
  wait_ssh
  echo "      back after $((SECONDS - start)) s"
}
shot() { python3 /repo/tests/vm/qmp.py screenshot "$W/qmp.sock" "$OUT/$1.png" && echo "      screenshot: $1.png"; }
# The login screen, the way a person uses it: type the user name and the
# password, then check a desktop session started.
gui_login() {
  local tag="$1" ok=0
  for _ in $(seq 1 60); do vm 'pgrep -x gnome-shell' >/dev/null 2>&1 && break; sleep 3; done
  sleep 10
  shot "$tag-login-screen"
  python3 /repo/tests/vm/qmp.py type "$W/qmp.sock" legion
  sleep 3
  python3 /repo/tests/vm/qmp.py type "$W/qmp.sock" Correct-Horse-9x
  for _ in $(seq 1 30); do
    if vm 'loginctl list-sessions --no-legend | awk "\$3 == \"legion\" && \$4 == \"seat0\"" | grep -q .'; then ok=1; break; fi
    sleep 3
  done
  sleep 8
  shot "$tag-after-login"
  t "login screen: legion logs in to a desktop session ($tag)" test "$ok" = 1
  # Log out again, so the next restart starts at the login screen.
  vm 'for s in $(loginctl list-sessions --no-legend | awk "\$4 == \"seat0\" && \$3 == \"legion\" { print \$1 }"); do sudo loginctl terminate-session "$s"; done' || true
}
console_login() { # tag [no-banner]
  local what="banner shown"
  [ "${2:-}" != no-banner ] || what="Ubuntu's own banner back"
  t "text console: $what and legion logs in ($1)" \
    python3 /repo/tests/vm/qmp.py console-login "$W/serial.sock" legion Correct-Horse-9x "${2:-banner}"
}

boot
wait_ssh
vm cloud-init status --wait >/dev/null || true
echo "VM up: $(vm 'lsb_release -ds; uname -r')"
tar -C /repo -cf - legion.sh legion-remove.sh assets tests/vm/vm-scenario.sh tests/vm/sensors.sh tests/vm/attack.sh | vm 'mkdir -p ~/legion && tar -C ~/legion -xf -'
if [ "${MODE:-full}" = attack ]; then
  aphase() { # like phase, for attack.sh
    local out
    out="$(vm "sudo bash ~/legion/tests/vm/attack.sh $*" 2>&1)" || true
    echo "$out"
    P=$((P + $(grep -c '^PASS' <<<"$out" || true))) F=$((F + $(grep -c '^FAIL' <<<"$out" || true)))
  }
  # From the runner, the VM's web service is at 127.0.0.1:2280; QEMU hands
  # the connection to the VM, where it arrives from outside (10.0.2.2).
  web_open() { python3 -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:2280/", timeout=5)' 2>/dev/null; }
  victim_ssh() { # password command...
    local pw="$1"; shift
    sshpass -p "$pw" ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
      -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive -o NumberOfPasswordPrompts=1 \
      -o ConnectTimeout=8 victim@127.0.0.1 "$@"
  }
  aphase prep
  t "before Legion: the web service is reachable from outside (the test can see it)" web_open
  t "before Legion: victim can log in over SSH with a password" victim_ssh Victim-Pass-77 true
  aphase install
  restart "Legion installed"
  aphase start
  echo "=== attacks from outside: port 8080"
  web=0; web_open || web=1
  echo "=== attacks by an ordinary user, over an SSH login"
  # The script goes as a command, not on stdin, so no command in it can
  # swallow the lines after it.
  victim_ssh Victim-Pass-77 "$(cat /repo/tests/vm/attack-victim.sh)" >/dev/null 2>&1 || true
  aphase admin
  aphase victim
  aphase scan
  aphase tamper
  echo "=== stability: is SSH still responsive during an audit flood?"
  vm 'sudo systemd-run --unit legion-flood --uid legion python3 -c "
for i in range(200000):
    try:
        open(\"/etc/shadow\")
    except OSError:
        pass"' >/dev/null 2>&1
  slow=0
  for _ in 1 2 3 4 5; do
    s0=$SECONDS; timeout 20 ssh "${S[@]}" -o ControlPath=none legion@127.0.0.1 true 2>/dev/null || slow=1
    [ $((SECONDS - s0)) -lt 10 ] || slow=1
    sleep 2
  done
  t "S0 new SSH logins still work during an audit flood" test "$slow" = 0
  vm 'sudo systemctl stop legion-flood 2>/dev/null; true'
  aphase stability
  echo "=== attacks from outside: password guessing and root login over SSH"
  for i in 1 2 3 4 5 6 7 8; do victim_ssh "wrong-$i" true >/dev/null 2>&1 || true; done
  limited=0; s0=$SECONDS; victim_ssh wrong-9 true >/dev/null 2>&1 || true; [ $((SECONDS - s0)) -lt 7 ] || limited=1
  echo "      waiting for the firewall's 30-second SSH rate limit to pass"
  sleep 40
  locked=0; victim_ssh Victim-Pass-77 true >/dev/null 2>&1 || locked=1
  sleep 35
  root=0; sshpass -p Correct-Horse-9x ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
    -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 -o ConnectTimeout=8 root@127.0.0.1 true >/dev/null 2>&1 || root=1
  aphase external "$web" "$locked" "$root" "$limited"
  restart "after the attacks"
  web2=0; web_open || web2=1
  t "after restart: web service still blocked from outside" test "$web2" = 1
  aphase after-restart
  aphase report
  vm 'sudo cat /root/legion-attack/attack-report.md' >"$OUT/attack-report.md" 2>/dev/null || true
  vm 'sudo systemctl poweroff' || true
  wait "$QEMU" 2>/dev/null || true
  echo "ATTACK RESULT: $P passed, $F failed (report: attack-report.md)"
  [ "$F" = 0 ]
  exit
fi
if [ "${MODE:-full}" = sensors ]; then
  out="$(vm 'sudo bash ~/legion/tests/vm/sensors.sh' 2>&1)" || true
  echo "$out"
  vm 'sudo systemctl poweroff' || true
  wait "$QEMU" 2>/dev/null || true
  grep -q 'RESULT: .* 0 failed' <<<"$out"
  exit
fi
phase before
restart "desktop installed"
phase desktop
gui_login before-legion
phase install
restart 1
phase after-restart 1
console_login "after restart 1"
gui_login after-restart-1
restart 2
phase after-restart 2
console_login "after restart 2"
gui_login after-restart-2
phase rerun
phase remove
restart "after removal"
phase after-removal
console_login "after removal" no-banner
gui_login after-removal
vm 'sudo systemctl poweroff' || true
wait "$QEMU" 2>/dev/null || true
cp "$W/console.log" "$OUT/console.log" 2>/dev/null || true
echo "VM RESULT: $P passed, $F failed"
[ "$F" = 0 ]

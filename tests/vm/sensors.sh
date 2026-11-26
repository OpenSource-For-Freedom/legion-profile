#!/usr/bin/env bash
# shellcheck disable=SC2016 # single-quoted commands run in an inner shell
# Compares three ways to feed Sigma rules on a real Ubuntu 26.04 kernel, with
# the same simulated attack for each:
#   - auditd with Legion's rules (what Legion ships)
#   - auditd plus Laurel (adds process ancestry and decoded commands as JSON)
#   - Sysmon for Linux (Microsoft, eBPF; the source most Linux Sigma rules
#     were written for)
# Reports which rules fire, CPU time, and log volume. Runs as root inside the
# test VM after Legion is installed (audit rules not locked).
unset TERM
D=/root/legion-sensors
mkdir -p "$D"
L=/home/legion/legion
Z=/opt/legion/zircolite
P=0 F=0
t() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then echo "PASS  $d"; P=$((P+1)); else echo "FAIL  $d"; F=$((F+1)); fi; }
apt_get() { DEBIAN_FRONTEND=noninteractive apt-get -y -q -o DPkg::Lock::Timeout=900 "$@"; }
cpu() { systemctl show -p CPUUsageNSec --value "$1" 2>/dev/null | grep -E '^[0-9]+$' || echo 0; }
bytes() { stat -c %s "$@" 2>/dev/null | awk '{ s += $1 } END { print s + 0 }'; }

echo "=== install Legion (no audit lock), Laurel and Sysmon for Linux"
LEGION_NO_ANIM=1 bash "$L/legion.sh" --allow-unencrypted --no-pro --no-lock-audit --no-forward-logs >"$D/legion.log" 2>&1
t "legion installed" test -x "$Z/Zircolite"
apt_get update >/dev/null 2>&1
apt_get install laurel netcat-openbsd >"$D/laurel-install.log" 2>&1
t "Laurel installed" test -x /usr/sbin/laurel
curl -fsSL -o /tmp/ms.deb https://packages.microsoft.com/config/ubuntu/26.04/packages-microsoft-prod.deb &&
  dpkg -i /tmp/ms.deb >/dev/null 2>&1 && apt_get update >/dev/null 2>&1
apt_get install sysmonforlinux >"$D/sysmon-install.log" 2>&1
t "Sysmon for Linux installed" command -v sysmon
schema="$(sysmon -s 2>/dev/null | grep -o 'schemaversion="[0-9.]*"' | head -n 1)"
cat >"$D/sysmon.xml" <<EOF
<Sysmon ${schema:-schemaversion=\"4.81\"}>
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude"/>
      <NetworkConnect onmatch="exclude"/>
      <FileCreate onmatch="exclude"/>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
EOF
sysmon -accepteula -i "$D/sysmon.xml" >"$D/sysmon-start.log" 2>&1
sleep 5
t "Sysmon running on this kernel ($(uname -r))" systemctl is-active -q sysmon
# auditd loads the Laurel plugin on a reload.
auditctl --signal reload >/dev/null 2>&1 || pkill -HUP -x auditd
sleep 5
t "Laurel receiving audit events" bash -c 'pgrep -x laurel && sleep 3 && test -s /var/log/laurel/audit.log'

echo "=== the same workload for all three: 500 ordinary commands, then the attack"
start_epoch="$(date +%s)"
start_day="$(LC_ALL=C date -d "@$start_epoch" +%x)" start_time="$(date -d "@$start_epoch" +%T)"
a0="$(bytes /var/log/audit/audit.log*)" l0="$(bytes /var/log/laurel/audit.log*)"
c_audit0="$(cpu auditd)" c_sysmon0="$(cpu sysmon)"
su - legion -c 'for i in $(seq 1 500); do /bin/true; done'
cp /bin/true /tmp/evil-test && chmod 755 /tmp/evil-test
su - legion -c '
  /tmp/evil-test
  touch /tmp/f; chmod 777 /tmp/f
  cat /etc/passwd >/dev/null; crontab -l; id; uname -a; whoami; hostname
  echo ZWNobyBzZW5zb3ItdGVzdAo= | base64 -d | sh
  wget -q -T 2 --post-file=/etc/hostname http://127.0.0.1:9/
  curl -s -m 2 -F "f=@/etc/hostname" http://127.0.0.1:9/
  nc -z -w 1 127.0.0.1 20-25
  bash -c "exec 3<>/dev/tcp/127.0.0.1/9" 2>/dev/null
  sudo -n insmod /nonexistent.ko
  sudo -n touch /etc/ld.so.preload; sudo -n rm -f /etc/ld.so.preload
  sudo -n useradd sensortest; sudo -n userdel sensortest
  sudo -n iptables -L >/dev/null
  rm -f /tmp/f
' >/dev/null 2>&1
rm -f /tmp/evil-test
sleep 10
end_epoch="$(date +%s)"

echo "=== Sigma rules that fired (all Linux rules, every level)"
LC_ALL=C ausearch --input-logs -ts "$start_day" "$start_time" --raw >"$D/auditd.log" 2>/dev/null
journalctl -t sysmon -o short --since "@$start_epoch" --until "@$end_epoch" >"$D/sysmon.log"
run_z() { # name input-flag file
  (cd "$D" && "$Z/Zircolite" "$2" -e "$3" -r "$Z/rules/rules_linux.json" -o "$D/$1.json" -q >"$D/$1.zircolite.out" 2>&1)
  python3 -c '
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    d = []
print("  %-8s %3d rules: %s" % (sys.argv[2], len(d), "; ".join(sorted("%s (%s)" % (x["title"], x["rule_level"]) for x in d))))' "$D/$1.json" "$1"
}
run_z auditd --auditd "$D/auditd.log"
run_z sysmon --sysmon-linux "$D/sysmon.log"
t "Sigma rules fire on auditd events" python3 -c 'import json; assert json.load(open("/root/legion-sensors/auditd.json"))'
t "Sigma rules fire on Sysmon events" python3 -c 'import json; assert json.load(open("/root/legion-sensors/sysmon.json"))'

echo "=== what Laurel adds (the /tmp program's event, as Laurel logs it)"
grep -m 1 '"/tmp/evil-test"' /var/log/laurel/audit.log | python3 -c '
import json, sys
for l in sys.stdin:
    e = json.loads(l)
    s = e.get("SYSCALL", {})
    print("  argv:", e.get("EXECVE", {}).get("argv"))
    print("  parent process:", json.dumps(s.get("PPID", {}))[:300])
    print("  labels:", s.get("LABELS"))' || echo "  not found"
t "Laurel logs the parent process of the attack" bash -c "grep '\"/tmp/evil-test\"' /var/log/laurel/audit.log | grep -q PPID"

echo "=== cost of the workload"
c_audit1="$(cpu auditd)" c_sysmon1="$(cpu sysmon)"
echo "  auditd (+ Laurel, same service): $(((c_audit1 - c_audit0) / 1000000)) ms CPU"
echo "  Sysmon:                          $(((c_sysmon1 - c_sysmon0) / 1000000)) ms CPU"
echo "  audit log grew $((($(bytes /var/log/audit/audit.log*) - a0) / 1024)) KB"
echo "  Laurel log grew $((($(bytes /var/log/laurel/audit.log*) - l0) / 1024)) KB"
echo "  Sysmon log: $(($(wc -c <"$D/sysmon.log") / 1024)) KB"
echo "RESULT: $P passed, $F failed"

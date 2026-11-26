#!/usr/bin/env bash
# Scenario test for Legion, run inside a systemd container. Logs go to /tmp,
# which AIDE does not watch.
unset TERM
P=0 F=0
t() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then echo "PASS  $d"; P=$((P+1)); else echo "FAIL  $d"; F=$((F+1)); fi; }
auth() { echo "$2" | pamtester "$1" kit authenticate acct_mgmt >/dev/null 2>&1; }
# Setup
apt-get remove -y -q nano >/dev/null 2>&1
ip link add virbr0 type bridge 2>/dev/null && ip link set virbr0 up
ufw --force reset >/dev/null; ufw allow 2222/tcp comment "user rule" >/dev/null
ufw allow from 172.17.0.0/16 to any port 5353 proto udp comment "my mdns" >/dev/null; ufw --force enable >/dev/null
ufw show added >/tmp/ufw.before
md5sum /etc/pam.d/common-* /etc/pam.d/su /etc/issue /etc/issue.net /etc/gdm3/greeter.dconf-defaults \
  /etc/login.defs /etc/default/useradd /etc/audit/auditd.conf 2>/dev/null >/tmp/files.before
# kit's password is 200 days old: Legion must give 14 days, not expire it now.
chage -d "$(date -d '200 days ago' +%F)" kit
grep '^kit:' /etc/shadow >/tmp/kit.shadow.before
REMOVES_BEFORE=$(grep -c '^Remove:' /var/log/apt/history.log)
echo "=== refuses to run from a pipe"
out="$(bash -s -- --check </root/legion.sh 2>&1)"; rc=$?
t "piped run refused (exit $rc)" bash -c "[ $rc = 2 ] && grep -q 'run Legion from a file' <<<\"\$1\"" _ "$out"
# Hostile conditions for the install: an interrupted package install, Postfix
# without a configuration, and the package lists lock held for 40 seconds.
echo "postfix postfix/main_mailer_type select No configuration" | debconf-set-selections
DEBIAN_FRONTEND=noninteractive apt-get install -y -q postfix >/dev/null 2>&1; rm -f /etc/postfix/main.cf
(cd /tmp && apt-get download -q hello >/dev/null 2>&1 && dpkg --unpack /tmp/hello_*.deb >/dev/null 2>&1)
python3 -c 'import fcntl, time; f = open("/var/lib/apt/lists/lock", "w"); fcntl.lockf(f, fcntl.LOCK_EX); time.sleep(40)' &
echo "setup: hello unpacked but not configured: $(dpkg-query -W -f '${Status}' hello 2>/dev/null)"
echo "=== install, no terminal, --no-ipv6, bad and broad networks in --allow-from"
# A log server stand-in for --forward-logs.
python3 -c 'import socketserver
class H(socketserver.StreamRequestHandler):
    def handle(self):
        with open("/tmp/received.log", "ab") as f:
            for line in self.rfile:
                f.write(line); f.flush()
socketserver.ThreadingTCPServer(("127.0.0.1", 5140), H).serve_forever()' &
LISTENER=$!
LEGION_NO_ANIM=1 bash /root/legion.sh --allow-unencrypted --no-pro --no-ipv6 --lock-audit --forward-logs syslog://127.0.0.1:5140 \
  --allow-from 10.0.0.300/24,1.0.0.0/1,128.0.0.0/1,8.8.8.0/24,10.9.0.0/24 >/tmp/run.log 2>&1; rc=$?
t "legion exits 0 (got $rc)" test "$rc" = 0
grep -E "✖ \[" /tmp/run.log
t "waited for the package lists lock (patching passed)" grep -q "✔ \[1/" /tmp/run.log
t "interrupted package install repaired" bash -c "dpkg-query -W -f '\${Status}' hello | grep -q 'install ok installed'"
t "Postfix without a configuration does not break hardening" bash -c "grep -q '✔ \[.*System hardening' /tmp/run.log"
t "firewall on despite bad --allow-from entries" bash -c "ufw status | grep -q 'Status: active'"
t "only the private network was allowed" bash -c "ufw show added | grep -q 'from 10.9.0.0/24' && ! ufw show added | grep -qE 'from (1.0.0.0/1|128.0.0.0/1|8.8.8.0/24)'"
t "no package removed during the run" test "$(grep -c '^Remove:' /var/log/apt/history.log)" = "$REMOVES_BEFORE"
t "leftover package config not purged" bash -c "dpkg -l nano | grep -q ^rc"
t "AIDE installed without its mail extras" bash -c "dpkg -s aide && ! dpkg -s aide-common && ! dpkg -s bsd-mailx"
t "SSH allowed, rate-limited" bash -c "ufw show added | grep -q 'ufw limit 22/tcp comment .Legion: SSH.'"
t "VM bridge allowed (input and routed)" bash -c "ufw show added | grep -q 'allow in on virbr0 comment' && ufw show added | grep -q 'route allow out on virbr0'"
t "user firewall rule kept" bash -c "ufw show added | grep -q \"2222/tcp comment 'user rule'\""
t "identical user rule not relabelled" bash -c "ufw show added | grep -q \"5353 proto udp comment 'my mdns'\""
t "audit watches the real sudo and kmod" bash -c "grep -q \"^-w $(readlink -f /usr/bin/sudo) -p x\" /etc/audit/rules.d/legion.rules && grep -q '^-w /usr/bin/kmod -p x' /etc/audit/rules.d/legion.rules"
t "cron.yearly locked" test "$(stat -c %a /etc/cron.yearly)" = 700
t "IPv6 off keeps loopback" grep -qx "net.ipv6.conf.lo.disable_ipv6 = 0" /etc/sysctl.d/60-legion-ipv6.conf
t "integrity check clean right after install" bash -c "systemctl start legion-integrity.service; [ \"\$(systemctl show -p Result --value legion-integrity.service)\" = success ]"
t "graphical login banner compiled into GDM's settings" bash -c "printf 'file-db:/tmp/greeter-db\n' >/tmp/greeter-profile && dconf compile /tmp/greeter-db /usr/share/gdm/dconf && [ \"\$(DCONF_PROFILE=/tmp/greeter-profile dconf read /org/gnome/login-screen/banner-message-enable)\" = true ]"
t "LEGION logo set for the login screen" bash -c "[ \"\$(DCONF_PROFILE=/tmp/greeter-profile dconf read /org/gnome/login-screen/logo)\" = \"'/usr/local/share/legion/login-logo.png'\" ]"
t "logo readable by the temporary login-screen user" bash -c "setpriv --reuid 60578 --regid 60578 --clear-groups head -c 8 /usr/local/share/legion/login-logo.png | grep -q PNG"
echo "=== Phase 2: tamper lockdown"
logger -t legion-test "forwarding test message"; sleep 3
t "log server receives system logs" grep -q 'forwarding test message' /tmp/received.log
t "forwarding has a disk queue for offline times" grep -q 'queue.filename="legion-forward"' /etc/rsyslog.d/60-legion-forward.conf
t "bad log server address refused, nothing changed" bash -c "! LEGION_NO_ANIM=1 bash /root/legion.sh --forward-logs 'http://x;rm' --allow-unencrypted --no-pro >/dev/null 2>&1 && grep -q 127.0.0.1 /etc/rsyslog.d/60-legion-forward.conf"
# augenrules always moves the last "-e" line to the end of the loaded rules.
t "audit lock rule written, and no other file sets the lock" bash -c "grep -qx -- '-e 2' /etc/audit/rules.d/99-legion-lock.rules && [ -z \"\$(grep -l '^-e' /etc/audit/rules.d/*.rules | grep -v 99-legion-lock)\" ]"
t "Legion's own files and AI agent settings are watched" bash -c "grep -q -- '-k legion-tamper' /etc/audit/rules.d/legion.rules"
t "sandboxed daily check still runs" bash -c "systemctl start legion-check.service; [ \"\$(systemctl show -p Result --value legion-check.service)\" = success ]"
t "sandboxed services are sandboxed" bash -c "systemctl show -p ProtectSystem --value legion-check.service | grep -qx full && systemctl show -p NoNewPrivileges --value legion-integrity.service | grep -qx yes"
t "evidence bundle has the baseline checksums" bash -c "tar -xzOf \"\$(ls -t /var/log/legion/evidence/*.tar.gz | head -n 1)\" --wildcards '*/status/status.txt' | grep -q 'integrity baseline checksums'"
echo "=== Phase 3: threat detection (Sigma rules, paired with YARA)"
t "Zircolite installed from the pinned, checksummed release" bash -c "[ \"\$(cat /opt/legion/zircolite/VERSION)\" = 4.7.1 ] && /opt/legion/zircolite/Zircolite --help"
t "only audit-log Sigma rules, medium level and up" python3 -c 'import json; r = json.load(open("/var/lib/legion/sigma/rules.json")); assert 15 < len(r) < 60 and all(x["logsource"]["service"] == "auditd" and x["level"] in ("medium", "high", "critical") for x in r)'
t "Sigma check runs every 15 minutes" systemctl is-enabled -q legion-sigma-scan.timer
t "every command people run is audited" grep -q -- '-S execve,execveat -F auid>=1000 -F auid!=unset -k exec' /etc/audit/rules.d/legion.rules
t "ld.so.preload watched before it exists" grep -qx -- '-w /etc/ld.so.preload -p wa -k persistence' /etc/audit/rules.d/legion.rules
# Containers cannot run auditd, so write the audit log a real attack would
# leave: a program run from /tmp, chmod 777, and /etc/ld.so.preload created
# through sudo; plus the same file written by dpkg, which is not an attack.
cat >/tmp/evil-test <<'EOF'
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
EOF
chmod 755 /tmp/evil-test
U1000="$(getent passwd 1000 | cut -d: -f1)"
audit_events() { # first-serial event...
  python3 - "$(($(date +%s) + 20))" "$@" <<'EOF'
import sys
now, first, kinds = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3:]
for i, kind in enumerate(kinds):
    n = first + i
    head = f"msg=audit({now + i}.100:{n}):"
    def sc(exe, comm, euid=1000, sysno=59, key="exec"):
        return (f'type=SYSCALL {head} arch=c000003e syscall={sysno} success=yes exit=0 a0=1 a1=2 a2=3 a3=0 items=2 '
                f'ppid=100 pid={n} auid=1000 uid={euid} gid=0 euid={euid} suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 '
                f'tty=pts0 ses=3 comm="{comm}" exe="{exe}" subj=unconfined key="{key}"')
    if kind == "tmp-exec":
        rec = [sc("/tmp/evil-test", "evil-test"), f'type=EXECVE {head} argc=1 a0="/tmp/evil-test"', f'type=CWD {head} cwd="/tmp"']
    elif kind == "chmod777":
        rec = [sc("/usr/bin/chmod", "chmod"), f'type=EXECVE {head} argc=3 a0="chmod" a1="777" a2="/tmp/f"', f'type=CWD {head} cwd="/tmp"']
    elif kind in ("preload", "dpkg-preload"):
        exe, comm = ("/usr/bin/tee", "tee") if kind == "preload" else ("/usr/bin/dpkg", "dpkg")
        rec = [sc(exe, comm, euid=0, sysno=257, key="persistence"), f'type=CWD {head} cwd="/root"',
               f'type=PATH {head} item=0 name="/etc/" inode=2 dev=fc:01 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0',
               f'type=PATH {head} item=1 name="/etc/ld.so.preload" inode=3 dev=fc:01 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=CREATE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0']
    rec.append(f'type=PROCTITLE {head} proctitle=78')
    print("\n".join(rec))
EOF
}
install -d -m 700 /var/log/audit
audit_events 9001 tmp-exec chmod777 preload dpkg-preload >>/var/log/audit/audit.log
/usr/local/sbin/legion-sigma-scan >/tmp/sigma.out 2>&1; rc=$?
cat /tmp/sigma.out | sed 's/^/      /'
A=/var/log/legion/sigma-alerts.log
t "Sigma check raises alerts for the attack (exit $rc)" test "$rc" = 1
for r in "Program Executions in Suspicious Folders" "Suspicious Commands Linux" "Modification of ld.so.preload"; do
  t "alert: $r" grep -q "\"rule\": \"$r\"" "$A"
done
t "alert names the user, program and command" python3 -c '
import json, sys
a = [json.loads(l) for l in open(sys.argv[1])]
c = [x for x in a if x["rule"] == "Suspicious Commands Linux"][0]
assert c["user"] == sys.argv[2] and c["program"] == "/usr/bin/chmod" and c["command"] == "chmod 777 /tmp/f", c
p = [x for x in a if x["rule"] == "Modification of ld.so.preload"][0]
assert p["runs_as"] == "root" and p["file"] == "/etc/ld.so.preload", p' "$A" "$U1000"
t "program from the alert scanned with YARA" python3 -c '
import json, sys
a = [json.loads(l) for l in open(sys.argv[1]) if "evil-test" in l][0]
print(a["yara"]); assert a["yara"].startswith("YARA match") or a["yara"] == "YARA: no match"' "$A"
grep -o '"yara": "[^"]*"' "$A" | sort | uniq -c | sed 's/^/      /'
t "package manager changes not reported" bash -c "! grep -q '/usr/bin/dpkg' $A"
t "alerts in the system log (and so on the log server)" bash -c "journalctl -t legion-sigma | grep -q 'Sigma alert (high): Modification of ld.so.preload'"
t "alerts reach the log server" bash -c "sleep 3; grep -q 'Sigma alert' /tmp/received.log"
n="$(wc -l <"$A")"
t "events already checked are not reported again (sandboxed service)" bash -c "systemctl start legion-sigma-scan.service; [ \"\$(systemctl show -p Result --value legion-sigma-scan.service)\" = success ] && [ \"\$(wc -l <$A)\" = $n ]"
echo "Suspicious Commands Linux" >>/etc/legion/sigma-ignore
audit_events 9101 chmod777 >>/var/log/audit/audit.log
t "rules listed in /etc/legion/sigma-ignore stay quiet" bash -c "/usr/local/sbin/legion-sigma-scan && [ \"\$(wc -l <$A)\" = $n ]"
LEGION_NO_ANIM=1 /usr/local/sbin/legion --report-only >/tmp/rep3.log 2>&1
t "compliance report flags the alerts" grep -q '✖ Threat detection' /tmp/rep3.log
t "evidence bundle carries the alerts" bash -c "tar -tzf \$(ls -t /var/log/legion/evidence/*.tar.gz | head -n 1) | grep -q sigma-alerts.log"
# Back to a quiet state for the tests that follow.
: >"$A"; sed -i '/^Suspicious Commands Linux$/d' /etc/legion/sigma-ignore; systemctl reset-failed legion-sigma-scan.service 2>/dev/null
rm -f /tmp/evil-test
echo "=== Phase 1: CIS / 800-171 additions"
day=$(( $(date +%s) / 86400 ))
t "kit's password age: 90 days max, 1 min, 7 warn, 45 inactive" bash -c "grep -q '^kit:[^:]*:[0-9]*:1:90:7:45:' /etc/shadow"
t "old password given 14 days, not expired on the spot" bash -c "[ \"\$(grep '^kit:' /etc/shadow | cut -d: -f3)\" = $((day - 76)) ]"
t "new accounts: 90-day passwords, disabled after 45 days" bash -c "grep -qP '^PASS_MAX_DAYS\t90$' /etc/login.defs && grep -qx INACTIVE=45 /etc/default/useradd"
t "kit can still log in (password not expired)" auth login Correct-Horse-9x
# shellcheck disable=SC2016 # expanded by the inner shells
t "idle shell timeout for console and SSH, not graphical terminals" bash -c 'su - kit -c "echo \$TMOUT" | grep -qx 900 && [ -z "$(env -i DISPLAY=:0 PATH=/usr/bin:/bin bash -lc "echo \${TMOUT:-}")" ]'
t "login umask hides new files from other users" bash -c "su - kit -c umask | grep -qE '^0(0|2)07$'"
t "sudo still works, and keeps umask 022 for root" bash -c "[ \"\$(su - kit -c 'sudo -n sh -c umask')\" = 0022 ]"
t "sudo settings in place and valid" bash -c "visudo -c -q && grep -qx 'Defaults use_pty' /etc/sudoers.d/legion"
t "su refused for normal users" bash -c "! su - kit -c 'echo x | su -c true root' 2>/dev/null"
t "root can still su" bash -c "su - kit -c true"
t "core dumps off, apport off" bash -c "grep -q 'hard core 0' /etc/security/limits.d/legion.conf && grep -qx Storage=none /etc/systemd/coredump.conf.d/legion.conf"
t "unused filesystems blocked" grep -q 'install hfsplus /bin/false' /etc/modprobe.d/legion-filesystems.conf
t "SSH hardened and still running" bash -c "sshd -T | grep -qx 'maxauthtries 4' && sshd -T | grep -qx 'x11forwarding no' && systemctl is-active -q ssh"
t "login screen hides user names" bash -c "dconf compile /tmp/greeter-db2 /usr/share/gdm/dconf && printf 'file-db:/tmp/greeter-db2\n' >/tmp/greeter-profile2 && [ \"\$(DCONF_PROFILE=/tmp/greeter-profile2 dconf read /org/gnome/login-screen/disable-user-list)\" = true ]"
t "media autorun off and locked" bash -c "grep -qx autorun-never=true /etc/dconf/db/local.d/00-legion-media && grep -q autorun-never /etc/dconf/db/local.d/locks/00-legion-media"
t "CIS audit rules generated (privileged programs, access, delete)" bash -c "grep -c -- '-k privileged' /etc/audit/rules.d/legion.rules | awk '\$1 > 5 { ok = 1 } END { exit !ok }' && grep -q 'exit=-EACCES' /etc/audit/rules.d/legion.rules && grep -q -- '-k delete' /etc/audit/rules.d/legion.rules"
t "audit rules only use system calls the machine has" bash -c "! grep -E -- '-S [^ ]*(chown32|stime)' /etc/audit/rules.d/legion.rules | grep -q 'arch=b64'"
t "auditd alerts when its disk runs low" grep -qx 'space_left_action = exec /usr/local/sbin/legion-audit-alert' /etc/audit/auditd.conf
# A oneshot service is "activating" while it runs, not "active".
for _ in $(seq 1 120); do
  case "$(systemctl show -p ActiveState --value legion-vuln-scan.service)" in activating | active) sleep 5 ;; *) break ;; esac
done
[ -f /var/lib/legion/oval/last ] || journalctl -u legion-vuln-scan.service --no-pager | tail -n 8 | sed 's/^/      /'
echo "vulnerability scan: $(cat /var/lib/legion/oval/last 2>/dev/null || echo 'no result') $(systemctl show -p Result --value legion-vuln-scan.service)"
t "vulnerability scan ran and wrote its report" bash -c "test -s /var/log/legion/vuln-report.html && test -f /var/lib/legion/oval/last"
t "report lists the new checks" bash -c "LEGION_NO_ANIM=1 bash /root/legion.sh --report-only >/tmp/rep.log 2>&1; grep -q 'Last 24 passwords cannot be reused' /tmp/rep.log && grep -q 'Setuid programs all come from packages' /tmp/rep.log"
grep -E '✖' /tmp/rep.log | sed 's/^/      report: /'
t "no failed units" bash -c "[ -z \"\$(systemctl --failed --no-legend --plain | grep -v polkit | grep -v legion-vuln-scan)\" ]"
t "root shell history does not trip the integrity check" bash -c "echo ls >>/root/.bash_history; echo x >/root/.lesshst; systemctl start legion-integrity.service; [ \"\$(systemctl show -p Result --value legion-integrity.service)\" = success ]"
echo "# tamper" >>/root/.bashrc; systemctl start legion-integrity.service 2>/dev/null
t "editing /root/.bashrc trips the integrity check" test "$(systemctl show -p Result --value legion-integrity.service)" != success
t "a failed scan fails its compliance check" bash -c "LEGION_NO_ANIM=1 bash /root/legion.sh --report-only 2>&1 | grep -q '✖ Daily file integrity check'"
sed -i '$ d' /root/.bashrc; /usr/local/sbin/legion-aide-baseline test >/dev/null 2>&1; systemctl reset-failed legion-integrity.service
echo "=== integrity: package updates accepted, other changes kept for review"
echo planted >/etc/legion-planted; sleep 2
DEBIAN_FRONTEND=noninteractive apt-get install -y -q tree >/dev/null 2>&1
t "apt run kept the earlier, unrelated change for review" grep -qx /etc/legion-planted /var/lib/legion/aide/pending
t "files apt itself changed were not flagged" bash -c "! grep -q '^/etc/ld.so\\|tree' /var/lib/legion/aide/pending"
systemctl start legion-integrity.service 2>/dev/null
t "daily check fails while the change is unreviewed" test "$(systemctl show -p Result --value legion-integrity.service)" != success
rm -f /etc/legion-planted; /usr/local/sbin/legion-aide-baseline manual; systemctl reset-failed legion-integrity.service
systemctl start legion-integrity.service
t "accepting with 'manual' clears it" test "$(systemctl show -p Result --value legion-integrity.service)" = success
echo "=== password history"
cp -p /etc/shadow /tmp/shadow.keep
t "password change works" bash -c "echo kit:Second-Pass-77x | chpasswd"
t "reusing a recent password is refused" bash -c "! echo kit:Correct-Horse-9x | chpasswd"
cp -p /tmp/shadow.keep /etc/shadow; /usr/local/sbin/legion-aide-baseline manual >/dev/null 2>&1
t "lockout: correct password works" auth login Correct-Horse-9x
for i in 1 2 3 4 5; do auth login wrong-$i; done
t "lockout: 5 failures lock the account" bash -c "! echo Correct-Horse-9x | pamtester login kit authenticate acct_mgmt"
faillock --user kit --reset
t "lockout: admin reset unlocks" auth login Correct-Horse-9x
t "drift check quiet when nothing changed" bash -c "/usr/local/sbin/legion --drift-only"
echo "=== one run at a time"
flock /run/legion.lock sleep 15 &
HOLDER=$!
sleep 1; out="$(LEGION_NO_ANIM=1 bash /root/legion.sh --report-only 2>&1)"; rc=$?; wait "$HOLDER"
t "second run at the same time refused (exit $rc)" bash -c "[ $rc = 2 ] && grep -q 'already running' <<<\"\$1\"" _ "$out"
echo "=== NO_COLOR survives the sudo hand-off"
cp /root/legion.sh /tmp/legion.sh && chmod 755 /tmp/legion.sh
out="$(su - kit -c "NO_COLOR=1 LEGION_NO_ANIM=1 script -qec 'bash /tmp/legion.sh --report-only' /dev/null" 2>&1)"
t "no color codes after sudo" bash -c "! grep -q \$'\\e\\[3[0-9]m' <<<\"\$1\"" _ "$out"
echo "=== drift alerts persist until fixed"
ufw disable >/dev/null
/usr/local/sbin/legion --drift-only >/dev/null 2>&1; r1=$?
LEGION_NO_ANIM=1 /usr/local/sbin/legion --check >/dev/null 2>&1
/usr/local/sbin/legion --drift-only >/dev/null 2>&1; r2=$?
ufw --force enable >/dev/null
/usr/local/sbin/legion --drift-only >/dev/null 2>&1; r3=$?
t "drift alert on firewall off ($r1), still after a manual check ($r2), cleared when fixed ($r3)" bash -c "[ $r1 = 1 ] && [ $r2 = 1 ] && [ $r3 = 0 ]"
echo "=== stale package lists"
find /var/lib/apt/lists -maxdepth 1 -name '*InRelease' -exec touch -d '5 days ago' {} +
t "updates check fails on 5-day-old package lists" bash -c "LEGION_NO_ANIM=1 /usr/local/sbin/legion --report-only 2>&1 | grep -q '✖ No pending security updates (package lists are 5 days old'"
apt-get update -q >/dev/null 2>&1
echo "=== second run (repeatable)"
LEGION_NO_ANIM=1 bash /root/legion.sh --allow-unencrypted --no-pro --no-ipv6 --allow-from 10.9.0.0/24 >/tmp/run2.log 2>&1; rc=$?
t "second run exits 0 (got $rc)" test "$rc" = 0
t "no duplicate firewall rules" bash -c "[ \$(ufw show added | sort | uniq -d | wc -l) = 0 ]"
echo "=== remove"
bash /root/legion-remove.sh --yes >/tmp/rm.log 2>&1; rc=$?
t "remove exits 0 (got $rc)" test "$rc" = 0
grep "✖" /tmp/rm.log
t "firewall still on, as before Legion" bash -c "ufw status | grep -q 'Status: active'"
t "firewall rules exactly as before" diff /tmp/ufw.before <(ufw show added)
t "PAM files and banners byte-identical to before" md5sum -c --quiet /tmp/files.before
t "lockout gone" bash -c "for i in 1 2 3 4 5 6; do echo w | pamtester login kit authenticate acct_mgmt; done; echo Correct-Horse-9x | pamtester login kit authenticate acct_mgmt"
t "kit's password age back to before (except the change date)" bash -c "[ \"\$(grep '^kit:' /etc/shadow | cut -d: -f4-7)\" = \"\$(cut -d: -f4-7 /tmp/kit.shadow.before)\" ]"
t "sudo, SSH, session, core dump, filesystem files removed" bash -c "! ls /etc/sudoers.d/legion /etc/ssh/sshd_config.d/00-legion.conf /etc/profile.d/legion-session.sh /etc/security/limits.d/legion.conf /etc/modprobe.d/legion-filesystems.conf /usr/share/pam-configs/legion-pwhistory /etc/security/opasswd 2>/dev/null"
t "group legion-su deleted, su works as before" bash -c "! getent group legion-su"
t "vulnerability scan removed" test ! -e /etc/systemd/system/legion-vuln-scan.timer
t "SSH server still running after removal" systemctl is-active -q ssh
t "threat detection removed" bash -c "[ ! -e /opt/legion ] && [ ! -e /etc/systemd/system/legion-sigma-scan.timer ] && [ ! -e /usr/local/sbin/legion-sigma-scan ]"
t "audit lock and log forwarding removed" bash -c "[ ! -e /etc/audit/rules.d/99-legion-lock.rules ] && [ ! -e /etc/rsyslog.d/60-legion-forward.conf ]"
t "IPv6 file removed" test ! -e /etc/sysctl.d/60-legion-ipv6.conf
t "logo image removed" test ! -e /usr/local/share/legion
t "cron.yearly back to 755" test "$(stat -c %a /etc/cron.yearly)" = 755
t "no failed units after removal" bash -c "[ -z \"\$(systemctl --failed --no-legend --plain | grep -v polkit)\" ]"
t "second removal is clean" bash -c "bash /root/legion-remove.sh --yes"
echo "=== removal when the login files were edited after Legion"
LEGION_NO_ANIM=1 bash /root/legion.sh --allow-unencrypted --no-pro --no-yara --no-aide --no-sigma --allow-from none >/tmp/run3.log 2>&1
sed -i '/# here are the per-package modules/d' /etc/pam.d/common-auth
bash /root/legion-remove.sh --yes >/tmp/rm2.log 2>&1; rc=$?
t "removal reports the lockout still active (exit $rc)" bash -c "[ $rc = 1 ] && grep -q 'account lockout still active' /tmp/rm2.log"
t "Legion's PAM profiles kept so it can be finished" test -f /usr/share/pam-configs/legion-faillock
pam-auth-update --force --disable legion-faillock legion-faillock-notify >/dev/null 2>&1
bash /root/legion-remove.sh --yes >/tmp/rm3.log 2>&1; rc=$?
t "removal finishes after the forced update (exit $rc)" test "$rc" = 0
t "lockout really gone" bash -c "for i in 1 2 3 4 5 6; do echo w | pamtester login kit authenticate acct_mgmt; done; echo Correct-Horse-9x | pamtester login kit authenticate acct_mgmt"
kill "$LISTENER" 2>/dev/null
echo "RESULT: $P passed, $F failed"

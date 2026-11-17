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
md5sum /etc/pam.d/common-* /etc/issue /etc/issue.net >/tmp/files.before
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
LEGION_NO_ANIM=1 bash /root/legion.sh --allow-unencrypted --no-pro --no-ipv6 \
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
t "no failed units" bash -c "[ -z \"\$(systemctl --failed --no-legend --plain | grep -v polkit)\" ]"
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
t "lockout: correct password works" auth login Correct-Horse-9x
for i in 1 2 3 4 5; do auth login wrong-$i; done
t "lockout: 5 failures lock the account" bash -c "! echo Correct-Horse-9x | pamtester login kit authenticate acct_mgmt"
faillock --user kit --reset
t "lockout: admin reset unlocks" auth login Correct-Horse-9x
t "drift check quiet when nothing changed" bash -c "/usr/local/sbin/legion --drift-only"
echo "=== one run at a time"
flock /run/legion.lock sleep 15 &
sleep 1; out="$(LEGION_NO_ANIM=1 bash /root/legion.sh --report-only 2>&1)"; rc=$?; wait
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
t "IPv6 file removed" test ! -e /etc/sysctl.d/60-legion-ipv6.conf
t "cron.yearly back to 755" test "$(stat -c %a /etc/cron.yearly)" = 755
t "no failed units after removal" bash -c "[ -z \"\$(systemctl --failed --no-legend --plain | grep -v polkit)\" ]"
t "second removal is clean" bash -c "bash /root/legion-remove.sh --yes"
echo "=== removal when the login files were edited after Legion"
LEGION_NO_ANIM=1 bash /root/legion.sh --allow-unencrypted --no-pro --no-yara --no-aide --allow-from none >/tmp/run3.log 2>&1
sed -i '/# here are the per-package modules/d' /etc/pam.d/common-auth
bash /root/legion-remove.sh --yes >/tmp/rm2.log 2>&1; rc=$?
t "removal reports the lockout still active (exit $rc)" bash -c "[ $rc = 1 ] && grep -q 'account lockout still active' /tmp/rm2.log"
t "Legion's PAM profiles kept so it can be finished" test -f /usr/share/pam-configs/legion-faillock
pam-auth-update --force --disable legion-faillock legion-faillock-notify >/dev/null 2>&1
bash /root/legion-remove.sh --yes >/tmp/rm3.log 2>&1; rc=$?
t "removal finishes after the forced update (exit $rc)" test "$rc" = 0
t "lockout really gone" bash -c "for i in 1 2 3 4 5 6; do echo w | pamtester login kit authenticate acct_mgmt; done; echo Correct-Horse-9x | pamtester login kit authenticate acct_mgmt"
echo "RESULT: $P passed, $F failed"

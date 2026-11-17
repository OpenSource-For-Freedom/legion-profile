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
echo "=== install, no terminal, --no-ipv6"
LEGION_NO_ANIM=1 bash /root/legion.sh --allow-unencrypted --no-pro --no-ipv6 >/tmp/run.log 2>&1; rc=$?
t "legion exits 0 (got $rc)" test "$rc" = 0
grep -E "✖ \[" /tmp/run.log
t "no package removed during the run" test "$(grep -c '^Remove:' /var/log/apt/history.log)" = "$REMOVES_BEFORE"
t "leftover package config not purged" bash -c "dpkg -l nano | grep -q ^rc"
t "no mail server pulled in by AIDE" bash -c "! dpkg -s postfix && ! dpkg -s bsd-mailx"
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
t "lockout: correct password works" auth login Correct-Horse-9x
for i in 1 2 3 4 5; do auth login wrong-$i; done
t "lockout: 5 failures lock the account" bash -c "! echo Correct-Horse-9x | pamtester login kit authenticate acct_mgmt"
faillock --user kit --reset
t "lockout: admin reset unlocks" auth login Correct-Horse-9x
t "drift check quiet when nothing changed" bash -c "/usr/local/sbin/legion --drift-only"
echo "=== second run (repeatable)"
LEGION_NO_ANIM=1 bash /root/legion.sh --allow-unencrypted --no-pro --no-ipv6 >/tmp/run2.log 2>&1; rc=$?
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
echo "RESULT: $P passed, $F failed"

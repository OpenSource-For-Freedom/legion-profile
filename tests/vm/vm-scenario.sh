#!/usr/bin/env bash
# shellcheck disable=SC2016 # single-quoted commands run in an inner shell
# Legion checks that need a real kernel. Runs as root inside the test VM, one
# phase per call: before, install, after-reboot, remove.
unset TERM
P=0 F=0
t() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then echo "PASS  $d"; P=$((P+1)); else echo "FAIL  $d"; F=$((F+1)); fi; }
D=/root/legion-test
mkdir -p "$D"
L=/home/legion/legion
KEYS="identity privilege user_emulation session logins system-locale time modules perm_mod access mounts delete MAC-policy privileged"
SYSCTLS="kernel.kptr_restrict kernel.dmesg_restrict fs.suid_dumpable net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.send_redirects net.ipv4.conf.all.secure_redirects net.ipv4.icmp_echo_ignore_broadcasts net.ipv6.conf.all.accept_redirects"
rules_loaded() { auditctl -l | grep -vc '^No rules'; }
user_actions() { # things a person does, done as the user legion (login ID 1000)
  su - legion -c 'touch ~/a; chmod 600 ~/a; mv ~/a ~/b; rm ~/b; cat /etc/shadow; sudo -n true; true' >/dev/null 2>&1
  sleep 2
}
case "$1" in
  before)
    echo "=== before Legion"
    for k in $SYSCTLS; do echo "$k=$(sysctl -n "$k")"; done >"$D/sysctl.before"
    rules_loaded >"$D/rules.before"
    echo "      auditd before Legion: $(systemctl is-active auditd 2>/dev/null || true)"
    ;;
  install)
    echo "=== install on a real kernel"
    DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 update -q >/dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q -o DPkg::Lock::Timeout=600 pamtester >/dev/null 2>&1 || echo "      could not install pamtester"
    start=$SECONDS
    LEGION_NO_ANIM=1 bash "$L/legion.sh" --allow-unencrypted --no-pro >"$D/run.log" 2>&1; rc=$?
    echo "      legion run took $(((SECONDS - start) / 60)) min"
    t "legion exits 0 (got $rc)" test "$rc" = 0
    grep '✖ \[' "$D/run.log" | sed 's/^/      /'
    t "auditd running with the new settings" systemctl is-active -q auditd
    t "auditd uses the low-disk alert" grep -qx 'space_left_action = exec /usr/local/sbin/legion-audit-alert' /etc/audit/auditd.conf
    n="$(rules_loaded)"; echo "$n" >"$D/rules.installed"
    echo "      $n audit rules loaded"
    t "all audit rules loaded (more than 60)" test "$n" -gt 60
    t "no audit rule failed to load" bash -c "! grep -q 'audit rules did not load' $D/run.log"
    for k in $KEYS; do t "audit rules for '$k' loaded" bash -c "auditctl -l | grep -qE -- '(-k |key=)$k( |\$)'"; done
    user_actions
    for k in perm_mod delete access privilege; do t "audit records '$k' for a real user" bash -c "ausearch --input-logs -k $k -ua 1000 -ts recent"; done
    hostnamectl hostname "$(hostname)"; touch /etc/hosts; sleep 1
    t "audit records changes to network settings" ausearch --input-logs -k system-locale -ts recent
    t "kernel settings applied" bash -c '[ "$(sysctl -n kernel.kptr_restrict)" = 2 ] && [ "$(sysctl -n net.ipv4.conf.all.accept_redirects)" = 0 ] && [ "$(sysctl -n kernel.dmesg_restrict)" = 1 ]'
    t "blocked filesystem cannot be loaded (hfsplus)" bash -c "! modprobe hfsplus"
    t "blocked protocol cannot be loaded (sctp)" bash -c "! modprobe sctp"
    t "no core dumps for a new login" bash -c "[ \"\$(su - legion -c 'ulimit -Hc')\" = 0 ]"
    t "login with password still works" bash -c "echo Correct-Horse-9x | pamtester login legion authenticate acct_mgmt"
    t "SSH server hardened" bash -c "sshd -T | grep -qx 'maxauthtries 4'"
    LEGION_NO_ANIM=1 /usr/local/sbin/legion --report-only >"$D/report.log" 2>&1
    t "audit checks pass in the report" bash -c "grep -q '✔ Audit rules (CIS set' $D/report.log && grep -q '✔ Audit logging running' $D/report.log"
    t "kernel check passes in the report" grep -q '✔ Kernel hardening settings' "$D/report.log"
    grep '✖' "$D/report.log" | sed 's/^/      report: /'
    systemctl --failed --no-legend --plain | sed 's/^/      failed unit: /'
    echo "      audit log size after install: $(du -sh /var/log/audit | cut -f1); events by key:"
    aureport --input-logs -k --summary -i 2>/dev/null | awk 'NR > 5 && NF == 2 { print "        " $2 ": " $1 }'
    ;;
  after-reboot)
    echo "=== after reboot"
    t "auditd running" systemctl is-active -q auditd
    t "same audit rules loaded as before the reboot" test "$(rules_loaded)" = "$(cat "$D/rules.installed")"
    t "kernel settings kept" bash -c '[ "$(sysctl -n kernel.kptr_restrict)" = 2 ] && [ "$(sysctl -n net.ipv4.conf.all.accept_redirects)" = 0 ]'
    t "firewall on" bash -c "ufw status | grep -q 'Status: active'"
    t "SSH still reachable (this test runs over it)" true
    t "no failed units except scan findings" bash -c "[ -z \"\$(systemctl --failed --no-legend --plain | grep -vE 'legion-vuln-scan|clamscan|legion-yara')\" ]"
    systemctl --failed --no-legend --plain | sed 's/^/      failed unit: /'
    LEGION_NO_ANIM=1 /usr/local/sbin/legion --report-only >"$D/report2.log" 2>&1
    grep -E '✖|Frameworks' "$D/report2.log" | sed 's/^/      report: /'
    t "audit checks still pass" grep -q '✔ Audit rules (CIS set' "$D/report2.log"
    ;;
  remove)
    echo "=== remove"
    bash "$L/legion-remove.sh" --yes >"$D/rm.log" 2>&1; rc=$?
    t "remove exits 0 (got $rc)" test "$rc" = 0
    grep '✖' "$D/rm.log" | sed 's/^/      /'
    t "audit rules back to before" test "$(rules_loaded)" = "$(cat "$D/rules.before")"
    for k in $SYSCTLS; do echo "$k=$(sysctl -n "$k")"; done >"$D/sysctl.after"
    t "kernel settings back to before" diff "$D/sysctl.before" "$D/sysctl.after"
    diff "$D/sysctl.before" "$D/sysctl.after" | sed 's/^/      /'
    t "sctp can load again" modprobe -n sctp
    t "SSH settings removed, server running" bash -c "[ ! -e /etc/ssh/sshd_config.d/00-legion.conf ] && sshd -t"
    ;;
esac
echo "RESULT: $P passed, $F failed"

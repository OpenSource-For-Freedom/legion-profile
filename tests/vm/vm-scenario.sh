#!/usr/bin/env bash
# shellcheck disable=SC2016 # single-quoted commands run in an inner shell
# Legion checks that need a real kernel and a real desktop. Runs as root
# inside the test VM, one phase per call:
#   before, desktop, install, after-restart N, rerun, remove, after-removal
unset TERM
P=0 F=0
t() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then echo "PASS  $d"; P=$((P+1)); else echo "FAIL  $d"; F=$((F+1)); fi; }
D=/root/legion-test
mkdir -p "$D"
L=/home/legion/legion
PW=Correct-Horse-9x
KEYS="identity privilege user_emulation session logins system-locale time modules perm_mod access mounts delete MAC-policy privileged legion-tamper exec persistence audit-log"
SYSCTLS="kernel.kptr_restrict kernel.dmesg_restrict fs.suid_dumpable net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.send_redirects net.ipv4.conf.all.secure_redirects net.ipv4.icmp_echo_ignore_broadcasts net.ipv6.conf.all.accept_redirects"
ALERTS=/var/log/legion/sigma-alerts.log
# Runs the Sigma check now, through its sandboxed service, and prints the
# alerts it added.
sigma_check() {
  local before
  before="$(wc -l <"$ALERTS" 2>/dev/null || echo 0)"
  systemctl start legion-sigma-scan.service
  echo "      Sigma check: $(systemctl show -p Result --value legion-sigma-scan.service), $(($(wc -l <"$ALERTS") - before)) new alerts"
  tail -n +"$((before + 1))" "$ALERTS" | python3 -c '
import json, sys
for l in sys.stdin:
    a = json.loads(l)
    print("        " + a["level"] + ": " + a["rule"] + " | " + a["user"] + " | " + (a["command"] or a["file"] or a["program"])[:80] + " | " + a["yara"])'
  tail -n +"$((before + 1))" "$ALERTS" >"$D/alerts.new"
  [ ! -s /var/lib/legion/sigma/unmatched.log ] || sed 's/^/        unmatched: /' /var/lib/legion/sigma/unmatched.log | cut -c1-400
}
rules_loaded() { auditctl -l 2>/dev/null | grep -vc '^No rules'; }
apt_get() { DEBIAN_FRONTEND=noninteractive apt-get -y -q -o DPkg::Lock::Timeout=900 "$@"; }
# Logins through PAM, the way each program asks: the login screen, the text
# console and sudo.
pam_logins() {
  t "PAM: login screen password check (gdm-password) $1" bash -c "echo $PW | pamtester gdm-password legion authenticate acct_mgmt"
  t "PAM: console login $1" bash -c "echo $PW | pamtester login legion authenticate acct_mgmt"
  t "PAM: sudo with a password $1" bash -c "echo $PW | pamtester sudo legion authenticate acct_mgmt"
  t "boot finished with no failed services, except scan findings $1" bash -c '
    s="$(systemctl is-system-running --wait)"; [ "$s" = running ] || [ -z "$(systemctl --failed --no-legend --plain | grep -vE "legion-vuln-scan|clamscan|legion-yara|legion-sigma")" ]'
  t "login screen (GDM) running $1" systemctl is-active -q gdm
  systemctl --failed --no-legend --plain | sed 's/^/      failed unit: /'
  echo "      boot time: $(systemd-analyze 2>/dev/null | head -n 1)"
}
# A log server stand-in: a tiny TCP listener that keeps what it receives.
listener() {
  cat >/usr/local/bin/test-log-server <<'EOF'
#!/usr/bin/python3
import socketserver
class H(socketserver.StreamRequestHandler):
    def handle(self):
        with open("/root/legion-test/received.log", "ab") as f:
            for line in self.rfile:
                f.write(line)
                f.flush()
socketserver.ThreadingTCPServer.allow_reuse_address = True
socketserver.ThreadingTCPServer(("127.0.0.1", 5140), H).serve_forever()
EOF
  chmod 755 /usr/local/bin/test-log-server
  printf '[Unit]\nDescription=Test log server\n[Service]\nExecStart=/usr/local/bin/test-log-server\n[Install]\nWantedBy=multi-user.target\n' \
    >/etc/systemd/system/test-log-server.service
  systemctl daemon-reload
  systemctl enable --now test-log-server
}
case "$1" in
  before)
    echo "=== before Legion: install a desktop and the login screen"
    apt_get update >/dev/null 2>&1
    apt_get install --no-install-recommends ubuntu-desktop-minimal gdm3 pamtester python3 >"$D/desktop-install.log" 2>&1
    t "desktop installed" dpkg -s gdm3 gnome-shell
    systemctl set-default graphical.target >/dev/null 2>&1
    listener
    ;;
  desktop)
    echo "=== desktop before Legion"
    rules_loaded >"$D/rules.before"
    for k in $SYSCTLS; do echo "$k=$(sysctl -n "$k")"; done >"$D/sysctl.before"
    pam_logins "(before Legion)"
    ;;
  install)
    echo "=== install on a real kernel, audit rules locked, logs forwarded"
    start=$SECONDS
    LEGION_NO_ANIM=1 bash "$L/legion.sh" --allow-unencrypted --no-pro --lock-audit --forward-logs syslog://127.0.0.1:5140 >"$D/run.log" 2>&1; rc=$?
    echo "      legion run took $(((SECONDS - start) / 60)) min"
    t "legion exits 0 (got $rc)" test "$rc" = 0
    grep -E '✖ \[' "$D/run.log" | sed 's/^/      /'
    t "auditd running" systemctl is-active -q auditd
    n="$(rules_loaded)"; echo "$n" >"$D/rules.installed"
    echo "      $n audit rules loaded"
    t "all audit rules loaded (more than 60)" test "$n" -gt 60
    for k in $KEYS; do t "audit rules for '$k' loaded" bash -c "auditctl -l | grep -qE -- '(-k |key=)$k( |\$)'"; done
    t "audit rules locked right away" bash -c "auditctl -s | grep -qx 'enabled 2'"
    t "locked: not even root can delete the rules" bash -c "! auditctl -D"
    su - legion -c 'touch ~/a; chmod 600 ~/a; rm ~/a; cat /etc/shadow; sudo -n true; true' >/dev/null 2>&1
    touch /usr/local/sbin/legion-tamper-test; rm -f /usr/local/sbin/legion-tamper-test
    sleep 3
    for k in perm_mod delete access privilege; do t "audit records '$k' for a real user" ausearch --input-logs -k "$k" -ua 1000 -ts recent; done
    t "audit records a change to Legion's own files" ausearch --input-logs -k legion-tamper -ts recent
    logger -t legion-test "forwarding test message"
    sleep 5
    t "log server receives system logs" grep -q 'forwarding test message' "$D/received.log"
    t "log server receives audit records" grep -q 'type=SYSCALL' "$D/received.log"
    t "Legion's scans run in their sandbox" bash -c '
      for u in legion-integrity legion-check; do systemctl start $u.service; r=$(systemctl show -p Result --value $u.service); [ "$r" = success ] || { echo "$u $r"; exit 1; }; done'
    t "kernel settings applied" bash -c '[ "$(sysctl -n kernel.kptr_restrict)" = 2 ] && [ "$(sysctl -n net.ipv4.conf.all.accept_redirects)" = 0 ]'
    t "blocked filesystem cannot be loaded (hfsplus)" bash -c "! modprobe hfsplus"
    echo "      simulated attack, as the user legion: a program run from /tmp, chmod 777,"
    echo "      insmod, and /etc/ld.so.preload created with sudo"
    cp /bin/true /tmp/evil-test
    printf '%s\n' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' >>/tmp/evil-test
    chmod 755 /tmp/evil-test
    su - legion -c '/tmp/evil-test; touch /tmp/f; chmod 777 /tmp/f; sudo -n insmod /nonexistent.ko; sudo -n touch /etc/ld.so.preload; sudo -n rm -f /etc/ld.so.preload; rm -f /tmp/f' >/dev/null 2>&1
    sleep 2
    sigma_check
    for r in "Program Executions in Suspicious Folders" "Suspicious Commands Linux" "Loading of Kernel Module via Insmod" "Modification of ld.so.preload"; do
      t "Sigma alert for the attack: $r" grep -q "\"rule\": \"$r\"" "$D/alerts.new"
    done
    t "alerts name the real user (legion), even through sudo" bash -c "grep 'insmod' $D/alerts.new | grep -q '\"user\": \"legion\"'"
    t "the program from /tmp was scanned with YARA" bash -c "grep evil-test $D/alerts.new | grep -q '\"yara\": \"YARA'"
    t "Sigma alerts reach the log server" bash -c "sleep 3; grep -q 'Sigma alert' $D/received.log"
    rm -f /tmp/evil-test
    systemctl reset-failed legion-sigma-scan.service
    LEGION_NO_ANIM=1 /usr/local/sbin/legion --report-only >"$D/report.log" 2>&1
    t "report: audit lock and log forwarding pass" bash -c "grep -q '✔ Audit rules locked until restart' $D/report.log && grep -q '✔ Logs copied to a log server' $D/report.log"
    grep '✖' "$D/report.log" | sed 's/^/      report: /'
    echo "      audit log: $(du -sh /var/log/audit | cut -f1); forwarded: $(wc -l <"$D/received.log") lines"
    ;;
  after-restart)
    echo "=== after restart $2"
    t "auditd running" systemctl is-active -q auditd
    t "audit rules locked after restart" bash -c "auditctl -s | grep -qx 'enabled 2'"
    t "same audit rules as before the restart" test "$(rules_loaded)" = "$(cat "$D/rules.installed")"
    t "kernel settings kept" bash -c '[ "$(sysctl -n kernel.kptr_restrict)" = 2 ] && [ "$(sysctl -n net.ipv4.conf.all.accept_redirects)" = 0 ]'
    t "firewall on" bash -c "ufw status | grep -q 'Status: active'"
    : >"$D/received.log"; logger -t legion-test "after restart $2"; sleep 5
    t "log forwarding works after restart" grep -q "after restart $2" "$D/received.log"
    pam_logins "(after restart $2)"
    sigma_check
    t "no Sigma alerts from restarts and logins (false alarms)" test ! -s "$D/alerts.new"
    systemctl reset-failed legion-sigma-scan.service 2>/dev/null
    echo "      audit log: $(du -sh /var/log/audit | cut -f1), $(grep -c 'key="exec"' /var/log/audit/audit.log) commands recorded"
    t "screen lock enforced for legion" bash -c "[ \"\$(su - legion -c 'dconf read /org/gnome/desktop/screensaver/lock-enabled')\" = true ]"
    t "login screen hides user names" grep -q 'disable-user-list=true' /etc/gdm3/greeter.dconf-defaults
    ;;
  rerun)
    echo "=== run Legion again while the audit rules are locked"
    LEGION_NO_ANIM=1 bash "$L/legion.sh" --allow-unencrypted --no-pro >"$D/run2.log" 2>&1; rc=$?
    t "second run exits 0 (got $rc)" test "$rc" = 0
    grep -E '✖ \[' "$D/run2.log" | sed 's/^/      /'
    t "second run says the audit changes need a restart" grep -q 'audit rules were locked' "$D/run2.log"
    t "settings kept without options (still locked, still forwarding)" bash -c "test -f /etc/audit/rules.d/99-legion-lock.rules && test -f /etc/rsyslog.d/60-legion-forward.conf"
    ;;
  remove)
    echo "=== remove"
    bash "$L/legion-remove.sh" --yes >"$D/rm.log" 2>&1; rc=$?
    t "remove exits 0 (got $rc)" test "$rc" = 0
    grep '✖' "$D/rm.log" | sed 's/^/      /'
    t "removal says a restart is needed for the locked rules" grep -q 'locked audit rules stay active' "$D/rm.log"
    t "forwarding stopped" test ! -e /etc/rsyslog.d/60-legion-forward.conf
    t "threat detection removed" bash -c "[ ! -e /opt/legion ] && [ ! -e /etc/systemd/system/legion-sigma-scan.timer ]"
    for k in $SYSCTLS; do echo "$k=$(sysctl -n "$k")"; done >"$D/sysctl.after"
    t "kernel settings back to before" diff "$D/sysctl.before" "$D/sysctl.after"
    diff "$D/sysctl.before" "$D/sysctl.after" | sed 's/^/      /'
    ;;
  after-removal)
    echo "=== after removal and restart"
    t "audit rules no longer locked" bash -c "! auditctl -s | grep -qx 'enabled 2'"
    t "audit rules back to before" test "$(rules_loaded)" = "$(cat "$D/rules.before")"
    pam_logins "(after removal)"
    ;;
esac
echo "RESULT: $P passed, $F failed"

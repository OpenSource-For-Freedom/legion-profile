#!/usr/bin/env bash
# shellcheck disable=SC2016,SC2046 # inner shells; the start time is two words on purpose
# Attack test for Legion on a real Ubuntu 26.04 kernel. Runs as root inside
# the test VM, one phase per call (see inside.sh for the order). Each attack
# technique is recorded with what should happen:
#   blocked     Legion should prevent it
#   audit       the audit record that proves it happened, and who did it
#   sigma       the Sigma alert it raised (matched on the alerts log)
#   log server  whether a copy reached the log server (survives local wiping)
# The report phase writes the results as a table: attack-report.md.
unset TERM
D=/root/legion-attack
mkdir -p "$D"
L=/home/legion/legion
M="$D/matrix.tsv" # id, technique, ATT&CK, blocked, audit, sigma pattern, log server pattern
ALERTS=/var/log/legion/sigma-alerts.log
RECEIVED="$D/received.log"
P=0 F=0
t() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then echo "PASS  $d"; P=$((P+1)); else echo "FAIL  $d"; F=$((F+1)); fi; }
apt_get() { DEBIAN_FRONTEND=noninteractive apt-get -y -q -o DPkg::Lock::Timeout=900 "$@"; }
# Audit records since the attacks started, decoded (-i), filtered by ausearch
# options; then grep for a pattern.
au() { LC_ALL=C ausearch --input-logs -ts $(cat "$D/t0") -i "$@" 2>/dev/null; }
has() { local p="$1"; shift; au "$@" | grep -q -- "$p"; }
VU="$(id -u victim 2>/dev/null)"
AU="$(id -u legion)"
# rec id "technique" ATT&CK blocked(yes/no/-) audit-result sigma-pattern logserver-pattern
rec() { printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$@" >>"$M"; }
# check id "technique" ATT&CK blocked audit-key audit-pattern uid sigma-pattern logserver-pattern
# Tests that the audit record exists, and records the row.
check() {
  local id="$1" name="$2" attack="$3" blocked="$4" key="$5" pat="$6" uid="$7" sig="$8" lsp="$9" opts=() a="no record"
  [ -z "$key" ] || opts+=(-k "$key")
  [ "$uid" = - ] || opts+=(-ua "$uid")
  if has "$pat" "${opts[@]}"; then a="${key:-recorded}"; fi
  t "$id audit record: $name" test "$a" != "no record"
  rec "$id" "$name" "$attack" "$blocked" "$a" "$sig" "$lsp"
}
listener() { # a log server stand-in on 127.0.0.1:5140
  cat >/usr/local/bin/test-log-server <<'EOF'
#!/usr/bin/python3
import socketserver
class H(socketserver.StreamRequestHandler):
    def handle(self):
        with open("/root/legion-attack/received.log", "ab") as f:
            for line in self.rfile:
                f.write(line)
                f.flush()
socketserver.ThreadingTCPServer.allow_reuse_address = True
socketserver.ThreadingTCPServer(("127.0.0.1", 5140), H).serve_forever()
EOF
  chmod 755 /usr/local/bin/test-log-server
  printf '[Unit]\nDescription=Test log server\n[Service]\nExecStart=/usr/local/bin/test-log-server\n[Install]\nWantedBy=multi-user.target\n' \
    >/etc/systemd/system/test-log-server.service
  # A web service listening on all addresses: the firewall must hide it.
  printf '[Unit]\nDescription=Test web service\n[Service]\nExecStart=/usr/bin/python3 -m http.server 8080 --directory /var/empty\n[Install]\nWantedBy=multi-user.target\n' \
    >/etc/systemd/system/test-web.service
  install -d /var/empty
  systemctl daemon-reload
  systemctl enable --now test-log-server test-web
}

case "$1" in
  prep)
    echo "=== prepare: a web service on port 8080, a log server, a second user"
    apt_get update >/dev/null 2>&1
    apt_get install python3 netcat-openbsd wget pamtester >/dev/null 2>&1
    listener
    t "web service listening on 8080" bash -c 'sleep 2; ss -ltn | grep -q ":8080 "'
    ;;
  install)
    echo "=== install Legion: audit rules locked, logs forwarded"
    LEGION_NO_ANIM=1 bash "$L/legion.sh" --allow-unencrypted --no-pro --lock-audit --forward-logs syslog://127.0.0.1:5140 >"$D/run.log" 2>&1; rc=$?
    t "legion exits 0 (got $rc)" test "$rc" = 0
    grep -E '✖ \[' "$D/run.log" | sed 's/^/      /'
    ;;
  start)
    echo "=== after restart: attacks start now"
    t "audit rules locked" bash -c "auditctl -s | grep -qx 'enabled 2'"
    auditctl -l | grep -vc '^No rules' >"$D/rules.count"
    echo "      $(cat "$D/rules.count") audit rules loaded"
    auditctl -s | awk '/^lost/ { print $2 }' >"$D/lost.before"
    sleep 1
    LC_ALL=C date '+%x %T' >"$D/t0"
    : >"$M"
    ;;
  admin)
    echo "=== attacks by an administrator (legion, through sudo)"
    # Each command runs as root with legion's login ID, as with sudo.
    tee /etc/ld.so.preload </dev/null >/dev/null; rm -f /etc/ld.so.preload
    useradd -o -u 0 -M -s /bin/bash legion-pt-root; userdel legion-pt-root
    insmod /nonexistent-legion-pt.ko 2>/dev/null
    modprobe hfsplus 2>/dev/null; echo $? >"$D/hfsplus.rc"
    ufw disable >/dev/null; systemctl stop ufw; systemctl start ufw; ufw --force enable >/dev/null
    echo 'legion-pt ALL=(ALL) NOPASSWD:ALL' >/etc/sudoers.d/legion-pt; rm -f /etc/sudoers.d/legion-pt
    sysctl -w kernel.randomize_va_space=0 >/dev/null; sysctl -w kernel.randomize_va_space=2 >/dev/null
    printf '[Service]\nExecStart=/bin/true\n' >/etc/systemd/system/legion-pt.service; rm -f /etc/systemd/system/legion-pt.service
    echo '# legion-pt' >/etc/pam.d/legion-pt; rm -f /etc/pam.d/legion-pt
    touch /etc/rsyslog.conf
    sleep 3
    check A1 "Preload library planted (/etc/ld.so.preload)" T1574.006 no persistence ld.so.preload "$AU" 'ld.so.preload' 'name="/etc/ld.so.preload"'
    check A2 "Second root account created (UID 0)" T1136.001 no identity /etc/passwd "$AU" 'useradd|User Account' 'legion-pt-root'
    check A3 "Kernel module loaded with insmod" T1547.006 no exec insmod "$AU" 'Insmod' '"insmod"'
    t "A4 blocked: Mac filesystem module (hfsplus) cannot be loaded" test "$(cat "$D/hfsplus.rc")" != 0
    check A4 "Blocked filesystem module requested" T1547.006 yes exec hfsplus "$AU" '-' '"hfsplus"'
    check A5 "Firewall turned off" T1562.004 no firewall /etc/ufw "$AU" 'Firewall' 'ufw'
    t "A5 firewall back on after the attack" bash -c "ufw status | grep -q 'Status: active'"
    check A6 "sudo rule added for a backdoor account" T1548.003 no privilege legion-pt "$AU" '-' 'legion-pt'
    check A7 "Memory randomization (ASLR) turned off" T1562.001 no exec randomize_va_space "$AU" 'ASLR' 'randomize_va_space'
    check A8 "System service created" T1543.002 no legion-tamper legion-pt.service "$AU" 'Systemd Service' 'legion-pt.service'
    check A9 "PAM module configuration added" T1556.003 no identity /etc/pam.d/legion-pt "$AU" '-' 'pam.d/legion-pt'
    check A10 "Logging configuration changed" T1562.006 no persistence /etc/rsyslog.conf "$AU" 'Logging Configuration' 'rsyslog.conf'
    ;;
  victim)
    echo "=== evidence for the attacks by an ordinary user (victim, over SSH)"
    check V1 "Password hashes read (/etc/shadow)" T1003.008 yes access /etc/shadow "$VU" '-' 'shadow'
    check V2 "sudo tried without permission" T1548.003 yes privilege sudo "$VU" '-' 'sudo'
    check V3 "setuid copy of a shell made" T1548.001 no perm_mod legion-pt-suid "$VU" 'Suspicious Commands' 'legion-pt-suid'
    check V4 "cron job added" T1053.003 no persistence crontabs "$VU" '-' 'crontabs'
    check V5 "systemd user service added" T1543.002 no persistence legion-pt.service "$VU" '-' 'legion-pt.service'
    check V6 "desktop autostart entry added" T1547.013 no persistence legion-pt.desktop "$VU" '-' 'legion-pt.desktop'
    check V7 "SSH key planted (authorized_keys)" T1098.004 no persistence authorized_keys "$VU" '-' 'authorized_keys'
    check V8 "shell startup file changed (.bashrc)" T1546.004 no persistence .bashrc "$VU" '-' '.bashrc'
    check V9 "tool downloaded to /tmp and run" T1204.002 no exec legion-pt-tool "$VU" 'legion-pt-tool' 'legion-pt-tool'
    check V10 "file opened to everyone (chmod 777)" T1222.002 no perm_mod legion-pt-share "$VU" 'Suspicious Commands' 'legion-pt-share'
    check V11 "file sent out with wget --post-file" T1048.003 no exec post-file "$VU" 'Wget' 'post-file'
    check V12 "reverse shell over /dev/tcp" T1059.004 no exec /dev/tcp "$VU" '-' '2F6465762F746370'
    check V13 "another process's memory read (/proc/1/mem)" T1003.007 yes access /proc/1/mem "$VU" '-' 'proc/1/mem'
    check V14 "system discovery (whoami, uname, /etc/passwd)" T1082 no exec whoami "$VU" '-' 'whoami'
    check V15 "preload library planted without root" T1574.006 yes '' ld.so.preload "$VU" '-' 'ld.so.preload'
    has ld.so.preload -ua "$VU" || au -ua "$VU" | grep -E 'type=(SYSCALL|PATH)' | tail -n 6 | sed 's/^/      last records of victim: /'
    t "V1 blocked: victim cannot read /etc/shadow" bash -c "! su -s /bin/sh victim -c 'cat /etc/shadow'"
    t "V13 blocked: victim cannot read another process's memory" bash -c "! su -s /bin/sh victim -c 'head -c1 /proc/1/mem'"
    ;;
  scan)
    echo "=== Sigma check and YARA scan over everything so far"
    systemctl start legion-sigma-scan.service
    echo "      Sigma check result: $(systemctl show -p Result --value legion-sigma-scan.service), $(wc -l <"$ALERTS") alerts"
    python3 -c '
import json, sys
for l in open(sys.argv[1]):
    a = json.loads(l)
    print("        " + a["level"] + ": " + a["rule"] + " | " + a["user"] + " | " + (a["command"] or a["file"] or a["program"])[:70] + " | " + a["yara"])' "$ALERTS"
    t "the /tmp tool was found by YARA when Sigma flagged it" bash -c "grep legion-pt-tool $ALERTS | grep -q 'YARA match'"
    start="$(date +%s)"
    systemctl start legion-yara-scan.service
    echo "      weekly YARA scan, run now: $(systemctl show -p Result --value legion-yara-scan.service) in $(($(date +%s) - start)) s"
    t "weekly YARA scan finds the dropped tool" bash -c "tail -n 20 /var/log/legion/yara-scan.log | grep -q legion-pt-tool"
    systemctl reset-failed legion-sigma-scan.service legion-yara-scan.service
    ;;
  tamper)
    echo "=== attacks on the audit trail itself (as administrator)"
    n0="$(cat "$D/rules.count")"
    t "T1 locked: audit rules cannot be deleted" bash -c '! auditctl -D'
    t "T2 locked: auditing cannot be turned off" bash -c '! auditctl -e 0'
    t "T3 auditd refuses to be stopped" bash -c '! systemctl stop auditd'
    pid="$(pidof auditd)"
    kill -9 "$pid"
    for _ in $(seq 1 30); do [ -n "$(pidof auditd)" ] && [ "$(pidof auditd)" != "$pid" ] && break; sleep 1; done
    t "T4 auditd killed with SIGKILL comes back by itself" bash -c "[ -n \"\$(pidof auditd)\" ] && [ \"\$(pidof auditd)\" != $pid ]"
    t "T4 rules still loaded and locked after the kill" bash -c "auditctl -s | grep -qx 'enabled 2' && [ \"\$(auditctl -l | grep -vc '^No rules')\" = $n0 ]"
    sleep 2
    check T1 "audit rules deletion tried" T1562.012 yes exec auditctl "$AU" '-' 'auditctl'
    check T4 "auditd killed" T1562.012 no '' DAEMON_START - '-' 'DAEMON_START'
    touch /usr/local/sbin/legion-sigma-scan
    check T5 "Legion's detection program changed" T1562.001 no legion-tamper legion-sigma-scan "$AU" '-' 'legion-sigma-scan'
    # Last: wipe the local audit log. The evidence must survive on the log
    # server, and the wipe itself must be recorded.
    sleep 5
    cp /var/log/audit/audit.log "$D/audit-before-wipe.log"
    truncate -s 0 /var/log/audit/audit.log
    sleep 3
    t "T6 the wipe of the audit log is itself recorded" bash -c "LC_ALL=C ausearch --input-logs -k audit-log -i 2>/dev/null | grep -q truncate"
    rec T6 "local audit log wiped" T1070.002 no audit-log '-' 'audit-log'
    t "T6 Sigma check copes with the wiped log" bash -c "systemctl start legion-sigma-scan.service; r=\$(systemctl show -p Result --value legion-sigma-scan.service); [ \"\$r\" = success ] || [ \"\$r\" = exit-code ]"
    systemctl reset-failed legion-sigma-scan.service
    ;;
  stability)
    echo "=== stability: audit flood and command storm"
    s0="$(cat "$D/lost.before")"
    start="$(date +%s.%N)"
    su - legion -c 'python3 -c "
for i in range(50000):
    try:
        open(\"/etc/shadow\")
    except OSError:
        pass"'
    flood=$(python3 -c "import time; print(round(time.time() - $start, 1))")
    start="$(date +%s.%N)"
    su - legion -c 'for i in $(seq 1 5000); do /bin/true; done'
    storm=$(python3 -c "import time; print(round(time.time() - $start, 1))")
    sleep 5
    lost="$(auditctl -s | awk '/^lost/ { print $2 }')"
    echo "      50000 refused file opens in ${flood}s, 5000 commands in ${storm}s; audit events lost: $((lost - s0)); backlog: $(auditctl -s | awk '/^backlog / { print $2 }')"
    echo "$flood $storm $((lost - s0))" >"$D/stability"
    t "S1 no audit events lost under a 50000-event flood" test "$((lost - s0))" = 0
    t "S2 auditd still running after the flood" systemctl is-active -q auditd
    start="$(date +%s.%N)"
    systemctl start legion-sigma-scan.service
    took=$(python3 -c "import time; print(round(time.time() - $start, 1))")
    mem="$(systemctl show -p MemoryPeak --value legion-sigma-scan.service)"
    echo "      Sigma check over the flood: ${took}s, peak memory $((${mem:-0} / 1048576)) MB, $(systemctl show -p Result --value legion-sigma-scan.service)"
    echo "$took $((${mem:-0} / 1048576))" >>"$D/stability"
    t "S3 Sigma check finishes the flood in under 5 minutes" python3 -c "assert $took < 300"
    systemctl reset-failed legion-sigma-scan.service
    t "S4 the flood reached the log server too" bash -c "for i in \$(seq 1 30); do [ \$(grep -c 'shadow' $RECEIVED) -gt 1000 ] && exit 0; sleep 5; done; exit 1"
    echo "      flood records on the log server: $(grep -c shadow "$RECEIVED")"
    # A security update of auditd must still install while auditd refuses
    # to stop.
    apt_get install --reinstall auditd >"$D/auditd-reinstall.log" 2>&1; rc=$?
    t "S5 auditd security update installs cleanly (exit $rc)" test "$rc" = 0
    t "S5 auditd running and rules still locked after the update" bash -c "systemctl is-active -q auditd && auditctl -s | grep -qx 'enabled 2'"
    ;;
  external)
    # $2: web port blocked (1/0), $3: brute force locked the account (1/0),
    # $4: root password login refused (1/0), $5: SSH rate limit hit (1/0)
    echo "=== evidence for the attacks from outside (from the runner, over the network)"
    t "E1 blocked: web service on 8080 not reachable from outside" test "$2" = 1
    t "E1 firewall logged the blocked connection" bash -c "journalctl -k | grep -q 'UFW BLOCK.*DPT=8080'"
    rec E1 "port scan / reach an exposed service" T1046 "$([ "$2" = 1 ] && echo yes || echo no)" "$(journalctl -k | grep -q 'UFW BLOCK.*DPT=8080' && echo 'firewall log' || echo 'no record')" '-' 'DPT=8080'
    t "E2 blocked: SSH password guessing locks the account" test "$3" = 1
    t "E2 SSH connections rate-limited by the firewall" test "$5" = 1
    t "E2 each failed password is in the audit log" bash -c "[ \$(LC_ALL=C ausearch --input-logs -m USER_AUTH -sv no -i 2>/dev/null | grep -c 'acct=victim') -ge 5 ]"
    rec E2 "SSH password guessing" T1110.001 "$([ "$3" = 1 ] && echo yes || echo no)" "USER_AUTH failed" '-' 'acct="victim"'
    t "E3 blocked: root cannot log in over SSH" test "$4" = 1
    rec E3 "root login over SSH" T1078.003 "$([ "$4" = 1 ] && echo yes || echo no)" "$(LC_ALL=C ausearch --input-logs -m USER_LOGIN,USER_AUTH,USER_ERR -sv no -i 2>/dev/null | grep -q 'acct=root' && echo 'USER_LOGIN failed' || echo 'sshd log only')" '-' 'acct="root"'
    ;;
  after-restart)
    echo "=== after restart: still locked, evidence kept, nothing broken"
    t "audit rules locked" bash -c "auditctl -s | grep -qx 'enabled 2'"
    t "same audit rules as before the attacks" test "$(auditctl -l | grep -vc '^No rules')" = "$(cat "$D/rules.count")"
    t "firewall on" bash -c "ufw status | grep -q 'Status: active'"
    t "Sigma alerts kept" test -s "$ALERTS"
    t "log forwarding works" bash -c ": >/dev/null; logger -t legion-test after-attack-restart; sleep 5; grep -q after-attack-restart $RECEIVED"
    t "no failed services, except scan findings" bash -c '[ -z "$(systemctl --failed --no-legend --plain | grep -vE "legion-vuln-scan|clamscan|legion-yara|legion-sigma")" ]'
    systemctl --failed --no-legend --plain | sed 's/^/      failed unit: /'
    t "admin can still log in (PAM)" bash -c 'echo Correct-Horse-9x | pamtester login legion authenticate acct_mgmt'
    LEGION_NO_ANIM=1 /usr/local/sbin/legion --report-only >"$D/report.log" 2>&1
    t "compliance report flags the threat alerts" grep -q '✖ Threat detection' "$D/report.log"
    grep '✖' "$D/report.log" | sed 's/^/      report: /'
    ;;
  report)
    python3 - "$M" "$ALERTS" "$RECEIVED" "$D/stability" >"$D/attack-report.md" <<'EOF'
import json, re, sys
rows = [l.rstrip("\n").split("\t") for l in open(sys.argv[1]) if l.strip()]
alerts = [l for l in open(sys.argv[2])] if sys.argv[2] else []
received = open(sys.argv[3], errors="replace").read()
stab = open(sys.argv[4]).read().split()
out = ["# Legion attack test", "",
       "Real Ubuntu 26.04 VM, Legion installed with the audit rules locked and logs forwarded to a log server.",
       "Each row is one attack. Blocked: Legion prevented it. Audit: the audit record that proves it, with the real user.",
       "Sigma: the alert it raised. Log server: a copy reached the log server, so wiping the device's logs does not erase it.", "",
       "| ID | Attack | ATT&CK | Blocked | Audit record | Sigma alert | Log server |",
       "|---|---|---|---|---|---|---|"]
gaps = 0
for id_, name, attack, blocked, audit, sig, lsp in rows:
    titles = []
    if sig != "-":
        for a in alerts:
            if re.search(sig, a):
                titles.append("%s (%s)" % (json.loads(a)["rule"], json.loads(a)["level"]))
    sigma = "; ".join(sorted(set(titles))) or ("none expected" if sig == "-" else "**missing**")
    ls = "yes" if lsp == "-" or lsp in received else "**no**"
    if lsp == "-":
        ls = "-"
    b = {"yes": "yes", "no": "no (allowed)", "-": "-"}.get(blocked, blocked)
    if audit == "no record" or sigma == "**missing**" or ls == "**no**":
        gaps += 1
    out.append(f"| {id_} | {name} | {attack} | {b} | {audit} | {sigma} | {ls} |")
out += ["", "## Stability", "",
        f"- 50,000 refused file opens in {stab[0]} s and 5,000 commands in {stab[1]} s; audit events lost: {stab[2]}",
        f"- Sigma check over that flood: {stab[3]} s, peak memory {stab[4]} MB",
        "", f"Rows with a gap: {gaps}"]
print("\n".join(out))
EOF
    cat "$D/attack-report.md"
    t "every attack left an audit record and a copy on the log server" bash -c "! grep -qE 'no record|\*\*no\*\*' $D/attack-report.md"
    ;;
esac
echo "RESULT: $P passed, $F failed"

# Attack test: does every attack leave evidence?

This test attacks a real Ubuntu 26.04 VM with Legion installed, the audit
rules locked and logs forwarded to a log server. It attacks the way a real
attacker would get in: from the network, as an ordinary user who logged in
over SSH, as an administrator through `sudo`, and against the audit trail
itself. It then checks the evidence each attack left behind.

- **Test:** `bash tests/vm/run.sh --attack` (scripts: `tests/vm/attack.sh`, `tests/vm/attack-victim.sh`, `tests/vm/inside.sh`)
- **Result:** 69 checks passed, 0 failed (run of 2026-11-26)
- **Raw output:** `evidence/<date>/attack.log` and `attack-report.md`

## Setup

1. Fresh VM from Canonical's checked cloud image.
2. A web service listening on port 8080 on all addresses, so the firewall has something to hide.
3. A test log server on the VM receiving Legion's forwarded logs.
4. A second, ordinary user, `victim`, who logs in over SSH with a password.
5. **Baseline, proving the test can see what it tests:** before Legion, the
   web service is reachable from outside and `victim` can log in with a
   password. Both checks passed.
6. Legion installed with `--lock-audit --forward-logs syslog://127.0.0.1:5140`, then a restart. 123 audit rules loaded and locked.

## Results

How to read the table:
- **Blocked** shows whether Legion prevented the attack. Most attacks by an administrator cannot be prevented on a device the administrator controls; the point there is that they cannot go unrecorded.
- **Audit record** is the audit rule key that captured it, found by searching for that attack's user and file names.
- **Log server** shows a copy reached the separate log server.

| ID | Attack | ATT&CK | Blocked | Audit record | Sigma alert | Log server |
|---|---|---|---|---|---|---|
| E1 | Reach a service from outside (port 8080) | T1046 | yes | firewall log (`UFW BLOCK ... DPT=8080`) | none expected | yes |
| E2 | SSH password guessing | T1110.001 | yes: rate-limited, then account locked | `USER_AUTH` failures with `acct=victim` | none expected | yes |
| E3 | root login over SSH | T1078.003 | yes | sshd log | none expected | yes |
| V1 | Read password hashes (`/etc/shadow`) | T1003.008 | yes | access | none expected | yes |
| V2 | `sudo` without permission | T1548.003 | yes | privilege | none expected | yes |
| V3 | setuid copy of a shell | T1548.001 | no | perm_mod | Suspicious Commands Linux (medium) | yes |
| V4 | cron job added | T1053.003 | no | persistence | none expected | yes |
| V5 | systemd user service added | T1543.002 | no | persistence | Systemd Service Creation (medium) | yes |
| V6 | desktop autostart entry added | T1547.013 | no | persistence | none expected | yes |
| V7 | SSH key planted in `authorized_keys` | T1098.004 | no | persistence | none expected | yes |
| V8 | `.bashrc` changed | T1546.004 | no | persistence | none expected | yes |
| V9 | tool dropped in `/tmp` and run | T1204.002 | no | exec | Program Executions in Suspicious Folders (medium), with YARA match | yes |
| V10 | file opened to everyone (`chmod 777`) | T1222.002 | no | perm_mod | Suspicious Commands Linux (medium) | yes |
| V11 | file sent out with `wget --post-file` | T1048.003 | no | exec | none (see note) | yes |
| V12 | reverse shell over `/dev/tcp` | T1059.004 | no | exec | none (no audit-log rule exists) | yes |
| V13 | read another process's memory (`/proc/1/mem`) | T1003.007 | yes | access | none expected | yes |
| V14 | system discovery (`whoami`, `uname`, `/etc/passwd`) | T1082 | no | exec | none (low-level rules are off) | yes |
| V15 | `/etc/ld.so.preload` written without root | T1574.006 | yes | recorded | none expected | yes |
| A1 | `/etc/ld.so.preload` planted | T1574.006 | no | persistence | Modification of ld.so.preload (high) | yes |
| A2 | second root account (UID 0) | T1136.001 | no | identity | Creation Of An User Account (medium) | yes |
| A3 | kernel module loaded with `insmod` | T1547.006 | no | exec | Loading of Kernel Module via Insmod (high) | yes |
| A4 | blocked filesystem module (hfsplus) | T1547.006 | yes | exec | none expected | yes |
| A5 | firewall turned off | T1562.004 | no (back on after) | firewall | Disable System Firewall (high) | yes |
| A6 | sudo rule for a backdoor account | T1548.003 | no | privilege | none expected | yes |
| A7 | memory randomization (ASLR) off | T1562.001 | no | exec | ASLR Disabled Via Sysctl (high) | yes |
| A8 | system service created | T1543.002 | no | legion-tamper | Systemd Service Creation (medium) | yes |
| A9 | PAM configuration added | T1556.003 | no | identity | none expected | yes |
| A10 | logging configuration changed | T1562.006 | no | persistence | Logging Configuration Changes (high) | yes |
| T1 | delete the audit rules (`auditctl -D`) | T1562.012 | yes (rules locked) | exec | none expected | yes |
| T2 | turn auditing off (`auditctl -e 0`) | T1562.012 | yes (rules locked) | exec (`auditctl`, same search as T1) | none expected | yes (same search as T1) |
| T3 | stop auditd (`systemctl stop auditd`) | T1562.012 | yes (refused) | not searched separately | none expected | not searched separately |
| T4 | kill auditd with SIGKILL | T1562.012 | no, back within seconds, rules still locked | `DAEMON_START` | none expected | yes |
| T5 | Legion's detection program changed | T1562.001 | no | legion-tamper | none expected | yes |
| T6 | local audit log wiped | T1070.002 | no | audit-log (the wipe itself) | none expected | yes: all earlier evidence still on the log server |

**Every attack the test searched for left an audit record naming the real
user, and every one reached the log server.** After the local audit log was wiped (T6), the
records of all the earlier attacks were still on the log server.

Notes:

- **V11:** the public Sigma rule for wget exfiltration only matches when
  `--post-file` is wget's first argument. This attack put it later, as an
  attacker can, so no alert was raised. The command is in the audit log and
  on the log server.
- **V12, V14:** recorded, but no alert for the audit log exists for these.
  Sysmon for Linux raises one for the reverse shell (see `sensor-comparison.md`).
- **Alerts in this run did not yet name the user for some command records**
  (insmod, useradd). That was fixed after the run (`findings.md`, item 3) and
  confirmed in the container test. The audit records themselves always named
  the user.
- **One `useradd` raised 15 identical alerts**, one per system call. Alerts
  now count once per rule and process; this was changed after the run.

## Stability

| Check | Result |
|---|---|
| 50,000 refused file opens as fast as possible | 1.8 s, **0 audit events lost** |
| 5,000 commands in a row | 3.6 s, all recorded |
| New SSH logins during a 200,000-event audit flood | all five worked, each under 10 s |
| Sigma check over the whole flood | 28.3 s, peak memory 729 MB (limit 1 GB) |
| auditd security update (reinstall) while auditd refuses to stop | installs cleanly, auditd running, rules still locked |
| Restart after all attacks | rules locked, same 123 rules, firewall on, web service still unreachable, log forwarding working, admin login working, no failed services except the expected scan findings |
| Daily compliance report after the attacks | flags the threat alerts |

## Second line of defence: the compliance check

Some attacks leave something behind. In this run the test's own cleanup could
not delete the extra UID 0 account (`userdel` refuses while processes run as
UID 0), so the backdoor was still there after the restart. Legion's compliance
check found the leftovers on its own, without the Sigma alerts:

- "Only root has UID 0": an account other than root has full administrator rights (UID 0)
- "No duplicate user or group IDs": duplicates: UID 0
- "System accounts cannot log in": `legion-pt-root` has a login shell
- "Setuid programs all come from packages": `/home/victim/legion-pt-suid`
- "Threat detection": 65 threat alerts in the last 7 days

The same report also listed what the test VM lacks by design: disk
encryption, Secure Boot, and an SSH server that allows passwords (turned on
for the password-guessing test).

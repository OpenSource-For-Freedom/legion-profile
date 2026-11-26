# Legion attack test

Real Ubuntu 26.04 VM, Legion installed with the audit rules locked and logs forwarded to a log server.
Each row is one attack. Blocked: Legion prevented it. Audit: the audit record that proves it, with the real user.
Sigma: the alert it raised. Log server: a copy reached the log server, so wiping the device's logs does not erase it.

| ID | Attack | ATT&CK | Blocked | Audit record | Sigma alert | Log server |
|---|---|---|---|---|---|---|
| A1 | Preload library planted (/etc/ld.so.preload) | T1574.006 | no (allowed) | persistence | Modification of ld.so.preload (high) | yes |
| A2 | Second root account created (UID 0) | T1136.001 | no (allowed) | identity | Creation Of An User Account (medium) | yes |
| A3 | Kernel module loaded with insmod | T1547.006 | no (allowed) | exec | Loading of Kernel Module via Insmod (high) | yes |
| A4 | Blocked filesystem module requested | T1547.006 | yes | exec | none expected | yes |
| A5 | Firewall turned off | T1562.004 | no (allowed) | firewall | Disable System Firewall (high) | yes |
| A6 | sudo rule added for a backdoor account | T1548.003 | no (allowed) | privilege | none expected | yes |
| A7 | Memory randomization (ASLR) turned off | T1562.001 | no (allowed) | exec | ASLR Disabled Via Sysctl or Direct Syscall - Linux (high) | yes |
| A8 | System service created | T1543.002 | no (allowed) | legion-tamper | Systemd Service Creation (medium) | yes |
| A9 | PAM module configuration added | T1556.003 | no (allowed) | identity | none expected | yes |
| A10 | Logging configuration changed | T1562.006 | no (allowed) | persistence | Logging Configuration Changes on Linux Host (high) | yes |
| V1 | Password hashes read (/etc/shadow) | T1003.008 | yes | access | none expected | yes |
| V2 | sudo tried without permission | T1548.003 | yes | privilege | none expected | yes |
| V3 | setuid copy of a shell made | T1548.001 | no (allowed) | perm_mod | Suspicious Commands Linux (medium) | yes |
| V4 | cron job added | T1053.003 | no (allowed) | persistence | none expected | yes |
| V5 | systemd user service added | T1543.002 | no (allowed) | persistence | none expected | yes |
| V6 | desktop autostart entry added | T1547.013 | no (allowed) | persistence | none expected | yes |
| V7 | SSH key planted (authorized_keys) | T1098.004 | no (allowed) | persistence | none expected | yes |
| V8 | shell startup file changed (.bashrc) | T1546.004 | no (allowed) | persistence | none expected | yes |
| V9 | tool downloaded to /tmp and run | T1204.002 | no (allowed) | exec | Program Executions in Suspicious Folders (medium) | yes |
| V10 | file opened to everyone (chmod 777) | T1222.002 | no (allowed) | perm_mod | Suspicious Commands Linux (medium) | yes |
| V11 | file sent out with wget --post-file | T1048.003 | no (allowed) | exec | **missing** | yes |
| V12 | reverse shell over /dev/tcp | T1059.004 | no (allowed) | exec | none expected | yes |
| V13 | another process's memory read (/proc/1/mem) | T1003.007 | yes | access | none expected | yes |
| V14 | system discovery (whoami, uname, /etc/passwd) | T1082 | no (allowed) | exec | none expected | yes |
| V15 | preload library planted without root | T1574.006 | yes | recorded | none expected | yes |
| T1 | audit rules deletion tried | T1562.012 | yes | exec | none expected | yes |
| T4 | auditd killed | T1562.012 | no (allowed) | recorded | none expected | yes |
| T5 | Legion's detection program changed | T1562.001 | no (allowed) | legion-tamper | none expected | yes |
| T6 | local audit log wiped | T1070.002 | no (allowed) | audit-log | none expected | yes |
| E1 | port scan / reach an exposed service | T1046 | yes | firewall log | none expected | yes |
| E2 | SSH password guessing | T1110.001 | yes | USER_AUTH failed | none expected | yes |
| E3 | root login over SSH | T1078.003 | yes | sshd log only | none expected | yes |

## Stability

- 50,000 refused file opens in 1.8 s and 5,000 commands in 3.6 s; audit events lost: 0
- Sigma check over that flood: 28.3 s, peak memory 729 MB

Rows with a gap: 1

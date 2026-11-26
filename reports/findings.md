# Problems found by testing, and how they were fixed

Testing is only useful if it finds things. This is every defect in Legion that
the tests below found during development, what it would have meant on a real
device, and the fix. Each fix was confirmed by rerunning the test that found
it. Problems that were only in the test scripts are listed separately at the
end.

## Defects in Legion

| # | Found by | Problem | Impact on a real device | Fix |
|---|---|---|---|---|
| 1 | Attack VM, T3 | An administrator could stop auditd with `systemctl stop auditd`, even with the audit rules locked. The kernel kept its rules, but nothing wrote the records to disk. | An insider with sudo could switch off the audit trail quietly; everything after that was lost. | auditd now refuses a manual stop (`RefuseManualStop=yes`) and restarts within a second if killed (`Restart=always`). Legion applies its own settings changes with a reload, which needs no stop. Ubuntu's auditd package updates still install (tested, S5). The daily check fails if the protection is missing. |
| 2 | Attack VM, YARA tests | The weekly YARA scan and the YARA check on Sigma alerts ran with a private `/tmp`, so they could not see `/tmp`, `/var/tmp` or `/dev/shm`. | Tools dropped in the usual attacker folders were never scanned. | Those two services now see the real temporary folders. Their other sandbox settings stay. |
| 3 | Desktop VM, Sigma test | Alerts were tied to the wrong audit event: Zircolite's row numbers do not match line numbers on real audit logs. | Alerts could name the wrong user and command, or none. | The audit event is now found by the record's contents, so the user, program and command come from the right event. Two details had to be right: Zircolite drops underscores from field names, and only command-argument records store values in hex. |
| 4 | Desktop VM, Sigma test | Changes Legion itself made during a run raised alerts. auditd writes to disk in batches, so the last seconds of a run were read after the "already reviewed" mark. | False alarms after every Legion run. | Legion records the time window of each run, and the Sigma check skips events inside it, whenever they reach the disk. |
| 5 | Attack test design | The audit logs themselves were not watched. | Wiping or editing the audit log left no record on the device. | `/var/log/audit` is watched (auditd's own writes are never audited). With log forwarding, the log server keeps the earlier records anyway (test T6). |
| 6 | Attack test design | A file watch on a folder that does not exist is skipped. On a new account, `~/.ssh` and `~/.config/systemd/user` do not exist. | A planted SSH key or user service on a new account was not recorded. | Legion creates those folders empty and private, records which ones it created, and removal deletes them again if they are still empty. |
| 7 | Desktop VM, removal | Kernel settings were not fully restored on removal: the firewall and crash-report steps changed some values before the hardening step saved them. | Removal left some kernel values changed. | All kernel values are saved before any step runs. |
| 8 | Container, audit step | An audit rule template starting with `-w` was read by `printf` as an option, so the audit step failed. | No audit rules on some systems. | Templates are passed after `--`. |
| 9 | Container, vulnerability scan | The weekly vulnerability scan needed `bunzip2`, which a minimal Ubuntu lacks, and counted Ubuntu's inventory entry as a finding. | Scan failed, or reported a vulnerability that was not one. | Decompression in Python; only patch definitions count as findings. |

## Problems in the test scripts (not in Legion)

- The container test waited forever on its own log listener. It now waits only for the process it started.
- The text-console login test looked for the banner before connecting, after the banner had already been printed. It now also checks the banner shown after logout, and after removal it checks that Ubuntu's own banner is back.
- The audit-lock test assumed file order mattered. `augenrules` always moves the lock to the end, so the test now checks that only Legion's lock file sets it.
- The attack runner stopped on the first failed password during password guessing, and fed the ordinary user's commands on standard input, where one command could swallow the rest. Both fixed.
- The `ausearch` checks read standard input when run over SSH without a terminal. They now read the log files explicitly (`--input-logs`).

## Known limits (not fixed, by design)

- **No Sigma rule for the audit log covers a reverse shell, base64-decoded commands or `curl` use.** Those actions are recorded in the audit log but raise no alert. Sysmon for Linux would alert on them (see `sensor-comparison.md`).
- **Account lockouts are kept in `/run/faillock`**, which empties on restart, so a restart unlocks accounts early. The failed attempts stay in the audit log.
- **An administrator can still change the auditd unit file or restart auditd.** Both are recorded, through the watches on `/etc/systemd/system` and the daemon's start record. Locking the audit rules (`--lock-audit`) keeps the rules themselves out of reach until a restart.

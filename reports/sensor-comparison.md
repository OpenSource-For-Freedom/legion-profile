# Event sources for threat detection: auditd, Laurel, Sysmon for Linux

Sigma rules can only find what the device records. This test puts the same
workload through three event sources on one VM and runs all 217 Linux Sigma
rules (every level) against each, with Zircolite 4.7.1.

- **Test:** `bash tests/vm/run.sh --sensors` (script: `tests/vm/sensors.sh`)
- **Run:** 2026-11-26, 8 checks passed, 0 failed. Its raw log was overwritten when a later rerun was stopped to free memory on the test machine; the figures below were recorded from that run's output. Rerun the test to reproduce them.
- **System:** Ubuntu 26.04.1, kernel 7.0.0-43, auditd 4.1.2 with Legion's rules (not locked), Laurel 0.7.3 (Ubuntu package), Sysmon for Linux 1.5.3 (Microsoft's package repository for Ubuntu 26.04)

## Workload

500 ordinary commands, then, as an ordinary user:

- a program copied to `/tmp` and run, `chmod 777`
- discovery commands (`cat /etc/passwd`, `crontab -l`, `id`, `uname`, `whoami`, `hostname`)
- a base64-decoded command piped to a shell
- uploads with `wget --post-file` and `curl -F`, a port scan with `nc -z`
- a reverse-shell connection through `/dev/tcp`
- through sudo: `insmod`, creating and deleting `/etc/ld.so.preload`, adding and deleting a user, listing firewall rules

## Results

| Source | Sigma rules that fired | CPU time for the workload | Log written |
|---|---|---|---|
| auditd with Legion's rules | 8 | 232 ms (auditd and Laurel together) | 805 KB |
| auditd plus Laurel | Laurel adds no rules; it rewrites the same events as JSON | (included above) | 946 KB more |
| Sysmon for Linux | 10 | 577 ms | 1,563 KB |

**Only auditd caught:**
- Loading of Kernel Module via Insmod (high)
- Modification of ld.so.preload (high)
- Creation Of An User Account (medium)

These come from audit file watches and account records, which Sysmon does not have.

**Only Sysmon caught:**
- Linux Reverse Shell Indicator (critical)
- Decode Base64 Encoded Text (low)
- Crontab Enumeration (low)
- Curl Usage on Linux (low)
- Chmod Targeting Sensitive Directories (medium)
- User Has Been Deleted Via Userdel (medium)

Most Linux Sigma rules (145 of 217) are written for process-creation events,
the shape Sysmon produces.

**Both caught**, under different rule names, the program run from `/tmp`, the
permission change, and system discovery.

**What Laurel adds:** for each event, the parent process (for example, that
`/tmp/evil-test` was started by `bash`, process 1612) and labels for every
process a package manager starts. That does not add detections. It would let
Legion tell package installs apart from attacks more precisely than its
current filter on the program name.

## Conclusion

- auditd, which Legion ships, covers persistence, kernel modules, accounts
  and the audit trail itself. It is the only one of the three whose rules can
  be locked against root.
- Sysmon for Linux adds process and network detail, most visibly the reverse
  shell. It costs about 2.5 times auditd's CPU for the same work and adds
  Microsoft's package repository to the device.
- The two together cover the most. Sysmon is a candidate for an optional
  addition; it is not installed by Legion today.

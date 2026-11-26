# Legion test reports

How Legion was tested, what each test proved, and the raw evidence. Every
result here comes from a script in `tests/` that anyone can run again on a
machine with Docker and hardware virtualization.

## Summary

| Test | What it covers | Latest result | Report |
|---|---|---|---|
| Container | Install, every setting, alerts, repeat runs, clean removal | 108 of 108 passed | [container-suite.md](container-suite.md) |
| Desktop VM | Real kernel, audit lock, 4 restarts, logins at the login screen, console and sudo | 96 of 97; the one failure is fixed | [vm-desktop.md](vm-desktop.md) |
| Attack VM | 34 attacks from the network, an ordinary user, an administrator and against the audit trail; stability under load | 69 of 69 passed | [attack-surface.md](attack-surface.md) |
| Sensor comparison | auditd, Laurel and Sysmon for Linux on the same attack | 8 of 8 passed | [sensor-comparison.md](sensor-comparison.md) |

## Headline results

- **Every attack the test searched for left an audit record naming the real
  user, and a copy on the log server.** Wiping the device's audit log left the
  earlier evidence intact on the log server, and the wipe itself was recorded.
- **The audit trail could not be switched off.** As root:
  - deleting the locked audit rules and turning auditing off both failed
  - stopping auditd was refused
  - killing it brought it back within seconds, with the rules still locked
- **Blocked:** outside access to an exposed service, SSH password guessing
  (rate-limited, then the account locked), root SSH login, reading password
  hashes, `sudo` without permission, reading another process's memory, and
  loading a blocked filesystem module.
- **Stable under load:** 50,000 audit events in under 2 seconds with none
  lost; SSH logins kept working during a 200,000-event flood; an auditd
  security update installed while auditd refused to stop.
- **No false alarms** from restarts and desktop logins.
- **Logins keep working:** after every restart, and after removal.

## Problems found

Testing found nine defects in Legion, including one serious one: an
administrator could stop auditd, even with the rules locked. All nine are
fixed. See [findings.md](findings.md), which also lists the known limits.

## Contents

- [methodology.md](methodology.md): environments, how the VM is driven, what counts as proof, limits
- [findings.md](findings.md): defects found by testing and their fixes; known limits
- [container-suite.md](container-suite.md), [vm-desktop.md](vm-desktop.md), [attack-surface.md](attack-surface.md), [sensor-comparison.md](sensor-comparison.md): one report per test
- `evidence/<date>/`: raw logs, the generated attack table, screenshots and the VM console log, with `SHA256SUMS`. Paths on the machine that ran the tests are replaced with placeholders.

## Regenerating the evidence

```bash
bash tests/run.sh                > .testlogs/container.log 2>&1
bash tests/vm/run.sh             > .testlogs/vm.log 2>&1
bash tests/vm/run.sh --attack    > .testlogs/attack.log 2>&1
bash tests/vm/run.sh --sensors   > .testlogs/sensors.log 2>&1
bash tests/collect-evidence.sh
```

Each VM test boots a 4 GB virtual machine. Run them one at a time on a
machine that is doing other work.

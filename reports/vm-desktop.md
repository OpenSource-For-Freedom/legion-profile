# Desktop VM test: real kernel, restarts and logins

This test runs Legion on a real Ubuntu 26.04 kernel with the GNOME desktop and
the GDM login screen. It checks what a container cannot: audit rules loaded
and locked, kernel settings, module blocking. Above all it checks that people
can still log in after every restart, at the login screen, on the text console
and through sudo.

- **Test:** `bash tests/vm/run.sh` (scripts: `tests/vm/inside.sh`, `tests/vm/vm-scenario.sh`, `tests/vm/qmp.py`)
- **Screenshots and console log:** `evidence/<date>/screenshots/` and `vm-console.log.gz`

## Sequence

1. Fresh VM; install the desktop (`ubuntu-desktop-minimal`, GDM); restart.
2. **Before Legion:** record the audit rule count and kernel values; log in through PAM (login screen, console, sudo); log in at the login screen by typing.
3. **Install Legion** with the audit rules locked and log forwarding on.
   - Audit rules: all rule groups loaded, locked; `auditctl -D` refused as root.
   - Audit events found for a real user.
   - Logs on the log server.
   - Sandboxed services run.
   - Kernel settings applied; blocked module refused.
   - Simulated attack raises Sigma alerts.
4. **Restart 1 and restart 2.** After each:
   - Rules still locked and identical; kernel settings kept; firewall on.
   - Forwarding works.
   - PAM logins work.
   - The Sigma check finds no false alarms from the restart and logins.
   - Screen lock enforced; login screen hides user names.
   - Console login with the banner; login screen login to a desktop session, with screenshots.
5. **Run Legion again while locked:** exits 0, warns that the audit changes need a restart, keeps the lock and forwarding.
6. **Remove Legion:** exits 0, warns a restart is needed, forwarding stopped, kernel values back to what was recorded before.
7. **Restart after removal:** rules no longer locked, rule count back to before, all logins work, Ubuntu's own console banner back.

## Results

| Run | Code | Result |
|---|---|---|
| 2026-11-25 (Phase 2) | tamper lockdown and forwarding | 83 of 84; the one failure was in the test (it expected Legion's banner after removal); fixed |
| 2026-11-26 (Phase 3) | threat detection added | 96 of 97; the one failure was a Sigma alert not naming the user for a command run through sudo. Fixed afterwards (`findings.md`, item 3) and confirmed in the container test. |

The final rerun on the last code was stopped before it finished, to free
memory on the test machine. The raw log of the 2026-11-26 run was cleared when
that rerun started, so the numbers above come from the test output recorded
during development. The screenshots and console log in the evidence folder
are from the 2026-11-25 run.

Measurements from the 2026-11-26 run:

- **No false Sigma alarms** after either restart, with console and login-screen logins in between.
- **Audit log size** (every command people run is recorded): 11 MB right after install, 12 MB after restart 1 (1,415 commands), 15 MB after restart 2 (1,966 commands). auditd keeps 20 files of 32 MB.
- **Restart:** the VM is back on SSH about 16 seconds after the restart command. Boot to userspace takes about 8 seconds.

## Screenshots

For each stage the runner saves two screenshots.

**`*-login-screen.png`, the login screen before typing.** After Legion it shows:
- the "Authorized use only" banner
- the Legion logo
- a user name box, with no list of users

**`*-after-login.png`, the screen after typing the user name and password:**
- the desktop

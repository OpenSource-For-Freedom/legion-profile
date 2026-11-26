# Container test: install, behaviour and clean removal

The container test runs Legion end to end in an Ubuntu 26.04 container with
systemd, then removes it and checks the system is back to how it was. It runs
in about 5 minutes and is the test for every change.

- **Test:** `bash tests/run.sh` (script: `tests/scenario.sh`, image: `tests/Dockerfile`)
- **Result:** 108 checks passed, 0 failed (run of 2026-11-26, after the last fix)
- **Raw output:** `evidence/<date>/container.log`
- **Also checked:** `shellcheck` on every script, with no findings

## What is set up before Legion runs

To make the test realistic, the container starts in states real devices are in:
- **Users and passwords:** a user whose password is 200 days old.
- **Firewall:** active, with the user's own rules.
- **Network:** a virtual machine bridge.
- **Packages:** an interrupted package install, and a package removed but not purged.
- **Running services:** SSH running, and a stand-in log server listening for Legion's forwarded logs.

## Checks by section

| Section | Checks | What is proven |
|---|---|---|
| Refuses to run from a pipe | 1 | `curl ... \| bash` is refused, so the script cannot be run unseen |
| Install with no terminal and awkward options | 20 | Exits 0; waits for the package lock; repairs the interrupted install; removes no package; keeps the user's firewall rules; allows only private networks from a list that includes bad and public entries; login banner and logo compiled into the login screen; integrity check clean right after install |
| Phase 2: tamper lockdown | 8 | Logs reach the log server; disk queue for offline times; a bad log server address is refused and changes nothing; audit lock written; Legion's own files and AI agent settings watched; services run sandboxed; evidence bundle has baseline checksums |
| Phase 3: threat detection | 18 | Pinned Zircolite release installed; only audit-log Sigma rules, medium and up; every command audited; persistence files watched before they exist; a written attack raises the right alerts, naming the user, program and command, with a YARA scan; package-manager changes not reported; alerts reach the system log and the log server; events are not reported twice; the ignore list works; the compliance report and evidence bundle carry the alerts |
| Phase 1: CIS and 800-171 additions | 24 | Password age (90 days, 14 days' grace for an old password), history, inactivity; idle timeout; umask; sudo settings; `su` limited to root; no core dumps; blocked filesystems; SSH hardening; hidden user list; no media autorun; CIS audit rules; low-disk alert; vulnerability scan writes its report |
| Integrity | 4 | Files a package update changes are not flagged; an unrelated change stays flagged and fails the daily check until an admin accepts it |
| Password history | 6 | The last 24 passwords are refused |
| One run at a time | 1 | A second run during a run is refused |
| Colour setting | 1 | `NO_COLOR` survives the sudo hand-off |
| Drift alerts | 1 | A setting that breaks keeps alerting until fixed |
| Stale package lists | 1 | Handled without failing |
| Second run | 2 | Repeatable: exits 0, no duplicate firewall rules |
| Removal | 17 | Firewall rules and login files byte-identical to before; lockout, sudo, SSH, session and filesystem settings gone; password ages back; group removed; threat detection, audit lock and forwarding removed; no failed services; a second removal is clean |
| Removal after login files were edited | 4 | Removal reports that the lockout is still active and keeps Legion's login profiles so it can be finished; after the edits are resolved it finishes, and the lockout is really gone |

## What this test cannot show

Containers share the host's kernel, so audit rules, kernel settings and module
blocking are written but not loaded here. The desktop VM and attack VM tests
cover those on a real kernel.

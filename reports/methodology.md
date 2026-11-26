# How Legion is tested

Legion changes security settings that can lock people out of a machine or
stop it booting. Every change is therefore tested on throwaway systems that
start from a clean Ubuntu 26.04 image, and every test is a script in this
repository that anyone can run again. Nothing is tested on a real workstation.

## Test environments

| Environment | What it is | Used for |
|---|---|---|
| Container | Ubuntu 26.04 container with systemd running inside (`tests/Dockerfile`) | Fast checks of everything that does not need a real kernel: files, PAM, firewall rules, services, reports, removal |
| Desktop VM | Ubuntu 26.04 cloud image in QEMU with KVM, run inside a container (`tests/vm/`), GNOME desktop and GDM login screen added | Real kernel: audit rules and the audit lock, kernel settings, module blocking, restarts, logins at the login screen and on the text console |
| Attack VM | Same VM, server install, a second ordinary user, password SSH logins allowed | Attacks from the network and from local accounts, attacks on the audit trail, stability under load |
| Sensor VM | Same VM with Laurel and Sysmon for Linux added | Comparing the event sources the Sigma rules can read |

All VMs start from Canonical's published cloud image, checked against
Canonical's `SHA256SUMS` before use. Each run gets a fresh copy-on-write disk,
so no run can affect the next.

## How the VM is driven

The test runner talks to the VM the way a person and an attacker would:

- **SSH** for commands, as the admin user through `sudo`, so the audit log
  attributes them to a real login.
- **The login screen** through QEMU's keyboard: the runner types the user
  name and password into GDM and takes screenshots before and after.
- **The text console** through the VM's serial port: the runner reads the
  login banner, logs in, and checks the shell answers.
- **The network** from outside the VM: connections arrive from the host side
  of QEMU's network (10.0.2.2), so the VM's firewall treats them as external.
  SSH password guessing uses `sshpass` against a real `sshd`.

## What counts as proof

A test passes only on an observed result, never on a configuration file
looking right. For example:

- **Firewall:** a connection from outside to a listening service fails, and
  the kernel logs the blocked packet.
- **Account lockout:** after wrong passwords, the right password is refused.
- **Audit trail:** `ausearch` finds the record for the action, with the
  login ID of the person who did it, even when they used `sudo`.
- **Locked audit rules:** `auditctl -D` and `auditctl -e 0` fail as root, and
  the rule count is unchanged after a restart.
- **Log forwarding:** the record appears on a separate log server process,
  and is still there after the local audit log is wiped.
- **Sigma alerts:** the alert is in `/var/log/legion/sigma-alerts.log` and in
  the system log, names the user and command, and the YARA result is recorded.
- **Restarts and logins:** after every restart the admin logs in at the login
  screen (a desktop session starts), on the console (banner shown, shell
  answers) and through PAM for `login`, `gdm-password` and `sudo`.
- **Removal:** files, settings, kernel values and the firewall are compared
  with copies taken before Legion was installed.

Every attack in the attack test uses file names containing `legion-pt`, so its
evidence can be told apart from normal system activity.

## Attack techniques

Attacks are labelled with MITRE ATT&CK technique IDs. They are simulations:
each performs the real action an attacker would take (plant a file, run a
command, guess a password) with harmless content, then the test looks for the
evidence. The YARA test file is `/bin/true` with a string appended that a
published YARA rule looks for; it is not malware.

## Limits

- Containers share the host's kernel, so audit, kernel and module tests run
  only in the VMs.
- The VMs have 4 CPUs and 4 GB of memory. Timings on real hardware will differ.
- The attack test covers techniques that leave evidence on the device. It is
  not a full penetration test of every service an organization might install.
- Sigma detection uses the community rules written for Linux audit logs.
  Techniques with no such rule are recorded in the audit log but raise no
  alert; the attack report marks these, and the sensor comparison shows which
  of them Sysmon for Linux would catch.

## Running the tests

```bash
bash tests/run.sh                      # container, about 5 minutes
bash tests/vm/run.sh                   # desktop VM with restarts, about 35 minutes
bash tests/vm/run.sh --attack          # attack VM, about 25 minutes
bash tests/vm/run.sh --sensors         # sensor comparison, about 10 minutes
bash tests/collect-evidence.sh         # copies the results into reports/evidence/
```

The VM tests need Docker and hardware virtualization (`/dev/kvm`).

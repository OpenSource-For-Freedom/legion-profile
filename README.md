# Legion Profile

![Legion Profile](docs/legion-banner.png)

Legion hardens Ubuntu 26.04 laptops and desktops and reports on them. Each check maps to SOC 2, HIPAA, NIST 800-53 (FedRAMP) and NIST 800-171 (CMMC Level 2) controls. Every run writes a report and an evidence bundle with checksums for auditors.

CIS and DISA STIG have not published benchmarks for Ubuntu 26.04 yet. Until they do, Legion uses the CIS Ubuntu 24.04 rules that apply to 26.04. When the official benchmark comes out, Legion runs it automatically.

## What it covers

- Ubuntu Pro: security updates for every package (ESM) and Livepatch. Optional. Needs your free token from https://ubuntu.com/pro/dashboard
- Updates: installs all pending updates and turns on daily automatic security updates
- Firewall: blocks incoming connections, allows outgoing
- Account lockout: 5 failed logins lock an account for 30 minutes, then it unlocks by itself
- Login banner, and a screen lock after 10 minutes that users cannot turn off
- Password policy: new passwords need 12+ characters and 3 character types
- Audit logging: records changes to accounts, sudo, system time, kernel modules and the firewall
- Log retention: keeps system logs for 1 year
- Malware scanning: ClamAV weekly, plus YARA weekly with the YARA Forge core rules
- File integrity: daily check of installed package files and of /etc, /boot, /usr/local and /root
- System hardening: safer kernel settings, unused network protocols blocked, tighter cron and sudoers permissions
- Daily compliance check: flags any check that starts failing

## Before you run it

**Encrypt the disk when you install Ubuntu.** Encryption can only be turned on during installation (Advanced features, then Use LVM and encryption). It cannot be added later without wiping the disk.

## How to run it

```bash
git clone https://github.com/OpenSource-For-Freedom/legion-profile.git
cd legion-profile
bash legion.sh
```

It asks for your sudo password and your Ubuntu Pro token (press Enter to skip), then runs each step and shows the result. Reboot when it finishes.

To skip the token question:

```bash
UBUNTU_PRO_SECRET=your-token bash legion.sh
```

After the first run, check the device any time without changing anything:

```bash
sudo legion --check
```

Run `bash legion.sh --help` for all options. It is safe to run again.

## Reports and evidence

- Compliance report: `/var/log/legion/compliance-report.md` (and `.json`)
- Evidence bundles: `/var/log/legion/evidence/`, each with a SHA-256 checksum
- Scan results: `/var/log/legion/yara-scan.log` and `integrity.log`

A ClamAV, YARA, integrity or daily compliance finding marks its service as failed. Check with `systemctl --failed`.

## If you get locked out

Wait 30 minutes, or have another admin run `sudo faillock --user NAME --reset`.

## How to remove it

If something breaks, this undoes Legion's settings and puts Ubuntu's defaults back:

```bash
bash legion-remove.sh
```

It keeps installed updates, Ubuntu Pro and your logs. Add `--remove-packages`, `--detach-pro` or `--purge-logs` to remove those too. Reboot afterward.

## Notes

- No script makes an organization compliant. These frameworks also cover policies, training, backups and vendor agreements. The report lists what Legion cannot check.
- FIPS-validated cryptography, required for FedRAMP and CMMC, is not yet available for Ubuntu 26.04. Legion reports it and picks it up once Ubuntu Pro offers it.
- Docker bypasses the firewall for published container ports.

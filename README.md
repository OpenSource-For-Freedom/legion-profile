# Legion Profile

One script that hardens an Ubuntu laptop or desktop and writes an evidence report for SOC 2 endpoint controls. It also adds YARA malware scanning and file integrity monitoring.

## Before you start

**Encrypt the disk when you install Ubuntu.** Full-disk encryption can only be turned on during installation (Advanced features, then Use LVM and encryption). It cannot be added later without wiping the disk. Do this before the device is set up or handed to anyone. Legion checks for it and asks before continuing on an unencrypted disk.

## Run it

```bash
bash legion.sh
```

It asks for your sudo password, checks the system, asks for an Ubuntu Pro token (optional), then runs each step and shows the result.

To skip the token question:

```bash
UBUNTU_PRO_SECRET=your-token bash legion.sh
```

Supported: Ubuntu 24.04 and 26.04, x86_64 and arm64.

Reboot when it finishes.

## What it does

| Step | What it sets up |
|---|---|
| Ubuntu Pro | Security updates for every package (ESM) and Livepatch. Needs a token from your Ubuntu One account at https://ubuntu.com/pro/dashboard. Free for up to 5 personal machines. |
| Patching | Installs all pending updates |
| Automatic updates | Security updates install daily |
| Firewall | Blocks incoming connections, allows outgoing |
| Audit logging | Records changes to accounts, sudo, time, kernel modules and the firewall |
| Log retention | Keeps system logs for 1 year, up to 2 GB |
| ClamAV | Weekly malware scan of /home |
| Password policy | New passwords need 12+ characters and 3 character types |
| System hardening | Safe kernel settings, blocks unused network protocols, locks down cron and sudoers permissions |
| YARA | Weekly scan of /home, /root and temp folders with the YARA Forge core rules |
| Integrity | Daily check of package files against their checksums, and AIDE for /etc, /boot, /usr/local, /root and cron |

## Options

| Option | Effect |
|---|---|
| `--allow-unencrypted` | Continue on an unencrypted disk without asking |
| `--pro-token-file FILE` | Read the Ubuntu Pro token from a file instead of asking |
| `--no-pro` | Skip Ubuntu Pro |
| `--no-yara` | Skip the YARA scan |
| `--no-aide` | Skip the integrity check |
| `--steam` | Allow Steam Remote Play on the local network |
| `--with-tools` | Also install lynis, gitleaks, pre-commit, shellcheck, Deja Dup, Bitwarden, Terraform and Trivy |
| `--report-only` | Change nothing, only write the report |

## Results

- Report: `/var/log/legion/endpoint-report.txt`
- Run log: `/var/log/legion/run-*.log`
- YARA results: `/var/log/legion/yara-scan.log`
- Integrity results: `/var/log/legion/integrity.log`

A ClamAV, YARA or integrity finding marks its service as failed. Check with `systemctl --failed`.

## Good to know

- This does not make an organisation SOC 2 compliant. SOC 2 covers policies, access reviews and more. This covers one device.
- Docker bypasses the firewall for published container ports.
- It does not set up backups, MDM, or central logging.
- Safe to run again.

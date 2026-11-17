#!/usr/bin/env bash
# Legion Profile removal: undoes the changes legion.sh made and puts Ubuntu's
# defaults back. Use it if something breaks after running Legion.
#
# Usage:
#   bash legion-remove.sh [options]       (asks for your sudo password)
#
# Options:
#   --remove-packages  also uninstall auditd, ClamAV, YARA, AIDE and OpenSCAP
#   --detach-pro       also detach this machine from Ubuntu Pro
#   --purge-logs       also delete /var/log/legion (your evidence reports)
#   -y, --yes          don't ask for confirmation
#   -h, --help         show this help
#
# Settings Legion changed are restored to what this machine had before
# Legion's first run, including whether the firewall was on. Kept on purpose:
# installed updates and the packages Ubuntu ships with (ufw,
# unattended-upgrades, libpam-pwquality). Removing libpam-pwquality would
# rewrite the login configuration, so this script never does.
set -euo pipefail

exec 3>&1
UTF8=0
case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in *[Uu][Tt][Ff]-8* | *[Uu][Tt][Ff]8*) UTF8=1 ;; esac
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_OK=$'\e[32m' C_FAIL=$'\e[31m' C_INFO=$'\e[36m' C_WARN=$'\e[33m' C_BOLD=$'\e[1m' C_RST=$'\e[0m'
else
  C_OK="" C_FAIL="" C_INFO="" C_WARN="" C_BOLD="" C_RST=""
fi
if [ "$UTF8" = 1 ]; then I_OK="✔" I_FAIL="✖" I_INFO="ℹ" I_WARN="!"; else I_OK="ok" I_FAIL="FAIL" I_INFO="i" I_WARN="!"; fi
ok() { printf '  %s%s%s %s\n' "$C_OK" "$I_OK" "$C_RST" "$*" >&3; }
fail() { printf '  %s%s%s %s\n' "$C_FAIL" "$I_FAIL" "$C_RST" "$*" >&3; }
info() { printf '  %s%s%s %s\n' "$C_INFO" "$I_INFO" "$C_RST" "$*" >&3; }
warn() { printf '  %s%s%s %s\n' "$C_WARN" "$I_WARN" "$C_RST" "$*" >&3; }
section() { printf '\n%s%s%s\n' "$C_BOLD" "$*" "$C_RST" >&3; }

usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; }

REMOVE_PACKAGES=0 DETACH_PRO=0 PURGE_LOGS=0 YES=0
ARGS=()
for arg in "$@"; do
  case "$arg" in
    --remove-packages) REMOVE_PACKAGES=1 ;;
    --detach-pro) DETACH_PRO=1 ;;
    --purge-logs) PURGE_LOGS=1 ;;
    -y | --yes) YES=1 ;;
    -h | --help) usage; exit 0 ;;
    *) echo "unknown option: $arg (see --help)" >&2; exit 2 ;;
  esac
  ARGS+=("$arg")
done

if [ "$(id -u)" != 0 ]; then
  SELF="$(readlink -f "$0" 2>/dev/null || true)"
  [ -f "$SELF" ] || { fail "cannot find this script on disk; run it as: sudo bash legion-remove.sh"; exit 2; }
  info "administrator access needed, asking sudo"
  exec sudo bash "$SELF" "${ARGS[@]}"
fi

section "Legion Profile removal"
info "this undoes Legion's settings and puts Ubuntu's defaults back"
[ "$REMOVE_PACKAGES" = 0 ] || warn "also uninstalling auditd, ClamAV, YARA, AIDE and OpenSCAP"
[ "$DETACH_PRO" = 0 ] || warn "also detaching from Ubuntu Pro"
[ "$PURGE_LOGS" = 0 ] || warn "also deleting /var/log/legion, including your evidence reports"
if [ "$YES" = 0 ]; then
  if [ -t 0 ] && [ -t 1 ]; then
    printf '  %s?%s remove Legion Profile from this machine? [y/N] ' "$C_WARN" "$C_RST" >&3
    read -r reply
    case "$reply" in [Yy]*) ;; *) info "cancelled, nothing changed"; exit 0 ;; esac
  else
    info "no terminal to confirm on; run with --yes"; exit 2
  fi
fi

FAILED=0
# Runs one undo action; reports it and carries on if it fails.
undo() { # label, command...
  local label="$1"; shift
  if "$@" >/dev/null 2>&1; then ok "$label"; else fail "$label"; FAILED=$((FAILED + 1)); fi
}
unit_off() { # stops, disables and deletes a unit Legion created
  local u
  for u in "$@"; do
    systemctl disable --now "$u" 2>/dev/null || true
    systemctl reset-failed "$u" 2>/dev/null || true
    rm -f "/etc/systemd/system/$u"
  done
}

# Copy Legion's backups and records first, so every restore below can use them
# no matter when /var/lib/legion is deleted.
B="$(mktemp -d)"
trap 'rm -rf "$B"' EXIT
[ ! -d /var/lib/legion/backup ] || cp -a /var/lib/legion/backup/. "$B"/
for f in created-repos installed-tools; do [ ! -f "/var/lib/legion/$f" ] || cp "/var/lib/legion/$f" "$B/$f"; done
in_container() { systemd-detect-virt --container -q 2>/dev/null; }

section "Login settings"
if [ -f /usr/share/pam-configs/legion-faillock ] || [ -f /usr/share/pam-configs/legion-faillock-notify ] ||
  grep -qE '^[^#]*pam_faillock.so.*unlock_time=1800' /etc/pam.d/common-auth 2>/dev/null; then
  # pam-auth-update leaves locally edited PAM files alone but still exits 0,
  # so check the file itself. Legion's profiles are deleted only once the
  # lockout is really gone; otherwise they are needed to finish the job.
  pam-auth-update --disable legion-faillock legion-faillock-notify >/dev/null 2>&1 || true
  if grep -qE '^[^#]*pam_faillock.so.*unlock_time=1800' /etc/pam.d/common-auth; then
    fail "account lockout still active: /etc/pam.d/common-auth has local edits"
    info "to finish, run: sudo pam-auth-update --force --disable legion-faillock legion-faillock-notify, then this script again"
    FAILED=$((FAILED + 1))
  else
    undo "account lockout removed" bash -c '
      rm -f /usr/share/pam-configs/legion-faillock /usr/share/pam-configs/legion-faillock-notify &&
        sed -i -E "/^legion-faillock(-notify)?$/d" /var/lib/pam/seen'
  fi
fi
if [ -e "$B/issue" ] || [ -e "$B/issue.absent" ] || [ -e "$B/issue.net" ] || [ -e "$B/issue.net.absent" ]; then
  # shellcheck disable=SC2016 # expanded by the inner shell
  undo "login banner restored" bash -c '
    for f in issue issue.net; do
      if [ -f "$1/$f" ]; then cp -p "$1/$f" "/etc/$f"; elif [ -f "$1/$f.absent" ]; then rm -f "/etc/$f"; fi
    done' _ "$B"
fi
if [ -f /etc/dconf/db/gdm.d/01-legion-banner ] || [ -f /etc/dconf/db/local.d/00-legion-screenlock ]; then
  # Empty settings folders are left in place on purpose: dconf update then
  # rebuilds them as empty databases, so no Legion lock survives.
  # shellcheck disable=SC2016 # expanded by the inner shell
  undo "login screen banner and enforced screen lock removed" bash -c '
    rm -f /etc/dconf/db/gdm.d/01-legion-banner /etc/dconf/db/local.d/00-legion-screenlock /etc/dconf/db/local.d/locks/00-legion-screenlock
    [ ! -f "$1/created-dconf-profile-gdm" ] || rm -f /etc/dconf/profile/gdm
    [ ! -f "$1/created-dconf-profile-user" ] || rm -f /etc/dconf/profile/user
    dconf update' _ "$B"
fi
if [ -f "$B/gdm3-greeter.dconf-defaults" ]; then
  # shellcheck disable=SC2016 # expanded by the inner shell
  undo "login screen settings restored" bash -c 'cp -p "$1" /etc/gdm3/greeter.dconf-defaults && { [ ! -x /usr/share/gdm/generate-config ] || /usr/share/gdm/generate-config || true; }' _ "$B/gdm3-greeter.dconf-defaults"
fi
if [ -f "$B/postfix-inet_interfaces" ] && command -v postconf >/dev/null; then
  # shellcheck disable=SC2016 # expanded by the inner shell
  undo "mail server network setting restored" bash -c 'postconf -e "inet_interfaces = $(cat "$1")" && { systemctl restart postfix 2>/dev/null || true; }' _ "$B/postfix-inet_interfaces"
fi

section "Scheduled scans and checks"
undo "YARA weekly scan removed" bash -c "$(declare -f unit_off); unit_off legion-yara-scan.timer legion-yara-scan.service; rm -f /usr/local/sbin/legion-yara-update /usr/local/sbin/legion-yara-scan"
undo "integrity check removed (AIDE and package checks)" bash -c "$(declare -f unit_off); unit_off legion-integrity.timer legion-integrity.service; rm -f /usr/local/sbin/legion-aide-baseline /usr/local/sbin/legion-integrity-check /etc/apt/apt.conf.d/99legion-aide; rm -rf /etc/legion"
# Ubuntu's own AIDE timer goes back to how it was before Legion. Older Legion
# versions did not record that; then it is turned on only if Ubuntu's AIDE
# database exists, since the job fails without one. Skipped when AIDE is
# about to be uninstalled.
# shellcheck disable=SC2016 # expanded by the inner shell
undo "Ubuntu's own daily AIDE timer restored" bash -c '
  systemctl unmask dailyaidecheck.timer 2>/dev/null || true
  [ "$2" = 0 ] && dpkg -s aide-common >/dev/null 2>&1 || exit 0
  if [ -f "$1/dailyaidecheck-state" ]; then
    [ "$(cat "$1/dailyaidecheck-state")" != enabled ] || systemctl enable --now dailyaidecheck.timer
  elif [ -f /var/lib/aide/aide.db ]; then
    systemctl enable --now dailyaidecheck.timer
  fi' _ "$B" "$REMOVE_PACKAGES"
undo "ClamAV weekly scan removed" bash -c "$(declare -f unit_off); unit_off clamscan-home.timer clamscan-home.service"
undo "daily compliance check and the legion command removed" bash -c "$(declare -f unit_off); unit_off legion-check.timer legion-check.service; rm -f /usr/local/sbin/legion"
undo "Legion state removed (/var/lib/legion)" rm -rf /var/lib/legion
systemctl daemon-reload

section "System settings"
if command -v ufw >/dev/null; then
  # Delete only rules Legion added, by their exact labels (older versions used
  # "mDNS LAN" and "Steam LAN"). Rules that existed before are never touched.
  # shellcheck disable=SC2016 # expanded by the inner shell
  undo "firewall rules added by Legion deleted" bash -c '
    ufw show added 2>/dev/null | grep -E " comment '\''(Legion: [^'\'']*|mDNS LAN|Steam LAN)'\''$" |
      sed -E "s/^ufw //; s/ comment '\''.*'\''$//" | while read -r rule; do
        # shellcheck disable=SC2086 # the rule is a list of ufw words
        case "$rule" in
          "route "*) ufw --force route delete ${rule#route } >/dev/null ;;
          *) ufw --force delete $rule >/dev/null ;;
        esac
      done'
  if [ -e "$B/ufw-was-active" ]; then
    # shellcheck disable=SC2016 # expanded by the inner shell
    undo "firewall settings restored; it stays on, as it was before Legion" bash -c '
      [ ! -f "$1/ufw-default" ] || cp -p "$1/ufw-default" /etc/default/ufw
      [ ! -f "$1/ufw.conf" ] || cp -p "$1/ufw.conf" /etc/ufw/ufw.conf
      ufw --force enable >/dev/null' _ "$B"
  else
    # shellcheck disable=SC2016 # expanded by the inner shell
    undo "firewall settings restored and turned off, as it was before Legion" bash -c '
      [ ! -f "$1/ufw-default" ] || cp -p "$1/ufw-default" /etc/default/ufw
      ufw disable >/dev/null
      [ ! -f "$1/ufw.conf" ] || cp -p "$1/ufw.conf" /etc/ufw/ufw.conf' _ "$B"
  fi
fi
if [ -e "$B/20auto-upgrades" ]; then
  undo "automatic update settings restored" cp -p "$B/20auto-upgrades" /etc/apt/apt.conf.d/20auto-upgrades
elif [ -e "$B/20auto-upgrades.absent" ]; then
  undo "automatic update settings restored" rm -f /etc/apt/apt.conf.d/20auto-upgrades
fi
undo "audit rules removed" rm -f /etc/audit/rules.d/legion.rules /etc/audit/rules.d/soc2.rules
if [ -f "$B/auditd.conf" ]; then
  undo "audit settings restored" cp -p "$B/auditd.conf" /etc/audit/auditd.conf
elif [ -f /etc/audit/auditd.conf ]; then
  undo "audit log rotation back to Ubuntu default (5 files)" sed -i -E 's/^num_logs\s*=.*/num_logs = 5/' /etc/audit/auditd.conf
fi
if command -v augenrules >/dev/null && ! in_container; then
  undo "audit rules reloaded" augenrules --load
fi
undo "log retention back to Ubuntu default" bash -c 'rm -f /etc/systemd/journald.conf.d/legion.conf /etc/systemd/journald.conf.d/soc2.conf; systemctl restart systemd-journald'
undo "password policy back to Ubuntu default" rm -f /etc/security/pwquality.conf.d/legion.conf /etc/security/pwquality.conf.d/soc2.conf
if [ -f "$B/nm-ipv6" ] && command -v nmcli >/dev/null; then
  # shellcheck disable=SC2016 # expanded by the inner shell
  undo "IPv6 settings of network connections restored" bash -c '
    while read -r uuid method; do nmcli connection modify "$uuid" ipv6.method "$method" 2>/dev/null || true; done <"$1"' _ "$B/nm-ipv6"
fi
undo "kernel settings files removed" rm -f /etc/sysctl.d/60-legion-hardening.conf /etc/sysctl.d/60-soc2-hardening.conf /etc/sysctl.d/60-legion-ipv6.conf
if ! in_container; then
  if [ -f "$B/sysctl" ]; then
    # The values this machine had before Legion, saved on its first run.
    # shellcheck disable=SC2016 # expanded by the inner shell
    undo "kernel settings restored to their values before Legion" bash -c '
      sysctl -q --system
      while IFS="=" read -r k v; do [ -z "$v" ] || sysctl -q -w "$k=$v"; done <"$1"' _ "$B/sysctl"
  else
    # Older Legion versions did not save them: use Ubuntu 26.04's values.
    undo "kernel settings back to Ubuntu defaults" bash -c '
      sysctl -q -w kernel.kptr_restrict=1 fs.protected_fifos=1 net.core.bpf_jit_harden=0 \
        net.ipv4.conf.all.log_martians=0 net.ipv4.conf.default.log_martians=0 \
        net.ipv4.conf.all.send_redirects=1 net.ipv4.conf.default.send_redirects=1 \
        net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.default.disable_ipv6=0 && sysctl -q --system &&
        { systemctl try-restart apport.service 2>/dev/null || true; }'
  fi
fi
undo "network protocol blocks removed" rm -f /etc/modprobe.d/legion-uncommon-net.conf /etc/modprobe.d/soc2-uncommon-net.conf
# shellcheck disable=SC2016 # expanded by the inner shell
undo "cron and sudoers permissions back to Ubuntu defaults" bash -c '
  [ ! -f /etc/crontab ] || chmod 644 /etc/crontab
  for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /etc/cron.yearly; do [ ! -d "$d" ] || chmod 755 "$d"; done
  [ ! -d /etc/sudoers.d ] || chmod 755 /etc/sudoers.d'
if [ -f "$B/created-repos" ]; then
  # Third-party package sources Legion added for --with-tools.
  # shellcheck disable=SC2016 # expanded by the inner shell
  undo "package sources added by Legion removed" bash -c '
    while read -r list key; do rm -f "/etc/apt/sources.list.d/$list" "/usr/share/keyrings/$key"; done <"$1"
    for i in $(seq 30); do apt-get update -q >/dev/null 2>&1 && break; sleep 10; done' _ "$B/created-repos"
fi
rm -f /var/log/soc2-endpoint-report.txt

if [ "$REMOVE_PACKAGES" = 1 ]; then
  section "Packages"
  export DEBIAN_FRONTEND=noninteractive
  pkgs=()
  for p in auditd audispd-plugins clamav clamav-freshclam yara aide aide-common openscap-scanner ssg-debderived; do
    dpkg -s "$p" >/dev/null 2>&1 && pkgs+=("$p")
  done
  # Tools installed by --with-tools, as recorded at the time.
  if [ -f "$B/installed-tools" ]; then
    while read -r kind name; do
      if [ "$kind" = apt ] && dpkg -s "$name" >/dev/null 2>&1; then pkgs+=("$name")
      elif [ "$kind" = snap ]; then undo "removed snap: $name" snap remove "$name"; fi
    done <"$B/installed-tools"
  fi
  if [ "${#pkgs[@]}" -gt 0 ]; then
    undo "uninstalled: ${pkgs[*]}" apt-get -y -q -o DPkg::Lock::Timeout=300 purge "${pkgs[@]}"
    # No automatic "apt autoremove": it can also remove unrelated packages,
    # up to the desktop session. Review its list yourself if you want it.
    info "packages no longer needed are kept; review with: apt autoremove --dry-run"
    systemctl reset-failed >/dev/null 2>&1 || true
  else
    info "none of Legion's packages are installed"
  fi
fi

if [ "$DETACH_PRO" = 1 ]; then
  section "Ubuntu Pro"
  if command -v pro >/dev/null && pro status --format json 2>/dev/null | grep -q '"attached": *true'; then
    undo "detached from Ubuntu Pro" pro detach --assume-yes
  else
    info "not attached to Ubuntu Pro"
  fi
fi

if [ "$PURGE_LOGS" = 1 ]; then
  undo "Legion logs and reports deleted" rm -rf /var/log/legion /var/log/clamscan-home.log
else
  info "logs and reports kept in /var/log/legion (delete with --purge-logs)"
fi

section "Result"
if [ "$FAILED" = 0 ]; then
  ok "Legion Profile removed"
  info "reboot to make sure every kernel setting is back to normal"
else
  fail "$FAILED step(s) could not be undone; see the lines marked above"
  exit 1
fi

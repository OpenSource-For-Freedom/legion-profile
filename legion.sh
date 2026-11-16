#!/usr/bin/env bash
# Legion Profile: endpoint hardening for Ubuntu laptops and desktops.
#
# Hardens the device, adds YARA malware scanning and file integrity
# monitoring, and writes an evidence report for the endpoint controls SOC 2
# auditors ask about. It does not make anyone "SOC 2 compliant": SOC 2 audits
# an organisation, and this covers one device.
#
# SET UP DISK ENCRYPTION FIRST. Full-disk encryption can only be chosen when
# Ubuntu is installed (installer: "Advanced features" > "Use LVM and
# encryption"). It cannot be added later without wiping the disk. Encrypt the
# disk at install time, before the device is set up or handed to anyone.
#
# Usage:
#   bash legion.sh [options]       (asks for your sudo password)
#
# Options:
#   --allow-unencrypted  continue without disk encryption, no question asked
#   --steam              allow Steam Remote Play from the local network
#   --no-yara            skip the weekly YARA scan
#   --no-aide            skip the daily integrity check
#   --no-pro             don't ask for an Ubuntu Pro token
#   --pro-token-file F   read the Ubuntu Pro token from file F instead of asking
#   --with-tools         also install lynis, gitleaks, pre-commit, shellcheck,
#                        python3-venv, python3-pip, deja-dup, Bitwarden,
#                        Terraform and Trivy
#   --report-only        change nothing; only write the evidence report
#   -h, --help           show this help
#
# Set UBUNTU_PRO_SECRET to your Ubuntu Pro token to skip the token question.
# Set NO_COLOR=1 for plain output, LEGION_NO_ANIM=1 to skip the animation.
set -euo pipefail

# ---------------------------------------------------------------- output

exec 3>&1 # status lines always go to the terminal; step output goes to the log
UTF8=0
case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in *[Uu][Tt][Ff]-8* | *[Uu][Tt][Ff]8*) UTF8=1 ;; esac
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_OK=$'\e[32m' C_FAIL=$'\e[31m' C_INFO=$'\e[36m' C_WARN=$'\e[33m'
  C_BOLD=$'\e[1m' C_DIM=$'\e[2m' C_RST=$'\e[0m'
else
  C_OK="" C_FAIL="" C_INFO="" C_WARN="" C_BOLD="" C_DIM="" C_RST=""
fi
ANIM=0
[ -t 1 ] && [ -z "${LEGION_NO_ANIM:-}" ] && ANIM=1
if [ "$UTF8" = 1 ]; then
  I_OK="✔" I_FAIL="✖" I_INFO="ℹ" I_WARN="!" SPIN=(⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏)
else
  I_OK="ok" I_FAIL="FAIL" I_INFO="i" I_WARN="!" SPIN=('|' '/' '-' "\\")
fi
RUNLOG=/dev/null
CLR="" # clears a spinner line; only meaningful on a terminal
[ ! -t 1 ] || CLR=$'\r\e[K'

_say() { printf '%s  %s%s%s %s\n' "$CLR" "$1" "$2" "$C_RST" "$3" >&3; echo "[$4] $3" >>"$RUNLOG"; }
ok() { _say "$C_OK" "$I_OK" "$*" ok; }
fail() { _say "$C_FAIL" "$I_FAIL" "$*" fail; }
info() { _say "$C_INFO" "$I_INFO" "$*" info; }
warn() { _say "$C_WARN" "$I_WARN" "$*" warn; }
section() { printf '\n%s%s%s\n' "$C_BOLD" "$*" "$C_RST" >&3; }

banner() {
  local lines i grad=(51 45 39 33 27 21)
  if [ "$UTF8" = 1 ]; then
    lines=(
      "██╗     ███████╗ ██████╗ ██╗ ██████╗ ███╗   ██╗"
      "██║     ██╔════╝██╔════╝ ██║██╔═══██╗████╗  ██║"
      "██║     █████╗  ██║  ███╗██║██║   ██║██╔██╗ ██║"
      "██║     ██╔══╝  ██║   ██║██║██║   ██║██║╚██╗██║"
      "███████╗███████╗╚██████╔╝██║╚██████╔╝██║ ╚████║"
      "╚══════╝╚══════╝ ╚═════╝ ╚═╝ ╚═════╝ ╚═╝  ╚═══╝"
    )
  else
    lines=("L E G I O N")
  fi
  echo >&3
  for i in "${!lines[@]}"; do
    if [ -n "$C_RST" ]; then printf '  \e[38;5;%sm%s\e[0m\n' "${grad[i]}" "${lines[i]}" >&3
    else printf '  %s\n' "${lines[i]}" >&3; fi
    [ "$ANIM" = 0 ] || sleep 0.07
  done
  printf '  %sP R O F I L E   ·   endpoint hardening   ·   SOC 2 evidence%s\n\n' "$C_DIM" "$C_RST" >&3
  if [ "$ANIM" = 1 ]; then
    local w=40 p full empty fill="#" rest="."
    [ "$UTF8" = 0 ] || { fill="█"; rest="░"; }
    for ((p = 0; p <= w; p++)); do
      printf -v full '%*s' "$p" ''
      printf -v empty '%*s' "$((w - p))" ''
      printf '\r  %sdeploying%s %s%s%s%s %3d%%' "$C_DIM" "$C_RST" "$C_INFO" "${full// /$fill}" "${empty// /$rest}" "$C_RST" "$((p * 100 / w))" >&3
      sleep 0.015
    done
    printf '\r\e[K' >&3
  fi
}

# ---------------------------------------------------------------- options

usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; }

ALLOW_UNENCRYPTED=0 STEAM=0 TOOLS=0 YARA=1 AIDE=1 PRO=1 REPORT_ONLY=0 BANNER_SHOWN=0
PRO_TOKEN_FILE=""
ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --allow-unencrypted) ALLOW_UNENCRYPTED=1 ;;
    --steam) STEAM=1 ;;
    --with-tools) TOOLS=1 ;;
    --no-yara) YARA=0 ;;
    --no-aide) AIDE=0 ;;
    --no-pro) PRO=0 ;;
    --pro-token-file)
      [ $# -ge 2 ] && [ -f "$2" ] || { echo "--pro-token-file needs a path to a file" >&2; exit 2; }
      PRO_TOKEN_FILE="$(readlink -f "$2")"
      ARGS+=("$1" "$PRO_TOKEN_FILE"); shift 2; continue ;;
    --report-only) REPORT_ONLY=1 ;;
    --banner-shown) BANNER_SHOWN=1; shift; continue ;; # internal: set when re-run through sudo
    -h | --help) usage; exit 0 ;;
    *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
  ARGS+=("$1")
  shift
done

[ "$BANNER_SHOWN" = 1 ] || banner

if [ "$(id -u)" != 0 ]; then
  SELF="$(readlink -f "$0" 2>/dev/null || true)"
  [ -f "$SELF" ] || { fail "cannot find this script on disk; run it as: sudo bash legion.sh"; exit 2; }
  command -v sudo >/dev/null || { fail "sudo is not installed; run this as root"; exit 2; }
  info "administrator access needed, asking sudo"
  if [ -n "${UBUNTU_PRO_SECRET:-}" ]; then
    exec sudo --preserve-env=UBUNTU_PRO_SECRET bash "$SELF" --banner-shown "${ARGS[@]}"
  fi
  exec sudo bash "$SELF" --banner-shown "${ARGS[@]}"
fi

# ---------------------------------------------------------------- setup

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=l # needrestart: list services to restart, don't restart them
APT=(-y -q -o DPkg::Lock::Timeout=300 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)
LOGDIR=/var/log/legion
STATE=/var/lib/legion
REPORT="$LOGDIR/endpoint-report.txt"
install -d -m 750 "$LOGDIR"
install -d -m 700 "$STATE"
RUNLOG="$LOGDIR/run-$(date +%Y%m%d-%H%M%S).log"
: >"$RUNLOG"
chmod 640 "$RUNLOG"
FLAGS="$(mktemp -d)" # steps run in subshells and leave notes for the summary here
trap 'rm -rf "$FLAGS"' EXIT

osr() { sed -n "s/^$1=//p" /etc/os-release | tr -d '"'; }
OS_ID="$(osr ID)"
OS_VERSION="$(osr VERSION_ID)"
OS_CODENAME="$(osr VERSION_CODENAME)"
ARCH="$(uname -m)"
IN_CONTAINER=0
systemd-detect-virt --container -q 2>/dev/null && IN_CONTAINER=1

# True when / sits on a LUKS (dm-crypt) device or an encrypted ZFS dataset.
root_encrypted() {
  local src fstype types
  src="$(findmnt -no SOURCE /)" || return 1
  fstype="$(findmnt -no FSTYPE /)"
  if [ "$fstype" = zfs ]; then
    [ "$(zfs get -H -o value encryption "$src" 2>/dev/null)" != off ] && return 0
    return 1
  fi
  src="${src%%[*}" # btrfs shows /dev/x[/@]
  types="$(lsblk -nso TYPE "$src" 2>/dev/null)" || return 1
  grep -qx crypt <<<"$types"
}

# ---------------------------------------------------------------- preflight

section "System check"
info "run log: $RUNLOG"
if [ "$OS_ID" != ubuntu ]; then
  fail "operating system: ${OS_ID:-unknown}. Legion supports Ubuntu only"; exit 2
fi
case "$OS_VERSION" in
  24.04 | 26.04) ok "operating system: $(osr PRETTY_NAME)" ;;
  *) warn "operating system: $(osr PRETTY_NAME) (tested on 24.04 and 26.04; continuing)" ;;
esac
case "$ARCH" in
  x86_64 | aarch64) ok "architecture: $ARCH" ;;
  *) fail "architecture: $ARCH is not supported"; exit 2 ;;
esac
if [ -d /run/systemd/system ]; then ok "init system: systemd"; else fail "init system: systemd is not running"; exit 2; fi
if [ "$IN_CONTAINER" = 1 ]; then info "running in a container: kernel settings and audit rules are written but not loaded"; fi
if [ "$REPORT_ONLY" = 0 ]; then
  FREE_GB=$(($(df --output=avail -k / | tail -n 1) / 1024 / 1024))
  if [ "$FREE_GB" -ge 3 ]; then ok "free disk space: ${FREE_GB} GB"; else fail "free disk space: ${FREE_GB} GB (need 3 GB)"; exit 2; fi
  # curl is not installed on a fresh Ubuntu Desktop, so test with a plain TCP connection.
  if timeout 15 bash -c 'exec 9<>/dev/tcp/security.ubuntu.com/80' 2>/dev/null; then
    ok "network: Ubuntu archive reachable"
  else
    fail "network: cannot reach security.ubuntu.com"; exit 2
  fi
  if pgrep -x 'apt|apt-get|dpkg|unattended-upgr' >/dev/null 2>&1; then
    info "package manager busy (probably automatic updates); steps wait up to 5 minutes for it"
  fi
fi

ENCRYPTED=0
if root_encrypted; then
  ENCRYPTED=1
  ok "disk encryption: root filesystem is encrypted"
else
  fail "disk encryption: root filesystem is NOT encrypted"
  if [ "$REPORT_ONLY" = 0 ] && [ "$ALLOW_UNENCRYPTED" = 0 ]; then
    info "encryption can only be enabled by reinstalling Ubuntu with \"Use LVM and encryption\""
    if [ -t 0 ] && [ -t 1 ]; then
      printf '  %s?%s continue and record encryption as a gap? [y/N] ' "$C_WARN" "$C_RST" >&3
      read -r reply
      case "$reply" in [Yy]*) warn "continuing; the report records encryption as a gap" ;; *) info "stopped, nothing changed"; exit 3 ;; esac
    else
      info "stopped, nothing changed. Run with --allow-unencrypted to continue anyway"; exit 3
    fi
  fi
fi
if command -v mokutil >/dev/null && mokutil --sb-state 2>/dev/null | grep -q enabled; then
  ok "secure boot: enabled"
else
  info "secure boot: off or unknown"
fi

# Ubuntu Pro: security updates for every package (ESM) and Livepatch. The
# token comes from the Ubuntu One account that owns the subscription. It is
# read without echo, never written to the log, and never put on a command line.
PRO_TOKEN=""
pro_attached() { command -v pro >/dev/null && pro status --format json 2>/dev/null | grep -q '"attached": *true'; }
if [ "$REPORT_ONLY" = 0 ] && [ "$PRO" = 1 ]; then
  if pro_attached; then
    ok "Ubuntu Pro: already attached"
  elif [ -n "${UBUNTU_PRO_SECRET:-}" ]; then
    PRO_TOKEN="${UBUNTU_PRO_SECRET//[[:space:]]/}"
    ok "Ubuntu Pro: token taken from UBUNTU_PRO_SECRET"
  elif [ -n "$PRO_TOKEN_FILE" ]; then
    PRO_TOKEN="$(tr -d '[:space:]' <"$PRO_TOKEN_FILE")"
    if [ -n "$PRO_TOKEN" ]; then ok "Ubuntu Pro: token read from file"; else fail "Ubuntu Pro: token file is empty"; exit 2; fi
  elif [ -t 0 ] && [ -t 1 ]; then
    info "Ubuntu Pro adds security updates for every package (ESM) and Livepatch"
    info "free for up to 5 personal machines; get your token at https://ubuntu.com/pro/dashboard"
    printf '  %s?%s Ubuntu Pro token (hidden; press Enter to skip): ' "$C_WARN" "$C_RST" >&3
    read -rs PRO_TOKEN
    echo >&3
    PRO_TOKEN="${PRO_TOKEN//[[:space:]]/}"
    if [ -n "$PRO_TOKEN" ]; then ok "Ubuntu Pro: token received"; else info "Ubuntu Pro: skipped"; fi
  else
    info "Ubuntu Pro: skipped (no terminal to ask; use --pro-token-file)"
  fi
fi
unset UBUNTU_PRO_SECRET # no later command needs it in its environment
WITH_PRO=0
[ -z "$PRO_TOKEN" ] || WITH_PRO=1

# ---------------------------------------------------------------- helpers

# Installs each package this release provides; leaves the rest in MISSING.
install_available() {
  local p cand have=()
  MISSING=""
  for p in "$@"; do
    cand="$(apt-cache policy "$p" 2>/dev/null | awk '/Candidate:/ { print $2 }')"
    if [ -n "$cand" ] && [ "$cand" != "(none)" ]; then have+=("$p"); else MISSING="$MISSING $p"; fi
  done
  [ "${#have[@]}" -eq 0 ] || apt-get "${APT[@]}" install "${have[@]}"
}

# Adds a third-party apt repository whose signing key must match a pinned
# fingerprint, installs one package from it, and removes the repository again
# if anything fails, so a broken source never lingers for automatic updates.
add_signed_repo() {
  local list="$1" keyring="$2" key_url="$3" fpr="$4" source="$5" pkg="$6"
  local tmp gnupg
  command -v "$pkg" >/dev/null 2>&1 && return 0
  tmp="$(mktemp)"
  gnupg="$(mktemp -d)"
  if ! curl -fsSL "$key_url" | GNUPGHOME="$gnupg" gpg --dearmor >"$tmp"; then
    rm -rf "$tmp" "$gnupg"; warn "$pkg: could not download its signing key"; return 1
  fi
  if ! GNUPGHOME="$gnupg" gpg --show-keys --with-colons "$tmp" |
    awk -F: -v f="$fpr" '$1 == "fpr" && $10 == f { ok = 1 } END { exit !ok }'; then
    rm -rf "$tmp" "$gnupg"; warn "$pkg: signing key does not match $fpr, not installed"; return 1
  fi
  rm -rf "$gnupg"
  install -m 644 "$tmp" "/usr/share/keyrings/$keyring"
  rm -f "$tmp"
  echo "deb [signed-by=/usr/share/keyrings/$keyring] $source" >"/etc/apt/sources.list.d/$list"
  if apt-get update -q && apt-get "${APT[@]}" install "$pkg"; then return 0; fi
  warn "$pkg: install failed; removing its repository again"
  rm -f "/etc/apt/sources.list.d/$list" "/usr/share/keyrings/$keyring"
  apt-get update -q || true
  return 1
}

STEP=0
TOTAL=$((8 + WITH_PRO + YARA + AIDE + TOOLS))
RESULTS=()
FAILED=0

# Runs one step in a subshell with its output in the run log, showing a
# spinner meanwhile. A failed step is reported and the next one still runs.
run_step() {
  local title="$1" fn="$2" pid rc start i=0 el
  STEP=$((STEP + 1))
  echo "=== [$STEP/$TOTAL] $title" >>"$RUNLOG"
  start=$SECONDS
  set +e
  (set -euo pipefail; "$fn") >>"$RUNLOG" 2>&1 &
  pid=$!
  if [ -t 1 ]; then
    while kill -0 "$pid" 2>/dev/null; do
      el=$((SECONDS - start))
      printf '\r\e[K  %s%s%s [%d/%d] %s %s%d:%02d%s' "$C_INFO" "${SPIN[i++ % ${#SPIN[@]}]}" "$C_RST" \
        "$STEP" "$TOTAL" "$title" "$C_DIM" $((el / 60)) $((el % 60)) "$C_RST" >&3
      sleep 0.12
    done
  fi
  wait "$pid"
  rc=$?
  set -e
  el=$((SECONDS - start))
  if [ "$rc" = 0 ]; then
    ok "[$STEP/$TOTAL] $title ${C_DIM}$((el / 60)):$(printf %02d $((el % 60)))${C_RST}"
    RESULTS+=("ok|$title")
  else
    local last
    last="$(tail -n 8 "$RUNLOG")"
    fail "[$STEP/$TOTAL] $title (exit $rc). Last lines of the log:"
    printf '%s\n' "$last" | sed 's/^/        /' >&3
    RESULTS+=("fail|$title")
    FAILED=$((FAILED + 1))
  fi
}

# ---------------------------------------------------------------- steps

step_patching() {
  # This script used to be called soc2-harden.sh and used soc2-* file names.
  rm -f /etc/audit/rules.d/soc2.rules /etc/systemd/journald.conf.d/soc2.conf \
    /etc/security/pwquality.conf.d/soc2.conf /etc/sysctl.d/60-soc2-hardening.conf \
    /etc/modprobe.d/soc2-uncommon-net.conf /var/log/soc2-endpoint-report.txt
  apt-get update -q -o DPkg::Lock::Timeout=300
  apt-get "${APT[@]}" full-upgrade
  apt-get "${APT[@]}" install curl gpg ca-certificates iproute2 needrestart
  apt-get "${APT[@]}" autoremove
  # Remove config files left behind by packages that were removed earlier.
  local rc_pkgs
  rc_pkgs="$(dpkg -l | awk '/^rc/ { print $2 }')"
  [ -z "$rc_pkgs" ] || echo "$rc_pkgs" | xargs dpkg --purge
  # A kernel update must come with the NVIDIA module for that kernel, or the
  # GPU has no driver after the reboot.
  if lsmod 2>/dev/null | awk '$1 == "nvidia" { f = 1 } END { exit !f }'; then
    local newest
    # Only version-named folders: some systems also have e.g. /lib/modules/kernel.
    newest="$(find /lib/modules -mindepth 1 -maxdepth 1 -type d -name '[0-9]*' -printf '%f\n' 2>/dev/null | sort -V | tail -n 1 || true)"
    if [ -z "$newest" ]; then
      info "NVIDIA driver loaded, but no kernels under /lib/modules to check"
    elif modinfo -k "$newest" nvidia >/dev/null 2>&1; then
      info "NVIDIA driver present for kernel $newest"
    else
      echo "No NVIDIA driver for kernel $newest. Before rebooting run: sudo ubuntu-drivers install, then run Legion again." >"$FLAGS/nvidia"
      warn "no NVIDIA driver for the new kernel $newest"
    fi
  fi
}

step_pro() {
  if ! command -v pro >/dev/null; then
    apt-get update -q -o DPkg::Lock::Timeout=300
    apt-get "${APT[@]}" install ubuntu-pro-client
  fi
  # Same as `pro attach TOKEN` with Pro's default services (ESM and, where
  # the kernel supports it, Livepatch). The token goes through a private file
  # because command-line arguments are visible to every user in `ps`.
  local cfg="$FLAGS/pro-attach.yaml"
  (umask 077 && printf 'token: %s\n' "$PRO_TOKEN" >"$cfg")
  pro attach --attach-config "$cfg"
  rm -f "$cfg"
  apt-get update -q -o DPkg::Lock::Timeout=300
  info "$(pro status 2>/dev/null | awk '$2 == "yes" && $3 == "enabled" { s = s " " $1 } END { print "enabled:" s }')"
}

step_auto_updates() {
  apt-get "${APT[@]}" install unattended-upgrades
  cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
}

step_firewall() {
  apt-get "${APT[@]}" install ufw
  # The LAN is the subnet of the interface that carries the default route, so
  # a VPN, Docker or VM bridge is never picked up by mistake.
  local iface lan=""
  iface="$(ip -4 route show default | awk '{ for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit } }')"
  [ -z "$iface" ] || lan="$(ip -4 route show dev "$iface" scope link proto kernel | awk '{ print $1; exit }')"
  ufw default deny incoming
  ufw default allow outgoing
  ufw logging low
  if [ -n "$lan" ]; then
    info "local network: $lan on $iface"
    ufw allow from "$lan" to any port 5353 proto udp comment 'mDNS LAN'
    if [ "$STEAM" = 1 ]; then
      ufw allow from "$lan" to any port 27031:27036 proto udp comment 'Steam LAN'
      ufw allow from "$lan" to any port 27036:27037 proto tcp comment 'Steam LAN'
    fi
  else
    warn "no default route found; no local network exceptions added"
  fi
  ufw --force enable
}

step_audit() {
  apt-get "${APT[@]}" install auditd audispd-plugins
  local b32=""
  # 32-bit system call rules only apply on x86_64.
  if [ "$ARCH" = x86_64 ]; then
    b32="-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime,stime -k time
-a always,exit -F arch=b32 -S init_module,finit_module,delete_module -k modules"
  fi
  cat >/etc/audit/rules.d/legion.rules <<EOF
# Identity and privilege changes
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k privilege
-w /etc/sudoers.d/ -p wa -k privilege
# Authentication and session records
-w /var/log/auth.log -p wa -k auth
-w /var/log/faillog -p wa -k auth
-w /var/log/lastlog -p wa -k logins
# Privilege escalation
-w /usr/bin/sudo -p x -k privilege
-w /usr/bin/su -p x -k privilege
# Time changes and kernel modules
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules
$b32
-w /etc/localtime -p wa -k time
-w /sbin/insmod -p x -k modules
-w /sbin/modprobe -p x -k modules
# Firewall and audit config itself
-w /etc/ufw/ -p wa -k firewall
-w /etc/audit/ -p wa -k audit-config
EOF
  # Rotate, never fill the disk: 20 files of max_log_file MB each are kept.
  sed -i -E 's/^#?\s*max_log_file_action\s*=.*/max_log_file_action = ROTATE/' /etc/audit/auditd.conf
  sed -i -E 's/^#?\s*num_logs\s*=.*/num_logs = 20/' /etc/audit/auditd.conf
  if [ "$IN_CONTAINER" = 1 ]; then
    systemctl enable auditd # the kernel audit system belongs to the host
  else
    augenrules --load
    systemctl enable --now auditd
    info "$(auditctl -l | grep -c .) audit rules loaded"
  fi
}

step_logs() {
  mkdir -p /etc/systemd/journald.conf.d
  cat >/etc/systemd/journald.conf.d/legion.conf <<'EOF'
[Journal]
Storage=persistent
SystemMaxUse=2G
MaxRetentionSec=1year
EOF
  systemctl restart systemd-journald
}

step_clamav() {
  apt-get "${APT[@]}" install clamav clamav-freshclam
  systemctl enable --now clamav-freshclam
  # clamscan exits 1 when it finds malware. That stays a failure on purpose,
  # so a detection shows up in `systemctl --failed`.
  cat >/etc/systemd/system/clamscan-home.service <<'EOF'
[Unit]
Description=Weekly ClamAV scan of /home
[Service]
Type=oneshot
Nice=19
IOSchedulingClass=idle
ExecStart=/usr/bin/clamscan -r -i --exclude-dir=node_modules --exclude-dir=[.]cache --exclude-dir=steamapps --log=/var/log/clamscan-home.log /home
EOF
  cat >/etc/systemd/system/clamscan-home.timer <<'EOF'
[Unit]
Description=Weekly ClamAV scan of /home
[Timer]
OnCalendar=Sun 03:00
Persistent=true
[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now clamscan-home.timer
}

step_passwords() {
  apt-get "${APT[@]}" install libpam-pwquality
  mkdir -p /etc/security/pwquality.conf.d
  cat >/etc/security/pwquality.conf.d/legion.conf <<'EOF'
minlen = 12
minclass = 3
maxrepeat = 3
dictcheck = 1
enforce_for_root
EOF
}

step_hardening() {
  # Low-risk subset of the Lynis/CIS kernel checks. Left alone on purpose:
  # ip_forward (Docker and VMs need it), rp_filter (VPNs), sysrq,
  # modules_disabled and unprivileged_bpf_disabled (Ubuntu's default is fine).
  cat >/etc/sysctl.d/60-legion-hardening.conf <<'EOF'
kernel.kptr_restrict = 2
fs.suid_dumpable = 0
fs.protected_fifos = 2
net.core.bpf_jit_harden = 2
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
EOF
  if [ "$IN_CONTAINER" = 0 ]; then
    sysctl -q -p /etc/sysctl.d/60-legion-hardening.conf || warn "some kernel settings apply only after a reboot"
  fi
  # Network protocols a laptop never uses; each has had kernel vulnerabilities.
  cat >/etc/modprobe.d/legion-uncommon-net.conf <<'EOF'
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
EOF
  [ ! -f /etc/crontab ] || chmod 600 /etc/crontab
  local d
  for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    [ ! -d "$d" ] || chmod 700 "$d"
  done
  [ ! -d /etc/sudoers.d ] || chmod 750 /etc/sudoers.d
}

step_yara() {
  # ClamAV finds common malware. YARA adds rules for attacker tooling, web
  # shells and stealers, and covers the folders malware is usually dropped in.
  apt-get "${APT[@]}" install yara unzip
  install -d -m 700 "$STATE/yara"
  cat >/usr/local/sbin/legion-yara-update <<'EOF'
#!/usr/bin/env bash
# Downloads the latest YARA Forge "core" rules (tuned for few false alarms),
# compiles them, and swaps them in only if they compile. On any failure the
# previous rules stay in place.
set -euo pipefail
DIR=/var/lib/legion/yara
URL=https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -fsSL --retry 3 -o "$tmp/rules.zip" "$URL"
unzip -q "$tmp/rules.zip" -d "$tmp"
src="$(find "$tmp" -name 'yara-rules-core.yar' -print -quit)"
[ -n "$src" ] || { echo "no yara-rules-core.yar in the download" >&2; exit 1; }
n="$(grep -c '^rule ' "$src")"
[ "$n" -ge 1000 ] || { echo "only $n rules in the download; keeping the current rules" >&2; exit 1; }
yarac -w "$src" "$tmp/rules.yarc"
install -m 600 "$tmp/rules.yarc" "$DIR/rules.yarc.new"
mv -f "$DIR/rules.yarc.new" "$DIR/rules.yarc"
echo "$(date -u +%FT%TZ) YARA Forge core, $n rules" >"$DIR/VERSION"
cat "$DIR/VERSION"
EOF
  cat >/usr/local/sbin/legion-yara-scan <<'EOF'
#!/usr/bin/env bash
# Scans user-writable folders with the compiled rules. Exits 1 when a rule
# matches, so the systemd unit shows as failed; exits 2 if the scan can't run.
set -uo pipefail
RULES=/var/lib/legion/yara/rules.yarc
LOG=/var/log/legion/yara-scan.log
[ -s "$RULES" ] || { echo "no compiled rules at $RULES; run legion-yara-update" >&2; exit 2; }
list="$(mktemp)" out="$(mktemp)" err="$(mktemp)"
trap 'rm -f "$list" "$out" "$err"' EXIT
# Skip dependency trees, caches, game libraries and git object stores: large,
# low-risk, and git objects are compressed so rules cannot read them anyway.
find /home /root /tmp /var/tmp /dev/shm -xdev \
  \( -name node_modules -o -name .cache -o -name steamapps -o -name .git \) -prune \
  -o -type f -size -64M -print >"$list" 2>/dev/null
yara -C -w -N -p 2 --scan-list "$RULES" "$list" >"$out" 2>"$err"
rc=$?
{
  echo "== $(date -u +%FT%TZ) $(wc -l <"$list") files, rules: $(cat /var/lib/legion/yara/VERSION 2>/dev/null || echo unknown)"
  echo "$(grep -c 'could not open file' "$err") files changed or vanished during the scan (skipped)"
  if [ -s "$out" ]; then cat "$out"; else echo "no matches"; fi
} >>"$LOG"
[ "$rc" = 0 ] || { echo "yara failed (exit $rc):" >&2; grep -v 'could not open file' "$err" >&2; exit 2; }
if [ -s "$out" ]; then cat "$out"; exit 1; fi
EOF
  chmod 750 /usr/local/sbin/legion-yara-update /usr/local/sbin/legion-yara-scan
  cat >/etc/systemd/system/legion-yara-scan.service <<'EOF'
[Unit]
Description=Weekly YARA scan of user-writable folders
Wants=network-online.target
After=network-online.target
[Service]
Type=oneshot
Nice=19
IOSchedulingClass=idle
# A failed rule update keeps the previous rules; the scan still runs.
ExecStartPre=-/usr/local/sbin/legion-yara-update
ExecStart=/usr/local/sbin/legion-yara-scan
EOF
  cat >/etc/systemd/system/legion-yara-scan.timer <<'EOF'
[Unit]
Description=Weekly YARA scan of user-writable folders
[Timer]
OnCalendar=Sun 04:00
Persistent=true
[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  if /usr/local/sbin/legion-yara-update; then
    info "rules: $(cut -d' ' -f2- "$STATE/yara/VERSION")"
  else
    warn "YARA rules could not be downloaded now; the weekly scan retries first"
  fi
  systemctl enable --now legion-yara-scan.timer
}

step_integrity() {
  # Two checks with no overlap:
  # - dpkg --verify compares every file a package installed with the package's
  #   own checksum. It needs no baseline, so updates never trigger it.
  # - AIDE covers what no package owns: /etc, /boot, /usr/local, /root and
  #   cron. Its baseline is refreshed after every apt run, and the changes that
  #   run made are logged first.
  # Ubuntu's own daily AIDE job, which scans the whole system, is turned off so
  # nothing is scanned twice. auditd still records who changed key files.
  apt-get "${APT[@]}" install aide
  systemctl mask dailyaidecheck.timer >/dev/null 2>&1 || true
  install -d -m 700 "$STATE/aide"
  install -d -m 755 /etc/legion
  cat >/etc/legion/aide.conf <<'EOF'
# Legion Profile AIDE scope: files no package owns. Package files are checked
# by dpkg --verify instead.
database_in=file:/var/lib/legion/aide/aide.db
database_out=file:/var/lib/legion/aide/aide.db.new
database_new=file:/var/lib/legion/aide/aide.db.new
gzip_dbout=yes
report_summarize_changes=yes
report_grouped=yes

Legion = p+u+g+s+ftype+sha512+acl+xattrs

/etc Legion
/boot Legion
/usr/local Legion
/root Legion
/var/spool/cron Legion

# Change in normal use
!/etc/mtab$
!/etc/adjtime$
!/etc/ld\.so\.cache$
!/etc/\.pwd\.lock$
!/etc/cups/subscriptions\.conf
!/etc/cups/.*\.O$
!/etc/NetworkManager/system-connections
!/boot/grub/grubenv$
!/root/\.cache
!/root/snap
EOF
  cat >/usr/local/sbin/legion-aide-baseline <<'EOF'
#!/usr/bin/env bash
# Records the current state as the AIDE baseline. Called by the installer and
# after every apt run; logs what changed since the previous baseline.
set -uo pipefail
CONF=/etc/legion/aide.conf
DB=/var/lib/legion/aide/aide.db
LOG=/var/log/legion/integrity.log
why="${1:-manual}"
if [ -f "$DB" ]; then
  out="$(aide --config="$CONF" --update 2>&1)"
  rc=$?
  [ "$rc" -lt 14 ] || { echo "$out" >&2; exit 2; }
  if [ "$rc" != 0 ]; then
    { echo "== $(date -u +%FT%TZ) baseline refreshed ($why); these changes were accepted:"; echo "$out"; } >>"$LOG"
  fi
else
  out="$(aide --config="$CONF" --init 2>&1)" || { echo "$out" >&2; exit 2; }
  echo "== $(date -u +%FT%TZ) baseline created ($why)" >>"$LOG"
fi
mv -f "$DB.new" "$DB"
EOF
  cat >/usr/local/sbin/legion-integrity-check <<'EOF'
#!/usr/bin/env bash
# Daily integrity check. Exits 1 when a package file or an AIDE-watched file
# changed, so the systemd unit shows as failed; exits 2 if a check can't run.
set -uo pipefail
LOG=/var/log/legion/integrity.log
status=0
# Package files. Ignored: config files (AIDE covers /etc) and missing docs,
# which many installs leave out on purpose.
pkg="$(dpkg --verify 2>&1 | awk '$2 != "c"' |
  grep -vE '^missing +(c +)?/usr/share/(doc|man|info|locale|lintian|help)/' || true)"
aide_out="$(aide --config=/etc/legion/aide.conf --check 2>&1)"
aide_rc=$?
{
  echo "== $(date -u +%FT%TZ) integrity check"
  if [ -n "$pkg" ]; then echo "package files that do not match their package:"; echo "$pkg"; else echo "package files: all match"; fi
  if [ "$aide_rc" = 0 ]; then echo "AIDE: no changes"; else echo "$aide_out"; fi
} >>"$LOG"
[ -z "$pkg" ] || { echo "$pkg"; status=1; }
if [ "$aide_rc" -ge 14 ]; then echo "$aide_out" >&2; exit 2; fi
[ "$aide_rc" = 0 ] || { echo "$aide_out"; status=1; }
exit "$status"
EOF
  chmod 750 /usr/local/sbin/legion-aide-baseline /usr/local/sbin/legion-integrity-check
  # Refresh the AIDE baseline after every package change, logging the changes.
  cat >/etc/apt/apt.conf.d/99legion-aide <<'EOF'
DPkg::Post-Invoke { "if [ -x /usr/local/sbin/legion-aide-baseline ] && [ -f /var/lib/legion/aide/aide.db ]; then /usr/local/sbin/legion-aide-baseline apt || true; fi"; };
EOF
  cat >/etc/systemd/system/legion-integrity.service <<'EOF'
[Unit]
Description=Daily integrity check (package checksums and AIDE)
[Service]
Type=oneshot
Nice=19
IOSchedulingClass=idle
ExecStart=/usr/local/sbin/legion-integrity-check
EOF
  cat >/etc/systemd/system/legion-integrity.timer <<'EOF'
[Unit]
Description=Daily integrity check (package checksums and AIDE)
[Timer]
OnCalendar=*-*-* 02:30
RandomizedDelaySec=30m
Persistent=true
[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  /usr/local/sbin/legion-aide-baseline install
  systemctl enable --now legion-integrity.timer
  info "AIDE baseline recorded"
}

step_tools() {
  local missing_all=""
  install_available lynis gitleaks pre-commit shellcheck python3-venv python3-pip deja-dup
  missing_all="$MISSING"
  if command -v snap >/dev/null 2>&1; then
    snap list bitwarden >/dev/null 2>&1 || snap install bitwarden || missing_all="$missing_all bitwarden"
  else
    missing_all="$missing_all bitwarden(no snap)"
  fi
  # HashiCorp's Linux package signing key, as published at
  # https://www.hashicorp.com/trust/security (checked 2026-11-15).
  add_signed_repo hashicorp.list hashicorp-archive-keyring.gpg \
    https://apt.releases.hashicorp.com/gpg \
    D55C0D1AC78A8D8126CB631CFC9CA96ACA026560 \
    "https://apt.releases.hashicorp.com $OS_CODENAME main" terraform ||
    missing_all="$missing_all terraform"
  # Aqua Security does not publish a fingerprint for this key. This is the key
  # served on 2026-11-15, identical to the keyserver.ubuntu.com copy.
  add_signed_repo trivy.list trivy.gpg \
    https://aquasecurity.github.io/trivy-repo/deb/public.key \
    825AD9036F7C850E6A6FED4935B8ACA44FD9CA9F \
    "https://aquasecurity.github.io/trivy-repo/deb generic main" trivy ||
    missing_all="$missing_all trivy"
  [ -z "$missing_all" ] || warn "not installed:$missing_all"
}

if [ "$REPORT_ONLY" = 0 ]; then
  section "Deploying profile"
  [ "$WITH_PRO" = 0 ] || run_step "Ubuntu Pro: ESM security updates and Livepatch" step_pro
  run_step "Patching: install all pending updates" step_patching
  run_step "Automatic security updates" step_auto_updates
  run_step "Firewall: block inbound, allow outbound" step_firewall
  run_step "Audit logging (auditd)" step_audit
  run_step "Log retention: 1 year, capped at 2 GB" step_logs
  run_step "Malware protection: ClamAV, weekly scan of /home" step_clamav
  run_step "Password policy: 12+ characters, 3 types" step_passwords
  run_step "System hardening: kernel, protocols, permissions" step_hardening
  [ "$YARA" = 0 ] || run_step "YARA: weekly scan of user-writable folders" step_yara
  [ "$AIDE" = 0 ] || run_step "Integrity: package checksums and AIDE, daily" step_integrity
  [ "$TOOLS" = 0 ] || run_step "Tools: audit, secrets, backups, Terraform, Trivy" step_tools
fi

# ---------------------------------------------------------------- report

section "Evidence report"
set +e
{
  echo "Legion Profile endpoint evidence, $(hostname), $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo; echo "-- OS"; osr PRETTY_NAME; uname -r
  echo; echo "-- disk encryption"
  if [ "$ENCRYPTED" = 1 ]; then echo "root filesystem encrypted: yes"; else echo "root filesystem encrypted: NO (gap: reinstall with encryption)"; fi
  lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINTS | grep -E 'crypt|/$'
  echo; echo "-- pending updates"; apt list --upgradable 2>/dev/null | grep -c upgradable
  echo; echo "-- reboot required"; if [ -f /var/run/reboot-required ]; then echo yes; else echo no; fi
  echo; echo "-- auto updates"; cat /etc/apt/apt.conf.d/20auto-upgrades
  echo; echo "-- ubuntu pro"; pro status 2>/dev/null || echo "pro client not installed"
  echo; echo "-- firewall"; ufw status verbose
  echo; echo "-- secure boot"; mokutil --sb-state
  echo; echo "-- apparmor"; if aa-enabled -q 2>/dev/null; then echo enabled; else echo disabled; fi
  echo; echo "-- auditd"; systemctl is-active auditd; echo "$(auditctl -l 2>/dev/null | grep -c .) rules loaded"
  echo; echo "-- journald"; cat /etc/systemd/journald.conf.d/legion.conf
  echo; echo "-- clamav"; systemctl is-active clamav-freshclam; systemctl is-enabled clamscan-home.timer
  echo; echo "-- yara"; systemctl is-enabled legion-yara-scan.timer; cat "$STATE/yara/VERSION"
  echo; echo "-- integrity monitoring"; systemctl is-enabled legion-integrity.timer
  echo "AIDE baseline $(date -r "$STATE/aide/aide.db" +%F 2>/dev/null || echo missing)"
  echo; echo "-- password policy"; cat /etc/security/pwquality.conf.d/legion.conf
  echo; echo "-- kernel hardening"; sysctl kernel.kptr_restrict fs.suid_dumpable fs.protected_fifos net.ipv4.conf.all.send_redirects
  echo; echo "-- time sync"; timedatectl show -p NTPSynchronized
  echo; echo "-- user accounts (uid >= 1000)"; awk -F: '$3 >= 1000 && $3 < 65534 { print $1, "uid=" $3, $7 }' /etc/passwd
  echo; echo "-- sudo group"; getent group sudo
  if [ -n "${SUDO_USER:-}" ] && command -v gsettings >/dev/null; then
    echo; echo "-- screen lock ($SUDO_USER)"
    for k in "org.gnome.desktop.screensaver lock-enabled" "org.gnome.desktop.session idle-delay"; do
      # shellcheck disable=SC2086 # $k is a schema and a key
      printf '%s = %s\n' "$k" "$(sudo -u "$SUDO_USER" gsettings get $k 2>/dev/null || echo unknown)"
    done
  fi
  echo; echo "-- listening (non-loopback)"; ss -tulnH | awk '$5 !~ /^(127\.|\[::1\]|127\.0\.0\.53)/ { print $1, $5 }'
} >"$REPORT" 2>&1
chmod 640 "$REPORT"

# Live checks for the terminal summary: one line per control.
check() { # label, command...
  local label="$1"; shift
  if "$@" >/dev/null 2>&1; then ok "$label"; else fail "$label"; fi
}
if [ "$ENCRYPTED" = 1 ]; then ok "disk encryption"; else fail "disk encryption (reinstall needed)"; fi
check "firewall active" bash -c 'ufw status | grep -q "Status: active"'
check "automatic security updates" test -f /etc/apt/apt.conf.d/20auto-upgrades
if pro_attached; then ok "Ubuntu Pro attached (ESM security updates)"; else info "Ubuntu Pro not attached"; fi
if [ "$IN_CONTAINER" = 1 ]; then info "audit rules: not loaded inside a container"
else check "audit logging running" systemctl is-active auditd; fi
check "log retention configured" test -f /etc/systemd/journald.conf.d/legion.conf
check "ClamAV weekly scan scheduled" systemctl is-enabled clamscan-home.timer
check "password policy" test -f /etc/security/pwquality.conf.d/legion.conf
if [ -f /etc/systemd/system/legion-yara-scan.timer ]; then
  check "YARA weekly scan scheduled, rules ready" bash -c "systemctl is-enabled legion-yara-scan.timer && test -s $STATE/yara/rules.yarc"
else info "YARA scan not enabled"; fi
if [ -f /etc/systemd/system/legion-integrity.timer ]; then
  check "integrity check scheduled, AIDE baseline ready" bash -c "systemctl is-enabled legion-integrity.timer && test -f $STATE/aide/aide.db"
else info "integrity check not enabled"; fi
set -e
info "full report: $REPORT"
info "run log: $RUNLOG"

[ "$REPORT_ONLY" = 1 ] && exit 0

section "Result"
if [ "$FAILED" = 0 ]; then
  ok "all $STEP steps completed"
else
  fail "$FAILED of $STEP steps failed. See the run log for details"
fi
[ "$ENCRYPTED" = 1 ] || warn "disk not encrypted. Reinstall with full-disk encryption before this device holds company data"
if [ -f "$FLAGS/nvidia" ]; then
  fail "NOT READY TO REBOOT: $(cat "$FLAGS/nvidia")"
  exit 1
fi
info "reboot now to finish the kernel and library updates"
[ "$FAILED" = 0 ] || exit 1

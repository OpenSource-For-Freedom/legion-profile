#!/usr/bin/env bash
# Legion Profile: endpoint hardening and compliance evidence for Ubuntu 26.04
# laptops and desktops.
#
# Hardens the device, adds YARA malware scanning, file integrity monitoring
# and account lockout, and writes a compliance report that maps every check to
# SOC 2, HIPAA, NIST 800-53 (FedRAMP) and NIST 800-171 (CMMC Level 2) controls.
# No script makes an organization compliant: these frameworks also cover
# policies, people and processes. Legion covers one device and proves it.
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
#   --no-sigma           skip threat detection (Sigma rules on the audit log)
#   --no-pro             don't ask for an Ubuntu Pro token
#   --pro-token-file F   read the Ubuntu Pro token from file F instead of asking
#   --with-tools         also install lynis, gitleaks, pre-commit, shellcheck,
#                        python3-venv, python3-pip, deja-dup, Bitwarden,
#                        Terraform and Trivy
#   --tailscale          allow incoming traffic over Tailscale (tailscale0)
#   --allow-from CIDRS   allow incoming traffic from these private networks,
#                        comma separated, e.g. 10.8.0.0/24,192.168.50.0/24
#   --no-ipv6            turn IPv6 off (only if nothing on this device needs it)
#   --ssh / --no-ssh     keep SSH reachable (rate-limited), or not; by default
#                        Legion asks when an SSH server is running
#   --no-lockout         skip the account lockout (5 failed logins lock an
#                        account for 30 minutes, then it unlocks by itself)
#   --forward-logs URL   send a copy of system and audit logs to a log server
#                        (SIEM): syslog+tls://HOST:PORT (encrypted, the
#                        server certificate is checked) or syslog://HOST:PORT
#   --no-forward-logs    keep logs on this device only (stops forwarding)
#   --lock-audit         lock the audit rules until the next restart, so not
#                        even an administrator can turn auditing off unseen
#   --no-lock-audit      don't lock them (the default)
#   --check              change nothing; check the device against the profile,
#                        write the reports, exit 1 if any check fails
#   --report-only        like --check, but always exit 0
#   -h, --help           show this help
#
# After the first run Legion installs itself as `legion`, so later checks are
# just: sudo legion --check
#
# Without these options Legion asks about Tailscale, private networks, IPv6,
# log forwarding and locking the audit rules.
# Set UBUNTU_PRO_SECRET to your Ubuntu Pro token to skip the token question.
# Set NO_COLOR=1 for plain output, LEGION_NO_ANIM=1 to skip the animation.
set -euo pipefail

# ---------------------------------------------------------------- output

exec 3>&1 # status lines always go to the terminal; step output goes to the log
UTF8=0
case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in *[Uu][Tt][Ff]-8* | *[Uu][Tt][Ff]8*) UTF8=1 ;; esac
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-}" != dumb ]; then
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
# Tools such as ufw translate their output; Legion parses it, so everything
# runs in a fixed English locale. (UTF-8 support was detected above.)
export LC_ALL=C.UTF-8 LANGUAGE=
RUNLOG=/dev/null
CLR="" # clears a spinner line; only meaningful on a terminal
[ ! -t 1 ] || CLR=$'\r\e[K'

_say() { printf '%s  %s%s%s %s\n' "$CLR" "$1" "$2" "$C_RST" "$3" >&3; echo "[$4] $3" >>"$RUNLOG"; }
ok() { _say "$C_OK" "$I_OK" "$*" ok; }
fail() { _say "$C_FAIL" "$I_FAIL" "$*" fail; }
info() { _say "$C_INFO" "$I_INFO" "$*" info; }
warn() { _say "$C_WARN" "$I_WARN" "$*" warn; }
section() { printf '\n%s%s%s\n' "$C_BOLD" "$*" "$C_RST" >&3; }

# Ubuntu logo (Circle of Friends on an orange disc), 26 x 26 pixels:
# . empty, o orange, w white. Two pixel rows make one line of half blocks.
LOGO_PX=(
  .........oooooooo.........
  .......oooooooooooo.......
  .....oooooooooooooooo.....
  ....oooooooooooowwwooo....
  ...oooooooooooowwwwwooo...
  ..ooooooooooooowwwwwoooo..
  ..oooooooooooooowwwwoooo..
  .ooooooooowwwwooooooooooo.
  .oooooooowwwwwooooooooooo.
  oooooooowwwwwwooowoooooooo
  ooooooowwwwooooowwwooooooo
  oowwwwooowoooooowwwooooooo
  oowwwwoooooooooowwwooooooo
  oowwwwoooooooooowwwooooooo
  oowwwwooowoooooowwwooooooo
  ooooooowwwwooooowwwooooooo
  oooooooowwwwwwooowoooooooo
  .oooooooowwwwwooooooooooo.
  .ooooooooowwwwooooooooooo.
  ..oooooooooooooowwwwoooo..
  ..ooooooooooooowwwwwoooo..
  ...oooooooooooowwwwwooo...
  ....oooooooooooowwwooo....
  .....oooooooooooooooo.....
  .......oooooooooooo.......
  .........oooooooo.........
)

# Turns LOGO_PX into 13 colored lines of half-block characters in LOGO_LINES.
logo_lines() {
  local fo fw bo bw r c t b top bot line z=$'\e[0m'
  if [[ "${COLORTERM:-}" == *truecolor* || "${COLORTERM:-}" == *24bit* ]]; then
    fo=$'\e[38;2;233;84;32m' fw=$'\e[38;2;255;255;255m' bo=$'\e[48;2;233;84;32m' bw=$'\e[48;2;255;255;255m'
  else
    fo=$'\e[38;5;202m' fw=$'\e[38;5;231m' bo=$'\e[48;5;202m' bw=$'\e[48;5;231m'
  fi
  LOGO_LINES=()
  for ((r = 0; r < ${#LOGO_PX[@]}; r += 2)); do
    top="${LOGO_PX[r]}" bot="${LOGO_PX[r + 1]}" line=""
    for ((c = 0; c < ${#top}; c++)); do
      t="${top:c:1}" b="${bot:c:1}"
      case "$t$b" in
        ..) line+=" " ;;
        .o) line+="$fo▄$z" ;;
        .w) line+="$fw▄$z" ;;
        o.) line+="$fo▀$z" ;;
        w.) line+="$fw▀$z" ;;
        oo) line+="$fo█$z" ;;
        ww) line+="$fw█$z" ;;
        ow) line+="$fo$bw▀$z" ;;
        wo) line+="$fw$bo▀$z" ;;
      esac
    done
    LOGO_LINES+=("$line")
  done
}

LEGION_ART=(
  "██╗     ███████╗ ██████╗ ██╗ ██████╗ ███╗   ██╗"
  "██║     ██╔════╝██╔════╝ ██║██╔═══██╗████╗  ██║"
  "██║     █████╗  ██║  ███╗██║██║   ██║██╔██╗ ██║"
  "██║     ██╔══╝  ██║   ██║██║██║   ██║██║╚██╗██║"
  "███████╗███████╗╚██████╔╝██║╚██████╔╝██║ ╚████║"
  "╚══════╝╚══════╝ ╚═════╝ ╚═╝ ╚═════╝ ╚═╝  ╚═══╝"
)
LEGION_TAGS=("SOC 2" "HIPAA" "FedRAMP" "NIST 800-171" "CMMC L2")

# The Ubuntu logo for the Linux console, 15 x 15 pixels: . empty, o orange,
# w white. Console fonts often lack half-block characters, so each pixel is
# drawn as two spaces with a background color, which needs no special glyph.
LOGO_CON_PX=(
  .....ooooo.....
  ...ooooooooo...
  ..ooooooowwoo..
  .oooooooowwooo.
  .ooooowwoooooo.
  ooooowwwooooooo
  owwoowooowwoooo
  owwwooooowwoooo
  owwoowooowwoooo
  ooooowwwooooooo
  .ooooowwoooooo.
  .oooooooowwooo.
  ..ooooooowwoo..
  ...ooooooooo...
  .....ooooo.....
)

# Prints the console login banner for /etc/issue: the Ubuntu logo, LEGION,
# the tags and the warning text in $1. Colors are the console's own 16:
# brown (its closest color to Ubuntu orange) and light gray. The LEGION
# gradient is 256-color, which the console maps to cyan and blue. The text has
# no backslashes, so agetty prints it as is. 80 columns wide.
issue_banner() {
  local i n t c row px tag="" z=$'\e[0m' dim=$'\e[2m' cyan=$'\e[36m' grad=(51 45 39 33 27 21)
  for t in "${LEGION_TAGS[@]}"; do tag+="${tag:+ $dim·$z }$cyan$t$z"; done
  echo
  for i in "${!LOGO_CON_PX[@]}"; do
    row="${LOGO_CON_PX[i]}" px=""
    for ((c = 0; c < ${#row}; c++)); do
      case "${row:c:1}" in
        o) px+=$'\e[43m  ' ;;
        w) px+=$'\e[47m  ' ;;
        *) px+="$z  " ;;
      esac
    done
    px+="$z"
    n=$((i - 3)) # centers lettering, tagline and tags on the 15 logo rows
    if [ "$n" -ge 0 ] && [ "$n" -lt "${#LEGION_ART[@]}" ]; then
      printf '%s  \e[38;5;%sm%s%s\n' "$px" "${grad[n]}" "${LEGION_ART[n]}" "$z"
    elif [ "$i" = 10 ]; then
      printf '%s  %sP R O F I L E   ·   endpoint hardening%s\n' "$px" "$dim" "$z"
    elif [ "$i" = 11 ]; then
      printf '%s  %s\n' "$px" "$tag"
    else
      printf '%s\n' "$px"
    fi
  done
  printf '\n  \e[1m%s%s\n\n' "$1" "$z"
}

banner() {
  local lines i grad=(51 45 39 33 27 21)
  if [ "$UTF8" = 1 ]; then
    lines=("${LEGION_ART[@]}")
  else
    lines=("L E G I O N")
  fi
  echo >&3
  # The Ubuntu logo sits left of the lettering when there is color, UTF-8 and
  # room (80 columns); otherwise the lettering is shown alone.
  local cols logo=0 n
  cols="$({ stty size </dev/tty; } 2>/dev/null | awk '{ print $2 }' || true)"
  [ "${cols:-0}" -gt 0 ] 2>/dev/null || cols="$(tput cols 2>/dev/null || true)"
  [ "${cols:-0}" -gt 0 ] 2>/dev/null || cols="${COLUMNS:-80}"
  if [ "$UTF8" = 1 ] && [ -n "$C_RST" ] && [ "${cols:-0}" -ge 80 ]; then logo=1; logo_lines; fi
  # Tagline and framework tags go under the lettering.
  local tag t sub tags=("${LEGION_TAGS[@]}")
  sub="${C_DIM}P R O F I L E   ·   endpoint hardening${C_RST}"
  tag=""
  for t in "${tags[@]}"; do tag+="${tag:+ ${C_DIM}·${C_RST} }${C_INFO}${t}${C_RST}"; done
  if [ "$logo" = 1 ]; then
    # Right of the 13 logo rows: lettering on rows 2-7, tagline on 9, tags on
    # 10, so the block is centered on the logo.
    for i in "${!LOGO_LINES[@]}"; do
      n=$((i - 2))
      if [ "$n" -ge 0 ] && [ "$n" -lt "${#lines[@]}" ]; then
        printf '  %s   \e[38;5;%sm%s\e[0m\n' "${LOGO_LINES[i]}" "${grad[n]}" "${lines[n]}" >&3
      elif [ "$i" = 9 ]; then
        printf '  %s   %s\n' "${LOGO_LINES[i]}" "$sub" >&3
      elif [ "$i" = 10 ]; then
        printf '  %s   %s\n' "${LOGO_LINES[i]}" "$tag" >&3
      else
        printf '  %s\n' "${LOGO_LINES[i]}" >&3
      fi
      [ "$ANIM" = 0 ] || sleep 0.04
    done
    echo >&3
  else
    for i in "${!lines[@]}"; do
      if [ -n "$C_RST" ]; then printf '  \e[38;5;%sm%s\e[0m\n' "${grad[i]}" "${lines[i]}" >&3
      else printf '  %s\n' "${lines[i]}" >&3; fi
      [ "$ANIM" = 0 ] || sleep 0.07
    done
    printf '  %s\n  %s\n\n' "$sub" "$tag" >&3
  fi
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

ALLOW_UNENCRYPTED=0 STEAM=0 TOOLS=0 YARA=1 AIDE=1 SIGMA=1 PRO=1 LOCKOUT=1 REPORT_ONLY=0 CHECK=0 DRIFT_ONLY=0 BANNER_SHOWN=0
PRO_TOKEN_FILE=""
TAILSCALE="" ALLOW_FROM="" ALLOW_FROM_SET=0 IPV6="" SSH_ALLOW="" RDP_ALLOW="" # empty means: ask
FORWARD="" LOCK_AUDIT="" # empty means: ask on a terminal, otherwise keep the current setting
ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --allow-unencrypted) ALLOW_UNENCRYPTED=1 ;;
    --steam) STEAM=1 ;;
    --with-tools) TOOLS=1 ;;
    --no-yara) YARA=0 ;;
    --no-aide) AIDE=0 ;;
    --no-sigma) SIGMA=0 ;;
    --no-pro) PRO=0 ;;
    --pro-token-file)
      [ $# -ge 2 ] && [ -f "$2" ] || { echo "--pro-token-file needs a path to a file" >&2; exit 2; }
      PRO_TOKEN_FILE="$(readlink -f "$2")"
      ARGS+=("$1" "$PRO_TOKEN_FILE"); shift 2; continue ;;
    --no-lockout) LOCKOUT=0 ;;
    --check) CHECK=1 ;;
    --drift-only) CHECK=1; DRIFT_ONLY=1 ;; # internal: daily timer; exit 1 only on new failures
    --tailscale) TAILSCALE=1 ;;
    --no-tailscale) TAILSCALE=0 ;;
    --allow-from)
      [ $# -ge 2 ] || { echo "--allow-from needs a list of networks, e.g. 10.8.0.0/24" >&2; exit 2; }
      ALLOW_FROM="${2//,/ }" ALLOW_FROM_SET=1
      ARGS+=("$1" "$2"); shift 2; continue ;;
    --no-ipv6) IPV6=0 ;;
    --ssh) SSH_ALLOW=1 ;;
    --no-ssh) SSH_ALLOW=0 ;;
    --ipv6) IPV6=1 ;;
    --report-only) REPORT_ONLY=1 ;;
    --forward-logs)
      [ $# -ge 2 ] || { echo "--forward-logs needs a log server, e.g. syslog+tls://logs.example.com:6514" >&2; exit 2; }
      FORWARD="$2"
      ARGS+=("$1" "$2"); shift 2; continue ;;
    --no-forward-logs) FORWARD=none ;;
    --lock-audit) LOCK_AUDIT=1 ;;
    --no-lock-audit) LOCK_AUDIT=0 ;;
    --banner-shown) BANNER_SHOWN=1; shift; continue ;; # internal: set when re-run through sudo
    -h | --help) usage; exit 0 ;;
    *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
  ARGS+=("$1")
  shift
done

READONLY=0
[ "$CHECK" = 0 ] && [ "$REPORT_ONLY" = 0 ] || READONLY=1
LEGION_VERSION="2026.11"
LEGION_START="$(date +%s)"
[ "$BANNER_SHOWN" = 1 ] || [ "$DRIFT_ONLY" = 1 ] || banner

# Legion installs a copy of itself for the daily check, so it must run from a
# file, not from a pipe such as "curl ... | bash".
SELF="$(readlink -f "$0" 2>/dev/null || true)"
if [ ! -f "$SELF" ] || ! grep -q '^LEGION_VERSION=' "$SELF" 2>/dev/null; then
  fail "run Legion from a file: download legion.sh, then run: bash legion.sh"; exit 2
fi
if [ "$(id -u)" != 0 ]; then
  command -v sudo >/dev/null || { fail "sudo is not installed; run this as root"; exit 2; }
  info "administrator access needed, asking sudo"
  keep="NO_COLOR,LEGION_NO_ANIM"
  [ -z "${UBUNTU_PRO_SECRET:-}" ] || keep+=",UBUNTU_PRO_SECRET"
  exec sudo --preserve-env="$keep" bash "$SELF" --banner-shown "${ARGS[@]}"
fi

# ---------------------------------------------------------------- setup

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=l # needrestart: list services to restart, don't restart them
APT=(-y -q -o DPkg::Lock::Timeout=300 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)
LOGDIR=/var/log/legion
STATE=/var/lib/legion
install -d -m 750 "$LOGDIR"
install -d -m 700 "$STATE"
# One Legion run at a time.
# The daily drift check waits for a run in progress; anything else stops.
exec 9>/run/legion.lock
if [ "$DRIFT_ONLY" = 1 ]; then
  flock -w 1800 9 || { fail "Legion is still running after 30 minutes"; exit 2; }
elif ! flock -n 9; then
  fail "Legion is already running"; exit 2
fi
RUNLOG="$LOGDIR/run-$(date +%Y%m%d-%H%M%S)-$$.log"
# Lets the AIDE apt hook tell Legion's own changes from others during this run.
[ "$READONLY" = 1 ] || echo "$LEGION_START" >/run/legion-run-start
find "$LOGDIR" -maxdepth 1 -name 'run-*.log' -printf '%T@ %p\n' 2>/dev/null | sort -rn | awk 'NR > 60 { print $2 }' | xargs -r rm -f
: >"$RUNLOG"
chmod 640 "$RUNLOG"
FLAGS="$(mktemp -d)" # steps run in subshells and leave notes for the summary here
trap 'rm -rf "$FLAGS"; [ "$READONLY" = 1 ] || rm -f /run/legion-run-start' EXIT

SELF_PATH="$(readlink -f "$0")"
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
    case "$(zfs get -H -o value encryption "$src" 2>/dev/null || true)" in "" | off | -) return 1 ;; *) return 0 ;; esac
  fi
  src="${src%%[*}" # btrfs shows /dev/x[/@]
  types="$(lsblk -nso TYPE "$src" 2>/dev/null || true)"
  if [ -n "$types" ]; then
    grep -qx crypt <<<"$types"
    return
  fi
  # lsblk printed nothing (seen in some sandboxes): walk the device-mapper
  # stack in sysfs instead. A dm-crypt layer has a uuid starting with CRYPT-.
  local dev queue=() u
  dev="$(readlink -f "$src" 2>/dev/null)" && dev="${dev##*/}" || return 1
  queue=("$dev")
  while [ "${#queue[@]}" -gt 0 ]; do
    dev="${queue[0]}" queue=("${queue[@]:1}")
    u="$(cat "/sys/class/block/$dev/dm/uuid" 2>/dev/null || true)"
    [[ "$u" == CRYPT-* ]] && return 0
    for u in /sys/class/block/"$dev"/slaves/*; do [ -e "$u" ] && queue+=("${u##*/}"); done
  done
  return 1
}

# ---------------------------------------------------------------- preflight

section "System check"
info "run log: $RUNLOG"
# The installed 'legion' command (used by the daily check) is refreshed by a
# full run. Say so when it differs from the copy running now.
if [ -x /usr/local/sbin/legion ] && [ "$SELF_PATH" != /usr/local/sbin/legion ] && ! cmp -s "$SELF_PATH" /usr/local/sbin/legion; then
  if [ "$READONLY" = 1 ]; then warn "the installed 'legion' command is a different version; a full run updates it"
  else info "the installed 'legion' command will be updated to this version"; fi
fi
if [ "$OS_ID" != ubuntu ]; then
  fail "operating system: ${OS_ID:-unknown}. Legion supports Ubuntu only"; exit 2
fi
case "$OS_VERSION" in
  26.04) ok "operating system: $(osr PRETTY_NAME)" ;;
  *) warn "operating system: $(osr PRETTY_NAME). Legion is built and tested for Ubuntu 26.04; continuing untested" ;;
esac
case "$ARCH" in
  x86_64 | aarch64) ok "architecture: $ARCH" ;;
  *) fail "architecture: $ARCH is not supported"; exit 2 ;;
esac
if [ -d /run/systemd/system ]; then ok "init system: systemd"; else fail "init system: systemd is not running"; exit 2; fi
if [ "$IN_CONTAINER" = 1 ]; then info "running in a container: kernel settings and audit rules are written but not loaded"; fi
if [ "$READONLY" = 0 ]; then
  FREE_GB=$(($(df --output=avail -k / | tail -n 1) / 1024 / 1024))
  if [ "$FREE_GB" -ge 3 ]; then ok "free disk space: ${FREE_GB} GB"; else fail "free disk space: ${FREE_GB} GB (need 3 GB)"; exit 2; fi
  # curl is not installed on a fresh Ubuntu Desktop, so test with plain TCP
  # connections. Each address is tried briefly, IPv4 and IPv6 alike, so a
  # network with broken IPv6 does not look offline.
  net_ok() {
    local a
    for a in $(getent ahostsv4 security.ubuntu.com 2>/dev/null | awk '!seen[$1]++ { print $1 }' | head -n 3) \
      $(getent ahostsv6 security.ubuntu.com 2>/dev/null | awk '!seen[$1]++ { print $1 }' | head -n 3); do
      timeout 5 bash -c "exec 9<>/dev/tcp/$a/80" 2>/dev/null && return 0
    done
    return 1
  }
  if net_ok; then
    ok "network: Ubuntu archive reachable"
  elif [ -n "$(apt-config dump 2>/dev/null | grep -iE '^Acquire::(http|https)::Proxy ' || true)" ] || [ -n "${https_proxy:-}${http_proxy:-}" ]; then
    warn "network: no direct connection to security.ubuntu.com, but a proxy is set; continuing"
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
  if [ "$READONLY" = 0 ] && [ "$ALLOW_UNENCRYPTED" = 0 ]; then
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

# Network questions: the firewall blocks all incoming traffic, so ask what
# must still reach this device. Answers can also come from options.
ask_yn() { # question, default y or n; returns 0 for yes
  local r hint="[y/N]"
  [ "$2" = y ] && hint="[Y/n]"
  printf '  %s?%s %s %s ' "$C_WARN" "$C_RST" "$1" "$hint" >&3
  read -r r || r=""
  r="${r:-$2}"
  [[ "$r" == [Yy]* ]]
}
# A private network in CIDR form (IPv4 or IPv6). "Allow everything" ranges
# are refused, since they would switch the firewall off.
# Only private ranges (10/8, 172.16/12, 192.168/16, fd00::/8, ...) with a
# prefix of at least /8 (IPv4) or /16 (IPv6); anything else is refused.
valid_cidr() {
  python3 -I -c '
import ipaddress, sys
try:
    n = ipaddress.ip_network(sys.argv[1], strict=False)
except ValueError:
    sys.exit(1)
ok = n.is_private and not n.is_loopback and not n.is_link_local and not n.is_unspecified
sys.exit(0 if ok and n.prefixlen >= (8 if n.version == 4 else 16) else 1)' "$1" 2>/dev/null
}
if [ "$READONLY" = 0 ]; then
  INTERACTIVE=0
  [ -t 0 ] && [ -t 1 ] && INTERACTIVE=1
  [ "$INTERACTIVE" = 0 ] && [ -z "$TAILSCALE$IPV6" ] && info "no terminal: Tailscale off, IPv6 kept (use --tailscale, --allow-from, --no-ipv6)"
  # SSH: keep it reachable when a server is running, so nobody is locked out.
  # Running Legion over SSH always keeps it (newer OpenSSH names its session
  # processes sshd-session).
  over_ssh=0 p=$$
  while [ "${p:-1}" -gt 1 ]; do
    case "$(ps -o comm= -p "$p" 2>/dev/null)" in sshd*) over_ssh=1; break ;; esac
    p="$(ps -o ppid= -p "$p" 2>/dev/null | tr -d ' ')"
  done
  listening() { ss -ltnH 2>/dev/null | awk -v port=":$1" '$4 ~ port"$" && $4 !~ /^(127\.|\[::1\])/ { f = 1 } END { exit !f }'; }
  if [ "$over_ssh" = 1 ]; then
    SSH_ALLOW=1
    warn "you are connected over SSH: SSH stays allowed (rate-limited)"
  elif [ -z "$SSH_ALLOW" ]; then
    SSH_ALLOW=0
    if listening 22; then
      SSH_ALLOW=1
      if [ "$INTERACTIVE" = 1 ]; then ask_yn "An SSH server is running. Keep SSH reachable (rate-limited)?" y || SSH_ALLOW=0; fi
    fi
  fi
  [ "$SSH_ALLOW" = 1 ] && ok "SSH: allowed, rate-limited"
  if listening 3389; then
    RDP_ALLOW=1
    if [ "$INTERACTIVE" = 1 ]; then ask_yn "Remote Desktop is on. Keep it reachable?" y || RDP_ALLOW=0; fi
    [ "$RDP_ALLOW" = 1 ] && ok "Remote Desktop: allowed"
  fi
  if [ -z "$TAILSCALE" ]; then
    TAILSCALE=0
    ts_found=n
    { command -v tailscale >/dev/null || ip link show tailscale0 >/dev/null 2>&1; } && ts_found=y
    if [ "$INTERACTIVE" = 1 ]; then
      [ "$ts_found" = y ] && info "Tailscale is installed on this device"
      ask_yn "Do you use Tailscale, and should this device be reachable over it?" "$ts_found" && TAILSCALE=1
    fi
  fi
  [ "$TAILSCALE" = 1 ] && ok "Tailscale: incoming traffic over tailscale0 allowed"
  [ "$ALLOW_FROM" != none ] || ALLOW_FROM=""
  if [ "$ALLOW_FROM_SET" = 0 ] && [ "$INTERACTIVE" = 1 ] &&
    ask_yn "Do other private networks need to reach this device (for example an office VPN)?" n; then
    printf '  %s?%s networks, separated by spaces (e.g. 10.8.0.0/24): ' "$C_WARN" "$C_RST" >&3
    read -r ALLOW_FROM || ALLOW_FROM=""
  fi
  good=""
  for net in $ALLOW_FROM; do
    if valid_cidr "$net"; then good+=" $net"; else warn "ignored '$net': not a private network in CIDR form"; fi
  done
  ALLOW_FROM="${good# }"
  [ -z "$ALLOW_FROM" ] || ok "private networks allowed in: $ALLOW_FROM"
  if [ -z "$IPV6" ]; then
    IPV6=1
    if [ "$INTERACTIVE" = 1 ]; then ask_yn "Does this device need IPv6? (if unsure, answer yes)" y || IPV6=0; fi
  fi
  if [ "$IPV6" = 1 ]; then ok "IPv6: kept"; else warn "IPv6: will be turned off"; fi

  # Off-device log copies: the only tamper evidence that survives someone
  # with administrator rights on this device. Unanswered, the current
  # setting stays.
  FWD_CONF=/etc/rsyslog.d/60-legion-forward.conf
  current_forward="$(sed -n 's/^# Legion destination: //p' "$FWD_CONF" 2>/dev/null || true)"
  if [ -z "$FORWARD" ] && [ "$INTERACTIVE" = 1 ]; then
    info "a log server (SIEM) keeps a copy of the logs that nobody on this device can change"
    if ask_yn "Send a copy of system and audit logs to a log server?" "$([ -n "$current_forward" ] && echo y || echo n)"; then
      printf '  %s?%s log server, e.g. syslog+tls://logs.example.com:6514 %s: ' "$C_WARN" "$C_RST" "${current_forward:+[$current_forward]}" >&3
      read -r FORWARD || FORWARD=""
      FORWARD="${FORWARD:-$current_forward}"
    else
      FORWARD=none
    fi
  fi
  [ -n "$FORWARD" ] || FORWARD="${current_forward:-none}"
  if [ "$FORWARD" != none ]; then
    if [[ "$FORWARD" =~ ^syslog(\+tls)?://([A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\]):([0-9]{1,5})$ ]] && [ "${BASH_REMATCH[3]}" -le 65535 ]; then
      FWD_TLS=0 FWD_HOST="${BASH_REMATCH[2]}" FWD_PORT="${BASH_REMATCH[3]}"
      [ -z "${BASH_REMATCH[1]}" ] || FWD_TLS=1
      FWD_HOST="${FWD_HOST#[}" FWD_HOST="${FWD_HOST%]}"
      if [ "$FWD_TLS" = 1 ]; then ok "log forwarding: $FORWARD (encrypted)"; else warn "log forwarding: $FORWARD (not encrypted; use syslog+tls:// if the server supports it)"; fi
    else
      fail "log server '$FORWARD' not understood: use syslog+tls://HOST:PORT or syslog://HOST:PORT"
      exit 2
    fi
  else
    info "log forwarding: off (logs stay on this device)"
  fi

  # Locked audit rules (auditd immutable mode): nobody, including root, can
  # change or turn off auditing until the next restart. Opt-in, because Legion
  # (and anyone) then needs a restart to change audit rules.
  current_lock=0
  [ ! -f /etc/audit/rules.d/99-legion-lock.rules ] || current_lock=1
  if [ -z "$LOCK_AUDIT" ] && [ "$INTERACTIVE" = 1 ]; then
    info "locked audit rules stop anyone, even an administrator, from turning auditing off without a restart"
    info "changing audit rules then needs a restart, including Legion's own updates"
    LOCK_AUDIT=0
    ask_yn "Lock the audit rules until each restart?" "$([ "$current_lock" = 1 ] && echo y || echo n)" && LOCK_AUDIT=1
  fi
  [ -n "$LOCK_AUDIT" ] || LOCK_AUDIT="$current_lock"
  if [ "$LOCK_AUDIT" = 1 ]; then ok "audit rules: will be locked; changing them needs a restart"; else info "audit rules: not locked"; fi
fi

# Ubuntu Pro: security updates for every package (ESM) and Livepatch. The
# token comes from the Ubuntu One account that owns the subscription. It is
# read without echo, never written to the log, and never put on a command line.
PRO_TOKEN=""
pro_attached() { command -v pro >/dev/null && pro status --format json 2>/dev/null | grep -q '"attached": *true'; }
if [ "$READONLY" = 0 ] && [ "$PRO" = 1 ]; then
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

# Keeps a copy of a file the first time Legion changes it, so legion-remove.sh
# can restore the original. A missing file is recorded as NAME.absent.
backup_once() { # file [name]
  local b="$STATE/backup/${2:-${1##*/}}"
  install -d -m 700 "$STATE/backup"
  [ -e "$b" ] || [ -e "$b.absent" ] || { if [ -e "$1" ]; then cp -p "$1" "$b"; else : >"$b.absent"; fi; }
}

# Sets KEY VALUE in a login.defs-style file: replaces the active line, or
# adds one. Commented lines are left alone.
set_def() { # key value file
  if grep -qE "^$1[[:space:]]" "$3"; then
    sed -i -E "s|^$1[[:space:]].*|$1\t$2|" "$3"
  else
    printf '%s\t%s\n' "$1" "$2" >>"$3"
  fi
}

# Adds a firewall rule labelled for Legion, unless the same rule already
# exists (with any label). An existing rule belongs to the user and is left
# alone, so legion-remove.sh never deletes it.
ufw_allow() { # label, rule words...
  local label="$1"
  shift
  if ufw show added 2>/dev/null | sed -E "s/ comment '.*'$//" | grep -qxF "ufw allow $*"; then
    info "firewall rule already present, left as is: ufw allow $*"
  else
    ufw allow "$@" comment "Legion: $label"
  fi
}

ufw_rule() { # verb (e.g. limit, "route allow"), label, rule words...
  local verb="$1" label="$2"
  shift 2
  # shellcheck disable=SC2086 # the verb may be two words
  if ufw show added 2>/dev/null | sed -E "s/ comment '.*'$//" | grep -qxF "ufw $verb $*"; then
    info "firewall rule already present, left as is: ufw $verb $*"
  else
    ufw $verb "$@" comment "Legion: $label"
  fi
}

# apt-get update, waiting up to 5 minutes while another apt (such as Ubuntu's
# own daily update check) holds the package lists lock.
apt_update() {
  local i
  for i in $(seq 30); do
    apt-get update -q && return 0
    [ "$i" = 30 ] || sleep 10
  done
  return 1
}

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
  echo "$list $keyring" >>"$STATE/created-repos"
  if apt_update && apt-get "${APT[@]}" install "$pkg"; then return 0; fi
  warn "$pkg: install failed; removing its repository again"
  rm -f "/etc/apt/sources.list.d/$list" "/usr/share/keyrings/$keyring"
  apt-get update -q || true
  return 1
}

STEP=0
TOTAL=$((13 + WITH_PRO + YARA + AIDE + SIGMA + LOCKOUT + TOOLS))
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
  # Finish any package install that was interrupted (power loss, a kill).
  dpkg --configure -a
  apt-get "${APT[@]}" -f install
  apt_update
  apt-get "${APT[@]}" full-upgrade
  apt-get "${APT[@]}" install curl gpg ca-certificates iproute2 needrestart
  # No "apt autoremove" and no purging of leftover package configs: both can
  # delete things people need. Autoremove can take out the whole desktop
  # session, and purging a removed docker.io deletes /var/lib/docker.
}

# A kernel update must come with the NVIDIA module for that kernel, or the GPU
# has no driver after the reboot. Its own step, so it runs even when patching
# failed partway.
step_nvidia() {
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
    apt_update
    apt-get "${APT[@]}" install ubuntu-pro-client
  fi
  # Same as `pro attach TOKEN` with Pro's default services (ESM and, where
  # the kernel supports it, Livepatch). The token goes through a private file
  # because command-line arguments are visible to every user in `ps`.
  local cfg="$FLAGS/pro-attach.yaml"
  (umask 077 && printf 'token: %s\n' "$PRO_TOKEN" >"$cfg")
  pro attach --attach-config "$cfg"
  rm -f "$cfg"
  apt_update
  info "$(pro status 2>/dev/null | awk '$2 == "yes" && $3 == "enabled" { s = s " " $1 } END { print "enabled:" s }')"
}

step_auto_updates() {
  apt-get "${APT[@]}" install unattended-upgrades
  backup_once /etc/apt/apt.conf.d/20auto-upgrades
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
  # Remember ufw's state and settings before Legion's first change, so
  # legion-remove.sh can put back exactly what was there.
  if [ ! -e "$STATE/backup/ufw-was-active" ] && [ ! -e "$STATE/backup/ufw-was-inactive" ]; then
    install -d -m 700 "$STATE/backup"
    if ufw status 2>/dev/null | grep -q 'Status: active'; then : >"$STATE/backup/ufw-was-active"; else : >"$STATE/backup/ufw-was-inactive"; fi
    backup_once /etc/default/ufw ufw-default
    backup_once /etc/ufw/ufw.conf ufw.conf
  fi
  ufw default deny incoming
  ufw default allow outgoing
  ufw logging low
  if [ -n "$lan" ]; then
    info "local network: $lan on $iface"
    ufw_allow "mDNS LAN" from "$lan" to any port 5353 proto udp
    if [ "$STEAM" = 1 ]; then
      ufw_allow "Steam LAN" from "$lan" to any port 27031:27036 proto udp
      ufw_allow "Steam LAN" from "$lan" to any port 27036:27037 proto tcp
    fi
  else
    warn "no default route found; no local network exceptions added"
  fi
  [ "$SSH_ALLOW" != 1 ] || ufw_rule limit "SSH" 22/tcp
  [ "$RDP_ALLOW" != 1 ] || ufw_allow "Remote Desktop" 3389/tcp
  [ "$TAILSCALE" != 1 ] || ufw_allow "Tailscale" in on tailscale0
  # Virtual machines (libvirt): DHCP and DNS on the bridge, and their traffic
  # through this machine, keep working.
  if ip link show virbr0 >/dev/null 2>&1; then
    ufw_allow "virtual machines" in on virbr0
    ufw_rule "route allow" "virtual machines" in on virbr0
    ufw_rule "route allow" "virtual machines" out on virbr0
  fi
  local net
  for net in $ALLOW_FROM; do ufw_allow "private network" from "$net" || warn "could not add a rule for $net"; done
  ufw --force enable
}

# One audit rule per architecture for the given system calls, keeping only
# the calls that architecture has (a name auditctl does not know would stop
# the whole rule file from loading).
audit_syscalls() { # "extra filters" key syscall...
  local filters="$1" key="$2" arch s list
  shift 2
  for arch in b64 b32; do
    if [ "$arch" = b32 ] && [ "$ARCH" != x86_64 ]; then continue; fi
    list=""
    for s in "$@"; do
      if ausyscall "$arch" "$s" --exact >/dev/null 2>&1; then list+="${list:+,}$s"; fi
    done
    if [ -n "$list" ]; then echo "-a always,exit -F arch=$arch -S $list${filters:+ $filters} -k $key"; fi
  done
}
# File and folder watches, for the paths that exist on this machine.
audit_watch() { # key path...
  local key="$1" f
  shift
  for f in "$@"; do
    if [ -e "$f" ]; then echo "-w $f -p wa -k $key"; fi
  done
}
# Watches for files an attacker would create, so they need not exist yet; the
# folder they would be created in must exist, or the rule would not load.
audit_watch_new() { # key path...
  local key="$1" f
  shift
  for f in "$@"; do
    if [ -e "$f" ] || [ -d "$(dirname "$f")" ]; then echo "-w $f -p wa -k $key"; fi
  done
}
# Run-watches go on the real program, not a link to it: on Ubuntu 26.04
# /usr/bin/sudo links to sudo-rs and modprobe/insmod link to kmod, and a
# watch on a link never fires.
audit_exec() { # rule-template key program...
  local tpl="$1" key="$2" prog real seen=" "
  shift 2
  for prog in "$@"; do
    real="$(readlink -f "$prog" 2>/dev/null || true)"
    if [ -x "$real" ] && [[ "$seen" != *" $real "* ]]; then
      seen+="$real "
      # shellcheck disable=SC2059 # the template is a fixed format
      printf -- "${tpl}\n" "$real" "$key"
    fi
  done
}
# Programs that run with raised privileges (setuid or setgid), on the local
# disks. Containers and snaps are skipped: their programs are not this
# system's.
# The local disk filesystems to search: / and any other local disk mounted
# as a folder (a separate /home, for example).
local_disks() {
  local m
  mounts=(/)
  while read -r m; do
    if [ -d "$m" ] && [ "$m" != / ]; then mounts+=("$m"); fi
  done < <(findmnt -rno TARGET -t ext2,ext3,ext4,xfs,btrfs,f2fs,zfs 2>/dev/null || true)
}
privileged_programs() {
  local mounts=()
  local_disks
  find "${mounts[@]}" -xdev \( -path /proc -o -path /sys -o -path /var/lib/docker -o -path /var/lib/containers -o -path /snap -o -path /var/snap \) -prune \
    -o -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null | sort -u
}

step_audit() {
  apt-get "${APT[@]}" install auditd audispd-plugins
  backup_once /etc/audit/auditd.conf
  local real users="-F auid>=1000 -F auid!=unset"
  {
    echo "# Legion Profile audit rules (CIS Ubuntu 24.04 section 6.3.3; NIST 800-53"
    echo "# AU-2, AU-12; 800-171 3.3.1, 3.3.2). Rules about what people do apply"
    echo "# to real users only (login ID 1000 and up), so system services do not"
    echo "# flood the log. Generated by Legion; changes here are overwritten."
    echo "## Accounts, groups, passwords and login settings"
    audit_watch identity /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/security/opasswd \
      /etc/nsswitch.conf /etc/pam.conf /etc/pam.d /etc/login.defs /etc/security/pwquality.conf.d
    echo "## Administrator rights"
    audit_watch privilege /etc/sudoers /etc/sudoers.d
    audit_exec '-w %s -p x -k %s' privilege /usr/bin/sudo /usr/bin/su
    audit_syscalls "-C euid!=uid -F auid!=unset" user_emulation execve
    echo "## Sessions and logins"
    audit_watch session /var/run/utmp /var/log/wtmp /var/log/btmp
    audit_watch logins /var/log/lastlog /run/faillock /var/log/auth.log
    echo "## Network settings and host name"
    audit_syscalls "" system-locale sethostname setdomainname
    audit_watch system-locale /etc/issue /etc/issue.net /etc/hosts /etc/hostname /etc/networks \
      /etc/network /etc/netplan /etc/NetworkManager/system-connections
    echo "## Time"
    audit_syscalls "" time adjtimex settimeofday clock_settime stime
    audit_watch time /etc/localtime
    echo "## Kernel modules"
    audit_syscalls "" modules init_module finit_module delete_module create_module query_module
    audit_exec '-w %s -p x -k %s' modules /usr/sbin/insmod /usr/sbin/modprobe /usr/sbin/rmmod /sbin/insmod /sbin/modprobe
    echo "## Permission and ownership changes"
    audit_syscalls "$users" perm_mod chmod fchmod fchmodat fchmodat2
    audit_syscalls "$users" perm_mod chown fchown lchown fchownat chown32 fchown32 lchown32
    audit_syscalls "$users" perm_mod setxattr lsetxattr fsetxattr removexattr lremovexattr fremovexattr
    echo "## File access refused"
    audit_syscalls "-F exit=-EACCES $users" access creat open openat openat2 truncate ftruncate truncate64 ftruncate64
    audit_syscalls "-F exit=-EPERM $users" access creat open openat openat2 truncate ftruncate truncate64 ftruncate64
    echo "## Mounts"
    audit_syscalls "$users" mounts mount umount umount2
    echo "## File deletion and renaming"
    audit_syscalls "$users" delete unlink unlinkat rename renameat renameat2
    echo "## AppArmor policy"
    audit_watch MAC-policy /etc/apparmor /etc/apparmor.d
    echo "## Commands that change permissions or accounts"
    audit_exec "-a always,exit -F path=%s -F perm=x $users -k %s" perm_chng /usr/bin/chcon /usr/bin/setfacl /usr/bin/chacl
    audit_exec "-a always,exit -F path=%s -F perm=x $users -k %s" usermod /usr/sbin/usermod
    echo "## Programs that run with raised privileges (setuid and setgid)"
    while read -r real; do
      echo "-a always,exit -F path=$real -F perm=x $users -k privileged"
    done < <(privileged_programs)
    echo "## Commands people run (NIST AU-12, 800-171 3.3.1; read by the Sigma rules)"
    audit_syscalls "$users" exec execve execveat
    echo "## Files attackers change to run code at login or hide it (Sigma rules)"
    audit_watch_new persistence /etc/ld.so.preload /etc/ld.so.conf /etc/ld.so.conf.d /etc/environment \
      /etc/shells /etc/profile /etc/profile.d /etc/bash.bashrc /etc/rsyslog.conf /etc/syslog.conf \
      /etc/sysctl.conf /etc/crontab /etc/cron.d /var/spool/cron/crontabs /etc/systemd/user \
      /root/.bashrc /root/.profile /root/.bash_profile /root/.ssh/authorized_keys
    echo "## Firewall and audit settings"
    audit_watch firewall /etc/ufw
    audit_watch audit-config /etc/audit /etc/libaudit.conf
    echo "## The audit logs themselves (auditd's own writes are never audited)"
    audit_watch audit-log /var/log/audit
    echo "## Legion itself: its programs, settings, schedules and baselines"
    audit_watch legion-tamper /usr/local/sbin /etc/legion /var/lib/legion/aide /etc/systemd/system \
      /etc/apt/apt.conf.d/99legion-aide /etc/sudoers.d/legion /usr/share/pam-configs /etc/rsyslog.d \
      /etc/dconf/db/local.d /etc/gdm3/greeter.dconf-defaults /etc/sysctl.d /etc/modprobe.d
    echo "## AI coding agent settings (hooks, MCP servers, permissions)"
    audit_watch ai-agent-config /etc/claude-code
    local home d
    while IFS=: read -r _ _ real _ _ home _; do
      if [ "$real" -ge 1000 ] 2>/dev/null && [ "$real" -lt 60000 ] && [ -d "$home" ]; then
        # A folder is watched as a whole only if it exists, so create the
        # missing ones a login-time backdoor would go into, empty and private.
        # (Output here goes into the rules file, so it stays silent.)
        for d in "$home/.ssh" "$home/.config" "$home/.config/autostart" "$home/.config/systemd" "$home/.config/systemd/user"; do
          if [ ! -e "$d" ] && install -d -m 700 -o "$real" -g "$(id -g "$real")" "$d" 2>/dev/null; then
            echo "$d" >>"$STATE/created-dirs"
          fi
        done
        audit_watch_new ai-agent-config "$home/.claude/settings.json" "$home/.claude/settings.local.json" \
          "$home/.mcp.json" "$home/.cursor/mcp.json" "$home/.codex/config.toml" "$home/.gemini/settings.json"
        audit_watch_new persistence "$home/.bashrc" "$home/.profile" "$home/.bash_profile" \
          "$home/.ssh/authorized_keys" "$home/.config/autostart" "$home/.config/systemd/user"
      fi
    done </etc/passwd
  } >/etc/audit/rules.d/legion.rules.new
  chmod 640 /etc/audit/rules.d/legion.rules.new
  mv -f /etc/audit/rules.d/legion.rules.new /etc/audit/rules.d/legion.rules
  # Locked rules (opt-in): "-e 2" must be the very last rule loaded.
  if [ "$LOCK_AUDIT" = 1 ]; then
    printf '# Legion Profile: lock the audit rules until the next restart.\n-e 2\n' >/etc/audit/rules.d/99-legion-lock.rules
    chmod 640 /etc/audit/rules.d/99-legion-lock.rules
  else
    rm -f /etc/audit/rules.d/99-legion-lock.rules
  fi
  local locked=0
  [ "$IN_CONTAINER" = 1 ] || ! auditctl -s 2>/dev/null | grep -qx 'enabled 2' || locked=1
  # Logs rotate and never fill the disk: 20 files of 32 MB. When the disk
  # runs low anyway, an alert goes to the system log and to logged-in users
  # (800-171 3.3.4) and auditd keeps recording.
  cat >/usr/local/sbin/legion-audit-alert <<'EOF'
#!/bin/sh
# Legion Profile: auditd runs this when the audit log disk runs low.
logger -p auth.crit -t legion "audit log disk space is low; audit records stop when the disk is full"
date -u +%Y-%m-%dT%H:%M:%SZ >/var/lib/legion/audit-space-low
wall "Legion: the audit log disk is running out of space. Free up disk space." 2>/dev/null || true
EOF
  chmod 750 /usr/local/sbin/legion-audit-alert
  local conf=/etc/audit/auditd.conf k v kv
  cp -p "$conf" "$conf.legion-prev"
  for kv in "max_log_file=32" "num_logs=20" "max_log_file_action=ROTATE" \
    "space_left_action=exec /usr/local/sbin/legion-audit-alert" \
    "admin_space_left_action=exec /usr/local/sbin/legion-audit-alert"; do
    k="${kv%%=*}" v="${kv#*=}"
    if grep -qE "^#?[[:space:]]*${k}[[:space:]]*=" "$conf"; then
      sed -i -E "s|^#?[[:space:]]*${k}[[:space:]]*=.*|$k = $v|" "$conf"
    else
      echo "$k = $v" >>"$conf"
    fi
  done
  if [ "$IN_CONTAINER" = 1 ]; then
    rm -f "$conf.legion-prev"
    systemctl enable auditd # the kernel audit system belongs to the host
    return 0
  fi
  systemctl enable auditd
  # Tamper protection (AU-9, 800-171 3.3.8): auditd cannot be stopped by hand,
  # even by root, and comes straight back if it is killed. Settings changes
  # are applied with a reload, which needs no stop.
  install -d -m 755 /etc/systemd/system/auditd.service.d
  cat >/etc/systemd/system/auditd.service.d/legion.conf <<'EOF'
# Legion Profile: keep the audit daemon running.
[Unit]
RefuseManualStop=yes
[Service]
Restart=always
RestartSec=1
EOF
  systemctl daemon-reload
  if [ "$locked" = 1 ]; then
    # The kernel refuses rule changes until a restart; that is the point.
    rm -f "$conf.legion-prev"
    : >"$FLAGS/restart-audit"
    info "audit rules are locked: the new rules and settings apply after a restart"
    return 0
  fi
  if systemctl is-active -q auditd; then systemctl reload auditd || true; else systemctl start auditd || true; fi
  sleep 1
  if ! systemctl is-active -q auditd; then
    cp -p "$conf.legion-prev" "$conf"
    systemctl start auditd || true
    warn "auditd did not start with the new settings; its previous settings are back"
  fi
  rm -f "$conf.legion-prev"
  if ! augenrules --load; then
    warn "some audit rules did not load; see: sudo augenrules --check"
    return 1
  fi
  info "$(auditctl -l | grep -c .) audit rules loaded"
  [ "$LOCK_AUDIT" = 0 ] || info "audit rules are locked until the next restart"
}

step_forward() {
  # A copy of system and audit logs goes to a log server (800-53 AU-4(1),
  # AU-9(2)). rsyslog keeps a queue on disk (up to 1 GB), so nothing is lost
  # while the device is offline. The audit log is sent from its file, so it
  # does not also fill the system journal.
  local f="$FWD_CONF"
  if [ "$FORWARD" = none ]; then
    if [ -f "$f" ]; then
      rm -f "$f"
      systemctl try-restart rsyslog 2>/dev/null || true
      info "log forwarding turned off"
    fi
    return 0
  fi
  local pkgs=(rsyslog)
  [ "$FWD_TLS" = 0 ] || pkgs+=(rsyslog-gnutls)
  apt-get "${APT[@]}" install "${pkgs[@]}"
  local tls=""
  if [ "$FWD_TLS" = 1 ]; then
    tls="StreamDriver=\"gtls\" StreamDriverMode=\"1\" StreamDriverAuthMode=\"x509/name\"
    StreamDriverPermittedPeers=\"$FWD_HOST\" StreamDriver.CAFile=\"/etc/ssl/certs/ca-certificates.crt\""
  fi
  cat >"$f.new" <<EOF
# Legion Profile: copies of system and audit logs go to a log server.
# Legion destination: $FORWARD
# Turn off with: sudo legion --no-forward-logs (or legion-remove.sh)
module(load="imfile")
ruleset(name="legion-forward") {
  action(type="omfwd" Target="$FWD_HOST" Port="$FWD_PORT" Protocol="tcp"
    $tls
    Template="RSYSLOG_SyslogProtocol23Format"
    queue.type="LinkedList" queue.filename="legion-forward" queue.maxDiskSpace="1g"
    queue.saveOnShutdown="on" action.resumeRetryCount="-1" action.resumeInterval="30")
}
input(type="imfile" File="/var/log/audit/audit.log" Tag="audit:" Facility="local6" Ruleset="legion-forward")
call legion-forward
EOF
  mv -f "$f.new" "$f"
  if ! rsyslogd -N1 >/dev/null 2>&1; then
    rm -f "$f"
    warn "log forwarding not set up: rsyslog did not accept the settings"
    return 1
  fi
  systemctl enable rsyslog
  systemctl restart rsyslog
  info "system and audit logs now also go to $FORWARD"
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
# Sandboxed (Legion tamper protection): system and home folders read-only,
# no privilege gain, private /tmp, kernel settings read-only.
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ProtectHome=read-only
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
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
  # Password history: the last 24 passwords cannot be reused (800-171
  # 3.5.8). Added through pam-auth-update, like the lockout.
  local rc=0
  cat >/usr/share/pam-configs/legion-pwhistory <<'EOF'
Name: Legion Profile: refuse the last 24 passwords
Default: yes
Priority: 512
Password-Type: Primary
Password:
	requisite	pam_pwhistory.so remember=24 enforce_for_root use_authtok
Password-Initial:
	requisite	pam_pwhistory.so remember=24 enforce_for_root
EOF
  [ -e /etc/security/opasswd ] || { install -m 600 /dev/null /etc/security/opasswd; : >"$STATE/backup/created-opasswd"; }
  pam-auth-update --enable legion-pwhistory
  if ! grep -q 'pam_pwhistory.so remember=24' /etc/pam.d/common-password; then
    pam-auth-update --disable legion-pwhistory || true
    rm -f /usr/share/pam-configs/legion-pwhistory
    warn "the password (PAM) files have local edits, so password history was not added"
    rc=1
  fi
  # Password age: changed at least every 90 days, at most once a day, with a
  # warning 7 days ahead. An account whose password expired 45 days ago is
  # disabled (800-171 3.5.6). New accounts get this from login.defs and
  # useradd; existing ones through chage. Their old values are kept for
  # legion-remove.sh.
  backup_once /etc/login.defs
  backup_once /etc/default/useradd
  set_def PASS_MAX_DAYS 90 /etc/login.defs
  set_def PASS_MIN_DAYS 1 /etc/login.defs
  set_def PASS_WARN_AGE 7 /etc/login.defs
  if grep -qE '^INACTIVE=' /etc/default/useradd; then
    sed -i -E 's/^INACTIVE=.*/INACTIVE=45/' /etc/default/useradd
  else
    echo INACTIVE=45 >>/etc/default/useradd
  fi
  # An existing password older than 76 days gets 14 more days, so nobody is
  # forced to change it in the middle of a session (sudo may refuse an
  # expired password until the next login).
  local today u last uid n=0 grace=0 accounts=()
  today=$(($(date +%s) / 86400))
  mapfile -t accounts < <(awk -F: '$2 !~ /^[!*]/ && $2 != "" { print $1 ":" $3 ":" $4 ":" $5 ":" $6 ":" $7 }' /etc/shadow)
  for u in "${accounts[@]}"; do
    IFS=: read -r u last _ <<<"$u"
    uid="$(id -u "$u" 2>/dev/null)" || continue
    [ "$uid" -ge 1000 ] && [ "$uid" -lt 60000 ] || continue
    grep -q "^${u}:" "$STATE/backup/chage" 2>/dev/null || grep "^${u}:" /etc/shadow | cut -d: -f1,3-7 >>"$STATE/backup/chage"
    if [ -n "$last" ] && [ "$last" -gt 0 ] && [ $((today - last)) -gt 76 ]; then
      chage -d "$(date -u -d "@$(((today - 76) * 86400))" +%F)" "$u"
      grace=$((grace + 1))
    fi
    chage -m 1 -M 90 -W 7 -I 45 "$u"
    n=$((n + 1))
  done
  info "$n accounts: passwords now expire every 90 days"
  [ "$grace" = 0 ] || info "$grace of them had a password older than 76 days and must change it within 14 days"
  return "$rc"
}

step_session() {
  # Idle text sessions (console, SSH) end after 15 minutes; graphical
  # sessions are covered by the screen lock (800-171 3.1.11).
  cat >/etc/profile.d/legion-session.sh <<'EOF'
# Legion Profile: idle console and SSH shells end after 15 minutes.
# Graphical sessions are covered by the screen lock instead.
if [ -z "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ] && [ "${TMOUT:-}" != 900 ]; then
  TMOUT=900
  readonly TMOUT
  export TMOUT
fi
EOF
  chmod 644 /etc/profile.d/legion-session.sh
  # New files are not readable by other users (umask 027, applied at login
  # by pam_umask). Commands run with sudo keep Ubuntu's usual umask, so
  # files installed as root stay readable, as before.
  backup_once /etc/login.defs
  set_def UMASK 027 /etc/login.defs
  # sudo: its own terminal for each command, the password again after 15
  # minutes, 3 tries. The file is checked before it is installed; a broken
  # sudoers file would lock everyone out of sudo.
  local tmp
  tmp="$(mktemp)"
  cat >"$tmp" <<'EOF'
# Legion Profile: sudo settings (CIS 5.2). Commands run in their own
# terminal, the password is asked again after 15 minutes, 3 tries are
# allowed, and commands keep Ubuntu's usual umask (022) whatever the user's
# own umask is.
Defaults use_pty
Defaults timestamp_timeout=15
Defaults passwd_tries=3
Defaults umask=0022
Defaults umask_override
EOF
  chmod 440 "$tmp"
  if visudo -c -q -f "$tmp" >/dev/null 2>&1; then
    install -m 440 -o root -g root "$tmp" /etc/sudoers.d/legion
    if ! visudo -c -q >/dev/null 2>&1; then
      rm -f /etc/sudoers.d/legion
      warn "sudo settings not added: the sudo configuration did not check out with them"
    fi
  else
    warn "sudo settings not added: this sudo does not accept them"
  fi
  rm -f "$tmp"
  # su is limited to members of an empty group, so only root can use it;
  # people use sudo instead (CIS 5.2.7). root itself is not affected.
  if [ -f /etc/pam.d/su ] && ! grep -qE '^auth[[:space:]]+required[[:space:]]+pam_wheel.so' /etc/pam.d/su; then
    if grep -qE '^auth[[:space:]]+sufficient[[:space:]]+pam_rootok.so' /etc/pam.d/su; then
      backup_once /etc/pam.d/su pam.d-su
      getent group legion-su >/dev/null || { groupadd -r legion-su; : >"$STATE/backup/created-group-legion-su"; }
      sed -i -E '0,/^auth[[:space:]]+sufficient[[:space:]]+pam_rootok.so.*/s//&\nauth       required   pam_wheel.so use_uid group=legion-su/' /etc/pam.d/su
    else
      warn "su not limited: /etc/pam.d/su has an unexpected layout"
    fi
  fi
  # No core dumps: they can hold passwords and keys from memory. Ubuntu's
  # crash reporter (apport) is turned off for the same reason (CIS 1.5).
  install -d -m 755 /etc/security/limits.d /etc/systemd/coredump.conf.d
  printf '# Legion Profile: no core dumps\n* hard core 0\n' >/etc/security/limits.d/legion.conf
  printf '# Legion Profile: no core dumps\n[Coredump]\nStorage=none\nProcessSizeMax=0\n' >/etc/systemd/coredump.conf.d/legion.conf
  if [ -f /etc/default/apport ]; then
    backup_once /etc/default/apport
    [ -e "$STATE/backup/apport-state" ] || systemctl is-enabled apport.service >"$STATE/backup/apport-state" 2>/dev/null || true
    sed -i -E 's/^enabled=.*/enabled=0/' /etc/default/apport
    systemctl disable --now apport.service 2>/dev/null || true
  fi
}

# SSH server hardening (CIS 5.1), only when an SSH server is installed.
# Password logins are left as they are, so nobody who logs in with a
# password is cut off. The settings are checked before sshd reloads them.
harden_ssh() {
  [ -x /usr/sbin/sshd ] && [ -d /etc/ssh/sshd_config.d ] || return 0
  local f=/etc/ssh/sshd_config.d/00-legion.conf root="no"
  # Someone logging in as root with a key keeps that ability.
  if [ -s /root/.ssh/authorized_keys ]; then
    root="prohibit-password"
    warn "SSH: root logs in with a key here, so root login stays allowed with keys only"
  fi
  cat >"$f" <<EOF
# Legion Profile: SSH server hardening (CIS 5.1). Password logins are left
# as they were.
Banner /etc/issue.net
PermitRootLogin $root
PermitEmptyPasswords no
HostbasedAuthentication no
IgnoreRhosts yes
MaxAuthTries 4
MaxStartups 10:30:60
MaxSessions 10
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 3
LogLevel VERBOSE
X11Forwarding no
EOF
  chmod 600 "$f"
  if sshd -t 2>/dev/null; then
    systemctl try-reload-or-restart ssh.service 2>/dev/null || true
    info "SSH server hardened"
  else
    rm -f "$f"
    warn "SSH server settings not changed: sshd did not accept them"
  fi
}

# The kernel settings Legion changes, saved once per setting before any step
# runs, so legion-remove.sh can put back the values this machine had. (The
# firewall and crash reporter steps change some of them too.) Later Legion
# versions add settings; those are saved on their first run.
save_sysctl_backup() {
  [ "$IN_CONTAINER" = 0 ] || return 0
  install -d -m 700 "$STATE/backup"
  local key
  for key in kernel.kptr_restrict fs.suid_dumpable fs.protected_fifos net.core.bpf_jit_harden \
    net.ipv4.conf.all.log_martians net.ipv4.conf.default.log_martians \
    net.ipv4.conf.all.send_redirects net.ipv4.conf.default.send_redirects \
    net.ipv6.conf.all.disable_ipv6 net.ipv6.conf.default.disable_ipv6 \
    kernel.dmesg_restrict kernel.yama.ptrace_scope kernel.randomize_va_space \
    net.ipv4.conf.all.accept_redirects net.ipv4.conf.default.accept_redirects \
    net.ipv4.conf.all.secure_redirects net.ipv4.conf.default.secure_redirects \
    net.ipv4.conf.all.accept_source_route net.ipv4.conf.default.accept_source_route \
    net.ipv4.icmp_echo_ignore_broadcasts net.ipv4.icmp_ignore_bogus_error_responses net.ipv4.tcp_syncookies \
    net.ipv6.conf.all.accept_redirects net.ipv6.conf.default.accept_redirects \
    net.ipv6.conf.all.accept_source_route net.ipv6.conf.default.accept_source_route; do
    grep -q "^$key=" "$STATE/backup/sysctl" 2>/dev/null || echo "$key=$(sysctl -n "$key" 2>/dev/null)" >>"$STATE/backup/sysctl"
  done
}

step_hardening() {
  # Low-risk subset of the Lynis/CIS kernel checks. Left alone on purpose:
  # ip_forward (Docker and VMs need it), rp_filter (VPNs), sysrq,
  # modules_disabled and unprivileged_bpf_disabled (Ubuntu's default is fine).
  # CIS 1.5 and 3.3. Left alone on purpose: ip_forward (Docker and VMs),
  # rp_filter (VPNs) and IPv6 router advertisements (IPv6 needs them).
  cat >/etc/sysctl.d/60-legion-hardening.conf <<'EOF'
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
kernel.randomize_va_space = 2
fs.suid_dumpable = 0
fs.protected_fifos = 2
net.core.bpf_jit_harden = 2
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
EOF
  if [ "$IN_CONTAINER" = 0 ]; then
    sysctl -q -p /etc/sysctl.d/60-legion-hardening.conf || warn "some kernel settings apply only after a reboot"
  fi
  # IPv6 off only when the user said it is not needed; a later run that keeps
  # IPv6 turns it back on.
  # The loopback interface keeps IPv6, since local services such as Postfix
  # expect ::1. NetworkManager turns IPv6 back on for a network when it
  # connects, so it is also set off in each saved Wi-Fi and wired connection
  # (their old settings are kept for legion-remove.sh).
  local uuid type method nmb="$STATE/backup/nm-ipv6"
  if [ "$IPV6" = 0 ]; then
    printf 'net.ipv6.conf.all.disable_ipv6 = 1\nnet.ipv6.conf.default.disable_ipv6 = 1\nnet.ipv6.conf.lo.disable_ipv6 = 0\n' >/etc/sysctl.d/60-legion-ipv6.conf
    [ "$IN_CONTAINER" = 1 ] || sysctl -q -p /etc/sysctl.d/60-legion-ipv6.conf || warn "IPv6 setting applies after a reboot"
    if command -v nmcli >/dev/null 2>&1; then
      install -d -m 700 "$STATE/backup"
      while IFS=: read -r uuid type; do
        case "$type" in 802-11-wireless | 802-3-ethernet) ;; *) continue ;; esac
        method="$(nmcli -g ipv6.method connection show "$uuid" 2>/dev/null || true)"
        [ "$method" = disabled ] && continue
        grep -q "^$uuid " "$nmb" 2>/dev/null || echo "$uuid ${method:-auto}" >>"$nmb"
        nmcli connection modify "$uuid" ipv6.method disabled || warn "could not change network connection $uuid"
      done < <(nmcli -t -f UUID,TYPE connection show 2>/dev/null || true)
    fi
    info "IPv6 turned off; Wi-Fi and wired connections pick this up when they next connect"
  elif [ -f /etc/sysctl.d/60-legion-ipv6.conf ]; then
    rm -f /etc/sysctl.d/60-legion-ipv6.conf
    [ "$IN_CONTAINER" = 1 ] || sysctl -q -w net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.default.disable_ipv6=0 || true
    if [ -f "$nmb" ] && command -v nmcli >/dev/null 2>&1; then
      while read -r uuid method; do nmcli connection modify "$uuid" ipv6.method "$method" 2>/dev/null || true; done <"$nmb"
      rm -f "$nmb"
    fi
    info "IPv6 turned back on"
  fi
  # Network protocols a laptop never uses; each has had kernel vulnerabilities.
  cat >/etc/modprobe.d/legion-uncommon-net.conf <<'EOF'
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
EOF
  # Filesystems a laptop does not need (CIS 1.1.1). Kept: squashfs (snaps),
  # overlay (Docker), vfat and exfat (USB drives and SD cards). A module
  # that is loaded right now stays loaded until the next reboot.
  cat >/etc/modprobe.d/legion-filesystems.conf <<'EOF'
install cramfs /bin/false
install freevxfs /bin/false
install hfs /bin/false
install hfsplus /bin/false
install jffs2 /bin/false
install udf /bin/false
EOF
  harden_ssh
  [ ! -f /etc/crontab ] || chmod 600 /etc/crontab
  local d
  for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /etc/cron.yearly; do
    [ ! -d "$d" ] || chmod 700 "$d"
  done
  [ ! -d /etc/sudoers.d ] || chmod 750 /etc/sudoers.d
  # A mail server only needs to accept mail from this device (CIS: mail
  # transfer agent in local-only mode). Local mail, such as cron reports,
  # keeps working. The old setting is kept for legion-remove.sh.
  if command -v postconf >/dev/null 2>&1 && [ -f /etc/postfix/main.cf ]; then
    local mta
    mta="$(postconf -h inet_interfaces 2>/dev/null || true)"
    if [ -n "$mta" ] && [ "$mta" != loopback-only ]; then
      install -d -m 700 "$STATE/backup"
      [ -f "$STATE/backup/postfix-inet_interfaces" ] || printf '%s\n' "$mta" >"$STATE/backup/postfix-inet_interfaces"
      postconf -e 'inet_interfaces = loopback-only'
      systemctl restart postfix 2>/dev/null || true
      info "mail server (Postfix) now accepts connections from this device only"
    fi
  fi
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
umask 027
export LC_ALL=C.UTF-8
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
# Sandboxed (Legion tamper protection): system and home folders read-only,
# no privilege gain, kernel settings read-only.
NoNewPrivileges=yes
# No private /tmp: the scan must see the real /tmp, /var/tmp and /dev/shm.
ProtectSystem=full
ProtectHome=read-only
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
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

step_sigma() {
  # Threat detection: every 15 minutes the new audit events are checked
  # against the Sigma rules for Linux audit logs (SigmaHQ), with Zircolite.
  # Each alert names the user, the program and the command, and the program
  # (or the file it wrote) is scanned with YARA. Alerts go to the system log,
  # so they reach the log server too, and to /var/log/legion/sigma-alerts.log.
  local ver=4.7.1 dir=/opt/legion/zircolite zip_arch sha tmp
  case "$ARCH" in
    x86_64) zip_arch=x64 sha=f09d3ba377ef0bf4899bba71b63ffca38d714f71765a716e46ad3549da5e316a ;;
    aarch64) zip_arch=arm64 sha=9c76c902a5d0709d67a1c3176bfa30b50d14950ae7fae5122c2b96341dbb28ed ;;
    *) warn "Zircolite has no build for $ARCH; skipping threat detection"; return 0 ;;
  esac
  apt-get "${APT[@]}" install curl unzip python3
  install -d -m 755 /opt/legion
  install -d -m 700 "$STATE/sigma"
  [ -d /etc/legion ] || install -d -m 755 /etc/legion
  if [ "$(cat "$dir/VERSION" 2>/dev/null)" != "$ver" ]; then
    tmp="$(mktemp -d)"
    # A pinned release, checked against its published SHA-256 before use.
    if ! curl -fsSL --retry 3 -o "$tmp/z.zip" \
      "https://github.com/wagga40/Zircolite/releases/download/v$ver/Zircolite-$ver-linux-$zip_arch.zip"; then
      rm -rf "$tmp"; echo "could not download Zircolite $ver" >&2; return 1
    fi
    if ! echo "$sha  $tmp/z.zip" | sha256sum -c --quiet; then
      rm -rf "$tmp"; echo "Zircolite download does not match its checksum; not installed" >&2; return 1
    fi
    unzip -q "$tmp/z.zip" -d "$tmp/x"
    rm -rf "$dir.new"
    mv "$tmp/x/Zircolite-$ver-linux-$zip_arch" "$dir.new"
    echo "$ver" >"$dir.new/VERSION"
    chown -R root:root "$dir.new"
    chmod -R go-w "$dir.new"
    rm -rf "$dir"
    mv "$dir.new" "$dir"
    rm -rf "$tmp"
  fi
  # Only the rules written for Linux audit logs, medium level and up: the
  # others need sensors this device does not have, and low-level rules flag
  # everyday admin commands.
  python3 -I - "$dir/rules/rules_linux.json" "$STATE/sigma/rules.json" <<'PY'
import json, sys
rules = json.load(open(sys.argv[1]))
keep = [r for r in rules
        if r.get("logsource", {}).get("service") == "auditd"
        and r.get("level") in ("medium", "high", "critical")]
json.dump(keep, open(sys.argv[2], "w"))
print(len(keep), "rules")
PY
  chmod 600 "$STATE/sigma/rules.json"
  [ -f /etc/legion/sigma-ignore ] || cat >/etc/legion/sigma-ignore <<'EOF'
# Sigma rules to ignore on this device, one rule title per line, exactly as
# it appears in /var/log/legion/sigma-alerts.log. Lines starting with # are
# ignored. Example:
# Unix Shell Configuration Modification
EOF
  cat >/usr/local/sbin/legion-sigma-scan <<'EOF'
#!/usr/bin/env bash
# Checks the audit events since the last check against the Sigma rules.
#   legion-sigma-scan                 check new events (run by the timer)
#   legion-sigma-scan --mark-reviewed skip everything logged so far
# Exits 1 when there are new alerts, so the systemd unit shows as failed.
set -uo pipefail
umask 027
export LC_ALL=C.UTF-8
DIR=/var/lib/legion/sigma
ZIRC=/opt/legion/zircolite/Zircolite
[ -s /var/log/audit/audit.log ] || { echo "no audit log yet"; exit 0; }
search() { ausearch --input-logs --checkpoint "$DIR/checkpoint" --raw "$@" 2>/dev/null; }
if [ "${1:-}" = --mark-reviewed ]; then
  search >/dev/null
  rc=$?
  [ "$rc" -lt 10 ] || { rm -f "$DIR/checkpoint"; search >/dev/null; }
  exit 0
fi
# Legion's own runs change watched files on purpose. Skip while it runs; at
# the end of a run Legion marks its own changes as reviewed.
flock -n /run/legion.lock true || { echo "Legion is running; checking next time"; exit 0; }
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
search >"$work/events.log"
rc=$?
if [ "$rc" -ge 10 ]; then
  # The checkpoint is damaged or its event was rotated away: start over from
  # the last few minutes rather than read every log again.
  rm -f "$DIR/checkpoint"
  search -ts recent >"$work/events.log"
fi
date -u +%FT%TZ >"$DIR/last"
[ -s "$work/events.log" ] || exit 0
cd "$work" || exit 2
if ! "$ZIRC" --auditd -e "$work/events.log" -r "$DIR/rules.json" -o "$work/found.json" -q >"$work/zircolite.out" 2>&1; then
  echo "Zircolite failed:" >&2; tail -n 20 "$work/zircolite.out" >&2; exit 2
fi
[ -s "$work/found.json" ] || exit 0
exec python3 -I /usr/local/lib/legion/sigma-alerts.py "$work/events.log" "$work/found.json"
EOF
  install -d -m 755 /usr/local/lib/legion
  cat >/usr/local/lib/legion/sigma-alerts.py <<'EOF'
"""Turns Zircolite matches into Legion alerts: adds the user, program and
command from the same audit event, scans the program or file with YARA, and
writes each alert to the system log and to /var/log/legion/sigma-alerts.log.
Exits 1 when there is at least one new alert."""
import calendar, json, os, pwd, re, subprocess, sys, syslog, time

events_file, found_file = sys.argv[1], sys.argv[2]
LOG = "/var/log/legion/sigma-alerts.log"
YARA_RULES = "/var/lib/legion/yara/rules.yarc"
# Package installs and updates change watched files as part of their job.
PACKAGE_TOOLS = {"/usr/bin/dpkg", "/usr/bin/apt", "/usr/bin/apt-get", "/usr/lib/snapd/snapd",
                 "/usr/bin/snap", "/usr/libexec/packagekitd", "/usr/libexec/fwupd/fwupd"}
FIELD = re.compile(r'(\w+)=("[^"]*"|\S+)')
SERIAL = re.compile(r"msg=audit\((\d+)\.\d+:(\d+)\)")

def fields(line):
    out = {}
    for k, v in FIELD.findall(line):
        if v.startswith('"'):
            v = v[1:-1]
        elif (k.startswith("a") and k[1:].isdigit() and line.startswith("type=EXECVE ")) or k == "proctitle":
            try:  # arguments with spaces are logged as hex
                v = bytes.fromhex(v).decode(errors="replace").replace("\0", " ")
            except ValueError:
                pass
        out[k] = v
    return out

lines = open(events_file, errors="replace").read().splitlines()
calls, commands, records = {}, {}, {}
for line in lines:
    m = SERIAL.search(line)
    if not m:
        continue
    rtype = line[5:line.find(" ")]
    # Zircolite drops underscores from field names (cap_fp becomes capfp).
    records.setdefault(rtype, []).append(({k.replace("_", ""): v for k, v in fields(line).items()}, m.group(1), m.group(2)))
    if line.startswith("type=SYSCALL "):
        calls.setdefault(m.group(2), {}).update(fields(line))
    elif line.startswith("type=CWD "):
        calls.setdefault(m.group(2), {})["cwd"] = fields(line).get("cwd", "")
    elif line.startswith("type=EXECVE "):
        f = fields(line)
        commands[m.group(2)] = " ".join(f.get(f"a{i}", "") for i in range(int(f.get("argc", 0) or 0)))

# Time windows of Legion's own runs: its changes are not attacks.
quiet = []
try:
    for l in open("/var/lib/legion/sigma/quiet"):
        a, b = l.split()
        quiet.append((int(a), int(b)))
except (OSError, ValueError):
    pass

# Zircolite reports the matching record's fields; find that record in the
# input to learn its audit event (and so the program, user and command).
SKIP = {"row_id", "OriginalLogfile", "host", "timestamp", "type"}
def locate(m):
    want = {k.replace("_", ""): str(v) for k, v in m.items() if k not in SKIP and v not in (None, "")}
    try:  # Zircolite's timestamp is the event time in UTC, to the second
        sec = str(calendar.timegm(time.strptime(m.get("timestamp", ""), "%Y-%m-%d %H:%M:%S")))
    except ValueError:
        sec = None
    best, best_score = (None, None), 0
    for f, epoch, serial in records.get(m.get("type", ""), []):
        score = sum(f.get(k) == v for k, v in want.items())
        if score == len(want):
            return epoch, serial
        # A field Zircolite reformatted: take the closest record of that second.
        if sec == epoch and score > best_score and score >= 0.7 * len(want):
            best, best_score = (epoch, serial), score
    if best[1] is None:
        # Record why, to tune the matching: the fields that differed from the
        # closest record of the same type.
        near = max(records.get(m.get("type", ""), [({}, 0, 0)]), key=lambda r: sum(r[0].get(k) == v for k, v in want.items()))[0]
        diff = {k: [v, near.get(k)] for k, v in want.items() if near.get(k) != v}
        try:
            with open("/var/lib/legion/sigma/unmatched.log", "a") as f:
                f.write(json.dumps({"type": m.get("type"), "timestamp": m.get("timestamp"), "differs": diff}) + "\n")
        except OSError:
            pass
    return best

ignore = set()
try:
    for t in open("/etc/legion/sigma-ignore"):
        t = t.strip()
        if t and not t.startswith("#"):
            ignore.add(t)
except OSError:
    pass

def user(uid):
    try:
        return pwd.getpwuid(int(uid)).pw_name
    except (ValueError, KeyError):
        return "unset" if uid in ("4294967295", "-1") else uid

def yara(path):
    if not os.path.exists(YARA_RULES):
        return "YARA not set up"
    if not path or not os.path.isfile(path):
        return "no file to scan"
    if os.path.getsize(path) > 64 * 1024 * 1024:
        return "file over 64 MB, not scanned"
    r = subprocess.run(["yara", "-C", "-w", "-N", YARA_RULES, path], capture_output=True, text=True)
    if r.returncode != 0:
        return "YARA failed: " + r.stderr.strip()[:200]
    hits = sorted({l.split()[0] for l in r.stdout.splitlines() if l.strip()})
    return "YARA match: " + ", ".join(hits) if hits else "YARA: no match"

alerts, seen = [], set()
for d in json.load(open(found_file)):
    title = d.get("title", "")
    if title in ignore:
        continue
    for m in d.get("matches", []):
        epoch, serial = locate(m)
        if serial is None:
            serial = "row " + str(m.get("row_id"))
        elif any(a <= int(epoch) <= b for a, b in quiet):
            continue
        if (title, serial) in seen:
            continue
        seen.add((title, serial))
        # Without the full event, a SYSCALL match still carries its own user,
        # program and process.
        call = calls.get(serial) or (m if m.get("type") == "SYSCALL" else {})
        exe = call.get("exe", m.get("exe", ""))
        if exe in PACKAGE_TOOLS:
            continue
        # One program run can match a rule on many system calls: one alert.
        run = (title, exe, call.get("pid", ""))
        if exe and call.get("pid") and run in seen:
            continue
        seen.add(run)
        target = m.get("name") if m.get("type") == "PATH" else exe
        if target and not target.startswith("/") and call.get("cwd"):
            target = os.path.join(call["cwd"], target)
        alerts.append({
            "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(epoch))) if epoch else m.get("timestamp"),
            "level": d.get("rule_level", ""),
            "rule": title,
            "rule_id": d.get("id", ""),
            "attack": [t for t in d.get("tags", []) if t.startswith("attack.")],
            "user": user(call.get("auid", "")),
            "runs_as": user(call.get("euid", "")),
            "program": exe,
            "command": commands.get(serial, ""),
            "file": m.get("name", "") if m.get("type") == "PATH" else "",
            "pid": call.get("pid", ""),
            "audit_event": serial,
            "yara": yara(target),
        })

if not alerts:
    sys.exit(0)
syslog.openlog("legion-sigma", 0, syslog.LOG_AUTHPRIV)
with open(LOG, "a") as f:
    for a in alerts:
        f.write(json.dumps(a) + "\n")
        prio = syslog.LOG_CRIT if a["level"] in ("high", "critical") or a["yara"].startswith("YARA match") else syslog.LOG_WARNING
        what = a["command"] or a["file"] or a["program"]
        syslog.syslog(prio, f'Sigma alert ({a["level"]}): {a["rule"]}; user {a["user"]}, '
                            f'program {a["program"]}, {what}; {a["yara"]}')
        print(f'{a["time"]} {a["level"]}: {a["rule"]} | {a["user"]} | {what} | {a["yara"]}')
sys.exit(1)
EOF
  chmod 750 /usr/local/sbin/legion-sigma-scan
  chmod 644 /usr/local/lib/legion/sigma-alerts.py
  touch "$LOGDIR/sigma-alerts.log"
  chmod 640 "$LOGDIR/sigma-alerts.log"
  cat >/etc/systemd/system/legion-sigma-scan.service <<'EOF'
[Unit]
Description=Check new audit events against the Sigma rules
After=auditd.service
[Service]
# Sandboxed (Legion tamper protection): system and home folders read-only,
# no privilege gain, kernel settings read-only.
NoNewPrivileges=yes
# No private /tmp: dropped tools land in /tmp, /var/tmp and /dev/shm.
ProtectSystem=full
ProtectHome=read-only
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
Type=oneshot
Nice=10
IOSchedulingClass=idle
MemoryHigh=1G
ExecStart=/usr/local/sbin/legion-sigma-scan
EOF
  cat >/etc/systemd/system/legion-sigma-scan.timer <<'EOF'
[Unit]
Description=Check new audit events against the Sigma rules every 15 minutes
[Timer]
OnBootSec=5min
OnUnitActiveSec=15min
AccuracySec=1min
[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now legion-sigma-scan.timer
  info "Zircolite $ver, $(python3 -I -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' "$STATE/sigma/rules.json") Sigma rules for audit logs"
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
  # Without recommended packages: aide-common pulls in a mail client and with
  # it Postfix, a mail server. Legion uses its own AIDE setup and needs neither.
  apt-get "${APT[@]}" install --no-install-recommends aide
  # Stop it before masking; masking a running timer leaves it "failed".
  install -d -m 700 "$STATE/backup"
  [ -e "$STATE/backup/dailyaidecheck-state" ] ||
    systemctl is-enabled dailyaidecheck.timer >"$STATE/backup/dailyaidecheck-state" 2>/dev/null || true
  systemctl disable --now dailyaidecheck.timer >/dev/null 2>&1 || true
  systemctl mask dailyaidecheck.timer >/dev/null 2>&1 || true
  systemctl reset-failed dailyaidecheck.timer >/dev/null 2>&1 || true
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
/var/spool/cron Legion
# In /root, only what changes how root logs in or starts programs; history,
# cache and editor files change whenever an admin uses a root shell.
/root/\.ssh Legion
/root/\.(bashrc|profile|bash_profile|bash_login|bash_logout)$ Legion
/root/\.config/autostart Legion

# Change in normal use
!/etc/mtab$
!/etc/adjtime$
!/etc/ld\.so\.cache$
!/etc/\.pwd\.lock$
!/etc/cups/subscriptions\.conf
!/etc/cups/.*\.O$
!/etc/NetworkManager/system-connections
!/boot/grub/grubenv$
EOF
  cat >/usr/local/sbin/legion-aide-baseline <<'EOF'
#!/usr/bin/env bash
# Records the current state as the AIDE baseline and logs what changed.
#   legion-aide-baseline apt                after a package operation (apt hook)
#   legion-aide-baseline "legion run" TIME  at the end of a Legion run
#   legion-aide-baseline manual             you reviewed the changes: accept all
# For apt and Legion runs, only changes made during that operation (file
# change time at or after its start) are accepted silently. Anything changed
# earlier was not made by it, so it goes on the pending list, and the daily
# check fails until someone reviews it and runs: legion-aide-baseline manual
set -uo pipefail
umask 027
export LC_ALL=C.UTF-8
CONF=/etc/legion/aide.conf
DB=/var/lib/legion/aide/aide.db
PENDING=/var/lib/legion/aide/pending
LOG=/var/log/legion/integrity.log
why="${1:-manual}" since="${2:-}"
if [ "$why" = apt ]; then
  since="$(cat /run/legion-apt-start 2>/dev/null || echo $(($(date +%s) - 900)))"
  rm -f /run/legion-apt-start
  # During a Legion run, Legion's own earlier changes count as made by it.
  r="$(cat /run/legion-run-start 2>/dev/null || true)"
  [ -z "$r" ] || [ "$r" -ge "$since" ] || since="$r"
fi
if [ ! -f "$DB" ]; then
  out="$(aide --config="$CONF" --init 2>&1)" || { echo "$out" >&2; exit 2; }
  echo "== $(date -u +%FT%TZ) baseline created ($why)" >>"$LOG"
  mv -f "$DB.new" "$DB"
  exit 0
fi
if [ "$why" = manual ]; then
  rm -f "$PENDING"
elif [ -n "$since" ]; then
  # Changed, added or removed paths since the last baseline.
  aide --config="$CONF" --check 2>/dev/null | sed -nE 's/^[a-z?!][^:]*: (\/.*)$/\1/p' | sort -u |
    while read -r p; do
      if [ -e "$p" ] || [ -L "$p" ]; then t="$(stat -c %Z "$p" 2>/dev/null || echo 0)"
      else t="$(stat -c %Z "$(dirname "$p")" 2>/dev/null || echo 0)"; fi
      [ "$t" -ge "$since" ] || echo "$p"
    done >>"$PENDING.new"
  if [ -s "$PENDING.new" ]; then
    { [ ! -f "$PENDING" ] || cat "$PENDING"; cat "$PENDING.new"; } | sort -u >"$PENDING.tmp"
    mv -f "$PENDING.tmp" "$PENDING"
    { echo "== $(date -u +%FT%TZ) changes not made by this $why, kept for review:"; cat "$PENDING.new"; } >>"$LOG"
  fi
  rm -f "$PENDING.new"
fi
out="$(aide --config="$CONF" --update 2>&1)"
rc=$?
[ "$rc" -lt 14 ] || { echo "$out" >&2; exit 2; }
if [ "$rc" != 0 ]; then
  { echo "== $(date -u +%FT%TZ) baseline refreshed ($why); these changes were accepted:"; echo "$out"; } >>"$LOG"
fi
mv -f "$DB.new" "$DB"
EOF
  cat >/usr/local/sbin/legion-integrity-check <<'EOF'
#!/usr/bin/env bash
# Daily integrity check. Exits 1 when a package file or an AIDE-watched file
# changed, so the systemd unit shows as failed; exits 2 if a check can't run.
set -uo pipefail
umask 027
export LC_ALL=C.UTF-8
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
# Changes found when a package operation or Legion run refreshed the baseline,
# but not made by it: they stay reported until reviewed.
if [ -s /var/lib/legion/aide/pending ]; then
  { echo "changes not made by a package update, not yet reviewed:"; cat /var/lib/legion/aide/pending
    echo "review them, then accept with: sudo legion-aide-baseline manual"; } | tee -a "$LOG"
  status=1
fi
exit "$status"
EOF
  chmod 750 /usr/local/sbin/legion-aide-baseline /usr/local/sbin/legion-integrity-check
  # Refresh the AIDE baseline after every package change, logging the changes.
  cat >/etc/apt/apt.conf.d/99legion-aide <<'EOF'
DPkg::Pre-Invoke { "[ -e /run/legion-apt-start ] || date +%s >/run/legion-apt-start || true"; };
DPkg::Post-Invoke { "if [ -x /usr/local/sbin/legion-aide-baseline ] && [ -f /var/lib/legion/aide/aide.db ]; then /usr/local/sbin/legion-aide-baseline apt || true; fi"; };
EOF
  cat >/etc/systemd/system/legion-integrity.service <<'EOF'
[Unit]
Description=Daily integrity check (package checksums and AIDE)
[Service]
# Sandboxed (Legion tamper protection): system and home folders read-only,
# no privilege gain, private /tmp, kernel settings read-only.
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ProtectHome=read-only
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
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
  /usr/local/sbin/legion-aide-baseline install "$LEGION_START"
  systemctl enable --now legion-integrity.timer
  info "AIDE baseline recorded"
}

step_tools() {
  local before p
  before=" $(dpkg-query -W -f '${Package} ' 2>/dev/null) "
  local missing_all=""
  install_available lynis gitleaks pre-commit shellcheck python3-venv python3-pip deja-dup
  missing_all="$MISSING"
  if command -v snap >/dev/null 2>&1; then
    if ! snap list bitwarden >/dev/null 2>&1; then
      if snap install bitwarden; then BITWARDEN_NEW=1; else missing_all="$missing_all bitwarden"; fi
    fi
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
  # Record what this run installed, for legion-remove.sh --remove-packages.
  for p in lynis gitleaks pre-commit shellcheck python3-venv python3-pip deja-dup terraform trivy; do
    [[ "$before" == *" $p "* ]] || ! dpkg -s "$p" >/dev/null 2>&1 || echo "apt $p" >>"$STATE/installed-tools"
  done
  if [ -n "${BITWARDEN_NEW:-}" ]; then echo "snap bitwarden" >>"$STATE/installed-tools"; fi
  [ -z "$missing_all" ] || warn "not installed:$missing_all"
}

step_login() {
  # Login banner (NIST AC-8, 800-171 3.1.9) and an enforced screen lock
  # (HIPAA automatic logoff, NIST AC-11, 800-171 3.1.10). Originals are kept in
  # $STATE/backup so legion-remove.sh can put them back.
  local text="Authorized use only. Activity on this device may be monitored and recorded."
  install -d -m 700 "$STATE/backup"
  local f
  for f in /etc/issue /etc/issue.net; do
    [ -e "$STATE/backup/${f##*/}" ] || [ -e "$STATE/backup/${f##*/}.absent" ] ||
      cp -p "$f" "$STATE/backup/${f##*/}" 2>/dev/null || : >"$STATE/backup/${f##*/}.absent"
  done
  # Console login: the full Legion banner with the Ubuntu logo. SSH login
  # (issue.net, shown only if sshd's Banner points at it): the lettering and
  # text without color, since SSH clients show it unprocessed.
  issue_banner "$text" >/etc/issue
  { echo; printf '  %s\n' "${LEGION_ART[@]}"; printf '\n  %s\n\n' "$text"; } >/etc/issue.net
  info "login banner set for the console and remote logins"
  if [ ! -f /usr/share/glib-2.0/schemas/org.gnome.desktop.screensaver.gschema.xml ] || ! command -v dconf >/dev/null; then
    info "no GNOME desktop found; login screen banner and screen lock skipped"
    return 0
  fi
  install -d -m 755 /etc/dconf/profile /etc/dconf/db/local.d/locks /etc/dconf/db/gdm.d
  # Login screen banner. On Ubuntu, GDM builds its login-screen settings at
  # every start from /usr/share/gdm/dconf, which links to
  # /etc/gdm3/greeter.dconf-defaults: the supported place for a banner. (GDM 50
  # no longer reads the "gdm" dconf profile that earlier Legion versions used;
  # those leftover files are removed here.)
  if [ -f "$STATE/backup/created-dconf-profile-gdm" ]; then
    rm -f /etc/dconf/profile/gdm "$STATE/backup/created-dconf-profile-gdm"
  fi
  rm -f /etc/dconf/db/gdm.d/01-legion-banner
  local g=/etc/gdm3/greeter.dconf-defaults logo="" asset
  # The LEGION logo image for the login screen ships next to legion.sh.
  asset="$(dirname "$SELF_PATH")/assets/legion-login-logo.png"
  if [ -f "$g" ] && [ -f "$asset" ]; then
    install -d -m 755 /usr/local/share/legion
    install -m 644 "$asset" /usr/local/share/legion/login-logo.png
    logo=/usr/local/share/legion/login-logo.png
  elif [ -f "$g" ] && [ -f /usr/local/share/legion/login-logo.png ]; then
    logo=/usr/local/share/legion/login-logo.png # installed copy, kept on re-runs
  fi
  if [ -f "$g" ]; then
    backup_once "$g" gdm3-greeter.dconf-defaults
    awk -v text="$text" -v logo="$logo" '
      /^#? *(banner-message-(enable|text)|disable-user-list)=/ && insec { next }
      /^logo=/ && insec { next }
      /^\[/ { insec = ($0 == "[org/gnome/login-screen]") }
      { print }
      insec && $0 == "[org/gnome/login-screen]" {
        print "banner-message-enable=true"
        print "banner-message-text=\x27" text "\x27"
        print "disable-user-list=true"
        if (logo != "") print "logo=\x27" logo "\x27"
        done = 1
      }
      END {
        if (!done) {
          print ""; print "[org/gnome/login-screen]"
          print "banner-message-enable=true"; print "banner-message-text=\x27" text "\x27"
          print "disable-user-list=true"
          if (logo != "") print "logo=\x27" logo "\x27"
        }
      }' "$g" >"$g.legion" && cat "$g.legion" >"$g" && rm -f "$g.legion"
    # The login screen also stops listing user names (CIS 1.7): people type
    # their user name. Rebuild GDM's settings now, so the next login screen
    # shows all this.
    [ ! -x /usr/share/gdm/generate-config ] || /usr/share/gdm/generate-config || true
    if [ -n "$logo" ]; then info "login screen banner and LEGION logo set"; else info "login screen banner set (logo image not found next to legion.sh)"; fi
  else
    info "no GDM login screen found; graphical login banner skipped"
  fi
  # Screen lock after 10 minutes idle, locked immediately, and users cannot
  # turn it off (dconf locks). 10 minutes meets CIS, DISA STIG and CMMC.
  if [ ! -f /etc/dconf/profile/user ]; then
    printf 'user-db:user\nsystem-db:local\n' >/etc/dconf/profile/user
    : >"$STATE/backup/created-dconf-profile-user"
  fi
  if grep -qx 'system-db:local' /etc/dconf/profile/user; then
    cat >/etc/dconf/db/local.d/00-legion-screenlock <<'EOF'
[org/gnome/desktop/session]
idle-delay=uint32 600

[org/gnome/desktop/screensaver]
lock-enabled=true
lock-delay=uint32 0
EOF
    cat >/etc/dconf/db/local.d/locks/00-legion-screenlock <<'EOF'
/org/gnome/desktop/session/idle-delay
/org/gnome/desktop/screensaver/lock-enabled
/org/gnome/desktop/screensaver/lock-delay
EOF
    info "screen locks after 10 minutes idle; users cannot turn this off"
    # Inserted USB drives and discs never start programs by themselves
    # (CIS 1.7, 800-171 3.8.7). Drives still mount as usual.
    cat >/etc/dconf/db/local.d/00-legion-media <<'EOF'
[org/gnome/desktop/media-handling]
autorun-never=true
EOF
    echo /org/gnome/desktop/media-handling/autorun-never >/etc/dconf/db/local.d/locks/00-legion-media
  else
    warn "custom user settings profile found; screen lock not enforced"
  fi
  dconf update
}

step_lockout() {
  # Locks an account for 30 minutes after 5 failed logins within 15 minutes,
  # then it unlocks by itself (NIST AC-7, 800-171 3.1.8). root is not locked,
  # so recovery stays possible. Added through pam-auth-update, Ubuntu's
  # supported way to change login settings; never by editing PAM files.
  local args="deny=5 fail_interval=900 unlock_time=1800 audit"
  cat >/usr/share/pam-configs/legion-faillock <<EOF
Name: Legion Profile: lock an account for 30 minutes after 5 failed logins
Default: yes
Priority: 0
Auth-Type: Primary
Auth:
	[default=die]	pam_faillock.so authfail $args
EOF
  cat >/usr/share/pam-configs/legion-faillock-notify <<EOF
Name: Legion Profile: check and reset failed login counts
Default: yes
Priority: 1024
Auth-Type: Primary
Auth:
	requisite	pam_faillock.so preauth $args
Account-Type: Primary
Account:
	required	pam_faillock.so
EOF
  pam-auth-update --enable legion-faillock legion-faillock-notify
  if grep -q 'pam_faillock.so preauth' /etc/pam.d/common-auth && grep -q 'pam_faillock.so authfail' /etc/pam.d/common-auth; then
    info "5 failed logins lock an account for 30 minutes; unlock sooner with: sudo faillock --user NAME --reset"
  else
    # pam-auth-update leaves locally edited PAM files alone. Undo cleanly.
    pam-auth-update --disable legion-faillock legion-faillock-notify || true
    rm -f /usr/share/pam-configs/legion-faillock /usr/share/pam-configs/legion-faillock-notify
    warn "the login (PAM) files have local edits, so the lockout was not added"
    return 1
  fi
}

step_compliance() {
  # SCAP tooling: when CIS / DISA STIG content for this Ubuntu release is
  # published in ssg-debderived, the compliance check runs it automatically.
  install_available openscap-scanner ssg-debderived
  # Install Legion itself so checks can run without the repository.
  if [ "$SELF_PATH" != /usr/local/sbin/legion ]; then install -m 755 "$SELF_PATH" /usr/local/sbin/legion; fi
  cat >/etc/systemd/system/legion-check.service <<'EOF'
[Unit]
Description=Daily Legion Profile compliance check
[Service]
# Sandboxed (Legion tamper protection): system and home folders read-only,
# no privilege gain, private /tmp, kernel settings read-only.
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ProtectHome=read-only
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
Type=oneshot
Nice=19
IOSchedulingClass=idle
Environment=NO_COLOR=1 LEGION_NO_ANIM=1
ExecStart=/usr/local/sbin/legion --drift-only
EOF
  cat >/etc/systemd/system/legion-check.timer <<'EOF'
[Unit]
Description=Daily Legion Profile compliance check
[Timer]
OnCalendar=*-*-* 06:30
RandomizedDelaySec=30m
Persistent=true
[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now legion-check.timer
  info "installed as 'legion'; a daily check at 06:30 flags any check that starts failing"
  # Weekly vulnerability scan (800-171 3.11.2): Ubuntu's security notices
  # (OVAL), checked against the installed packages with OpenSCAP. Lists the
  # known vulnerabilities on this device with their CVE numbers. A finding
  # fails the service, like the malware scans.
  command -v oscap >/dev/null || { warn "OpenSCAP not available; vulnerability scan skipped"; return 0; }
  cat >/usr/local/sbin/legion-vuln-scan <<'EOF'
#!/bin/bash
# Legion Profile: weekly vulnerability scan with Ubuntu's OVAL data.
set -euo pipefail
. /etc/os-release
dir=/var/lib/legion/oval log=/var/log/legion
install -d -m 700 "$dir"
url="https://security-metadata.canonical.com/oval/com.ubuntu.${VERSION_CODENAME}.usn.oval.xml.bz2"
python3 -I -c '
import bz2, shutil, sys, urllib.request
urllib.request.urlretrieve(sys.argv[1], sys.argv[2] + ".bz2.new")
with bz2.open(sys.argv[2] + ".bz2.new") as src, open(sys.argv[2] + ".new", "wb") as dst:
    shutil.copyfileobj(src, dst)' "$url" "$dir/usn.oval.xml"
rm -f "$dir/usn.oval.xml.bz2.new"
mv -f "$dir/usn.oval.xml.new" "$dir/usn.oval.xml"
rc=0
oscap oval eval --results "$dir/results.xml" --report "$log/vuln-report.html" "$dir/usn.oval.xml" >"$dir/eval.txt" 2>&1 || rc=$?
if [ "$rc" -gt 2 ] || ! grep -q '^Definition ' "$dir/eval.txt"; then
  echo "the OVAL scan did not run (oscap exit $rc); see $dir/eval.txt"
  exit 2
fi
# Security notices (class "patch") that apply, by number and title. Other
# true definitions, such as "this is Ubuntu 26.04", are not findings.
python3 -I -c '
import re, sys
import xml.etree.ElementTree as ET
hits = set(re.findall(r"^Definition (\S+): true$", open(sys.argv[2]).read(), re.M))
ns = {"o": "http://oval.mitre.org/XMLSchema/oval-definitions-5"}
for d in ET.parse(sys.argv[1]).getroot().iterfind(".//o:definition", ns):
    if d.get("id") in hits and d.get("class") == "patch":
        print(d.findtext("o:metadata/o:title", "", ns).strip())' "$dir/usn.oval.xml" "$dir/eval.txt" | sort >"$log/vuln-scan.txt"
chmod 640 "$log/vuln-report.html" "$log/vuln-scan.txt"
n="$(grep -c . "$log/vuln-scan.txt" || true)"
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $n" >"$dir/last"
if [ "$n" -gt 0 ]; then
  echo "$n Ubuntu security notice(s) apply to installed packages; see $log/vuln-report.html"
  exit 1
fi
echo "no known vulnerabilities in installed packages"
EOF
  chmod 750 /usr/local/sbin/legion-vuln-scan
  cat >/etc/systemd/system/legion-vuln-scan.service <<'EOF'
[Unit]
Description=Weekly Legion Profile vulnerability scan (Ubuntu OVAL)
Wants=network-online.target
After=network-online.target
[Service]
# Sandboxed (Legion tamper protection): system and home folders read-only,
# no privilege gain, private /tmp, kernel settings read-only.
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ProtectHome=read-only
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
Type=oneshot
Nice=19
IOSchedulingClass=idle
ExecStart=/usr/local/sbin/legion-vuln-scan
EOF
  cat >/etc/systemd/system/legion-vuln-scan.timer <<'EOF'
[Unit]
Description=Weekly Legion Profile vulnerability scan (Ubuntu OVAL)
[Timer]
OnCalendar=Sat 04:00
RandomizedDelaySec=1h
Persistent=true
[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable legion-vuln-scan.timer
  systemctl start legion-vuln-scan.timer
  # The first scan runs now, in the background.
  [ -f /var/lib/legion/oval/last ] || systemctl start --no-block legion-vuln-scan.service
  info "weekly vulnerability scan set up; the first one is running now"
}

if [ "$READONLY" = 0 ]; then
  section "Deploying profile"
  save_sysctl_backup
  [ "$WITH_PRO" = 0 ] || run_step "Ubuntu Pro: ESM security updates and Livepatch" step_pro
  run_step "Patching: install all pending updates" step_patching
  PATCH_FAILED=0
  [ "${RESULTS[${#RESULTS[@]} - 1]%%|*}" = ok ] || PATCH_FAILED=1
  run_step "NVIDIA driver ready for the new kernel" step_nvidia
  run_step "Automatic security updates" step_auto_updates
  run_step "Firewall: block inbound, allow outbound" step_firewall
  run_step "Log retention: 1 year, capped at 2 GB" step_logs
  run_step "Malware protection: ClamAV, weekly scan of /home" step_clamav
  run_step "Passwords: 12+ characters, last 24 refused, 90-day age" step_passwords
  run_step "Sessions: idle timeout, umask, sudo, su, no core dumps" step_session
  run_step "System hardening: kernel, filesystems, protocols, SSH" step_hardening
  [ "$YARA" = 0 ] || run_step "YARA: weekly scan of user-writable folders" step_yara
  [ "$AIDE" = 0 ] || run_step "Integrity: package checksums and AIDE, daily" step_integrity
  run_step "Login: banner and enforced screen lock" step_login
  [ "$LOCKOUT" = 0 ] || run_step "Account lockout: 5 failed logins, 30 minutes" step_lockout
  [ "$TOOLS" = 0 ] || run_step "Tools: audit, secrets, backups, Terraform, Trivy" step_tools
  run_step "Audit logging (auditd)" step_audit
  run_step "Log forwarding to a log server" step_forward
  [ "$SIGMA" = 0 ] || run_step "Threat detection: Sigma rules on audit events, every 15 minutes" step_sigma
  run_step "Compliance: daily check, weekly vulnerability scan" step_compliance
  # Legion's own changes in this run are not attacks.
  [ ! -x /usr/local/sbin/legion-sigma-scan ] || /usr/local/sbin/legion-sigma-scan --mark-reviewed >/dev/null 2>&1 || true
  # Legion's own later steps change files AIDE watches; accept them (logged in
  # integrity.log) so the next daily check does not report them.
  if [ -x /usr/local/sbin/legion-aide-baseline ] && [ -f "$STATE/aide/aide.db" ]; then
    /usr/local/sbin/legion-aide-baseline "legion run" "$LEGION_START" >/dev/null 2>&1 || warn "could not refresh the AIDE baseline"
  fi
fi

# ---------------------------------------------------------------- compliance

# Each check sets NOTE and returns 0 (pass), 1 (fail) or 2 (not applicable or
# not available). The rules follow the CIS Ubuntu 24.04 benchmark where it
# applies to 26.04; no CIS or DISA STIG benchmark for 26.04 exists yet.
NOTE=""
in_container() { [ "$IN_CONTAINER" = 1 ] && { NOTE="runs on the host kernel, not checkable in a container"; return 0; }; return 1; }
pro_service() { # prints "<available> <status>" for an Ubuntu Pro service
  pro status --format json 2>/dev/null | python3 -I -c '
import json, sys
d = json.load(sys.stdin)
for s in d.get("services", []):
    if s.get("name") == sys.argv[1]:
        print(s.get("available", "-"), s.get("status", "-"))
        break' "$1" 2>/dev/null
}

c_encryption() { [ "$ENCRYPTED" = 1 ] && return 0; NOTE="reinstall Ubuntu with full-disk encryption"; return 1; }
c_fips() {
  [ "$(cat /proc/sys/crypto/fips_enabled 2>/dev/null)" = 1 ] && { NOTE="FIPS mode on"; return 0; }
  local a st
  read -r a st <<<"$(pro_service fips-updates)"
  if [ "$st" = disabled ]; then NOTE="available: sudo pro enable fips-updates (needs a reboot)"; return 1; fi
  if [ "$a" = yes ] && ! pro_attached; then NOTE="available after attaching Ubuntu Pro"; return 1; fi
  NOTE="FIPS-validated packages are not yet available for Ubuntu $OS_VERSION"
  return 2
}
c_updates() {
  # The answer is only as fresh as the package lists.
  local newest age
  newest="$(find /var/lib/apt/lists -maxdepth 1 -name '*InRelease' -printf '%T@\n' 2>/dev/null | sort -rn | head -n 1)"
  if [ -z "$newest" ]; then NOTE="no package lists; run apt update"; return 1; fi
  age=$(( ($(date +%s) - ${newest%.*}) / 86400 ))
  if [ "$age" -gt 2 ]; then NOTE="package lists are $age days old, so pending updates are unknown"; return 1; fi
  local n
  # dist-upgrade, not upgrade: it also counts security updates that need new
  # dependencies, which a plain upgrade holds back silently.
  n="$(apt-get -s -o Debug::NoLocking=1 dist-upgrade 2>/dev/null | grep -c '^Inst .*-security' || true)"
  [ "$n" = 0 ] && return 0
  NOTE="$n security updates pending"; return 1
}
c_autoupdates() {
  local UU=0
  eval "$(apt-config shell UU APT::Periodic::Unattended-Upgrade)"
  [ "$UU" = 1 ] && return 0; NOTE="automatic security updates are off"; return 1
}
c_pro() { pro_attached && return 0; NOTE="optional: attach Ubuntu Pro for security updates to every package"; return 2; }
c_livepatch() {
  in_container && return 2
  local a st
  read -r a st <<<"$(pro_service livepatch)"
  [ "$st" = enabled ] && return 0
  pro_attached || { NOTE="optional: needs Ubuntu Pro"; return 2; }
  NOTE="enable with: sudo pro enable livepatch"; return 1
}
c_firewall() {
  local out
  out="$(ufw status verbose 2>/dev/null)"
  grep -q 'Status: active' <<<"$out" && grep -q 'deny (incoming)' <<<"$out" && return 0
  NOTE="firewall off or not blocking incoming connections"; return 1
}
c_auditd() {
  in_container && return 2
  systemctl is-active -q auditd || { NOTE="auditd not running"; return 1; }
  [ "$(systemctl show -p RefuseManualStop --value auditd)" = yes ] || { NOTE="auditd can be stopped by hand (run Legion again)"; return 1; }
}
c_audit_rules() {
  in_container && return 2
  local r k
  r="$(auditctl -l 2>/dev/null)"
  for k in identity privilege user_emulation session logins system-locale time modules perm_mod access mounts delete MAC-policy privileged legion-tamper exec persistence audit-log; do
    # auditctl -l shows file watches as "-k NAME" and syscall rules as "key=NAME".
    grep -qE -- "(-k |key=)$k( |$)" <<<"$r" || { NOTE="audit rules for '$k' not loaded"; return 1; }
  done
}
c_log_retention() {
  grep -qx 'Storage=persistent' /etc/systemd/journald.conf.d/legion.conf 2>/dev/null &&
    grep -qx 'MaxRetentionSec=1year' /etc/systemd/journald.conf.d/legion.conf && [ -d /var/log/journal ] && return 0
  NOTE="system logs are not kept for a year"; return 1
}
c_log_protect() {
  local d p
  for d in /var/log/audit /var/log/legion; do
    [ -d "$d" ] || continue
    p="$(stat -c %a "$d")"
    case "$p" in 700 | 750) ;; *) NOTE="$d is readable by other users ($p)"; return 1 ;; esac
  done
}
c_time() {
  in_container && return 2
  [ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" = yes ] && return 0
  NOTE="clock not synchronized"; return 1
}
# A scan whose last run failed (it found something, or could not run) fails
# its check until the cause is dealt with and the scan runs clean.
last_run_failed() { systemctl is-failed -q "$1" 2>/dev/null; }
c_clamav() {
  if ! systemctl is-active -q clamav-freshclam || ! systemctl is-enabled -q clamscan-home.timer; then
    NOTE="ClamAV updates or weekly scan not running"; return 1
  fi
  ! last_run_failed clamscan-home.service || { NOTE="the last ClamAV scan found something; see /var/log/clamscan-home.log"; return 1; }
}
c_yara() {
  if ! systemctl is-enabled -q legion-yara-scan.timer 2>/dev/null || [ ! -s "$STATE/yara/rules.yarc" ]; then
    NOTE="YARA scan not set up (run Legion without --no-yara)"; return 1
  fi
  ! last_run_failed legion-yara-scan.service || { NOTE="the last YARA scan found something; see /var/log/legion/yara-scan.log"; return 1; }
}
c_sigma() {
  if ! systemctl is-enabled -q legion-sigma-scan.timer 2>/dev/null || [ ! -x /opt/legion/zircolite/Zircolite ]; then
    NOTE="threat detection not set up (run Legion without --no-sigma)"; return 1
  fi
  local n
  n="$(python3 -I -c '
import json, sys, time
cut = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 7 * 86400))
n = 0
try:
    for line in open(sys.argv[1]):
        try:
            n += json.loads(line).get("time", "") >= cut
        except ValueError:
            pass
except OSError:
    pass
print(n)' "$LOGDIR/sigma-alerts.log")"
  [ "${n:-0}" = 0 ] || { NOTE="$n threat alerts in the last 7 days; see $LOGDIR/sigma-alerts.log"; return 1; }
  ! last_run_failed legion-sigma-scan.service || { NOTE="the last Sigma check failed; see systemctl status legion-sigma-scan"; return 1; }
}
c_integrity() {
  if ! systemctl is-enabled -q legion-integrity.timer 2>/dev/null || [ ! -f "$STATE/aide/aide.db" ]; then
    NOTE="integrity check not set up (run Legion without --no-aide)"; return 1
  fi
  ! last_run_failed legion-integrity.service || { NOTE="the last integrity check found changes; see /var/log/legion/integrity.log"; return 1; }
}
c_password() {
  local conf minlen minclass
  conf="$(cat /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null | grep -vE '^\s*#')"
  minlen="$(awk -F= '/^[[:space:]]*minlen[[:space:]]*=/ { gsub(/ /, "", $2); v = $2 } END { print v + 0 }' <<<"$conf")"
  minclass="$(awk -F= '/^[[:space:]]*minclass[[:space:]]*=/ { gsub(/ /, "", $2); v = $2 } END { print v + 0 }' <<<"$conf")"
  [ "$minlen" -ge 12 ] && [ "$minclass" -ge 3 ] && return 0
  NOTE="passwords need at least 12 characters and 3 character types"; return 1
}
c_lockout() {
  grep -qE '^[^#]*pam_faillock.so preauth' /etc/pam.d/common-auth 2>/dev/null &&
    grep -q 'pam_faillock.so authfail' /etc/pam.d/common-auth && return 0
  NOTE="no lockout after failed logins (run Legion without --no-lockout)"; return 1
}
c_banner() {
  if ! grep -qi 'authorized use only' /etc/issue 2>/dev/null || ! grep -qi 'authorized use only' /etc/issue.net 2>/dev/null; then
    NOTE="no login banner on the console"; return 1
  fi
  # On a GNOME desktop the graphical login screen is the one people see.
  if [ -f /etc/gdm3/greeter.dconf-defaults ]; then
    if ! awk '/^\[/ { s = ($0 == "[org/gnome/login-screen]") } s && /^banner-message-enable=true$/ { f = 1 } END { exit !f }' /etc/gdm3/greeter.dconf-defaults; then
      NOTE="no banner on the graphical login screen"; return 1
    fi
  fi
}
c_screenlock() {
  [ -f /usr/share/glib-2.0/schemas/org.gnome.desktop.screensaver.gschema.xml ] || { NOTE="no GNOME desktop"; return 2; }
  local f=/etc/dconf/db/local.d/00-legion-screenlock delay
  if ! { [ -f "$f" ] && [ -f /etc/dconf/db/local.d/locks/00-legion-screenlock ] &&
    grep -qx 'system-db:local' /etc/dconf/profile/user 2>/dev/null; }; then
    NOTE="screen lock not enforced"; return 1
  fi
  delay="$(awk '/^idle-delay=/ { print $2 }' "$f")"
  [ "${delay:-0}" -gt 0 ] && [ "$delay" -le 900 ] && grep -qx 'lock-enabled=true' "$f" && return 0
  NOTE="screen lock delay is not 15 minutes or less"; return 1
}
c_secureboot() {
  in_container && return 2
  command -v mokutil >/dev/null || { NOTE="mokutil not installed"; return 2; }
  mokutil --sb-state 2>/dev/null | grep -q 'SecureBoot enabled' && return 0
  NOTE="Secure Boot is off (turn it on in the firmware settings)"; return 1
}
c_apparmor() { in_container && return 2; aa-enabled -q 2>/dev/null && return 0; NOTE="AppArmor is off"; return 1; }
c_ssh() {
  if ! ss -ltnH 2>/dev/null | awk '{ print $4 }' | grep -qE ':22$'; then NOTE="no SSH server listening"; return 0; fi
  local t
  t="$(sshd -T 2>/dev/null)"
  local n
  n="$(awk '$1 == "maxauthtries" { print $2 }' <<<"$t")"
  if ! { [ "${n:-6}" -le 4 ] && grep -qx 'x11forwarding no' <<<"$t" && grep -qx 'permitemptypasswords no' <<<"$t"; }; then
    NOTE="SSH server not hardened (run Legion again)"; return 1
  fi
  grep -qx 'permitrootlogin no' <<<"$t" && grep -qx 'passwordauthentication no' <<<"$t" && return 0
  NOTE="SSH allows root or password logins"; return 1
}
c_listeners() {
  # Lists each non-loopback TCP listener as port(program), e.g. 25(master).
  local l
  l="$(ss -ltnpH 2>/dev/null | awk '$4 !~ /^(127\.|\[::1\]|\[::ffff:127\.)/ && $4 !~ /%lo:/ {
      port = $4; sub(/.*:/, "", port)
      prog = $0; if (match(prog, /\(\("[^"]+"/)) prog = substr(prog, RSTART + 3, RLENGTH - 4); else prog = "?"
      print port "(" prog ")" }' | sort -u | tr '\n' ' ')"
  [ -z "$l" ] && return 0
  NOTE="services reachable from the network: ${l% }"
  case "$l" in *docker-proxy*) NOTE="$NOTE. Ports published by Docker bypass the firewall" ;; esac
  return 1
}
c_kernel() {
  in_container && return 2
  [ "$(sysctl -n kernel.kptr_restrict)" = 2 ] && [ "$(sysctl -n fs.suid_dumpable)" = 0 ] &&
    [ "$(sysctl -n fs.protected_fifos)" = 2 ] && [ "$(sysctl -n net.ipv4.conf.all.send_redirects)" = 0 ] && return 0
  NOTE="kernel settings differ (reboot, or run Legion again)"; return 1
}
c_aslr() { [ "$(sysctl -n kernel.randomize_va_space 2>/dev/null)" = 2 ] && return 0; NOTE="memory address randomization is not full"; return 1; }
c_protocols() {
  grep -q 'install sctp /bin/false' /etc/modprobe.d/legion-uncommon-net.conf 2>/dev/null && return 0
  NOTE="unused network protocols are not blocked"; return 1
}
c_perms() {
  [ ! -f /etc/crontab ] || [ "$(stat -c %a /etc/crontab)" = 600 ] || { NOTE="/etc/crontab is readable by other users"; return 1; }
  local d
  for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /etc/cron.yearly; do
    [ ! -d "$d" ] || [ "$(stat -c %a "$d")" = 700 ] || { NOTE="$d is readable by other users"; return 1; }
  done
  [ ! -d /etc/sudoers.d ] || [ "$(stat -c %a /etc/sudoers.d)" = 750 ] || { NOTE="/etc/sudoers.d is readable by other users"; return 1; }
  # Account files: Ubuntu's own permissions or stricter.
  local f max
  for f in /etc/passwd:644 /etc/group:644 /etc/shadow:640 /etc/gshadow:640 /etc/passwd-:644 /etc/group-:644 /etc/shadow-:640 /etc/gshadow-:640; do
    max="${f#*:}" f="${f%:*}"
    [ -e "$f" ] || continue
    [ $((8#$(stat -c %a "$f") & ~8#$max)) = 0 ] && [ "$(stat -c %u "$f")" = 0 ] || { NOTE="$f has loose permissions"; return 1; }
  done
}
c_empty_passwords() {
  awk -F: '$2 == "" { f = 1 } END { exit !f }' /etc/shadow && { NOTE="an account has no password"; return 1; }
  return 0
}
c_uid0() {
  [ "$(awk -F: '$3 == 0 { print $1 }' /etc/passwd | tr '\n' ' ')" = "root " ] && return 0
  NOTE="an account other than root has full administrator rights (UID 0)"; return 1
}
c_scap() {
  local ds="/usr/share/xml/scap/ssg/content/ssg-ubuntu${OS_VERSION//./}-ds.xml" profile fails
  if [ ! -f "$ds" ] || ! command -v oscap >/dev/null; then
    NOTE="no CIS / DISA STIG SCAP content for Ubuntu $OS_VERSION yet; runs automatically once published"; return 2
  fi
  profile="$(oscap info --profiles "$ds" 2>/dev/null | grep -o '^[^:]*cis_level1_workstation' | head -n 1)"
  [ -n "$profile" ] || { NOTE="SCAP content found, but no CIS Level 1 Workstation profile"; return 2; }
  oscap xccdf eval --profile "$profile" --report "$LOGDIR/cis-scap-report.html" "$ds" >"$LOGDIR/cis-scap.txt" 2>&1
  fails="$(grep -c '^Result.*fail' "$LOGDIR/cis-scap.txt" || true)"
  [ "$fails" = 0 ] && { NOTE="CIS Level 1 Workstation: all rules pass"; return 0; }
  NOTE="$fails CIS Level 1 Workstation rules fail; see cis-scap-report.html"; return 1
}

# Accounts of real people: login ID 1000 and up (the login screen's own
# temporary accounts start at 60000).
human_uid() { [ "$1" -ge 1000 ] 2>/dev/null && [ "$1" -lt 60000 ]; }
c_pwhistory() {
  local r
  r="$(grep -E '^[^#]*pam_pwhistory.so' /etc/pam.d/common-password 2>/dev/null | grep -o 'remember=[0-9]*' | head -n 1)"
  [ "${r#remember=}" -ge 24 ] 2>/dev/null && return 0
  NOTE="recent passwords can be reused (needs the last 24 refused)"; return 1
}
c_pwage() {
  local max u h m uid bad=""
  max="$(awk '$1 == "PASS_MAX_DAYS" { print $2 }' /etc/login.defs)"
  if ! { [ "${max:-0}" -ge 1 ] && [ "$max" -le 90 ]; } 2>/dev/null; then NOTE="new accounts' passwords do not expire within 90 days"; return 1; fi
  while IFS=: read -r u h _ _ m _; do
    case "$h" in "" | '!'* | '*'*) continue ;; esac
    if ! uid="$(id -u "$u" 2>/dev/null)" || ! human_uid "$uid"; then continue; fi
    { [ "${m:-0}" -ge 1 ] && [ "$m" -le 90 ]; } 2>/dev/null || bad+=" $u"
  done </etc/shadow
  [ -z "$bad" ] && return 0
  NOTE="passwords that do not expire within 90 days:$bad"; return 1
}
c_inactive() {
  local d u h i uid bad=""
  d="$(sed -n 's/^INACTIVE=//p' /etc/default/useradd 2>/dev/null | tail -n 1)"
  if ! { [ "${d:--1}" -ge 0 ] && [ "$d" -le 45 ]; } 2>/dev/null; then NOTE="new accounts are not disabled after inactivity"; return 1; fi
  while IFS=: read -r u h _ _ _ _ i _; do
    case "$h" in "" | '!'* | '*'*) continue ;; esac
    if ! uid="$(id -u "$u" 2>/dev/null)" || ! human_uid "$uid"; then continue; fi
    { [ "${i:--1}" -ge 0 ] && [ "$i" -le 45 ]; } 2>/dev/null || bad+=" $u"
  done </etc/shadow
  [ -z "$bad" ] && return 0
  NOTE="accounts never disabled after inactivity:$bad"; return 1
}
c_shells() {
  local bad
  bad="$(awk -F: '($3 < 1000 || $3 == 65534) && $1 != "root" && $7 !~ /(nologin|false|sync|shutdown|halt)$/ { printf " %s", $1 }' /etc/passwd)"
  [ -z "$bad" ] && return 0
  NOTE="system accounts with a login shell:$bad"; return 1
}
c_session_timeout() {
  grep -qs '^ *TMOUT=900' /etc/profile.d/legion-session.sh && return 0
  NOTE="idle console and SSH shells do not end"; return 1
}
c_umask() {
  local m
  m="$(awk '$1 == "UMASK" { print $2 }' /etc/login.defs)"
  case "$m" in 027 | 0027 | 077 | 0077) return 0 ;; esac
  NOTE="new files are readable by other users (umask ${m:-022})"; return 1
}
c_sudo() {
  local d t
  d="$(cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -E '^[[:space:]]*Defaults')"
  grep -qw use_pty <<<"$d" || { NOTE="sudo does not run commands in their own terminal (use_pty)"; return 1; }
  t="$(grep -o 'timestamp_timeout=-\?[0-9]*' <<<"$d" | tail -n 1)"
  t="${t#timestamp_timeout=}"
  if [ -n "$t" ] && { [ "$t" -lt 0 ] || [ "$t" -gt 15 ]; }; then NOTE="sudo remembers the password for more than 15 minutes"; return 1; fi
}
c_su() {
  local g
  g="$(grep -E '^auth[[:space:]]+required[[:space:]]+pam_wheel.so' /etc/pam.d/su 2>/dev/null | grep -o 'group=[^ ]*' | head -n 1)"
  g="${g#group=}"
  [ -n "$g" ] || { NOTE="any user who knows root's password can use su"; return 1; }
  [ -z "$(getent group "$g" | cut -d: -f4)" ] && return 0
  NOTE="members of $g can use su"; return 1
}
c_coredumps() {
  grep -qsE '^\*[[:space:]]+hard[[:space:]]+core[[:space:]]+0' /etc/security/limits.conf /etc/security/limits.d/*.conf ||
    { NOTE="core dumps are allowed"; return 1; }
  grep -qs '^Storage=none' /etc/systemd/coredump.conf /etc/systemd/coredump.conf.d/*.conf || { NOTE="systemd stores core dumps"; return 1; }
  if [ -f /etc/default/apport ] && ! grep -q '^enabled=0' /etc/default/apport; then NOTE="crash reporter (apport) is on"; return 1; fi
}
c_filesystems() {
  local m
  for m in cramfs freevxfs hfs hfsplus jffs2 udf; do
    grep -qsE "^install[[:space:]]+${m}[[:space:]]+/bin/(false|true)" /etc/modprobe.d/*.conf || { NOTE="$m filesystem not blocked"; return 1; }
  done
}
c_media() {
  [ -f /usr/share/glib-2.0/schemas/org.gnome.desktop.media-handling.gschema.xml ] || { NOTE="no GNOME desktop"; return 2; }
  grep -qsx 'autorun-never=true' /etc/dconf/db/local.d/00-legion-media &&
    grep -qsx /org/gnome/desktop/media-handling/autorun-never /etc/dconf/db/local.d/locks/00-legion-media && return 0
  NOTE="inserted media can start programs"; return 1
}
c_userlist() {
  [ -f /etc/gdm3/greeter.dconf-defaults ] || { NOTE="no GDM login screen"; return 2; }
  awk '/^\[/ { s = ($0 == "[org/gnome/login-screen]") } s && /^disable-user-list=true$/ { f = 1 } END { exit !f }' /etc/gdm3/greeter.dconf-defaults && return 0
  NOTE="the login screen lists user names"; return 1
}
c_audit_alert() {
  grep -qE '^space_left_action[[:space:]]*=[[:space:]]*(email|exec|single|halt)' /etc/audit/auditd.conf 2>/dev/null ||
    { NOTE="no alert when the audit log disk runs low"; return 1; }
  if [ -n "$(find /var/lib/legion/audit-space-low -mtime -7 2>/dev/null)" ]; then
    NOTE="audit log disk ran low on $(cat /var/lib/legion/audit-space-low); free up space"; return 1
  fi
}
c_forwarding() {
  local f=/etc/rsyslog.d/60-legion-forward.conf dest kb
  [ -f "$f" ] || { NOTE="optional: logs stay on this device (set a log server with --forward-logs)"; return 2; }
  dest="$(sed -n 's/^# Legion destination: //p' "$f")"
  systemctl is-active -q rsyslog || { NOTE="rsyslog is not running, so nothing reaches $dest"; return 1; }
  # Logs waiting in the disk queue: some is normal while offline.
  kb="$(du -sk /var/spool/rsyslog/legion-forward* 2>/dev/null | awk '{ s += $1 } END { print s + 0 }')"
  [ "$kb" -lt 102400 ] || { NOTE="$((kb / 1024)) MB of logs waiting to reach $dest"; return 1; }
  NOTE="to $dest"
}
c_audit_lock() {
  [ -f /etc/audit/rules.d/99-legion-lock.rules ] || { NOTE="optional: audit rules can be changed by an administrator (lock with --lock-audit)"; return 2; }
  in_container && return 2
  auditctl -s 2>/dev/null | grep -qx 'enabled 2' && { NOTE="locked until the next restart"; return 0; }
  NOTE="set to lock, but not locked yet: restart the device"; return 1
}
c_vulns() {
  local f=/var/lib/legion/oval/last when n age
  systemctl is-enabled -q legion-vuln-scan.timer 2>/dev/null || { NOTE="vulnerability scan not set up"; return 1; }
  [ -f "$f" ] || { NOTE="first scan not finished yet"; return 2; }
  read -r when n <"$f"
  age=$((($(date +%s) - $(date -d "$when" +%s 2>/dev/null || echo 0)) / 86400))
  if last_run_failed legion-vuln-scan.service && [ "${n:-0}" = 0 ]; then NOTE="the last scan could not run; see: systemctl status legion-vuln-scan"; return 1; fi
  [ "$age" -le 14 ] || { NOTE="last scan was $age days ago"; return 1; }
  [ "${n:-0}" = 0 ] && { NOTE="no known vulnerabilities on $when"; return 0; }
  NOTE="$n Ubuntu security notice(s) apply: $(head -n 1 "$LOGDIR/vuln-scan.txt" 2>/dev/null)$([ "$n" -gt 1 ] && echo ", ..."). Install updates; see vuln-report.html"; return 1
}
# One pass over the local disks for the file checks below, shared by them.
fs_scan() {
  [ -f "$FLAGS/fs-scan" ] && return 0
  local mounts=()
  local_disks
  nice -n 19 ionice -c 3 find "${mounts[@]}" -xdev \
    \( -path /proc -o -path /sys -o -path /var/lib/docker -o -path /var/lib/containers -o -path /snap -o -path /var/snap \) -prune \
    -o \( -type f -perm -0002 -printf 'ww %p\n' \) \
    -o \( -type d -perm -0002 ! -perm -1000 -printf 'wd %p\n' \) \
    -o \( \( -nouser -o -nogroup \) -printf 'un %p\n' \) \
    -o \( -type f \( -perm -4000 -o -perm -2000 \) -printf 'su %p\n' \) >"$FLAGS/fs-scan.new" 2>/dev/null || true
  sort -u "$FLAGS/fs-scan.new" >"$FLAGS/fs-scan"
}
fs_list() { # kind... ; prints matching paths
  local k
  for k in "$@"; do sed -n "s/^$k //p" "$FLAGS/fs-scan"; done
}
fs_note() { # count label; first 3 paths from stdin
  local n="$1" l="$2" first
  first="$(head -n 3 | tr '\n' ' ')"
  NOTE="$n $l: ${first% }$([ "$n" -gt 3 ] && echo ", ...")"
}
c_world_writable() {
  fs_scan
  local n
  n="$(fs_list ww wd | grep -c . || true)"
  [ "$n" = 0 ] && return 0
  fs_list ww wd | fs_note "$n" "world-writable files or folders without the sticky bit"
  return 1
}
c_unowned() {
  fs_scan
  local n
  n="$(fs_list un | grep -c . || true)"
  [ "$n" = 0 ] && return 0
  fs_list un | fs_note "$n" "files with no owner or group"
  return 1
}
c_privileged() {
  fs_scan
  local n
  fs_list su >"$LOGDIR/privileged-programs.txt"
  # usr-merge: a package may list /bin/x for what is now /usr/bin/x.
  cat /var/lib/dpkg/info/*.list 2>/dev/null >"$FLAGS/dpkg-files"
  awk 'NR == FNR { p[$0] = 1; next } { g = $0; sub(/^\/usr/, "", g) } !($0 in p) && !(g in p) && !(("/usr" $0) in p)' \
    "$FLAGS/dpkg-files" "$LOGDIR/privileged-programs.txt" >"$FLAGS/unpackaged"
  n="$(grep -c . "$FLAGS/unpackaged" || true)"
  if [ "$n" = 0 ]; then NOTE="$(grep -c . "$LOGDIR/privileged-programs.txt") setuid/setgid programs, all from packages"; return 0; fi
  fs_note "$n" "setuid/setgid programs not from any package" <"$FLAGS/unpackaged"
  return 1
}
c_dup_ids() {
  local d
  d="$({
    cut -d: -f3 /etc/passwd | sort | uniq -d | sed 's/^/UID /'
    cut -d: -f1 /etc/passwd | sort | uniq -d | sed 's/^/user /'
    cut -d: -f3 /etc/group | sort | uniq -d | sed 's/^/GID /'
    cut -d: -f1 /etc/group | sort | uniq -d | sed 's/^/group /'
  } | tr '\n' ' ')"
  [ -z "$d" ] && return 0
  NOTE="duplicates: ${d% }"; return 1
}
c_homes() {
  local u uid home m bad=""
  while IFS=: read -r u _ uid _ _ home _; do
    human_uid "$uid" && [ -d "$home" ] || continue
    m="$(stat -c %a "$home")"
    [ $((8#$m & 8#027)) = 0 ] || bad+=" $home ($m)"
  done </etc/passwd
  [ -z "$bad" ] && return 0
  NOTE="home folders open to other users:$bad (fix: chmod 750)"; return 1
}

# id | check | function | SOC 2 | HIPAA | NIST 800-53 | NIST 800-171 / CMMC L2
CHECKS=(
  "disk-encryption|Full-disk encryption|c_encryption|CC6.1|164.312(a)(2)(iv)|SC-28|3.13.16"
  "fips|FIPS-validated cryptography|c_fips|CC6.1|164.312(a)(2)(iv)|SC-13|3.13.11"
  "security-updates|No pending security updates|c_updates|CC7.1|164.308(a)(1)(ii)(B)|SI-2|3.14.1"
  "auto-updates|Automatic security updates|c_autoupdates|CC7.1|164.308(a)(1)(ii)(B)|SI-2|3.14.1"
  "vulnerability-scan|Weekly vulnerability scan, nothing open|c_vulns|CC7.1|164.308(a)(1)(ii)(A)|RA-5|3.11.2"
  "ubuntu-pro|Ubuntu Pro (ESM security updates)|c_pro|CC7.1|164.308(a)(1)(ii)(B)|SI-2|3.14.1"
  "livepatch|Livepatch (kernel fixes without reboot)|c_livepatch|CC7.1|-|SI-2|3.14.1"
  "firewall|Firewall blocks incoming connections|c_firewall|CC6.6|-|SC-7|3.13.1"
  "listeners|No reachable network services|c_listeners|CC6.6|-|CM-7|3.4.7"
  "ssh|SSH hardened or off|c_ssh|CC6.6|164.312(a)(1)|CM-7|3.4.7"
  "protocols|Unused network protocols blocked|c_protocols|CC6.6|-|CM-7|3.4.6"
  "filesystems|Unused filesystems blocked|c_filesystems|CC6.8|-|CM-7|3.4.6"
  "media-autorun|USB drives and discs never start programs|c_media|CC6.8|-|CM-7|3.8.7"
  "auditd|Audit logging running|c_auditd|CC7.2|164.312(b)|AU-12|3.3.1"
  "audit-rules|Audit rules (CIS set: accounts, sudo, logins, access, changes)|c_audit_rules|CC7.2|164.312(b)|AU-2|3.3.1"
  "audit-alert|Alert when the audit log disk runs low|c_audit_alert|CC7.2|164.312(b)|AU-5|3.3.4"
  "audit-lock|Audit rules locked until restart|c_audit_lock|CC7.2|164.312(b)|AU-9|3.3.8"
  "log-forwarding|Logs copied to a log server|c_forwarding|CC7.2|164.312(b)|AU-9(2)|3.3.8"
  "log-retention|System logs kept for 1 year|c_log_retention|CC7.2|164.312(b)|AU-11|3.3.1"
  "log-protection|Audit logs readable only by admins|c_log_protect|CC7.2|164.312(b)|AU-9|3.3.8"
  "time-sync|Clock synchronized|c_time|CC7.2|164.312(b)|AU-8|3.3.7"
  "clamav|ClamAV updates and weekly scan|c_clamav|CC6.8|164.308(a)(5)(ii)(B)|SI-3|3.14.2"
  "yara|YARA weekly scan|c_yara|CC6.8|164.308(a)(5)(ii)(B)|SI-3|3.14.5"
  "sigma|Threat detection: Sigma rules on audit events|c_sigma|CC7.2|164.308(a)(1)(ii)(D)|SI-4|3.14.6"
  "integrity|Daily file integrity check|c_integrity|CC7.1|164.312(c)(1)|SI-7|-"
  "secure-boot|Secure Boot|c_secureboot|CC6.8|-|SI-7(9)|-"
  "apparmor|AppArmor confinement|c_apparmor|CC6.8|-|AC-3(3)|-"
  "kernel|Kernel hardening settings|c_kernel|CC7.1|-|CM-6|3.4.2"
  "aslr|Full memory address randomization|c_aslr|CC6.8|-|SI-16|-"
  "core-dumps|No core dumps or crash reports|c_coredumps|CC6.1|-|CM-6|3.4.2"
  "password-policy|Password length and complexity|c_password|CC6.1|164.308(a)(5)(ii)(D)|IA-5(1)|3.5.7"
  "password-history|Last 24 passwords cannot be reused|c_pwhistory|CC6.1|164.308(a)(5)(ii)(D)|IA-5(1)|3.5.8"
  "password-age|Passwords expire within 90 days|c_pwage|CC6.1|164.308(a)(5)(ii)(D)|IA-5(1)|-"
  "inactive-accounts|Inactive accounts disabled after 45 days|c_inactive|CC6.2|164.308(a)(3)(ii)(C)|AC-2(3)|3.5.6"
  "duplicate-ids|No duplicate user or group IDs|c_dup_ids|CC6.1|164.312(a)(2)(i)|IA-2|3.5.1"
  "system-shells|System accounts cannot log in|c_shells|CC6.1|-|AC-2|3.1.1"
  "lockout|Lockout after failed logins|c_lockout|CC6.1|164.308(a)(5)(ii)(C)|AC-7|3.1.8"
  "empty-passwords|No accounts without a password|c_empty_passwords|CC6.1|164.312(d)|IA-2|3.5.2"
  "uid0|Only root has UID 0|c_uid0|CC6.1|164.312(a)(1)|AC-6|3.1.5"
  "permissions|Cron, sudoers and account files locked to admins|c_perms|CC6.1|164.312(a)(1)|AC-6|3.1.5"
  "home-folders|Home folders closed to other users|c_homes|CC6.1|164.312(a)(1)|AC-3|3.1.1"
  "world-writable|No world-writable files|c_world_writable|CC6.1|164.312(a)(1)|AC-3|3.1.1"
  "unowned-files|No files without an owner|c_unowned|CC6.1|-|CM-6|3.4.2"
  "privileged-programs|Setuid programs all come from packages|c_privileged|CC6.8|-|CM-7|3.4.7"
  "sudo|sudo: own terminal, 15-minute password timeout|c_sudo|CC6.1|164.312(b)|AC-6(9)|3.1.7"
  "su|su limited to root|c_su|CC6.1|-|AC-6|3.1.5"
  "session-timeout|Idle console and SSH sessions end|c_session_timeout|CC6.1|164.312(a)(2)(iii)|AC-12|3.1.11"
  "umask|New files private by default (umask 027)|c_umask|CC6.1|-|CM-6|3.4.2"
  "screen-lock|Enforced screen lock|c_screenlock|CC6.1|164.312(a)(2)(iii)|AC-11|3.1.10"
  "banner|Login banner|c_banner|-|-|AC-8|3.1.9"
  "login-user-list|Login screen hides user names|c_userlist|CC6.1|-|CM-6|3.4.2"
  "cis-scap|CIS benchmark scan (OpenSCAP)|c_scap|CC7.1|-|CM-6|3.4.2"
)
# Evidence these frameworks need that no device check can provide.
MANUAL=(
  "Backups and tested restores|A1.2|164.308(a)(7)(ii)(A)|CP-9|3.8.9"
  "Multi-factor authentication|CC6.1|164.312(d)|IA-2(1)|3.5.3"
  "Central log collection and review|CC7.2|164.308(a)(1)(ii)(D)|AU-6|3.3.5"
  "Risk assessment|CC3.2|164.308(a)(1)(ii)(A)|RA-3|3.11.1"
  "Security awareness training|CC2.2|164.308(a)(5)(i)|AT-2|3.2.1"
  "Incident response plan|CC7.4|164.308(a)(6)|IR-8|3.6.1"
  "Vendor agreements (BAAs, subprocessors)|CC9.2|164.308(b)(1)|SA-9|-"
  "Written security policies|CC5.3|164.316(a)|PL-1|-"
)
FRAMEWORKS=("SOC 2" "HIPAA" "NIST 800-53 (FedRAMP)" "NIST 800-171 (CMMC L2)")

R_ID=() R_TITLE=() R_STATUS=() R_NOTE=() R_MAP=()
run_checks() {
  local line id title fn s h n5 n1 rc
  for line in "${CHECKS[@]}"; do
    IFS='|' read -r id title fn s h n5 n1 <<<"$line"
    NOTE=""
    set +e
    "$fn" >/dev/null 2>&1
    rc=$?
    set -e
    R_ID+=("$id") R_TITLE+=("$title") R_NOTE+=("$NOTE") R_MAP+=("$s|$h|$n5|$n1")
    case "$rc" in 0) R_STATUS+=(pass) ;; 1) R_STATUS+=(fail) ;; *) R_STATUS+=(n/a) ;; esac
  done
}

json_esc() { local v="${1//\\/\\\\}"; v="${v//\"/\\\"}"; printf '%s' "$v"; }

write_reports() {
  local md="$LOGDIR/compliance-report.md" js="$LOGDIR/compliance-report.json" now i f col p n a
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  {
    echo "# Legion Profile compliance report"
    echo
    echo "- Device: $(hostname)"
    echo "- System: $(osr PRETTY_NAME), kernel $(uname -r)"
    echo "- Checked: $now"
    echo "- Legion: $LEGION_VERSION"
    echo
    echo "This report is evidence for an auditor, not an audit. Checks follow the CIS Ubuntu 24.04 benchmark where it applies to 26.04; no CIS or DISA STIG benchmark for 26.04 has been published. Control IDs show where each check is used as evidence."
    echo
    echo "## Summary"
    echo
    echo "| Framework | Pass | Fail | Not available |"
    echo "|---|---|---|---|"
    for col in 0 1 2 3; do
      p=0 n=0 a=0
      for i in "${!R_ID[@]}"; do
        IFS='|' read -r -a f <<<"${R_MAP[i]}"
        [ "${f[col]}" != "-" ] || continue
        case "${R_STATUS[i]}" in pass) p=$((p + 1)) ;; fail) n=$((n + 1)) ;; *) a=$((a + 1)) ;; esac
      done
      echo "| ${FRAMEWORKS[col]} | $p | $n | $a |"
    done
    echo
    echo "## Device checks"
    echo
    echo "| Check | Result | SOC 2 | HIPAA | NIST 800-53 | NIST 800-171 / CMMC L2 | Notes |"
    echo "|---|---|---|---|---|---|---|"
    for i in "${!R_ID[@]}"; do
      IFS='|' read -r -a f <<<"${R_MAP[i]}"
      case "${R_STATUS[i]}" in pass) r="PASS" ;; fail) r="**FAIL**" ;; *) r="not available" ;; esac
      echo "| ${R_TITLE[i]} | $r | ${f[0]} | ${f[1]} | ${f[2]} | ${f[3]} | ${R_NOTE[i]} |"
    done
    echo
    echo "## Evidence needed from outside this device"
    echo
    echo "| Item | SOC 2 | HIPAA | NIST 800-53 | NIST 800-171 / CMMC L2 |"
    echo "|---|---|---|---|---|"
    for line in "${MANUAL[@]}"; do
      IFS='|' read -r -a f <<<"$line"
      echo "| ${f[0]} | ${f[1]} | ${f[2]} | ${f[3]} | ${f[4]} |"
    done
  } >"$md"
  {
    printf '{\n  "device": "%s",\n  "system": "%s",\n  "checked": "%s",\n  "legion_version": "%s",\n  "checks": [\n' \
      "$(json_esc "$(hostname)")" "$(json_esc "$(osr PRETTY_NAME)")" "$now" "$LEGION_VERSION"
    for i in "${!R_ID[@]}"; do
      IFS='|' read -r -a f <<<"${R_MAP[i]}"
      printf '    {"id": "%s", "check": "%s", "result": "%s", "note": "%s", "soc2": "%s", "hipaa": "%s", "nist_800_53": "%s", "nist_800_171": "%s"}%s\n' \
        "${R_ID[i]}" "$(json_esc "${R_TITLE[i]}")" "${R_STATUS[i]}" "$(json_esc "${R_NOTE[i]}")" \
        "${f[0]}" "${f[1]}" "${f[2]}" "${f[3]}" "$([ "$i" -lt $((${#R_ID[@]} - 1)) ] && echo ,)"
    done
    printf '  ]\n}\n'
  } >"$js"
  chmod 640 "$md" "$js"
}

# One archive with the reports, recent logs and Legion's settings, plus a
# SHA-256 checksum, so an auditor can confirm nothing was changed afterwards.
make_bundle() {
  local dir="$LOGDIR/evidence" name tmp b f
  install -d -m 750 "$dir"
  name="legion-evidence-$(hostname)-$(date -u +%Y%m%dT%H%M%SZ)"
  tmp="$(mktemp -d)"
  b="$tmp/$name"
  install -d "$b/reports" "$b/logs" "$b/settings" "$b/status"
  cp "$LOGDIR"/compliance-report.* "$b/reports/" 2>/dev/null || true
  cp "$LOGDIR"/cis-scap-report.html "$b/reports/" 2>/dev/null || true
  [ ! -s "$RUNLOG" ] || cp "$RUNLOG" "$b/logs/"
  for f in yara-scan.log integrity.log vuln-scan.txt privileged-programs.txt sigma-alerts.log; do [ ! -f "$LOGDIR/$f" ] || tail -n 2000 "$LOGDIR/$f" >"$b/logs/$f"; done
  cp "$LOGDIR"/vuln-report.html "$b/reports/" 2>/dev/null || true
  for f in /etc/audit/rules.d/legion.rules /etc/systemd/journald.conf.d/legion.conf \
    /etc/security/pwquality.conf.d/legion.conf /etc/sysctl.d/60-legion-hardening.conf \
    /etc/modprobe.d/legion-uncommon-net.conf /etc/apt/apt.conf.d/20auto-upgrades /etc/legion/aide.conf \
    /etc/dconf/db/local.d/00-legion-screenlock /etc/issue \
    /etc/pam.d/common-auth /etc/pam.d/common-account /etc/pam.d/common-password /etc/pam.d/su \
    /etc/login.defs /etc/default/useradd /etc/profile.d/legion-session.sh /etc/sudoers.d/legion \
    /etc/security/limits.d/legion.conf /etc/systemd/coredump.conf.d/legion.conf /etc/modprobe.d/legion-filesystems.conf \
    /etc/ssh/sshd_config.d/00-legion.conf /etc/audit/auditd.conf /etc/gdm3/greeter.dconf-defaults \
    /etc/dconf/db/local.d/00-legion-media /etc/audit/rules.d/99-legion-lock.rules /etc/rsyslog.d/60-legion-forward.conf \
    /etc/legion/sigma-ignore /etc/systemd/system/auditd.service.d/legion.conf; do
    [ ! -f "$f" ] || cp "$f" "$b/settings/$(echo "${f#/}" | tr / _)"
  done
  {
    echo "== ufw"; ufw status verbose 2>&1
    echo; echo "== ubuntu pro"; pro status 2>&1
    echo; echo "== audit rules"; auditctl -l 2>&1
    echo; echo "== legion timers"; systemctl list-timers --all --no-pager 'legion*' 'clamscan*' 2>&1
    echo; echo "== failed units"; systemctl --failed --no-pager 2>&1
    echo; echo "== audit status (enabled 2 = locked)"; auditctl -s 2>&1
    # A swapped-in integrity baseline would show as a changed checksum
    # between bundles.
    echo; echo "== integrity baseline checksums"
    sha256sum "$STATE"/aide/aide.db* /usr/local/sbin/legion* 2>&1
  } >"$b/status/status.txt"
  (cd "$b" && find . -type f -print0 | sort -z | xargs -0 sha256sum >"$tmp/SHA256SUMS") && mv "$tmp/SHA256SUMS" "$b/SHA256SUMS"
  tar -C "$tmp" -czf "$dir/$name.tar.gz" "$name"
  (cd "$dir" && sha256sum "$name.tar.gz" >"$name.tar.gz.sha256")
  chmod 640 "$dir/$name.tar.gz" "$dir/$name.tar.gz.sha256"
  rm -rf "$tmp"
  # Keep the 30 most recent bundles.
  find "$dir" -maxdepth 1 -name 'legion-evidence-*.tar.gz' -printf '%T@ %p\n' | sort -rn | awk 'NR > 30 { print $2 }' |
    while read -r f; do rm -f "$f" "$f.sha256"; done
  BUNDLE="$dir/$name.tar.gz"
}

section "Compliance checks"
run_checks
FAILS=0 NEW_FAILS=""
LAST="$STATE/last-check"
for i in "${!R_ID[@]}"; do
  label="${R_TITLE[i]}"
  [ -z "${R_NOTE[i]}" ] || label="$label ${C_DIM}(${R_NOTE[i]})${C_RST}"
  case "${R_STATUS[i]}" in
    pass) [ "$DRIFT_ONLY" = 1 ] || ok "$label" ;;
    fail)
      FAILS=$((FAILS + 1))
      [ "$DRIFT_ONLY" = 1 ] || fail "$label"
      case "${R_ID[i]}" in
        time-sync | security-updates) ;; # short-lived after resume or a new update; not drift
        *) if [ -f "$LAST" ] && grep -qx "${R_ID[i]} pass" "$LAST"; then NEW_FAILS="$NEW_FAILS ${R_ID[i]}"; fi ;;
      esac
      ;;
    *) [ "$DRIFT_ONLY" = 1 ] || info "$label" ;;
  esac
done
# Saved state: a check that passed before and fails now stays recorded as
# "pass", so the daily drift check keeps alerting until it is fixed.
for i in "${!R_ID[@]}"; do
  st="${R_STATUS[i]}"
  if [ "$st" = fail ] && [ -f "$LAST" ] && grep -qx "${R_ID[i]} pass" "$LAST"; then st=pass; fi
  echo "${R_ID[i]} $st"
done >"$LAST.new"
mv -f "$LAST.new" "$LAST"

set +e
write_reports
make_bundle
set -e

section "Frameworks"
for col in 0 1 2 3; do
  p=0 n=0
  for i in "${!R_ID[@]}"; do
    IFS='|' read -r -a f <<<"${R_MAP[i]}"
    [ "${f[col]}" != "-" ] || continue
    case "${R_STATUS[i]}" in pass) p=$((p + 1)) ;; fail) n=$((n + 1)) ;; esac
  done
  if [ "$n" = 0 ]; then ok "${FRAMEWORKS[col]}: all $p device checks pass"
  else fail "${FRAMEWORKS[col]}: $p pass, $n fail"; fi
done
info "report: $LOGDIR/compliance-report.md (and .json)"
info "evidence bundle: ${BUNDLE:-not created}"
info "${#MANUAL[@]} items need evidence from outside this device; listed in the report"
[ "$READONLY" = 1 ] || info "run log: $RUNLOG"

if [ "$DRIFT_ONLY" = 1 ]; then
  if [ -n "$NEW_FAILS" ]; then fail "checks that passed before and now fail:$NEW_FAILS"; exit 1; fi
  exit 0
fi
if [ "$READONLY" = 1 ]; then
  [ "$CHECK" = 1 ] && [ "$REPORT_ONLY" = 0 ] && [ "$FAILS" -gt 0 ] && exit 1
  exit 0
fi

# Legion's own changes in this run are not attacks. The Sigma check skips
# events from this time window; auditd may write the last ones to disk a
# little later, so the window runs a few seconds past the end.
if [ -d "$STATE/sigma" ]; then
  echo "$LEGION_START $(($(date +%s) + 10))" >>"$STATE/sigma/quiet"
  tail -n 50 "$STATE/sigma/quiet" >"$STATE/sigma/quiet.new" && mv -f "$STATE/sigma/quiet.new" "$STATE/sigma/quiet"
fi

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
if [ "${PATCH_FAILED:-0}" = 1 ]; then
  fail "installing updates did not finish. Check the run log and fix it before you reboot"
else
  info "reboot now to finish the kernel and library updates"
  [ ! -f "$FLAGS/restart-audit" ] || warn "the audit rules were locked, so the new ones apply only after this reboot"
fi
[ "$FAILED" = 0 ] || exit 1

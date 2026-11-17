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
#   --check              change nothing; check the device against the profile,
#                        write the reports, exit 1 if any check fails
#   --report-only        like --check, but always exit 0
#   -h, --help           show this help
#
# After the first run Legion installs itself as `legion`, so later checks are
# just: sudo legion --check
#
# Without these options Legion asks about Tailscale, private networks and IPv6.
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

ALLOW_UNENCRYPTED=0 STEAM=0 TOOLS=0 YARA=1 AIDE=1 PRO=1 LOCKOUT=1 REPORT_ONLY=0 CHECK=0 DRIFT_ONLY=0 BANNER_SHOWN=0
PRO_TOKEN_FILE=""
TAILSCALE="" ALLOW_FROM="" ALLOW_FROM_SET=0 IPV6="" SSH_ALLOW="" RDP_ALLOW="" # empty means: ask
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
TOTAL=$((11 + WITH_PRO + YARA + AIDE + LOCKOUT + TOOLS))
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

step_audit() {
  apt-get "${APT[@]}" install auditd audispd-plugins
  backup_once /etc/audit/auditd.conf
  local b32=""
  # 32-bit system call rules only apply on x86_64.
  if [ "$ARCH" = x86_64 ]; then
    b32="-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime,stime -k time
-a always,exit -F arch=b32 -S init_module,finit_module,delete_module -k modules"
  fi
  # Exec watches go on the real program, not a link to it: on Ubuntu 26.04
  # /usr/bin/sudo links to sudo-rs and modprobe/insmod link to kmod, and a
  # watch on a link never fires.
  local prog real priv="" mods="" seen=" "
  for prog in /usr/bin/sudo /usr/bin/su; do
    real="$(readlink -f "$prog" 2>/dev/null || true)"
    [ -x "$real" ] && [[ "$seen" != *" $real "* ]] || continue
    seen+="$real " priv+="-w $real -p x -k privilege"$'\n'
  done
  for prog in /usr/sbin/insmod /usr/sbin/modprobe /usr/sbin/rmmod /sbin/insmod /sbin/modprobe; do
    real="$(readlink -f "$prog" 2>/dev/null || true)"
    [ -x "$real" ] && [[ "$seen" != *" $real "* ]] || continue
    seen+="$real " mods+="-w $real -p x -k modules"$'\n'
  done
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
-w /run/faillock/ -p wa -k auth
-w /var/log/lastlog -p wa -k logins
# Privilege escalation
${priv%$'\n'}
# Time changes and kernel modules
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules
$b32
-w /etc/localtime -p wa -k time
${mods%$'\n'}
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
  if [ ! -f "$STATE/backup/sysctl" ] && [ "$IN_CONTAINER" = 0 ]; then
    install -d -m 700 "$STATE/backup"
    local key
    for key in kernel.kptr_restrict fs.suid_dumpable fs.protected_fifos net.core.bpf_jit_harden \
      net.ipv4.conf.all.log_martians net.ipv4.conf.default.log_martians \
      net.ipv4.conf.all.send_redirects net.ipv4.conf.default.send_redirects \
      net.ipv6.conf.all.disable_ipv6 net.ipv6.conf.default.disable_ipv6; do
      echo "$key=$(sysctl -n "$key" 2>/dev/null)"
    done >"$STATE/backup/sysctl"
  fi
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
  # Login screen banner. GDM reads the "gdm" dconf profile; the /etc copy is
  # Ubuntu's own profile with Legion's system database added.
  if [ -f /usr/share/dconf/profile/gdm ] && { [ ! -f /etc/dconf/profile/gdm ] || [ -f "$STATE/backup/created-dconf-profile-gdm" ]; }; then
    awk '{ print } /^user-db:user$/ { print "system-db:gdm" }' /usr/share/dconf/profile/gdm >/etc/dconf/profile/gdm
    : >"$STATE/backup/created-dconf-profile-gdm"
  fi
  if [ ! -f /etc/dconf/profile/gdm ] && [ ! -f /usr/share/dconf/profile/gdm ]; then
    info "no GDM login screen found; graphical login banner skipped"
  elif grep -qx 'system-db:gdm' /etc/dconf/profile/gdm 2>/dev/null; then
    cat >/etc/dconf/db/gdm.d/01-legion-banner <<EOF
[org/gnome/login-screen]
banner-message-enable=true
banner-message-text='$text'
EOF
    info "login screen banner set"
  else
    warn "custom GDM settings profile found; login screen banner not set"
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
}

if [ "$READONLY" = 0 ]; then
  section "Deploying profile"
  [ "$WITH_PRO" = 0 ] || run_step "Ubuntu Pro: ESM security updates and Livepatch" step_pro
  run_step "Patching: install all pending updates" step_patching
  PATCH_FAILED=0
  [ "${RESULTS[${#RESULTS[@]} - 1]%%|*}" = ok ] || PATCH_FAILED=1
  run_step "NVIDIA driver ready for the new kernel" step_nvidia
  run_step "Automatic security updates" step_auto_updates
  run_step "Firewall: block inbound, allow outbound" step_firewall
  run_step "Audit logging (auditd)" step_audit
  run_step "Log retention: 1 year, capped at 2 GB" step_logs
  run_step "Malware protection: ClamAV, weekly scan of /home" step_clamav
  run_step "Password policy: 12+ characters, 3 types" step_passwords
  run_step "System hardening: kernel, protocols, permissions" step_hardening
  [ "$YARA" = 0 ] || run_step "YARA: weekly scan of user-writable folders" step_yara
  [ "$AIDE" = 0 ] || run_step "Integrity: package checksums and AIDE, daily" step_integrity
  run_step "Login: banner and enforced screen lock" step_login
  [ "$LOCKOUT" = 0 ] || run_step "Account lockout: 5 failed logins, 30 minutes" step_lockout
  [ "$TOOLS" = 0 ] || run_step "Tools: audit, secrets, backups, Terraform, Trivy" step_tools
  run_step "Compliance: daily check, SCAP content" step_compliance
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
c_auditd() { in_container && return 2; systemctl is-active -q auditd && return 0; NOTE="auditd not running"; return 1; }
c_audit_rules() {
  in_container && return 2
  local r k
  r="$(auditctl -l 2>/dev/null)"
  for k in identity privilege time modules; do
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
  if [ -f /usr/share/dconf/profile/gdm ] && command -v dconf >/dev/null; then
    if ! grep -qx 'banner-message-enable=true' /etc/dconf/db/gdm.d/01-legion-banner 2>/dev/null ||
      ! grep -qx 'system-db:gdm' /etc/dconf/profile/gdm 2>/dev/null; then
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

# id | check | function | SOC 2 | HIPAA | NIST 800-53 | NIST 800-171 / CMMC L2
CHECKS=(
  "disk-encryption|Full-disk encryption|c_encryption|CC6.1|164.312(a)(2)(iv)|SC-28|3.13.16"
  "fips|FIPS-validated cryptography|c_fips|CC6.1|164.312(a)(2)(iv)|SC-13|3.13.11"
  "security-updates|No pending security updates|c_updates|CC7.1|164.308(a)(1)(ii)(B)|SI-2|3.14.1"
  "auto-updates|Automatic security updates|c_autoupdates|CC7.1|164.308(a)(1)(ii)(B)|SI-2|3.14.1"
  "ubuntu-pro|Ubuntu Pro (ESM security updates)|c_pro|CC7.1|164.308(a)(1)(ii)(B)|SI-2|3.14.1"
  "livepatch|Livepatch (kernel fixes without reboot)|c_livepatch|CC7.1|-|SI-2|3.14.1"
  "firewall|Firewall blocks incoming connections|c_firewall|CC6.6|-|SC-7|3.13.1"
  "listeners|No reachable network services|c_listeners|CC6.6|-|CM-7|3.4.7"
  "ssh|SSH hardened or off|c_ssh|CC6.6|164.312(a)(1)|CM-7|3.4.7"
  "protocols|Unused network protocols blocked|c_protocols|CC6.6|-|CM-7|3.4.6"
  "auditd|Audit logging running|c_auditd|CC7.2|164.312(b)|AU-12|3.3.1"
  "audit-rules|Audit rules for accounts, sudo, time, modules|c_audit_rules|CC7.2|164.312(b)|AU-2|3.3.1"
  "log-retention|System logs kept for 1 year|c_log_retention|CC7.2|164.312(b)|AU-11|3.3.1"
  "log-protection|Audit logs readable only by admins|c_log_protect|CC7.2|164.312(b)|AU-9|3.3.8"
  "time-sync|Clock synchronized|c_time|CC7.2|164.312(b)|AU-8|3.3.7"
  "clamav|ClamAV updates and weekly scan|c_clamav|CC6.8|164.308(a)(5)(ii)(B)|SI-3|3.14.2"
  "yara|YARA weekly scan|c_yara|CC6.8|164.308(a)(5)(ii)(B)|SI-3|3.14.5"
  "integrity|Daily file integrity check|c_integrity|CC7.1|164.312(c)(1)|SI-7|-"
  "secure-boot|Secure Boot|c_secureboot|CC6.8|-|SI-7(9)|-"
  "apparmor|AppArmor confinement|c_apparmor|CC6.8|-|AC-3(3)|-"
  "kernel|Kernel hardening settings|c_kernel|CC7.1|-|CM-6|3.4.2"
  "aslr|Full memory address randomization|c_aslr|CC6.8|-|SI-16|-"
  "password-policy|Password length and complexity|c_password|CC6.1|164.308(a)(5)(ii)(D)|IA-5(1)|3.5.7"
  "lockout|Lockout after failed logins|c_lockout|CC6.1|164.308(a)(5)(ii)(C)|AC-7|3.1.8"
  "empty-passwords|No accounts without a password|c_empty_passwords|CC6.1|164.312(d)|IA-2|3.5.2"
  "uid0|Only root has UID 0|c_uid0|CC6.1|164.312(a)(1)|AC-6|3.1.5"
  "permissions|Cron and sudoers locked to admins|c_perms|CC6.1|164.312(a)(1)|AC-6|3.1.5"
  "screen-lock|Enforced screen lock|c_screenlock|CC6.1|164.312(a)(2)(iii)|AC-11|3.1.10"
  "banner|Login banner|c_banner|-|-|AC-8|3.1.9"
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
  for f in yara-scan.log integrity.log; do [ ! -f "$LOGDIR/$f" ] || tail -n 2000 "$LOGDIR/$f" >"$b/logs/$f"; done
  for f in /etc/audit/rules.d/legion.rules /etc/systemd/journald.conf.d/legion.conf \
    /etc/security/pwquality.conf.d/legion.conf /etc/sysctl.d/60-legion-hardening.conf \
    /etc/modprobe.d/legion-uncommon-net.conf /etc/apt/apt.conf.d/20auto-upgrades /etc/legion/aide.conf \
    /etc/dconf/db/local.d/00-legion-screenlock /etc/dconf/db/gdm.d/01-legion-banner /etc/issue \
    /etc/pam.d/common-auth /etc/pam.d/common-account; do
    [ ! -f "$f" ] || cp "$f" "$b/settings/$(echo "${f#/}" | tr / _)"
  done
  {
    echo "== ufw"; ufw status verbose 2>&1
    echo; echo "== ubuntu pro"; pro status 2>&1
    echo; echo "== audit rules"; auditctl -l 2>&1
    echo; echo "== legion timers"; systemctl list-timers --all --no-pager 'legion*' 'clamscan*' 2>&1
    echo; echo "== failed units"; systemctl --failed --no-pager 2>&1
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
fi
[ "$FAILED" = 0 ] || exit 1

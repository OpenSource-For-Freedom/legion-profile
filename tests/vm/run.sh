#!/usr/bin/env bash
# End-to-end test of Legion on a real Ubuntu 26.04 kernel: boots a cloud
# image in a QEMU virtual machine, runs Legion, checks the audit rules,
# kernel settings and services, reboots, checks again, then removes Legion.
# Needs Docker and /dev/kvm. Nothing on this machine is changed; the cloud
# image is cached in ~/.cache/legion-vm.
#
#   bash tests/vm/run.sh             full test with the desktop and restarts
#   bash tests/vm/run.sh --sensors   compare auditd, Laurel and Sysmon for Linux
#   bash tests/vm/run.sh --attack    attack the device and check every attack left
#                                    evidence; writes attack-report.md
set -euo pipefail
cd "$(dirname "$0")/../.."
[ -e /dev/kvm ] || { echo "no /dev/kvm: hardware virtualization is needed" >&2; exit 2; }
cache="${XDG_CACHE_HOME:-$HOME/.cache}/legion-vm"
mkdir -p "$cache"
base=https://cloud-images.ubuntu.com/resolute/current
img=resolute-server-cloudimg-amd64.img
sum="$(curl -fsSL "$base/SHA256SUMS" | awk -v f="*$img" '$2 == f { print $1 }')"
if [ ! -f "$cache/$img" ] || [ "$(sha256sum <"$cache/$img" | cut -d' ' -f1)" != "$sum" ]; then
  echo "downloading $img"
  curl -fL -o "$cache/$img.part" "$base/$img"
  [ "$(sha256sum <"$cache/$img.part" | cut -d' ' -f1)" = "$sum" ] || { echo "checksum mismatch" >&2; exit 2; }
  mv "$cache/$img.part" "$cache/$img"
fi
docker build -q -t legion-vm-runner -f tests/vm/Dockerfile tests/vm >/dev/null
name="legion-vm-$$"
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
mode=full
case "${1:-}" in --sensors) mode=sensors ;; --attack) mode=attack ;; esac
out="${LEGION_VM_OUT:-$cache/out-$mode}"
rm -rf "$out" && mkdir -p "$out"
echo "screenshots and console log: $out"
docker run --name "$name" --rm --device /dev/kvm -v "$cache:/cache:ro" -v "$PWD:/repo:ro" -v "$out:/out" -e HOST_UID="$(id -u)" -e MODE="$mode" \
  legion-vm-runner bash /repo/tests/vm/inside.sh

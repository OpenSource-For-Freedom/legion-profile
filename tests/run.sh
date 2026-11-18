#!/usr/bin/env bash
# Runs Legion's scenario tests in a throwaway Ubuntu 26.04 container with
# systemd. Needs Docker. Nothing on this machine is changed.
#
#   bash tests/run.sh
#
# Containers share the host kernel, so audit rules and kernel settings are
# written but not loaded; those parts need a real machine or VM to test.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v shellcheck >/dev/null && shellcheck -S style legion.sh legion-remove.sh tests/*.sh && echo "shellcheck: clean"
bash -n legion.sh legion-remove.sh
name="legion-test-$$"
image="legion-test:26.04"
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker build -q -t "$image" -f tests/Dockerfile tests >/dev/null
docker run -d -t --name "$name" -e LANG=C.UTF-8 \
  --cap-add NET_ADMIN --cap-add SYS_ADMIN --security-opt apparmor=unconfined \
  --tmpfs /run --tmpfs /run/lock --cgroupns=private \
  "$image" sh -c 'mount -o remount,rw /sys/fs/cgroup && exec /sbin/init' >/dev/null
for _ in $(seq 1 60); do
  case "$(docker exec "$name" systemctl is-system-running 2>/dev/null || true)" in running | degraded) break ;; esac
  sleep 1
done
for f in legion.sh legion-remove.sh tests/scenario.sh; do docker cp "$f" "$name:/root/"; done
docker exec "$name" mkdir -p /root/assets
docker cp assets/legion-login-logo.png "$name:/root/assets/"
out="$(docker exec "$name" bash /root/scenario.sh)"
echo "$out"
grep -q 'RESULT: .* 0 failed' <<<"$out"

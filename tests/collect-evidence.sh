#!/usr/bin/env bash
# Copies the output of the last test runs into reports/evidence/DATE/, so the
# results in reports/ can be checked against the raw logs:
#
#   bash tests/run.sh               > .testlogs/container.log 2>&1
#   bash tests/vm/run.sh            > .testlogs/vm.log 2>&1
#   bash tests/vm/run.sh --attack   > .testlogs/attack.log 2>&1
#   bash tests/vm/run.sh --sensors  > .testlogs/sensors.log 2>&1
#   bash tests/collect-evidence.sh
#
# Paths on the machine that ran the tests are replaced with placeholders.
# Every file gets a SHA-256 checksum in SHA256SUMS.
set -euo pipefail
cd "$(dirname "$0")/.."
cache="${XDG_CACHE_HOME:-$HOME/.cache}/legion-vm"
day="$(date -u +%F)"
dest="reports/evidence/$day"
rm -rf "$dest"
mkdir -p "$dest/screenshots"
clean() { # removes this machine's paths and user name from text
  sed -e "s#$PWD#<repo>#g" -e "s#$cache#<vm-cache>#g" -e "s#$HOME#<home>#g"
}
for f in container vm attack sensors; do
  [ ! -s ".testlogs/$f.log" ] || clean <".testlogs/$f.log" >"$dest/$f.log"
done
[ ! -s "$cache/out-attack/attack-report.md" ] || cp "$cache/out-attack/attack-report.md" "$dest/"
# Screenshots and the serial console (logins and the banner as a person sees
# them) from the latest desktop run; older runners wrote them to out/.
full="$cache/out-full"
ls "$full"/*.png >/dev/null 2>&1 || full="$cache/out"
cp "$full"/*.png "$dest/screenshots/" 2>/dev/null || true
[ ! -s "$full/console.log" ] || clean <"$full/console.log" | gzip -9 >"$dest/vm-console.log.gz"
git rev-parse HEAD >"$dest/tested-commit.txt" 2>/dev/null || true
git status --short >>"$dest/tested-commit.txt" 2>/dev/null || true
sums="$(cd "$dest" && find . -type f -print0 | sort -z | xargs -0 sha256sum)"
echo "$sums" >"$dest/SHA256SUMS"
if grep -rIl -e "$HOME" -e "$(id -un)@" "$dest" 2>/dev/null; then
  echo "a file above still names this machine; not safe to commit" >&2; exit 1
fi
echo "evidence in $dest"

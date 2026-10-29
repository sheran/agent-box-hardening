#!/usr/bin/env bash
# make-chain.sh - record a new known version ("chain") of a managed file.
#
# A chain is the allowlist entry box-hardening.sh uses to re-harden one
# platform version of a file:
#   <chains dir>/<set>/<version>/orig.sha256       stock file as shipped
#   <chains dir>/<set>/<version>/sandboxed.sha256  stock minus --no-sandbox lines (optional)
#   <chains dir>/<set>/<version>/hardened.sha256   the only state that PASSes
#   <chains dir>/<set>/<version>/patch.diff        (sandboxed or stock) -> hardened
#
# Usage: tools/make-chain.sh [--strip-no-sandbox] CHAINS_DIR SET VERSION STOCK_FILE HARDENED_FILE
#
# Run it on a workstation after you have reviewed a new stock file and written
# its hardened version by hand. Commit the result, regenerate SHA256SUMS, and
# have a human approve the new SHA256SUMS hash before deploying.
set -euo pipefail
strip=0
if [ "${1:-}" = --strip-no-sandbox ]; then strip=1; shift; fi
[ $# -eq 5 ] || { sed -n '2,17p' "$0" >&2; exit 2; }
dir="$1/$2/$3" stock="$4" hard="$5"
[[ "$2" =~ ^[A-Za-z0-9._-]+$ && "$3" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "make-chain: bad set/version name" >&2; exit 2; }
[ ! -e "${dir}" ] || { echo "make-chain: ${dir} already exists; pick a new version name" >&2; exit 1; }
sha() { sha256sum "$1" | cut -d' ' -f1; }
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
base="${stock}"
if [ "${strip}" -eq 1 ]; then
	sed -E '/^[[:space:]]*--no-sandbox[[:space:]]*$/d' "${stock}" >"${work}/sandboxed"
	cmp -s "${stock}" "${work}/sandboxed" && { echo "make-chain: no standalone --no-sandbox line in ${stock}" >&2; exit 1; }
	base="${work}/sandboxed"
fi
if grep -Eq -- '(^|[[:space:]])--no-sandbox([[:space:]]|$)' "${hard}"; then
	echo "make-chain: hardened file still contains --no-sandbox" >&2; exit 1
fi
# diff exits 1 when the files differ, which is the normal case here.
diff -u --label stock --label hardened "${base}" "${hard}" >"${work}/patch.diff" || [ $? -eq 1 ]
[ -s "${work}/patch.diff" ] || { echo "make-chain: hardened file equals the stock file" >&2; exit 1; }
patch -s --no-backup-if-mismatch -r - -o "${work}/check" "${base}" <"${work}/patch.diff" >/dev/null
cmp -s "${work}/check" "${hard}" || { echo "make-chain: patch does not reproduce the hardened file" >&2; exit 1; }
mkdir -p "${dir}"
sha "${stock}" >"${dir}/orig.sha256"
[ "${strip}" -eq 0 ] || sha "${base}" >"${dir}/sandboxed.sha256"
sha "${hard}" >"${dir}/hardened.sha256"
cp "${work}/patch.diff" "${dir}/patch.diff"
echo "make-chain: wrote ${dir} (stock $(cut -c1-12 "${dir}/orig.sha256") -> hardened $(cut -c1-12 "${dir}/hardened.sha256"))"

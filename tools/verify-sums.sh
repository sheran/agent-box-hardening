#!/usr/bin/env bash
# tools/verify-sums.sh [DIR] - check an installed copy before root runs it.
#   1. SHA256SUMS must hash to the human-approved value in
#      ${APPROVED_SUMS:-/etc/box-hardening/approved-sums.sha256}
#      (a root-owned file, not group/other writable)
#   2. every file listed in SHA256SUMS must match
#   3. no unlisted *.sh / *.py may exist in the tree (nothing smuggled in)
# Exit 0 = approved and intact, 1 = mismatch, 2 = no approval recorded.
set -euo pipefail
export LC_ALL=C
DIR="${1:-$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/..}"
APPROVED="${APPROVED_SUMS:-/etc/box-hardening/approved-sums.sha256}"
cd "${DIR}"
if [ ! -f "${APPROVED}" ] || [ -L "${APPROVED}" ]; then
	echo "verify-sums: no approved hash at ${APPROVED}; a human must approve SHA256SUMS first" >&2; exit 2
fi
st="$(stat -c '%u %a' "${APPROVED}")"
if [ "${REQUIRE_ROOT_APPROVAL:-1}" = 1 ] && { [ "${st%% *}" != 0 ] || [ $((0${st##* } & 022)) -ne 0 ]; }; then
	echo "verify-sums: ${APPROVED} must be root-owned and not group/other writable" >&2; exit 1
fi
want="$(tr -cd '0-9a-f' <"${APPROVED}" | cut -c1-64)"
have="$(sha256sum SHA256SUMS | cut -d' ' -f1)"
if [ "${want}" != "${have}" ]; then
	echo "verify-sums: SHA256SUMS is ${have:0:12}..., approved is ${want:0:12}...; review the change and re-approve" >&2; exit 1
fi
sha256sum --quiet -c SHA256SUMS || { echo "verify-sums: files differ from SHA256SUMS" >&2; exit 1; }
extra="$(find . -path ./.git -prune -o -type f \( -name '*.sh' -o -name '*.py' \) -print | sed 's|^\./||' | sort |
	comm -23 - <(cut -c67- SHA256SUMS | sort))"
if [ -n "${extra}" ]; then echo "verify-sums: unlisted code: ${extra//$'\n'/ }" >&2; exit 1; fi
echo "verify-sums: OK (approved ${have:0:12}..., $(wc -l <SHA256SUMS) files)"

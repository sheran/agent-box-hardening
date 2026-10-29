#!/usr/bin/env bash
# tests/run-all.sh - everything CI (or you) should run before approving a change.
# Needs no root and no private files: every test uses temp directories.
set -uo pipefail
cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." || exit 2
fail=0
step() { echo "== $1"; shift; if "$@"; then echo "-- ok"; else echo "-- FAILED"; fail=1; fi; }
mapfile -t SH < <(git ls-files -co --exclude-standard '*.sh' 'config/*.example' 'examples/stock/*' | grep -v '\.md$' | sort)
if command -v shellcheck >/dev/null; then step "shellcheck (${#SH[@]} files)" shellcheck -x -s bash "${SH[@]}"
else echo "== shellcheck not installed; skipped"; fi
step "bash -n" bash -c 'for f in "$@"; do bash -n "$f" || exit 1; done' _ "${SH[@]}"
step "python compile" python3 -c 'import ast,sys; ast.parse(open(sys.argv[1]).read())' box-drift.py
step "box-hardening selftest" ./box-hardening.sh --selftest
step "fast-fix selftest" ./box-fastfix-watch.sh --selftest
step "drift selftest" ./box-drift.py --selftest
# shellcheck disable=SC2317  # sums_test is called through step
sums_test() {
	local t rc=0
	t="$(mktemp -d)"
	git ls-files -co --exclude-standard | grep -vx SHA256SUMS | xargs -d '\n' cp --parents -t "${t}"
	(cd "${t}" && LC_ALL=C find . -type f ! -name SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort | xargs -d '\n' sha256sum >"${t}.sums" && mv "${t}.sums" SHA256SUMS)
	sha256sum "${t}/SHA256SUMS" | cut -d' ' -f1 >"${t}.approved"
	APPROVED_SUMS="${t}.approved" REQUIRE_ROOT_APPROVAL=0 ./tools/verify-sums.sh "${t}" >/dev/null || rc=1
	echo '# tampered' >>"${t}/box-hardening.sh"
	APPROVED_SUMS="${t}.approved" REQUIRE_ROOT_APPROVAL=0 ./tools/verify-sums.sh "${t}" >/dev/null 2>&1 && rc=1
	rm -rf "${t}" "${t}.approved"
	return "${rc}"
}
step "verify-sums accepts approved tree, refuses tampered one" sums_test
[ "${fail}" -eq 0 ] && echo "ALL TESTS PASSED" || echo "SOME TESTS FAILED"
exit "${fail}"

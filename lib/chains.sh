# shellcheck shell=bash
# lib/chains.sh - the known-version engine (hash allowlist) for managed files.
#
# ${CHAINS_DIR}/<set>/<version>/ holds orig.sha256, optional sandboxed.sha256,
# hardened.sha256 and patch.diff. A file is only ever turned into the hardened
# hash of the version it came from; anything else is refused and left alone.

read_hash() { local h; h="$(tr -cd '0-9a-f' <"$1" 2>/dev/null | cut -c1-64)"; [ "${#h}" -eq 64 ] && echo "${h}"; }

# chain_for SET HASH -> CH_DIR CH_ORIG CH_SB CH_HARD CH_ROLE (orig|sandboxed|hardened); 1 if unknown
chain_for() {
	local set="$1" h="$2" d o s k
	CH_DIR="" CH_ORIG="" CH_SB="" CH_HARD="" CH_ROLE=""
	[ -d "${CHAINS_DIR}/${set}" ] || return 1
	for d in "${CHAINS_DIR}/${set}"/*/; do
		d="${d%/}"
		[ -f "${d}/patch.diff" ] || continue
		o="$(read_hash "${d}/orig.sha256" || true)"; k="$(read_hash "${d}/hardened.sha256" || true)"
		s=""; [ ! -f "${d}/sandboxed.sha256" ] || s="$(read_hash "${d}/sandboxed.sha256" || true)"
		[ -n "${o}" ] && [ -n "${k}" ] || continue
		case "${h}" in
		"${k}") CH_ROLE=hardened ;;
		"${o}") CH_ROLE=orig ;;
		*) if [ -n "${s}" ] && [ "${h}" = "${s}" ]; then CH_ROLE=sandboxed; else continue; fi ;;
		esac
		CH_DIR="${d}" CH_ORIG="${o}" CH_SB="${s}" CH_HARD="${k}"
		return 0
	done
	return 1
}
hardened_hashes() { # hardened_hashes SET -> every known hardened hash of the set
	local d
	for d in "${CHAINS_DIR}/$1"/*/; do
		[ -f "${d}patch.diff" ] && read_hash "${d}hardened.sha256" || true
	done
}

# build_hardened SET IN OUT -> 0 and OUT is the hardened file, or 1 + MSG
build_hardened() {
	local set="$1" in="$2" out="$3" h work base
	h="$(sha "${in}")"
	if ! chain_for "${set}" "${h}"; then
		MSG="${set}: hash ${h:0:12}... is not a known version; not patching blind (review the new platform file, add a chain, get the new SHA256SUMS approved)"
		return 1
	fi
	work="$(mktemp -d)"
	case "${CH_ROLE}" in
	hardened) cp "${in}" "${out}"; rm -rf "${work}"; return 0 ;;
	sandboxed) base="${in}" ;;
	orig)
		base="${in}"
		if [ -n "${CH_SB}" ]; then
			sed -E '/^[[:space:]]*--no-sandbox[[:space:]]*$/d' "${in}" >"${work}/sandboxed"
			if [ "$(sha "${work}/sandboxed")" != "${CH_SB}" ]; then
				MSG="${set}: removing --no-sandbox did not give the known sandboxed hash"; rm -rf "${work}"; return 1
			fi
			base="${work}/sandboxed"
		fi
		;;
	esac
	if ! patch -s --no-backup-if-mismatch -r - -o "${work}/hardened" "${base}" <"${CH_DIR}/patch.diff" >/dev/null 2>&1; then
		MSG="${set}: hardening patch did not apply cleanly"; rm -rf "${work}"; return 1
	fi
	if [ "$(sha "${work}/hardened")" != "${CH_HARD}" ]; then
		MSG="${set}: patched file differs from the known hardened hash"; rm -rf "${work}"; return 1
	fi
	cp "${work}/hardened" "${out}"; rm -rf "${work}"
}

# check_target PATH SET ROOT_OWNED: PASS only on a known hardened hash
check_target() {
	local f="$1" set="$2" root="$3" h label
	[ -f "${f}" ] || { MSG="${f} missing"; return 1; }
	h="$(sha "${f}")"
	if chain_for "${set}" "${h}"; then
		case "${CH_ROLE}" in
		hardened) label="known hardened ${h:0:8} ($(basename "${CH_DIR}"))" ;;
		orig) label="STOCK version ${h:0:8} ($(basename "${CH_DIR}"))" ;;
		sandboxed) label="sandbox-only version ${h:0:8} ($(basename "${CH_DIR}"))" ;;
		esac
	else label="unknown hash ${h:0:12}..."; fi
	if grep -Eq -- '(^|[[:space:]])--no-sandbox([[:space:]]|$)' "${f}"; then MSG="${label}: --no-sandbox present"; return 1; fi
	[ "${CH_ROLE}" = hardened ] || { MSG="${label}: not the hardened version"; return 1; }
	if [ "${root}" = 1 ] && ! root_owned_ok "${f}"; then
		MSG="hardened content but $(stat -c '%U:%G %a' "${f}"), want root-owned, not group/other writable"; return 1
	fi
	MSG="${label}, $(stat -c '%U:%G %a' "${f}")"
}
fix_target() {
	local f="$1" set="$2" root="$3" out
	[ -f "${f}" ] || { MSG="${f} missing (layout changed?); not creating it, review"; return 1; }
	out="$(mktemp)"
	build_hardened "${set}" "${f}" "${out}" || { rm -f "${out}"; return 1; }
	if [ "$(sha "${f}")" != "$(sha "${out}")" ]; then
		backup "${f}" && install_like "${out}" "${f}"
		log "${f} re-hardened (takes effect at the next start through it)"
	fi
	rm -f "${out}"
	[ "${root}" != 1 ] || { chown root:root "${f}" && chmod go-w "${f}"; }
}
CUR_T_PATH="" CUR_T_SET="" CUR_T_ROOT=""
c_target() { check_target "${CUR_T_PATH}" "${CUR_T_SET}" "${CUR_T_ROOT}"; }
f_target() { fix_target "${CUR_T_PATH}" "${CUR_T_SET}" "${CUR_T_ROOT}"; }
targets_step() { # targets_step SECTION
	local t sec path set root
	for t in "${TARGETS[@]}"; do
		IFS='|' read -r sec path set root <<<"${t}"
		[ "${sec}" = "$1" ] || continue
		CUR_T_PATH="${path}" CUR_T_SET="${set}" CUR_T_ROOT="${root:-0}"
		step "$1" "${path}: known hardened version" c_target f_target
	done
}
list_targets() {
	local t sec path set root hs
	for t in "${TARGETS[@]}"; do
		IFS='|' read -r sec path set root <<<"${t}"
		hs="$(hardened_hashes "${set}" | tr '\n' ' ')"
		printf '%s|%s|%s|%s\n' "${sec}" "${path}" "${hs% }" "${root:-0}"
	done
}

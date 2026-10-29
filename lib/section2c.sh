# shellcheck shell=bash
# lib/section2c.sh - Section 2C: file and socket permissions.
#
# The browser user has no supplementary groups, so "other" bits are all that
# stand between it and the agent's files. Keep the workspace closed to
# others, nothing world-writable inside it, the private dirs you list at 700,
# and local control sockets at an owner/mode you choose.

c2c_workspace() { local m; m="$(stat -c '%U:%G %a' "${WORKSPACE}")"; MSG="${WORKSPACE} ${m}"; [ "${m##* }" = 750 ]; }
f2c_workspace() { chmod 750 "${WORKSPACE}"; }
c2c_ww() {
	local c
	c="$(find "${WORKSPACE}" -xdev \( -type f -o -type d \) -perm -0002 -print 2>/dev/null | wc -l)"
	MSG="${c} world-writable files/dirs under ${WORKSPACE}"; [ "${c}" -eq 0 ]
}
f2c_ww() { find "${WORKSPACE}" -xdev \( -type f -o -type d \) -perm -0002 -exec chmod o-w {} +; }
CUR_DIR="" CUR_SOCK="" CUR_SOCK_OWN="" CUR_SOCK_MODE=""
c2c_dir() { MSG="${CUR_DIR} $(stat -c '%U:%G %a' "${CUR_DIR}")"; [ "$(stat -c %a "${CUR_DIR}")" = 700 ]; }
f2c_dir() { chmod 700 "${CUR_DIR}"; }
c2c_sock() {
	MSG="${CUR_SOCK} $(stat -c '%U:%G %a' "${CUR_SOCK}")"
	[ "$(stat -c '%U:%G %a' "${CUR_SOCK}")" = "${CUR_SOCK_OWN} ${CUR_SOCK_MODE}" ]
}
f2c_sock() { chown "${CUR_SOCK_OWN}" "${CUR_SOCK}" && chmod "${CUR_SOCK_MODE}" "${CUR_SOCK}"; }
private_dir_list() {
	local g d
	for g in "${PRIVATE_DIRS[@]}"; do
		# shellcheck disable=SC2086  # globs in PRIVATE_DIRS are meant to expand
		for d in ${g}; do [ -d "${d}" ] && [ ! -L "${d}" ] && echo "${d}"; done
	done | sort -u
}
section_2c() {
	local d s
	log "== Section 2 Part C: file and socket permissions =="
	step 2C "${WORKSPACE} mode 750" c2c_workspace f2c_workspace
	step 2C "no world-writable under ${WORKSPACE}" c2c_ww f2c_ww
	for d in $(private_dir_list); do CUR_DIR="${d}"; step 2C "${d} mode 700" c2c_dir f2c_dir; done
	for s in "${SOCKETS[@]}"; do
		IFS='|' read -r CUR_SOCK CUR_SOCK_OWN CUR_SOCK_MODE <<<"${s}"
		if [ -S "${CUR_SOCK}" ]; then step 2C "$(basename "${CUR_SOCK}") ${CUR_SOCK_MODE} ${CUR_SOCK_OWN}" c2c_sock f2c_sock
		else record 2C "$(basename "${CUR_SOCK}") ${CUR_SOCK_MODE} ${CUR_SOCK_OWN}" SKIP "${CUR_SOCK} not present"; fi
	done
}

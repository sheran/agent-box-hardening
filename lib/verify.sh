# shellcheck shell=bash
# lib/verify.sh - final verification: "browser user denied, agent works".
# Everything here is a live retest of the property, not a re-read of config.

verify_browser() {
	local p cnt wronguser nosb rend seccomp_ok code
	if ! getent passwd "${BROWSER_USER}" >/dev/null; then vrec V/1 "browser user cannot sudo" 1 "user ${BROWSER_USER} missing (cannot test)"
	elif runuser -u "${BROWSER_USER}" -- sudo -n -l >/dev/null 2>&1; then vrec V/1 "browser user cannot sudo" 1 "${BROWSER_USER} has sudo rights"
	else vrec V/1 "browser user cannot sudo" 0 "sudo -n -l refused for ${BROWSER_USER}"; fi
	nosb="$(pgrep -f -- "${BROWSER_PROC_REGEX}.*--no-sandbox" | wc -l || true)"
	cnt="$(pgrep -u "${BROWSER_USER}" -f -- "--user-data-dir=${BROWSER_PROFILE_DIR}" | wc -l || true)"
	wronguser="$(pgrep -f -- "--user-data-dir=${BROWSER_PROFILE_DIR}" | while read -r p; do
		[ "$(stat -c %U "/proc/${p}" 2>/dev/null)" = "${BROWSER_USER}" ] || echo "${p}"
	done | wc -l || true)"
	if [ "${nosb}" -gt 0 ] || [ "${wronguser}" -gt 0 ]; then
		vrec V/1 "browser user + sandbox" 1 "${nosb} browser process(es) with --no-sandbox, ${wronguser} on the browser profile not running as ${BROWSER_USER}"
	elif [ "${cnt}" -eq 0 ]; then
		record V/1 "browser user + sandbox" SKIP "no browser on ${BROWSER_PROFILE_DIR} running"
	else
		rend=0 seccomp_ok=0
		for p in $(pgrep -u "${BROWSER_USER}" -f -- "--type=renderer" || true); do
			rend=$((rend + 1))
			[ "$(awk '/^Seccomp:/{print $2}' "/proc/${p}/status" 2>/dev/null)" != 2 ] || seccomp_ok=$((seccomp_ok + 1))
		done
		[ "${rend}" -eq "${seccomp_ok}" ] && code=0 || code=1
		vrec V/1 "browser user + sandbox" "${code}" "${cnt} procs as ${BROWSER_USER}, none --no-sandbox; renderers Seccomp:2 ${seccomp_ok}/${rend}"
	fi
}
verify_firewall() {
	local p n allowed ports=0
	for p in "${NFT_ALLOWED_LO_PORTS[@]}"; do
		[ -n "$(ss -ltnH "sport = :${p}" 2>/dev/null)" ] || continue
		if tcp_ok_as "${BROWSER_USER}" "${p}"; then vrec V/2A "browser -> lo:${p} allowed" 0 "connects"
		else vrec V/2A "browser -> lo:${p} allowed" 1 "blocked (browsing may break)"; fi
	done
	# Every other listening local TCP port must be dropped for the browser user.
	for p in $(ss -ltnH 2>/dev/null | awk '{ n = $4; sub(/.*:/, "", n); print n }' | sort -un); do
		allowed=0
		for n in "${NFT_ALLOWED_LO_PORTS[@]}"; do [ "${n}" != "${p}" ] || allowed=1; done
		[ "${allowed}" -eq 0 ] || continue
		ports=$((ports + 1))
		[ "${ports}" -le "${VERIFY_MAX_PORTS}" ] || { record V/2A "more ports" SKIP "stopped after ${VERIFY_MAX_PORTS} ports"; break; }
		if tcp_ok_as "${BROWSER_USER}" "${p}"; then vrec V/2A "browser -> lo:${p} blocked" 1 "browser user connected"
		elif tcp_ok_as "${AGENT_USER}" "${p}"; then vrec V/2A "browser -> lo:${p} blocked" 0 "browser dropped, agent connects"
		else record V/2A "browser -> lo:${p} blocked" WARN "the agent cannot connect either (bound elsewhere?)"; fi
	done
}
verify_x() {
	local n mode code
	for n in $(x_display_list); do
		mode="$(xvfb_mode "${n}")"
		x_connect "${AGENT_USER}" "${AGENT_XAUTH}" "${n}" && code=0 || code=1
		vrec V/2B ":${n} agent with cookie connects" "${code}" "Xvfb ${mode}"
		if x_connect "${AGENT_USER}" /dev/null "${n}"; then vrec V/2B ":${n} no-cookie client refused" 1 "connected without a cookie"
		else vrec V/2B ":${n} no-cookie client refused" 0 "refused"; fi
		if [ "${n}" = "${BROWSER_DISPLAY}" ]; then
			x_connect "${BROWSER_USER}" "${BROWSER_XAUTH}" "${n}" && code=0 || code=1
			vrec V/2B ":${n} browser user connects (own display)" "${code}" ""
		elif x_connect "${BROWSER_USER}" "${BROWSER_XAUTH}" "${n}"; then vrec V/2B ":${n} browser user refused" 1 "connected"
		else vrec V/2B ":${n} browser user refused" 0 "refused"; fi
	done
}
verify_files() {
	local p
	if runuser -u "${BROWSER_USER}" -- ls "${WORKSPACE}" >/dev/null 2>&1; then vrec V/2C "browser lists ${WORKSPACE}" 1 "allowed"
	elif runuser -u "${AGENT_USER}" -- ls "${WORKSPACE}" >/dev/null 2>&1; then vrec V/2C "browser lists ${WORKSPACE}" 0 "denied; agent works"
	else vrec V/2C "browser lists ${WORKSPACE}" 1 "the agent cannot list it either"; fi
	for p in $(private_dir_list); do
		if runuser -u "${BROWSER_USER}" -- ls "${p}" >/dev/null 2>&1; then vrec V/2C "browser reads ${p}" 1 "allowed"
		else vrec V/2C "browser reads ${p}" 0 "denied"; fi
	done
	for p in "${SOCKETS[@]}"; do
		p="${p%%|*}"
		[ -S "${p}" ] || continue
		if runuser -u "${BROWSER_USER}" -- test -w "${p}"; then vrec V/2C "browser cannot use $(basename "${p}")" 1 "socket writable by ${BROWSER_USER}"
		else vrec V/2C "browser cannot use $(basename "${p}")" 0 "not writable by ${BROWSER_USER}"; fi
	done
}
section_v() {
	log "== Final verification =="
	if ! getent passwd "${BROWSER_USER}" >/dev/null; then
		record V "verification" FAIL "user ${BROWSER_USER} missing; nothing to verify against (run --apply)"
		return 0
	fi
	if want V || want 1; then verify_browser; fi
	if want V || want 2A; then verify_firewall; fi
	if want V || want 2B; then verify_x; fi
	if want V || want 2C; then verify_files; fi
}

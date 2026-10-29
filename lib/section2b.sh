# shellcheck shell=bash
# lib/section2b.sh - Section 2B: X display cookie auth.
#
# Each Xvfb display :N should run with -auth ${XAUTH_SRV_PREFIX}N instead of
# -ac. The agent's ~/.Xauthority holds every display's cookie; the browser
# user's ~/.Xauthority holds only its own display's cookie, so a compromised
# browser cannot read or inject input into the agent's other displays.

CUR_N=""
c2b_cookie() {
	local n="${CUR_N}" srv="${XAUTH_SRV_PREFIX}${CUR_N}" srvc agentset mode
	mode="$(xvfb_mode "${n}")"
	[ -f "${srv}" ] && [ ! -L "${srv}" ] || { MSG="${srv} missing (Xvfb :${n} is ${mode})"; return 1; }
	[ "$(stat -c '%U:%G %a' "${srv}")" = "${AGENT_USER}:${AGENT_USER} 600" ] ||
		{ MSG="${srv} is $(stat -c '%U:%G %a' "${srv}"), want ${AGENT_USER}:${AGENT_USER} 600"; return 1; }
	srvc="$(cookies_for "${srv}" "${n}" | sed -n 1p)"
	[ -n "${srvc}" ] || { MSG="${srv} holds no cookie for :${n}"; return 1; }
	[ -f "${AGENT_XAUTH}" ] && [ "$(stat -c '%U:%G %a' "${AGENT_XAUTH}")" = "${AGENT_USER}:${AGENT_USER} 600" ] ||
		{ MSG="${AGENT_XAUTH} missing or not ${AGENT_USER}:${AGENT_USER} 600"; return 1; }
	agentset="$(cookies_for "${AGENT_XAUTH}" "${n}")"
	[[ $'\n'"${agentset}"$'\n' == *$'\n'"${srvc}"$'\n'* ]] || { MSG="${AGENT_XAUTH} lacks the :${n} server cookie"; return 1; }
	if [ "${mode}" = auth ] && ! x_connect "${AGENT_USER}" "${AGENT_XAUTH}" "${n}"; then
		MSG="Xvfb :${n} rejects the agent's cookie (stale cookie vs running server)"; return 1
	fi
	MSG="server cookie 600, in the agent's .Xauthority"
	[ "${mode}" != auth ] || MSG="${MSG}, accepted by the live Xvfb"
}
f2b_cookie() {
	local n="${CUR_N}" srv="${XAUTH_SRV_PREFIX}${CUR_N}" mode srvc agc cookie="" agentset
	mode="$(xvfb_mode "${n}")"
	srvc="$(cookies_for "${srv}" "${n}" | sed -n 1p)"
	agc="$(cookies_for "${AGENT_XAUTH}" "${n}" | sed -n 1p)"
	if [ "${mode}" = auth ]; then
		# The running server already has a cookie; never replace it.
		if [ -n "${srvc}" ] && x_connect "${AGENT_USER}" "${srv}" "${n}"; then cookie="${srvc}"
		elif [ -n "${agc}" ] && x_connect "${AGENT_USER}" "${AGENT_XAUTH}" "${n}"; then cookie="${agc}"
		else MSG="Xvfb :${n} runs with -auth but no cookie on disk is accepted; needs a display restart"; return 1; fi
	else
		cookie="${srvc:-${agc:-}}"
		[ -n "${cookie}" ] || cookie="$(mcookie)"
	fi
	if [ "${srvc}" != "${cookie}" ] || [ -L "${srv}" ] || [ "$(stat -c %U "${srv}" 2>/dev/null)" != "${AGENT_USER}" ]; then
		rm -f "${srv}"
		xauth_add "${AGENT_USER}" "${srv}" "${n}" "${cookie}" || { MSG="writing ${srv} failed"; return 1; }
	fi
	chmod 600 "${srv}"
	agentset="$(cookies_for "${AGENT_XAUTH}" "${n}")"
	if [[ $'\n'"${agentset}"$'\n' != *$'\n'"${cookie}"$'\n'* ]]; then
		xauth_add "${AGENT_USER}" "${AGENT_XAUTH}" "${n}" "${cookie}" || { MSG="merging into ${AGENT_XAUTH} failed"; return 1; }
	fi
	chmod 600 "${AGENT_XAUTH}"
	cookie="" srvc="" agc=""
}
c2b_browser() {
	local n="${BROWSER_DISPLAY}" srvc bc ds
	getent passwd "${BROWSER_USER}" >/dev/null || { MSG="user ${BROWSER_USER} missing"; return 1; }
	[ -f "${BROWSER_XAUTH}" ] || { MSG="${BROWSER_XAUTH} missing"; return 1; }
	[ "$(stat -c '%U:%G %a' "${BROWSER_XAUTH}")" = "${BROWSER_USER}:${BROWSER_USER} 600" ] ||
		{ MSG="${BROWSER_XAUTH} is $(stat -c '%U:%G %a' "${BROWSER_XAUTH}"), want ${BROWSER_USER}:${BROWSER_USER} 600"; return 1; }
	ds="$(displays_in "${BROWSER_XAUTH}" | tr '\n' ' ')"
	[ "${ds}" = "${n} " ] || { MSG="${BROWSER_XAUTH} holds displays [${ds% }], want only :${n}"; return 1; }
	srvc="$(cookies_for "${XAUTH_SRV_PREFIX}${n}" "${n}" | sed -n 1p)"
	bc="$(cookies_for "${BROWSER_XAUTH}" "${n}" | sed -n 1p)"
	[ -n "${srvc}" ] && [ "${srvc}" = "${bc}" ] || { MSG="the browser user's :${n} cookie does not match ${XAUTH_SRV_PREFIX}${n}"; return 1; }
	MSG="${BROWSER_USER}:${BROWSER_USER} 600, only :${n}, matches the server cookie"
}
f2b_browser() {
	local n="${BROWSER_DISPLAY}" srvc tmp
	srvc="$(cookies_for "${XAUTH_SRV_PREFIX}${n}" "${n}" | sed -n 1p)"
	[ -n "${srvc}" ] || { MSG="no :${n} server cookie to copy (cookie step failed)"; return 1; }
	tmp="$(runuser -u "${BROWSER_USER}" -- mktemp "${BROWSER_HOME}/.Xauthority.bh.XXXXXX")" || { MSG="mktemp failed"; return 1; }
	if ! xauth_add "${BROWSER_USER}" "${tmp}" "${n}" "${srvc}"; then rm -f "${tmp}"; MSG="xauth write failed"; return 1; fi
	srvc=""
	runuser -u "${BROWSER_USER}" -- mv -f "${tmp}" "${BROWSER_XAUTH}" && chmod 600 "${BROWSER_XAUTH}"
}
c2b_live() {
	local n="${CUR_N}" mode
	mode="$(xvfb_mode "${n}")"
	case "${mode}" in
	auth) MSG="Xvfb :${n} running with -auth (no -ac)" ;;
	none) MSG="Xvfb :${n} not running" ;;
	ac) MSG="Xvfb :${n} still running with -ac (cookie auth not in force until it restarts)"; return 1 ;;
	*) MSG="Xvfb :${n} running without -ac or -auth (unexpected)"; return 1 ;;
	esac
}
f2b_live() {
	if [ "${MODE}" = watch ]; then
		MSG="Xvfb :${CUR_N} on -ac needs a restart; --watch never restarts displays (run --apply --restart-displays when idle)"; return 1
	fi
	if [ "${RESTART_DISPLAYS}" -ne 1 ]; then
		MSG="needs an Xvfb restart; rerun with --apply --restart-displays (dead-man's switch armed)"; return 1
	fi
	restart_display "${CUR_N}"
}

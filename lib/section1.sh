# shellcheck shell=bash
# lib/section1.sh - Section 1: the browser user, its sudo rule, and the launcher.

c1_user() {
	local pw uid shell home groups
	pw="$(getent passwd "${BROWSER_USER}" || true)"
	[ -n "${pw}" ] || { MSG="user ${BROWSER_USER} does not exist"; return 1; }
	uid="$(cut -d: -f3 <<<"${pw}")"; home="$(cut -d: -f6 <<<"${pw}")"; shell="$(cut -d: -f7 <<<"${pw}")"
	groups="$(id -Gn "${BROWSER_USER}")"
	MSG="uid ${uid}, groups '${groups}', shell ${shell}, home ${home}"
	[ "${uid}" != 0 ] || { MSG="${MSG}; uid 0!"; return 1; }
	[ "${home}" = "${BROWSER_HOME}" ] || { MSG="${MSG}; home should be ${BROWSER_HOME}"; return 1; }
	case "${shell}" in /usr/sbin/nologin | /sbin/nologin | /bin/false | /usr/bin/false) ;; *) MSG="${MSG}; login shell should be nologin"; return 1 ;; esac
	[ "${groups}" = "${BROWSER_USER}" ] || { MSG="${MSG}; must have no supplementary groups (the agent's group would undo Section 2C)"; return 1; }
}
f1_user() {
	local uopt=() gopt=()
	if ! getent passwd "${BROWSER_USER}" >/dev/null; then
		if [ -n "${BROWSER_PREFERRED_UID}" ]; then
			getent passwd "${BROWSER_PREFERRED_UID}" >/dev/null || uopt=(-u "${BROWSER_PREFERRED_UID}")
			getent group "${BROWSER_PREFERRED_UID}" >/dev/null || gopt=(-g "${BROWSER_PREFERRED_UID}")
		fi
		if ! getent group "${BROWSER_USER}" >/dev/null; then
			groupadd -r "${gopt[@]}" "${BROWSER_USER}" || { MSG="groupadd failed"; return 1; }
		fi
		useradd -r "${uopt[@]}" -g "${BROWSER_USER}" -d "${BROWSER_HOME}" -M -s /usr/sbin/nologin "${BROWSER_USER}" ||
			{ MSG="useradd failed"; return 1; }
		log "1 created user ${BROWSER_USER} uid $(id -u "${BROWSER_USER}")"
		return 0
	fi
	[ "$(getent passwd "${BROWSER_USER}" | cut -d: -f6)" = "${BROWSER_HOME}" ] ||
		{ MSG="${BROWSER_USER}'s home is not ${BROWSER_HOME}; not moving it automatically"; return 1; }
	usermod -s /usr/sbin/nologin -G "" "${BROWSER_USER}" || { MSG="usermod failed"; return 1; }
}
c1_home() {
	local bad d
	getent passwd "${BROWSER_USER}" >/dev/null || { MSG="user ${BROWSER_USER} missing"; return 1; }
	for d in "${BROWSER_HOME}" "${BROWSER_PROFILE_DIR}"; do
		[ -d "${d}" ] || { MSG="${d} missing"; return 1; }
		[ "$(stat -c '%U:%G %a' "${d}")" = "${BROWSER_USER}:${BROWSER_USER} 700" ] ||
			{ MSG="${d} is $(stat -c '%U:%G %a' "${d}"), want ${BROWSER_USER}:${BROWSER_USER} 700"; return 1; }
	done
	bad="$(find "${BROWSER_HOME}" -xdev \( ! -user "${BROWSER_USER}" -o ! -group "${BROWSER_USER}" \) -print -quit 2>/dev/null || true)"
	[ -z "${bad}" ] || { MSG="not owned by ${BROWSER_USER}: ${bad}"; return 1; }
	MSG="${BROWSER_HOME} and profile ${BROWSER_USER}:${BROWSER_USER} 700, all contents owned by ${BROWSER_USER}"
}
f1_home() {
	getent passwd "${BROWSER_USER}" >/dev/null || { MSG="user ${BROWSER_USER} missing"; return 1; }
	install -d -o "${BROWSER_USER}" -g "${BROWSER_USER}" -m 700 "${BROWSER_HOME}" "${BROWSER_PROFILE_DIR}" &&
		chown -R "${BROWSER_USER}:${BROWSER_USER}" "${BROWSER_HOME}" &&
		chmod 700 "${BROWSER_HOME}" "${BROWSER_PROFILE_DIR}"
}
# The agent may switch to the browser user (and only that user; never root).
sudoers_rule() {
	printf '# Managed by box-hardening.sh. %s may run commands as %s (never as root),\n' "${AGENT_USER}" "${BROWSER_USER}"
	printf '# so the launcher can start the browser under its own unprivileged user.\n'
	printf '%s ALL=(%s:%s) NOPASSWD: ALL\n' "${AGENT_USER}" "${BROWSER_USER}" "${BROWSER_USER}"
}
c1_sudoers() {
	[ -f "${BROWSER_SUDOERS}" ] && [ ! -L "${BROWSER_SUDOERS}" ] || { MSG="${BROWSER_SUDOERS} missing"; return 1; }
	[ "$(stat -c '%U:%G %a' "${BROWSER_SUDOERS}")" = "root:root 440" ] ||
		{ MSG="${BROWSER_SUDOERS} is $(stat -c '%U:%G %a' "${BROWSER_SUDOERS}"), want root:root 440"; return 1; }
	[ "$(cat "${BROWSER_SUDOERS}")" = "$(sudoers_rule)" ] || { MSG="${BROWSER_SUDOERS} content differs from the managed rule"; return 1; }
	MSG="${AGENT_USER} -> (${BROWSER_USER}:${BROWSER_USER}) only, root:root 440"
}
f1_sudoers() {
	local tmp
	tmp="$(mktemp "$(dirname "${BROWSER_SUDOERS}")/.bh.XXXXXX")" || { MSG="mktemp failed"; return 1; }
	sudoers_rule >"${tmp}" && chmod 440 "${tmp}" && chown root:root "${tmp}"
	visudo -cqf "${tmp}" >/dev/null 2>&1 || { rm -f "${tmp}"; MSG="visudo rejected the rule"; return 1; }
	[ ! -f "${BROWSER_SUDOERS}" ] || backup "${BROWSER_SUDOERS}"
	mv -f "${tmp}" "${BROWSER_SUDOERS}"
}
section_1() {
	log "== Section 1: browser user and launcher =="
	step 1 "browser system user" c1_user f1_user
	step 1 "${BROWSER_HOME} + profile ownership" c1_home f1_home
	[ -z "${BROWSER_SUDOERS}" ] || step 1 "sudo rule: ${AGENT_USER} -> ${BROWSER_USER} only" c1_sudoers f1_sudoers
	targets_step 1
}

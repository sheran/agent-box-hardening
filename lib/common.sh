# shellcheck shell=bash
# lib/common.sh - results, the step() engine and shared helpers.
# Sourced by box-hardening.sh; defines functions only.

ts() { date '+%F %T %Z'; }
log() { printf '%s [%s] %s\n' "$(ts)" "${MODE}" "$*"; }

# ---- results ------------------------------------------------------------------
R_SEC=() R_NAME=() R_STAT=() R_DETAIL=()
QUIET_RECORD=0
record() {
	R_SEC+=("$1"); R_NAME+=("$2"); R_STAT+=("$3"); R_DETAIL+=("$4")
	[ "${QUIET_RECORD}" -eq 1 ] || log "$1 | $2 | $3 | $4"
}
want() { [ -z "${ONLY}" ] || [[ ",${ONLY}," == *",$1,"* ]]; }

# step SECTION NAME CHECK_FN FIX_FN
# CHECK_FN sets MSG and returns 0 when compliant. FIX_FN only runs in apply/watch.
MSG=""
step() {
	local sec="$1" name="$2" chk="$3" fix="$4" before
	MSG=""
	if "${chk}"; then record "${sec}" "${name}" PASS "${MSG}"; return 0; fi
	before="${MSG}"
	if [ "${MODE}" = check ]; then record "${sec}" "${name}" FAIL "drift: ${before}"; return 0; fi
	log "${sec} ${name}: drift (${before}); fixing"
	MSG=""
	if ! "${fix}"; then record "${sec}" "${name}" FAIL "fix refused/failed: ${MSG:-${before}}"; return 0; fi
	MSG=""
	if "${chk}"; then record "${sec}" "${name}" FIXED "was: ${before}; now: ${MSG}"
	else record "${sec}" "${name}" FAIL "still drifted after fix: ${MSG}"; fi
}
vrec() { if [ "$3" = 0 ]; then record "$1" "$2" PASS "$4"; else record "$1" "$2" FAIL "$4"; fi; }

# ---- config safety ----------------------------------------------------------------
# safe_config FILE OWNER_UID -> 0 if FILE is a regular file (not a symlink) owned
# by OWNER_UID and not writable by group or others. The config is sourced as
# root, so anything less would let another user run code as root.
safe_config() {
	local f="$1" want_uid="$2" st
	[ -f "${f}" ] && [ ! -L "${f}" ] || return 1
	st="$(stat -c '%u %a' "${f}" 2>/dev/null)" || return 1
	[ "${st%% *}" = "${want_uid}" ] && [ $((0${st##* } & 022)) -eq 0 ]
}

# ---- file helpers -----------------------------------------------------------------
sha() { sha256sum "$1" | cut -d' ' -f1; }
as_user() { # as_user USER CMD... (direct when already that user)
	local u="$1"; shift
	if [ "$(id -un)" = "${u}" ]; then "$@"; else runuser -u "${u}" -- "$@"; fi
}
backup() {
	mkdir -p "${BACKUP_DIR}" && chmod 700 "${BACKUP_DIR}"
	local name="${1#/}"
	cp -a "$1" "${BACKUP_DIR}/${name//\//_}.$(date +%Y%m%d-%H%M%S)"
}
install_like() { # install_like SRC DEST (atomic, keeps DEST owner and mode)
	local src="$1" dest="$2" owner mode tmp
	owner="$(stat -c %U:%G "${dest}")"; mode="$(stat -c %a "${dest}")"
	tmp="$(mktemp "${dest}.bh.XXXXXX")"
	cat "${src}" >"${tmp}"
	chown "${owner}" "${tmp}" && chmod "${mode}" "${tmp}"
	mv -f "${tmp}" "${dest}"
}
root_owned_ok() { [ "$(stat -c '%U:%G' "$1")" = root:root ] && [ $((0$(stat -c %a "$1") & 022)) -eq 0 ]; }
browser_uid() { id -u "${BROWSER_USER}" 2>/dev/null; }
tcp_ok_as() { timeout 2 runuser -u "$1" -- bash -c "exec 3<>/dev/tcp/127.0.0.1/$2" >/dev/null 2>&1; }

# ---- X cookie helpers (values stay in memory, never printed or in argv) -----------
cookies_for() { # cookies_for FILE N -> hex cookies for display :N
	[ -r "$1" ] || return 0
	xauth -i -f "$1" list 2>/dev/null | awk -v d=":$2" '{ if (substr($1, length($1) - length(d) + 1) == d) print $3 }'
}
displays_in() {
	[ -r "$1" ] || return 0
	xauth -i -f "$1" list 2>/dev/null | awk '{ n = $1; sub(/.*:/, "", n); sub(/\..*/, "", n); print n }' | sort -u
}
xauth_add() { # xauth_add OWNER FILE N COOKIE (cookie via stdin)
	printf 'add :%s . %s\n' "$3" "$4" | as_user "$1" sh -c 'umask 077; exec xauth -q -f "$1" source -' _ "$2"
}
xvfb_pid() {
	local p
	for p in $(pgrep -x Xvfb 2>/dev/null || true); do
		[ "$(tr '\0' '\n' <"/proc/${p}/cmdline" 2>/dev/null | sed -n 2p)" = ":$1" ] && { echo "${p}"; return 0; }
	done
	return 0
}
xvfb_mode() { # none | ac | auth | open
	local p args
	p="$(xvfb_pid "$1")"
	[ -n "${p}" ] || { echo none; return; }
	args="$(tr '\0' ' ' <"/proc/${p}/cmdline" 2>/dev/null) "
	if [[ "${args}" == *" -auth ${XAUTH_SRV_PREFIX}$1 "* ]] && [[ "${args}" != *" -ac "* ]]; then echo auth
	elif [[ "${args}" == *" -ac "* ]]; then echo ac
	else echo open; fi
}
x_connect() { # x_connect USER XAUTHORITY N
	timeout 5 runuser -u "$1" -- env -i PATH=/usr/bin:/bin HOME="$(getent passwd "$1" | cut -d: -f6)" \
		DISPLAY=":$3" XAUTHORITY="$2" xdpyinfo >/dev/null 2>&1
}
x_display_list() {
	local p
	for p in $(pgrep -x Xvfb || true); do tr '\0' '\n' <"/proc/${p}/cmdline" 2>/dev/null | sed -n '2s/^://p'; done |
		grep -E '^[0-9]+$' | sort -un || true
}

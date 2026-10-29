#!/usr/bin/env bash
# =============================================================================
# box-fastfix-watch.sh - re-harden managed files within seconds of a revert.
#
# The hourly `box-hardening.sh --watch` run catches everything, but a platform
# redeploy can put the stock browser launcher back (sandbox off, browser as
# the agent user) at any moment, and the next browser start would use it. This
# small root daemon watches only the managed files from
# `box-hardening.sh --list-targets`:
#
#   * every POLL_SECONDS (default 2) it hashes each target; if inotifywait is
#     installed it is used as a wake-up so most changes are seen immediately
#   * a hash that is not a known hardened hash triggers
#     `box-hardening.sh --watch --only <section>`, which re-hardens known
#     stock versions and refuses unknown ones (hash allowlist)
#   * failures retry with backoff (2, 4, 8, 15, 30 s); an unknown version is
#     re-checked every RECHECK_UNKNOWN_SECONDS instead of hammering
#   * each detection and outcome is recorded via `box-drift.sh --add-event`
#     (optional) and in LOG_FILE
#
# It runs as root, so it only executes box-hardening.sh when that file, its
# lib/ and every parent directory are root-owned and not group/other writable.
#
# Usage: box-fastfix-watch.sh --start | --stop | --status | --ensure-running
#        box-fastfix-watch.sh --once      (one scan, then exit)
#        box-fastfix-watch.sh --selftest  (temp files only, any user)
# Settings: /etc/box-hardening/fastfix.conf (root-owned, not group/other writable)
# =============================================================================
set -euo pipefail
umask 077
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C

SELF="$(readlink -f "${BASH_SOURCE[0]}")"
CONF=/etc/box-hardening/fastfix.conf
BOX_HARDENING=/opt/box-hardening/box-hardening.sh
BOX_HARDENING_ARGS=()                   # e.g. (--config /etc/box-hardening/box-hardening.conf)
BOX_DRIFT=/opt/box-hardening/box-drift.sh   # optional; skipped if missing
POLL_SECONDS=2
RECHECK_UNKNOWN_SECONDS=600
REFRESH_TARGETS_SECONDS=300
RUN_DIR=/run/box-fastfix
LOG_FILE=/var/log/box-fastfix.log
BACKOFF=(2 4 8 15 30)
TRUST_CHECK=1

MODE="${1:---status}"
log() { printf '%s fastfix: %s\n' "$(date '+%F %T %Z')" "$*" >>"${LOG_FILE}"; }

# ---- trust checks ----------------------------------------------------------------
# root_tree_ok PATH: PATH and every parent directory are root-owned and not
# writable by group or others (otherwise a non-root user could swap the code).
root_tree_ok() {
	local p="$1" st
	while :; do
		st="$(stat -Lc '%u %a' "${p}" 2>/dev/null)" || return 1
		[ "${st%% *}" = 0 ] && [ $((0${st##* } & 022)) -eq 0 ] || return 1
		[ "${p}" = / ] && return 0
		p="$(dirname "${p}")"
	done
}
hardening_ok() {
	local f
	root_tree_ok "${BOX_HARDENING}" || return 1
	for f in "$(dirname "${BOX_HARDENING}")"/lib/*.sh; do root_tree_ok "${f}" || return 1; done
}
load_conf() {
	local st
	[ -e "${CONF}" ] || return 0
	st="$(stat -c '%u %a' "${CONF}")"
	if [ -L "${CONF}" ] || [ ! -f "${CONF}" ] || [ "${st%% *}" != 0 ] || [ $((0${st##* } & 022)) -ne 0 ]; then
		echo "fastfix: ${CONF} must be a root-owned regular file, not group/other writable" >&2; exit 2
	fi
	# shellcheck source=config/fastfix.conf.example
	. "${CONF}"
}

# ---- one scan --------------------------------------------------------------------
# State per target path: LAST_HASH, NEXT_TRY (epoch), TRIES, UNKNOWN (1 = refused).
declare -A LAST_HASH=() NEXT_TRY=() TRIES=() UNKNOWN=()
T_SEC=() T_PATH=() T_HASHES=()
TARGETS_AT=0
event() { # event KIND PATH DETAIL
	log "$1 $2: $3"
	if [ -x "${BOX_DRIFT}" ]; then "${BOX_DRIFT}" --add-event --kind "$1" --path "$2" --detail "$3" >/dev/null 2>&1 || true; fi
}
load_targets() {
	local line sec path hs root
	T_SEC=() T_PATH=() T_HASHES=()
	while IFS='|' read -r sec path hs root; do
		[ -n "${path}" ] || continue
		T_SEC+=("${sec}") T_PATH+=("${path}") T_HASHES+=(" ${hs} ")
		: "${root}"
	done < <("${BOX_HARDENING}" "${BOX_HARDENING_ARGS[@]}" --list-targets 2>/dev/null || true)
	TARGETS_AT="$(date +%s)"
	[ "${#T_PATH[@]}" -gt 0 ] || log "no targets from ${BOX_HARDENING} --list-targets"
}
run_fix() { # run_fix SECTION -> prints the RESULT/ATTENTION lines, returns the watch rc
	local rc=0 out
	out="$("${BOX_HARDENING}" "${BOX_HARDENING_ARGS[@]}" --watch --only "$1" 2>&1)" || rc=$?
	grep -E '^(RESULT|FIXED|ATTENTION):' <<<"${out}" || true
	return "${rc}"
}
scan_once() {
	local i p h now out rc n
	now="$(date +%s)"
	[ $((now - TARGETS_AT)) -lt "${REFRESH_TARGETS_SECONDS}" ] || load_targets
	for i in "${!T_PATH[@]}"; do
		p="${T_PATH[$i]}"
		h="$(sha256sum "${p}" 2>/dev/null | cut -d' ' -f1 || true)"
		[ -n "${h}" ] || h=missing
		if [[ "${T_HASHES[$i]}" == *" ${h} "* ]]; then
			[ "${LAST_HASH[${p}]:-}" = "${h}" ] || { [ -z "${LAST_HASH[${p}]:-}" ] || event fastfix-ok "${p}" "hardened (${h:0:12})"; }
			LAST_HASH[${p}]="${h}" TRIES[${p}]=0 NEXT_TRY[${p}]=0 UNKNOWN[${p}]=0
			continue
		fi
		if [ "${LAST_HASH[${p}]:-}" != "${h}" ]; then
			event fastfix-drift "${p}" "not a hardened hash (now ${h:0:12})"
			LAST_HASH[${p}]="${h}" TRIES[${p}]=0 NEXT_TRY[${p}]=0 UNKNOWN[${p}]=0
		fi
		[ "${now}" -ge "${NEXT_TRY[${p}]:-0}" ] || continue
		if [ "${TRUST_CHECK}" = 1 ] && ! hardening_ok; then
			event fastfix-refused "${p}" "${BOX_HARDENING} or its lib/ is not root-owned/read-only for others; not running it"
			NEXT_TRY[${p}]=$((now + RECHECK_UNKNOWN_SECONDS)); continue
		fi
		rc=0; out="$(run_fix "${T_SEC[$i]}")" || rc=$?
		h="$(sha256sum "${p}" 2>/dev/null | cut -d' ' -f1 || true)"
		if [[ "${T_HASHES[$i]}" == *" ${h} "* ]]; then
			event fastfix-fixed "${p}" "re-hardened to ${h:0:12} (watch rc ${rc})"
			LAST_HASH[${p}]="${h}" TRIES[${p}]=0 NEXT_TRY[${p}]=0 UNKNOWN[${p}]=0
		elif grep -q 'not a known version' <<<"${out}"; then
			[ "${UNKNOWN[${p}]:-0}" = 1 ] || event fastfix-unknown "${p}" "unknown version ${h:0:12}; needs human review (re-checking every ${RECHECK_UNKNOWN_SECONDS}s)"
			UNKNOWN[${p}]=1 NEXT_TRY[${p}]=$((now + RECHECK_UNKNOWN_SECONDS))
		else
			n="${TRIES[${p}]:-0}"
			NEXT_TRY[${p}]=$((now + BACKOFF[n < ${#BACKOFF[@]} ? n : ${#BACKOFF[@]} - 1]))
			TRIES[${p}]=$((n + 1))
			event fastfix-retry "${p}" "fix attempt $((n + 1)) failed (rc ${rc}); $(tr '\n' ' ' <<<"${out}" | cut -c1-200)"
		fi
	done
}
wait_for_change() {
	local dirs=() p
	if command -v inotifywait >/dev/null 2>&1; then
		for p in "${T_PATH[@]}"; do dirs+=("$(dirname "${p}")"); done
		if [ "${#dirs[@]}" -gt 0 ]; then
			inotifywait -qq -t "${POLL_SECONDS}" -e close_write,moved_to,create,delete,attrib "${dirs[@]}" 2>/dev/null || true
			return 0
		fi
	fi
	sleep "${POLL_SECONDS}"
}

# ---- daemon control ----------------------------------------------------------------
pid_alive() {
	local p
	p="$(cat "${RUN_DIR}/pid" 2>/dev/null || true)"
	[[ "${p}" =~ ^[0-9]+$ ]] && tr '\0' ' ' <"/proc/${p}/cmdline" 2>/dev/null | grep -q 'box-fastfix-watch.sh --run'
}
run_loop() {
	exec 9>"${RUN_DIR}/lock"
	flock -n 9 || { echo "fastfix: already running"; exit 0; }
	echo "$$" >"${RUN_DIR}/pid"
	trap 'log "stopping (pid $$)"; rm -f "${RUN_DIR}/pid"; exit 0' TERM INT
	log "started (pid $$, poll ${POLL_SECONDS}s, inotify $(command -v inotifywait >/dev/null 2>&1 && echo on || echo off))"
	load_targets
	while :; do
		scan_once || log "scan error (continuing)"
		wait_for_change
		sleep 0.2
	done
}
need_root() { [ "$(id -u)" -eq 0 ] || exec sudo -n -- "${SELF}" "$@"; }

selftest() {
	local t pass=0 fail=0 calls
	t="$(mktemp -d)"
	ok() { if [ "$1" = 0 ]; then pass=$((pass + 1)); echo "PASS  $2"; else fail=$((fail + 1)); echo "FAIL  $2"; fi; }
	printf 'hardened\n' >"${t}/hardened.ref"
	printf 'stock\n' >"${t}/stock.ref"
	cp "${t}/stock.ref" "${t}/target"
	# A fake box-hardening.sh: lists one target; --watch restores the hardened
	# file only while ${t}/mode is "fixable", and says "not a known version" otherwise.
	cat >"${t}/fake-hardening.sh" <<FAKE
#!/usr/bin/env bash
case "\$*" in
*--list-targets*) echo "1|${t}/target|$(sha256sum "${t}/hardened.ref" | cut -d' ' -f1)|0" ;;
*--watch*)
	echo call >>"${t}/calls"
	if [ "\$(cat "${t}/mode")" = fixable ]; then cp "${t}/hardened.ref" "${t}/target"; echo "RESULT: fixed"; exit 10; fi
	echo "ATTENTION: [1] target -- fix refused/failed: hash 0000 is not a known version"; echo "RESULT: needs-attention"; exit 20 ;;
esac
FAKE
	printf '#!/bin/sh\necho "$*" >>"%s/events"\n' "${t}" >"${t}/fake-drift.sh"
	chmod 755 "${t}/fake-hardening.sh" "${t}/fake-drift.sh"
	BOX_HARDENING="${t}/fake-hardening.sh" BOX_DRIFT="${t}/fake-drift.sh" LOG_FILE="${t}/log" TRUST_CHECK=0
	echo fixable >"${t}/mode"
	load_targets
	ok "$([ "${#T_PATH[@]}" -eq 1 ] && echo 0 || echo 1)" "targets read from --list-targets"
	scan_once
	ok "$(cmp -s "${t}/target" "${t}/hardened.ref" && echo 0 || echo 1)" "stock file re-hardened on first scan"
	grep -q 'fastfix-drift' "${t}/events" && grep -q 'fastfix-fixed' "${t}/events"; ok $? "drift + fixed events recorded"
	scan_once; scan_once
	calls="$(wc -l <"${t}/calls")"
	ok "$([ "${calls}" -eq 1 ] && echo 0 || echo 1)" "hardened file: no further fix runs (${calls} call)"
	echo unknown >"${t}/mode"; printf 'new platform version\n' >"${t}/target"
	scan_once; scan_once; scan_once
	calls="$(wc -l <"${t}/calls")"
	ok "$([ "${calls}" -eq 2 ] && echo 0 || echo 1)" "unknown version: one attempt, then waits for the recheck interval (${calls} calls)"
	ok "$([ "$(grep -c fastfix-unknown "${t}/events")" -eq 1 ] && echo 0 || echo 1)" "unknown version reported once"
	ok "$(cmp -s "${t}/target" "${t}/hardened.ref" && echo 1 || echo 0)" "unknown version left untouched"
	echo fixable >"${t}/mode"; printf 'stock again\n' >"${t}/target"
	scan_once
	ok "$(cmp -s "${t}/target" "${t}/hardened.ref" && echo 0 || echo 1)" "a new change resets the wait and is fixed at once"
	# trust check on the real filesystem: a root-owned system path passes, a temp file does not
	ok "$(root_tree_ok /usr/bin/env && echo 0 || echo 1)" "root-owned path trusted"
	ok "$(root_tree_ok "${t}/fake-hardening.sh" && [ "$(id -u)" -ne 0 ] && echo 1 || echo 0)" "user-owned path not trusted"
	TRUST_CHECK=1; printf 'x\n' >"${t}/target"; : >"${t}/calls"; NEXT_TRY=()
	scan_once
	ok "$([ ! -s "${t}/calls" ] && grep -q fastfix-refused "${t}/events" && echo 0 || echo 1)" "untrusted box-hardening.sh never run as root"
	rm -rf "${t}"
	echo "fastfix selftest: ${pass} passed, ${fail} failed"
	[ "${fail}" -eq 0 ]
}

case "${MODE}" in
--selftest) selftest; exit $? ;;
--start | --ensure-running)
	need_root "$@"; load_conf
	install -d -m 700 "${RUN_DIR}"
	if pid_alive; then echo "fastfix: running (pid $(cat "${RUN_DIR}/pid"))"; exit 0; fi
	[ "${MODE}" = --start ] || log "ensure-running: watcher was not running; starting it"
	setsid nohup "${SELF}" --run >/dev/null 2>&1 </dev/null &
	sleep 1
	if pid_alive; then echo "fastfix: started (pid $(cat "${RUN_DIR}/pid"))"; else echo "fastfix: failed to start (see ${LOG_FILE})"; exit 1; fi ;;
--run) need_root "$@"; load_conf; install -d -m 700 "${RUN_DIR}"; run_loop ;;
--once) need_root "$@"; load_conf; load_targets; scan_once ;;
--stop)
	need_root "$@"; load_conf
	if pid_alive; then kill "$(cat "${RUN_DIR}/pid")"; echo "fastfix: stopped"; else echo "fastfix: not running"; fi ;;
--status)
	load_conf 2>/dev/null || true
	if pid_alive; then echo "fastfix: running (pid $(cat "${RUN_DIR}/pid"))"; else echo "fastfix: stopped"; exit 3; fi ;;
-h | --help) sed -n '2,29p' "${SELF}" ;;
*) echo "fastfix: unknown mode ${MODE}" >&2; exit 2 ;;
esac

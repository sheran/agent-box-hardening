#!/usr/bin/env bash
# =============================================================================
# box-hardening.sh - idempotent, self-checking hardening for the browser on an
# AI agent's cloud VM.
#
# The agent drives a desktop Chrome. Stock images often start it with
# --no-sandbox, as the agent user, on an X display anyone can connect to. This
# script keeps four things true, and repairs them when a platform redeploy
# quietly puts the stock files back:
#
#   Section 1   Browser user      Chrome runs as a dedicated unprivileged user
#               and launcher      with its sandbox on; the launcher is a known
#                                 hardened version (hash allowlist)
#   Section 2A  Firewall          nftables: the browser user may only reach the
#                                 local ports you allow; everything else drops
#   Section 2B  X cookie auth     displays use MIT-MAGIC-COOKIE instead of -ac;
#                                 the browser user only gets its own display
#   Section 2C  Permissions       workspace 750, nothing world-writable in it,
#                                 private dirs 700, sockets with fixed owners
#   Verify                        "browser user denied, agent works" retests
#
# Every step: check -> fix only if drifted (apply/watch) -> re-check.
#
# Exit status (check/apply): 0 = all PASS/FIXED, 1 = any FAIL, 2 = usage/lock.
# Exit status (--watch):     0 = clean, 10 = fixed, 20 = needs-attention, 2 = usage/lock.
# Exit status (--detect-fresh): 0 = same instance (resume), 30 = same instance,
#   rebooted, 31 = same instance but hardening/VPN state missing, 40 = fresh
#   instance, 41 = no baseline yet (created now), 2 = usage/lock.
#
# Rules this script keeps:
#   * No secrets in this file, its config or its log. X cookies are generated
#     at run time and passed to xauth on stdin (never argv), never printed.
#   * A managed file whose hash is not in the allowlist is never patched: the
#     step FAILs and asks a human to review the new platform version.
#   * Displays are never restarted unless --restart-displays is given, and then
#     only behind a dead-man's switch.
# =============================================================================
set -euo pipefail
umask 077
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C

SELF="$(readlink -f "${BASH_SOURCE[0]}")"
HERE="$(dirname "${SELF}")"

# ---- defaults (override in the config file; see config/box-hardening.conf.example)
CONFIG_FILE=/etc/box-hardening/box-hardening.conf
AGENT_USER=agent
BROWSER_USER=chrome
BROWSER_PREFERRED_UID=""
BROWSER_HOME=/home/chrome
BROWSER_PROFILE_DIR=/home/chrome/browser-profile
BROWSER_DISPLAY=1
BROWSER_PROC_REGEX='(^|/)(chrome|chromium|chromium-browser)( |$)'
BROWSER_SUDOERS=/etc/sudoers.d/agent-browser
CHAINS_DIR=/etc/box-hardening/chains
TARGETS=(
	"1|/opt/agent/launchers/browser|browser-launcher|0"
	"2B|/usr/local/bin/xvfb-wrapper|xvfb-wrapper|1"
)
NFT_TABLE=browser_hardening
NFT_ALLOWED_LO_PORTS=(3128)
NFT_ALLOW_EXTERNAL=0
NFT_PRIVATE_V4="10.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16"
NFT_PRIVATE_V6="::1, fc00::/7, fe80::/10"
XAUTH_SRV_PREFIX=/tmp/xauth-srv-
XVFB_AUTH_LOG=/tmp/xvfb-wrapper-auth.log
XVFB_NOAUTH_DIR=/run/xvfb-wrapper
DISPLAY_RESTART_MODE=none
WORKSPACE=/workspace
PRIVATE_DIRS=()
SOCKETS=()
STATE_DIR=/var/lib/box-hardening
BACKUP_DIR=/var/backups/box-hardening
LOG_FILE=/var/log/box-hardening.log
LOCK_FILE=/run/box-hardening.lock
BASELINE_FILE=""
VPN_STATE_FILE=""
VPN_STATUS_CMD=""
FASTFIX_PIDFILE=/run/box-fastfix/pid
DMS_SECONDS=600
VERIFY_MAX_PORTS=30

for _lib in common chains section1 section2a section2b display-restart section2c verify detect selftest; do
	# shellcheck source=/dev/null
	. "${HERE}/lib/${_lib}.sh"
done

# ---- options ----------------------------------------------------------------
MODE=check
ONLY=""
RESTART_DISPLAYS=0
ORIG_ARGS=("$@")

usage() {
	cat <<'USAGE'
Usage: box-hardening.sh [--config FILE] [--check | --apply | --watch] [--only LIST] [--restart-displays]
       box-hardening.sh [--config FILE] --detect-fresh | --rebaseline | --list-targets
       box-hardening.sh --selftest
  --check              read-only drift report (default)
  --apply              fix drift, then re-verify every item
  --watch              unattended: safe fixes only (never restarts displays, never
                       patches unknown hashes), then RESULT: clean|fixed|needs-attention
  --only LIST          comma list of sections: 1,2A,2B,2C,V
  --restart-displays   (with --apply) restart Xvfb displays still on -ac, behind a
                       dead-man's-switch rollback
  --detect-fresh       same instance (resume/reboot) or a fresh one? exit 0/30/31/40/41
  --rebaseline         record this instance as the known one (after a rebuild)
  --list-targets       print SECTION|PATH|HARDENED_HASHES|ROOT_OWNED for each managed file
  --selftest           test the engine, wrapper, firewall and detection on temp files only
  --config FILE        config to source (default /etc/box-hardening/box-hardening.conf)
USAGE
}

while [ $# -gt 0 ]; do
	case "$1" in
	--check) MODE=check ;;
	--apply) MODE=apply ;;
	--watch) MODE=watch ;;
	--only)
		[ $# -ge 2 ] || { usage >&2; exit 2; }
		ONLY="$(tr '[:lower:]' '[:upper:]' <<<"$2")"; shift ;;
	--only=*) ONLY="$(tr '[:lower:]' '[:upper:]' <<<"${1#--only=}")" ;;
	--config)
		[ $# -ge 2 ] || { usage >&2; exit 2; }
		CONFIG_FILE="$2"; shift ;;
	--config=*) CONFIG_FILE="${1#--config=}" ;;
	--restart-displays) RESTART_DISPLAYS=1 ;;
	--selftest) MODE=selftest ;;
	--detect-fresh) MODE=detect ;;
	--rebaseline) MODE=rebaseline ;;
	--list-targets) MODE=list ;;
	-h | --help) usage; exit 0 ;;
	*) echo "box-hardening: unknown option: $1" >&2; usage >&2; exit 2 ;;
	esac
	shift
done
if [ "${RESTART_DISPLAYS}" -eq 1 ] && [ "${MODE}" != apply ]; then
	echo "box-hardening: --restart-displays needs --apply" >&2; exit 2
fi
case "${MODE}" in detect | rebaseline | list | selftest)
	[ -z "${ONLY}" ] || { echo "box-hardening: --only does not apply to this mode" >&2; exit 2; } ;;
esac
for _s in ${ONLY//,/ }; do
	case "${_s}" in 1 | 2A | 2B | 2C | V) ;; *) echo "box-hardening: bad section '${_s}'" >&2; exit 2 ;; esac
done

# ---- root (the self-test runs as any user, on temp files only) ---------------
if [ "${MODE}" != selftest ] && [ "$(id -u)" -ne 0 ]; then
	exec sudo -n -- "${SELF}" "${ORIG_ARGS[@]}"
fi

# ---- config (never read in --selftest, so tests do not depend on this box) ---
if [ "${MODE}" != selftest ]; then
	if [ -e "${CONFIG_FILE}" ]; then
		safe_config "${CONFIG_FILE}" 0 ||
			{ echo "box-hardening: ${CONFIG_FILE} must be a root-owned regular file, not group/other writable" >&2; exit 2; }
		# shellcheck source=config/box-hardening.conf.example
		. "${CONFIG_FILE}"
	elif [ "${CONFIG_FILE}" != /etc/box-hardening/box-hardening.conf ]; then
		echo "box-hardening: config ${CONFIG_FILE} not found" >&2; exit 2
	fi
fi
[ -n "${BASELINE_FILE}" ] || BASELINE_FILE="${WORKSPACE}/.box-hardening/instance-baseline"
INSTANCE_MARKER="${STATE_DIR}/instance-id"
AGENT_HOME="$(getent passwd "${AGENT_USER}" 2>/dev/null | cut -d: -f6 || true)"
[ -n "${AGENT_HOME}" ] || AGENT_HOME="/home/${AGENT_USER}"
AGENT_XAUTH="${AGENT_HOME}/.Xauthority"
BROWSER_XAUTH="${BROWSER_HOME}/.Xauthority"

# ---- logging and lock (skipped for --selftest and --list-targets) ------------
case "${MODE}" in
selftest | list) ;;
*)
	touch "${LOG_FILE}" && chmod 640 "${LOG_FILE}"
	exec > >(tee -a "${LOG_FILE}") 2>&1
	exec 8>"${LOCK_FILE}"
	_lockwait=(-n)
	case "${MODE}" in detect | rebaseline) _lockwait=(-w 60) ;; esac
	flock "${_lockwait[@]}" 8 || { echo "box-hardening: another run holds ${LOCK_FILE}"; exit 2; }
	;;
esac

# ---- main -----------------------------------------------------------------------
if [ "${MODE}" = list ]; then list_targets; exit 0; fi
log "box-hardening start: mode=${MODE} only=${ONLY:-all} restart_displays=${RESTART_DISPLAYS}"
if [ "${MODE}" = detect ]; then rc=0; detect_fresh || rc=$?; exit "${rc}"; fi
if [ "${MODE}" = rebaseline ]; then if rebaseline; then exit 0; else exit 1; fi; fi
if [ "${MODE}" = selftest ]; then
	QUIET_RECORD=1
	selftest
else
	if want 1; then section_1; fi
	if want 2A; then section_2a; fi
	if want 2B; then section_2b; fi
	if want 2C; then section_2c; fi
	section_v
fi

fails=0 passes=0 fixed=0 warns=0 skips=0
printf '\n%-6s %-58s %-6s %s\n' SECTION CHECK RESULT DETAIL
printf '%s\n' "----------------------------------------------------------------------------------------------------"
for i in "${!R_SEC[@]}"; do
	printf '%-6s %-58s %-6s %s\n' "${R_SEC[$i]}" "${R_NAME[$i]}" "${R_STAT[$i]}" "${R_DETAIL[$i]}"
	case "${R_STAT[$i]}" in
	PASS) passes=$((passes + 1)) ;; FIXED) fixed=$((fixed + 1)) ;; FAIL) fails=$((fails + 1)) ;;
	WARN) warns=$((warns + 1)) ;; *) skips=$((skips + 1)) ;;
	esac
done
printf '\n'
log "summary: PASS=${passes} FIXED=${fixed} FAIL=${fails} WARN=${warns} SKIP=${skips}"
if [ "${MODE}" = watch ]; then
	if [ "${fails}" -gt 0 ]; then result=needs-attention rc=20
	elif [ "${fixed}" -gt 0 ]; then result=fixed rc=10
	else result=clean rc=0; fi
	echo "RESULT: ${result}"
	echo "COUNTS: pass=${passes} fixed=${fixed} fail=${fails} warn=${warns} skip=${skips}"
	for i in "${!R_SEC[@]}"; do
		case "${R_STAT[$i]}" in
		FIXED) echo "FIXED: [${R_SEC[$i]}] ${R_NAME[$i]} -- ${R_DETAIL[$i]}" ;;
		FAIL) echo "ATTENTION: [${R_SEC[$i]}] ${R_NAME[$i]} -- ${R_DETAIL[$i]}" ;;
		WARN) echo "NOTE: [${R_SEC[$i]}] ${R_NAME[$i]} -- ${R_DETAIL[$i]}" ;;
		esac
	done
	exit "${rc}"
fi
[ "${fails}" -eq 0 ] || exit 1
exit 0

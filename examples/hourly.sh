#!/usr/bin/env bash
# examples/hourly.sh - one scheduled pass (run as root by systemd/box-hardening.timer).
#
#   0. refuse to run if the tree differs from the approved SHA256SUMS
#   1. drift snapshot "pre"   (what did the platform change since last time?)
#   2. --detect-fresh         (resume? reboot? brand-new VM from a redeploy?)
#   3. apply on a fresh VM, otherwise --watch (fix known drift, flag the rest)
#   4. drift snapshot "post"  (record what the hardening itself changed)
#   5. make sure the fast-fix watcher is running
#
# Output is one short block; the RESULT line is what a monitor should read.
# Exit status: the --watch/--apply status (0 clean, 10 fixed, 20 needs attention).
set -uo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
BASE="${BOX_HARDENING_BASE:-/opt/box-hardening}"
CONF_ARGS=()
[ -n "${BOX_HARDENING_CONFIG:-}" ] && CONF_ARGS=(--config "${BOX_HARDENING_CONFIG}")
drift() { [ -x "${BASE}/box-drift.sh" ] && "${BASE}/box-drift.sh" "$@" 2>&1 | sed 's/^/drift: /' || true; }

# Refuse to run anything as root unless the installed tree is the approved one.
if [ -f /etc/box-hardening/approved-sums.sha256 ] && ! "${BASE}/tools/verify-sums.sh" "${BASE}"; then
	echo "ATTENTION: installed files do not match the approved SHA256SUMS; not running"
	echo "RESULT: needs-attention"
	exit 20
fi
drift --label hourly-pre
"${BASE}/box-hardening.sh" "${CONF_ARGS[@]}" --detect-fresh
fresh=$?
case "${fresh}" in
40)
	echo "NOTE: fresh instance detected; running a full apply"
	"${BASE}/box-hardening.sh" "${CONF_ARGS[@]}" --apply >/dev/null
	# Re-run in watch mode for a compact status, then record the new instance.
	"${BASE}/box-hardening.sh" "${CONF_ARGS[@]}" --watch
	rc=$?
	"${BASE}/box-hardening.sh" "${CONF_ARGS[@]}" --rebaseline >/dev/null || rc=20 ;;
0 | 30 | 31 | 41)
	"${BASE}/box-hardening.sh" "${CONF_ARGS[@]}" --watch
	rc=$? ;;
*)
	echo "ATTENTION: --detect-fresh returned ${fresh}"
	rc=20 ;;
esac
drift --label hourly-post
"${BASE}/box-fastfix-watch.sh" --ensure-running || { echo "ATTENTION: fast-fix watcher not running"; rc=20; }
exit "${rc}"

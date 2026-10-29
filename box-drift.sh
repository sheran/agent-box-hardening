#!/usr/bin/env bash
# box-drift.sh - run box-drift.py as the agent user, even when called from root
# (the hourly job and the fast-fix watcher). The drift database belongs to the
# agent user; root never writes it, so root never follows paths the agent controls.
#   DRIFT_USER        user that owns the database (default: agent)
#   BOX_DRIFT_CONFIG  inventory JSON (default: ~DRIFT_USER/.config/box-drift/inventory.json)
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HERE="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
DRIFT_USER="${DRIFT_USER:-agent}"
if [ "$(id -u)" -eq 0 ] && [ "${DRIFT_USER}" != root ]; then
	home="$(getent passwd "${DRIFT_USER}" | cut -d: -f6)"
	[ -n "${home}" ] || { echo "box-drift: no user ${DRIFT_USER}" >&2; exit 2; }
	cfg="${BOX_DRIFT_CONFIG:-${home}/.config/box-drift/inventory.json}"
	cd /
	exec runuser -u "${DRIFT_USER}" -- env -i PATH="${PATH}" HOME="${home}" LC_ALL=C \
		BOX_DRIFT_CONFIG="${cfg}" python3 "${HERE}/box-drift.py" "$@"
fi
exec python3 "${HERE}/box-drift.py" "$@"

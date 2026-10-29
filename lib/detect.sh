# shellcheck shell=bash
# lib/detect.sh - fresh-instance detection (--detect-fresh / --rebaseline).
#
# A platform "update the agent's computer" can move the VM to a new instance:
# the persistent disk (home, workspace) survives, the root filesystem (users,
# VPN identity, nft table, patched files, ${STATE_DIR}) probably does not. A
# hibernate-resume keeps everything, boot ID included; a reboot keeps the root
# filesystem but gets a new boot ID and loses /run, /tmp and the nft table.
#
# The baseline lives on the persistent disk; a random marker lives on the root
# filesystem. Strong signals (marker missing/different, machine-id changed)
# mean "fresh" on their own; supporting signals (hostname changed, browser
# user gone, VPN state gone) need two together.
# The baseline is key=value lines, parsed (never sourced), mode 600, no secrets.

BASELINE_KEYS="machine_id hostname boot_id instance_id browser_uid vpn_state nft_table"
B_machine_id="" B_hostname="" B_boot_id="" B_instance_id="" B_browser_uid="" B_vpn_state=""
# shellcheck disable=SC2034  # B_nft_table is recorded for humans, not compared
B_nft_table=""
C_machine_id="" C_hostname="" C_boot_id="" C_instance_id="" C_browser_uid="" C_vpn_state="" C_nft_table=""
C_vpn_backend="" C_fastfix=""
D_HAVE_BASELINE=0 D_CLASS="" D_RC=0 D_MARKERS="" D_REASONS=() D_MISSING=()

marker_val() { if [ -f "$1" ] && [ ! -L "$1" ]; then tr -cd '0-9a-f-' <"$1" | cut -c1-64; fi; }
collect_markers() {
	local pw p
	C_machine_id="$(tr -cd '0-9a-f' </etc/machine-id 2>/dev/null | cut -c1-64 || true)"
	C_hostname="$(tr -cd 'A-Za-z0-9._-' </proc/sys/kernel/hostname 2>/dev/null || true)"
	C_boot_id="$(tr -cd '0-9a-f-' </proc/sys/kernel/random/boot_id 2>/dev/null || true)"
	C_instance_id="$(marker_val "${INSTANCE_MARKER}")"
	pw="$(getent passwd "${BROWSER_USER}" || true)"
	C_browser_uid="$(cut -d: -f3 <<<"${pw}")"
	if [ -z "${VPN_STATE_FILE}" ]; then C_vpn_state=untracked
	elif [ -f "${VPN_STATE_FILE}" ]; then C_vpn_state=present; else C_vpn_state=missing; fi
	if nft list table inet "${NFT_TABLE}" >/dev/null 2>&1; then C_nft_table=present; else C_nft_table=missing; fi
	C_vpn_backend=n/a
	if [ -n "${VPN_STATUS_CMD}" ]; then
		C_vpn_backend="$(timeout 10 bash -c "${VPN_STATUS_CMD}" 2>/dev/null | tr -cd 'A-Za-z' | cut -c1-32 || true)"
		[ -n "${C_vpn_backend}" ] || C_vpn_backend=unknown
	fi
	C_fastfix=stopped
	p="$(cat "${FASTFIX_PIDFILE}" 2>/dev/null || true)"
	if [[ "${p}" =~ ^[0-9]+$ ]] && tr '\0' ' ' <"/proc/${p}/cmdline" 2>/dev/null | grep -q 'box-fastfix-watch.sh --run'; then
		C_fastfix=running
	fi
}
baseline_read() {
	local f="$1" k v
	for k in ${BASELINE_KEYS}; do printf -v "B_${k}" '%s' ""; done
	[ -f "${f}" ] && [ ! -L "${f}" ] || return 1
	while IFS='=' read -r k v; do
		[[ "${k}" =~ ^[a-z_]+$ ]] || continue
		[[ " ${BASELINE_KEYS} " == *" ${k} "* ]] || continue
		[[ "${v}" =~ ^[A-Za-z0-9._:-]*$ ]] || continue # anything odd is ignored, never evaluated
		printf -v "B_${k}" '%s' "${v}"
	done <"${f}"
	[ -n "${B_machine_id}" ] || [ -n "${B_instance_id}" ]
}
baseline_write() {
	local f="$1" d tmp k v
	d="$(dirname "${f}")"
	[ ! -L "${f}" ] || { MSG="${f} is a symlink; not writing"; return 1; }
	mkdir -p "${d}" || { MSG="cannot create ${d}"; return 1; }
	tmp="$(mktemp "${d}/.instance-baseline.XXXXXX")" || { MSG="mktemp in ${d} failed"; return 1; }
	{
		echo "# box-hardening instance baseline (no secrets). Written by box-hardening.sh; compared by --detect-fresh."
		echo "version=1"
		echo "updated=$(date '+%Y-%m-%dT%H:%M:%S%z')"
		for k in ${BASELINE_KEYS}; do v="C_${k}"; echo "${k}=${!v}"; done
	} >"${tmp}"
	chmod 600 "${tmp}"
	if [ "$(id -u)" -eq 0 ] && getent passwd "${AGENT_USER}" >/dev/null; then chown "${AGENT_USER}:${AGENT_USER}" "${tmp}"; fi
	mv -f "${tmp}" "${f}"
}
ensure_marker() {
	local f="$1"
	C_instance_id="$(marker_val "${f}")"
	[ -z "${C_instance_id}" ] || return 0
	[ ! -L "${f}" ] || { MSG="${f} is a symlink"; return 1; }
	install -d -m 700 "$(dirname "${f}")" || { MSG="cannot create $(dirname "${f}")"; return 1; }
	{ tr -cd '0-9a-f-' </proc/sys/kernel/random/uuid >"${f}" && chmod 600 "${f}"; } || { MSG="cannot write ${f}"; return 1; }
	C_instance_id="$(marker_val "${f}")"
}
classify() {
	local strong=0 support=0 mid host boot mark bu
	D_REASONS=() D_MISSING=()
	[ -n "${C_browser_uid}" ] || D_MISSING+=("browser user -- run --apply (Section 1 creates it)")
	[ "${C_vpn_state}" != missing ] || D_MISSING+=("VPN state ${VPN_STATE_FILE} -- the VPN needs re-joining with a fresh key from the owner")
	[ "${C_nft_table}" = present ] || D_MISSING+=("nft table inet ${NFT_TABLE} -- run --apply (Section 2A); normal after a reboot")
	if [ "${D_HAVE_BASELINE}" -ne 1 ]; then
		if [ -z "${C_browser_uid}" ] || [ "${C_vpn_state}" = missing ]; then
			D_REASONS+=("no baseline at ${BASELINE_FILE}, and the browser user or VPN state is missing")
			D_CLASS=fresh D_RC=40
		else D_CLASS=baseline-created D_RC=41; fi
		D_MARKERS="browser_user=${C_browser_uid:+present} vpn_state=${C_vpn_state} nft_table=${C_nft_table}"
		return 0
	fi
	# strong signals: the root filesystem or the machine identity is new
	if [ -n "${B_instance_id}" ] && [ -z "${C_instance_id}" ]; then
		mark=missing; strong=$((strong + 1)); D_REASONS+=("instance marker ${INSTANCE_MARKER} missing (new root filesystem)")
	elif [ -n "${B_instance_id}" ] && [ "${B_instance_id}" != "${C_instance_id}" ]; then
		mark=differs; strong=$((strong + 1)); D_REASONS+=("instance marker differs from the baseline")
	else mark=match; fi
	if [ -n "${B_machine_id}" ] && [ "${B_machine_id}" != "${C_machine_id}" ]; then
		mid=changed; strong=$((strong + 1)); D_REASONS+=("machine-id changed")
	else mid=same; fi
	# supporting signals: each alone can have another cause
	if [ -n "${B_hostname}" ] && [ "${B_hostname}" != "${C_hostname}" ]; then
		host=changed; support=$((support + 1)); D_REASONS+=("hostname changed")
	else host=same; fi
	if [ -n "${B_browser_uid}" ] && [ -z "${C_browser_uid}" ]; then support=$((support + 1)); D_REASONS+=("browser user gone"); fi
	if [ "${B_vpn_state}" = present ] && [ "${C_vpn_state}" = missing ]; then support=$((support + 1)); D_REASONS+=("VPN state file gone"); fi
	if [ -n "${B_boot_id}" ] && [ "${B_boot_id}" != "${C_boot_id}" ]; then boot=changed; else boot=same; fi
	bu=missing; [ -z "${C_browser_uid}" ] || bu=present
	D_MARKERS="machine_id=${mid} hostname=${host} boot_id=${boot} instance_marker=${mark} browser_user=${bu} vpn_state=${C_vpn_state} nft_table=${C_nft_table}"
	if [ "${strong}" -gt 0 ] || [ "${support}" -ge 2 ]; then D_CLASS=fresh D_RC=40
	elif [ "${boot}" = changed ]; then D_CLASS=same-rebooted D_RC=30
	elif [ "${#D_MISSING[@]}" -gt 0 ]; then D_CLASS=same-state-missing D_RC=31
	else D_CLASS=same D_RC=0; fi
}
detect_fresh() {
	local r m bl j i
	collect_markers
	if baseline_read "${BASELINE_FILE}"; then D_HAVE_BASELINE=1; else D_HAVE_BASELINE=0; fi
	classify
	case "${D_CLASS}" in
	baseline-created)
		if ensure_marker "${INSTANCE_MARKER}" && baseline_write "${BASELINE_FILE}"; then bl="created ${BASELINE_FILE}"
		else bl="could not be created: ${MSG}"; D_RC=1; fi ;;
	fresh) bl="unchanged (run --rebaseline after the rebuild)" ;;
	*)
		# Same instance: refresh boot_id and presence fields. A browser uid that went
		# missing is kept, so the loss still counts if the instance changes later.
		[ -n "${C_instance_id}" ] || ensure_marker "${INSTANCE_MARKER}" || true
		[ -n "${C_browser_uid}" ] || C_browser_uid="${B_browser_uid}"
		if baseline_write "${BASELINE_FILE}"; then bl="updated"; else bl="not updated: ${MSG}"; fi ;;
	esac
	echo "INSTANCE: ${D_CLASS}"
	if [ "${D_CLASS}" = fresh ]; then
		j="${D_REASONS[0]}"
		for ((i = 1; i < ${#D_REASONS[@]}; i++)); do j="${j}; ${D_REASONS[$i]}"; done
		echo "FRESH_INSTANCE: ${j}"
	fi
	for r in "${D_REASONS[@]}"; do echo "REASON: ${r}"; done
	echo "MARKERS: ${D_MARKERS} vpn=${C_vpn_backend} fastfix=${C_fastfix}"
	for m in "${D_MISSING[@]}"; do echo "MISSING: ${m}"; done
	if [ "${C_vpn_state}" = missing ] || { [ "${C_vpn_backend}" != n/a ] && [ "${C_vpn_backend}" != Running ]; }; then
		echo "VPN: not joined (state ${C_vpn_state}, backend ${C_vpn_backend}); needs a fresh key from the owner (see REBUILD.md)"
	fi
	case "${D_CLASS}" in
	fresh) echo "NEXT: verify sources, box-hardening.sh --apply, box-fastfix-watch.sh --start, tell the owner (REBUILD.md), then --rebaseline" ;;
	same-rebooted | same-state-missing) echo "NEXT: normal flow (--watch fixes local drift; box-fastfix-watch.sh --ensure-running)" ;;
	*) echo "NEXT: none" ;;
	esac
	echo "BASELINE: ${bl}"
	return "${D_RC}"
}
rebaseline() {
	collect_markers
	if ! ensure_marker "${INSTANCE_MARKER}" || ! baseline_write "${BASELINE_FILE}"; then
		echo "BASELINE: write failed: ${MSG}"; return 1
	fi
	echo "BASELINE: written ${BASELINE_FILE} (browser_user ${C_browser_uid:+present}, vpn_state ${C_vpn_state}, nft_table ${C_nft_table})"
}

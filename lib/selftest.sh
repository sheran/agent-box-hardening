# shellcheck shell=bash
# lib/selftest.sh - box-hardening.sh --selftest.
# Temp files only; runs as any user; changes nothing on the system. Uses the
# sample files in examples/, so it needs no private or platform files.

st_chains() { # known-version engine on the example launcher and X wrapper
	local t="$1" ex="$2" st="$2/stock" code got
	CHAINS_DIR="${ex}/chains"
	MSG=""; build_hardened browser-launcher "${st}/browser-launcher.stock" "${t}/l1" && cmp -s "${t}/l1" "${st}/browser-launcher.hardened" && code=0 || code=1
	vrec ST "launcher: stock -> hardened" "${code}" "${MSG:-matches the reference}"
	sed -E '/^[[:space:]]*--no-sandbox[[:space:]]*$/d' "${st}/browser-launcher.stock" >"${t}/l2s"
	MSG=""; build_hardened browser-launcher "${t}/l2s" "${t}/l2" && cmp -s "${t}/l2" "${st}/browser-launcher.hardened" && code=0 || code=1
	vrec ST "launcher: sandbox-only -> hardened" "${code}" "${MSG:-matches the reference}"
	MSG=""; build_hardened browser-launcher "${st}/browser-launcher.hardened" "${t}/l3" && cmp -s "${t}/l3" "${st}/browser-launcher.hardened" && code=0 || code=1
	vrec ST "launcher: hardened -> unchanged" "${code}" "${MSG:-no-op}"
	cp "${st}/browser-launcher.hardened" "${t}/lh"
	MSG=""; check_target "${t}/lh" browser-launcher 0 && code=0 || code=1
	vrec ST "launcher: hardened passes check" "${code}" "${MSG}"
	cp "${st}/browser-launcher.stock" "${t}/lo"
	MSG=""; if check_target "${t}/lo" browser-launcher 0; then vrec ST "launcher: stock fails check" 1 "passed"
	else vrec ST "launcher: stock fails check" 0 "${MSG}"; fi
	if [ "$(id -u)" -ne 0 ]; then
		MSG=""; if check_target "${t}/lh" browser-launcher 1; then vrec ST "non-root owner fails a root-owned target" 1 "passed"
		else vrec ST "non-root owner fails a root-owned target" 0 "${MSG}"; fi
	fi
	{ cat "${st}/browser-launcher.stock"; echo "# platform update"; } >"${t}/l4"
	MSG=""; if build_hardened browser-launcher "${t}/l4" "${t}/l5"; then vrec ST "launcher: unknown hash refused" 1 "patched blind"
	else vrec ST "launcher: unknown hash refused" 0 "${MSG}"; fi
	MSG=""; if build_hardened xvfb-wrapper "${st}/browser-launcher.stock" "${t}/l6"; then vrec ST "cross-target file refused" 1 "patched blind"
	else vrec ST "cross-target file refused" 0 "${MSG}"; fi
	cp -r "${ex}/chains" "${t}/chains"
	sed -i "s/RUN_USER=chrome/RUN_USER=root/" "${t}/chains/browser-launcher/example-v1/patch.diff"
	CHAINS_DIR="${t}/chains"
	MSG=""; if build_hardened browser-launcher "${st}/browser-launcher.stock" "${t}/l7"; then vrec ST "tampered patch refused (hash check)" 1 "accepted"
	else vrec ST "tampered patch refused (hash check)" 0 "${MSG}"; fi
	echo "not-a-hash" >"${t}/chains/browser-launcher/example-v1/orig.sha256"
	MSG=""; if build_hardened browser-launcher "${st}/browser-launcher.stock" "${t}/l8"; then vrec ST "malformed chain ignored" 1 "accepted"
	else vrec ST "malformed chain ignored" 0 "${MSG}"; fi
	CHAINS_DIR="${t}/none"
	MSG=""; if build_hardened browser-launcher "${st}/browser-launcher.stock" "${t}/l9"; then vrec ST "no chains dir: everything refused" 1 "accepted"
	else vrec ST "no chains dir: everything refused" 0 "refused"; fi
	CHAINS_DIR="${ex}/chains"
	MSG=""; build_hardened xvfb-wrapper "${st}/xvfb-wrapper.stock" "${t}/x1" && cmp -s "${t}/x1" "${st}/xvfb-wrapper.hardened" && code=0 || code=1
	vrec ST "X wrapper: stock -> hardened" "${code}" "${MSG:-matches the reference}"
	got="$(TARGETS=("1|/x/launcher|browser-launcher|0" "2B|/x/wrapper|xvfb-wrapper|1"); list_targets)"
	if [ "$(wc -l <<<"${got}")" -eq 2 ] &&
		[[ "${got}" == "1|/x/launcher|$(read_hash "${ex}/chains/browser-launcher/example-v1/hardened.sha256")|0"* ]]; then code=0; else code=1; fi
	vrec ST "--list-targets output" "${code}" ""
}

st_wrapper() { # the hardened X wrapper, run for real against a fake Xvfb
	local t="$1" st="$2/stock" me code
	me="$(id -un)"
	mkdir -p "${t}/bin" "${t}/home"
	printf '#!/bin/sh\nprintf "%%s\\n" "$@" >"%s/xvfb-args"\n' "${t}" >"${t}/bin/Xvfb"; chmod 755 "${t}/bin/Xvfb"
	sed -e "s|^_xa_user=.*|_xa_user=${me}|" -e "s|^_xa_home=.*|_xa_home=${t}/home|" -e "s|^_xa_prefix=.*|_xa_prefix=${t}/srv-|" \
		-e "s|^_xa_log=.*|_xa_log=${t}/auth.log|" -e "s|^_xa_noauth_dir=.*|_xa_noauth_dir=${t}/noauth|" \
		"${st}/xvfb-wrapper.hardened" >"${t}/wrapper"
	PATH="${t}/bin:${PATH}" bash "${t}/wrapper" 77 >/dev/null 2>&1 && code=0 || code=1
	if grep -qx -- -auth "${t}/xvfb-args" && ! grep -qx -- -ac "${t}/xvfb-args" && [ "$(stat -c %a "${t}/srv-77")" = 600 ] &&
		[ -n "$(cookies_for "${t}/srv-77" 77)" ] && [ "$(cookies_for "${t}/srv-77" 77)" = "$(cookies_for "${t}/home/.Xauthority" 77)" ]; then :; else code=1; fi
	vrec ST "X wrapper: -ac dropped, -auth added, cookie 600 + merged" "${code}" "value not shown"
	PATH="${t}/bin:${PATH}" bash "${t}/wrapper" 77 >/dev/null 2>&1 || true
	[ "$(xauth -i -f "${t}/home/.Xauthority" list 2>/dev/null | wc -l)" -eq 1 ] && code=0 || code=1
	vrec ST "X wrapper: second start reuses the cookie" "${code}" ""
	printf '#!/bin/sh\nexit 1\n' >"${t}/bin/mcookie"; chmod 755 "${t}/bin/mcookie"
	PATH="${t}/bin:${PATH}" bash "${t}/wrapper" 78 >/dev/null 2>&1 || true
	grep -qx -- -ac "${t}/xvfb-args" && ! grep -qx -- -auth "${t}/xvfb-args" && grep -q WARNING "${t}/auth.log" && code=0 || code=1
	vrec ST "X wrapper: fail-safe keeps -ac and logs WARNING" "${code}" ""
	rm -f "${t}/bin/mcookie"; ln -s "${t}/home/.Xauthority" "${t}/srv-79"
	PATH="${t}/bin:${PATH}" bash "${t}/wrapper" 79 >/dev/null 2>&1 || true
	grep -qx -- -ac "${t}/xvfb-args" && code=0 || code=1
	vrec ST "X wrapper: planted symlink cookie not trusted" "${code}" ""
	mkdir -p "${t}/noauth"; touch "${t}/noauth/noauth-80"
	PATH="${t}/bin:${PATH}" bash "${t}/wrapper" 80 >/dev/null 2>&1 || true
	grep -qx -- -ac "${t}/xvfb-args" && [ ! -e "${t}/srv-80" ] && code=0 || code=1
	vrec ST "X wrapper: opt-out marker honoured" "${code}" ""
}

st_cookies_nft_config() {
	local t="$1" me c got code nftbin
	me="$(id -un)"
	c="$(mcookie)"
	: >"${t}/xa"
	xauth_add "${me}" "${t}/xa" 77 "${c}"; xauth_add "${me}" "${t}/xa" 78 "$(mcookie)"
	got="$(cookies_for "${t}/xa" 77)"
	[ "${got}" = "${c}" ] && code=0 || code=1; vrec ST "xauth write/read via stdin" "${code}" "round trip ok, value not shown"
	[ "$(displays_in "${t}/xa" | tr '\n' ' ')" = "77 78 " ] && code=0 || code=1; vrec ST "xauth display parsing" "${code}" ""
	c="" got=""
	# firewall: load the ruleset into a throwaway network namespace and compare
	nftbin="$(command -v nft || true)"
	if [ -n "${nftbin}" ] && unshare -rn true 2>/dev/null; then
		for NFT_ALLOW_EXTERNAL in 0 1; do
			# shellcheck disable=SC2016  # positional parameters of the inner sh
			got="$(nft_ruleset 4242 | unshare -rn sh -c '"$1" -f - && "$1" list table inet "$2"' _ "${nftbin}" "${NFT_TABLE}" 2>&1)" && code=0 || code=1
			[ "${code}" = 0 ] && [ "$(nft_normalise 4242 <<<"${got}")" = "$(nft_expected_listing 4242)" ] || code=1
			vrec ST "nft ruleset loads and matches its check (external=${NFT_ALLOW_EXTERNAL})" "${code}" "throwaway netns"
		done
		NFT_ALLOW_EXTERNAL=0
	else record ST "nft ruleset" SKIP "nft or unprivileged user namespaces not available"; fi
	# config safety
	printf 'AGENT_USER=x\n' >"${t}/conf"; chmod 600 "${t}/conf"
	safe_config "${t}/conf" "$(id -u)" && code=0 || code=1; vrec ST "config: private own file accepted" "${code}" ""
	chmod 620 "${t}/conf"; safe_config "${t}/conf" "$(id -u)" && code=1 || code=0; vrec ST "config: group-writable refused" "${code}" ""
	chmod 600 "${t}/conf"; ln -s "${t}/conf" "${t}/conflink"
	safe_config "${t}/conflink" "$(id -u)" && code=1 || code=0; vrec ST "config: symlink refused" "${code}" ""
	safe_config "${t}/conf" "$(($(id -u) + 1))" && code=1 || code=0; vrec ST "config: wrong owner refused" "${code}" ""
	bash -n "${HERE}/config/box-hardening.conf.example" && code=0 || code=1; vrec ST "config example parses" "${code}" ""
}

st_markers() {
	C_machine_id=aaaa1111bbbb2222cccc3333dddd4444 C_hostname=vm-a C_boot_id=b0000001-0000-0000-0000-000000000001
	C_instance_id=11111111-2222-3333-4444-555555555555 C_browser_uid=990 C_vpn_state=present C_nft_table=present
	C_vpn_backend=Running C_fastfix=running
}
st_case() { # st_case BASELINE NAME WANT_CLASS WANT_RC [HAVE_BASELINE]
	local code
	D_HAVE_BASELINE="${5:-1}"
	baseline_read "$1" || true
	classify
	[ "${D_CLASS}" = "$3" ] && [ "${D_RC}" = "$4" ] && code=0 || code=1
	vrec ST "detect: $2" "${code}" "${D_CLASS}/${D_RC}${D_REASONS[0]:+ (${D_REASONS[0]})}"
}
st_detect() { # synthetic markers and temp files only
	local t="$1" bl="$1/bl" code c rc1=0 rc2=0 rc3=0
	local sv_bl="${BASELINE_FILE}" sv_mk="${INSTANCE_MARKER}" sv_vpn="${VPN_STATE_FILE}" sv_bu="${BROWSER_USER}" sv_pid="${FASTFIX_PIDFILE}"
	st_markers; MSG=""
	if baseline_write "${bl}" && baseline_read "${bl}" && [ "${B_machine_id}" = "${C_machine_id}" ] &&
		[ "${B_instance_id}" = "${C_instance_id}" ] && [ "${B_browser_uid}" = 990 ] && [ "$(stat -c %a "${bl}")" = 600 ]; then code=0; else code=1; fi
	vrec ST "detect: baseline write/read round trip" "${code}" "${MSG:-600, fields match}"
	st_markers; st_case "${bl}" "hibernate-resume (all same)" same 0
	st_markers; C_boot_id=b0000002-0000-0000-0000-000000000002 C_nft_table=missing; st_case "${bl}" "reboot (new boot ID, nft gone)" same-rebooted 30
	st_markers; C_vpn_state=missing; st_case "${bl}" "same boot, VPN state gone" same-state-missing 31
	st_markers; C_hostname=vm-b; st_case "${bl}" "hostname change alone is not fresh" same 0
	st_markers; C_instance_id=""; st_case "${bl}" "fresh: root-fs marker missing" fresh 40
	st_markers; C_instance_id=99999999-2222-3333-4444-555555555555; st_case "${bl}" "fresh: root-fs marker differs" fresh 40
	st_markers; C_machine_id=eeee1111ffff2222; st_case "${bl}" "fresh: machine-id changed" fresh 40
	st_markers; C_browser_uid="" C_vpn_state=missing; st_case "${bl}" "fresh: browser user + VPN state gone" fresh 40
	st_markers; C_instance_id="" C_machine_id=eeee1111ffff2222 C_browser_uid="" C_vpn_state=missing C_nft_table=missing C_boot_id=x
	st_case "${bl}" "fresh: full new instance" fresh 40
	[ "${#D_MISSING[@]}" -eq 3 ] && code=0 || code=1
	vrec ST "detect: full new instance lists 3 missing items" "${code}" "${#D_MISSING[@]} missing"
	st_markers; C_vpn_state=untracked; baseline_write "${bl}"; st_case "${bl}" "VPN untracked never counts as missing" same 0
	st_markers; baseline_write "${bl}"
	st_markers; st_case "${bl}" "no baseline, hardened box -> create" baseline-created 41 0
	st_markers; C_browser_uid=""; st_case "${bl}" "no baseline, browser user missing -> fresh" fresh 40 0
	printf '%s\n' 'machine_id=$(touch '"${t}"'/pwned)' 'instance_id=`id`' 'evil=1' 'hostname=ok-host' >"${t}/bad"
	baseline_read "${t}/bad" || true
	[ -z "${B_machine_id}" ] && [ -z "${B_instance_id}" ] && [ "${B_hostname}" = ok-host ] && [ ! -e "${t}/pwned" ] && code=0 || code=1
	vrec ST "detect: baseline parser ignores code and unknown keys" "${code}" "never sourced"
	ln -s "${bl}" "${t}/link"; MSG=""
	if baseline_write "${t}/link"; then vrec ST "detect: symlinked baseline refused" 1 "wrote through symlink"
	else vrec ST "detect: symlinked baseline refused" 0 "${MSG}"; fi
	MSG=""
	if ensure_marker "${t}/m/instance-id" && c="${C_instance_id}" && ensure_marker "${t}/m/instance-id" && [ "${C_instance_id}" = "${c}" ] &&
		[[ "${c}" =~ ^[0-9a-f-]{36}$ ]] && [ "$(stat -c %a "${t}/m/instance-id")" = 600 ]; then code=0; else code=1; fi
	vrec ST "detect: marker created once, 600, then kept" "${code}" "${MSG:-ok}"
	# End to end on this machine's live markers, with every path redirected to temp.
	BASELINE_FILE="${t}/e2e/instance-baseline" INSTANCE_MARKER="${t}/e2e-root/instance-id"
	VPN_STATE_FILE="${t}/vpn.state" BROWSER_USER="$(id -un)" FASTFIX_PIDFILE="${t}/nopid"
	: >"${VPN_STATE_FILE}"
	detect_fresh >"${t}/o1" || rc1=$?
	detect_fresh >"${t}/o2" || rc2=$?
	rm -f "${INSTANCE_MARKER}"
	detect_fresh >"${t}/o3" || rc3=$?
	BASELINE_FILE="${sv_bl}" INSTANCE_MARKER="${sv_mk}" VPN_STATE_FILE="${sv_vpn}" BROWSER_USER="${sv_bu}" FASTFIX_PIDFILE="${sv_pid}"
	[ "${rc1}" = 41 ] && grep -q '^INSTANCE: baseline-created' "${t}/o1" && code=0 || code=1
	vrec ST "detect e2e: first run creates baseline" "${code}" "rc ${rc1}"
	case "${rc2}" in 0 | 31) code=0 ;; *) code=1 ;; esac
	grep -q '^INSTANCE: same' "${t}/o2" || code=1
	vrec ST "detect e2e: second run = same instance" "${code}" "rc ${rc2}"
	[ "${rc3}" = 40 ] && grep -q '^FRESH_INSTANCE: instance marker' "${t}/o3" && code=0 || code=1
	vrec ST "detect e2e: marker removed = FRESH_INSTANCE" "${code}" "rc ${rc3}"
	grep -Eqi '[0-9a-f]{32}' "${t}/o1" "${t}/o2" "${t}/o3" && code=1 || code=0
	vrec ST "detect e2e: no machine-id or marker values in output" "${code}" ""
}

selftest() {
	local t sv_chains="${CHAINS_DIR}"
	t="$(mktemp -d)"
	log "== Self-test (temp dir ${t}) =="
	st_chains "${t}" "${HERE}/examples"
	st_wrapper "${t}" "${HERE}/examples"
	st_cookies_nft_config "${t}"
	st_detect "${t}"
	CHAINS_DIR="${sv_chains}"
	rm -rf "${t}"
}

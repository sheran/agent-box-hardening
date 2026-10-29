# shellcheck shell=bash
# lib/section2a.sh - Section 2A: an nftables table that limits the browser user.
#
# Output from the browser uid jumps to a chain that allows replies, the
# loopback ports in NFT_ALLOWED_LO_PORTS (for example a local egress proxy) and,
# if NFT_ALLOW_EXTERNAL=1, public addresses. Everything else is dropped, so a
# compromised renderer cannot reach the agent's local services or the private
# network the VM sits on.

nft_body() { # nft_body UID INDENT -> the table, in nft's own listing order
	local uid="$1" t="$2" p
	printf 'table inet %s {\n' "${NFT_TABLE}"
	printf '%schain output {\n%s%stype filter hook output priority filter; policy accept;\n' "${t}" "${t}" "${t}"
	printf '%s%smeta skuid %s jump browser_out\n%s}\n' "${t}" "${t}" "${uid}" "${t}"
	printf '%schain browser_out {\n%s%sct state established,related counter accept\n' "${t}" "${t}" "${t}"
	for p in "${NFT_ALLOWED_LO_PORTS[@]}"; do printf '%s%soif "lo" tcp dport %s counter accept\n' "${t}" "${t}" "${p}"; done
	if [ "${NFT_ALLOW_EXTERNAL}" = 1 ]; then
		printf '%s%soif != "lo" ip daddr != { %s } counter accept\n' "${t}" "${t}" "${NFT_PRIVATE_V4}"
		printf '%s%soif != "lo" ip6 daddr != { %s } counter accept\n' "${t}" "${t}" "${NFT_PRIVATE_V6}"
	fi
	printf '%s%scounter drop\n%s}\n}\n' "${t}" "${t}" "${t}"
}
# Atomic replace: create-if-missing, delete, re-add, all in one nft transaction.
nft_ruleset() { printf 'table inet %s {}\ndelete table inet %s\n' "${NFT_TABLE}" "${NFT_TABLE}"; nft_body "$1" $'\t'; }
nft_expected_listing() { nft_body "$1" ""; }
nft_normalise() { # nft_normalise UID < listing
	sed -E -e 's/counter packets [0-9]+ bytes [0-9]+/counter/g' -e 's/[[:space:]]*#.*$//' \
		-e 's/^[[:space:]]+//' -e 's/[[:space:]]+$//' -e '/^$/d' \
		-e "s/meta skuid \"?${BROWSER_USER}\"? /meta skuid $1 /"
}
c2a_table() {
	local uid live
	command -v nft >/dev/null || { MSG="nft not installed"; return 1; }
	uid="$(browser_uid)" || { MSG="user ${BROWSER_USER} missing; cannot build the skuid rule"; return 1; }
	live="$(nft list table inet "${NFT_TABLE}" 2>/dev/null)" || { MSG="table inet ${NFT_TABLE} missing"; return 1; }
	if [ "$(nft_normalise "${uid}" <<<"${live}")" != "$(nft_expected_listing "${uid}")" ]; then
		MSG="table differs from expected (browser uid ${uid})"; return 1
	fi
	MSG="inet ${NFT_TABLE}: skuid ${uid} -> lo tcp ${NFT_ALLOWED_LO_PORTS[*]:-none}"
	[ "${NFT_ALLOW_EXTERNAL}" != 1 ] || MSG="${MSG} + public addresses"
	MSG="${MSG}, rest dropped"
}
f2a_table() {
	local uid
	if ! command -v nft >/dev/null; then
		log "2A installing nftables"
		{ DEBIAN_FRONTEND=noninteractive apt-get install -y -q nftables >/dev/null 2>&1 ||
			{ apt-get update -q >/dev/null 2>&1 && DEBIAN_FRONTEND=noninteractive apt-get install -y -q nftables >/dev/null; }; } ||
			{ MSG="apt-get install nftables failed"; return 1; }
	fi
	uid="$(browser_uid)" || { MSG="user ${BROWSER_USER} missing"; return 1; }
	nft_ruleset "${uid}" | nft -f - || { MSG="nft -f failed"; return 1; }
}
section_2a() {
	log "== Section 2 Part A: browser user firewall =="
	step 2A "nft table ${NFT_TABLE}" c2a_table f2a_table
}

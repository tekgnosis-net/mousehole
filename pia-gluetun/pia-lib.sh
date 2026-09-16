#!/bin/sh
# shellcheck shell=sh
# Shared helpers for pia-entrypoint.sh and pia-recover.sh. POSIX sh only.

# pia_log COMPONENT MESSAGE  -> "<ISO8601Z> [component] message" on stderr
pia_log() {
	printf '%s [%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" "$2" >&2
}

# pia_clamp VARNAME DEFAULT MIN MAX -> prints the integer value of $VARNAME,
# falling back to DEFAULT when unset or not a non-negative integer, then
# clamped into [MIN, MAX].
pia_clamp() {
	_name=$1
	_def=$2
	_min=$3
	_max=$4
	eval "_val=\${$_name:-}"
	case "$_val" in
	'' | *[!0-9]*) _val=$_def ;;
	esac
	[ "$_val" -lt "$_min" ] && _val=$_min
	[ "$_val" -gt "$_max" ] && _val=$_max
	printf '%s\n' "$_val"
}

# pia_bool VARNAME DEFAULT -> prints "true" or "false".
# Accepts on/off, yes/no, true/false, 1/0 (case-insensitive).
pia_bool() {
	eval "_val=\${$1:-}"
	[ -n "$_val" ] || _val=$2
	case "$(printf '%s' "$_val" | tr '[:upper:]' '[:lower:]')" in
	on | yes | true | 1) printf 'true\n' ;;
	off | no | false | 0) printf 'false\n' ;;
	*) printf '%s\n' "$2" ;;
	esac
}

# pia_control_port ADDRESS -> the port part of gluetun's
# HTTP_CONTROL_SERVER_ADDRESS (":8000", "0.0.0.0:8009", "8009").
pia_control_port() {
	case "$1" in
	'') printf '8000\n' ;;
	*:*) printf '%s\n' "${1##*:}" ;;
	*) printf '%s\n' "$1" ;;
	esac
}

# pia_write_auth BASEFILE OUTFILE APIKEY
# Writes OUTFILE = BASEFILE (if it exists) + the pia-recover apikey role.
# gluetun allows a route to be listed in several roles, so the base file may
# already open some of these routes with auth = "none".
pia_write_auth() {
	_base=$1
	_out=$2
	_key=$3
	{
		if [ -f "$_base" ]; then
			cat "$_base"
			printf '\n'
		fi
		printf '[[roles]]\n'
		printf 'name = "pia-recover"\n'
		printf 'auth = "apikey"\n'
		printf 'apikey = "%s"\n' "$_key"
		printf 'routes = ["GET /v1/vpn/status", "GET /v1/vpn/settings", "PUT /v1/vpn/settings", "GET /v1/publicip/ip", "GET /v1/portforward"]\n'
	} >"$_out"
	chmod 600 "$_out"
}

# pia_export_gluetun_env  -> exports gluetun's WireGuard settings from the
# PIA_WG_* variables (sourced from register.env) and the PIA_* credentials.
pia_export_gluetun_env() {
	export VPN_SERVICE_PROVIDER=custom
	export VPN_TYPE=wireguard
	export WIREGUARD_PRIVATE_KEY="$PIA_WG_PRIVATE_KEY"
	export WIREGUARD_PUBLIC_KEY="$PIA_WG_SERVER_KEY"
	export WIREGUARD_ADDRESSES="$PIA_WG_PEER_IP/32"
	export WIREGUARD_ENDPOINT_IP="$PIA_WG_SERVER_IP"
	export WIREGUARD_ENDPOINT_PORT="$PIA_WG_SERVER_PORT"
	export SERVER_NAMES="$PIA_WG_CN"
	# The gluetun base image ships VPN_PORT_FORWARDING=off as an image default,
	# so it must be set explicitly from our own knob rather than inherited.
	if [ "$(pia_bool PIA_PORT_FORWARDING true)" = true ]; then
		export VPN_PORT_FORWARDING=on
	else
		export VPN_PORT_FORWARDING=off
	fi
	export VPN_PORT_FORWARDING_PROVIDER="private internet access"
	export VPN_PORT_FORWARDING_USERNAME="$PIA_USER"
	export VPN_PORT_FORWARDING_PASSWORD="$PIA_PASS"
}

# pia_iptables -> prints the iptables binary that holds gluetun's rules.
# gluetun picks whichever of iptables-legacy / iptables-nft / iptables works,
# so look for its OUTPUT rules rather than assuming a backend.
pia_iptables() {
	for _b in iptables-legacy iptables-nft iptables; do
		if command -v "$_b" >/dev/null 2>&1 && "$_b" -S OUTPUT 2>/dev/null | grep -q '^-A OUTPUT'; then
			printf '%s\n' "$_b"
			return 0
		fi
	done
	for _b in iptables-legacy iptables-nft iptables; do
		if command -v "$_b" >/dev/null 2>&1; then
			printf '%s\n' "$_b"
			return 0
		fi
	done
	return 1
}

# pia_allow_bypass MARK -> makes sure packets carrying fwmark MARK may leave
# for PIA's API (TCP 443, TCP 1337) and DNS (TCP+UDP 53) despite gluetun's
# firewall. Idempotent. gluetun's routing rule already sends marked packets
# around the tunnel; this only opens the OUTPUT chain for them.
pia_allow_bypass() {
	_mark=$1
	[ "$_mark" -ne 0 ] || return 0
	_ipt=$(pia_iptables) || {
		pia_log pia-lib "no iptables binary found, cannot open bypass rules"
		return 1
	}
	_added=0
	for _spec in "-p tcp --dport 443" "-p tcp --dport 1337" "-p tcp --dport 53" "-p udp --dport 53"; do
		# shellcheck disable=SC2086  # _spec is a fixed word list
		if ! "$_ipt" -C OUTPUT -m mark --mark "$_mark" $_spec -j ACCEPT 2>/dev/null; then
			# shellcheck disable=SC2086
			"$_ipt" -I OUTPUT 1 -m mark --mark "$_mark" $_spec -j ACCEPT
			_added=1
		fi
	done
	[ "$_added" -eq 0 ] || pia_log pia-lib "firewall: allowed fwmark $_mark to PIA (tcp 443, tcp 1337, tcp/udp 53) via $_ipt"
}

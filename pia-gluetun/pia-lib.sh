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
	export VPN_ENDPOINT_IP="$PIA_WG_SERVER_IP"
	export VPN_ENDPOINT_PORT="$PIA_WG_SERVER_PORT"
	export SERVER_NAMES="$PIA_WG_CN"
	export VPN_PORT_FORWARDING="${VPN_PORT_FORWARDING:-on}"
	export VPN_PORT_FORWARDING_PROVIDER="private internet access"
	export VPN_PORT_FORWARDING_USERNAME="$PIA_USER"
	export VPN_PORT_FORWARDING_PASSWORD="$PIA_PASS"
}

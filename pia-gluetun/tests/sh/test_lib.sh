#!/bin/sh
# Unit tests for pia-lib.sh. Run with: sh tests/sh/test_lib.sh
# shellcheck disable=SC2034  # test variables are read through eval in pia_clamp/pia_bool
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
# shellcheck source=../../pia-lib.sh disable=SC1091
. "$ROOT/pia-lib.sh"

fails=0
check() {
	# check DESCRIPTION EXPECTED ACTUAL
	if [ "$2" = "$3" ]; then
		echo "ok   $1"
	else
		echo "FAIL $1: expected '$2' got '$3'"
		fails=$((fails + 1))
	fi
}

# pia_clamp
unset X
check "clamp default when unset" 60 "$(pia_clamp X 60 10 3600)"
X=abc
check "clamp default when not numeric" 60 "$(pia_clamp X 60 10 3600)"
X=-5
check "clamp default when negative" 60 "$(pia_clamp X 60 10 3600)"
X=1
check "clamp raises to min" 10 "$(pia_clamp X 60 10 3600)"
X=99999
check "clamp lowers to max" 3600 "$(pia_clamp X 60 10 3600)"
X=120
check "clamp passes value in range" 120 "$(pia_clamp X 60 10 3600)"
X=0
check "clamp allows zero when min is zero" 0 "$(pia_clamp X 60 0 3600)"

# pia_bool
unset B
check "bool default" true "$(pia_bool B true)"
B=off
check "bool off" false "$(pia_bool B true)"
B=YES
check "bool YES" true "$(pia_bool B false)"
B=0
check "bool 0" false "$(pia_bool B true)"
B=maybe
check "bool garbage falls back to default" false "$(pia_bool B false)"

# pia_control_port
check "port from :8009" 8009 "$(pia_control_port :8009)"
check "port from 0.0.0.0:8000" 8000 "$(pia_control_port 0.0.0.0:8000)"
check "port from bare number" 8123 "$(pia_control_port 8123)"
check "port default when empty" 8000 "$(pia_control_port '')"

# pia_write_auth
tmp=$(mktemp -d)
pia_write_auth "$tmp/does-not-exist" "$tmp/out.toml" KEY123
check "auth without base has one role" 1 "$(grep -c '^\[\[roles\]\]' "$tmp/out.toml")"
check "auth contains api key" 1 "$(grep -c 'apikey = "KEY123"' "$tmp/out.toml")"
check "auth opens PUT settings" 1 "$(grep -c '"PUT /v1/vpn/settings"' "$tmp/out.toml")"
check "auth file mode 600" 600 "$(stat -c %a "$tmp/out.toml")"
pia_write_auth "$ROOT/auth/config.toml" "$tmp/out2.toml" KEY456
check "auth with base has two roles" 2 "$(grep -c '^\[\[roles\]\]' "$tmp/out2.toml")"
check "auth keeps lan-readonly role" 1 "$(grep -c 'name = "lan-readonly"' "$tmp/out2.toml")"

# pia_export_gluetun_env
PIA_WG_PRIVATE_KEY=priv PIA_WG_SERVER_KEY=pub PIA_WG_PEER_IP=10.1.2.3 PIA_WG_SERVER_IP=1.1.1.1 \
	PIA_WG_SERVER_PORT=1337 PIA_WG_CN=cn1 PIA_USER=u PIA_PASS=p
pia_export_gluetun_env
check "export addresses adds /32" 10.1.2.3/32 "$WIREGUARD_ADDRESSES"
check "export server names" cn1 "$SERVER_NAMES"
check "export endpoint" 1.1.1.1 "$VPN_ENDPOINT_IP"
check "export pf provider" "private internet access" "$VPN_PORT_FORWARDING_PROVIDER"
check "export pf username" u "$VPN_PORT_FORWARDING_USERNAME"
check "export provider custom" custom "$VPN_SERVICE_PROVIDER"

# pia_log format
line=$(pia_log comp "hello world" 2>&1)
case "$line" in
[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z" [comp] hello world") echo "ok   log format" ;;
*) echo "FAIL log format: '$line'"; fails=$((fails + 1)) ;;
esac

rm -rf "$tmp"
if [ "$fails" -eq 0 ]; then echo "test_lib: all passed"; else echo "test_lib: $fails failed"; exit 1; fi

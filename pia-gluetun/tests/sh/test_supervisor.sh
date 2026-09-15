#!/bin/sh
# Behavioural tests for pia-entrypoint.sh + pia-recover.sh using the fakes in
# tests/fakes. Run with: sh tests/sh/test_supervisor.sh
set -u  # no -e: a failed check must not abort the remaining sections
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
SH=${TEST_SH:-sh}

fails=0
check() {
	if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: expected '$2' got '$3'"; fails=$((fails + 1)); fi
}
# wait_for DESCRIPTION SECONDS COMMAND... -> polls until the command succeeds
wait_for() {
	desc=$1; secs=$2; shift 2
	i=0
	while ! "$@" 2>/dev/null; do
		i=$((i + 1))
		if [ "$i" -ge $((secs * 10)) ]; then echo "FAIL timeout waiting for: $desc"; fails=$((fails + 1)); return 1; fi
		sleep 0.1
	done
	echo "ok   $desc"
}
gluetun_pid() { sed -n 's/^PID=//p' "$FAKE_DIR/gluetun.env"; }
starts() { [ -f "$FAKE_DIR/gluetun.starts" ] && wc -l <"$FAKE_DIR/gluetun.starts" || echo 0; }
starts_is() { [ "$(starts)" -eq "$1" ]; }
calls_has() { grep -q -- "$1" "$FAKE_DIR/calls.log"; }
log_has() { grep -q -- "$1" "$FAKE_DIR/entrypoint.log"; }

setup() {
	FAKE_DIR=$(mktemp -d)
	export FAKE_DIR
	export PATH="$ROOT/tests/fakes:$PATH"
	export PIA_GLUETUN_ENTRYPOINT="$ROOT/tests/fakes/gluetun-entrypoint"
	export PIA_STATE_DIR="$FAKE_DIR/state" PIA_RUN_DIR="$FAKE_DIR/run"
	export PIA_PORTFORWARD_FILE="$FAKE_DIR/piaportforward.json"
	export PIA_DEFAULT_AUTH="$ROOT/auth/config.toml"
	export PIA_REGION=swiss PIA_USER=user PIA_PASS=pass
	export HTTP_CONTROL_SERVER_ADDRESS=:8009
	export PIA_STARTUP_GRACE=0 PIA_CHECK_INTERVAL=1 PIA_FAIL_THRESHOLD=2
	export PIA_SAME_SERVER_ATTEMPTS=1 PIA_MIN_SERVER_CHANGE_INTERVAL=0
	unset HTTP_CONTROL_SERVER_AUTH_CONFIG_FILEPATH
	: >"$FAKE_DIR/calls.log"
}
start() {
	# shellcheck disable=SC2086  # SH may be "busybox sh"
	$SH "$ROOT/pia-entrypoint.sh" >"$FAKE_DIR/entrypoint.log" 2>&1 &
	SUP=$!
}
stop() {
	kill -TERM "$SUP" 2>/dev/null || true
	wait "$SUP" 2>/dev/null || true
	rm -rf "$FAKE_DIR"
}

echo "--- cold start, USR1 restart, TERM shutdown"
setup
start
wait_for "gluetun started" 5 starts_is 1
check "no pin on cold start" 0 "$(grep -c -- '--pin-cn' "$FAKE_DIR/calls.log")"
check "SERVER_NAMES exported" new-server "$(sed -n 's/^SERVER_NAMES=//p' "$FAKE_DIR/gluetun.env")"
check "endpoint exported" 10.0.0.2 "$(sed -n 's/^VPN_ENDPOINT_IP=//p' "$FAKE_DIR/gluetun.env")"
check "addresses /32" 10.9.112.7/32 "$(sed -n 's/^WIREGUARD_ADDRESSES=//p' "$FAKE_DIR/gluetun.env")"
check "private key passed" 1 "$(sed -n 's/^HAS_PRIVATE_KEY=//p' "$FAKE_DIR/gluetun.env")"
check "pf username passed" user "$(sed -n 's/^VPN_PORT_FORWARDING_USERNAME=//p' "$FAKE_DIR/gluetun.env")"
check "auth file path exported" "$FAKE_DIR/run/auth.toml" "$(sed -n 's/^HTTP_CONTROL_SERVER_AUTH_CONFIG_FILEPATH=//p' "$FAKE_DIR/gluetun.env")"
check "auth file has both roles" 2 "$(grep -c '^\[\[roles\]\]' "$FAKE_DIR/run/auth.toml")"
check "api key file mode" 600 "$(stat -c %a "$FAKE_DIR/run/apikey")"
check "api key matches auth file" 1 "$(grep -c "apikey = \"$(cat "$FAKE_DIR/run/apikey")\"" "$FAKE_DIR/run/auth.toml")"
first_pid=$(gluetun_pid)
# Simulate the loop having re-registered, then ask for an in-place restart.
sed -i "s/PIA_WG_CN='new-server'/PIA_WG_CN='restarted-server'/" "$FAKE_DIR/run/register.env"
kill -USR1 "$SUP"
wait_for "gluetun restarted after USR1" 5 starts_is 2
check "restart got new SERVER_NAMES" restarted-server "$(sed -n 's/^SERVER_NAMES=//p' "$FAKE_DIR/gluetun.env")"
if [ "$(gluetun_pid)" != "$first_pid" ]; then echo "ok   gluetun pid changed"; else echo "FAIL pid unchanged"; fails=$((fails + 1)); fi
kill -TERM "$SUP"
if wait "$SUP"; then echo "ok   supervisor exits 0 on TERM"; else echo "FAIL supervisor exit $?"; fails=$((fails + 1)); fi
sleep 0.3
check "gluetun stopped after TERM" 0 "$(kill -0 "$(gluetun_pid)" 2>/dev/null && echo 1 || echo 0)"
rm -rf "$FAKE_DIR"

echo "--- warm start reuses previous server"
setup
mkdir -p "$PIA_STATE_DIR"
FAKE_DIR=$FAKE_DIR "$ROOT/tests/fakes/pia-wg" register --state-dir "$PIA_STATE_DIR" --pin-cn old-server >/dev/null
: >"$FAKE_DIR/calls.log"
start
wait_for "gluetun started" 5 starts_is 1
check "register pinned to previous CN" 1 "$(grep -c -- '--pin-cn old-server' "$FAKE_DIR/calls.log")"
check "SERVER_NAMES is previous server" old-server "$(sed -n 's/^SERVER_NAMES=//p' "$FAKE_DIR/gluetun.env")"
stop

echo "--- warm start with vanished server releases the pin"
setup
mkdir -p "$PIA_STATE_DIR"
FAKE_DIR=$FAKE_DIR "$ROOT/tests/fakes/pia-wg" register --state-dir "$PIA_STATE_DIR" --pin-cn old-server >/dev/null
echo 3 >"$FAKE_DIR/register_exit"
: >"$FAKE_DIR/calls.log"
export PIA_REGISTER_ATTEMPTS=3
start
sleep 1
rm -f "$FAKE_DIR/register_exit"
wait_for "gluetun started after pin release" 12 starts_is 1
check "pin released log" 1 "$(grep -c 'releasing pin' "$FAKE_DIR/entrypoint.log")"
check "new server chosen" new-server "$(sed -n 's/^SERVER_NAMES=//p' "$FAKE_DIR/gluetun.env")"
unset PIA_REGISTER_ATTEMPTS
stop

echo "--- recovery: same server first, apply via API"
setup
start
wait_for "gluetun started" 5 starts_is 1
: >"$FAKE_DIR/calls.log"
touch "$FAKE_DIR/piaportforward.json"
echo 0 >"$FAKE_DIR/health"
wait_for "re-registered pinned to current server" 10 calls_has '--pin-cn new-server'
wait_for "apply called" 5 calls_has '^apply '
sleep 0.5
check "no restart when apply succeeds" 1 "$(starts)"
check "pf signature kept on same server" 1 "$([ -f "$FAKE_DIR/piaportforward.json" ] && echo 1 || echo 0)"
echo 1 >"$FAKE_DIR/health"
wait_for "healthy again logged" 5 log_has 'healthy again'
stop

echo "--- recovery: apply failure falls back to in-place restart"
setup
export PIA_SAME_SERVER_ATTEMPTS=5
start
wait_for "gluetun started" 5 starts_is 1
echo 1 >"$FAKE_DIR/apply_exit"
echo 0 >"$FAKE_DIR/health"
wait_for "fallback restart happened" 10 starts_is 2
check "fallback logged" 1 "$(grep -c 'falling back to in-place gluetun restart' "$FAKE_DIR/entrypoint.log")"
unset PIA_SAME_SERVER_ATTEMPTS
stop

echo "--- recovery: roll to another server after same-server attempts"
setup
export PIA_SAME_SERVER_ATTEMPTS=0 PIA_MIN_SERVER_CHANGE_INTERVAL=0
start
wait_for "gluetun started" 5 starts_is 1
touch "$FAKE_DIR/piaportforward.json"
: >"$FAKE_DIR/calls.log"
echo 0 >"$FAKE_DIR/health"
wait_for "register excluded current server" 10 calls_has '--exclude-cn new-server'
wait_for "server change logged" 5 log_has 'server change: new-server'
check "pf signature dropped on server change" 0 "$([ -f "$FAKE_DIR/piaportforward.json" ] && echo 1 || echo 0)"
check "new server chosen" new-server-alt "$(sed -n "s/^PIA_WG_CN='\(.*\)'/\1/p" "$FAKE_DIR/run/register.env")"
stop

echo "--- recovery: change interval holds the server"
setup
export PIA_SAME_SERVER_ATTEMPTS=0 PIA_MIN_SERVER_CHANGE_INTERVAL=604800
date +%s >"$FAKE_DIR/changed_epoch"
start
wait_for "gluetun started" 5 starts_is 1
: >"$FAKE_DIR/calls.log"
echo 0 >"$FAKE_DIR/health"
wait_for "hold logged" 10 log_has 'server change interval not reached'
check "no exclusion while holding" 0 "$(grep -c -- '--exclude-cn new-server' "$FAKE_DIR/calls.log")"
check "re-registered same server" 1 "$(grep -c -- '--pin-cn new-server' "$FAKE_DIR/calls.log")"
stop

echo "--- missing configuration fails fast"
setup
unset PIA_REGION
# shellcheck disable=SC2086
if $SH "$ROOT/pia-entrypoint.sh" >"$FAKE_DIR/entrypoint.log" 2>&1; then echo "FAIL should exit non-zero"; fails=$((fails + 1)); else echo "ok   exits without PIA_REGION"; fi
check "explains missing region" 1 "$(grep -c 'PIA_REGION is required' "$FAKE_DIR/entrypoint.log")"
rm -rf "$FAKE_DIR"

if [ "$fails" -eq 0 ]; then echo "test_supervisor ($SH): all passed"; else echo "test_supervisor ($SH): $fails failed"; exit 1; fi

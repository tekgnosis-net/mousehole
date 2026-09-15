#!/bin/sh
# pia-gluetun entrypoint: register a fresh PIA WireGuard key, export gluetun's
# settings as env vars, then supervise gluetun and the recovery loop.
#
# This process stays PID 1 (or the top process under `init: true`). gluetun
# runs as a child so the recovery loop can ask for an in-place restart
# (SIGUSR1) that keeps the container's network namespace intact.
set -eu

PIA_HERE=$(dirname "$0")
# shellcheck source=pia-lib.sh
. "$PIA_HERE/pia-lib.sh"
C=pia-entrypoint

# ---- knobs (see README "Dials") -------------------------------------------
PIA_REGION=${PIA_REGION:-}
PIA_STATE_DIR=${PIA_STATE_DIR:-/gluetun/pia}
PIA_RUN_DIR=${PIA_RUN_DIR:-/run/pia}
PIA_GLUETUN_ENTRYPOINT=${PIA_GLUETUN_ENTRYPOINT:-/gluetun-entrypoint}
PIA_DEFAULT_AUTH=${PIA_DEFAULT_AUTH:-/pia/auth/config.toml}
PIA_PORTFORWARD_FILE=${PIA_PORTFORWARD_FILE:-/gluetun/piaportforward.json}
PIA_REGISTER_ATTEMPTS=$(pia_clamp PIA_REGISTER_ATTEMPTS 5 1 20)
PIA_REGISTER_TIMEOUT=$(pia_clamp PIA_REGISTER_TIMEOUT 30 5 120)
PIA_PORT_FORWARD_ONLY=$(pia_bool PIA_PORT_FORWARD_ONLY true)
export PIA_MIN_SERVER_CHANGE_INTERVAL
PIA_MIN_SERVER_CHANGE_INTERVAL=$(pia_clamp PIA_MIN_SERVER_CHANGE_INTERVAL 3600 0 604800)

if [ -z "$PIA_REGION" ]; then
	pia_log $C "PIA_REGION is required (e.g. swiss)"
	exit 1
fi
if [ -z "${PIA_USER:-}" ] && [ -z "${PIA_USER_FILE:-}" ]; then
	pia_log $C "PIA_USER (or PIA_USER_FILE) is required"
	exit 1
fi
if [ -z "${PIA_PASS:-}" ] && [ -z "${PIA_PASS_FILE:-}" ]; then
	pia_log $C "PIA_PASS (or PIA_PASS_FILE) is required"
	exit 1
fi
# Resolve *_FILE credentials once so gluetun's port-forward settings get them.
if [ -z "${PIA_USER:-}" ]; then PIA_USER=$(tr -d '\r\n' <"$PIA_USER_FILE"); fi
if [ -z "${PIA_PASS:-}" ]; then PIA_PASS=$(tr -d '\r\n' <"$PIA_PASS_FILE"); fi
export PIA_USER PIA_PASS PIA_REGION PIA_STATE_DIR PIA_RUN_DIR PIA_PORTFORWARD_FILE

umask 077
mkdir -p "$PIA_STATE_DIR" "$PIA_RUN_DIR"
chmod 700 "$PIA_STATE_DIR" "$PIA_RUN_DIR"

# ---- choose pin: reuse the previous server for this region when known -----
old_cn=""
old_ip=""
if pia-wg state --state-dir "$PIA_STATE_DIR" >"$PIA_RUN_DIR/previous.env" 2>/dev/null; then
	# shellcheck source=/dev/null
	. "$PIA_RUN_DIR/previous.env"
	if [ "$PIA_WG_REGION" = "$PIA_REGION" ]; then
		old_cn=$PIA_WG_CN
		old_ip=$PIA_WG_SERVER_IP
		pia_log $C "previous server for region $PIA_REGION: $old_cn ($old_ip), will try to reuse it"
	else
		pia_log $C "region changed from $PIA_WG_REGION to $PIA_REGION, choosing a new server"
	fi
fi

# ---- register (with retries; drop the pin if that server is gone/dead) ----
attempt=1
pin_cn=$old_cn
pin_ip=$old_ip
while :; do
	set -- register --region "$PIA_REGION" --state-dir "$PIA_STATE_DIR" \
		--timeout "${PIA_REGISTER_TIMEOUT}s" --port-forward-only="$PIA_PORT_FORWARD_ONLY" --format env
	if [ -n "$pin_cn" ]; then
		set -- "$@" --pin-cn "$pin_cn" --pin-ip "$pin_ip"
	fi
	if pia-wg "$@" >"$PIA_RUN_DIR/register.env.new"; then
		break
	else
		rc=$?
	fi
	if [ -n "$pin_cn" ] && { [ "$rc" -eq 3 ] || [ "$attempt" -ge 2 ]; }; then
		pia_log $C "pinned server $pin_cn unavailable (exit $rc), releasing pin"
		pin_cn=""
		pin_ip=""
	fi
	if [ "$attempt" -ge "$PIA_REGISTER_ATTEMPTS" ]; then
		pia_log $C "key registration failed after $attempt attempts, giving up"
		exit 1
	fi
	delay=$((attempt * 5))
	pia_log $C "key registration failed (exit $rc), retrying in ${delay}s ($attempt/$PIA_REGISTER_ATTEMPTS)"
	sleep "$delay"
	attempt=$((attempt + 1))
done
mv "$PIA_RUN_DIR/register.env.new" "$PIA_RUN_DIR/register.env"
# shellcheck source=/dev/null
. "$PIA_RUN_DIR/register.env"

if [ -n "$old_cn" ] && [ "$old_cn" != "$PIA_WG_CN" ]; then
	pia_log $C "server change: $old_cn ($old_ip) -> $PIA_WG_CN ($PIA_WG_SERVER_IP); dropping old port-forward signature"
	rm -f "$PIA_PORTFORWARD_FILE"
fi
pia_export_gluetun_env
pia_log $C "gluetun will connect to $PIA_WG_CN at $PIA_WG_SERVER_IP:$PIA_WG_SERVER_PORT (region $PIA_REGION)"

# ---- control server auth: base file + boot-time API key for the loop ------
api_key=$(head -c 32 /dev/urandom | base64 | tr -d '/+=\n')
printf '%s' "$api_key" >"$PIA_RUN_DIR/apikey"
chmod 600 "$PIA_RUN_DIR/apikey"
base_auth=${HTTP_CONTROL_SERVER_AUTH_CONFIG_FILEPATH:-/gluetun/auth/config.toml}
[ -f "$base_auth" ] || base_auth=$PIA_DEFAULT_AUTH
pia_write_auth "$base_auth" "$PIA_RUN_DIR/auth.toml" "$api_key"
export HTTP_CONTROL_SERVER_AUTH_CONFIG_FILEPATH="$PIA_RUN_DIR/auth.toml"
PIA_CONTROL_URL="http://127.0.0.1:$(pia_control_port "${HTTP_CONTROL_SERVER_ADDRESS:-:8000}")"
export PIA_CONTROL_URL
unset api_key

# ---- supervise -------------------------------------------------------------
gluetun_pid=""
shutdown=0
restart=0

start_gluetun() {
	"$PIA_GLUETUN_ENTRYPOINT" &
	gluetun_pid=$!
	pia_log $C "gluetun started (pid $gluetun_pid)"
}

# shellcheck disable=SC2317  # invoked via trap
on_term() {
	shutdown=1
	if [ -n "$gluetun_pid" ]; then kill -TERM "$gluetun_pid" 2>/dev/null || true; fi
}
# shellcheck disable=SC2317  # invoked via trap
on_usr1() {
	restart=1
	if [ -n "$gluetun_pid" ]; then kill -TERM "$gluetun_pid" 2>/dev/null || true; fi
}
trap on_term TERM INT
trap on_usr1 USR1

"$PIA_HERE/pia-recover.sh" &
recover_pid=$!
start_gluetun

rc=0
while :; do
	if wait "$gluetun_pid"; then rc=0; else rc=$?; fi
	# wait returns early (>128) when a trap fires; keep waiting while alive.
	if kill -0 "$gluetun_pid" 2>/dev/null; then
		continue
	fi
	if [ "$shutdown" -eq 1 ]; then
		break
	fi
	if [ "$restart" -eq 1 ]; then
		restart=0
		# shellcheck source=/dev/null
		. "$PIA_RUN_DIR/register.env"
		pia_export_gluetun_env
		pia_log $C "in-place restart requested: reconnecting to $PIA_WG_CN ($PIA_WG_SERVER_IP)"
		start_gluetun
		continue
	fi
	pia_log $C "gluetun exited with status $rc"
	break
done

kill -TERM "$recover_pid" 2>/dev/null || true
wait "$recover_pid" 2>/dev/null || true
exit "$rc"

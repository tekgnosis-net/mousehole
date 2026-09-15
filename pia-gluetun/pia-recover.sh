#!/bin/sh
# pia-gluetun recovery loop. Started by pia-entrypoint.sh; never run alone.
#
# Polls gluetun's control server. After PIA_FAIL_THRESHOLD consecutive
# unhealthy probes it registers a new key, preferring the same server, and
# applies it through PUT /v1/vpn/settings (mode "api") or by asking the
# supervisor for an in-place gluetun restart (mode "restart", also the
# fallback when the PUT is rejected). The container's network namespace is
# never touched.
set -eu

PIA_HERE=$(dirname "$0")
# shellcheck source=pia-lib.sh
. "$PIA_HERE/pia-lib.sh"
C=pia-recover

interval=$(pia_clamp PIA_CHECK_INTERVAL 60 1 3600)
threshold=$(pia_clamp PIA_FAIL_THRESHOLD 3 1 100)
same_attempts=$(pia_clamp PIA_SAME_SERVER_ATTEMPTS 2 0 10)
min_change=$(pia_clamp PIA_MIN_SERVER_CHANGE_INTERVAL 3600 0 604800)
grace=$(pia_clamp PIA_STARTUP_GRACE 120 0 3600)
register_timeout=$(pia_clamp PIA_REGISTER_TIMEOUT 30 5 120)
require_port=$(pia_bool PIA_REQUIRE_PORT_FORWARD true)
pf_only=$(pia_bool PIA_PORT_FORWARD_ONLY true)
mode=${PIA_RECOVERY_MODE:-api}
case "$mode" in api | restart) ;; *) mode=api ;; esac

run_dir=${PIA_RUN_DIR:?}
state_dir=${PIA_STATE_DIR:?}
control=${PIA_CONTROL_URL:?}
pf_file=${PIA_PORTFORWARD_FILE:-/gluetun/piaportforward.json}
supervisor=$PPID

trap 'exit 0' TERM INT

pia_log $C "started: interval=${interval}s threshold=$threshold same_server_attempts=$same_attempts min_server_change=${min_change}s mode=$mode require_port=$require_port"

# register PIN_CN PIN_IP EXCLUDE_CN -> writes $run_dir/register.env.new
register() {
	set -- register --region "$PIA_REGION" --state-dir "$state_dir" \
		--timeout "${register_timeout}s" --port-forward-only="$pf_only" --format env \
		--pin-cn "$1" --pin-ip "$2" --exclude-cn "$3"
	pia-wg "$@" >"$run_dir/register.env.new"
}

# apply_new -> activates $run_dir/register.env.new; returns 1 on failure
apply_new() {
	# shellcheck source=/dev/null
	. "$run_dir/register.env.new"
	new_cn=$PIA_WG_CN
	new_ip=$PIA_WG_SERVER_IP
	if [ "$new_cn" != "$cur_cn" ]; then
		pia_log $C "server change: $cur_cn ($cur_ip, exit ip ${last_ip:-unknown}) -> $new_cn ($new_ip); dropping old port-forward signature"
		rm -f "$pf_file"
	fi
	mv "$run_dir/register.env.new" "$run_dir/register.env"
	if [ "$mode" = api ]; then
		if pia-wg apply --control "$control" --api-key-file "$run_dir/apikey" --state-dir "$state_dir"; then
			return 0
		fi
		pia_log $C "control-server apply failed, falling back to in-place gluetun restart"
	fi
	kill -USR1 "$supervisor"
}

fails=0
same_fail=0
recovering=0
last_ip=""
sleep "$grace"

while :; do
	sleep "$interval"
	if pia-wg probe --control "$control" --api-key-file "$run_dir/apikey" --require-port="$require_port" >"$run_dir/probe.env" 2>/dev/null; then
		# shellcheck source=/dev/null
		. "$run_dir/probe.env"
		last_ip=$PIA_PROBE_PUBLIC_IP
		if [ "$fails" -gt 0 ] || [ "$recovering" -eq 1 ]; then
			pia_log $C "healthy again: ip=$PIA_PROBE_PUBLIC_IP port=$PIA_PROBE_PORT"
		fi
		fails=0
		same_fail=0
		recovering=0
		continue
	fi
	# shellcheck source=/dev/null
	. "$run_dir/probe.env"
	fails=$((fails + 1))
	pia_log $C "unhealthy ($fails/$threshold): status=${PIA_PROBE_STATUS:-?} ip=${PIA_PROBE_PUBLIC_IP:-none} port=${PIA_PROBE_PORT:-0} ${PIA_PROBE_ERROR:-}"
	[ "$fails" -ge "$threshold" ] || continue

	# shellcheck source=/dev/null
	. "$run_dir/register.env"
	cur_cn=$PIA_WG_CN
	cur_ip=$PIA_WG_SERVER_IP
	age=$(($(date +%s) - PIA_WG_SERVER_CHANGED_EPOCH))

	if [ "$same_fail" -lt "$same_attempts" ]; then
		pia_log $C "recovering on the same server $cur_cn (attempt $((same_fail + 1))/$same_attempts)"
		if register "$cur_cn" "$cur_ip" ""; then
			same_fail=$((same_fail + 1))
			apply_new || true
		else
			rc=$?
			if [ "$rc" -eq 3 ]; then
				pia_log $C "$cur_cn is no longer listed by PIA, rolling to another server now"
				same_fail=$same_attempts
				if register "" "" "$cur_cn"; then
					same_fail=0
					apply_new || true
				fi
			else
				pia_log $C "re-registration with $cur_cn failed (exit $rc), will retry"
				same_fail=$((same_fail + 1))
			fi
		fi
	elif [ "$age" -ge "$min_change" ]; then
		pia_log $C "rolling to another server in $PIA_REGION (last change ${age}s ago)"
		if register "" "" "$cur_cn"; then
			same_fail=0
			apply_new || true
		else
			pia_log $C "registration with a new server failed (exit $?), will retry"
		fi
	else
		pia_log $C "holding $cur_cn: server change interval not reached (${age}s < ${min_change}s), re-registering"
		if register "$cur_cn" "$cur_ip" ""; then
			apply_new || true
		else
			pia_log $C "re-registration with $cur_cn failed (exit $?), will retry"
		fi
	fi
	fails=0
	recovering=1
	sleep "$grace"
done

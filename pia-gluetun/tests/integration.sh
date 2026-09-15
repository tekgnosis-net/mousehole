#!/bin/sh
# Integration test for pia-gluetun. Needs real PIA credentials and Docker.
# Never run in CI. Usage:
#
#   PIA_USER=pXXXX PIA_PASS=... sh pia-gluetun/tests/integration.sh [image]
#
# What it asserts, in order:
#   1. tunnel comes up, public IP is not the host's, a port is forwarded
#   2. a dependent container (network_mode: service:) sees the same public IP
#   3. after blocking the WireGuard endpoint inside the container, the loop
#      recovers, the container ID and the dependent's container ID are
#      unchanged, and at most one server change was logged
set -u

IMAGE=${1:-pia-gluetun:local}
REGION=${PIA_REGION:-swiss}
NAME=pia-it-$$
DEP=pia-it-dep-$$
fails=0
say() { printf '%s [integration] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
check() { if [ "$2" = "$3" ]; then say "ok   $1"; else say "FAIL $1: expected '$2' got '$3'"; fails=$((fails + 1)); fi; }
cleanup() {
	say "logs (last 60 lines):"
	docker logs --tail 60 "$NAME" 2>&1 | sed 's/^/    /'
	docker rm -f "$DEP" "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

: "${PIA_USER:?}" "${PIA_PASS:?}"
host_ip=$(wget -q -O - https://api.ipify.org 2>/dev/null || curl -s https://api.ipify.org)

say "starting $IMAGE region=$REGION"
docker run -d --name "$NAME" --cap-add NET_ADMIN --device /dev/net/tun \
	-e PIA_USER="$PIA_USER" -e PIA_PASS="$PIA_PASS" -e PIA_REGION="$REGION" \
	-e PIA_CHECK_INTERVAL=10 -e PIA_FAIL_THRESHOLD=2 -e PIA_STARTUP_GRACE=20 \
	-e HTTP_CONTROL_SERVER_ADDRESS=:8000 -e LOG_LEVEL=info \
	"$IMAGE" >/dev/null || exit 1
docker run -d --name "$DEP" --network "container:$NAME" alpine:3.20 sleep 3600 >/dev/null || exit 1

probe() { docker exec "$NAME" wget -q -O - -T 5 "http://127.0.0.1:8000/v1/$1" 2>/dev/null; }
wait_for() { # DESC SECONDS CMD...
	d=$1; s=$2; shift 2; i=0
	while ! "$@" >/dev/null 2>&1; do i=$((i + 1)); [ "$i" -lt "$s" ] || { say "FAIL timeout: $d"; fails=$((fails + 1)); return 1; }; sleep 1; done
	say "ok   $d"
}
tunnel_up() { probe vpn/status | grep -q '"running"' && probe publicip/ip | grep -q '"public_ip":"[0-9]'; }
port_up() { probe portforward | grep -Eq '"port":[1-9][0-9]*'; }

wait_for "tunnel running with public ip" 120 tunnel_up || exit 1
wait_for "port forwarded" 180 port_up || exit 1
vpn_ip=$(probe publicip/ip | sed -n 's/.*"public_ip":"\([^"]*\)".*/\1/p')
port=$(probe portforward | sed -n 's/.*"port":\([0-9]*\).*/\1/p')
say "public ip $vpn_ip, forwarded port $port"
if [ "$vpn_ip" != "$host_ip" ]; then say "ok   public ip differs from host ip"; else say "FAIL vpn ip equals host ip"; fails=$((fails + 1)); fi
dep_ip=$(docker exec "$DEP" wget -q -O - -T 10 https://api.ipify.org 2>/dev/null || echo none)
check "dependent container exits via the tunnel" "$vpn_ip" "$dep_ip"
if docker logs "$NAME" 2>&1 | grep -q 'port forwarded is'; then say "ok   gluetun logged forwarded port"; else say "FAIL no 'port forwarded is' log"; fails=$((fails + 1)); fi

cid_before=$(docker inspect -f '{{.Id}}' "$NAME")
dep_before=$(docker inspect -f '{{.Id}}' "$DEP")
endpoint=$(docker exec "$NAME" sh -c '. /run/pia/register.env && echo "$PIA_WG_SERVER_IP"')
cn_before=$(docker exec "$NAME" sh -c '. /run/pia/register.env && echo "$PIA_WG_CN"')
say "simulating outage: dropping traffic to $endpoint ($cn_before)"
docker exec "$NAME" iptables -I OUTPUT -d "$endpoint" -j DROP

wait_for "loop noticed the outage" 120 sh -c "docker logs $NAME 2>&1 | grep -q 'unhealthy (2/2)'"
wait_for "recovery attempted" 120 sh -c "docker logs $NAME 2>&1 | grep -q 'recovering on the same server'"
# The same-server attempt cannot succeed while the DROP rule is in place;
# lift it so the re-registration/apply can complete, mirroring a transient
# upstream outage.
docker exec "$NAME" iptables -D OUTPUT -d "$endpoint" -j DROP
wait_for "tunnel healthy again" 240 sh -c "docker logs $NAME 2>&1 | grep -q 'healthy again'"
wait_for "port forwarded after recovery" 180 port_up

check "container id unchanged" "$cid_before" "$(docker inspect -f '{{.Id}}' "$NAME")"
check "dependent container id unchanged" "$dep_before" "$(docker inspect -f '{{.Id}}' "$DEP")"
check "dependent still running" running "$(docker inspect -f '{{.State.Status}}' "$DEP")"
changes=$(docker logs "$NAME" 2>&1 | grep -c 'server change:')
if [ "$changes" -le 1 ]; then say "ok   at most one server change ($changes)"; else say "FAIL $changes server changes"; fails=$((fails + 1)); fi
say "gateway probe results (for the open PIA gateway question):"
docker logs "$NAME" 2>&1 | grep -i 'trying IP\|gateway\|19999' | tail -5 | sed 's/^/    /'

if [ "$fails" -eq 0 ]; then say "integration: all passed"; else say "integration: $fails failed"; exit 1; fi

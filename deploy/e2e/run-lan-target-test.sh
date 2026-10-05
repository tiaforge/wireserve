#!/usr/bin/env bash
# wireserve service-on-a-LAN-address test (PLAN.md M26).
#
# `serve myrouter 443:<device>:80` makes a device on the owning node's LAN —
# one that cannot run an agent — reachable from the mesh through that node.
#
#     [coordinator]──( inet )──[client agent]
#                        │
#                  [owner agent]
#                        │
#                    ( lan )──[device]  (no route to the mesh)
#
# What this proves, and what no unit test can:
#
#   1. a mesh peer reaches the device through the service address, over real
#      TCP, and the reply finds its way back;
#   2. the device sees the owner's LAN address (the masquerade), since it has
#      no route back into the mesh;
#   3. the owner's own clients reach it too (the output-path rewrite);
#   4. only the published port answers — the device's other ports, and the
#      target port on the service address, stay refused;
#   5. the owner turned forwarding on for its LAN interface alone, left the
#      global switch alone, and while it owns that flag nothing else is
#      forwarded from the LAN;
#   6. the rest of the mesh never learns the device's address;
#   7. `leave` turns the LAN interface's forwarding back off.
#
# Rootful Podman, same reasoning as run-transit-test.sh (service-address
# rewrites and the forwarding sysctls both need the host's own user
# namespace).
#
# Usage: sudo ./deploy/e2e/run-lan-target-test.sh
# Exit code 0 = every check passed.

set -euo pipefail
cd "$(dirname "$0")/../.."
. deploy/e2e/lib.sh

INET=wireserve-lan-inet
LAN=wireserve-lan-lan
COORD=wireserve-lan-coord
OWNER=wireserve-lan-owner
CLIENT=wireserve-lan-client
DEVICE=wireserve-lan-device
DEBUG_IMG=wireserve-e2e-debug-tools
ADMIN_TOKEN=lan-target-test-admin-token
WG_PORT=51820

log()  { echo; echo "=== $* ==="; }
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
note() { echo "NOTE: $*"; }

cleanup() {
    podman rm -fv -t 0 "$COORD" "$OWNER" "$CLIENT" "$DEVICE" >/dev/null 2>&1 || true
    for c in $(podman ps -aq --filter "name=wireserve-lan-helper" 2>/dev/null); do
        podman rm -fv -t 0 "$c" >/dev/null 2>&1 || true
    done
    podman network rm "$LAN" "$INET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

in_netns() {
    local target=$1; shift
    podman run --rm --name "wireserve-lan-helper-$$-$RANDOM" \
        --network "container:$target" --cap-add=NET_ADMIN "$DEBUG_IMG" "$@"
}
ip_on() {
    podman inspect "$1" --format "{{(index .NetworkSettings.Networks \"$2\").IPAddress}}"
}
admin() { podman exec "$COORD" wireserve-admin "$@"; }
fwd_flag() { in_netns "$OWNER" cat "/proc/sys/net/ipv4/conf/$1/forwarding" 2>/dev/null || echo "?"; }
# One TCP exchange: prints whatever the far end answered, empty on failure.
# A check that something is refused sets ASK_TIMEOUT short: by then the path
# is known to work, and what answers at all answers in well under a second.
ask() { local from=$1 addr=$2 port=$3; in_netns "$from" timeout "${ASK_TIMEOUT:-8}" socat -t3 - "TCP:$addr:$port" </dev/null 2>/dev/null || true; }

log "checking prerequisites"
command -v podman >/dev/null || fail "podman not found on PATH"
command -v python3 >/dev/null || fail "python3 not found on PATH"
modinfo wireguard >/dev/null 2>&1 || fail "WireGuard kernel module not available"
[ "$(podman info --format '{{.Host.Security.Rootless}}')" = false ] \
    || fail "needs rootful podman (service-address rewrites and the forwarding sysctls are refused in a user namespace): sudo $0"
pass "podman, python3 and the WireGuard kernel module are present"

log "building images"
./deploy/e2e/build.sh
pass "images built"

log "creating the two segments"
podman network create --internal "$INET" >/dev/null
podman network create --internal "$LAN" >/dev/null
pass "inet and lan, both internal"

log "starting the coordinator"
podman run -d --name "$COORD" --network "$INET" \
    -e WIRESERVE_ADMIN_TOKEN="$ADMIN_TOKEN" \
    wireserve-coordinator:e2e >/dev/null
sleep 2
COORD_IP=$(ip_on "$COORD" "$INET")
echo "coordinator: $COORD_IP"

log "starting the device on the lan only"
podman run -d --name "$DEVICE" --network "$LAN" "$DEBUG_IMG" sleep infinity >/dev/null
sleep 1
DEVICE_IP=$(ip_on "$DEVICE" "$LAN")
# What it answers says who it thinks is talking to it.
podman exec -d "$DEVICE" socat TCP-LISTEN:80,fork,reuseaddr SYSTEM:'echo device peer=$SOCAT_PEERADDR'
podman exec -d "$DEVICE" socat TCP-LISTEN:22,fork,reuseaddr SYSTEM:'echo device ssh'
echo "device: $DEVICE_IP"

log "starting the owner (inet + lan) with forwarding off everywhere, and the client"
# A podman host usually forwards globally (netavark turns it on), and a new
# namespace inherits that. Forwarding is switched off explicitly so the
# owner looks like an ordinary host, the case where the agent must turn the
# LAN interface's flag on and guard it.
podman run -d --name "$OWNER" --network "$INET" --network "$LAN" \
    --cap-add=NET_ADMIN --security-opt unmask=/proc/sys --security-opt apparmor=unconfined --device /dev/net/tun \
    --sysctl net.ipv4.conf.all.forwarding=0 --sysctl net.ipv4.conf.default.forwarding=0 \
    --entrypoint sleep wireserve-agent:e2e infinity >/dev/null
podman run -d --name "$CLIENT" --network "$INET" \
    --cap-add=NET_ADMIN --security-opt unmask=/proc/sys --security-opt apparmor=unconfined --device /dev/net/tun \
    --entrypoint sleep wireserve-agent:e2e infinity >/dev/null
sleep 1
OWNER_INET=$(ip_on "$OWNER" "$INET")
OWNER_LAN=$(ip_on "$OWNER" "$LAN")
LAN_IF=$(in_netns "$OWNER" ip -o -4 addr show | awk -v ip="$OWNER_LAN" '$4 ~ "^"ip"/" {print $2}')
[ -n "$LAN_IF" ] || fail "could not find the owner's lan interface"
echo "owner: inet $OWNER_INET, lan $OWNER_LAN on $LAN_IF"
# The agent writes the lan interface's flag itself; a runtime that mounts
# /proc/sys read-only would make every check below fail for the wrong reason.
podman exec "$OWNER" sh -c "echo 0 > /proc/sys/net/ipv4/conf/$LAN_IF/forwarding" \
    || fail "/proc/sys/net is not writable in the owner container, so the agent could not turn forwarding on"
[ "$(fwd_flag all)" = 0 ] && [ "$(fwd_flag "$LAN_IF")" = 0 ] \
    || fail "could not switch forwarding off in the owner (all=$(fwd_flag all) $LAN_IF=$(fwd_flag "$LAN_IF"))"
pass "the owner forwards nothing to begin with"

create_node() { admin node create "$1" | grep -oE 'jtk_[a-f0-9]+'; }
sees() { podman exec "$1" wireserve status --json | grep -q "\"name\": \"$2\""; }
pending() { podman exec "$1" wireserve status --json | grep -q '"pending": true'; }

log "joining both agents"
JT_OWNER=$(create_node node-owner)
JT_CLIENT=$(create_node node-client)
podman exec "$OWNER" wireserve join "http://$COORD_IP:47820" --allow-plaintext-http "$JT_OWNER" \
    --listen-port "$WG_PORT" --endpoint "$OWNER_INET:$WG_PORT" 2>/dev/null
podman exec "$CLIENT" wireserve join "http://$COORD_IP:47820" --allow-plaintext-http "$JT_CLIENT" \
    --listen-port "$WG_PORT" --endpoint "$(ip_on "$CLIENT" "$INET"):$WG_PORT" 2>/dev/null
for a in "$OWNER" "$CLIENT"; do
    podman exec -d "$a" wireserve daemon --poll-interval-secs "$POLL"
done
wait_for 30 sees "$OWNER" node-client || fail "node-owner never got node-client into its peers"
wait_for 30 sees "$CLIENT" node-owner || fail "node-client never got node-owner into its peers"
pass "both agents registered and polling"

log "refusals at serve time"
if podman exec "$OWNER" wireserve bad 443:127.0.0.1:80 >/dev/null 2>&1; then
    fail "serve accepted a loopback target"
fi
if podman exec "$OWNER" wireserve bad '443:[fd00::1]:80' >/dev/null 2>&1; then
    fail "serve accepted an IPv6 target"
fi
pass "loopback and IPv6 targets are refused"

log "serving the device's port 80 on 443"
podman exec "$OWNER" wireserve myrouter "443:$DEVICE_IP:80"
wait_for 20 pending "$OWNER" || fail "node-owner never reported myrouter"
admin service approve myrouter --node node-owner || fail "could not approve myrouter"
admin service list | grep '^myrouter ' | grep -q "443:$DEVICE_IP:80/tcp" \
    || fail "the approver does not see the target address"
pass "the approver sees 443:$DEVICE_IP:80/tcp"
wait_for 20 eval '! pending "$OWNER"' || fail "node-owner never learnt myrouter was approved"
wait_for 20 podman exec "$CLIENT" getent hosts myrouter.wg || true

VIP=$(podman exec "$CLIENT" getent hosts myrouter.wg | awk '{print $1}')
[ -n "$VIP" ] || fail "myrouter.wg does not resolve on the client"
echo "myrouter.wg=$VIP"
wait_for 20 eval '[ -n "$(ask "$CLIENT" "$VIP" 443)" ]' || true

log "1-2/7: the client reaches the device, which sees the owner's lan address"
GOT=$(ask "$CLIENT" "$VIP" 443)
echo "answer: ${GOT:-<none>}"
[ -n "$GOT" ] || fail "no answer from the device through myrouter.wg:443"
[ "$GOT" = "device peer=$OWNER_LAN" ] \
    || fail "the device should see the owner's lan address $OWNER_LAN (masquerade), got '$GOT'"
pass "the device answered, and saw $OWNER_LAN"

log "3/7: the owner's own clients reach it too"
GOT=$(ask "$OWNER" "$VIP" 443)
[ "$GOT" = "device peer=$OWNER_LAN" ] || fail "from the owner itself: got '${GOT:-<none>}'"
pass "the owner reaches its own service through the output path"

log "4/7: only the published port answers"
[ -z "$(ASK_TIMEOUT=4 ask "$CLIENT" "$VIP" 22)" ] || fail "the device's unpublished port 22 was reachable"
[ -z "$(ASK_TIMEOUT=4 ask "$CLIENT" "$VIP" 80)" ] || fail "the target port 80 was reachable on the service address"
[ -z "$(ASK_TIMEOUT=4 ask "$CLIENT" "$DEVICE_IP" 80)" ] || fail "the device was reachable at its own address from the mesh"
pass "22, 80 on the service address, and the device's own address are all refused"

log "5/7: forwarding on the lan interface alone, and guarded"
[ "$(fwd_flag "$LAN_IF")" = 1 ] || fail "$LAN_IF forwarding is not on (got '$(fwd_flag "$LAN_IF")')"
[ "$(fwd_flag all)" = 0 ] || fail "the GLOBAL forwarding switch changed"
[ "$(fwd_flag wireserve0)" = 1 ] || fail "wireserve0 forwarding is not on"
pass "$LAN_IF and wireserve0 forward; the global switch is untouched"
in_netns "$OWNER" nft list table inet wireserve.wireserve0 | grep -q "iifname \"$LAN_IF\" meta nfproto ipv4 ct mark" \
    || fail "no guard for $LAN_IF in the agent's table"
# The device tries to use the owner as a router to the inet segment. One-way
# UDP, recorded where it lands: a TCP connect would fail even without the
# guard, since the reply would arrive on the owner's inet interface, whose
# forwarding is off — so it would pass for the wrong reason. The request
# direction depends on $LAN_IF's flag (on, checked above) and the guard alone.
# The device runs without NET_ADMIN, so its route goes in from a helper.
in_netns "$DEVICE" ip route add "$COORD_IP/32" via "$OWNER_LAN"
PROBE=wireserve-lan-helper-probe-$$
podman run -d --name "$PROBE" --network "container:$COORD" "$DEBUG_IMG" \
    socat -u UDP-RECV:47999 STDOUT >/dev/null
sleep 1
for _ in 1 2 3; do
    podman exec "$DEVICE" bash -c "echo routed-through-owner > /dev/udp/$COORD_IP/47999" || true
    sleep 1
done
if podman logs "$PROBE" 2>/dev/null | grep -q routed-through-owner; then
    fail "the device's packet reached the coordinator through the owner — the lan is being routed"
fi
podman rm -fv -t 0 "$PROBE" >/dev/null
pass "nothing but the service's own flows is forwarded from $LAN_IF"

log "6/7: the rest of the mesh never learns the device's address"
if podman exec "$CLIENT" wireserve status --json | grep -q "$DEVICE_IP"; then
    fail "the client's directory carries the device's address"
fi
podman exec "$OWNER" wireserve status | grep myrouter | grep -q "443:$DEVICE_IP:80/tcp" \
    || fail "the owner's own list does not show its declaration"
pass "the client sees only the public face; the owner sees its declaration"

log "7/7: leave turns the lan interface's forwarding back off"
podman exec "$OWNER" wireserve leave
sleep 3
[ "$(fwd_flag "$LAN_IF")" = 0 ] || fail "$LAN_IF still forwards after leave (got '$(fwd_flag "$LAN_IF")')"
[ "$(fwd_flag all)" = 0 ] || fail "the global switch changed on leave"
pass "$LAN_IF is back to not forwarding"

echo
echo "=== LAN TARGET TEST COMPLETE ==="

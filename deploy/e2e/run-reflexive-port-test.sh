#!/usr/bin/env bash
# wireserve reflexive probe on the WireGuard port (PLAN.md M50).
#
# A node on a network that lets UDP out to the WireGuard port and nothing
# else (hotel and office Wi-Fi) never reaches the coordinator's reflexive
# responder on 47820/udp, so it never learns its NAT-mapped address. The
# node on the coordinator's own host can answer the probe on its WireGuard
# port instead. This suite builds exactly that:
#
#     ( inet, 192.0.2.0/24 )
#          │                         │
#     [coordinator + node-coord]   [router-w]  masquerade; UDP out to
#      one network namespace,          │       51820 only; node-wifi's
#      WireGuard on 51820          ( site-w )  51820 mapped to 40404
#                                      │
#                                 [node-wifi]
#
# and checks:
#   1. node-wifi's join, before any responder is named, learns nothing:
#      the strict Wi-Fi really blocks the coordinator's own port;
#   2. once node-coord is named and its agent confirms, /probe lists its
#      WireGuard port first;
#   3. node-wifi's daemon then learns its real NAT-mapped port (40404),
#      not the naive listen-port guess;
#   4. its dialable stays unknown: the coordinator never saw the probe,
#      so it sent no second answer to judge by;
#   5. WireGuard between the two still works over the very flow the probe
#      used (same source port, same destination port): tproxy takes the
#      probe alone, where NAT would have taken the whole flow (#347);
#   6. clearing the responder takes the port out of /probe again.
#
# Rootful Podman, as the other suites: the agents need real nftables
# (tproxy) and kernel WireGuard.
#
# Usage: sudo ./deploy/e2e/run-reflexive-port-test.sh
# Exit code 0 = every check passed.

set -euo pipefail
cd "$(dirname "$0")/../.."
. deploy/e2e/lib.sh

INET=wireserve-rp-inet
SITE_W=wireserve-rp-site-w
COORD=wireserve-rp-coord
COORD_NODE=wireserve-rp-coord-node
ROUTER_W=wireserve-rp-router-w
WIFI=wireserve-rp-wifi
DEBUG_IMG=wireserve-e2e-debug-tools
ADMIN_TOKEN=reflexive-port-test-admin-token
WG_PORT=51820
WIFI_NAT_PORT=40404

log()  { echo; echo "=== $* ==="; }
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
note() { echo "NOTE: $*"; }

cleanup() {
    podman rm -fv -t 0 "$WIFI" "$ROUTER_W" "$COORD_NODE" "$COORD" >/dev/null 2>&1 || true
    for c in $(podman ps -aq --filter "name=wireserve-rp-helper" 2>/dev/null); do
        podman rm -fv -t 0 "$c" >/dev/null 2>&1 || true
    done
    podman network rm "$SITE_W" "$INET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

in_netns() {
    local target=$1; shift
    podman run --rm --name "wireserve-rp-helper-$$-$RANDOM" \
        --network "container:$target" --cap-add=NET_ADMIN "$DEBUG_IMG" "$@"
}
in_netns_bg() {
    local target=$1; shift
    podman run -d --name "wireserve-rp-helper-$$-$RANDOM" \
        --network "container:$target" --cap-add=NET_ADMIN "$DEBUG_IMG" "$@" >/dev/null
}
ip_on() {
    podman inspect "$1" --format "{{(index .NetworkSettings.Networks \"$2\").IPAddress}}"
}
admin() { podman exec "$COORD" wireserve-admin "$@"; }
peers() { admin node list --json; }
peer_field() { peers | jq -r --arg n "$1" --arg f "$2" '.peers[] | select(.name == $n) | .[$f] // "-"'; }
# /probe as node-wifi sees it, through its strict Wi-Fi (TCP gets out).
probe_ports() { in_netns "$WIFI" curl -fsS "http://$COORD_IP:47820/probe" | jq -c '.reflexive_ports // []'; }

# What to look at when a check fails.
diag() {
    note "the mesh as the coordinator sees it:"
    peers || true
    note "node-coord's daemon, reflexive lines and warnings:"
    podman exec "$COORD_NODE" grep -E 'reflexive|WARN|ERROR' /tmp/daemon.log || true
    note "node-wifi's daemon, reflexive lines and warnings:"
    podman exec "$WIFI" grep -E 'reflexive|WARN|ERROR' /tmp/daemon.log 2>/dev/null || true
    note "node-coord's reflexive chain:"
    in_netns "$COORD" nft list chain inet wireserve.wireserve0 reflexive-pre || true
}

log "checking prerequisites"
command -v podman >/dev/null || fail "podman not found on PATH"
command -v jq >/dev/null || fail "jq not found on PATH (reads wireserve-admin --json)"
modinfo wireguard >/dev/null 2>&1 || fail "WireGuard kernel module not available"
[ "$(podman info --format '{{.Host.Security.Rootless}}')" = false ] \
    || fail "needs rootful podman (kernel WireGuard and tproxy in the agents' namespaces): sudo $0"
pass "podman and the WireGuard kernel module are present"

log "building images"
./deploy/e2e/build.sh
pass "images built"

log "creating the network segments"
# Internal, so the router is the only NAT (see run-nat-test.sh), and on a
# public-looking range, as the coordinator's host would be.
podman network create --internal --subnet 192.0.2.0/24 "$INET" >/dev/null
podman network create --internal "$SITE_W" >/dev/null
pass "an 'internet' and one site behind a strict Wi-Fi"

log "starting the coordinator, and a node in its network namespace"
podman run -d --name "$COORD" --network "$INET" \
    -e WIRESERVE_ADMIN_TOKEN="$ADMIN_TOKEN" \
    -e WIRESERVE_NET_V4_CIDR="$MESH_V4" \
    wireserve-coordinator:e2e >/dev/null
sleep 2
COORD_IP=$(ip_on "$COORD" "$INET")
COORD_IF=$(in_netns "$COORD" sh -c "ip -o -4 addr show | awk '/ $COORD_IP\\//{print \$2}'")
# Internal networks have no default route; the agent finds its interface by one.
in_netns "$COORD" ip route replace default dev "$COORD_IF" >/dev/null
# The node on the coordinator's host: the same address, the same network
# namespace, its own WireGuard on 51820.
podman run -d --name "$COORD_NODE" --network "container:$COORD" \
    --cap-add=NET_ADMIN --cap-add=NET_RAW --security-opt unmask=/proc/sys --security-opt apparmor=unconfined --device /dev/net/tun \
    --entrypoint sleep wireserve-agent:e2e infinity >/dev/null
sleep 1
echo "coordinator and node-coord: $COORD_IP ($COORD_IF)"

log "starting the strict Wi-Fi router and node-wifi behind it"
podman run -d --name "$ROUTER_W" --network "$INET" --network "$SITE_W" \
    --cap-add=NET_ADMIN --sysctl net.ipv4.ip_forward=1 \
    "$DEBUG_IMG" sleep infinity >/dev/null
sleep 1
ROUTER_W_INET=$(if_on "$ROUTER_W" "$INET")
ROUTER_W_WAN=$(ip_on "$ROUTER_W" "$INET")
ROUTER_W_LAN=$(ip_on "$ROUTER_W" "$SITE_W")
podman run -d --name "$WIFI" --network "$SITE_W" \
    --cap-add=NET_ADMIN --cap-add=NET_RAW --security-opt unmask=/proc/sys --security-opt apparmor=unconfined --device /dev/net/tun \
    --entrypoint sleep wireserve-agent:e2e infinity >/dev/null
sleep 1
in_netns "$WIFI" ip route replace default via "$ROUTER_W_LAN" >/dev/null
WIFI_LAN=$(ip_on "$WIFI" "$SITE_W")
# Masquerade, but node-wifi's WireGuard port mapped to a port of its own for
# every destination, as a home router's would: the port a probe learns, and
# the naive guess (its address + listen port) gets wrong. TCP leaves freely
# (the poll); UDP only to the WireGuard port.
podman exec -i "$ROUTER_W" nft -f - <<NFT
table ip nat {
    chain postrouting {
        type nat hook postrouting priority 100;
        oifname "$ROUTER_W_INET" ip saddr $WIFI_LAN udp sport $WG_PORT snat to $ROUTER_W_WAN:$WIFI_NAT_PORT
        oifname "$ROUTER_W_INET" masquerade
    }
}
table inet strictwifi {
    chain forward {
        type filter hook forward priority -10; policy accept;
        oifname "$ROUTER_W_INET" meta l4proto udp udp dport != $WG_PORT drop
    }
}
NFT
podman exec "$ROUTER_W" nft list table inet strictwifi | has "udp dport != $WG_PORT drop" \
    || fail "the strict Wi-Fi is not in place — the rest would prove nothing"
echo "router-w wan=$ROUTER_W_WAN lan=$ROUTER_W_LAN; node-wifi $WIFI_LAN"
pass "only UDP $WG_PORT leaves node-wifi's network, its port mapped to $WIFI_NAT_PORT"

create_node() { admin node create "$1" | grep -oE 'jtk_[a-f0-9]+'; }
start_daemon() { podman exec -d "$1" sh -c "exec wireserve daemon --poll-interval-secs $POLL >/tmp/daemon.log 2>&1"; }

log "joining node-coord and starting its daemon"
JT=$(create_node node-coord)
podman exec "$COORD_NODE" wireserve join "http://$COORD_IP:47820" --allow-plaintext-http "$JT" \
    --listen-port "$WG_PORT" 2>/dev/null
start_daemon "$COORD_NODE"

log "1/6: node-wifi joins before any responder is named, and learns nothing"
# `join` runs the same probe as the daemon's start. Only 47820/udp is listed
# yet, and the strict Wi-Fi drops it.
[ "$(probe_ports)" = "[]" ] || fail "/probe lists ports before a responder was named: $(probe_ports)"
JT=$(create_node node-wifi)
podman exec "$WIFI" wireserve join "http://$COORD_IP:47820" --allow-plaintext-http "$JT" \
    --listen-port "$WG_PORT" 2>/dev/null
[ "$(peer_field node-wifi reflexive_addr)" = "-" ] \
    || { diag; fail "node-wifi learned $(peer_field node-wifi reflexive_addr) through a Wi-Fi that should block 47820/udp"; }
pass "the coordinator's own port is unreachable from node-wifi's network"

log "2/6: node-coord is named, confirms, and /probe lists its WireGuard port"
admin node responder node-coord
wait_for 30 eval '[ "$(peers | jq -r .reflexive_answering)" = true ]' \
    || { diag; fail "node-coord never confirmed it answers on its WireGuard port"; }
admin node show node-coord | has -E "^probe responder: +answering$" \
    || { admin node show node-coord; fail "node show does not say node-coord is answering"; }
[ "$(probe_ports | jq '.[0]')" = "$WG_PORT" ] || { diag; fail "/probe does not list $WG_PORT first: $(probe_ports)"; }
pass "node-coord answers, and /probe lists $(probe_ports)"

log "3/6: node-wifi's daemon learns its real NAT-mapped port"
# The daemon probes once at its start, before WireGuard takes the port.
start_daemon "$WIFI"
want="$ROUTER_W_WAN:$WIFI_NAT_PORT"
wait_for 40 eval '[ "$(peer_field node-wifi reflexive_addr)" = "$want" ]' \
    || { diag; fail "node-wifi's reflexive address is $(peer_field node-wifi reflexive_addr), not $want"; }
pass "node-wifi learned $want through node-coord's WireGuard port"

log "4/6: node-wifi's dialable stays unknown"
settle
[ "$(peers | jq '.dialable["node-wifi"]')" = null ] \
    || { diag; fail "node-wifi reported dialable=$(peers | jq '.dialable["node-wifi"]'); the coordinator never saw its probe"; }
pass "no second answer to judge by, so nothing is claimed"

log "5/6: WireGuard between the two works over the flow the probe used"
# node-wifi probed from its 51820 to node-coord's 51820, and its WireGuard
# then speaks on exactly that flow. A NAT rule for the probe would have sent
# all of it to the responder.
podman exec "$COORD_NODE" wireserve svc-coord 12345
wait_for 20 eval 'podman exec "$COORD_NODE" wireserve status --json | has "\"pending\": true"' \
    || fail "node-coord never reported svc-coord"
admin service approve svc-coord --node node-coord || fail "could not approve svc-coord"
wait_for 30 podman exec "$WIFI" getent hosts svc-coord.wg || fail "node-wifi never learned svc-coord.wg"
SVC=$(podman exec "$WIFI" getent hosts svc-coord.wg | awk '{print $1}')
in_netns_bg "$COORD" nc -l -k -p 12345
sleep 2
wait_for 30 podman exec "$WIFI" timeout 5 bash -c "exec 3<>/dev/tcp/$SVC/12345" \
    || { diag; in_netns "$WIFI" wg show || true; fail "node-wifi could not reach svc-coord through the tunnel"; }
in_netns "$WIFI" wg show wireserve0 latest-handshakes | awk '$2 > 0 { found = 1 } END { exit !found }' \
    || fail "node-wifi has no WireGuard handshake with node-coord"
pass "node-wifi reaches node-coord's service over a live tunnel"

log "6/6: clearing the responder takes its port out of /probe"
admin node responder --clear
[ "$(probe_ports)" = "[]" ] || fail "/probe still lists $(probe_ports) after --clear"
wait_for 20 eval '! in_netns "$COORD" nft list chain inet wireserve.wireserve0 reflexive-pre' \
    || fail "node-coord kept its reflexive rule after --clear"
pass "no port listed, and node-coord's rule is gone"

echo
echo "=== REFLEXIVE PORT TEST COMPLETE ==="

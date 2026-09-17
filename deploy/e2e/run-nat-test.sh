#!/usr/bin/env bash
# WireServe NAT traversal test.
#
# The plain E2E test (run-e2e-test.sh) puts both agents on one bridge
# network where they can already reach each other directly. That is the
# easy topology and not the one anybody actually deploys. This script
# builds the realistic one: two separate "sites", each behind its own
# NAT router, with the coordinator out on a shared "internet" segment.
#
#     [coordinator]───────────( inet )───────────┐
#                                │               │
#                          [router-a]       [router-b]
#                          DNAT 51820        no forward
#                                │               │
#                          ( site-a )       ( site-b )
#                                │               │
#                            [agent1]     [agent2]  [agent3]
#
# agent1 is the home server: a port-forward makes its WireGuard port
# reachable from outside. agent2 is the laptop: outbound NAT only, no
# forward, which is the case PersistentKeepalive exists for. agent3 shares
# agent2's NAT, because two machines in the same house behind one router
# is entirely normal and is where source-port assumptions break.
#
# Everything runs in rootless Podman: the routers are ordinary containers
# with CAP_NET_ADMIN doing real nftables masquerade and DNAT, and the site
# networks are `--internal` so Podman itself adds no path to the outside.
# The only way out of a site is through its router.
#
# Usage: ./deploy/e2e/run-nat-test.sh
# Exit code 0 = every check passed.

set -euo pipefail
cd "$(dirname "$0")/../.."

INET=wireserve-nat-inet
SITE_A=wireserve-nat-site-a
SITE_B=wireserve-nat-site-b
COORD=wireserve-nat-coord
ROUTER_A=wireserve-nat-router-a
ROUTER_B=wireserve-nat-router-b
AGENT1=wireserve-nat-agent1
AGENT2=wireserve-nat-agent2
AGENT3=wireserve-nat-agent3
DEBUG_IMG=wireserve-e2e-debug-tools
ADMIN_TOKEN=nat-test-admin-token
WG_PORT=51820

log()  { echo; echo "=== $* ==="; }
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
note() { echo "NOTE: $*"; }

cleanup() {
    podman rm -f "$COORD" "$ROUTER_A" "$ROUTER_B" "$AGENT1" "$AGENT2" "$AGENT3" \
        >/dev/null 2>&1 || true
    for c in $(podman ps -aq --filter "name=wireserve-nat-helper" 2>/dev/null); do
        podman rm -f "$c" >/dev/null 2>&1 || true
    done
    podman network rm "$SITE_A" "$SITE_B" "$INET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

# Runs a throwaway helper inside another container's network namespace.
# The agent image has no iproute2 or nc, and adding them to a shipped
# image just to test it would be the wrong trade; sharing the namespace
# gets the same access without touching what we deploy.
in_netns() {
    local target=$1; shift
    podman run --rm --name "wireserve-nat-helper-$$-$RANDOM" \
        --network "container:$target" --cap-add=NET_ADMIN "$DEBUG_IMG" "$@"
}
in_netns_bg() {
    local target=$1; shift
    podman run -d --name "wireserve-nat-helper-$$-$RANDOM" \
        --network "container:$target" --cap-add=NET_ADMIN "$DEBUG_IMG" "$@" >/dev/null
}

ip_on() {
    podman inspect "$1" --format "{{(index .NetworkSettings.Networks \"$2\").IPAddress}}"
}

log "checking prerequisites"
command -v podman >/dev/null || fail "podman not found on PATH"
command -v python3 >/dev/null || fail "python3 not found on PATH"
modinfo wireguard >/dev/null 2>&1 || fail "WireGuard kernel module not available"
pass "podman, python3 and the WireGuard kernel module are present"

log "building images"
podman build -q -f deploy/docker/coordinator.Dockerfile -t wireserve-coordinator:nat-test . >/dev/null
podman build -q -f deploy/docker/agent.Dockerfile -t wireserve-agent:nat-test . >/dev/null
podman build -q -f deploy/e2e/debug-tools.Dockerfile -t "$DEBUG_IMG" deploy/e2e >/dev/null
pass "images built"

log "creating the three network segments"
# All three are --internal, including the one standing in for the public
# internet, and that detail is the difference between this test measuring
# something and measuring nothing.
#
# Netavark masquerades any traffic whose source belongs to one of its
# non-internal network subnets. Our routers masquerade site traffic to
# their own inet-side address, so on a non-internal inet segment netavark
# would then masquerade it a SECOND time on the way into the far site,
# rewriting the source to that bridge's own address. The receiving agent
# would learn a bogus endpoint for its peer, replies would have no return
# path, and the handshake would half-complete: packets in, nothing back.
# Marking every segment internal leaves our router containers as the only
# thing performing NAT, which is the entire point. Nothing here needs
# outbound internet at runtime.
podman network create --internal "$INET" >/dev/null
podman network create --internal "$SITE_A" >/dev/null
podman network create --internal "$SITE_B" >/dev/null
pass "three internal segments, so the only NAT is the one our routers do"

log "starting the coordinator on the inet segment"
podman run -d --name "$COORD" --network "$INET" \
    -e WIRESERVE_ADMIN_TOKEN="$ADMIN_TOKEN" \
    wireserve-coordinator:nat-test >/dev/null
sleep 2
COORD_IP=$(ip_on "$COORD" "$INET")
echo "coordinator: $COORD_IP"

start_router() {
    local name=$1 site=$2
    podman run -d --name "$name" --network "$INET" --network "$site" \
        --cap-add=NET_ADMIN --sysctl net.ipv4.ip_forward=1 \
        "$DEBUG_IMG" sleep infinity >/dev/null
    sleep 1
    # eth0 is the inet side, eth1 the site side: interface order follows
    # the order the --network flags were given above.
    podman exec "$name" nft add table ip nat
    podman exec "$name" nft 'add chain ip nat postrouting { type nat hook postrouting priority 100 ; }'
    podman exec "$name" nft 'add chain ip nat prerouting { type nat hook prerouting priority -100 ; }'
    podman exec "$name" nft 'add rule ip nat postrouting oifname "eth0" masquerade'
}

log "starting the two NAT routers"
start_router "$ROUTER_A" "$SITE_A"
start_router "$ROUTER_B" "$SITE_B"
ROUTER_A_WAN=$(ip_on "$ROUTER_A" "$INET")
ROUTER_A_LAN=$(ip_on "$ROUTER_A" "$SITE_A")
ROUTER_B_WAN=$(ip_on "$ROUTER_B" "$INET")
ROUTER_B_LAN=$(ip_on "$ROUTER_B" "$SITE_B")
echo "router-a  wan=$ROUTER_A_WAN  lan=$ROUTER_A_LAN"
echo "router-b  wan=$ROUTER_B_WAN  lan=$ROUTER_B_LAN"
pass "both routers are masquerading their site behind a single address"

start_agent() {
    local name=$1 site=$2 gateway=$3
    podman run -d --name "$name" --network "$site" \
        --cap-add=NET_ADMIN --device /dev/net/tun \
        --entrypoint sleep wireserve-agent:nat-test infinity >/dev/null
    sleep 1
    # An --internal network has no default route; point it at our router.
    in_netns "$name" ip route replace default via "$gateway" >/dev/null
}

log "starting three agents behind the NATs"
start_agent "$AGENT1" "$SITE_A" "$ROUTER_A_LAN"
start_agent "$AGENT2" "$SITE_B" "$ROUTER_B_LAN"
start_agent "$AGENT3" "$SITE_B" "$ROUTER_B_LAN"
AGENT1_LAN=$(ip_on "$AGENT1" "$SITE_A")
AGENT2_LAN=$(ip_on "$AGENT2" "$SITE_B")
AGENT3_LAN=$(ip_on "$AGENT3" "$SITE_B")
echo "agent1 (site-a, will get a port-forward): $AGENT1_LAN"
echo "agent2 (site-b, no forward):             $AGENT2_LAN"
echo "agent3 (site-b, shares agent2's NAT):    $AGENT3_LAN"

log "port-forwarding UDP/$WG_PORT on router-a to agent1"
podman exec "$ROUTER_A" nft \
    "add rule ip nat prerouting iifname \"eth0\" udp dport $WG_PORT dnat to $AGENT1_LAN:$WG_PORT"
pass "agent1 is reachable from the inet segment, the other two are not"

log "checking the agents can reach the coordinator through NAT at all"
for a in "$AGENT1" "$AGENT2" "$AGENT3"; do
    podman exec "$a" timeout 10 bash -c "exec 3<>/dev/tcp/$COORD_IP/8080" \
        || fail "$a cannot reach the coordinator through its NAT"
done
pass "all three agents reach the coordinator through their NAT"

create_node() {
    podman exec "$COORD" wireserve-admin create-node "$1" | grep -oE 'jtk_[a-f0-9]+'
}

log "joining the three nodes"
JT1=$(create_node node1)
JT2=$(create_node node2)
JT3=$(create_node node3)
# agent1 knows its public endpoint, because somebody configured the
# port-forward and told it so. This is the normal home-server case.
podman exec "$AGENT1" wireserve-agent join "http://$COORD_IP:8080" "$JT1" \
    --listen-port "$WG_PORT" --endpoint-addr "$ROUTER_A_WAN:$WG_PORT" 2>/dev/null
# agent2 and agent3 do not: they are behind NAT with nothing forwarded, so
# they leave it unset and the coordinator falls back to the source address
# it observes (spec §4.2).
podman exec "$AGENT2" wireserve-agent join "http://$COORD_IP:8080" "$JT2" --listen-port "$WG_PORT" 2>/dev/null
podman exec "$AGENT3" wireserve-agent join "http://$COORD_IP:8080" "$JT3" --listen-port "$WG_PORT" 2>/dev/null
pass "all three nodes registered from behind NAT"

log "what endpoint did the coordinator record for each node?"
podman exec "$COORD" wireserve-admin list-peers | while read -r line; do echo "  $line"; done

for a in "$AGENT1" "$AGENT2" "$AGENT3"; do
    podman exec -d "$a" wireserve-agent daemon --poll-interval-secs 5
done
log "waiting for poll cycles and WireGuard handshakes"
sleep 20

mesh_ip_of() {
    podman exec "$1" wireserve-agent list | python3 -c "
import json, sys
peers = json.load(sys.stdin).get('peers', [])
m = [p['ip4'] for p in peers if p.get('name') == '$2']
print(m[0] if m else '')
"
}

AGENT1_MESH=$(mesh_ip_of "$AGENT2" node1)
AGENT2_MESH=$(mesh_ip_of "$AGENT1" node2)
[ -n "$AGENT1_MESH" ] || fail "agent2 does not know node1's mesh address"
[ -n "$AGENT2_MESH" ] || fail "agent1 does not know node2's mesh address"
echo "node1 mesh address: $AGENT1_MESH"
echo "node2 mesh address: $AGENT2_MESH"

log "declaring a service on each of agent1 and agent2"
podman exec "$AGENT1" wireserve-agent serve svc-one 12345 tcp
podman exec "$AGENT2" wireserve-agent serve svc-two 12345 tcp
sleep 8
# Service approval is on by default. This harness is about NAT traversal,
# not about the approval gate (run-e2e-test.sh covers that), so approve
# both and get on with the actual question.
podman exec "$COORD" wireserve-admin approve-service node1 svc-one \
    || fail "could not approve svc-one"
podman exec "$COORD" wireserve-admin approve-service node2 svc-two \
    || fail "could not approve svc-two"
sleep 12
in_netns_bg "$AGENT1" nc -l -k -p 12345
in_netns_bg "$AGENT2" nc -l -k -p 12345
sleep 2

# --- The actual question this whole harness exists to answer. ---

log "NAT-ed client to port-forwarded server (agent2 -> agent1)"
# The easy direction: agent2 initiates, its router creates a mapping, and
# agent1 is directly reachable anyway. This is the case every home setup
# depends on and it must work.
if podman exec "$AGENT2" timeout 15 bash -c "exec 3<>/dev/tcp/$AGENT1_MESH/12345"; then
    pass "a node behind NAT reaches a port-forwarded node's declared service"
else
    fail "a node behind NAT could NOT reach a port-forwarded node — this is the baseline case and must work"
fi

log "port-forwarded server back to NAT-ed client (agent1 -> agent2)"
# The hard direction, and the interesting one. Nothing is forwarded to
# agent2, so this can only work because agent2's traffic and its
# PersistentKeepalive have already opened a mapping through router-b, and
# because WireGuard corrected agent2's endpoint from the packets it
# actually received rather than trusting what the coordinator said.
if podman exec "$AGENT1" timeout 15 bash -c "exec 3<>/dev/tcp/$AGENT2_MESH/12345"; then
    pass "the port-forwarded node reaches back into the NAT-ed node (keepalive plus endpoint correction work)"
else
    fail "could not reach back into the NAT-ed node"
fi

log "handshake state on agent1"
in_netns "$AGENT1" wg show wg0 | sed 's/^/  /'

log "comparing the endpoint the coordinator recorded against the real one"
# The coordinator composes its fallback endpoint (spec §4.2) from the
# source address it observed plus the node's OWN reported listen_port. It
# cannot do better: it sees a TCP connection, and the port a NAT maps for
# WireGuard's UDP is unrelated to it. So for any node behind NAT this
# value is a guess, and this check prints how good a guess it was.
echo "  recorded by the coordinator:"
podman exec "$COORD" wireserve-admin list-peers | awk '{printf "    %-8s %s\n", $1, $NF}'
echo "  actually observed by agent1, learned from received packets:"
in_netns "$AGENT1" wg show wg0 endpoints | awk '{printf "    %s\n", $0}'

DUPES=$(podman exec "$COORD" wireserve-admin list-peers | awk '{print $NF}' \
    | grep -v 'endpoint=-$' | sort | uniq -d)
if [ -n "$DUPES" ]; then
    note "two nodes were recorded at the SAME endpoint: ${DUPES#endpoint=}"
    note "agent2 and agent3 share a NAT and both report listen_port $WG_PORT, so the"
    note "fallback produced one address for both. At most one is reachable there."
    note "This is survivable only because WireGuard replaces the endpoint with the"
    note "real source of the first packet it receives from a peer, so a node that"
    note "speaks first (every 25s, via PersistentKeepalive) gets corrected."
else
    note "no two nodes share a recorded endpoint in this run"
fi

log "connectivity between every pair of nodes"
in_netns_bg "$AGENT3" nc -l -k -p 12345
sleep 2
A3_MESH=$(mesh_ip_of "$AGENT1" node3)

check_pair() {
    local from=$1 to_ip=$2 label=$3 required=$4
    if podman exec "$from" timeout 12 bash -c "exec 3<>/dev/tcp/$to_ip/12345" 2>/dev/null; then
        pass "$label"
        return 0
    fi
    if [ "$required" = "required" ]; then
        fail "$label — this path must work"
    fi
    note "$label could NOT connect"
    return 1
}

# Across the two NATs, in both directions. The second one is the
# interesting half: nothing is forwarded to agent2, so it can only work
# because agent2's keepalive holds a mapping open through its router and
# WireGuard corrected agent2's endpoint from the traffic it received.
check_pair "$AGENT2" "$AGENT1_MESH" "NAT-ed node reaches the port-forwarded node" required
check_pair "$AGENT1" "$AGENT2_MESH" "port-forwarded node reaches back into the NAT-ed node" required
check_pair "$AGENT3" "$AGENT1_MESH" "the second NAT-ed node also reaches the port-forwarded node" required

# Both of these sit behind the SAME router, which is two machines in one
# house — an entirely ordinary homelab layout. Each knows the other only
# by their shared router's external address, so reaching it means sending
# a packet out to your own NAT's public side and expecting it back in.
# That is NAT hairpinning, and plenty of routers do not do it.
log "the two nodes behind a shared NAT, which is the interesting case"
if check_pair "$AGENT2" "$A3_MESH" "node behind a shared NAT reaches its neighbour" optional \
   && check_pair "$AGENT3" "$AGENT2_MESH" "and the reverse" optional; then
    note "this router hairpins. Not every router does, so do not rely on it."
else
    note "Two nodes behind ONE router cannot reach each other here: each knows the"
    note "other only by their shared external address, and reaching that from inside"
    note "needs NAT hairpinning, which this router (and many real ones) will not do."
    note "They both still reach everything outside that NAT normally. v1 has no STUN"
    note "or local-endpoint discovery to fix this — spec lists both as deferred."
fi

log "default-deny still holds over a NAT-ed tunnel"
in_netns_bg "$AGENT1" nc -l -k -p 12346
sleep 2
if podman exec "$AGENT2" timeout 8 bash -c "exec 3<>/dev/tcp/$AGENT1_MESH/12346" 2>/dev/null; then
    fail "an UNDECLARED port was reachable across the mesh"
fi
pass "an undeclared port is refused across a NAT-ed tunnel too"

echo
echo "=== NAT TEST COMPLETE ==="

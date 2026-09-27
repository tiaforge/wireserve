#!/usr/bin/env bash
# WireServe opt-in transit test (NAT-traversal step 3, PLAN.md M23).
#
# run-nat-test.sh proves ordinary NAT traversal — a port-forwarded node and
# a NAT-ed node reaching each other, two nodes behind a shared NAT using
# the LAN path, a node behind symmetric NAT reached via its reflexive
# address. This script proves the case none of that covers: two nodes each
# behind their OWN symmetric NAT, with no shared LAN and nothing forwarded
# to either. Reflexive discovery cannot help them reach each other — a
# symmetric NAT maps a different external port per *destination*, so the
# port either one learns talking to the coordinator is useless to the
# other — and today that pair simply has no path. A third node that
# already reaches both, opted in as transit, routes between them through
# WireGuard's own AllowedIPs — a real decrypt/re-encrypt at the kernel
# layer, never a new relay protocol.
#
#     [coordinator]──────────────( inet )──────────────────────┐
#          │                        │                │          │
#          │                  [router-a]        [router-b]  [router-c]
#          │                  DNAT 51820      masquerade   masquerade
#          │                        │            random       random
#          │                  ( site-a )       ( site-b )  ( site-c )
#          │                        │                │          │
#          │                  [agent1]          [agent2]   [agent4]
#          │              (only node with `transit on`)
#
# agent1 is reachable directly (port-forwarded), same as run-nat-test.sh's
# agent1, and is the only node opted in as transit. agent2 and agent4 each
# sit behind their own genuinely symmetric NAT (router-b/router-c reuse
# M22's own already-proven `masquerade random` setup) with no shared LAN
# and no shared predictability between them — the one pairing this
# project's existing NAT traversal (LAN hairpin, reflexive discovery)
# cannot solve.
#
# Everything runs in rootful Podman, same reasoning as run-nat-test.sh
# (service-address rewrites and the interface-scoped forwarding sysctl
# both need the host's own user namespace).
#
# Usage: sudo ./deploy/e2e/run-transit-test.sh
# Exit code 0 = every check passed.

set -euo pipefail
cd "$(dirname "$0")/../.."

INET=wireserve-transit-inet
SITE_A=wireserve-transit-site-a
SITE_B=wireserve-transit-site-b
SITE_C=wireserve-transit-site-c
COORD=wireserve-transit-coord
ROUTER_A=wireserve-transit-router-a
ROUTER_B=wireserve-transit-router-b
ROUTER_C=wireserve-transit-router-c
AGENT1=wireserve-transit-agent1
AGENT2=wireserve-transit-agent2
AGENT4=wireserve-transit-agent4
DEBUG_IMG=wireserve-e2e-debug-tools
ADMIN_TOKEN=transit-test-admin-token
WG_PORT=51820

log()  { echo; echo "=== $* ==="; }
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
note() { echo "NOTE: $*"; }

cleanup() {
    podman rm -f "$COORD" "$ROUTER_A" "$ROUTER_B" "$ROUTER_C" "$AGENT1" "$AGENT2" "$AGENT4" \
        >/dev/null 2>&1 || true
    for c in $(podman ps -aq --filter "name=wireserve-transit-helper" 2>/dev/null); do
        podman rm -f "$c" >/dev/null 2>&1 || true
    done
    podman network rm "$SITE_A" "$SITE_B" "$SITE_C" "$INET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

in_netns() {
    local target=$1; shift
    podman run --rm --name "wireserve-transit-helper-$$-$RANDOM" \
        --network "container:$target" --cap-add=NET_ADMIN "$DEBUG_IMG" "$@"
}
in_netns_bg() {
    local target=$1; shift
    podman run -d --name "wireserve-transit-helper-$$-$RANDOM" \
        --network "container:$target" --cap-add=NET_ADMIN "$DEBUG_IMG" "$@" >/dev/null
}

ip_on() {
    podman inspect "$1" --format "{{(index .NetworkSettings.Networks \"$2\").IPAddress}}"
}

log "checking prerequisites"
command -v podman >/dev/null || fail "podman not found on PATH"
command -v python3 >/dev/null || fail "python3 not found on PATH"
modinfo wireguard >/dev/null 2>&1 || fail "WireGuard kernel module not available"
[ "$(podman info --format '{{.Host.Security.Rootless}}')" = false ] \
    || fail "needs rootful podman (the kernel refuses service-address rewrites, and the transit forwarding sysctl, in a user namespace): sudo $0"
pass "podman, python3 and the WireGuard kernel module are present"

log "building images"
podman build -q -f deploy/docker/coordinator.Dockerfile -t wireserve-coordinator:transit-test . >/dev/null
podman build -q -f deploy/docker/agent.Dockerfile -t wireserve-agent:transit-test . >/dev/null
podman build -q -f deploy/e2e/debug-tools.Dockerfile -t "$DEBUG_IMG" deploy/e2e >/dev/null
pass "images built"

log "creating the four network segments"
# All --internal — see run-nat-test.sh's own note on why: it keeps our
# router containers as the only thing performing NAT, which is the entire
# point of the topology.
podman network create --internal "$INET" >/dev/null
podman network create --internal "$SITE_A" >/dev/null
podman network create --internal "$SITE_B" >/dev/null
podman network create --internal "$SITE_C" >/dev/null
pass "four internal segments, so the only NAT is the one our routers do"

log "starting the coordinator on the inet segment"
podman run -d --name "$COORD" --network "$INET" \
    -e WIRESERVE_ADMIN_TOKEN="$ADMIN_TOKEN" \
    wireserve-coordinator:transit-test >/dev/null
sleep 2
COORD_IP=$(ip_on "$COORD" "$INET")
echo "coordinator: $COORD_IP"

start_router() {
    local name=$1 site=$2
    podman run -d --name "$name" --network "$INET" --network "$site" \
        --cap-add=NET_ADMIN --sysctl net.ipv4.ip_forward=1 \
        "$DEBUG_IMG" sleep infinity >/dev/null
    sleep 1
    podman exec "$name" nft add table ip nat
    podman exec "$name" nft 'add chain ip nat postrouting { type nat hook postrouting priority 100 ; }'
    podman exec "$name" nft 'add chain ip nat prerouting { type nat hook prerouting priority -100 ; }'
    podman exec "$name" nft 'add rule ip nat postrouting oifname "eth0" masquerade'
}

log "starting the three NAT routers"
start_router "$ROUTER_A" "$SITE_A"
start_router "$ROUTER_B" "$SITE_B"
start_router "$ROUTER_C" "$SITE_C"
# router-b and router-c both get a genuine per-destination port remapping
# (M22's own already-proven regression setup) — real symmetric NAT on
# BOTH sides of the pair this test is about, with no shared predictability
# between them, so neither the naive WAN guess nor reflexive discovery can
# ever produce a working direct path. router-a is untouched: agent1 has a
# real port-forward and is reachable directly, same as run-nat-test.sh.
for r in "$ROUTER_B" "$ROUTER_C"; do
    podman exec "$r" nft flush chain ip nat postrouting
    podman exec "$r" nft 'add rule ip nat postrouting oifname "eth0" masquerade random'
done
ROUTER_A_WAN=$(ip_on "$ROUTER_A" "$INET")
ROUTER_A_LAN=$(ip_on "$ROUTER_A" "$SITE_A")
ROUTER_B_LAN=$(ip_on "$ROUTER_B" "$SITE_B")
ROUTER_C_LAN=$(ip_on "$ROUTER_C" "$SITE_C")
echo "router-a  wan=$ROUTER_A_WAN  lan=$ROUTER_A_LAN"
echo "router-b  lan=$ROUTER_B_LAN (random masquerade)"
echo "router-c  lan=$ROUTER_C_LAN (random masquerade)"
pass "router-b and router-c both do genuine per-destination NAT"

start_agent() {
    local name=$1 site=$2 gateway=$3
    podman run -d --name "$name" --network "$site" \
        --cap-add=NET_ADMIN --security-opt unmask=/proc/sys --device /dev/net/tun \
        --entrypoint sleep wireserve-agent:transit-test infinity >/dev/null
    sleep 1
    in_netns "$name" ip route replace default via "$gateway" >/dev/null
}

log "starting the three agents"
start_agent "$AGENT1" "$SITE_A" "$ROUTER_A_LAN"
start_agent "$AGENT2" "$SITE_B" "$ROUTER_B_LAN"
start_agent "$AGENT4" "$SITE_C" "$ROUTER_C_LAN"
AGENT1_LAN=$(ip_on "$AGENT1" "$SITE_A")
AGENT2_LAN=$(ip_on "$AGENT2" "$SITE_B")
AGENT4_LAN=$(ip_on "$AGENT4" "$SITE_C")
echo "agent1 (site-a, port-forwarded, will be the transit carrier): $AGENT1_LAN"
echo "agent2 (site-b, symmetric NAT):                              $AGENT2_LAN"
echo "agent4 (site-c, symmetric NAT):                              $AGENT4_LAN"

log "port-forwarding UDP/$WG_PORT on router-a to agent1"
podman exec "$ROUTER_A" nft \
    "add rule ip nat prerouting iifname \"eth0\" udp dport $WG_PORT dnat to $AGENT1_LAN:$WG_PORT"

create_node() {
    podman exec "$COORD" wireserve-admin create-node "$1" | grep -oE 'jtk_[a-f0-9]+'
}

log "joining the three nodes"
JT1=$(create_node node1)
JT2=$(create_node node2)
JT4=$(create_node node4)
podman exec "$AGENT1" wireserve join "http://$COORD_IP:47820" --allow-plaintext-http "$JT1" \
    --listen-port "$WG_PORT" --endpoint-addr "$ROUTER_A_WAN:$WG_PORT" 2>/dev/null
podman exec "$AGENT2" wireserve join "http://$COORD_IP:47820" --allow-plaintext-http "$JT2" --listen-port "$WG_PORT" 2>/dev/null
podman exec "$AGENT4" wireserve join "http://$COORD_IP:47820" --allow-plaintext-http "$JT4" --listen-port "$WG_PORT" 2>/dev/null
pass "all three nodes registered"

for a in "$AGENT1" "$AGENT2" "$AGENT4"; do
    podman exec -d "$a" wireserve daemon --poll-interval-secs 5
done
log "waiting for poll cycles and WireGuard handshakes (transit still off everywhere)"
sleep 20

# Baselines for the interface-scoped-forwarding check further down. NOT
# assumed to be "0": a fresh network namespace inherits its own starting
# `conf.all.forwarding` (and so every interface's own initial value) from
# whatever the HOST namespace already has at container-creation time —
# and Podman/netavark itself turns the host's own ip_forward on as a
# normal, expected part of setting up bridge networking, which this very
# script's own network segments already trigger. So the meaningful
# assertion is never "reads 0", only "stays exactly what it started at
# once our own code has run" — captured here, before anyone opts in.
AGENT1_ALL_BASELINE=$(in_netns "$AGENT1" cat /proc/sys/net/ipv4/conf/all/forwarding 2>/dev/null || echo "?")
AGENT2_WG_BASELINE=$(in_netns "$AGENT2" cat /proc/sys/net/ipv4/conf/wireserve0/forwarding 2>/dev/null || echo "?")
AGENT4_WG_BASELINE=$(in_netns "$AGENT4" cat /proc/sys/net/ipv4/conf/wireserve0/forwarding 2>/dev/null || echo "?")

log "declaring a service on agent2 and agent4"
podman exec "$AGENT2" wireserve serve svc-two 12345
podman exec "$AGENT4" wireserve serve svc-four 12345
sleep 8
podman exec "$COORD" wireserve-admin approve-service node2 svc-two || fail "could not approve svc-two"
podman exec "$COORD" wireserve-admin approve-service node4 svc-four || fail "could not approve svc-four"
sleep 12

svc_addr() { podman exec "$1" getent hosts "$2" | awk '{print $1}'; }
SVC2=$(svc_addr "$AGENT4" svc-two.wg)
SVC4=$(svc_addr "$AGENT2" svc-four.wg)
[ -n "$SVC2" ] && [ -n "$SVC4" ] || fail "a service name does not resolve (svc-two=$SVC2 svc-four=$SVC4)"
echo "svc-two.wg=$SVC2 svc-four.wg=$SVC4"

log "confirming agent2 and agent4 provably cannot reach each other directly"
# The baseline this whole feature exists to fix: two independent symmetric
# NATs, no shared LAN, nothing forwarded to either. Every existing tier
# (LAN, reflexive, plain WAN) must fail here — if this ever starts
# passing, the test topology has stopped exercising the case transit is
# for.
in_netns_bg "$AGENT2" nc -l -k -p 12345
in_netns_bg "$AGENT4" nc -l -k -p 12345
sleep 2
if podman exec "$AGENT4" timeout 10 bash -c "exec 3<>/dev/tcp/$SVC2/12345" 2>/dev/null; then
    fail "agent4 reached agent2 directly — the topology is not exercising two independent symmetric NATs"
fi
if podman exec "$AGENT2" timeout 10 bash -c "exec 3<>/dev/tcp/$SVC4/12345" 2>/dev/null; then
    fail "agent2 reached agent4 directly — the topology is not exercising two independent symmetric NATs"
fi
pass "agent2 and agent4 cannot reach each other directly — this is the case transit exists for"

log "opting agent1 in as transit"
podman exec "$AGENT1" wireserve transit on
log "approving node1 as a carrier (the node's own opt-in is not enough on its own)"
podman exec "$COORD" wireserve-admin approve-transit node1 || fail "could not approve node1 for transit"
log "waiting for transit selection to propagate (up to one poll interval each side)"
sleep 20

log "confirming the coordinator names agent1 as transit_via for this pair"
NODE2_TRANSIT_VIA=$(podman exec "$AGENT4" wireserve list --json \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print(next((p.get('transit_via') or '' for p in d['peers'] if p.get('name')=='node2'), ''))")
[ -n "$NODE2_TRANSIT_VIA" ] || fail "agent4's poll response never got a transit_via for node2"
pass "agent4 was told to route to node2 via a transit carrier"

log "confirming a real service connection now succeeds end to end through agent1"
if podman exec "$AGENT4" timeout 20 bash -c "exec 3<>/dev/tcp/$SVC2/12345"; then
    pass "agent4 reaches agent2's declared service, routed through agent1"
else
    fail "agent4 still cannot reach agent2's service after transit came up"
fi
if podman exec "$AGENT2" timeout 20 bash -c "exec 3<>/dev/tcp/$SVC4/12345"; then
    pass "agent2 reaches agent4's declared service, routed through agent1"
else
    fail "agent2 still cannot reach agent4's service after transit came up"
fi

log "confirming agent2 has no kernel peer entry for agent4 at all"
AGENT4_PUBKEY=$(podman exec "$AGENT4" wireserve list --json \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print(next((p.get('pubkey') for p in d['peers'] if p.get('name')=='node4'), ''))")
AGENT2_PUBKEY=$(podman exec "$AGENT2" wireserve list --json \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print(next((p.get('pubkey') for p in d['peers'] if p.get('name')=='node2'), ''))")
if in_netns "$AGENT2" wg show wireserve0 allowed-ips | grep -q "$AGENT4_PUBKEY"; then
    fail "agent2 has its own kernel peer entry for agent4 — AllowedIPs redirection did not take effect"
fi
pass "agent2 has no kernel peer entry for agent4 — routed entirely via agent1's entry"
if in_netns "$AGENT2" wg show wireserve0 allowed-ips | grep -F "$SVC4" >/dev/null 2>&1; then
    note "agent2's peer table (for reference):"
    in_netns "$AGENT2" wg show wireserve0 allowed-ips | sed 's/^/  /'
fi

log "confirming default-deny still holds for anything outside the declared pair"
in_netns_bg "$AGENT4" nc -l -k -p 12346
sleep 2
if podman exec "$AGENT2" timeout 8 bash -c "exec 3<>/dev/tcp/$SVC4/12346" 2>/dev/null; then
    fail "an UNDECLARED port on agent4 was reachable through the transit path"
fi
pass "an undeclared port stays refused even when the pair is routed through transit"

log "confirming interface-scoped forwarding, not the host's global switch"
AGENT1_WG_FWD=$(in_netns "$AGENT1" cat /proc/sys/net/ipv4/conf/wireserve0/forwarding 2>/dev/null || echo "?")
AGENT1_ALL_FWD=$(in_netns "$AGENT1" cat /proc/sys/net/ipv4/conf/all/forwarding 2>/dev/null || echo "?")
[ "$AGENT1_WG_FWD" = "1" ] || fail "agent1's wireserve0 forwarding flag is not 1 (got '$AGENT1_WG_FWD') — transit traffic would be dropped at the kernel level"
[ "$AGENT1_ALL_FWD" = "$AGENT1_ALL_BASELINE" ] \
    || fail "agent1's GLOBAL forwarding switch changed (baseline '$AGENT1_ALL_BASELINE', now '$AGENT1_ALL_FWD') — this is exactly the open-router regression the interface-scoped design exists to avoid"
pass "agent1 forwards on its wg interface alone; the host-wide switch was never touched (baseline '$AGENT1_ALL_BASELINE', unchanged)"
# IPv6 (PLAN.md M27 phase 0): per-interface `forwarding` never forwarded
# IPv6; `force_forwarding` (Linux 6.17) does, and only where the kernel has it.
if in_netns "$AGENT1" test -e /proc/sys/net/ipv6/conf/wireserve0/force_forwarding; then
    AGENT1_WG_FWD6=$(in_netns "$AGENT1" cat /proc/sys/net/ipv6/conf/wireserve0/force_forwarding)
    [ "$AGENT1_WG_FWD6" = "1" ] || fail "agent1's wireserve0 force_forwarding is not 1 (got '$AGENT1_WG_FWD6') — IPv6 transit would be dropped"
    pass "agent1 forwards IPv6 on its wg interface alone (force_forwarding)"
else
    note "this kernel has no force_forwarding; IPv6 transit is expected to be IPv4-only here"
fi
for entry in "$AGENT2:$AGENT2_WG_BASELINE" "$AGENT4:$AGENT4_WG_BASELINE"; do
    a=${entry%%:*}
    baseline=${entry#*:}
    FWD=$(in_netns "$a" cat /proc/sys/net/ipv4/conf/wireserve0/forwarding 2>/dev/null || echo "?")
    [ "$FWD" = "$baseline" ] || fail "$a never opted in as transit, but its forwarding flag moved from '$baseline' to '$FWD' — should be untouched"
done
pass "the two nodes that never opted in have their forwarding posture completely untouched"

log "toggling transit off on agent1 mid-run"
podman exec "$AGENT1" wireserve transit off
sleep 20
in_netns_bg "$AGENT2" nc -l -k -p 12345
in_netns_bg "$AGENT4" nc -l -k -p 12345
sleep 2
if podman exec "$AGENT4" timeout 10 bash -c "exec 3<>/dev/tcp/$SVC2/12345" 2>/dev/null; then
    fail "agent4 could still reach agent2 after transit was turned off — the pair should have unwound back to (broken) direct-dial"
fi
pass "turning transit off unwinds both sides back to the ordinary (broken) direct-dial state within one poll interval"

echo
echo "=== TRANSIT TEST COMPLETE ==="

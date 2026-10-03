#!/usr/bin/env bash
# wireserve end-to-end test: builds the real container images and
# exercises a genuine two-node mesh — real kernel WireGuard interfaces,
# real nftables rules, real HTTP against a live coordinator — inside
# Podman containers. This is not a mock: it is the exact test that found
# and confirmed the fixes for several real bugs during this project's own
# development (see PLAN.md's decisions log), and it exists so that
# history doesn't have to repeat itself by hand in a future session.
#
# Prerequisites:
#   - ROOTFUL podman (`sudo`). Rootless used to be enough — rootless
#     containers get CAP_NET_ADMIN over their own network namespace, which
#     covers WireGuard and nftables — but service addresses (PLAN.md M20)
#     rewrite packet headers, and since the "netfilter: disable payload
#     mangling in userns" hardening the kernel refuses that in any network
#     namespace a non-init user namespace owns, which is every rootless
#     container. See run-service-vip-spike.sh.
#   - the WireGuard kernel module available on the host (`modinfo
#     wireguard` must succeed) — defguard_wireguard_rs's Kernel backend
#     needs it; there is no userspace fallback wired up in this project
#   - outbound internet access at BUILD time (to fetch crates and apt
#     packages) — the containers do NOT need internet access at runtime,
#     and in fact this script's own custom bridge network does not
#     reliably provide it (see the note in coordinator.Dockerfile/
#     agent.Dockerfile about DNS inside a custom Podman network)
#
# Usage: sudo ./deploy/e2e/run-e2e-test.sh
# Exit code 0 = every check passed. `set -e` aborts immediately on the
# first failing command, with that command visible in the output.

set -euo pipefail
cd "$(dirname "$0")/../.."   # repo root
. deploy/e2e/lib.sh

NET=wireserve-e2e-test
ADMIN_TOKEN=e2e-test-admin-token
COORD=wireserve-coord-e2e-test
AGENT1=wireserve-agent1-e2e-test
AGENT2=wireserve-agent2-e2e-test
DEBUG_CONTAINER=wireserve-debug-e2e-test
DEBUG_IMG=wireserve-e2e-debug-tools

log() { echo; echo "=== $* ==="; }
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

cleanup() {
    log "cleaning up containers and network"
    podman rm -fv -t 0 "$COORD" "$AGENT1" "$AGENT2" "$DEBUG_CONTAINER" \
        wireserve-guard-e2e-test >/dev/null 2>&1 || true
    podman network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Also up front, not only on exit: a previous run that was killed rather
# than allowed to finish (Ctrl-C, a timeout, a crashed shell) leaves its
# containers behind, and `podman run` then fails on the name collision
# instead of doing anything useful.
cleanup

log "checking prerequisites"
command -v podman >/dev/null || fail "podman not found on PATH"
command -v python3 >/dev/null || fail "python3 not found on PATH (used to parse \`wireserve status\`)"
modinfo wireguard >/dev/null 2>&1 || fail "WireGuard kernel module not available (modinfo wireguard failed)"
[ "$(podman info --format '{{.Host.Security.Rootless}}')" = false ] \
    || fail "needs rootful podman (the kernel refuses service-address rewrites in user namespaces): sudo $0"
pass "podman and the WireGuard kernel module are present"

log "building images"
./deploy/e2e/build.sh

log "starting coordinator"
podman network create "$NET" >/dev/null 2>&1 || true
podman run -d --name "$COORD" --network "$NET" \
    -e WIRESERVE_ADMIN_TOKEN="$ADMIN_TOKEN" \
    wireserve-coordinator:e2e >/dev/null
sleep 1
COORD_IP=$(podman inspect "$COORD" --format "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}")
echo "coordinator reachable at $COORD_IP"

create_node() {
    podman exec "$COORD" wireserve-admin node create "$1" | grep -oE 'jtk_[a-f0-9]+'
}

log "creating and joining two nodes"
JT1=$(create_node node1)
JT2=$(create_node node2)

start_agent() {
    local name=$1 token=$2
    podman run -d --name "$name" --network "$NET" \
        --cap-add=NET_ADMIN --device /dev/net/tun \
        --entrypoint sleep wireserve-agent:e2e infinity >/dev/null
    podman exec "$name" wireserve join "http://$COORD_IP:47820" --allow-plaintext-http "$token" --listen-port 51820
    podman exec -d "$name" wireserve daemon --poll-interval-secs "$POLL"
}
start_agent "$AGENT1" "$JT1"
start_agent "$AGENT2" "$JT2"

log "waiting for both agents to see each other"
sees() { podman exec "$1" wireserve status --json | grep -q "\"name\": \"$2\""; }
wait_for 30 sees "$AGENT1" node2 || fail "agent1 never got node2 into its peers"
wait_for 30 sees "$AGENT2" node1 || fail "agent2 never got node1 into its peers"

log "checking both agents have a real wireserve0 interface"
for agent in "$AGENT1" "$AGENT2"; do
    podman exec "$agent" test -d /sys/class/net/wireserve0 || fail "$agent has no wireserve0 interface"
done
pass "both agents created a real kernel WireGuard interface"

log "checking agent1's wireserve0 has a configured peer"
podman run -d --name "$DEBUG_CONTAINER" --network "container:$AGENT1" \
    --cap-add=NET_ADMIN "$DEBUG_IMG" >/dev/null
sleep 1
PEER_COUNT=$(podman exec "$DEBUG_CONTAINER" wg show wireserve0 peers | grep -c . || true)
[ "$PEER_COUNT" -ge 1 ] || fail "agent1's wireserve0 has no configured peers"
pass "agent1's wireserve0 has $PEER_COUNT configured peer(s)"

# The single most important check in this script: everything above only
# proves that control-plane state was written somewhere. This proves the
# mesh actually carries a packet. Its absence is exactly how a missing
# routing step survived several review rounds — `wg show` listed the peer,
# /etc/hosts had the name, `wireserve status` looked right, and not one byte
# could travel between the two nodes, because WireGuard's AllowedIPs is a
# crypto-routing table and does not put anything in the kernel's.

# Reads a peer's mesh IPv4 out of `wireserve status`. Parsed as JSON
# rather than grepped: field order is not something a test should depend
# on, and the mesh range is configurable, so matching on a literal prefix
# would silently stop finding anything the moment someone changes it.
mesh_ip_of() {
    local from=$1 peer=$2
    podman exec "$from" wireserve status --json | python3 -c "
import json, sys
peers = json.load(sys.stdin).get('peers', [])
match = [p['ip4'] for p in peers if p.get('name') == '$peer']
print(match[0] if match else '')
"
}

log "checking the mesh actually passes traffic (agent1 -> agent2 over wireserve0)"
AGENT2_MESH_IP=$(mesh_ip_of "$AGENT2" node2)
[ -n "$AGENT2_MESH_IP" ] || fail "could not determine agent2's mesh address"
echo "agent2 mesh address: $AGENT2_MESH_IP"
podman exec "$DEBUG_CONTAINER" ip route get "$AGENT2_MESH_IP" \
    || fail "no route to agent2's mesh address from agent1 — peer routes were never installed"
podman exec "$DEBUG_CONTAINER" ip route get "$AGENT2_MESH_IP" | grep -q "dev wireserve0" \
    || fail "route to agent2's mesh address does not go via wireserve0"
pass "agent1 has a kernel route to agent2 via wireserve0"

podman exec "$DEBUG_CONTAINER" ping -c2 -W3 "$AGENT2_MESH_IP" >/dev/null 2>&1 \
    && echo "NOTE: agent2 answers ICMP on the mesh" \
    || echo "NOTE: agent2 does not answer ICMP on the mesh, which is expected —" \
            "default-deny on wireserve0 drops inbound echo requests (they are neither" \
            "ESTABLISHED/RELATED nor a declared service port)."

log "declaring services on agent1 — they must NOT propagate before approval"
# Each service gets its own address (PLAN.md M20), so two of them can both
# answer on :80 of one node: testsvc maps 80 onto the listener on 12345,
# web2 maps 80 onto 12347, udpsvc maps UDP 53 onto 5353.
podman exec "$AGENT1" wireserve testsvc 80:12345
podman exec "$AGENT1" wireserve web2 80:12347
podman exec "$AGENT1" wireserve udpsvc 53:5353/udp
# Once agent1 shows them pending the coordinator has them; then give
# agent2 a few polls in which they could (wrongly) arrive.
pending() { podman exec "$AGENT1" wireserve status --json | grep -q '"pending": true'; }
wait_for 20 pending || true
settle
# Service approval is on by default: a declaration is stored but withheld
# from every other node's directory until an admin approves it, so that
# one compromised node cannot claim an unclaimed name and have every
# other node's /etc/hosts point at it. Check the gate actually holds
# against a real mesh before approving, or the approval step below would
# prove nothing.
if podman exec "$AGENT2" grep -q "testsvc.wg" /etc/hosts; then
    fail "testsvc.wg reached agent2 WITHOUT approval — the approval gate is not holding"
fi
pass "an unapproved service is withheld from the mesh directory"

podman exec "$AGENT1" wireserve status --json | grep -q '"pending": true' \
    || fail "the declaring node does not show its own service as pending"
pass "the declaring node reports its service as pending approval"

log "approving the services and checking hosts-file sync on agent2"
for svc in testsvc web2 udpsvc; do
    podman exec "$COORD" wireserve-admin service approve "$svc" --node node1 \
        || fail "could not approve $svc for node1"
done
for svc in testsvc web2 udpsvc; do
    wait_for 20 podman exec "$AGENT2" grep -q "$svc.wg" /etc/hosts \
        || fail "agent2's /etc/hosts never picked up $svc.wg after approval"
done
# ...and agent1 has learnt they are approved, and opened them.
wait_for 20 eval '! pending' \
    || fail "agent1 still shows its services pending after approval"
pass "agent2's /etc/hosts synced testsvc.wg once approved"

AGENT1_MESH_IP=$(mesh_ip_of "$AGENT1" node1)
[ -n "$AGENT1_MESH_IP" ] || fail "could not determine agent1's mesh address"
resolve() { podman exec "$AGENT2" getent hosts "$1" | awk '{print $1}'; }
VIP=$(resolve testsvc.wg)
VIP2=$(resolve web2.wg)
UVIP=$(resolve udpsvc.wg)
echo "agent1 mesh address: $AGENT1_MESH_IP; testsvc.wg=$VIP web2.wg=$VIP2 udpsvc.wg=$UVIP"
for v in "$VIP" "$VIP2" "$UVIP"; do
    [ -n "$v" ] && [ "$v" != "$AGENT1_MESH_IP" ] \
        || fail "a service name does not resolve to its own address (got '$v')"
done
[ "$(printf '%s\n' "$VIP" "$VIP2" "$UVIP" | sort -u | wc -l)" = 3 ] \
    || fail "two services share an address"
pass "every service name resolves to an address of its own"

log "checking the service addresses carry traffic, and nothing else does"
# The listeners run in the debug container, which shares agent1's network
# namespace, so they sit behind agent1's nftables rules. Each answers with
# the address it saw the client connect from: a service reached through
# its address must still see the real client, not the node or the VIP.
# A listener on the undeclared port too, or an unreachable result there
# would prove nothing ("refused because nothing listens" and "dropped by
# the firewall" look identical from the far end).
#
# Connections are made with `bash`, not `sh`: /dev/tcp is a bash builtin
# and the image's /bin/sh is dash, where it silently fails and would make
# every one of these checks pass regardless of the firewall.
listen() { podman exec -d "$DEBUG_CONTAINER" socat "$1" SYSTEM:"echo $2 peer=\$SOCAT_PEERADDR"; }
listen TCP-LISTEN:12345,fork,reuseaddr testsvc
listen TCP-LISTEN:12347,fork,reuseaddr web2
listen TCP-LISTEN:12346,fork,reuseaddr undeclared
listen UDP-RECVFROM:5353,fork udpsvc
sleep 1

ask() { # from proto addr port
    podman exec "$1" timeout 5 bash -c "exec 3<>/dev/$2/$3/$4 && { [ $2 = tcp ] || echo hi >&3; } && head -1 <&3" 2>/dev/null || true
}
expect() { # from proto addr port expected
    local got; got=$(ask "$1" "$2" "$3" "$4")
    [ "$got" = "$5" ] || fail "$3:$4/$2 from $1: expected '$5', got '${got:-nothing}'"
}
refused() { # from proto addr port
    local got; got=$(ask "$1" "$2" "$3" "$4")
    [ -z "$got" ] || fail "$3:$4/$2 from $1 should be closed to the mesh, got '$got'"
}

# Sanity: the undeclared listener answers inside agent1's own namespace.
[ "$(ask "$DEBUG_CONTAINER" tcp 127.0.0.1 12346)" = "undeclared peer=127.0.0.1" ] \
    || fail "the undeclared-port listener is not actually listening — the checks below would be meaningless"

expect "$AGENT2" tcp "$VIP" 80 "testsvc peer=$AGENT2_MESH_IP"
pass "testsvc.wg:80 reaches the listener on 12345, which sees agent2's real address"
expect "$AGENT2" tcp "$VIP2" 80 "web2 peer=$AGENT2_MESH_IP"
pass "a second service on the same node answers on :80 of its own address"
expect "$AGENT2" udp "$UVIP" 53 "udpsvc peer=$AGENT2_MESH_IP"
pass "udpsvc.wg:53/udp reaches 5353/udp, with the real client address"

refused "$AGENT2" tcp "$AGENT1_MESH_IP" 12345
refused "$AGENT2" tcp "$VIP" 12345
refused "$AGENT2" tcp "$VIP" 81
refused "$AGENT2" udp "$AGENT1_MESH_IP" 5353
pass "the target ports are closed to the mesh: only the published ports answer"
refused "$AGENT2" tcp "$AGENT1_MESH_IP" 12346
pass "an undeclared port is refused across the mesh (default-deny holds)"

expect "$AGENT1" tcp "$VIP" 80 "testsvc peer=$AGENT1_MESH_IP"
expect "$AGENT1" udp "$UVIP" 53 "udpsvc peer=$AGENT1_MESH_IP"
pass "the owning node reaches its own services through their addresses"

log "checking wireserve status reflects real data on agent1 (regression: F1)"
podman exec "$AGENT1" wireserve status --json | grep -q '"local": true' \
    || fail "wireserve status did not show the locally-declared service — the shared-state bug (F1) may have regressed"
pass "wireserve status shows real, current data"
podman exec "$AGENT2" wireserve status | grep -E "^testsvc\.wg +$VIP +80:12345/tcp +node1 +online +yes$" >/dev/null \
    || fail "the human-readable list does not show testsvc.wg: $(podman exec "$AGENT2" wireserve status)"
pass "the human-readable list shows the service, its address and mapping"

log "testing revoke propagation"
podman exec "$COORD" wireserve-admin node revoke node1
wait_for 20 eval '! sees "$AGENT2" node1' \
    || fail "node1 is still listed as a peer on agent2 after revoke"
pass "node1 dropped out of agent2's peer list after revoke"

log "the agent must never take over an interface it did not create"
# The library underneath is idempotent to a fault: creating an interface
# that already exists returns success, and configuring it then flushes its
# addresses, overwrites its private key and listen port, and sends
# WireGuard's ReplacePeers flag, dropping every peer on it. On a host that
# already runs another tunnel under the agent's name, starting the daemon
# used to quietly destroy it. Everything below is set up to look exactly
# like that situation: somebody else's wireserve0.
GUARD=wireserve-guard-e2e-test
podman rm -fv -t 0 "$GUARD" >/dev/null 2>&1 || true
podman run -d --name "$GUARD" --network "$NET" \
    --cap-add=NET_ADMIN --device /dev/net/tun \
    --entrypoint sleep wireserve-agent:e2e infinity >/dev/null
JT_GUARD=$(create_node node3)
podman exec "$GUARD" wireserve join "http://$COORD_IP:47820" --allow-plaintext-http "$JT_GUARD" --listen-port 51820

FOREIGN_KEY=$(podman run --rm "$DEBUG_IMG" wg genkey)
podman run --rm --network "container:$GUARD" --cap-add=NET_ADMIN "$DEBUG_IMG" sh -c "
    ip link add wireserve0 type wireguard &&
    echo '$FOREIGN_KEY' > /tmp/k && wg set wireserve0 private-key /tmp/k listen-port 51821 &&
    ip addr add 192.0.2.77/32 dev wireserve0 && ip link set wireserve0 up"
FOREIGN_PUB=$(echo "$FOREIGN_KEY" | podman run --rm -i "$DEBUG_IMG" wg pubkey)
echo "pre-existing wireserve0 public key: $FOREIGN_PUB"
foreign_intact() {
    local pub
    pub=$(podman run --rm --network "container:$GUARD" --cap-add=NET_ADMIN "$DEBUG_IMG" wg show wireserve0 public-key)
    [ "$pub" = "$FOREIGN_PUB" ] || fail "the pre-existing interface's private key was overwritten ($pub != $FOREIGN_PUB)"
    podman run --rm --network "container:$GUARD" --cap-add=NET_ADMIN "$DEBUG_IMG" ip addr show wireserve0 \
        | grep -q "192.0.2.77" || fail "the pre-existing interface's address was flushed"
}

# Told to use exactly that name, it refuses.
if podman exec "$GUARD" wireserve daemon --poll-interval-secs "$POLL" --ifname wireserve0 2>&1 | tee /tmp/guard-out.txt; then
    fail "the agent started on an interface it did not create — it should have refused"
fi
grep -qi "cannot use the interface name 'wireserve0'" /tmp/guard-out.txt \
    || fail "the agent failed, but not with the interface-conflict error: $(cat /tmp/guard-out.txt)"
foreign_intact
pass "pinned to a foreign interface's name, the agent refused and left it alone"

# Left to choose, it goes around it.
podman exec -d "$GUARD" wireserve daemon --poll-interval-secs "$POLL"
wait_for 20 podman exec "$GUARD" test -d /sys/class/net/wireserve1 \
    || fail "the agent did not come up on the next free name, wireserve1"
foreign_intact
pass "without --ifname the agent picked wireserve1 and left the foreign wireserve0 alone"
podman rm -fv -t 0 "$GUARD" >/dev/null 2>&1 || true

log "testing leave removes the managed hosts-file block (regression: F2)"
podman exec "$AGENT2" wireserve leave
sleep 1
if podman exec "$AGENT2" grep -q "BEGIN WIRESERVE" /etc/hosts; then
    fail "managed hosts-file block still present on agent2 after leave"
fi
pass "leave removed the managed hosts-file block"

echo
echo "=== ALL CHECKS PASSED ==="

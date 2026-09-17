#!/usr/bin/env bash
# WireServe end-to-end test: builds the real container images and
# exercises a genuine two-node mesh — real kernel WireGuard interfaces,
# real nftables rules, real HTTP against a live coordinator — inside
# Podman containers. This is not a mock: it is the exact test that found
# and confirmed the fixes for several real bugs during this project's own
# development (see PLAN.md's decisions log), and it exists so that
# history doesn't have to repeat itself by hand in a future session.
#
# Prerequisites:
#   - podman (rootless is fine — this script was developed and verified
#     against rootless Podman; rootless containers get CAP_NET_ADMIN
#     scoped to their own network namespace via --cap-add, which is
#     sufficient for creating a WireGuard interface inside that
#     namespace — no host-level CAP_NET_ADMIN or root needed on the
#     invoking shell)
#   - the WireGuard kernel module available on the host (`modinfo
#     wireguard` must succeed) — defguard_wireguard_rs's Kernel backend
#     needs it; there is no userspace fallback wired up in this project
#   - outbound internet access at BUILD time (to fetch crates and apt
#     packages) — the containers do NOT need internet access at runtime,
#     and in fact this script's own custom bridge network does not
#     reliably provide it (see the note in coordinator.Dockerfile/
#     agent.Dockerfile about DNS inside a custom Podman network)
#
# Usage: ./deploy/e2e/run-e2e-test.sh
# Exit code 0 = every check passed. `set -e` aborts immediately on the
# first failing command, with that command visible in the output.

set -euo pipefail
cd "$(dirname "$0")/../.."   # repo root

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
    podman rm -f "$COORD" "$AGENT1" "$AGENT2" "$DEBUG_CONTAINER" \
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
command -v python3 >/dev/null || fail "python3 not found on PATH (used to parse \`wireserve-agent list\`)"
modinfo wireguard >/dev/null 2>&1 || fail "WireGuard kernel module not available (modinfo wireguard failed)"
pass "podman and the WireGuard kernel module are present"

log "building images"
podman build -f deploy/docker/coordinator.Dockerfile -t wireserve-coordinator:e2e-test .
podman build -f deploy/docker/agent.Dockerfile -t wireserve-agent:e2e-test .
podman build -f deploy/e2e/debug-tools.Dockerfile -t "$DEBUG_IMG" deploy/e2e

log "starting coordinator"
podman network create "$NET" >/dev/null 2>&1 || true
podman run -d --name "$COORD" --network "$NET" \
    -e WIRESERVE_ADMIN_TOKEN="$ADMIN_TOKEN" \
    wireserve-coordinator:e2e-test >/dev/null
sleep 1
COORD_IP=$(podman inspect "$COORD" --format "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}")
echo "coordinator reachable at $COORD_IP"

create_node() {
    podman exec "$COORD" wireserve-admin create-node "$1" | grep -oE 'jtk_[a-f0-9]+'
}

log "creating and joining two nodes"
JT1=$(create_node node1)
JT2=$(create_node node2)

start_agent() {
    local name=$1 token=$2
    podman run -d --name "$name" --network "$NET" \
        --cap-add=NET_ADMIN --device /dev/net/tun \
        --entrypoint sleep wireserve-agent:e2e-test infinity >/dev/null
    podman exec "$name" wireserve-agent join "http://$COORD_IP:8080" "$token" --listen-port 51820
    podman exec -d "$name" wireserve-agent daemon --poll-interval-secs 5
}
start_agent "$AGENT1" "$JT1"
start_agent "$AGENT2" "$JT2"

log "waiting for the first few poll cycles"
sleep 8

log "checking both agents have a real wg0 interface"
for agent in "$AGENT1" "$AGENT2"; do
    podman exec "$agent" test -d /sys/class/net/wg0 || fail "$agent has no wg0 interface"
done
pass "both agents created a real kernel WireGuard interface"

log "checking agent1's wg0 has a configured peer"
podman run -d --name "$DEBUG_CONTAINER" --network "container:$AGENT1" \
    --cap-add=NET_ADMIN "$DEBUG_IMG" >/dev/null
sleep 1
PEER_COUNT=$(podman exec "$DEBUG_CONTAINER" wg show wg0 peers | grep -c . || true)
[ "$PEER_COUNT" -ge 1 ] || fail "agent1's wg0 has no configured peers"
pass "agent1's wg0 has $PEER_COUNT configured peer(s)"

# The single most important check in this script: everything above only
# proves that control-plane state was written somewhere. This proves the
# mesh actually carries a packet. Its absence is exactly how a missing
# routing step survived several review rounds — `wg show` listed the peer,
# /etc/hosts had the name, `wireserve list` looked right, and not one byte
# could travel between the two nodes, because WireGuard's AllowedIPs is a
# crypto-routing table and does not put anything in the kernel's.

# Reads a peer's mesh IPv4 out of `wireserve-agent list`. Parsed as JSON
# rather than grepped: field order is not something a test should depend
# on, and the mesh range is configurable, so matching on a literal prefix
# would silently stop finding anything the moment someone changes it.
mesh_ip_of() {
    local from=$1 peer=$2
    podman exec "$from" wireserve-agent list | python3 -c "
import json, sys
peers = json.load(sys.stdin).get('peers', [])
match = [p['ip4'] for p in peers if p.get('name') == '$peer']
print(match[0] if match else '')
"
}

log "checking the mesh actually passes traffic (agent1 -> agent2 over wg0)"
AGENT2_MESH_IP=$(mesh_ip_of "$AGENT2" node2)
[ -n "$AGENT2_MESH_IP" ] || fail "could not determine agent2's mesh address"
echo "agent2 mesh address: $AGENT2_MESH_IP"
podman exec "$DEBUG_CONTAINER" ip route get "$AGENT2_MESH_IP" \
    || fail "no route to agent2's mesh address from agent1 — peer routes were never installed"
podman exec "$DEBUG_CONTAINER" ip route get "$AGENT2_MESH_IP" | grep -q "dev wg0" \
    || fail "route to agent2's mesh address does not go via wg0"
pass "agent1 has a kernel route to agent2 via wg0"

podman exec "$DEBUG_CONTAINER" ping -c2 -W3 "$AGENT2_MESH_IP" >/dev/null 2>&1 \
    && echo "NOTE: agent2 answers ICMP on the mesh" \
    || echo "NOTE: agent2 does not answer ICMP on the mesh, which is expected —" \
            "default-deny on wg0 drops inbound echo requests (they are neither" \
            "ESTABLISHED/RELATED nor a declared service port)."

log "declaring a service on agent1 — it must NOT propagate before approval"
podman exec "$AGENT1" wireserve-agent serve testsvc 12345 tcp
sleep 8
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

podman exec "$AGENT1" wireserve-agent list | grep -q '"pending": true' \
    || fail "the declaring node does not show its own service as pending"
pass "the declaring node reports its service as pending approval"

log "approving the service and checking hosts-file sync on agent2"
podman exec "$COORD" wireserve-admin approve-service node1 testsvc \
    || fail "could not approve testsvc for node1"
sleep 8
podman exec "$AGENT2" grep -q "testsvc.wg" /etc/hosts \
    || fail "agent2's /etc/hosts never picked up testsvc.wg after approval"
pass "agent2's /etc/hosts synced testsvc.wg once approved"

log "checking the firewall allows the declared port and denies everything else"
# agent1 declared testsvc on tcp/12345 above. Both listeners below run in
# the debug container, which shares agent1's network namespace, so they
# listen on agent1's wg0 and are governed by agent1's nftables rules.
# Listening on BOTH ports is what makes this a real test: with nothing
# bound to the undeclared port, an unreachable result would prove nothing,
# since "refused because nothing is listening" and "dropped by the
# firewall" look identical from the far end.
#
# Connections are made with `bash`, not `sh`: /dev/tcp is a bash builtin
# and the image's /bin/sh is dash, where it silently fails and would make
# every one of these checks pass regardless of the firewall.
AGENT1_MESH_IP=$(mesh_ip_of "$AGENT1" node1)
[ -n "$AGENT1_MESH_IP" ] || fail "could not determine agent1's mesh address"
echo "agent1 mesh address: $AGENT1_MESH_IP"

podman exec -d "$DEBUG_CONTAINER" nc -l -k -p 12345
podman exec -d "$DEBUG_CONTAINER" nc -l -k -p 12346
sleep 1

# Sanity: both listeners must be reachable from INSIDE agent1's own
# namespace, or the checks below would be testing a broken listener rather
# than the firewall. Loopback is not subject to the wg0-scoped rules.
podman exec "$DEBUG_CONTAINER" timeout 5 bash -c "exec 3<>/dev/tcp/127.0.0.1/12346" \
    || fail "the undeclared-port listener is not actually listening — the firewall check below would be meaningless"

podman exec "$AGENT2" timeout 5 bash -c "exec 3<>/dev/tcp/$AGENT1_MESH_IP/12345" \
    || fail "declared service port 12345 is NOT reachable across the mesh"
pass "the declared service port is reachable across the mesh"

if podman exec "$AGENT2" timeout 5 bash -c "exec 3<>/dev/tcp/$AGENT1_MESH_IP/12346" 2>/dev/null; then
    fail "an UNDECLARED port was reachable across the mesh — default-deny is not working"
fi
pass "an undeclared port is refused across the mesh (default-deny holds)"

log "checking wireserve list reflects real data on agent1 (regression: F1)"
podman exec "$AGENT1" wireserve-agent list | grep -q '"local": true' \
    || fail "wireserve list did not show the locally-declared service — the shared-state bug (F1) may have regressed"
pass "wireserve list shows real, current data"

log "testing revoke propagation"
podman exec "$COORD" wireserve-admin revoke node1
sleep 8
if podman exec "$AGENT2" wireserve-agent list | grep -q '"name": "node1"'; then
    fail "node1 is still listed as a peer on agent2 after revoke"
fi
pass "node1 dropped out of agent2's peer list after revoke"

log "the agent must refuse to take over an interface it did not create"
# The library underneath is idempotent to a fault: creating an interface
# that already exists returns success, and configuring it then flushes its
# addresses, overwrites its private key and listen port, and sends
# WireGuard's ReplacePeers flag, dropping every peer on it. On a host that
# already runs a wg-quick tunnel called wg0 — the default name, and a very
# common way to reach a machine remotely — starting this daemon used to
# quietly destroy it. Everything below is set up to look exactly like that
# situation.
GUARD=wireserve-guard-e2e-test
podman rm -f "$GUARD" >/dev/null 2>&1 || true
podman run -d --name "$GUARD" --network "$NET" \
    --cap-add=NET_ADMIN --device /dev/net/tun \
    --entrypoint sleep wireserve-agent:e2e-test infinity >/dev/null
JT_GUARD=$(create_node node3)
podman exec "$GUARD" wireserve-agent join "http://$COORD_IP:8080" "$JT_GUARD" --listen-port 51820

# Stand up somebody else's wg0 first, with its own key and address.
FOREIGN_KEY=$(podman run --rm "$DEBUG_IMG" wg genkey)
podman run --rm --network "container:$GUARD" --cap-add=NET_ADMIN "$DEBUG_IMG" sh -c "
    ip link add wg0 type wireguard &&
    echo '$FOREIGN_KEY' > /tmp/k && wg set wg0 private-key /tmp/k listen-port 51821 &&
    ip addr add 192.0.2.77/32 dev wg0 && ip link set wg0 up"
FOREIGN_PUB=$(echo "$FOREIGN_KEY" | podman run --rm -i "$DEBUG_IMG" wg pubkey)
echo "pre-existing wg0 public key: $FOREIGN_PUB"

if podman exec "$GUARD" wireserve-agent daemon --poll-interval-secs 5 2>&1 | tee /tmp/guard-out.txt; then
    fail "the agent started on an interface it did not create — it should have refused"
fi
grep -qi "refusing to take over" /tmp/guard-out.txt \
    || fail "the agent failed, but not with the interface-conflict error: $(cat /tmp/guard-out.txt)"
pass "the agent refused to start on a pre-existing wg0"

STILL_PUB=$(podman run --rm --network "container:$GUARD" --cap-add=NET_ADMIN "$DEBUG_IMG" wg show wg0 public-key)
[ "$STILL_PUB" = "$FOREIGN_PUB" ] \
    || fail "the pre-existing interface's private key was overwritten ($STILL_PUB != $FOREIGN_PUB)"
podman run --rm --network "container:$GUARD" --cap-add=NET_ADMIN "$DEBUG_IMG" ip addr show wg0 \
    | grep -q "192.0.2.77" || fail "the pre-existing interface's address was flushed"
pass "the pre-existing interface kept its key and its address"

# And with a free name it starts normally, so the guard is not just
# refusing everything.
podman exec -d "$GUARD" wireserve-agent daemon --poll-interval-secs 5 --ifname wg1
sleep 8
podman exec "$GUARD" test -d /sys/class/net/wg1 \
    || fail "the agent did not come up on the alternative interface name"
pass "the same agent starts normally on a free interface name (--ifname wg1)"
podman rm -f "$GUARD" >/dev/null 2>&1 || true

log "testing leave removes the managed hosts-file block (regression: F2)"
podman exec "$AGENT2" wireserve-agent leave
sleep 1
if podman exec "$AGENT2" grep -q "BEGIN WIRESERVE" /etc/hosts; then
    fail "managed hosts-file block still present on agent2 after leave"
fi
pass "leave removed the managed hosts-file block"

echo
echo "=== ALL CHECKS PASSED ==="

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
    podman rm -f "$COORD" "$AGENT1" "$AGENT2" "$DEBUG_CONTAINER" >/dev/null 2>&1 || true
    podman network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

log "checking prerequisites"
command -v podman >/dev/null || fail "podman not found on PATH"
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

log "declaring a service on agent1 and checking hosts-file sync on agent2"
podman exec "$AGENT1" wireserve-agent serve testsvc 12345 tcp
sleep 8
podman exec "$AGENT2" grep -q "testsvc.wg" /etc/hosts \
    || fail "agent2's /etc/hosts never picked up testsvc.wg"
pass "agent2's /etc/hosts synced testsvc.wg from the mesh directory"

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

log "testing leave removes the managed hosts-file block (regression: F2)"
podman exec "$AGENT2" wireserve-agent leave
sleep 1
if podman exec "$AGENT2" grep -q "BEGIN WIRESERVE" /etc/hosts; then
    fail "managed hosts-file block still present on agent2 after leave"
fi
pass "leave removed the managed hosts-file block"

echo
echo "=== ALL CHECKS PASSED ==="

#!/usr/bin/env bash
# wireserve host-firewall interop end-to-end test: a real two-node mesh in
# Podman where agent1's network namespace ALSO has a host firewall of the
# kind that used to make declared services unreachable — a ufw-style
# iptables INPUT policy DROP and a native `inet filter` input chain with
# `policy drop`. Checks that the agent lets exactly its mesh interface
# through them (and nothing else), keeps doing so when they are reloaded,
# removes everything on `leave`, and touches nothing when it refuses to
# start on an interface it doesn't own.
#
# Same prerequisites as run-e2e-test.sh (ROOTFUL podman, the WireGuard
# kernel module, internet access at build time). firewalld is not covered here —
# it needs systemd and D-Bus inside the node.
#
# Usage: sudo ./deploy/e2e/run-host-firewall-test.sh

set -euo pipefail
cd "$(dirname "$0")/../.."   # repo root
. deploy/e2e/lib.sh

NET=wireserve-hostfw-test
ADMIN_TOKEN=hostfw-test-admin-token
COORD=wireserve-coord-hostfw-test
AGENT1=wireserve-agent1-hostfw-test
AGENT2=wireserve-agent2-hostfw-test
GUARD=wireserve-guard-hostfw-test
DBG1=wireserve-debug1-hostfw-test
DBG_GUARD=wireserve-debugg-hostfw-test
DEBUG_IMG=wireserve-e2e-debug-tools

log() { echo; echo "=== $* ==="; }
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

cleanup() {
    log "cleaning up containers and network"
    podman rm -fv -t 0 "$COORD" "$AGENT1" "$AGENT2" "$GUARD" "$DBG1" "$DBG_GUARD" \
        wireserve-legacy-hostfw-test wireserve-debugl-hostfw-test >/dev/null 2>&1 || true
    podman network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

log "checking prerequisites"
command -v podman >/dev/null || fail "podman not found on PATH"
command -v python3 >/dev/null || fail "python3 not found on PATH"
modinfo wireguard >/dev/null 2>&1 || fail "WireGuard kernel module not available"
[ "$(podman info --format '{{.Host.Security.Rootless}}')" = false ] \
    || fail "needs rootful podman (the kernel refuses service-address rewrites in user namespaces): sudo $0"
pass "prerequisites present"

log "building images"
./deploy/e2e/build.sh

log "starting coordinator"
podman network create "$NET" >/dev/null 2>&1 || true
podman run -d --name "$COORD" --network "$NET" \
    -e WIRESERVE_ADMIN_TOKEN="$ADMIN_TOKEN" wireserve-coordinator:e2e >/dev/null
sleep 1
COORD_IP=$(podman inspect "$COORD" --format "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}")

create_node() {
    podman exec "$COORD" wireserve-admin node create "$1" | grep -oE 'jtk_[a-f0-9]+'
}

node_container() {
    podman run -d --name "$1" --network "$NET" \
        --cap-add=NET_ADMIN --device /dev/net/tun \
        --entrypoint sleep wireserve-agent:e2e infinity >/dev/null
}

# Debug container sharing a node's network namespace: its nft/iptables
# see and change exactly that node's firewall.
debug_for() {
    podman run -d --name "$1" --network "container:$2" --cap-add=NET_ADMIN --cap-add=NET_RAW \
        "$DEBUG_IMG" >/dev/null
}

in_dbg() { podman exec "$DBG1" sh -c "$1"; }

# The kind of host firewall that used to block the mesh. The WireGuard
# port itself is allowed on eth0, as any real ufw user would have to.
HOST_FIREWALL='
set -e
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -i eth0 -p udp --dport 51820 -j ACCEPT
iptables -P INPUT DROP
nft -f - <<EOF
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
    iifname "eth0" udp dport 51820 accept
  }
}
EOF
'

# nft-native rules carrying our tag, counted from JSON (text output may or
# may not render iptables-nft's comment match, depending on nft's version;
# JSON never does, so this counts only the rules added through nft).
native_tags() {
    in_dbg "nft -j list ruleset" | python3 -c "
import json, sys
d = json.load(sys.stdin)['nftables']
print(sum(1 for o in d if 'rule' in o and str(o['rule'].get('comment', '')).startswith('wireserve:')))"
}

mesh_ip_of() {
    podman exec "$1" wireserve status --json | python3 -c "
import json, sys
m = [p['ip4'] for p in json.load(sys.stdin).get('peers', []) if p.get('name') == '$2']
print(m[0] if m else '')"
}

log "starting two nodes; agent1 behind a ufw-like iptables DROP and a native nftables DROP"
JT1=$(create_node node1)
JT2=$(create_node node2)
node_container "$AGENT1"
node_container "$AGENT2"
debug_for "$DBG1" "$AGENT1"
in_dbg "$HOST_FIREWALL"
BEFORE_IPT=$(in_dbg "iptables -S INPUT")
BEFORE_NFT=$(in_dbg "nft list table inet filter")

podman exec "$AGENT1" wireserve join "http://$COORD_IP:47820" --allow-plaintext-http "$JT1" --listen-port 51820
podman exec "$AGENT2" wireserve join "http://$COORD_IP:47820" --allow-plaintext-http "$JT2" --listen-port 51820
podman exec -d "$AGENT1" wireserve daemon --poll-interval-secs "$POLL"
podman exec -d "$AGENT2" wireserve daemon --poll-interval-secs "$POLL"
wait_for 30 eval '[ "$(in_dbg "iptables -S INPUT; nft list table inet filter" | grep -c wireserve:wireserve0\")" -ge 2 ]' || true

log "checking the host firewalls now let wireserve0 through (and only wireserve0)"
IPT=$(in_dbg "iptables -S INPUT")
echo "$IPT"
echo "$IPT" | sed -n 2p | grep -qx -- '-A INPUT -i wireserve0 -m comment --comment "wireserve:wireserve0" -j ACCEPT' \
    || fail "iptables INPUT does not start with our wireserve0 accept"
NFT=$(in_dbg "nft list table inet filter")
echo "$NFT"
[ "$(echo "$NFT" | grep -c 'wireserve:wireserve0"')" = 1 ] || fail "native input chain lacks exactly one wireserve0 accept"
echo "$NFT" | grep 'wireserve:wireserve0"' | grep -q 'iifname "wireserve0" counter' \
    || fail "native accept is not scoped to iifname wireserve0"
[ "$(native_tags)" = 1 ] \
    || fail "wireserve-tagged nft rules exist somewhere other than the one native input chain"
pass "iptables and the native input chain each have exactly one wireserve0-scoped accept"

log "declaring and approving a service on agent1"
# Published on :80 of its own address (PLAN.md M20), onto 12345: the
# rewritten packet still arrives on wireserve0, so it is the same
# interface-scoped accept in the host firewalls that has to let it in.
podman exec "$AGENT1" wireserve testsvc 80:12345
pending() { podman exec "$AGENT1" wireserve status --json | grep -q '"pending": true'; }
wait_for 20 pending || fail "agent1 never reported testsvc to the coordinator"
podman exec "$COORD" wireserve-admin service approve testsvc --node node1
wait_for 20 podman exec "$AGENT2" getent hosts testsvc.wg || true
wait_for 20 eval '! pending' || fail "agent1 never learnt testsvc was approved"
AGENT1_MESH_IP=$(mesh_ip_of "$AGENT2" node1)
[ -n "$AGENT1_MESH_IP" ] || fail "could not determine agent1's mesh address"
VIP=$(podman exec "$AGENT2" getent hosts testsvc.wg | awk '{print $1}')
[ -n "$VIP" ] || fail "testsvc.wg does not resolve on agent2"
AGENT1_BRIDGE_IP=$(podman inspect "$AGENT1" --format "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}")

podman exec -d "$DBG1" nc -l -k -p 12345
podman exec -d "$DBG1" nc -l -k -p 12346
sleep 1
podman exec "$DBG1" timeout 5 bash -c "exec 3<>/dev/tcp/127.0.0.1/12345" \
    || fail "listener on 12345 not up — checks below would be meaningless"

can_connect() { podman exec "$AGENT2" timeout 4 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; }

log "E1/E2: declared port reachable over the mesh, nothing else, nothing on eth0"
can_connect "$VIP" 80 || fail "declared service NOT reachable over the mesh through the host firewalls"
pass "declared service reachable over the mesh despite iptables DROP + native nftables DROP"
if can_connect "$AGENT1_MESH_IP" 12345; then
    fail "the service's target port is reachable straight on the node's mesh address"
fi
pass "only the published port answers; the target port itself stays closed to the mesh"
if can_connect "$AGENT1_MESH_IP" 12346; then
    fail "an undeclared port is reachable over the mesh — our default-deny is not deciding"
fi
pass "undeclared port refused over the mesh"
if can_connect "$AGENT1_BRIDGE_IP" 12345; then
    fail "the service is reachable on eth0 — the host firewall was opened beyond wireserve0"
fi
pass "the same service is still blocked on eth0 (nothing opened on another interface)"

log "E3: a native config reload is repaired within seconds"
in_dbg "nft delete table inet filter"
in_dbg "$(echo "$HOST_FIREWALL" | sed -n '/^nft -f/,/^EOF$/p')"
for _ in $(seq 1 30); do
    in_dbg "nft list table inet filter" | grep -q 'wireserve:wireserve0"' && break
    sleep 0.1
done
in_dbg "nft list table inet filter" | grep -q 'wireserve:wireserve0"' || fail "rule not restored within 3s after reload"
can_connect "$VIP" 80 || fail "service unreachable after the reload was repaired"
pass "native table reload repaired within 3s; service reachable again"

log "E3: an iptables rule removed by hand comes back within one poll"
in_dbg "iptables -D INPUT -i wireserve0 -m comment --comment wireserve:wireserve0 -j ACCEPT"
wait_for 10 eval '[ "$(in_dbg "iptables -S INPUT" | grep -c wireserve:wireserve0\")" = 1 ]' \
    || fail "iptables rule not restored"
[ "$(native_tags)" = 1 ] || fail "native rule duplicated during repair"
pass "iptables rule restored, no duplicates anywhere"

log "E4: leave removes everything we added and nothing else"
podman exec "$AGENT1" wireserve leave
sleep 2
if in_dbg "nft list ruleset; iptables -S" | grep -q 'wireserve'; then
    in_dbg "nft list ruleset; iptables -S"
    fail "wireserve rules or tables left behind after leave"
fi
[ "$(in_dbg "iptables -S INPUT")" = "$BEFORE_IPT" ] || fail "iptables INPUT differs from before the agent ran"
[ "$(in_dbg "nft list table inet filter")" = "$BEFORE_NFT" ] || fail "native table differs from before the agent ran"
pass "host firewalls are exactly as they were before the agent started"

log "E5: refusing a foreign interface touches no firewall at all"
node_container "$GUARD"
debug_for "$DBG_GUARD" "$GUARD"
podman exec "$DBG_GUARD" sh -c "$HOST_FIREWALL"
podman exec "$DBG_GUARD" sh -c "wg genkey > /tmp/k && ip link add wg0 type wireguard && \
    wg set wg0 private-key /tmp/k listen-port 51821 && ip link set wg0 up"
# Stateless (-s): rule counters change with any traffic and are not what
# is being compared here.
guard_rules() { podman exec "$DBG_GUARD" sh -c "nft -s list ruleset; iptables -S"; }
GUARD_BEFORE=$(guard_rules)
JT3=$(create_node node3)
podman exec "$GUARD" wireserve join "http://$COORD_IP:47820" --allow-plaintext-http "$JT3" --listen-port 51820
# Pinned to that name (without --ifname it would simply pick another), so
# the agent has to refuse — and must do so before any firewall change,
# since every rule it would install is keyed on the name.
if podman exec "$GUARD" wireserve daemon --poll-interval-secs "$POLL" --ifname wg0 >/tmp/hostfw-guard.txt 2>&1; then
    fail "the agent started on a foreign wg0"
fi
grep -qi "cannot use the interface name 'wg0'" /tmp/hostfw-guard.txt || fail "unexpected failure: $(cat /tmp/hostfw-guard.txt)"
GUARD_AFTER=$(guard_rules)
if [ "$GUARD_AFTER" != "$GUARD_BEFORE" ]; then
    diff <(echo "$GUARD_BEFORE") <(echo "$GUARD_AFTER") || true
    fail "the refused start still changed the firewall"
fi
pass "refused start on a foreign wg0 left every firewall untouched"

log "E6: legacy iptables (skipped if legacy iptables can't be used here)"
LEGACY=wireserve-legacy-hostfw-test
DBG_LEGACY=wireserve-debugl-hostfw-test
podman rm -fv -t 0 "$LEGACY" "$DBG_LEGACY" >/dev/null 2>&1 || true
node_container "$LEGACY"
debug_for "$DBG_LEGACY" "$LEGACY"
if podman exec "$DBG_LEGACY" sh -c "iptables-legacy -A INPUT -i lo -j ACCEPT && iptables-legacy -P INPUT DROP" 2>/dev/null \
   && podman exec "$DBG_LEGACY" grep -qx filter /proc/net/ip_tables_names; then
    JT4=$(create_node node4)
    podman exec "$LEGACY" wireserve join "http://$COORD_IP:47820" --allow-plaintext-http "$JT4" --listen-port 51820
    podman exec -d "$LEGACY" wireserve daemon --poll-interval-secs "$POLL"
    wait_for 20 eval 'podman exec "$DBG_LEGACY" iptables-legacy -S INPUT | grep -q wireserve:wireserve0\"' || true
    podman exec "$DBG_LEGACY" iptables-legacy -S INPUT | sed -n 2p \
        | grep -qx -- '-A INPUT -i wireserve0 -m comment --comment "wireserve:wireserve0" -j ACCEPT' \
        || fail "legacy iptables INPUT does not start with our wireserve0 accept"
    podman exec "$LEGACY" wireserve leave
    sleep 2
    if podman exec "$DBG_LEGACY" iptables-legacy -S INPUT | grep -q wireserve; then
        fail "legacy iptables rule left behind after leave"
    fi
    pass "legacy iptables opened for wireserve0 and cleaned up on leave"
else
    echo "SKIPPED: legacy iptables (ip_tables) not usable in this environment"
fi
podman rm -fv -t 0 "$LEGACY" "$DBG_LEGACY" >/dev/null 2>&1 || true

echo
echo "=== ALL HOST-FIREWALL CHECKS PASSED ==="

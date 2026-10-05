#!/usr/bin/env bash
# wireserve phone relay test (PLAN.md M40, M41).
#
# A phone cannot run the agent, so it joins with an exported `.conf` and an
# official WireGuard client. A node behind a NAT nothing gets through can't
# be dialled by it directly; the phone reaches that node through a carrier's
# public relay port instead, and the carrier forwards the phone's session
# with the node — end to end, WireGuard between the two — without being able
# to read it.
#
# What this proves, and what no unit or namespace test can:
#
#   1. the agents tell whether they are dialable: the carrier on a public
#      address is, the node behind NAT is not (`node list` shows it);
#   2. the export checks the carrier's relay port from outside, and with the
#      port blocked upstream of the carrier stops before creating anything,
#      naming the exact port and address to open;
#   3. once it is open, the config dials the carrier directly and the NAT-ed
#      node at the carrier's relay port, with the carry MTU, and no covering
#      mesh route to anyone;
#   4. the phone reaches the NAT-ed node's service with real TCP;
#   5. the carrier forwarded only UDP while it did — not one TCP packet, it
#      never saw inside;
#   6. the phone roams (a new source port) and reaches it again;
#   7. default-deny still holds through the relay;
#   8. `transit ports` names the port, its device, and that it is open;
#   9. a refresh keeps the phone's address.
#
#     ( inet 198.51.100.0/24 )──────────┬──────────────┬─────────────┐
#          │                            │              │             │
#     [coordinator]               [carrier agent]  [router-h]    [router-p]
#                                 (public address, masquerade    masquerade
#                                  transit on)         │             │
#                                                  ( site-h )    ( site-p )
#                                                      │             │
#                                                  [homeserver]   [phone]
#                                                (NAT, nothing   (plain wg,
#                                                  forwarded)     no agent)
#
# The inet segment uses TEST-NET-2 on purpose: a carrier needs a public
# address to be one, and every podman default is private.
#
# Rootful Podman, same reasoning as run-transit-test.sh.
#
# Usage: sudo ./deploy/e2e/run-phone-relay-test.sh
# Exit code 0 = every check passed.

set -euo pipefail
cd "$(dirname "$0")/../.."
. deploy/e2e/lib.sh

INET=wireserve-pr-inet
SITE_H=wireserve-pr-site-h
SITE_P=wireserve-pr-site-p
COORD=wireserve-pr-coord
ROUTER_H=wireserve-pr-router-h
ROUTER_P=wireserve-pr-router-p
CARRIER=wireserve-pr-carrier
HOME_AGENT=wireserve-pr-homeserver
PHONE=wireserve-pr-phone
DEBUG_IMG=wireserve-e2e-debug-tools
ADMIN_TOKEN=phone-relay-test-admin-token
WG_PORT=51820
OUT=$(mktemp -d)

log()  { echo; echo "=== $* ==="; }
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
note() { echo "NOTE: $*"; }

cleanup() {
    podman rm -fv -t 0 "$COORD" "$ROUTER_H" "$ROUTER_P" "$CARRIER" "$HOME_AGENT" "$PHONE" >/dev/null 2>&1 || true
    for c in $(podman ps -aq --filter "name=wireserve-pr-helper" 2>/dev/null); do
        podman rm -fv -t 0 "$c" >/dev/null 2>&1 || true
    done
    podman network rm "$SITE_H" "$SITE_P" "$INET" >/dev/null 2>&1 || true
    rm -rf "$OUT"
}
trap cleanup EXIT
cleanup
OUT=$(mktemp -d)

in_netns() {
    local target=$1; shift
    podman run --rm --name "wireserve-pr-helper-$$-$RANDOM" \
        --network "container:$target" --cap-add=NET_ADMIN "$DEBUG_IMG" "$@"
}
# For a command that reads a heredoc: `podman run` passes stdin on only with -i.
in_netns_stdin() {
    local target=$1; shift
    podman run --rm -i --name "wireserve-pr-helper-$$-$RANDOM" \
        --network "container:$target" --cap-add=NET_ADMIN "$DEBUG_IMG" "$@"
}
in_netns_bg() {
    local target=$1; shift
    podman run -d --name "wireserve-pr-helper-$$-$RANDOM" \
        --network "container:$target" --cap-add=NET_ADMIN "$DEBUG_IMG" "$@" >/dev/null
}
ip_on() {
    podman inspect "$1" --format "{{(index .NetworkSettings.Networks \"$2\").IPAddress}}"
}
admin() { podman exec "$COORD" wireserve-admin "$@"; }

log "checking prerequisites"
command -v podman >/dev/null || fail "podman not found on PATH"
command -v jq >/dev/null || fail "jq not found on PATH (reads wireserve-admin --json)"
command -v python3 >/dev/null || fail "python3 not found on PATH"
modinfo wireguard >/dev/null 2>&1 || fail "WireGuard kernel module not available"
[ "$(podman info --format '{{.Host.Security.Rootless}}')" = false ] \
    || fail "needs rootful podman (service-address rewrites and the forwarding sysctl are refused in a user namespace): sudo $0"
pass "podman, python3 and the WireGuard kernel module are present"

log "building images"
./deploy/e2e/build.sh
pass "images built"

log "creating the network segments"
podman network create --internal --subnet 198.51.100.0/24 "$INET" >/dev/null
podman network create --internal "$SITE_H" >/dev/null
podman network create --internal "$SITE_P" >/dev/null
pass "an 'internet' on a public-looking range, and two NAT-ed sites"

log "starting the coordinator"
podman run -d --name "$COORD" --network "$INET" \
    -e WIRESERVE_ADMIN_TOKEN="$ADMIN_TOKEN" \
    wireserve-coordinator:e2e >/dev/null
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
    podman exec "$name" nft "add rule ip nat postrouting oifname \"$(if_on "$name" "$INET")\" masquerade"
}

log "starting the two NAT routers"
start_router "$ROUTER_H" "$SITE_H"
start_router "$ROUTER_P" "$SITE_P"
ROUTER_H_LAN=$(ip_on "$ROUTER_H" "$SITE_H")
ROUTER_P_LAN=$(ip_on "$ROUTER_P" "$SITE_P")

log "starting the carrier directly on the inet segment"
podman run -d --name "$CARRIER" --network "$INET" \
    --cap-add=NET_ADMIN --security-opt unmask=/proc/sys --security-opt apparmor=unconfined --device /dev/net/tun --sysctl net.ipv4.ip_forward=0 \
    --entrypoint sleep wireserve-agent:e2e infinity >/dev/null
sleep 1
CARRIER_IP=$(ip_on "$CARRIER" "$INET")
# Internal networks have no default route; a carrier finds the interface
# phones reach it on by one.
CARRIER_IF=$(in_netns "$CARRIER" sh -c "ip -o -4 addr show | awk '/ $CARRIER_IP\\//{print \$2}'")
in_netns "$CARRIER" ip route replace default dev "$CARRIER_IF" >/dev/null
echo "carrier: $CARRIER_IP ($CARRIER_IF)"

log "starting the homeserver agent behind NAT"
podman run -d --name "$HOME_AGENT" --network "$SITE_H" \
    --cap-add=NET_ADMIN --security-opt unmask=/proc/sys --security-opt apparmor=unconfined --device /dev/net/tun \
    --entrypoint sleep wireserve-agent:e2e infinity >/dev/null
sleep 1
in_netns "$HOME_AGENT" ip route replace default via "$ROUTER_H_LAN" >/dev/null

create_node() { admin node create "$1" | grep -oE 'jtk_[a-f0-9]+'; }
sees() { podman exec "$1" wireserve status --json | has "\"name\": \"$2\""; }
pending() { podman exec "$1" wireserve status --json | has '"pending": true'; }
dialable_known() {
    [ "$(admin node list --json | jq '[.dialable["node-carrier"], .dialable["node-home"]] | map(select(. != null)) | length')" = 2 ]
}
# The relay port the carrier holds for homeserver, as homeserver sees it.
relay_port() {
    podman exec "$HOME_AGENT" wireserve status --json \
        | python3 -c "import json,sys; d=json.load(sys.stdin); print(next(p['relay']['port'] for p in d['peers'] if p['name']=='node-home'))"
}

log "joining the two agents"
JT_CARRIER=$(create_node node-carrier)
JT_HOME=$(create_node node-home)
podman exec "$CARRIER" wireserve join "http://$COORD_IP:47820" --allow-plaintext-http "$JT_CARRIER" \
    --listen-port "$WG_PORT" 2>/dev/null
podman exec "$HOME_AGENT" wireserve join "http://$COORD_IP:47820" --allow-plaintext-http "$JT_HOME" \
    --listen-port "$WG_PORT" 2>/dev/null
# Each daemon's output is kept in its container, for a failure to show.
for a in "$CARRIER" "$HOME_AGENT"; do
    podman exec -d "$a" sh -c "exec wireserve daemon --poll-interval-secs $POLL >/tmp/daemon.log 2>&1"
done
wait_for 30 sees "$CARRIER" node-home || fail "node-carrier never got node-home into its peers"
wait_for 30 sees "$HOME_AGENT" node-carrier || fail "node-home never got node-carrier into its peers"
wait_for 40 dialable_known || true
pass "both agents registered and polling"

log "1/9: each agent knows whether it is dialable"
PEERS=$(admin node list --json)
[ "$(echo "$PEERS" | jq '.dialable["node-carrier"]')" = true ] || { echo "$PEERS"; fail "the carrier on a public address did not find itself dialable"; }
[ "$(echo "$PEERS" | jq '.dialable["node-home"]')" = false ] || { echo "$PEERS"; fail "the node behind NAT did not find itself undialable"; }
pass "carrier dialable, homeserver not"

log "declaring a service on homeserver"
podman exec "$HOME_AGENT" wireserve svc-home 12345
wait_for 20 pending "$HOME_AGENT" || fail "node-home never reported svc-home"
admin service approve svc-home --node node-home || fail "could not approve svc-home"
wait_for 20 eval '! pending "$HOME_AGENT"' || fail "node-home never learnt svc-home was approved"

# What a carrier that doesn't qualify looks like from both sides.
carrier_diag() {
    note "the carrier as the coordinator sees it:"
    admin node show node-carrier || true
    note "the coordinator on the carrier, transit and rate limits:"
    podman logs "$COORD" 2>&1 | grep -E 'node-carrier|transit|rate_limited' | tail -20 || true
    note "the carrier's probe, carry interface, warnings and errors:"
    podman exec "$CARRIER" grep -E 'reflexive|carry|WARN|ERROR' /tmp/daemon.log || true
    note "the carrier's links:"
    in_netns "$CARRIER" ip -d link show || true
    note "the carrier's own status:"
    podman exec "$CARRIER" wireserve status || true
}

log "opting the carrier in (both halves)"
podman exec "$CARRIER" wireserve transit on
admin transit approve node-carrier || fail "could not approve node-carrier"
# Approved and offering, as the coordinator sees it: what step 2 needs.
wait_for 30 eval 'admin node show node-carrier | has -E "^transit: +on$"' \
    || { carrier_diag; fail "node-carrier is approved but the coordinator never saw it offer transit"; }
wait_for 30 relay_port || fail "homeserver never got a relay port on the carrier"

RELAY_PORT=$(relay_port)
echo "homeserver's relay port: $RELAY_PORT"

log "2/9: with the relay port blocked upstream, the export stops and says what to open"
# A cloud firewall in front of the carrier: it drops the port before
# anything on the carrier sees it.
in_netns_stdin "$CARRIER" nft -f - <<NFT
table ip cloudfw {
    chain pre {
        type filter hook prerouting priority -400; policy accept;
        iifname "$CARRIER_IF" udp dport $RELAY_PORT drop
    }
}
NFT
in_netns "$CARRIER" nft list table ip cloudfw | has "udp dport $RELAY_PORT drop" \
    || fail "the simulated cloud firewall is not in place — this check would prove nothing"
if admin device create phone --register-url "http://127.0.0.1:47820" >"$OUT/closed.conf" 2>"$OUT/closed.log"; then
    cat "$OUT/closed.log"
    # The usual reason: the carrier doesn't count as one (see the warning).
    carrier_diag
    fail "the export went ahead with the relay port closed"
fi
grep -q "open UDP $RELAY_PORT inbound on node-carrier ($CARRIER_IP)" "$OUT/closed.log" \
    || { cat "$OUT/closed.log"; fail "the refusal does not name the port and address to open"; }
admin node list --json | jq -e 'any(.peers[]; .name == "phone")' >/dev/null && fail "the refused export created the node anyway"
pass "refused before creating anything, naming UDP $RELAY_PORT on $CARRIER_IP"
in_netns "$CARRIER" nft delete table ip cloudfw

log "3/9: exporting the phone's config"
# Tried again while the carrier may still be opening its relay port: a
# refused export creates nothing (step 2).
wait_for 20 eval 'admin device create phone --register-url "http://127.0.0.1:47820" > "$OUT/phone.conf" 2>"$OUT/export.log"' \
    || {
        cat "$OUT/export.log"
        carrier_diag
        note "the carrier's port checks:"
        podman exec "$CARRIER" grep -i 'port check' /tmp/daemon.log || true
        note "the carrier's ruleset:"
        in_netns "$CARRIER" nft list ruleset || true
        fail "device create failed with the port open"
    }
note "exported config:"
sed 's/^PrivateKey = .*/PrivateKey = <redacted>/; s/^/  /' "$OUT/phone.conf"
grep -qx "MTU = 1340" "$OUT/phone.conf" || fail "no carry MTU, though a node is relayed"
grep -qx "Endpoint = $CARRIER_IP:$WG_PORT" "$OUT/phone.conf" || fail "the carrier is not dialled directly"
grep -qx "Endpoint = $CARRIER_IP:$RELAY_PORT" "$OUT/phone.conf" || fail "homeserver is not dialled at the carrier's relay port"
grep -qE "AllowedIPs = [0-9.]+/2[0-9]" "$OUT/phone.conf" && fail "a covering mesh route in the config — the gateway is supposed to be gone"
[ "$(grep -c '^\[Peer\]' "$OUT/phone.conf")" = "2" ] || fail "expected exactly two [Peer] blocks"
pass "carrier direct, homeserver at the relay port, carry MTU, no covering route"

# The phone is a peer of both agents from their next poll on.
wait_for 20 sees "$CARRIER" phone || fail "the carrier never got the phone into its peers"
wait_for 20 sees "$HOME_AGENT" phone || fail "homeserver never got the phone into its peers"

log "bringing the phone up as a plain WireGuard client, no agent"
podman run -d --name "$PHONE" --network "$SITE_P" \
    --cap-add=NET_ADMIN --security-opt unmask=/proc/sys --security-opt apparmor=unconfined --device /dev/net/tun \
    "$DEBUG_IMG" sleep infinity >/dev/null
sleep 1
podman exec "$PHONE" ip route replace default via "$ROUTER_P_LAN"
podman exec "$PHONE" mkdir -p /etc/wireguard
podman exec -i "$PHONE" tee /etc/wireguard/wg0.conf < "$OUT/phone.conf" >/dev/null
podman exec "$PHONE" wg-quick up wg0 || fail "the official-client config would not come up"

in_netns_stdin "$CARRIER" nft -f - <<'NFT'
table inet relayprobe {
    # Postrouting, not forward: the host-firewall interop puts accepts at the
    # head of every forward chain it finds, ahead of any counter.
    chain f {
        type filter hook postrouting priority 400; policy accept;
        oifname "wireserve0" meta l4proto tcp counter
        oifname "wireserve0" meta l4proto udp counter
    }
}
NFT

svc_addr() { podman exec "$1" getent hosts "$2" | awk 'NR == 1 {print $1}'; }
SVC_HOME=$(svc_addr "$CARRIER" svc-home.wg)
[ -n "$SVC_HOME" ] || fail "svc-home.wg does not resolve"
in_netns_bg "$HOME_AGENT" nc -l -k -p 12345
sleep 1

log "4/9: the phone reaches the NAT-ed node's service through the relay"
podman exec "$PHONE" timeout 30 bash -c "exec 3<>/dev/tcp/$SVC_HOME/12345" \
    || { podman exec "$PHONE" wg show wg0; in_netns "$CARRIER" nft list ruleset; fail "the phone cannot reach svc-home"; }
pass "svc-home reached"

log "5/9: the carrier forwarded only the session's UDP"
COUNTERS=$(in_netns "$CARRIER" nft list chain inet relayprobe f)
TCP_SEEN=$(echo "$COUNTERS" | awk '/l4proto tcp counter/ {for (i=1;i<=NF;i++) if ($i=="packets") print $(i+1)}')
UDP_SEEN=$(echo "$COUNTERS" | awk '/l4proto udp counter/ {for (i=1;i<=NF;i++) if ($i=="packets") print $(i+1)}')
[ "$TCP_SEEN" = "0" ] || fail "the carrier forwarded $TCP_SEEN TCP packets — it saw inside the session"
[ "${UDP_SEEN:-0}" -gt 0 ] || fail "the carrier forwarded no UDP — the connection did not go through it"
pass "$UDP_SEEN UDP packets and 0 TCP through the carrier"

log "6/9: the phone roams and gets back"
podman exec "$PHONE" wg set wg0 listen-port 51999
sleep 3
podman exec "$PHONE" timeout 40 bash -c "until exec 3<>/dev/tcp/$SVC_HOME/12345; do sleep 2; done" 2>/dev/null \
    || fail "after a new source port the phone never reached svc-home again"
pass "reached again from a new source port"

log "7/9: default-deny holds through the relay"
in_netns_bg "$HOME_AGENT" nc -l -k -p 12346
sleep 2
if podman exec "$PHONE" timeout 8 bash -c "exec 3<>/dev/tcp/$SVC_HOME/12346" 2>/dev/null; then
    fail "an UNDECLARED port on homeserver was reachable through the relay"
fi
pass "an undeclared port stays refused"

log "8/9: relay-ports names the port, its device, and that it is open"
admin transit ports
PORT=$(admin transit ports --json | jq -c --argjson p "$RELAY_PORT" '.ports[] | select(.port == $p)')
echo "$PORT"
[ "$(echo "$PORT" | jq -r .address)" = "$CARRIER_IP" ] || fail "relay-ports does not list the port with its address"
[ "$(echo "$PORT" | jq .open)" = true ] || fail "relay-ports does not say it is open"
echo "$PORT" | jq -e '.devices | index("phone")' >/dev/null || fail "relay-ports does not name the phone"
pass "listed, open, used by the phone"

log "9/9: a refresh keeps the phone's address"
PHONE_IP4=$(grep '^Address' "$OUT/phone.conf" | sed 's/Address = //; s#/32.*##')
admin device refresh phone --register-url "http://127.0.0.1:47820" > "$OUT/phone2.conf" 2>/dev/null \
    || fail "device refresh failed"
NEW_IP4=$(grep '^Address' "$OUT/phone2.conf" | sed 's/Address = //; s#/32.*##')
[ "$NEW_IP4" = "$PHONE_IP4" ] || fail "a refresh renumbered the device ($PHONE_IP4 -> $NEW_IP4)"
grep -qx "Endpoint = $CARRIER_IP:$RELAY_PORT" "$OUT/phone2.conf" || fail "the refreshed config lost its relay"
pass "same address, same relay"

echo
echo "=== PHONE RELAY TEST COMPLETE ==="

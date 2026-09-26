#!/usr/bin/env bash
# WireServe exit test (PLAN.md M27): a phone's full-tunnel profile sends its
# internet traffic out through its gateway, and a home resolver served on the
# mesh names services for it.
#
# What this proves, and what the namespace test in nftables.rs cannot — that
# one has no WireGuard, no coordinator and no exported config:
#
#   1. `--exit` is refused while the gateway has not run `exit on`;
#   2. the export writes two profiles with one key, the second carrying
#      `0.0.0.0/0, ::/0` on the gateway and a `DNS =` line;
#   3. the phone reaches an "internet" host through the gateway, which sees
#      the gateway's address, not the phone's — it has no route to the mesh;
#   4. the mesh still works in the full tunnel;
#   5. the gateway's own LAN is refused, although that host routes to the mesh;
#   6. the internet host cannot open anything into the mesh through the
#      gateway, even with a route to it (the guard);
#   7. the resolver named by `--dns`, a dnsmasq served on 53 through a
#      service address, answers a service's name from the phone;
#   8. all of that with a FORWARD policy of DROP in the gateway's iptables,
#      Docker-style, so host-firewall interop has to open the exit's flows;
#   9. `exit off` stops it again;
#  10. without the full tunnel, a device exported with `--mesh-dns` names
#      services through the same resolver, and a public one is refused for
#      that profile (PLAN.md M28).
#
#     ( inet 203.0.113.0/24 )───────────────┬──────────────┐
#          │              │                 │              │
#     [coordinator]  [internet host]    [gw agent]     [router-p]
#                                           │           masquerade
#                                      ( gw-lan )          │
#                                           │          ( site-p )
#                                      [lan host]          │
#                                                       [phone]
#
# The inet segment uses TEST-NET-3 on purpose. The exit refuses private
# destinations, and every podman default is private, so an internet host on
# one would be refused for the right reason and prove nothing.
#
# Rootful Podman, same reasoning as run-gateway-test.sh. Every container the
# agent runs in gets `--security-opt unmask=/proc/sys`: podman mounts
# /proc/sys read-only otherwise, and the agent's own forwarding switches are
# half of what an exit is. The net.* keys it writes are this container's
# own namespace's. In a rootful container the unmask very likely makes the
# host's non-namespaced keys (kernel.*, vm.*) writable to its root as well —
# fine for a throwaway harness running our own code, not a deployment setting.
#
# Usage: sudo ./deploy/e2e/run-exit-test.sh
# Exit code 0 = every check passed.

set -euo pipefail
cd "$(dirname "$0")/../.."

INET=wireserve-exit-inet
GW_LAN=wireserve-exit-gw-lan
SITE_P=wireserve-exit-site-p
COORD=wireserve-exit-coord
ROUTER_P=wireserve-exit-router-p
GW=wireserve-exit-gw
HOME_AGENT=wireserve-exit-home
WEB=wireserve-exit-internet
LAN_HOST=wireserve-exit-lan
PHONE=wireserve-exit-phone
TABLET=wireserve-exit-tablet
DEBUG_IMG=wireserve-e2e-debug-tools
ADMIN_TOKEN=exit-test-admin-token
WG_PORT=51820
OUT=$(mktemp -d)

log()  { echo; echo "=== $* ==="; }
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
note() { echo "NOTE: $*"; }

cleanup() {
    podman rm -f "$COORD" "$ROUTER_P" "$GW" "$HOME_AGENT" "$WEB" "$LAN_HOST" "$PHONE" "$TABLET" >/dev/null 2>&1 || true
    for c in $(podman ps -aq --filter "name=wireserve-exit-helper" 2>/dev/null); do
        podman rm -f "$c" >/dev/null 2>&1 || true
    done
    podman network rm "$SITE_P" "$GW_LAN" "$INET" >/dev/null 2>&1 || true
    rm -rf "$OUT"
}
trap cleanup EXIT
cleanup
OUT=$(mktemp -d)

# NET_RAW for ping and tcpdump, which podman no longer grants by default.
in_netns() {
    local target=$1; shift
    podman run --rm --name "wireserve-exit-helper-$$-$RANDOM" \
        --network "container:$target" --cap-add=NET_ADMIN --cap-add=NET_RAW "$DEBUG_IMG" "$@"
}
in_netns_bg() {
    local target=$1; shift
    podman run -d --name "wireserve-exit-helper-$$-$RANDOM" \
        --network "container:$target" --cap-add=NET_ADMIN --cap-add=NET_RAW "$@" >/dev/null
}
ip_on() {
    podman inspect "$1" --format "{{(index .NetworkSettings.Networks \"$2\").IPAddress}}"
}
admin() { podman exec "$COORD" wireserve-admin "$@"; }
# Reads one line from a TCP service, which is what the internet host answers
# with: the address it saw the connection come from.
tcp_line() { podman exec "$1" timeout 15 bash -c "exec 3<>/dev/tcp/$2/$3; head -1 <&3"; }

log "checking prerequisites"
command -v podman >/dev/null || fail "podman not found on PATH"
command -v python3 >/dev/null || fail "python3 not found on PATH"
modinfo wireguard >/dev/null 2>&1 || fail "WireGuard kernel module not available"
[ "$(podman info --format '{{.Host.Security.Rootless}}')" = false ] \
    || fail "needs rootful podman (service-address rewrites and the forwarding sysctl are refused in a user namespace): sudo $0"
pass "podman, python3 and the WireGuard kernel module are present"

log "building images"
podman build -q -f deploy/docker/coordinator.Dockerfile -t wireserve-coordinator:exit-test . >/dev/null
podman build -q -f deploy/docker/agent.Dockerfile -t wireserve-agent:exit-test . >/dev/null
podman build -q -f deploy/e2e/debug-tools.Dockerfile -t "$DEBUG_IMG" deploy/e2e >/dev/null
pass "images built"

log "creating the network segments"
podman network create --internal --subnet 203.0.113.0/24 "$INET" >/dev/null
podman network create --internal "$GW_LAN" >/dev/null
podman network create --internal "$SITE_P" >/dev/null
pass "an 'internet' on a public-looking range, the gateway's LAN, and the phone's site"

log "starting the coordinator and the internet host"
podman run -d --name "$COORD" --network "$INET" \
    -e WIRESERVE_ADMIN_TOKEN="$ADMIN_TOKEN" \
    wireserve-coordinator:exit-test >/dev/null
podman run -d --name "$WEB" --network "$INET" "$DEBUG_IMG" \
    socat TCP-LISTEN:8080,fork,reuseaddr SYSTEM:'echo $SOCAT_PEERADDR' >/dev/null
sleep 2
COORD_IP=$(ip_on "$COORD" "$INET")
WEB_IP=$(ip_on "$WEB" "$INET")
echo "coordinator: $COORD_IP  internet host: $WEB_IP"

log "starting the phone's NAT router"
podman run -d --name "$ROUTER_P" --network "$INET" --network "$SITE_P" \
    --cap-add=NET_ADMIN --sysctl net.ipv4.ip_forward=1 \
    "$DEBUG_IMG" sleep infinity >/dev/null
sleep 1
podman exec "$ROUTER_P" nft add table ip nat
podman exec "$ROUTER_P" nft 'add chain ip nat postrouting { type nat hook postrouting priority 100 ; }'
podman exec "$ROUTER_P" nft 'add rule ip nat postrouting oifname "eth0" masquerade'
ROUTER_P_LAN=$(ip_on "$ROUTER_P" "$SITE_P")

log "starting the gateway (inet + its own LAN) and a node behind it"
# Global IPv4 forwarding off, as on a VPS: the agent has to own and guard the
# egress switch itself, which is what makes check 6 mean something.
podman run -d --name "$GW" --network "$INET" --network "$GW_LAN" \
    --cap-add=NET_ADMIN --security-opt unmask=/proc/sys --device /dev/net/tun --sysctl net.ipv4.ip_forward=0 \
    --entrypoint sleep wireserve-agent:exit-test infinity >/dev/null
sleep 1
GW_IP=$(ip_on "$GW" "$INET")
GW_LAN_IP=$(ip_on "$GW" "$GW_LAN")
# Internal networks have no default route; an exit finds its egress by one.
GW_INET_IF=$(in_netns "$GW" sh -c "ip -o -4 addr show | awk '/ $GW_IP\\//{print \$2}'")
in_netns "$GW" ip route replace default dev "$GW_INET_IF" >/dev/null
podman exec "$GW" sh -c "cat /proc/sys/net/ipv4/conf/$GW_INET_IF/forwarding > /proc/sys/net/ipv4/conf/$GW_INET_IF/forwarding" \
    || fail "/proc/sys/net is not writable in the gateway container, so the agent could not turn forwarding on"
# Docker's posture: FORWARD policy DROP, which interop has to open for the
# exit's own flows only.
in_netns "$GW" iptables -P FORWARD DROP
echo "gw: $GW_IP (egress $GW_INET_IF), lan $GW_LAN_IP"

podman run -d --name "$HOME_AGENT" --network "$INET" \
    --cap-add=NET_ADMIN --security-opt unmask=/proc/sys --device /dev/net/tun \
    --entrypoint sleep wireserve-agent:exit-test infinity >/dev/null
sleep 1

podman run -d --name "$LAN_HOST" --network "$GW_LAN" --cap-add=NET_ADMIN "$DEBUG_IMG" \
    socat TCP-LISTEN:8080,fork,reuseaddr SYSTEM:'echo $SOCAT_PEERADDR' >/dev/null
sleep 1
LAN_IP=$(ip_on "$LAN_HOST" "$GW_LAN")

create_node() { admin create-node "$1" | grep -oE 'jtk_[a-f0-9]+'; }

log "joining the agents"
JT_GW=$(create_node node-gw)
JT_HOME=$(create_node node-home)
podman exec "$GW" wireserve join "http://$COORD_IP:47820" --allow-plaintext-http "$JT_GW" \
    --listen-port "$WG_PORT" --endpoint-addr "$GW_IP:$WG_PORT" 2>/dev/null
podman exec "$HOME_AGENT" wireserve join "http://$COORD_IP:47820" --allow-plaintext-http "$JT_HOME" \
    --listen-port "$WG_PORT" 2>/dev/null
for a in "$GW" "$HOME_AGENT"; do
    podman exec -d "$a" wireserve daemon --poll-interval-secs 5
done
sleep 15
pass "both agents registered and polling"

# The LAN host routes the mesh back through the gateway, so only the exit's
# own refusal can stop the phone reaching it.
MESH_V4=$(podman exec "$GW" wireserve list --json \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print(next(p['ip4'] for p in d['peers'] if p['name']=='node-gw'))")
MESH_NET="${MESH_V4%.*}.0/24"
in_netns "$LAN_HOST" ip route replace "$MESH_NET" via "$GW_LAN_IP" >/dev/null

log "a service on the home node, and a resolver on the gateway"
podman exec "$HOME_AGENT" wireserve serve svc-home 12345 tcp
podman exec "$GW" wireserve serve dns 53:53/udp 53:53/tcp
sleep 8
admin approve-service node-home svc-home || fail "could not approve svc-home"
admin approve-service node-gw dns || fail "could not approve dns"
sleep 12
svc_addr() { podman exec "$1" getent hosts "$2" | awk '{print $1}'; }
SVC_HOME=$(svc_addr "$GW" svc-home.wg)
DNS_VIP=$(svc_addr "$GW" dns.wg)
[ -n "$SVC_HOME" ] && [ -n "$DNS_VIP" ] || fail "a service name does not resolve (home=$SVC_HOME dns=$DNS_VIP)"
# A dnsmasq in the gateway's network namespace, answering from a copy of the
# gateway's hosts file — the file a resolver running on that node reads.
podman cp "$GW:/etc/hosts" "$OUT/gw-hosts"
in_netns_bg "$GW" -v "$OUT/gw-hosts:/wireserve-hosts:ro" "$DEBUG_IMG" \
    dnsmasq --no-daemon --no-resolv --no-hosts --addn-hosts=/wireserve-hosts \
    --listen-address="$MESH_V4" --bind-interfaces
in_netns_bg "$HOME_AGENT" "$DEBUG_IMG" nc -l -k -p 12345
echo "svc-home.wg=$SVC_HOME  dns.wg=$DNS_VIP"

log "making node-gw a gateway"
podman exec "$GW" wireserve transit on
admin approve-transit node-gw || fail "could not approve node-gw for transit"
sleep 10

log "1/9: --exit is refused while the gateway has not opted in"
if admin export-config phone --gateway node-gw --exit --dns dns --out /tmp/phone.conf \
    --register-url "http://127.0.0.1:47820" >"$OUT/refused.log" 2>&1; then
    fail "an exit profile was written for a gateway that never ran \`exit on\`"
fi
grep -q "exit on" "$OUT/refused.log" || { cat "$OUT/refused.log"; fail "the refusal does not say what to run"; }
# Nothing was created: step 2 exports the same name without --refresh,
# which a leftover node would make fail with a conflict.
pass "refused, naming \`exit on\`"

log "2/9: two profiles, one key"
podman exec "$GW" wireserve exit on
sleep 10
admin export-config phone --gateway node-gw --exit --dns dns --out /tmp/phone.conf \
    --register-url "http://127.0.0.1:47820" \
    || fail "export-config --exit failed (a conflict here means step 1 created the node before refusing)"
podman cp "$COORD:/tmp/phone.conf" "$OUT/phone.conf"
podman cp "$COORD:/tmp/phone-exit.conf" "$OUT/phone-exit.conf"
note "full-tunnel profile:"
sed 's/^PrivateKey = .*/PrivateKey = <redacted>/; s/^/  /' "$OUT/phone-exit.conf"
[ "$(grep '^PrivateKey' "$OUT/phone.conf")" = "$(grep '^PrivateKey' "$OUT/phone-exit.conf")" ] \
    || fail "the two profiles hold different keys"
grep -qx "AllowedIPs = 0.0.0.0/0, ::/0" "$OUT/phone-exit.conf" || fail "the gateway does not carry everything"
grep -qx "DNS = $DNS_VIP" "$OUT/phone-exit.conf" || fail "the resolver is not the dns service's address"
grep -q "^DNS" "$OUT/phone.conf" && fail "the mesh profile must not name a resolver (PLAN.md #104)"
admin list-peers | grep '^phone' | grep -q 'exit=yes' || fail "list-peers does not show the phone's exit"
pass "same key; everything on the gateway and a resolver in the second profile only"

log "bringing the phone up on the full-tunnel profile"
podman run -d --name "$PHONE" --network "$SITE_P" \
    --cap-add=NET_ADMIN --security-opt unmask=/proc/sys --device /dev/net/tun \
    --sysctl net.ipv4.conf.all.src_valid_mark=1 --sysctl net.ipv6.conf.all.disable_ipv6=0 \
    "$DEBUG_IMG" sleep infinity >/dev/null
sleep 1
podman exec "$PHONE" ip route replace default via "$ROUTER_P_LAN"
podman exec "$PHONE" mkdir -p /etc/wireguard
# wg-quick hands `DNS =` to resolvconf, which a container has no use for;
# check 7 queries the resolver directly instead. Everything else is wg-quick's
# own full-tunnel routing: a fwmark keeps WireGuard's own packets — to every
# peer's endpoint, not just the gateway's — out of the tunnel, which is what
# the phone apps do by exempting their sockets. Anything less and the
# direct peer's handshakes ride out through the exit, so the mesh would only
# seem to work for as long as the exit does.
grep -v '^DNS' "$OUT/phone-exit.conf" | podman exec -i "$PHONE" tee /etc/wireguard/wg0.conf >/dev/null
podman exec "$PHONE" wg-quick up wg0 || fail "the full-tunnel profile would not come up"
sleep 10
PHONE_IP4=$(grep '^Address' "$OUT/phone.conf" | sed 's/Address = //; s#/32.*##')

# What the gateway looks like when an exit check fails, and where one retry's
# packets go: in on the mesh, out on the egress, back, or nowhere.
exit_diagnostics() {
    note "gateway agent's view:"
    podman exec "$GW" wireserve list --json \
        | python3 -c "import json,sys; d=json.load(sys.stdin); print({k: d.get(k) for k in ('transit_capable','exit_capable','exit_clients')})" || true
    note "gateway sysctls:"
    in_netns "$GW" sh -c 'for f in all wireserve0 '"$GW_INET_IF"'; do echo "$f ipv4 forwarding=$(cat /proc/sys/net/ipv4/conf/$f/forwarding) rp_filter=$(cat /proc/sys/net/ipv4/conf/$f/rp_filter)"; done' || true
    note "gateway routes:"; in_netns "$GW" ip -4 route || true
    note "gateway route to the internet host:"; in_netns "$GW" ip route get "$WEB_IP" || true
    note "gateway iptables FORWARD:"; in_netns "$GW" iptables -S FORWARD || true
    note "gateway nft ruleset:"; in_netns "$GW" nft list ruleset || true
    note "gateway wg:"; in_netns "$GW" wg show wireserve0 || true
    note "phone wg and routes:"; podman exec "$PHONE" wg show wg0 || true; podman exec "$PHONE" ip -4 route || true
    note "one retry, captured on the gateway's mesh and egress interfaces:"
    in_netns_bg "$GW" "$DEBUG_IMG" sh -c "timeout 12 tcpdump -lni wireserve0 -c 20 'tcp port 8080 or icmp' > /tmp/wg.txt 2>&1; cat /tmp/wg.txt"
    in_netns_bg "$GW" "$DEBUG_IMG" sh -c "timeout 12 tcpdump -lni $GW_INET_IF -c 20 'tcp port 8080 or icmp' > /tmp/eg.txt 2>&1; cat /tmp/eg.txt"
    sleep 2
    tcp_line "$PHONE" "$WEB_IP" 8080 || true
    sleep 12
    for c in $(podman ps -aq --filter "name=wireserve-exit-helper" 2>/dev/null); do
        podman logs "$c" 2>/dev/null | sed 's/^/  /'
    done
}

log "3/9: the internet, masqueraded"
SEEN=$(tcp_line "$PHONE" "$WEB_IP" 8080) \
    || { exit_diagnostics; fail "the phone cannot reach the internet host through the exit"; }
[ "$SEEN" = "$GW_IP" ] || fail "the internet host saw '$SEEN', not the gateway's $GW_IP"
pass "the internet host saw the gateway's address ($SEEN), not the phone's $PHONE_IP4"

log "4/9: the mesh still works in the full tunnel"
podman exec "$PHONE" timeout 15 bash -c "exec 3<>/dev/tcp/$SVC_HOME/12345" \
    || fail "the phone lost the mesh in the full tunnel"
# Directly, not through the exit: every peer in the file has handshaken with
# the phone itself. (The exit forwards to public addresses, so a home node on
# one would also be reachable the long way round — and stop being so the
# moment the exit went away.)
if podman exec "$PHONE" wg show wg0 latest-handshakes | awk '$2 == 0 {bad=1} END {exit !bad}'; then
    podman exec "$PHONE" wg show wg0
    fail "a direct peer never handshook with the phone — its traffic is going through the exit"
fi
pass "svc-home reachable, over the phone's own direct peer entry"

log "5/9: the gateway's LAN is not the internet"
if tcp_line "$PHONE" "$LAN_IP" 8080 >/dev/null 2>&1; then
    fail "the exit forwarded to a private address on the gateway's LAN"
fi
pass "the LAN host stays unreachable, though it routes to the mesh"

log "6/9: nothing gets in from the internet side"
in_netns "$WEB" ip route replace "$MESH_NET" via "$GW_IP" >/dev/null
if in_netns "$WEB" ping -c3 -W1 "$PHONE_IP4" >/dev/null 2>&1; then
    fail "the internet host reached the phone through the gateway"
fi
EGRESS_FWD=$(in_netns "$GW" cat "/proc/sys/net/ipv4/conf/$GW_INET_IF/forwarding")
[ "$EGRESS_FWD" = "1" ] || fail "the gateway's egress does not forward ($EGRESS_FWD) — check 3 passed some other way"
in_netns "$GW" nft list table inet wireserve.wireserve0 | grep -q "iifname \"$GW_INET_IF\" meta nfproto ipv4 ct mark" \
    || fail "the egress forwards without the guard"
pass "the egress forwards, guarded: unsolicited traffic stays out"

log "7/9: the home resolver names the mesh"
ANSWER=$(podman exec "$PHONE" dig +short +time=3 +tries=2 "@$DNS_VIP" svc-home.wg) || true
[ "$ANSWER" = "$SVC_HOME" ] || fail "the resolver answered '$ANSWER' for svc-home.wg, expected $SVC_HOME"
pass "svc-home.wg -> $ANSWER, from the phone, over the dns service's address"

log "8/9: host-firewall interop opened the exit's flows only"
in_netns "$GW" iptables -S FORWARD | grep -q "0x2000000/0x2000000" \
    || in_netns "$GW" nft list chain ip filter FORWARD | grep -q "0x02000000" \
    || fail "nothing opened FORWARD for the exit, yet check 3 passed — was the policy really DROP?"
pass "FORWARD DROP opened for exit-marked flows"

log "9/9: exit off"
podman exec "$GW" wireserve exit off
sleep 12
if tcp_line "$PHONE" "$WEB_IP" 8080 >/dev/null 2>&1; then
    fail "the phone still reaches the internet after \`exit off\`"
fi
podman exec "$PHONE" timeout 15 bash -c "exec 3<>/dev/tcp/$SVC_HOME/12345" \
    || fail "\`exit off\` broke the mesh too"
pass "the internet is gone, the mesh stays"

log "10/10: names without the full tunnel (--mesh-dns)"
if admin export-config tablet --gateway node-gw --dns 9.9.9.9 --mesh-dns --out /tmp/tablet.conf \
    --register-url "http://127.0.0.1:47820" >"$OUT/mesh-refused.log" 2>&1; then
    fail "a public resolver was accepted for the mesh profile, which would ask it outside the tunnel"
fi
grep -q "not on the mesh" "$OUT/mesh-refused.log" || { cat "$OUT/mesh-refused.log"; fail "the refusal does not say why"; }
admin export-config tablet --gateway node-gw --dns dns --mesh-dns --out /tmp/tablet.conf \
    --register-url "http://127.0.0.1:47820" || fail "export-config --mesh-dns failed"
podman cp "$COORD:/tmp/tablet.conf" "$OUT/tablet.conf"
grep -qx "DNS = $DNS_VIP" "$OUT/tablet.conf" || fail "the mesh profile does not name the resolver"
grep -q "0.0.0.0/0" "$OUT/tablet.conf" && fail "--mesh-dns must not widen the mesh profile"
podman run -d --name "$TABLET" --network "$SITE_P" \
    --cap-add=NET_ADMIN --security-opt unmask=/proc/sys --device /dev/net/tun \
    "$DEBUG_IMG" sleep infinity >/dev/null
sleep 1
podman exec "$TABLET" ip route replace default via "$ROUTER_P_LAN"
podman exec "$TABLET" mkdir -p /etc/wireguard
grep -v '^DNS' "$OUT/tablet.conf" | podman exec -i "$TABLET" tee /etc/wireguard/wg0.conf >/dev/null
podman exec "$TABLET" wg-quick up wg0 || fail "the mesh profile would not come up"
sleep 5
ANSWER=$(podman exec "$TABLET" dig +short +time=3 +tries=2 "@$DNS_VIP" svc-home.wg) || true
[ "$ANSWER" = "$SVC_HOME" ] || fail "through the mesh profile the resolver answered '$ANSWER' for svc-home.wg, expected $SVC_HOME"
pass "svc-home.wg -> $ANSWER over the plain mesh profile; a public resolver is refused for it"

echo
echo "=== EXIT TEST COMPLETE ==="

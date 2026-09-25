#!/usr/bin/env bash
# WireServe static-peer gateway test (PLAN.md M24).
#
# A phone cannot run the agent, so it joins with an exported `.conf` and an
# official WireGuard client. Before this milestone that file listed every
# node individually, which made it a snapshot: anything joining later was
# unroutable from the device until it was exported and imported again. A
# gateway replaces the listing with one peer carrying the whole mesh range.
#
# What this proves, and what no unit test can:
#
#   1. the device reaches a node it has NO direct entry for, through the
#      gateway, with real TCP;
#   2. a node it DOES have a direct entry for still works at the same time
#      — the regression the design almost shipped, where naming a gateway
#      for an in-config peer makes that peer drop the device while the
#      device still dials it (its /32 outranks the gateway's /24, and
#      WireGuard has no failover, so it black-holes);
#   3. a service declared AFTER the export is reachable with no re-import,
#      which is the entire product claim;
#   4. the NAT-ed node has no kernel peer entry for the device at all — its
#      reply path is folded onto the gateway's entry;
#   5. default-deny still holds through the gateway path;
#   6. forwarding is enabled on the gateway's wg interface alone.
#
#     [coordinator]──────────────( inet )───────────────────┐
#          │                   │        │                   │
#          │             [router-h]  [router-p]        [gw agent]
#          │             masquerade  masquerade      (port-forwarded,
#          │                   │        │             transit on)
#          │            ( site-h )  ( site-p )
#          │                   │        │
#          │           [homeserver]   [phone]
#          │         (NAT, no forward) (plain wg, no agent)
#
# `gw` sits directly on the inet segment with a routable endpoint, so it is
# the only eligible gateway. `homeserver` is behind NAT with nothing
# forwarded to it, so it has no routable endpoint and is deliberately left
# out of the phone's config — exactly the node the gateway exists to reach.
#
# Rootful Podman, same reasoning as run-transit-test.sh (service-address
# rewrites and the interface-scoped forwarding sysctl both need the host's
# own user namespace).
#
# Usage: sudo ./deploy/e2e/run-gateway-test.sh
# Exit code 0 = every check passed.

set -euo pipefail
cd "$(dirname "$0")/../.."

INET=wireserve-gw-inet
SITE_H=wireserve-gw-site-h
SITE_P=wireserve-gw-site-p
COORD=wireserve-gw-coord
ROUTER_H=wireserve-gw-router-h
ROUTER_P=wireserve-gw-router-p
GW=wireserve-gw-gw
HOME_AGENT=wireserve-gw-homeserver
PHONE=wireserve-gw-phone
DEBUG_IMG=wireserve-e2e-debug-tools
ADMIN_TOKEN=gateway-test-admin-token
WG_PORT=51820

log()  { echo; echo "=== $* ==="; }
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
note() { echo "NOTE: $*"; }

cleanup() {
    podman rm -f "$COORD" "$ROUTER_H" "$ROUTER_P" "$GW" "$HOME_AGENT" "$PHONE" >/dev/null 2>&1 || true
    for c in $(podman ps -aq --filter "name=wireserve-gw-helper" 2>/dev/null); do
        podman rm -f "$c" >/dev/null 2>&1 || true
    done
    podman network rm "$SITE_H" "$SITE_P" "$INET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

in_netns() {
    local target=$1; shift
    podman run --rm --name "wireserve-gw-helper-$$-$RANDOM" \
        --network "container:$target" --cap-add=NET_ADMIN "$DEBUG_IMG" "$@"
}
in_netns_bg() {
    local target=$1; shift
    podman run -d --name "wireserve-gw-helper-$$-$RANDOM" \
        --network "container:$target" --cap-add=NET_ADMIN "$DEBUG_IMG" "$@" >/dev/null
}
ip_on() {
    podman inspect "$1" --format "{{(index .NetworkSettings.Networks \"$2\").IPAddress}}"
}
admin() { podman exec "$COORD" wireserve-admin "$@"; }

log "checking prerequisites"
command -v podman >/dev/null || fail "podman not found on PATH"
command -v python3 >/dev/null || fail "python3 not found on PATH"
modinfo wireguard >/dev/null 2>&1 || fail "WireGuard kernel module not available"
[ "$(podman info --format '{{.Host.Security.Rootless}}')" = false ] \
    || fail "needs rootful podman (service-address rewrites and the forwarding sysctl are refused in a user namespace): sudo $0"
pass "podman, python3 and the WireGuard kernel module are present"

log "building images"
podman build -q -f deploy/docker/coordinator.Dockerfile -t wireserve-coordinator:gw-test . >/dev/null
podman build -q -f deploy/docker/agent.Dockerfile -t wireserve-agent:gw-test . >/dev/null
podman build -q -f deploy/e2e/debug-tools.Dockerfile -t "$DEBUG_IMG" deploy/e2e >/dev/null
pass "images built"

log "creating the three network segments"
podman network create --internal "$INET" >/dev/null
podman network create --internal "$SITE_H" >/dev/null
podman network create --internal "$SITE_P" >/dev/null
pass "three internal segments, so the only NAT is the one our routers do"

log "starting the coordinator"
podman run -d --name "$COORD" --network "$INET" \
    -e WIRESERVE_ADMIN_TOKEN="$ADMIN_TOKEN" \
    wireserve-coordinator:gw-test >/dev/null
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
    podman exec "$name" nft 'add rule ip nat postrouting oifname "eth0" masquerade'
}

log "starting the two NAT routers"
start_router "$ROUTER_H" "$SITE_H"
start_router "$ROUTER_P" "$SITE_P"
ROUTER_H_LAN=$(ip_on "$ROUTER_H" "$SITE_H")
ROUTER_P_LAN=$(ip_on "$ROUTER_P" "$SITE_P")
pass "homeserver and the phone are each behind NAT with nothing forwarded in"

log "starting the gateway agent directly on the inet segment"
podman run -d --name "$GW" --network "$INET" \
    --cap-add=NET_ADMIN --security-opt unmask=/proc/sys --device /dev/net/tun \
    --entrypoint sleep wireserve-agent:gw-test infinity >/dev/null
sleep 1
GW_IP=$(ip_on "$GW" "$INET")
# A hostname, not the literal address, and for a real reason rather than
# cosmetics: gateway eligibility requires a *globally routable* endpoint, and
# every address in this topology is RFC1918 because podman networks are. A
# node on a real public IP would pass on the literal; a node on dynamic DNS —
# which is what most people actually run — passes on the name. So the test
# exercises the same path a real deployment does. `--add-host` below gives the
# containers that have to dial it a way to resolve it.
GW_HOST=gw.test
echo "gw: $GW_IP, advertised as $GW_HOST:$WG_PORT (will be the gateway)"

log "starting the homeserver agent behind NAT"
podman run -d --name "$HOME_AGENT" --network "$SITE_H" \
    --cap-add=NET_ADMIN --security-opt unmask=/proc/sys --device /dev/net/tun --add-host "$GW_HOST:$GW_IP" \
    --entrypoint sleep wireserve-agent:gw-test infinity >/dev/null
sleep 1
in_netns "$HOME_AGENT" ip route replace default via "$ROUTER_H_LAN" >/dev/null
pass "homeserver has no routable endpoint — the case the gateway exists for"

create_node() { admin create-node "$1" | grep -oE 'jtk_[a-f0-9]+'; }

log "joining the two agents"
JT_GW=$(create_node node-gw)
JT_HOME=$(create_node node-home)
podman exec "$GW" wireserve-agent join "http://$COORD_IP:47820" --allow-plaintext-http "$JT_GW" \
    --listen-port "$WG_PORT" --endpoint-addr "$GW_HOST:$WG_PORT" 2>/dev/null
podman exec "$HOME_AGENT" wireserve-agent join "http://$COORD_IP:47820" --allow-plaintext-http "$JT_HOME" \
    --listen-port "$WG_PORT" 2>/dev/null
for a in "$GW" "$HOME_AGENT"; do
    podman exec -d "$a" wireserve-agent daemon --poll-interval-secs 5
done
sleep 15
pass "both agents registered and polling"

GW_ALL_BASELINE=$(in_netns "$GW" cat /proc/sys/net/ipv4/conf/all/forwarding 2>/dev/null || echo "?")
HOME_WG_BASELINE=$(in_netns "$HOME_AGENT" cat /proc/sys/net/ipv4/conf/wireserve0/forwarding 2>/dev/null || echo "?")

log "declaring a service on homeserver and on the gateway"
podman exec "$HOME_AGENT" wireserve-agent serve svc-home 12345 tcp
podman exec "$GW" wireserve-agent serve svc-gw 12345 tcp
sleep 8
admin approve-service node-home svc-home || fail "could not approve svc-home"
admin approve-service node-gw svc-gw || fail "could not approve svc-gw"
sleep 12

log "opting the gateway in as a carrier (both halves)"
podman exec "$GW" wireserve-agent transit on
admin approve-transit node-gw || fail "could not approve node-gw for transit"
sleep 10

log "exporting the phone's config against that gateway"
admin export-config phone --gateway node-gw \
    --register-url "http://127.0.0.1:47820" > /tmp/wireserve-gw-phone.conf 2>/dev/null \
    || fail "export-config failed"
note "exported config:"
sed 's/^PrivateKey = .*/PrivateKey = <redacted>/; s/^/  /' /tmp/wireserve-gw-phone.conf

GW_PUBKEY=$(podman exec "$GW" wireserve-agent list --json \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print(next((p['pubkey'] for p in d['peers'] if p.get('name')=='node-gw'), ''))" 2>/dev/null || true)
if [ -z "$GW_PUBKEY" ]; then
    GW_PUBKEY=$(in_netns "$GW" wg show wireserve0 public-key)
fi

log "checking the config's shape before importing it"
grep -q "AllowedIPs = .*/2[0-9]" /tmp/wireserve-gw-phone.conf \
    || grep -qE "AllowedIPs = [0-9.]+/[0-9]+, .*::/[0-9]+" /tmp/wireserve-gw-phone.conf \
    || fail "no mesh-range AllowedIPs in the config — the gateway peer was not rendered"
pass "the config carries a mesh-range block, not just host prefixes"
PEER_BLOCKS=$(grep -c '^\[Peer\]' /tmp/wireserve-gw-phone.conf)
echo "peer blocks: $PEER_BLOCKS"
[ "$PEER_BLOCKS" = "1" ] \
    || fail "expected exactly one [Peer] (the gateway); homeserver has no routable endpoint and must not get a direct entry, and the gateway must not be emitted twice"
pass "exactly one [Peer] block — the gateway, rendered once"

log "bringing the phone up as a plain WireGuard client, no agent"
podman run -d --name "$PHONE" --network "$SITE_P" \
    --cap-add=NET_ADMIN --security-opt unmask=/proc/sys --device /dev/net/tun --add-host "$GW_HOST:$GW_IP" \
    "$DEBUG_IMG" sleep infinity >/dev/null
sleep 1
podman exec "$PHONE" ip route replace default via "$ROUTER_P_LAN"
podman exec "$PHONE" mkdir -p /etc/wireguard
podman exec -i "$PHONE" tee /etc/wireguard/wg0.conf < /tmp/wireserve-gw-phone.conf >/dev/null
podman exec "$PHONE" wg-quick up wg0 || fail "the official-client config would not come up"
sleep 10
pass "the exported config came up unmodified under wg-quick"

svc_addr() { podman exec "$1" getent hosts "$2" | awk '{print $1}'; }
SVC_HOME=$(svc_addr "$GW" svc-home.wg)
SVC_GW=$(svc_addr "$HOME_AGENT" svc-gw.wg)
[ -n "$SVC_HOME" ] && [ -n "$SVC_GW" ] || fail "a service name does not resolve (home=$SVC_HOME gw=$SVC_GW)"
echo "svc-home.wg=$SVC_HOME  svc-gw.wg=$SVC_GW"

in_netns_bg "$HOME_AGENT" nc -l -k -p 12345
in_netns_bg "$GW" nc -l -k -p 12345
sleep 3

log "1/3: the phone reaches a node it has NO direct entry for, through the gateway"
if podman exec "$PHONE" timeout 20 bash -c "exec 3<>/dev/tcp/$SVC_HOME/12345"; then
    pass "the phone reached homeserver's service with no direct peer entry for it"
else
    fail "the phone cannot reach homeserver through the gateway"
fi

log "2/3: the gateway's own service still works at the same time"
if podman exec "$PHONE" timeout 20 bash -c "exec 3<>/dev/tcp/$SVC_GW/12345"; then
    pass "the gateway's own service is reachable too"
else
    fail "the phone cannot reach the gateway's own service"
fi

log "3/3: a service declared AFTER the export is reachable with NO re-import"
# The product claim. Nothing about the phone changes here — no new export,
# no reimport, no restart of its tunnel.
podman exec "$HOME_AGENT" wireserve-agent serve svc-later 12399 tcp
sleep 8
admin approve-service node-home svc-later || fail "could not approve svc-later"
sleep 12
SVC_LATER=$(svc_addr "$GW" svc-later.wg)
[ -n "$SVC_LATER" ] || fail "svc-later.wg does not resolve"
in_netns_bg "$HOME_AGENT" nc -l -k -p 12399
sleep 3
if podman exec "$PHONE" timeout 20 bash -c "exec 3<>/dev/tcp/$SVC_LATER/12399"; then
    pass "a service that did not exist at export time is reachable with no re-import — this is the whole point"
else
    fail "svc-later is unreachable; the config still behaves like a snapshot"
fi

log "confirming homeserver has no kernel peer entry for the phone"
PHONE_IP4=$(grep '^Address' /tmp/wireserve-gw-phone.conf | sed 's/Address = //; s#/32.*##')
echo "phone mesh address: $PHONE_IP4"
HOME_ALLOWED=$(in_netns "$HOME_AGENT" wg show wireserve0 allowed-ips)
PHONE_OWN_ENTRY=$(echo "$HOME_ALLOWED" | grep -c "^$GW_PUBKEY.*$PHONE_IP4" || true)
if [ "$PHONE_OWN_ENTRY" -lt 1 ]; then
    note "homeserver's peer table:"
    echo "$HOME_ALLOWED" | sed 's/^/  /'
    fail "the phone's address is not folded onto the gateway's peer entry — its reply path is broken"
fi
pass "the phone's address sits on the gateway's entry, not one of its own"

log "confirming default-deny still holds through the gateway path"
in_netns_bg "$HOME_AGENT" nc -l -k -p 12346
sleep 3
if podman exec "$PHONE" timeout 8 bash -c "exec 3<>/dev/tcp/$SVC_HOME/12346" 2>/dev/null; then
    fail "an UNDECLARED port on homeserver was reachable through the gateway"
fi
pass "an undeclared port stays refused even through the gateway"

log "confirming interface-scoped forwarding, not the host's global switch"
GW_WG_FWD=$(in_netns "$GW" cat /proc/sys/net/ipv4/conf/wireserve0/forwarding 2>/dev/null || echo "?")
GW_ALL_FWD=$(in_netns "$GW" cat /proc/sys/net/ipv4/conf/all/forwarding 2>/dev/null || echo "?")
[ "$GW_WG_FWD" = "1" ] || fail "the gateway's wireserve0 forwarding flag is not 1 (got '$GW_WG_FWD')"
[ "$GW_ALL_FWD" = "$GW_ALL_BASELINE" ] \
    || fail "the gateway's GLOBAL forwarding switch changed (baseline '$GW_ALL_BASELINE', now '$GW_ALL_FWD') — the open-router regression"
pass "the gateway forwards on its wg interface alone (global switch unchanged at '$GW_ALL_BASELINE')"
if in_netns "$GW" test -e /proc/sys/net/ipv6/conf/wireserve0/force_forwarding; then
    GW_WG_FWD6=$(in_netns "$GW" cat /proc/sys/net/ipv6/conf/wireserve0/force_forwarding)
    [ "$GW_WG_FWD6" = "1" ] || fail "the gateway's wireserve0 force_forwarding is not 1 (got '$GW_WG_FWD6')"
    pass "the gateway forwards IPv6 on its wg interface alone (force_forwarding)"
fi
HOME_WG_FWD=$(in_netns "$HOME_AGENT" cat /proc/sys/net/ipv4/conf/wireserve0/forwarding 2>/dev/null || echo "?")
[ "$HOME_WG_FWD" = "$HOME_WG_BASELINE" ] \
    || fail "homeserver never opted in, but its forwarding flag moved from '$HOME_WG_BASELINE' to '$HOME_WG_FWD'"
pass "the node that never opted in has its forwarding posture untouched"

log "confirming a refresh keeps the phone's address"
admin export-config phone --refresh --register-url "http://127.0.0.1:47820" \
    > /tmp/wireserve-gw-phone2.conf 2>/dev/null || fail "export-config --refresh failed"
NEW_IP4=$(grep '^Address' /tmp/wireserve-gw-phone2.conf | sed 's/Address = //; s#/32.*##')
[ "$NEW_IP4" = "$PHONE_IP4" ] \
    || fail "a refresh renumbered the device ($PHONE_IP4 -> $NEW_IP4) — the whole point is that it does not"
grep -q "AllowedIPs = .*/2[0-9]" /tmp/wireserve-gw-phone2.conf \
    || grep -qE "AllowedIPs = [0-9.]+/[0-9]+, .*::/[0-9]+" /tmp/wireserve-gw-phone2.conf \
    || fail "the refreshed config lost its gateway peer"
pass "a refresh keeps the same address and the same gateway"

log "confirming a refresh aimed at an agent node is refused outright"
if admin export-config node-home --refresh --register-url "http://127.0.0.1:47820" >/dev/null 2>&1; then
    fail "--refresh was allowed against an agent node — that nulls its pubkey and drops it off the mesh"
fi
if ! podman exec "$COORD" wireserve-admin list-peers | grep -q node-home; then
    fail "node-home left the directory — the kind check did not happen before the mutation"
fi
pass "a refresh against an agent node is refused, and the node is untouched"

rm -f /tmp/wireserve-gw-phone.conf /tmp/wireserve-gw-phone2.conf
echo
echo "=== GATEWAY TEST COMPLETE ==="

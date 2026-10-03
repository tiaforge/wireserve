#!/usr/bin/env bash
# wireserve sign-in test (PLAN.md M34, M36): who gets into a restricted
# service, decided by the service's own terminator — by device first, then
# by the groups a sign-in proves.
#
# jellyfin is in group `media`, granted to `tag:tv` (the gate node) and to
# `oidc:family` (whoever signs in with that group). The client is untagged:
# a shared device, whose people get in by signing in. What this proves,
# against real WireGuard, a real ACME CA (Pebble) and real DNS (BIND):
#
#   1. the provider and both services are served with TLS by their own
#      nodes, and the provider itself cannot be put in a group;
#   2. without a session the client is sent to the login URL, and the
#      backend never sees the request;
#   3. signed in with `family`, the backend sees who (the provider's
#      identity headers), not a forged X-Auth-User, not the session cookie —
#      other cookies kept;
#   4. signed in with another group: 403, backend untouched — and an answer
#      the provider marks cacheable is reused for the same cookie only
#      (PLAN.md M37);
#   5. the tagged gate gets in without any session: its device is granted,
#      and the sign-in is never asked;
#   6. grafana, still in `default`, needs no sign-in, but loses the cookie
#      and a forged identity too;
#   7. jellyfin's other port admits the granted gate and refuses the client;
#   8. a request to jellyfin's address naming another host gets 421, and
#      never reaches the backend or the sign-in;
#   9. the provider is trusted only on its own node (WIRESERVE_AUTH_NODE):
#      once gate withdraws `auth` and home declares it, answering every
#      /verify with 200, jellyfin refuses instead of asking the impostor;
#  10. taking jellyfin out of `media` puts it back in `default`: no sign-in,
#      and its other port open to everyone.
#
#     ( net )──┬──────────┬───────┬────────┬──────────────┬──────────────────┬──────────┐
#          [coordinator] [bind] [pebble] [gate agent     [home agent        [client agent]
#                                         auth 443:8080   jellyfin 443:8096
#                                         (stub /verify)  + 8920 (media)
#                                         tag tv]         grafana 443:3000
#                                                         + 3001 (default)]
#
# The provider is a stub (deploy/e2e/auth-stub.sh) standing in for authward's
# /verify: it signs in `authward_session=ok` as alice in `family` and
# `authward_session=guest` as bob in `guests`, but only when the terminator
# forwarded the protected service's own name in X-Forwarded-Host.
#
# Rootful Podman, like the other harnesses that run WireGuard.
#
# Usage: sudo ./deploy/e2e/run-service-auth-test.sh
# Exit code 0 = every check passed.

set -euo pipefail
cd "$(dirname "$0")/../.."

NET=wireserve-sa-net
COORD=wireserve-sa-coord
BIND=wireserve-sa-bind
PEBBLE=wireserve-sa-pebble
GATE=wireserve-sa-gate
HOME_AGENT=wireserve-sa-home
CLIENT=wireserve-sa-client
DEBUG_IMG=wireserve-e2e-debug-tools
BIND_IMG=docker.io/internetsystemsconsortium/bind9:9.20
PEBBLE_IMG=ghcr.io/letsencrypt/pebble:latest
ADMIN_TOKEN=service-auth-test-admin-token
DOMAIN=int.test
WG_PORT=51820

log()  { echo; echo "=== $* ==="; }
pass() { echo "PASS: $*"; }
fail() {
    echo "FAIL: $*" >&2
    for c in "$GATE" "$HOME_AGENT"; do
        for f in tls.log agent.log; do
            echo "--- $c:/var/log/$f (tail) ---" >&2
            podman exec "$c" tail -n 30 "/var/log/$f" >&2 2>/dev/null || true
        done
    done
    echo "--- $COORD (tail) ---" >&2
    podman logs --tail 30 "$COORD" >&2 2>/dev/null || true
    exit 1
}

cleanup() {
    podman rm -f "$COORD" "$BIND" "$PEBBLE" "$GATE" "$HOME_AGENT" "$CLIENT" >/dev/null 2>&1 || true
    for c in $(podman ps -aq --filter "name=wireserve-sa-helper" 2>/dev/null); do
        podman rm -f "$c" >/dev/null 2>&1 || true
    done
    podman network rm "$NET" >/dev/null 2>&1 || true
    [ -n "${WORK:-}" ] && rm -rf "$WORK"
    return 0
}
trap cleanup EXIT
cleanup
WORK=$(mktemp -d)

in_netns() {
    local target=$1; shift
    podman run --rm --name "wireserve-sa-helper-$$-$RANDOM" \
        --network "container:$target" --cap-add=NET_ADMIN --cap-add=NET_RAW \
        -v "$WORK:/work:ro,Z" "$DEBUG_IMG" "$@"
}
in_netns_bg() {
    local target=$1; shift
    podman run -d --name "wireserve-sa-helper-$$-$RANDOM" --network "container:$target" \
        -v "$PWD/deploy/e2e:/e2e:ro" -v "$WORK:/work:Z" "$DEBUG_IMG" "$@" >/dev/null
}
ip_on() {
    podman inspect "$1" --format "{{(index .NetworkSettings.Networks \"$2\").IPAddress}}"
}
admin() { podman exec "$COORD" wireserve-admin "$@"; }
# A field of a service's directory entry, as the client last saw it.
entry() {
    podman exec "$CLIENT" cat /var/lib/wireserve/agent-state.json | python3 -c "
import json,sys
d=json.load(sys.stdin).get('last_directory') or {}
s=next((s for s in d.get('services',[]) if s['name']=='$1'), {})
print(s.get('$2', ''))"
}
wait_for() {
    local what=$1 secs=$2; shift 2
    for _ in $(seq 1 "$secs"); do
        "$@" >/dev/null 2>&1 && return 0
        sleep 1
    done
    fail "timed out after ${secs}s waiting for: $what"
}
terminated() { [ "$(entry "$1" terminated)" = True ]; }
# Whether home's own access list says jellyfin falls back to the sign-in.
signs_in() {
    podman exec "$HOME_AGENT" cat /var/lib/wireserve/agent-state.json | python3 -c "
import json,sys
a=next((a for a in json.load(sys.stdin).get('own_access',[]) if a['name']=='$1'), {})
sys.exit(0 if a.get('sign_in') else 1)"
}
# HTTPS by name from a node, verified: headers and body, then the status
# and redirect target.
fetch_from() {
    local from=$1 host=$2; shift 2
    local vip
    vip=$(entry "$host" vip4)
    in_netns "$from" curl -s --max-time 10 --cacert /work/pebble-root.pem \
        --resolve "$host.$DOMAIN:443:$vip" -D - "$@" "https://$host.$DOMAIN/" \
        -w '\nSTATUS %{http_code} %{redirect_url}\n'
}
fetch() { fetch_from "$CLIENT" "$@"; }

log "checking prerequisites"
command -v podman >/dev/null || fail "podman not found on PATH"
command -v jq >/dev/null || fail "jq not found on PATH (reads wireserve-admin --json)"
command -v python3 >/dev/null || fail "python3 not found on PATH"
modinfo wireguard >/dev/null 2>&1 || fail "WireGuard kernel module not available"
[ "$(podman info --format '{{.Host.Security.Rootless}}')" = false ] \
    || fail "needs rootful podman (WireGuard and the firewall need the host's user namespace): sudo $0"
pass "podman, python3 and the WireGuard kernel module are present"

log "building images"
podman build -q -f deploy/docker/coordinator.Dockerfile -t wireserve-coordinator:sa-test . >/dev/null
podman build -q -f deploy/docker/agent.Dockerfile -t wireserve-agent:sa-test . >/dev/null
podman build -q -f deploy/e2e/debug-tools.Dockerfile -t "$DEBUG_IMG" deploy/e2e >/dev/null
podman pull -q "$BIND_IMG" >/dev/null
podman pull -q "$PEBBLE_IMG" >/dev/null
pass "images built"

log "BIND for $DOMAIN, Pebble validating against it"
podman network create "$NET" >/dev/null
TSIG_SECRET=$(head -c 32 /dev/urandom | base64)
mkdir -p "$WORK/bind"
cat > "$WORK/bind/named.conf" <<EOF
key "wireserve" { algorithm hmac-sha256; secret "$TSIG_SECRET"; };
options { directory "/var/cache/bind"; listen-on { any; }; listen-on-v6 { none; }; recursion no; allow-query { any; }; };
zone "$DOMAIN" {
    type primary;
    file "/var/cache/bind/$DOMAIN.zone";
    update-policy { grant wireserve subdomain $DOMAIN. ANY; };
};
EOF
cat > "$WORK/bind/$DOMAIN.zone" <<EOF
\$TTL 60
@  IN SOA ns.$DOMAIN. admin.$DOMAIN. 1 3600 600 86400 60
@  IN NS  ns.$DOMAIN.
ns IN A   192.0.2.53
EOF
chmod -R a+rwX "$WORK/bind"
podman run -d --name "$BIND" --network "$NET" \
    -v "$WORK/bind/named.conf:/etc/bind/named.conf:ro,Z" -v "$WORK/bind:/var/cache/bind:Z" \
    --entrypoint /usr/sbin/named "$BIND_IMG" -g -c /etc/bind/named.conf >/dev/null
sleep 2
BIND_IP=$(ip_on "$BIND" "$NET")
podman run -d --name "$PEBBLE" --network "$NET" --network-alias pebble \
    -e PEBBLE_VA_NOSLEEP=1 -e PEBBLE_WFE_NONCEREJECT=0 \
    "$PEBBLE_IMG" -config test/config/pebble-config.json -dnsserver "$BIND_IP:53" >/dev/null
sleep 2
podman cp "$PEBBLE:/test/certs/pebble.minica.pem" "$WORK/pebble-minica.pem" \
    || fail "could not copy Pebble's listener CA out of its image"
pass "BIND at $BIND_IP, Pebble at https://pebble:14000/dir"

log "coordinator: records, certificates, and 'auth' as the sign-in"
podman run -d --name "$COORD" --network "$NET" \
    -e WIRESERVE_ADMIN_TOKEN="$ADMIN_TOKEN" \
    -e WIRESERVE_REQUIRE_SERVICE_APPROVAL=false \
    -e WIRESERVE_SERVICE_DOMAIN="$DOMAIN" \
    -e WIRESERVE_DNS_PROVIDER=rfc2136 -e WIRESERVE_DNS_SERVER="$BIND_IP:53" \
    -e WIRESERVE_DNS_TSIG_KEY_NAME=wireserve -e WIRESERVE_DNS_TSIG_SECRET="$TSIG_SECRET" \
    -e WIRESERVE_DNS_TTL=60 \
    -e WIRESERVE_ACME_DIRECTORY=https://pebble:14000/dir -e WIRESERVE_ACME_PROPAGATION_SECS=0 \
    -e WIRESERVE_AUTH_SERVICE=auth -e WIRESERVE_AUTH_NODE=node-gate \
    wireserve-coordinator:sa-test >/dev/null
sleep 2
COORD_IP=$(ip_on "$COORD" "$NET")

for c in "$GATE" "$HOME_AGENT" "$CLIENT"; do
    podman run -d --name "$c" --network "$NET" \
        --cap-add=NET_ADMIN --security-opt unmask=/proc/sys --device /dev/net/tun \
        --entrypoint sleep wireserve-agent:sa-test infinity >/dev/null
done
# Pebble issues from a root made at start: every terminator trusts it for the
# sign-in check, as a public CA's root is trusted without asking.
in_netns "$COORD" curl -sk --max-time 10 https://pebble:15000/roots/0 > "$WORK/pebble-root.pem"
grep -q 'BEGIN CERTIFICATE' "$WORK/pebble-root.pem" || fail "could not fetch Pebble's issuing root"
for c in "$GATE" "$HOME_AGENT"; do
    podman cp "$WORK/pebble-minica.pem" "$c:/etc/pebble-minica.pem"
    podman cp "$WORK/pebble-root.pem" "$c:/etc/pebble-root.pem"
done

log "joining the three agents; gate and home run their terminators"
for pair in "$GATE:node-gate" "$HOME_AGENT:node-home" "$CLIENT:node-client"; do
    c=${pair%%:*}; n=${pair#*:}
    jt=$(admin node create "$n" | grep -oE 'jtk_[a-f0-9]+')
    podman exec "$c" wireserve join "http://$COORD_IP:47820" --allow-plaintext-http "$jt" \
        --listen-port "$WG_PORT" --endpoint "$(ip_on "$c" "$NET"):$WG_PORT" 2>/dev/null
    podman exec -d "$c" sh -c 'wireserve daemon --poll-interval-secs 3 >/var/log/agent.log 2>&1'
done
for c in "$GATE" "$HOME_AGENT"; do
    podman exec -d "$c" sh -c 'WIRESERVE_ACME_CA_FILE=/etc/pebble-minica.pem WIRESERVE_TLS_TRUST_FILE=/etc/pebble-root.pem \
        wireserve tls-daemon --state-dir /var/lib/wireserve-tls >>/var/log/tls.log 2>&1'
done
podman exec "$GATE" wireserve auth 443:8080
in_netns_bg "$GATE" socat "TCP-LISTEN:8080,fork,reuseaddr" EXEC:/e2e/auth-stub.sh
podman exec "$HOME_AGENT" wireserve jellyfin 443:8096 8920:8920
podman exec "$HOME_AGENT" wireserve grafana 443:3000 3001:3001
for port in 8096 8920 3000 3001; do
    in_netns_bg "$HOME_AGENT" socat "TCP-LISTEN:$port,fork,reuseaddr" EXEC:"/e2e/echo-backend.sh $port"
done

log "1/10: all three terminated; jellyfin in media, for tag:tv and oidc:family"
for s in auth jellyfin grafana; do
    wait_for "$s to be terminated" 120 terminated "$s"
done
admin group create media
admin group add media jellyfin
admin grant add oidc:family media
admin grant add tag:tv media
admin tag add node-gate tv
if admin group add media auth 2>/dev/null; then
    fail "the sign-in service was put in a group"
fi
admin service list --json | jq -e '.services[] | select(.name == "jellyfin") | .groups | index("media")' >/dev/null \
    || fail "service list does not show jellyfin in media"
wait_for "home to fall back to the sign-in for jellyfin" 30 signs_in jellyfin
# The terminator picks it up on its next check-in.
sleep 8
pass "auth, jellyfin and grafana served by their own nodes; jellyfin restricted"

log "2/10: no session, sent to sign in"
OUT=$(fetch jellyfin) || true
echo "$OUT" | tail -1
echo "$OUT" | grep -q '^STATUS 302 https://auth.int.test/login' || { echo "$OUT"; fail "expected a redirect to the login URL"; }
echo "$OUT" | grep -q 'backend:' && fail "the backend was reached without a session"
pass "redirected to the login URL; the backend never saw the request"

log "3/10: signed in with family, the backend sees who, and not the cookie"
OUT=$(fetch jellyfin -H 'Cookie: theme=dark; authward_session=ok; lang=de' -H 'X-Auth-User: mallory') || true
echo "$OUT" | sed 's/^/  /'
echo "$OUT" | grep -q '^STATUS 200' || fail "a signed-in request did not reach the backend"
echo "$OUT" | grep -q 'backend:8096' || fail "the wrong backend answered"
echo "$OUT" | grep -qi '^x-auth-user: alice' || fail "the backend did not get the identity header"
echo "$OUT" | grep -qi '^x-auth-groups: family' || fail "the backend did not get the groups header"
echo "$OUT" | grep -qi 'mallory' && fail "a forged X-Auth-User reached the backend"
echo "$OUT" | grep -q 'authward_session' && fail "the sign-in cookie reached the backend"
echo "$OUT" | grep -qi '^cookie: .*theme=dark' || fail "other cookies were lost"
pass "X-Auth-User: alice, groups family; mallory and authward_session gone; theme kept"

log "4/10: signed in without a granted group: 403"
OUT=$(fetch jellyfin -H 'Cookie: authward_session=guest') || true
echo "$OUT" | tail -1
echo "$OUT" | grep -q '^STATUS 403' || { echo "$OUT"; fail "a guest was not refused"; }
echo "$OUT" | grep -q 'backend:' && fail "a guest reached the backend"
pass "bob (guests) refused with 403"

log "4b/10: a signed-in answer is reused while the provider allows it"
asked() { wc -l < "$WORK/verify.count" 2>/dev/null || echo 0; }
BEFORE=$(asked)
for _ in 1 2 3; do
    OUT=$(fetch jellyfin -H 'Cookie: authward_session=ok; n=cache') || true
    echo "$OUT" | grep -q '^STATUS 200' || { echo "$OUT"; fail "a signed-in request failed"; }
done
[ "$(( $(asked) - BEFORE ))" -eq 1 ] || fail "three requests with one cookie asked the provider $(( $(asked) - BEFORE )) times"
OUT=$(fetch jellyfin -H 'Cookie: authward_session=guest; n=cache') || true
echo "$OUT" | grep -q '^STATUS 403' || { echo "$OUT"; fail "another cookie got the cached answer"; }
pass "three requests, one /verify; another cookie is asked about afresh"

log "5/10: the tagged device gets in without signing in"
OUT=$(fetch_from "$GATE" jellyfin -H 'X-Auth-User: mallory') || true
echo "$OUT" | tail -1
echo "$OUT" | grep -q '^STATUS 200' || { echo "$OUT"; fail "the tagged gate was asked to sign in"; }
echo "$OUT" | grep -q 'backend:8096' || fail "the wrong backend answered"
echo "$OUT" | grep -qi 'mallory' && fail "a forged X-Auth-User reached the backend from a granted device"
pass "node-gate (tag tv) reached jellyfin with no session"

log "6/10: a service in default needs no sign-in, and loses the cookie too"
OUT=$(fetch grafana -H 'Cookie: authward_session=ok; theme=dark' -H 'X-Auth-User: mallory') || true
echo "$OUT" | grep -q '^STATUS 200' || { echo "$OUT"; fail "grafana asked for a sign-in"; }
echo "$OUT" | grep -q 'authward_session' && { echo "$OUT"; fail "the sign-in cookie reached grafana"; }
echo "$OUT" | grep -qi 'mallory' && { echo "$OUT"; fail "a forged X-Auth-User reached grafana"; }
pass "grafana served without a sign-in, without the cookie or a forged identity"

log "7/10: jellyfin's other port follows the grants"
JF_VIP=$(entry jellyfin vip4); GF_VIP=$(entry grafana vip4)
in_netns "$CLIENT" curl -s --max-time 6 "http://$GF_VIP:3001/" | grep -q 'backend:3001' \
    || fail "grafana's other port is unreachable — the next check would prove nothing"
if in_netns "$CLIENT" curl -s --max-time 6 "http://$JF_VIP:8920/" | grep -q 'backend:'; then
    fail "the client reached jellyfin's other port, around the sign-in"
fi
in_netns "$GATE" curl -s --max-time 6 "http://$JF_VIP:8920/" | grep -q 'backend:8920' \
    || fail "the granted gate could not reach jellyfin's other port"
pass "8920: the gate gets in, the client does not"

log "8/10: a request naming another host is misdirected"
OUT=$(fetch jellyfin -H "Host: grafana.$DOMAIN" -H 'Cookie: authward_session=ok') || true
echo "$OUT" | tail -1
echo "$OUT" | grep -q '^STATUS 421' || { echo "$OUT"; fail "a foreign Host was not refused with 421"; }
echo "$OUT" | grep -q 'backend:' && { echo "$OUT"; fail "a foreign Host reached a backend"; }
pass "Host: grafana on jellyfin's address: 421, no backend"

log "9/10: a provider on another node is not the provider"
podman exec "$GATE" wireserve auth off
auth_gone() { [ -z "$(entry auth name)" ]; }
wait_for "auth to leave the directory" 30 auth_gone
podman exec "$HOME_AGENT" wireserve auth 443:8081
in_netns_bg "$HOME_AGENT" socat "TCP-LISTEN:8081,fork,reuseaddr" EXEC:/e2e/impostor-stub.sh
held_by_home() { [ "$(entry auth node)" = node-home ] && terminated auth; }
wait_for "home's auth to be terminated" 120 held_by_home
sleep 8
OUT=$(fetch jellyfin -H 'Cookie: authward_session=ok') || true
echo "$OUT" | tail -1
echo "$OUT" | grep -qi 'impostor' && { echo "$OUT"; fail "the impostor's answer let the request in"; }
echo "$OUT" | grep -q 'backend:' && { echo "$OUT"; fail "jellyfin was reached through the impostor"; }
echo "$OUT" | grep -q '^STATUS 503' || { echo "$OUT"; fail "expected jellyfin to refuse with no provider"; }
pass "auth declared by node-home is ignored; jellyfin refuses with 503"

log "10/10: out of its group, jellyfin is back in default"
admin group remove media jellyfin | grep -q 'back in default' || fail "the admin was not told jellyfin is in default again"
wait_for "jellyfin without a sign-in" 60 sh -c "podman run --rm --network container:$CLIENT -v $WORK:/work:ro,Z $DEBUG_IMG curl -s --max-time 5 --cacert /work/pebble-root.pem --resolve jellyfin.$DOMAIN:443:$JF_VIP https://jellyfin.$DOMAIN/ | grep -q backend:8096"
wait_for "jellyfin's other port back" 30 sh -c "podman run --rm --network container:$CLIENT $DEBUG_IMG curl -s --max-time 3 http://$JF_VIP:8920/ | grep -q backend:8920"
pass "in default again: no sign-in, and 8920 reachable"

echo
echo "=== SERVICE AUTH TEST COMPLETE ==="

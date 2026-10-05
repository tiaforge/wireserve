#!/usr/bin/env bash
# wireserve sign-in test (PLAN.md M36, M48): who gets into a restricted
# service, decided by the service's own terminator — by device first, then
# by the groups a person signs in with, at the coordinator, through the
# same identity provider client device owners use.
#
# jellyfin is in group `media`, granted to `tag:tv` (the gate node) and to
# `oidc:family` (whoever signs in with that group). The client is untagged:
# a shared device, whose people get in by signing in. What this proves,
# against real WireGuard, a real ACME CA (Pebble), real DNS (BIND) and a
# real OpenID Connect provider (mock-oauth2-server):
#
#   1. both services are served with TLS by their own node, and jellyfin's
#      node falls back to the sign-in;
#   2. without a session the browser is sent to the coordinator's sign-in,
#      and the backend never sees the request;
#   3. alice signs in at the provider with `family` and lands back on
#      jellyfin: the backend sees who she is, not a forged X-Auth-User, not
#      the session cookie — other cookies kept;
#   4. bob, signed in with another group, is told so by the coordinator and
#      never handed a ticket; jellyfin's backend is untouched; and a ticket
#      someone opens in another browser than their own signs nobody in;
#   5. the tagged gate gets in without any session: its device is granted;
#   6. grafana, still in `default`, needs no sign-in, and a session cookie
#      or a forged identity sent to it never reaches its backend;
#   7. jellyfin's other port admits the granted gate and refuses the client;
#   8. a request to jellyfin's address naming another host gets 421;
#   9. alice's jellyfin session is jellyfin's alone: sent to grafana, once
#      that is restricted too, it gets her sent to sign in;
#  10. past the refresh interval her session is renewed in place, `owner
#      status` lists her, and signing out at jellyfin ends it;
#  11. taking jellyfin out of `media` puts it back in `default`.
#
#     ( net )──┬──────────┬───────┬────────┬────────┬──────────────┬──────────────────┬──────────┐
#          [coordinator] [bind] [pebble] [mock    [gate agent    [home agent        [client agent]
#                                         oidc]    tag tv]        jellyfin 443:8096
#                                                                 + 8920 (media)
#                                                                 grafana 443:3000
#                                                                 + 3001 (default)]
#
# curl in the client's network plays the browser, a cookie jar per person.
#
# Rootful Podman, like the other harnesses that run WireGuard.
#
# Usage: sudo ./deploy/e2e/run-service-auth-test.sh
# Exit code 0 = every check passed.

set -euo pipefail
cd "$(dirname "$0")/../.."
. deploy/e2e/lib.sh

NET=wireserve-sa-net
COORD=wireserve-sa-coord
BIND=wireserve-sa-bind
PEBBLE=wireserve-sa-pebble
MOCK=wireserve-sa-mock
GATE=wireserve-sa-gate
HOME_AGENT=wireserve-sa-home
CLIENT=wireserve-sa-client
DEBUG_IMG=wireserve-e2e-debug-tools
BIND_IMG=docker.io/internetsystemsconsortium/bind9:9.20
PEBBLE_IMG=ghcr.io/letsencrypt/pebble:latest
MOCK_IMG=ghcr.io/navikt/mock-oauth2-server:latest
ADMIN_TOKEN=service-auth-test-admin-token
DOMAIN=int.test
WG_PORT=51820
# The coordinator by name, which curl is told the address of (--resolve);
# the provider by address, its issuer being the address it is asked on.
PUBLIC=http://coord:47820
ISSUER=""
COORD_IP=""
# The refresh interval, at its shortest: a session token lasts this long.
REFRESH=60

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
    podman logs --tail 40 "$COORD" >&2 2>/dev/null || true
    exit 1
}

cleanup() {
    podman rm -fv -t 0 "$COORD" "$BIND" "$PEBBLE" "$MOCK" "$GATE" "$HOME_AGENT" "$CLIENT" >/dev/null 2>&1 || true
    for c in $(podman ps -aq --filter "name=wireserve-sa-helper" 2>/dev/null); do
        podman rm -fv -t 0 "$c" >/dev/null 2>&1 || true
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
        -v "$WORK:/work:Z" "$DEBUG_IMG" "$@"
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
wait_until() {
    local what=$1 secs=$2; shift 2
    for _ in $(seq 1 "$secs"); do
        "$@" >/dev/null 2>&1 && return 0
        sleep 1
    done
    fail "timed out after ${secs}s waiting for: $what"
}
terminated() { [ "$(entry "$1" terminated)" = True ]; }
# Whether home's own access list says a service falls back to the sign-in.
signs_in() {
    podman exec "$HOME_AGENT" cat /var/lib/wireserve/agent-state.json | python3 -c "
import json,sys
a=next((a for a in json.load(sys.stdin).get('own_access',[]) if a['name']=='$1'), {})
sys.exit(0 if a.get('sign_in') else 1)"
}
# HTTPS by name from a node, verified, with no cookies: headers and body,
# then the status and redirect target.
fetch_from() {
    local from=$1 host=$2; shift 2
    local vip
    vip=$(entry "$host" vip4)
    in_netns "$from" curl -s --max-time 10 --cacert /work/pebble-root.pem \
        --resolve "$host.$DOMAIN:443:$vip" -D - "$@" "https://$host.$DOMAIN/" \
        -w '\nSTATUS %{http_code} %{redirect_url}\n'
}
fetch() { fetch_from "$CLIENT" "$@"; }
# A browser on the client for one person: a cookie jar of their own, and
# every name it needs resolved — the coordinator, both services.
browser() {
    local who=$1; shift
    in_netns "$CLIENT" curl -sS --max-time 15 --cacert /work/pebble-root.pem \
        --resolve "coord:47820:$COORD_IP" \
        --resolve "jellyfin.$DOMAIN:443:$(entry jellyfin vip4)" \
        --resolve "grafana.$DOMAIN:443:$(entry grafana vip4)" \
        -b "/work/jar-$who" -c "/work/jar-$who" "$@"
}
# Signs `who` in at the provider with `groups`, starting from jellyfin's
# redirect, up to the coordinator's last answer: its status and where it
# sends the browser (a ticket for jellyfin, when it admits them).
to_ticket() {
    local who=$1 groups=$2 start auth callback
    : > "$WORK/jar-$who"
    start=$(browser "$who" -o /dev/null -w '%{redirect_url}' "https://jellyfin.$DOMAIN/") \
        || fail "$who: jellyfin did not answer"
    case "$start" in "$PUBLIC/sign-in?service=jellyfin.$DOMAIN&to=%2F&bind="*) ;; *) fail "$who: not sent to sign in: '$start'" ;; esac
    grep -q '__Host-wireserve-bind' "$WORK/jar-$who" || fail "$who: jellyfin set no bind cookie"
    auth=$(browser "$who" -o "/work/start-$who.html" -w '%{redirect_url}' "$start") || fail "$who: the coordinator did not answer"
    case "$auth" in "$ISSUER/authorize?"*) ;; *) cat "$WORK/start-$who.html" >&2; fail "$who: not sent to the provider: '$auth'" ;; esac
    callback=$(browser "$who" -o "/work/login-$who.html" -w '%{redirect_url}' --data-urlencode "username=$who" \
        --data-urlencode "claims={\"groups\":[$groups],\"email\":\"$who@example.com\",\"email_verified\":true}" "$auth") \
        || fail "$who: the provider's login form failed"
    case "$callback" in "$PUBLIC/oidc/callback?"*) ;; *) cat "$WORK/login-$who.html" >&2; fail "$who: the provider did not send the browser back: '$callback'" ;; esac
    browser "$who" -o "/work/landed-$who.html" -w '%{http_code} %{redirect_url}' "$callback"
}
# Signs `who` in to jellyfin with `groups`, to the page the browser ends on:
# its status and URL.
sign_in() {
    local who=$1 answer
    answer=$(to_ticket "$@")
    case "$answer" in
        "302 https://jellyfin.$DOMAIN/.wireserve/callback?ticket="*)
            browser "$who" -L -o "/work/landed-$who.html" -w '%{http_code} %{url_effective}' "${answer#302 }" ;;
        *) echo "$answer $(grep -o 'not for any of your groups' "$WORK/landed-$who.html" || true)" ;;
    esac
}

log "checking prerequisites"
command -v podman >/dev/null || fail "podman not found on PATH"
command -v jq >/dev/null || fail "jq not found on PATH (reads wireserve-admin --json)"
command -v python3 >/dev/null || fail "python3 not found on PATH"
modinfo wireguard >/dev/null 2>&1 || fail "WireGuard kernel module not available"
[ "$(podman info --format '{{.Host.Security.Rootless}}')" = false ] \
    || fail "needs rootful podman (WireGuard and the firewall need the host's user namespace): sudo $0"
pass "podman, python3 and the WireGuard kernel module are present"

log "building images"
./deploy/e2e/build.sh
podman pull -q "$BIND_IMG" >/dev/null
podman pull -q "$PEBBLE_IMG" >/dev/null
podman pull -q "$MOCK_IMG" >/dev/null
pass "images built"

log "BIND for $DOMAIN, Pebble validating against it, and the identity provider"
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
podman run -d --name "$MOCK" --network "$NET" \
    -e SERVER_PORT=8080 -e JSON_CONFIG='{"interactiveLogin": true}' "$MOCK_IMG" >/dev/null
sleep 2
podman cp "$PEBBLE:/test/certs/pebble.minica.pem" "$WORK/pebble-minica.pem" \
    || fail "could not copy Pebble's listener CA out of its image"
ISSUER="http://$(ip_on "$MOCK" "$NET"):8080/default"
mock_up() { in_netns "$MOCK" curl -sf --max-time 3 "$ISSUER/.well-known/openid-configuration" >/dev/null; }
wait_until "the provider to answer" 60 mock_up
pass "BIND at $BIND_IP, Pebble at https://pebble:14000/dir, the provider at $ISSUER"

log "coordinator: records, certificates, and the provider for the sign-in"
podman run -d --name "$COORD" --network "$NET" --network-alias coord \
    -e WIRESERVE_ADMIN_TOKEN="$ADMIN_TOKEN" \
    -e WIRESERVE_REQUIRE_SERVICE_APPROVAL=false \
    -e WIRESERVE_SERVICE_DOMAIN="$DOMAIN" \
    -e WIRESERVE_DNS_PROVIDER=rfc2136 -e WIRESERVE_DNS_SERVER="$BIND_IP:53" \
    -e WIRESERVE_DNS_TSIG_KEY_NAME=wireserve -e WIRESERVE_DNS_TSIG_SECRET="$TSIG_SECRET" \
    -e WIRESERVE_DNS_TTL=60 \
    -e WIRESERVE_ACME_DIRECTORY=https://pebble:14000/dir -e WIRESERVE_ACME_PROPAGATION_SECS=0 \
    -e WIRESERVE_PUBLIC_URL="$PUBLIC" \
    -e WIRESERVE_OIDC_ISSUER="$ISSUER" -e WIRESERVE_OIDC_CLIENT_ID=wireserve \
    -e WIRESERVE_OIDC_CLIENT_SECRET=anything -e WIRESERVE_OIDC_REFRESH_SECS="$REFRESH" \
    wireserve-coordinator:e2e >/dev/null
sleep 2
COORD_IP=$(ip_on "$COORD" "$NET")

for c in "$GATE" "$HOME_AGENT" "$CLIENT"; do
    podman run -d --name "$c" --network "$NET" \
        --cap-add=NET_ADMIN --security-opt unmask=/proc/sys --security-opt apparmor=unconfined --device /dev/net/tun \
        --entrypoint sleep wireserve-agent:e2e infinity >/dev/null
done
# Pebble issues from a root made at start: the browser trusts it, as a
# public CA's root is trusted without asking.
in_netns "$COORD" curl -sk --max-time 10 https://pebble:15000/roots/0 > "$WORK/pebble-root.pem"
grep -q 'BEGIN CERTIFICATE' "$WORK/pebble-root.pem" || fail "could not fetch Pebble's issuing root"
podman cp "$WORK/pebble-minica.pem" "$HOME_AGENT:/etc/pebble-minica.pem"

log "joining the three agents; home runs its terminator"
for pair in "$GATE:node-gate" "$HOME_AGENT:node-home" "$CLIENT:node-client"; do
    c=${pair%%:*}; n=${pair#*:}
    jt=$(admin node create "$n" | grep -oE 'jtk_[a-f0-9]+')
    podman exec "$c" wireserve join "http://$COORD_IP:47820" --allow-plaintext-http "$jt" \
        --listen-port "$WG_PORT" --endpoint "$(ip_on "$c" "$NET"):$WG_PORT" 2>/dev/null
    podman exec -d "$c" sh -c 'wireserve daemon --poll-interval-secs '"$POLL"' >/var/log/agent.log 2>&1'
done
podman exec -d "$HOME_AGENT" sh -c 'WIRESERVE_ACME_CA_FILE=/etc/pebble-minica.pem \
    wireserve tls-daemon --state-dir /var/lib/wireserve-tls --check-in-secs '"$POLL"' >>/var/log/tls.log 2>&1'
podman exec "$HOME_AGENT" wireserve jellyfin 443:8096 8920:8920
podman exec "$HOME_AGENT" wireserve grafana 443:3000 3001:3001
for port in 8096 8920 3000 3001; do
    in_netns_bg "$HOME_AGENT" socat "TCP-LISTEN:$port,fork,reuseaddr" EXEC:"/e2e/echo-backend.sh $port"
done

log "1/11: both terminated; jellyfin in media, for tag:tv and oidc:family"
for s in jellyfin grafana; do
    wait_until "$s to be terminated" 120 terminated "$s"
done
admin group create media
admin group add media jellyfin
admin grant add oidc:family media
admin grant add tag:tv media
admin tag add node-gate tv
admin service list --json | jq -e '.services[] | select(.name == "jellyfin") | .groups | index("media")' >/dev/null \
    || fail "service list does not show jellyfin in media"
wait_until "home to fall back to the sign-in for jellyfin" 30 signs_in jellyfin
# The terminator picks it up on its next check-in.
wait_until "the terminator to ask for a sign-in" 30 eval 'fetch jellyfin | grep -q "^STATUS 302"'
pass "jellyfin and grafana served by their own node; jellyfin restricted"

log "2/11: no session, sent to the coordinator's sign-in"
OUT=$(fetch jellyfin) || true
echo "$OUT" | tail -1
echo "$OUT" | grep -q "^STATUS 302 $PUBLIC/sign-in?service=jellyfin.$DOMAIN&to=%2F" \
    || { echo "$OUT"; fail "expected a redirect to the coordinator's sign-in"; }
echo "$OUT" | grep -q 'backend:' && fail "the backend was reached without a session"
pass "redirected to the sign-in; the backend never saw the request"

log "3/11: alice signs in with family and lands back on jellyfin, as herself"
LANDED=$(sign_in alice '"family"')
echo "  $LANDED"
[ "$LANDED" = "200 https://jellyfin.$DOMAIN/" ] || { cat "$WORK/landed-alice.html"; fail "alice did not land on jellyfin: $LANDED"; }
grep -q 'backend:8096' "$WORK/landed-alice.html" || { cat "$WORK/landed-alice.html"; fail "the wrong backend answered"; }
grep -q '__Host-wireserve-session' "$WORK/jar-alice" || fail "the browser keeps no session cookie for jellyfin"
# Another cookie of jellyfin's own, beside the session, and a forged identity.
printf 'jellyfin.%s\tFALSE\t/\tTRUE\t0\ttheme\tdark\n' "$DOMAIN" >> "$WORK/jar-alice"
OUT=$(browser alice -D - -H 'X-Auth-User: mallory' "https://jellyfin.$DOMAIN/") || true
echo "$OUT" | sed 's/^/  /'
echo "$OUT" | grep -qi '^x-auth-user: alice' || fail "the backend did not get the identity header"
echo "$OUT" | grep -qi '^x-auth-groups: family' || fail "the backend did not get the groups header"
echo "$OUT" | grep -qi '^x-auth-email: alice@example.com' || fail "the backend did not get the e-mail header"
echo "$OUT" | grep -qi 'mallory' && fail "a forged X-Auth-User reached the backend"
echo "$OUT" | grep -q 'wireserve-session' && fail "the session cookie reached the backend"
echo "$OUT" | grep -qi '^cookie: .*theme=dark' || fail "other cookies were lost"
pass "X-Auth-User: alice, groups family; mallory and the session cookie gone; theme kept"

log "4/11: bob, signed in without a granted group, gets no ticket"
LANDED=$(sign_in bob '"guests"') || true
echo "  $LANDED"
case "$LANDED" in "403 "*"not for any of your groups") ;; *) cat "$WORK/landed-bob.html"; fail "bob was not stopped at the coordinator: $LANDED" ;; esac
grep -q '__Host-wireserve-session' "$WORK/jar-bob" && fail "bob got a session cookie for jellyfin"
pass "bob (guests) told jellyfin is not for him; no ticket, no cookie"

log "4b/11: a ticket handed to another browser signs nobody in"
ANSWER=$(to_ticket mallory '"family"')
case "$ANSWER" in "302 https://jellyfin.$DOMAIN/.wireserve/callback?ticket="*) ;; *) fail "mallory got no ticket: $ANSWER" ;; esac
: > "$WORK/jar-victim"
GOT=$(browser victim -o "/work/victim.html" -w '%{http_code}' "${ANSWER#302 }") || true
[ "$GOT" = 403 ] || { cat "$WORK/victim.html"; fail "another browser redeemed mallory's ticket: $GOT"; }
grep -q 'wireserve-session' "$WORK/jar-victim" && fail "the other browser got mallory's session"
GOT=$(browser mallory -o /dev/null -w '%{http_code}' "${ANSWER#302 }") || true
[ "$GOT" != 302 ] || fail "the ticket worked again after another browser had tried it"
pass "mallory's ticket, opened in another browser: 403, no session — and used up"

log "5/11: the tagged device gets in without signing in"
OUT=$(fetch_from "$GATE" jellyfin -H 'X-Auth-User: mallory') || true
echo "$OUT" | tail -1
echo "$OUT" | grep -q '^STATUS 200' || { echo "$OUT"; fail "the tagged gate was asked to sign in"; }
echo "$OUT" | grep -q 'backend:8096' || fail "the wrong backend answered"
echo "$OUT" | grep -qi 'mallory' && fail "a forged X-Auth-User reached the backend from a granted device"
pass "node-gate (tag tv) reached jellyfin with no session"

log "6/11: a service in default needs no sign-in, and never sees a session cookie"
ALICE_TOKEN=$(awk '$6 == "__Host-wireserve-session" {print $7}' "$WORK/jar-alice" | tail -1)
[ -n "$ALICE_TOKEN" ] || fail "no session token in alice's jar"
OUT=$(fetch grafana -H "Cookie: __Host-wireserve-session=$ALICE_TOKEN; theme=dark" -H 'X-Auth-User: mallory') || true
echo "$OUT" | grep -q '^STATUS 200' || { echo "$OUT"; fail "grafana asked for a sign-in"; }
echo "$OUT" | grep -q 'wireserve-session' && { echo "$OUT"; fail "the session cookie reached grafana"; }
echo "$OUT" | grep -qi 'mallory' && { echo "$OUT"; fail "a forged X-Auth-User reached grafana"; }
pass "grafana served without a sign-in, without the cookie or a forged identity"

log "7/11: jellyfin's other port follows the grants"
JF_VIP=$(entry jellyfin vip4); GF_VIP=$(entry grafana vip4)
in_netns "$CLIENT" curl -s --max-time 6 "http://$GF_VIP:3001/" | grep -q 'backend:3001' \
    || fail "grafana's other port is unreachable — the next check would prove nothing"
if in_netns "$CLIENT" curl -s --max-time 6 "http://$JF_VIP:8920/" | grep -q 'backend:'; then
    fail "the client reached jellyfin's other port, around the sign-in"
fi
in_netns "$GATE" curl -s --max-time 6 "http://$JF_VIP:8920/" | grep -q 'backend:8920' \
    || fail "the granted gate could not reach jellyfin's other port"
pass "8920: the gate gets in, the client does not"

log "8/11: a request naming another host is misdirected"
OUT=$(browser alice -D - -H "Host: grafana.$DOMAIN" "https://jellyfin.$DOMAIN/" -w '\nSTATUS %{http_code}\n') || true
echo "$OUT" | tail -1
echo "$OUT" | grep -q '^STATUS 421' || { echo "$OUT"; fail "a foreign Host was not refused with 421"; }
echo "$OUT" | grep -q 'backend:' && { echo "$OUT"; fail "a foreign Host reached a backend"; }
pass "Host: grafana on jellyfin's address: 421, no backend"

log "9/11: a session is good at its own service only"
admin group add media grafana
wait_until "grafana to fall back to the sign-in" 30 signs_in grafana
wait_until "grafana's terminator to ask for a sign-in" 30 eval 'fetch grafana | grep -q "^STATUS 302"'
OUT=$(fetch grafana -H "Cookie: __Host-wireserve-session=$ALICE_TOKEN") || true
echo "$OUT" | tail -1
echo "$OUT" | grep -q "^STATUS 302 $PUBLIC/sign-in?service=grafana.$DOMAIN" \
    || { echo "$OUT"; fail "jellyfin's session got into grafana"; }
echo "$OUT" | grep -q 'backend:' && fail "grafana's backend was reached with jellyfin's session"
admin group remove media grafana >/dev/null
pass "alice's jellyfin cookie, sent to grafana, sends her to sign in there"

log "10/11: past the refresh interval the session is renewed; signing out ends it"
sleep $((REFRESH + 5))
OUT=$(browser alice -D - "https://jellyfin.$DOMAIN/" -w '\nSTATUS %{http_code}\n') || true
echo "$OUT" | grep -q '^STATUS 200' || { echo "$OUT"; fail "the session was not renewed"; }
echo "$OUT" | grep -qi '^set-cookie: __Host-wireserve-session=wst1\.' || { echo "$OUT"; fail "no renewed token came back"; }
echo "$OUT" | grep -qi '^x-auth-user: alice' || fail "the renewed session is not alice's"
podman logs "$COORD" 2>&1 | grep -E 'session_ended|session refresh failed' && fail "renewing alice's session failed"
admin owner status | tee "$WORK/status.out"
grep -q 'sign-in.*on: web services ask' "$WORK/status.out" || fail "owner status does not say the sign-in is on"
grep -qE '^alice@example.com +family' "$WORK/status.out" || fail "owner status does not list alice as signed in"
OUT=$(browser alice -D - -X POST -H "Origin: https://jellyfin.$DOMAIN" -H 'Sec-Fetch-Site: same-origin' \
    "https://jellyfin.$DOMAIN/.wireserve/sign-out" -w '\nSTATUS %{http_code} %{redirect_url}\n') || true
echo "$OUT" | tail -1
echo "$OUT" | grep -q "^STATUS 303 $PUBLIC/signed-out" || { echo "$OUT"; fail "signing out did not go on to the coordinator"; }
OUT=$(browser alice -o /dev/null "https://jellyfin.$DOMAIN/" -w 'STATUS %{http_code} %{redirect_url}') || true
echo "  $OUT"
case "$OUT" in "STATUS 302 $PUBLIC/sign-in?"*) ;; *) fail "after signing out, jellyfin still let alice in: $OUT" ;; esac
admin owner status | grep -q 'alice@example.com' && fail "owner status still lists alice as signed in"
pass "renewed after ${REFRESH}s; signed out, she is asked to sign in again"

log "11/11: out of its group, jellyfin is back in default"
admin group remove media jellyfin | grep -q 'back in default' || fail "the admin was not told jellyfin is in default again"
wait_until "jellyfin without a sign-in" 60 sh -c "podman run --rm --network container:$CLIENT -v $WORK:/work:ro,Z $DEBUG_IMG curl -s --max-time 5 --cacert /work/pebble-root.pem --resolve jellyfin.$DOMAIN:443:$JF_VIP https://jellyfin.$DOMAIN/ | grep -q backend:8096"
wait_until "jellyfin's other port back" 30 sh -c "podman run --rm --network container:$CLIENT $DEBUG_IMG curl -s --max-time 3 http://$JF_VIP:8920/ | grep -q backend:8920"
pass "in default again: no sign-in, and 8920 reachable"

echo
echo "=== SERVICE AUTH TEST COMPLETE ==="

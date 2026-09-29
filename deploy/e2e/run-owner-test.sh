#!/usr/bin/env bash
# WireServe device owners test (PLAN.md M38): a person claims a device with
# an admin's link, through a real OpenID Connect provider, and the device
# then reaches what their groups are granted.
#
#     ( net )──┬──────────┬────────┬──────────────┬──────────────┬─────────┐
#          [coordinator] [mock    [home agent    [laptop agent  [tv agent]
#                         oidc]    db 5432,       (claimed by
#                                  group infra]   alice, family)]
#
# The provider is navikt's mock-oauth2-server with its login form: whoever
# "signs in" says who they are and which claims they carry. curl, in the
# laptop's network, plays the browser.
#
# What this proves:
#
#   1. a claim link from `claim-url` leads to the provider's sign-in, and
#      back to a confirmation page naming the node;
#   2. confirming makes alice the laptop's owner, and `oidc:family -> infra`
#      lets the laptop reach db — while the unclaimed tv is refused;
#   3. the link works once;
#   4. the coordinator refreshes alice's groups with her refresh token and
#      keeps her as the owner;
#   5. `owner clear` takes it all away again.
#
# Rootful Podman, like the other harnesses that rewrite service addresses.
#
# Usage: sudo ./deploy/e2e/run-owner-test.sh
# Exit code 0 = every check passed.

set -euo pipefail
cd "$(dirname "$0")/../.."

NET=wireserve-ow-net
COORD=wireserve-ow-coord
MOCK=wireserve-ow-mock
HOME_AGENT=wireserve-ow-home
LAPTOP=wireserve-ow-laptop
TV=wireserve-ow-tv
DEBUG_IMG=wireserve-e2e-debug-tools
MOCK_IMG=ghcr.io/navikt/mock-oauth2-server:latest
ADMIN_TOKEN=owner-test-admin-token
WG_PORT=51820
PUBLIC=http://coord:47820
ISSUER=http://mock:8080/default
WORK=""

log()  { echo; echo "=== $* ==="; }
pass() { echo "PASS: $*"; }
fail() {
    echo "FAIL: $*" >&2
    echo "--- $COORD (tail) ---" >&2
    podman logs --tail 40 "$COORD" >&2 2>/dev/null || true
    exit 1
}

cleanup() {
    podman rm -f "$COORD" "$MOCK" "$HOME_AGENT" "$LAPTOP" "$TV" >/dev/null 2>&1 || true
    for c in $(podman ps -aq --filter "name=wireserve-ow-helper" 2>/dev/null); do
        podman rm -f "$c" >/dev/null 2>&1 || true
    done
    podman network rm "$NET" >/dev/null 2>&1 || true
    if [ -n "$WORK" ]; then rm -rf "$WORK"; fi
}
trap cleanup EXIT
cleanup
WORK=$(mktemp -d)

in_netns() {
    local target=$1; shift
    podman run --rm --name "wireserve-ow-helper-$$-$RANDOM" \
        --network "container:$target" --cap-add=NET_ADMIN -v "$WORK:/work:Z" "$DEBUG_IMG" "$@"
}
in_netns_bg() {
    local target=$1; shift
    podman run -d --name "wireserve-ow-helper-$$-$RANDOM" --network "container:$target" "$DEBUG_IMG" "$@" >/dev/null
}
ip_on() {
    podman inspect "$1" --format "{{(index .NetworkSettings.Networks \"$2\").IPAddress}}"
}
admin() { podman exec "$COORD" wireserve-admin "$@"; }
vip_of() { podman exec "$LAPTOP" getent hosts "$1.wg" | awk '{print $1}'; }
ask() { in_netns "$1" sh -c "echo hi | timeout 8 socat -t3 - TCP:$(vip_of db):5432" 2>/dev/null || true; }
reaches() { [ -n "$(ask "$1")" ]; }
refused() { [ -z "$(ask "$1")" ]; }
wait_for() {
    local what=$1 secs=$2; shift 2
    for _ in $(seq 1 "$secs"); do
        "$@" >/dev/null 2>&1 && return 0
        sleep 1
    done
    fail "timed out after ${secs}s waiting for: $what"
}
# The browser: curl in the laptop's network, with a cookie jar.
browser() { in_netns "$LAPTOP" curl -s --max-time 15 -b /work/jar -c /work/jar "$@"; }

log "checking prerequisites"
command -v podman >/dev/null || fail "podman not found on PATH"
modinfo wireguard >/dev/null 2>&1 || fail "WireGuard kernel module not available"
[ "$(podman info --format '{{.Host.Security.Rootless}}')" = false ] \
    || fail "needs rootful podman (service-address rewrites are refused in a user namespace): sudo $0"
pass "podman and the WireGuard kernel module are present"

log "building images"
podman build -q -f deploy/docker/coordinator.Dockerfile -t wireserve-coordinator:ow-test . >/dev/null
podman build -q -f deploy/docker/agent.Dockerfile -t wireserve-agent:ow-test . >/dev/null
podman build -q -f deploy/e2e/debug-tools.Dockerfile -t "$DEBUG_IMG" deploy/e2e >/dev/null
podman pull -q "$MOCK_IMG" >/dev/null
pass "images built"

log "the identity provider, and a coordinator using it"
podman network create --internal "$NET" >/dev/null
podman run -d --name "$MOCK" --network "$NET" --network-alias mock \
    -e SERVER_PORT=8080 -e JSON_CONFIG='{"interactiveLogin": true}' "$MOCK_IMG" >/dev/null
podman run -d --name "$COORD" --network "$NET" --network-alias coord \
    -e WIRESERVE_ADMIN_TOKEN="$ADMIN_TOKEN" -e WIRESERVE_REQUIRE_SERVICE_APPROVAL=false \
    -e WIRESERVE_PUBLIC_URL="$PUBLIC" \
    -e WIRESERVE_OIDC_ISSUER="$ISSUER" -e WIRESERVE_OIDC_CLIENT_ID=wireserve \
    -e WIRESERVE_OIDC_CLIENT_SECRET=anything -e WIRESERVE_OIDC_REFRESH_SECS=60 \
    wireserve-coordinator:ow-test >/dev/null
sleep 3
COORD_IP=$(ip_on "$COORD" "$NET")

log "joining home, laptop and tv"
for pair in "$HOME_AGENT:node-home" "$LAPTOP:node-laptop" "$TV:node-tv"; do
    c=${pair%%:*}; n=${pair#*:}
    podman run -d --name "$c" --network "$NET" \
        --cap-add=NET_ADMIN --security-opt unmask=/proc/sys --device /dev/net/tun \
        --entrypoint sleep wireserve-agent:ow-test infinity >/dev/null
    jt=$(admin create-node "$n" 2>/dev/null | grep -oE 'jtk_[a-f0-9]+')
    podman exec "$c" wireserve join "http://$COORD_IP:47820" --allow-plaintext-http "$jt" \
        --listen-port "$WG_PORT" --endpoint-addr "$(ip_on "$c" "$NET"):$WG_PORT" 2>/dev/null
    podman exec -d "$c" sh -c 'wireserve daemon --poll-interval-secs 3 >/var/log/agent.log 2>&1'
done
admin group create infra
admin grant add oidc:family infra
podman exec "$HOME_AGENT" wireserve serve db 5432 --group infra
in_netns_bg "$HOME_AGENT" socat TCP-LISTEN:5432,fork,reuseaddr EXEC:cat
wait_for "db to resolve on the laptop" 60 sh -c "podman exec $LAPTOP getent hosts db.wg"
wait_for "db to resolve on the tv" 60 sh -c "podman exec $TV getent hosts db.wg"
sleep 6
refused "$LAPTOP" || fail "the laptop reached db before anyone claimed it"
refused "$TV" || fail "the tv reached db"
pass "db is in infra; nobody but home reaches it"

log "1/5: the claim link leads through the provider to a confirmation"
URL=$(admin claim-url node-laptop 2>&1 | grep -oE "$PUBLIC/claim/clm_[0-9a-f]+")
[ -n "$URL" ] || fail "claim-url printed no link"
AUTH=$(browser -o /dev/null -w '%{redirect_url}' "$URL")
case "$AUTH" in "$ISSUER/authorize?"*) ;; *) fail "the link did not lead to the provider: '$AUTH'" ;; esac
CALLBACK=$(browser -o /dev/null -w '%{redirect_url}' --data-urlencode username=alice \
    --data-urlencode 'claims={"groups":["family"],"email":"alice@example.com"}' "$AUTH")
case "$CALLBACK" in "$PUBLIC/claim/callback?"*) ;; *) fail "the provider did not send the browser back: '$CALLBACK'" ;; esac
browser "$CALLBACK" > "$WORK/confirm.html"
grep -q 'node-laptop' "$WORK/confirm.html" || { cat "$WORK/confirm.html"; fail "the confirmation does not name the node"; }
grep -q 'alice@example.com' "$WORK/confirm.html" || fail "the confirmation does not name who signed in"
TOKEN=$(sed -n 's/.*name="token" value="\([0-9a-f]*\)".*/\1/p' "$WORK/confirm.html")
[ -n "$TOKEN" ] || fail "no confirmation token on the page"
pass "signed in as alice; asked to confirm node-laptop"

log "2/5: confirmed, the laptop reaches what family is granted"
browser --data-urlencode "token=$TOKEN" "$PUBLIC/claim/confirm" | grep -q 'is yours now' || fail "the confirmation failed"
admin access --node node-laptop | tee "$WORK/laptop.out"
grep -q 'belongs to alice@example.com' "$WORK/laptop.out" || fail "the laptop has no owner"
grep -q 'oidc:family' "$WORK/laptop.out" || fail "the laptop does not act as oidc:family"
wait_for "the laptop to reach db" 30 reaches "$LAPTOP"
refused "$TV" || fail "the unclaimed tv reached db"
pass "node-laptop belongs to alice and reaches db; node-tv does not"

log "3/5: the link works once"
browser "$URL" | grep -q 'not valid' || fail "a used link started another sign-in"
pass "a used link is refused"

log "4/5: the owner's groups are refreshed"
refreshed() { podman logs "$COORD" 2>&1 | grep -q 'owner_refreshed'; }
wait_for "a refresh of alice's groups" 150 refreshed
podman logs "$COORD" 2>&1 | grep -E 'owner refresh failed|owner_dropped' && fail "refreshing alice's groups failed"
admin access --node node-laptop | grep -q 'belongs to alice@example.com' || fail "alice lost the laptop on refresh"
reaches "$LAPTOP" || fail "the laptop lost db on refresh"
pass "refreshed without losing anything"

log "5/5: owner clear takes it away"
admin owner clear node-laptop
wait_for "the laptop to be refused db" 30 refused "$LAPTOP"
pass "node-laptop belongs to nobody, and is refused"

echo
echo "=== OWNER TEST COMPLETE ==="

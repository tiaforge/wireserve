#!/usr/bin/env bash
# WireServe public DNS records test (PLAN.md M32), against a real BIND taking
# RFC 2136 updates signed with TSIG — the provider path `dns-update` really
# speaks, not a fake.
#
# What this proves:
#
#   1. a pending service gets no record; approving it publishes one at its
#      own address, and a 443 service's name points at the proxy's address;
#   2. `list-services` reports the record as published;
#   3. withdrawing a service removes its record;
#   4. revoking a node removes the records of every service it had;
#   5. a record the operator made by hand in the same zone is never touched,
#      and a record at a service's name is replaced (the domain is ours);
#   6. a coordinator restart with the records already written changes
#      nothing.
#
#     ( net )──┬──────────────┬──────────────┐
#          [coordinator]    [bind]     (nodes are plain HTTP calls
#                                        from the coordinator's netns)
#
# No WireGuard and no packet rewriting, so rootless podman is enough.
#
# Usage: ./deploy/e2e/run-dns-test.sh
# Exit code 0 = every check passed.

set -euo pipefail
cd "$(dirname "$0")/../.."

NET=wireserve-dns-net
COORD=wireserve-dns-coord
BIND=wireserve-dns-bind
DEBUG_IMG=wireserve-e2e-debug-tools
BIND_IMG=docker.io/internetsystemsconsortium/bind9:9.20
ADMIN_TOKEN=dns-test-admin-token
DOMAIN=int.test

log()  { echo; echo "=== $* ==="; }
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

cleanup() {
    podman rm -f "$COORD" "$BIND" >/dev/null 2>&1 || true
    for c in $(podman ps -aq --filter "name=wireserve-dns-helper" 2>/dev/null); do
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
    podman run --rm --name "wireserve-dns-helper-$$-$RANDOM" --network "container:$target" "$DEBUG_IMG" "$@"
}
ip_on() {
    podman inspect "$1" --format "{{(index .NetworkSettings.Networks \"$2\").IPAddress}}"
}
admin() { podman exec "$COORD" wireserve-admin "$@"; }
# What BIND answers for a name: the addresses, one per line, or nothing.
lookup() { in_netns "$COORD" dig +short "@$BIND_IP" "$1" A | sort; }
# `create-node`, then `/register` with a fresh key: prints the bearer token.
new_node() {
    local token pubkey
    token=$(admin create-node "$1" | sed -n 's/.*join token: //p')
    pubkey=$(head -c 32 /dev/urandom | base64)
    in_netns "$COORD" curl -sf -X POST http://127.0.0.1:47820/register \
        -H 'Content-Type: application/json' \
        -d "{\"join_token\":\"$token\",\"pubkey\":\"$pubkey\",\"listen_port\":51820}" \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["bearer_token"])'
}
# A poll declaring `services` (JSON array); prints the response.
poll() {
    in_netns "$COORD" curl -sf -X POST http://127.0.0.1:47820/poll \
        -H "Authorization: Bearer $1" -H 'Content-Type: application/json' \
        -d "{\"services\":$2}"
}
svc() { echo "{\"name\":\"$1\",\"port\":$3,\"proto\":\"tcp\",\"ports\":[{\"public\":$2,\"target\":$3,\"proto\":\"tcp\"}]}"; }
vip_of() {
    admin list-services | awk -v n="$1" '$1 == n { print $4 }'
}
# Waits until `lookup NAME` prints exactly WANT (empty for "no record").
expect_record() {
    local name=$1 want=$2 got=""
    for _ in $(seq 1 30); do
        got=$(lookup "$name")
        [ "$got" = "$want" ] && return 0
        sleep 1
    done
    fail "$name resolves to '${got}', expected '${want}'"
}

log "checking prerequisites"
command -v podman >/dev/null || fail "podman not found on PATH"
command -v python3 >/dev/null || fail "python3 not found on PATH"
pass "podman and python3 are present"

log "building images"
podman build -q -f deploy/docker/coordinator.Dockerfile -t wireserve-coordinator:dns-test . >/dev/null
podman build -q -f deploy/e2e/debug-tools.Dockerfile -t "$DEBUG_IMG" deploy/e2e >/dev/null
podman pull -q "$BIND_IMG" >/dev/null
pass "images built"

log "BIND authoritative for $DOMAIN, taking updates signed with a TSIG key"
TSIG_SECRET=$(head -c 32 /dev/urandom | base64)
mkdir -p "$WORK/bind"
cat > "$WORK/bind/named.conf" <<EOF
key "wireserve" { algorithm hmac-sha256; secret "$TSIG_SECRET"; };
options {
    directory "/var/cache/bind";
    listen-on { any; };
    listen-on-v6 { none; };
    recursion no;
    allow-query { any; };
};
zone "$DOMAIN" {
    type primary;
    file "/var/cache/bind/$DOMAIN.zone";
    update-policy { grant wireserve subdomain $DOMAIN. ANY; };
};
EOF
# `keep` is the operator's own record; `prom` is a stale hand-made record at
# a service's name, which the coordinator is expected to replace.
cat > "$WORK/bind/$DOMAIN.zone" <<EOF
\$TTL 300
@     IN SOA ns.$DOMAIN. admin.$DOMAIN. 1 3600 600 86400 300
@     IN NS  ns.$DOMAIN.
ns    IN A   192.0.2.53
keep  IN A   192.0.2.10
prom  IN A   192.0.2.99
EOF
chmod -R a+rwX "$WORK/bind"
podman network create "$NET" >/dev/null
podman run -d --name "$BIND" --network "$NET" \
    -v "$WORK/bind/named.conf:/etc/bind/named.conf:ro,Z" \
    -v "$WORK/bind:/var/cache/bind:Z" \
    --entrypoint /usr/sbin/named "$BIND_IMG" -g -c /etc/bind/named.conf >/dev/null
sleep 2
BIND_IP=$(ip_on "$BIND" "$NET")
[ -n "$BIND_IP" ] || fail "BIND did not start: $(podman logs "$BIND" 2>&1 | tail -5)"

start_coordinator() {
    podman run -d --name "$COORD" --network "$NET" \
        -v wireserve-dns-coord-data:/var/lib/wireserve \
        -e WIRESERVE_ADMIN_TOKEN="$ADMIN_TOKEN" \
        -e WIRESERVE_REQUIRE_SERVICE_APPROVAL=true \
        -e WIRESERVE_SERVICE_DOMAIN="$DOMAIN" -e WIRESERVE_SERVICE_PROXY=web \
        -e WIRESERVE_DNS_PROVIDER=rfc2136 \
        -e WIRESERVE_DNS_SERVER="$BIND_IP:53" \
        -e WIRESERVE_DNS_TSIG_KEY_NAME=wireserve \
        -e WIRESERVE_DNS_TSIG_SECRET="$TSIG_SECRET" \
        -e WIRESERVE_DNS_TTL=60 \
        -e RUST_LOG=info \
        wireserve-coordinator:dns-test >/dev/null
    sleep 2
}
podman volume rm -f wireserve-dns-coord-data >/dev/null 2>&1 || true
start_coordinator
[ "$(lookup keep.$DOMAIN)" = 192.0.2.10 ] || fail "the hand-made record is not being served"
pass "BIND serves the zone, and the coordinator is up"

log "1. pending gets nothing; approved gets its record, 443 at the proxy"
PX=$(new_node px)
HOME_B=$(new_node home)
poll "$PX" "[$(svc web 443 8443)]" >/dev/null
poll "$HOME_B" "[$(svc prom 80 9090), $(svc plex 443 32400)]" >/dev/null
sleep 8
[ -z "$(lookup web.$DOMAIN)" ] || fail "a pending service was published"
admin approve-service px web >/dev/null
admin approve-service home prom >/dev/null
admin approve-service home plex >/dev/null
WEB_VIP=$(vip_of web); PROM_VIP=$(vip_of prom)
[ -n "$WEB_VIP" ] && [ -n "$PROM_VIP" ] || fail "no service addresses: $(admin list-services)"
expect_record "web.$DOMAIN" "$WEB_VIP"
expect_record "prom.$DOMAIN" "$PROM_VIP"
expect_record "plex.$DOMAIN" "$WEB_VIP"
pass "web and prom at their own addresses, plex (443) at the proxy's $WEB_VIP"
pass "prom's stale hand-made 192.0.2.99 was replaced"

log "2. list-services reports the records"
admin list-services | grep -q "^prom.*dns=published" || fail "no dns=published: $(admin list-services)"
pass "dns=published"

log "3. a withdrawn service leaves DNS"
poll "$HOME_B" "[$(svc plex 443 32400)]" >/dev/null
expect_record "prom.$DOMAIN" ""
expect_record "plex.$DOMAIN" "$WEB_VIP"
pass "prom removed, plex kept"

log "4. a revoked node's services leave DNS"
admin revoke home >/dev/null
expect_record "plex.$DOMAIN" ""
expect_record "web.$DOMAIN" "$WEB_VIP"
pass "plex removed with its node, web kept"

log "5. the operator's own record was never touched"
[ "$(lookup keep.$DOMAIN)" = 192.0.2.10 ] || fail "keep.$DOMAIN changed"
pass "keep.$DOMAIN still 192.0.2.10"

log "6. a restart with everything already written changes nothing"
SERIAL=$(in_netns "$COORD" dig +short "@$BIND_IP" "$DOMAIN" SOA | awk '{print $3}')
podman rm -f "$COORD" >/dev/null
start_coordinator
sleep 10
poll "$PX" "[$(svc web 443 8443)]" >/dev/null
sleep 8
AFTER=$(in_netns "$COORD" dig +short "@$BIND_IP" "$DOMAIN" SOA | awk '{print $3}')
[ "$SERIAL" = "$AFTER" ] || fail "the zone changed on restart (serial $SERIAL -> $AFTER)"
expect_record "web.$DOMAIN" "$WEB_VIP"
pass "zone serial unchanged at $SERIAL"

podman volume rm -f wireserve-dns-coord-data >/dev/null 2>&1 || true
echo
echo "All DNS record checks passed."

#!/usr/bin/env bash
# wireserve public DNS records test (PLAN.md M32), against a real BIND taking
# RFC 2136 updates signed with TSIG — the provider path `dns-update` really
# speaks, not a fake.
#
# What this proves:
#
#   1. a pending service gets no record; approving it publishes one at its
#      own address, a 443 service included;
#   2. `service list` reports the record as published;
#   3. withdrawing a service removes its record;
#   4. revoking a node removes the records of every service it had;
#   5. a record the operator made by hand in the same zone is never touched
#      — not even one at a service's name: it is left alone, `service list`
#      says why, and withdrawing the service does not delete it;
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
. deploy/e2e/lib.sh

NET=wireserve-dns-net
COORD=wireserve-dns-coord
BIND=wireserve-dns-bind
DEBUG_IMG=wireserve-e2e-debug-tools
# Canonical's image rather than ISC's: ISC publishes amd64 only, and the
# release workflow runs this suite on arm64 too. It has no shell, which
# is fine — nothing here runs inside it.
BIND_IMG=docker.io/ubuntu/bind9:9.20-26.04_stable
ADMIN_TOKEN=dns-test-admin-token
DOMAIN=int.test

log()  { echo; echo "=== $* ==="; }
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

cleanup() {
    podman rm -fv -t 0 "$COORD" "$BIND" >/dev/null 2>&1 || true
    for c in $(podman ps -aq --filter "name=wireserve-dns-helper" 2>/dev/null); do
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
    podman run --rm --name "wireserve-dns-helper-$$-$RANDOM" --network "container:$target" "$DEBUG_IMG" "$@"
}
ip_on() {
    podman inspect "$1" --format "{{(index .NetworkSettings.Networks \"$2\").IPAddress}}"
}
admin() { podman exec "$COORD" wireserve-admin "$@"; }
# What BIND answers for a name: the addresses, one per line, or nothing.
lookup() { in_netns "$COORD" dig +short "@$BIND_IP" "$1" A | sort; }
# `node create`, then `/register` with a fresh key: prints the bearer token.
new_node() {
    local token pubkey
    token=$(admin node create "$1" | sed -n 's/.*join token: //p')
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
    admin service list --json | jq -r --arg n "$1" '.services[] | select(.name == $n) | .vip4 // empty'
}
# Where service NAME's record stands: `published`, `pending` or `error: <why>`.
dns_of() {
    admin service list --json \
        | jq -r --arg n "$1" '.services[] | select(.name == $n) | .dns | if .state == "error" then "error: \(.error)" else .state // "-" end'
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
command -v jq >/dev/null || fail "jq not found on PATH (reads wireserve-admin --json)"
command -v python3 >/dev/null || fail "python3 not found on PATH"
pass "podman and python3 are present"

log "building images"
./deploy/e2e/build.sh
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
# `keep` is the operator's own record; `prom` is a hand-made record at a
# service's name, which the coordinator must leave alone (PLAN.md #231).
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
# --user 0:0: the image's own user is not root; named runs as root here,
# as it did in ISC's image.
podman run -d --name "$BIND" --network "$NET" --user 0:0 \
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
        -e WIRESERVE_SERVICE_DOMAIN="$DOMAIN" \
        -e WIRESERVE_DNS_PROVIDER=rfc2136 \
        -e WIRESERVE_DNS_SERVER="$BIND_IP:53" \
        -e WIRESERVE_DNS_TSIG_KEY_NAME=wireserve \
        -e WIRESERVE_DNS_TSIG_SECRET="$TSIG_SECRET" \
        -e WIRESERVE_DNS_TTL=60 \
        -e RUST_LOG=info \
        wireserve-coordinator:e2e >/dev/null
    sleep 2
}
podman volume rm -f wireserve-dns-coord-data >/dev/null 2>&1 || true
start_coordinator
[ "$(lookup keep.$DOMAIN)" = 192.0.2.10 ] || fail "the hand-made record is not being served"
pass "BIND serves the zone, and the coordinator is up"

log "1. pending gets nothing; approved gets its record at its own address"
PX=$(new_node px)
HOME_B=$(new_node home)
poll "$PX" "[$(svc web 443 8443)]" >/dev/null
poll "$HOME_B" "[$(svc prom 80 9090), $(svc plex 443 32400), $(svc docs 80 9091)]" >/dev/null
# A poll wakes the coordinator's DNS pass, which runs at most MIN_SPACING
# (5s, dns/sync.rs) later: one has run by now.
sleep 6
[ -z "$(lookup web.$DOMAIN)" ] || fail "a pending service was published"
admin service approve web --node px >/dev/null
admin service approve prom --node home >/dev/null
admin service approve plex --node home >/dev/null
admin service approve docs --node home >/dev/null
WEB_VIP=$(vip_of web); PLEX_VIP=$(vip_of plex); DOCS_VIP=$(vip_of docs)
[ -n "$WEB_VIP" ] && [ -n "$PLEX_VIP" ] && [ -n "$DOCS_VIP" ] || fail "no service addresses: $(admin service list)"
expect_record "web.$DOMAIN" "$WEB_VIP"
expect_record "plex.$DOMAIN" "$PLEX_VIP"
expect_record "docs.$DOMAIN" "$DOCS_VIP"
pass "web, plex and docs each at their own address"
# prom was approved too, and its name already held a hand-made record.
for _ in $(seq 1 30); do
    dns_of prom | has '^error: .*not overwriting' && break
    sleep 1
done
dns_of prom | has '^error: .*not overwriting' \
    || fail "prom should be reported as not overwriting the zone's record: $(admin service list)"
[ "$(lookup prom.$DOMAIN)" = 192.0.2.99 ] || fail "prom's hand-made record was overwritten"
pass "prom.$DOMAIN left at the operator's 192.0.2.99, and said so"

log "2. service list reports the records"
[ "$(dns_of docs)" = published ] || fail "docs's record is not published: $(admin service list)"
pass "docs's record is published"

log "3. a withdrawn service leaves DNS — and a record that was never ours stays"
poll "$HOME_B" "[$(svc plex 443 32400)]" >/dev/null
expect_record "docs.$DOMAIN" ""
[ "$(lookup prom.$DOMAIN)" = 192.0.2.99 ] || fail "withdrawing prom deleted the operator's record"
expect_record "plex.$DOMAIN" "$PLEX_VIP"
pass "docs removed, plex kept, the hand-made prom record kept"

log "4. a revoked node's services leave DNS"
admin node revoke home >/dev/null
expect_record "plex.$DOMAIN" ""
expect_record "web.$DOMAIN" "$WEB_VIP"
pass "plex removed with its node, web kept"

log "5. the operator's own records were never touched"
[ "$(lookup keep.$DOMAIN)" = 192.0.2.10 ] || fail "keep.$DOMAIN changed"
[ "$(lookup prom.$DOMAIN)" = 192.0.2.99 ] || fail "prom.$DOMAIN changed"
pass "keep.$DOMAIN still 192.0.2.10 and prom.$DOMAIN still 192.0.2.99"

log "6. a restart with everything already written changes nothing"
SERIAL=$(in_netns "$COORD" dig +short "@$BIND_IP" "$DOMAIN" SOA | awk '{print $3}')
# A plain stop, as Podman and Quadlet do it: as PID 1 the coordinator only
# stops on SIGTERM because it handles it, and otherwise sat out the 10s.
STOP_START=$SECONDS
podman stop -t 10 "$COORD" >/dev/null
[ $((SECONDS - STOP_START)) -lt 5 ] || fail "the coordinator took $((SECONDS - STOP_START))s to stop on SIGTERM"
[ "$(podman inspect "$COORD" --format '{{.State.ExitCode}}')" = 0 ] || fail "the coordinator did not exit cleanly on SIGTERM"
podman rm -fv -t 0 "$COORD" >/dev/null
start_coordinator
# The restarted coordinator runs a pass as it starts, and the poll wakes
# another at most MIN_SPACING (5s) after that one: both have run by now.
poll "$PX" "[$(svc web 443 8443)]" >/dev/null
sleep 6
AFTER=$(in_netns "$COORD" dig +short "@$BIND_IP" "$DOMAIN" SOA | awk '{print $3}')
[ "$SERIAL" = "$AFTER" ] || fail "the zone changed on restart (serial $SERIAL -> $AFTER)"
expect_record "web.$DOMAIN" "$WEB_VIP"
pass "zone serial unchanged at $SERIAL"

podman volume rm -f wireserve-dns-coord-data >/dev/null 2>&1 || true
echo
echo "All DNS record checks passed."

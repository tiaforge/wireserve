#!/usr/bin/env bash
# WireServe access grants test (PLAN.md M36): service groups, grants and
# node tags, enforced by each service's own node on real traffic.
#
#     [coordinator]──( net )──┬──────────────┬──────────────┐
#                        [home agent]   [client a]      [client b]
#                        web 80, db 5432 tagged ops      no tag
#
# What this proves, against real WireGuard and nftables:
#
#   1. a fresh mesh reaches every service, as before grants existed;
#   2. putting db in a group takes it out of `default`: nobody but its own
#      node reaches it, while web stays open;
#   3. `grant add tag:ops infra` lets the tagged node in, and only it;
#   4. taking the grant away cuts a connection already open;
#   5. a declaration naming a group lands in it — once: naming another
#      later changes nothing and says so in `wireserve list`, and naming a
#      group that does not exist publishes nothing;
#   6. a group in use cannot be deleted, and `access` explains who reaches
#      a service and why.
#
# Rootful Podman, like the other harnesses that rewrite service addresses.
#
# Usage: sudo ./deploy/e2e/run-grants-test.sh
# Exit code 0 = every check passed.

set -euo pipefail
cd "$(dirname "$0")/../.."

NET=wireserve-gr-net
COORD=wireserve-gr-coord
HOME_AGENT=wireserve-gr-home
CLIENT_A=wireserve-gr-a
CLIENT_B=wireserve-gr-b
DEBUG_IMG=wireserve-e2e-debug-tools
ADMIN_TOKEN=grants-test-admin-token
WG_PORT=51820
WORK=""

log()  { echo; echo "=== $* ==="; }
pass() { echo "PASS: $*"; }
fail() {
    echo "FAIL: $*" >&2
    for c in "$HOME_AGENT" "$CLIENT_A"; do
        echo "--- $c:/var/log/agent.log (tail) ---" >&2
        podman exec "$c" tail -n 30 /var/log/agent.log >&2 2>/dev/null || true
    done
    echo "--- home's firewall ---" >&2
    in_netns "$HOME_AGENT" nft list table inet wireserve.wireserve0 >&2 2>/dev/null || true
    exit 1
}

cleanup() {
    podman rm -f "$COORD" "$HOME_AGENT" "$CLIENT_A" "$CLIENT_B" >/dev/null 2>&1 || true
    for c in $(podman ps -aq --filter "name=wireserve-gr-helper" 2>/dev/null); do
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
    podman run --rm --name "wireserve-gr-helper-$$-$RANDOM" \
        --network "container:$target" --cap-add=NET_ADMIN -v "$WORK:/work:Z" "$DEBUG_IMG" "$@"
}
in_netns_bg() {
    local target=$1; shift
    podman run -d --name "wireserve-gr-helper-$$-$RANDOM" \
        --network "container:$target" -v "$WORK:/work:Z" "$DEBUG_IMG" "$@" >/dev/null
}
ip_on() {
    podman inspect "$1" --format "{{(index .NetworkSettings.Networks \"$2\").IPAddress}}"
}
admin() { podman exec "$COORD" wireserve-admin "$@"; }
vip_of() { podman exec "$CLIENT_A" getent hosts "$1.wg" | awk '{print $1}'; }
# One exchange with a service: what came back, empty when refused.
ask() {
    local from=$1 name=$2 port=$3
    in_netns "$from" sh -c "echo hi | timeout 8 socat -t3 - TCP:$(vip_of "$name"):$port" 2>/dev/null || true
}
reaches() { [ -n "$(ask "$1" "$2" "$3")" ]; }
refused() { [ -z "$(ask "$1" "$2" "$3")" ]; }
wait_for() {
    local what=$1 secs=$2; shift 2
    for _ in $(seq 1 "$secs"); do
        "$@" >/dev/null 2>&1 && return 0
        sleep 1
    done
    fail "timed out after ${secs}s waiting for: $what"
}

log "checking prerequisites"
command -v podman >/dev/null || fail "podman not found on PATH"
modinfo wireguard >/dev/null 2>&1 || fail "WireGuard kernel module not available"
[ "$(podman info --format '{{.Host.Security.Rootless}}')" = false ] \
    || fail "needs rootful podman (service-address rewrites are refused in a user namespace): sudo $0"
pass "podman and the WireGuard kernel module are present"

log "building images"
podman build -q -f deploy/docker/coordinator.Dockerfile -t wireserve-coordinator:gr-test . >/dev/null
podman build -q -f deploy/docker/agent.Dockerfile -t wireserve-agent:gr-test . >/dev/null
podman build -q -f deploy/e2e/debug-tools.Dockerfile -t "$DEBUG_IMG" deploy/e2e >/dev/null
pass "images built"

log "coordinator, approval off"
podman network create --internal "$NET" >/dev/null
podman run -d --name "$COORD" --network "$NET" \
    -e WIRESERVE_ADMIN_TOKEN="$ADMIN_TOKEN" -e WIRESERVE_REQUIRE_SERVICE_APPROVAL=false \
    wireserve-coordinator:gr-test >/dev/null
sleep 2
COORD_IP=$(ip_on "$COORD" "$NET")

log "joining home, a and b"
for pair in "$HOME_AGENT:node-home" "$CLIENT_A:node-a" "$CLIENT_B:node-b"; do
    c=${pair%%:*}; n=${pair#*:}
    podman run -d --name "$c" --network "$NET" \
        --cap-add=NET_ADMIN --security-opt unmask=/proc/sys --device /dev/net/tun \
        --entrypoint sleep wireserve-agent:gr-test infinity >/dev/null
    jt=$(admin create-node "$n" | grep -oE 'jtk_[a-f0-9]+')
    podman exec "$c" wireserve join "http://$COORD_IP:47820" --allow-plaintext-http "$jt" \
        --listen-port "$WG_PORT" --endpoint-addr "$(ip_on "$c" "$NET"):$WG_PORT" 2>/dev/null
    podman exec -d "$c" sh -c 'wireserve daemon --poll-interval-secs 3 >/var/log/agent.log 2>&1'
done
admin tag add node-a ops
podman exec "$HOME_AGENT" wireserve serve web 80:8080
podman exec "$HOME_AGENT" wireserve serve db 5432
in_netns_bg "$HOME_AGENT" socat TCP-LISTEN:8080,fork,reuseaddr SYSTEM:'echo web'
in_netns_bg "$HOME_AGENT" socat TCP-LISTEN:5432,fork,reuseaddr EXEC:cat
wait_for "db to resolve on a" 60 sh -c "podman exec $CLIENT_A getent hosts db.wg"
wait_for "db to resolve on b" 60 sh -c "podman exec $CLIENT_B getent hosts db.wg"
pass "home serves web and db; node-a is tagged ops"

log "1/6: a fresh mesh reaches everything"
wait_for "a to reach db" 30 reaches "$CLIENT_A" db 5432
for c in "$CLIENT_A" "$CLIENT_B"; do
    reaches "$c" web 80 || fail "$c does not reach web"
    reaches "$c" db 5432 || fail "$c does not reach db"
done
pass "a and b reach web and db"

log "2/6: a group takes db out of default"
admin group create infra
admin group add infra db
wait_for "b to be refused db" 30 refused "$CLIENT_B" db 5432
refused "$CLIENT_A" db 5432 || fail "a reached db before anything was granted"
reaches "$CLIENT_B" web 80 || fail "web left default too"
reaches "$HOME_AGENT" db 5432 || fail "db's own node lost it"
pass "db reaches nobody but home; web is still open"

log "3/6: a grant to a tag lets exactly that node in"
admin grant add tag:ops infra
wait_for "a to reach db" 30 reaches "$CLIENT_A" db 5432
refused "$CLIENT_B" db 5432 || fail "b reached db without the tag"
pass "node-a (tag ops) reaches db; node-b does not"

log "4/6: taking the grant away cuts an open connection"
in_netns_bg "$CLIENT_A" sh -c "(echo one; sleep 20; echo two) | socat -t25 - TCP:$(vip_of db):5432 > /work/flow.out 2>&1"
wait_for "the connection to carry its first line" 10 grep -q one "$WORK/flow.out"
admin grant remove tag:ops infra
sleep 25
cat "$WORK/flow.out"
grep -q two "$WORK/flow.out" && fail "the open connection outlived the grant"
refused "$CLIENT_A" db 5432 || fail "a still reaches db"
pass "the open connection was cut at the next packet"

log "5/6: a declaration names a group once, and never an unknown one"
admin grant add tag:ops infra
admin group create media
podman exec "$HOME_AGENT" wireserve serve vault 8200 --group infra
in_netns_bg "$HOME_AGENT" socat TCP-LISTEN:8200,fork,reuseaddr SYSTEM:'echo vault'
wait_for "vault to resolve on b" 60 sh -c "podman exec $CLIENT_B getent hosts vault.wg"
wait_for "a to reach vault" 30 reaches "$CLIENT_A" vault 8200
refused "$CLIENT_B" vault 8200 || fail "vault landed in default"
admin list-services | grep '^vault' | grep -q 'groups=infra' || fail "vault is not listed in infra"
podman exec "$HOME_AGENT" wireserve serve vault 8200 --group media
wait_for "the notice about vault" 30 sh -c "podman exec $HOME_AGENT wireserve list | grep -q 'vault: stays in infra'"
admin list-services | grep '^vault' | grep -q 'groups=infra' || fail "a declaration moved vault"
podman exec "$HOME_AGENT" wireserve serve ghost 9000 --group nope
wait_for "the notice about ghost" 30 sh -c "podman exec $HOME_AGENT wireserve list | grep -q 'ghost: there is no group nope'"
admin list-services | grep -q '^ghost' && fail "a service naming an unknown group was published"
pass "vault joined infra and stayed there; ghost was not published"

log "6/6: groups in use stay, and access explains"
if admin group delete infra 2>/dev/null; then
    fail "a group holding services was deleted"
fi
admin access db | tee "$WORK/access.out"
grep -q 'groups:     infra' "$WORK/access.out" || fail "access does not name db's group"
grep -qE 'node-a[[:space:]]+via tag:ops' "$WORK/access.out" || fail "access does not say node-a reaches db through tag:ops"
grep -q 'node-b' "$WORK/access.out" && fail "access claims node-b reaches db"
admin access --node node-b | tee "$WORK/node-b.out"
grep -qE '^  web' "$WORK/node-b.out" || fail "node-b should reach web, through everyone"
grep -qE '^  (db|vault)' "$WORK/node-b.out" && fail "node-b should reach nothing in infra"
pass "infra could not be deleted; access names node-a via tag:ops, and node-b reaches web alone"

echo
echo "=== GRANTS TEST COMPLETE ==="

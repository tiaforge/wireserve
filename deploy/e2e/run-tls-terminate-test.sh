#!/usr/bin/env bash
# WireServe per-node TLS termination test (PLAN.md M33), against a real
# ACME CA (Pebble), a real authoritative DNS server taking RFC 2136 updates
# (BIND), real WireGuard and real nftables.
#
# What this proves:
#
#   1. the home node's terminator gets a certificate from the CA, the
#      challenge record having been published by the coordinator on its
#      behalf, and the directory then marks the service terminated;
#   2. a client on another node reaches https://plex.int.test on the
#      service's own address, verified against the CA, and the backend sees
#      who is calling (X-Wireserve-Node, X-Forwarded-For) with forged copies
#      of those headers removed;
#   3. the owner node itself reaches it the same way, named as itself;
#   4. port 443 stays free for other software (PLAN.md M35): a stranger
#      listening on 0.0.0.0:443 of the home node, started before the
#      terminator, keeps it, while 1–3 went to the terminator's own port;
#      that port answers neither the LAN nor the mesh directly;
#   5. the service's other port is still an ordinary mapping;
#   6. the challenge record is gone once the certificate is issued;
#   7. restarting the terminator serves the stored certificate, no new one;
#   8. a stopped terminator hands the address back to the plain mapping;
#   9. a daemon stop removes the local route, and a daemon killed with -9
#      has its leftover route swept on the next start.
#
#     ( net )──┬──────────┬───────┬────────┬──────────────┬────────────┐
#          [coordinator] [bind] [pebble] [home agent       [client agent]
#                                         + terminator
#                                         plex 443:32400 81:32401]
#
# Rootful Podman, like the other harnesses that run WireGuard.
#
# Usage: sudo ./deploy/e2e/run-tls-terminate-test.sh
# Exit code 0 = every check passed.

set -euo pipefail
cd "$(dirname "$0")/../.."

NET=wireserve-tt-net
COORD=wireserve-tt-coord
BIND=wireserve-tt-bind
PEBBLE=wireserve-tt-pebble
HOME_AGENT=wireserve-tt-home
CLIENT=wireserve-tt-client
DEBUG_IMG=wireserve-e2e-debug-tools
BIND_IMG=docker.io/internetsystemsconsortium/bind9:9.20
PEBBLE_IMG=ghcr.io/letsencrypt/pebble:latest
ADMIN_TOKEN=tls-terminate-test-admin-token
DOMAIN=int.test
WG_PORT=51820

log()  { echo; echo "=== $* ==="; }
pass() { echo "PASS: $*"; }
fail() {
    echo "FAIL: $*" >&2
    # The containers go with the trap below; their logs go first.
    for f in tls.log agent.log agent2.log; do
        echo "--- $HOME_AGENT:/var/log/$f (tail) ---" >&2
        podman exec "$HOME_AGENT" tail -n 40 "/var/log/$f" >&2 2>/dev/null || true
    done
    echo "--- $CLIENT:/var/log/agent.log (tail) ---" >&2
    podman exec "$CLIENT" tail -n 15 /var/log/agent.log >&2 2>/dev/null || true
    echo "--- $COORD (tail) ---" >&2
    podman logs --tail 40 "$COORD" >&2 2>/dev/null || true
    echo "--- $PEBBLE (tail) ---" >&2
    podman logs --tail 30 "$PEBBLE" >&2 2>/dev/null || true
    exit 1
}

cleanup() {
    podman rm -f "$COORD" "$BIND" "$PEBBLE" "$HOME_AGENT" "$CLIENT" >/dev/null 2>&1 || true
    for c in $(podman ps -aq --filter "name=wireserve-tt-helper" 2>/dev/null); do
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
    podman run --rm --name "wireserve-tt-helper-$$-$RANDOM" \
        --network "container:$target" --cap-add=NET_ADMIN --cap-add=NET_RAW \
        -v "$WORK:/work:ro,Z" "$DEBUG_IMG" "$@"
}
in_netns_bg() {
    local target=$1; shift
    podman run -d --name "wireserve-tt-helper-$$-$RANDOM" --network "container:$target" \
        -v "$PWD/deploy/e2e:/e2e:ro" "$DEBUG_IMG" "$@" >/dev/null
}
ip_on() {
    podman inspect "$1" --format "{{(index .NetworkSettings.Networks \"$2\").IPAddress}}"
}
admin() { podman exec "$COORD" wireserve-admin "$@"; }
# A field of this node's own directory entry for `name`, from the agent's
# cached directory.
entry() {
    podman exec "$1" cat /var/lib/wireserve/agent-state.json | python3 -c "
import json,sys
d=json.load(sys.stdin).get('last_directory') or {}
s=next((s for s in d.get('services',[]) if s['name']=='$2'), {})
print(s.get('$3', ''))"
}
# HTTPS to plex by name at its own address, verified against Pebble's root:
# the response headers and body, then the status.
fetch() {
    local from=$1; shift
    in_netns "$from" curl -s --max-time 10 --cacert /work/pebble-root.pem \
        --resolve "plex.$DOMAIN:443:$PLEX_VIP" -D - "$@" "https://plex.$DOMAIN/" \
        -w '\nSTATUS %{http_code}\n'
}
# The agent image has no procps: signal by command line through /proc.
signal() {
    # `$$` is the searching shell itself, whose own command line contains
    # the pattern: skipped, or it signals itself first.
    podman exec "$1" sh -c 'for p in /proc/[0-9]*; do [ "${p#/proc/}" = "$$" ] && continue; tr "\0" " " 2>/dev/null <$p/cmdline | grep -q -- "'"$3"'" && kill -'"$2"' ${p#/proc/} 2>/dev/null; done; true' \
        || fail "could not signal $3 in $1"
}
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
command -v python3 >/dev/null || fail "python3 not found on PATH"
modinfo wireguard >/dev/null 2>&1 || fail "WireGuard kernel module not available"
[ "$(podman info --format '{{.Host.Security.Rootless}}')" = false ] \
    || fail "needs rootful podman (WireGuard and the firewall need the host's user namespace): sudo $0"
pass "podman, python3 and the WireGuard kernel module are present"

log "building images"
podman build -q -f deploy/docker/coordinator.Dockerfile -t wireserve-coordinator:tt-test . >/dev/null
podman build -q -f deploy/docker/agent.Dockerfile -t wireserve-agent:tt-test . >/dev/null
podman build -q -f deploy/e2e/debug-tools.Dockerfile -t "$DEBUG_IMG" deploy/e2e >/dev/null
podman pull -q "$BIND_IMG" >/dev/null
podman pull -q "$PEBBLE_IMG" >/dev/null
pass "images built"

log "BIND for $DOMAIN, and Pebble validating against it"
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

log "coordinator: $DOMAIN, records through BIND, certificates from Pebble"
podman run -d --name "$COORD" --network "$NET" \
    -e WIRESERVE_ADMIN_TOKEN="$ADMIN_TOKEN" \
    -e WIRESERVE_REQUIRE_SERVICE_APPROVAL=false \
    -e WIRESERVE_SERVICE_DOMAIN="$DOMAIN" \
    -e WIRESERVE_DNS_PROVIDER=rfc2136 -e WIRESERVE_DNS_SERVER="$BIND_IP:53" \
    -e WIRESERVE_DNS_TSIG_KEY_NAME=wireserve -e WIRESERVE_DNS_TSIG_SECRET="$TSIG_SECRET" \
    -e WIRESERVE_DNS_TTL=60 \
    -e WIRESERVE_ACME_DIRECTORY=https://pebble:14000/dir -e WIRESERVE_ACME_PROPAGATION_SECS=0 \
    wireserve-coordinator:tt-test >/dev/null
sleep 2
COORD_IP=$(ip_on "$COORD" "$NET")

for c in "$HOME_AGENT" "$CLIENT"; do
    podman run -d --name "$c" --network "$NET" \
        --cap-add=NET_ADMIN --security-opt unmask=/proc/sys --device /dev/net/tun \
        --entrypoint sleep wireserve-agent:tt-test infinity >/dev/null
done
podman cp "$WORK/pebble-minica.pem" "$HOME_AGENT:/etc/pebble-minica.pem"

log "joining both agents; the home node runs its terminator"
for pair in "$HOME_AGENT:node-home" "$CLIENT:node-client"; do
    c=${pair%%:*}; n=${pair#*:}
    jt=$(admin create-node "$n" | grep -oE 'jtk_[a-f0-9]+')
    podman exec "$c" wireserve join "http://$COORD_IP:47820" --allow-plaintext-http "$jt" \
        --listen-port "$WG_PORT" --endpoint-addr "$(ip_on "$c" "$NET"):$WG_PORT" 2>/dev/null
    podman exec -d "$c" sh -c 'wireserve daemon --poll-interval-secs 3 >/var/log/agent.log 2>&1'
done
start_terminator() {
    podman exec -d "$HOME_AGENT" sh -c 'WIRESERVE_ACME_CA_FILE=/etc/pebble-minica.pem \
        wireserve tls-serve --state-dir /var/lib/wireserve-tls >>/var/log/tls.log 2>&1'
}
# Something else of the host's on every address's 443 (PLAN.md M35),
# there before the terminator, the way a Caddy started at boot would be.
in_netns_bg "$HOME_AGENT" socat "TCP-LISTEN:443,fork,reuseaddr" SYSTEM:"echo stranger"
start_terminator
podman exec "$HOME_AGENT" wireserve serve plex 443:32400 81:32401
for port in 32400 32401; do
    in_netns_bg "$HOME_AGENT" socat "TCP-LISTEN:$port,fork,reuseaddr" EXEC:"/e2e/echo-backend.sh $port"
done
sleep 8
PLEX_VIP=$(entry "$HOME_AGENT" plex vip4)
HOME_IP=$(podman exec "$HOME_AGENT" wireserve list --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["node"]["ip4"])' 2>/dev/null || true)
[ -n "$PLEX_VIP" ] || fail "plex has no service address: $(podman exec "$HOME_AGENT" wireserve list)"
pass "plex at $PLEX_VIP"

log "1/9: a certificate from Pebble, and plex terminated"
terminated_on() { [ "$(entry "$1" plex terminated)" = True ]; }
wait_for "the terminator to report plex" 90 terminated_on "$HOME_AGENT"
podman exec "$HOME_AGENT" grep -q 'certificate issued' /var/log/tls.log || fail "no issuance in the terminator's log"
[ "$(podman exec "$HOME_AGENT" grep -c 'certificate issued' /var/log/tls.log)" = 1 ] || fail "more than one issuance"
in_netns "$CLIENT" curl -sk --max-time 10 https://pebble:15000/roots/0 > "$WORK/pebble-root.pem"
grep -q 'BEGIN CERTIFICATE' "$WORK/pebble-root.pem" || fail "could not fetch Pebble's issuing root"
wait_for "the client to see plex terminated" 30 terminated_on "$CLIENT"
pass "issued once; the directory says terminated"

log "2/9: from the client, verified TLS on the service's own address"
OUT=$(fetch "$CLIENT" -H 'X-Wireserve-Node: evil' -H 'X-Forwarded-For: 6.6.6.6') || true
echo "$OUT" | sed 's/^/  /'
echo "$OUT" | grep -q '^STATUS 200' || fail "the request did not succeed over verified TLS"
echo "$OUT" | grep -q 'backend:32400' || fail "the backend was not reached"
echo "$OUT" | grep -qi '^x-wireserve-node: node-client' || fail "the backend was not told the caller"
echo "$OUT" | grep -qi 'evil' && fail "a forged X-Wireserve-Node reached the backend"
echo "$OUT" | grep -qi '6.6.6.6' && fail "a forged X-Forwarded-For reached the backend"
echo "$OUT" | grep -qi '^x-forwarded-proto: https' || fail "no X-Forwarded-Proto"
echo "$OUT" | grep -qi "^host: plex.$DOMAIN" || fail "the backend did not see its own name as Host"
pass "200 over a Pebble certificate; X-Wireserve-Node: node-client; forged headers gone"

log "3/9: from the owner node itself"
OUT=$(fetch "$HOME_AGENT") || true
echo "$OUT" | grep -q '^STATUS 200' || { echo "$OUT"; fail "the owner node could not reach its own service by name"; }
echo "$OUT" | grep -qi '^x-wireserve-node: node-home' || { echo "$OUT"; fail "the owner node was not named as itself"; }
pass "the owner node is named node-home"

log "4/9: 443 stays the stranger's, and the terminator's port is closed"
in_netns "$HOME_AGENT" curl -s --max-time 4 http://127.0.0.1:443/ | grep -q stranger \
    || fail "the stranger lost 0.0.0.0:443"
HOME_LAN=$(ip_on "$HOME_AGENT" "$NET")
if in_netns "$CLIENT" curl -sk --max-time 4 --resolve "plex.$DOMAIN:11443:$HOME_LAN" "https://plex.$DOMAIN:11443/" | grep -q backend; then
    fail "the terminator's port answers the LAN"
fi
if in_netns "$CLIENT" curl -sk --max-time 4 --resolve "plex.$DOMAIN:11443:$PLEX_VIP" "https://plex.$DOMAIN:11443/" | grep -q backend; then
    fail "the terminator's port answers the mesh without the rewrite"
fi
pass "the stranger keeps 0.0.0.0:443; 11443 answers only through the rewrite"

log "5/9: the other port is still an ordinary mapping"
in_netns "$CLIENT" curl -s --max-time 6 "http://$PLEX_VIP:81/" | grep -q 'backend:32401' \
    || fail "port 81 no longer reaches its target"
if in_netns "$CLIENT" curl -s --max-time 4 "http://$PLEX_VIP:32400/" | grep -q backend; then
    fail "the 443 target is reachable directly"
fi
pass "81 → 32401 mapped; 32400 closed from the mesh"

log "6/9: no challenge record left behind"
wait_for "the challenge record to go" 30 sh -c "[ -z \"\$(podman run --rm --network container:$COORD $DEBUG_IMG dig +short @$BIND_IP _acme-challenge.plex.$DOMAIN TXT)\" ]"
pass "_acme-challenge.plex.$DOMAIN is empty"

log "7/9: a restarted terminator serves the stored certificate"
SERIAL=$(in_netns "$CLIENT" sh -c "echo | openssl s_client -connect $PLEX_VIP:443 -servername plex.$DOMAIN 2>/dev/null | openssl x509 -noout -serial" 2>/dev/null || true)
signal "$HOME_AGENT" TERM 'wireserve tls-serve'
sleep 1
start_terminator
sleep 12
[ "$(podman exec "$HOME_AGENT" grep -c 'certificate issued' /var/log/tls.log)" = 1 ] || fail "the restart issued a new certificate"
fetch "$CLIENT" | grep -q '^STATUS 200' || fail "not served after the restart"
AFTER=$(in_netns "$CLIENT" sh -c "echo | openssl s_client -connect $PLEX_VIP:443 -servername plex.$DOMAIN 2>/dev/null | openssl x509 -noout -serial" 2>/dev/null || true)
[ -z "$SERIAL" ] || [ "$SERIAL" = "$AFTER" ] || fail "a different certificate after the restart ($SERIAL → $AFTER)"
pass "same certificate, no new issuance"

log "8/9: a stopped terminator hands the address back to the mapping"
signal "$HOME_AGENT" TERM 'wireserve tls-serve'
# The firewall stops relying on it after 30s without a check-in.
wait_for "plain HTTP on :443 to reach the backend again" 60 \
    sh -c "podman run --rm --network container:$CLIENT $DEBUG_IMG curl -s --max-time 3 http://$PLEX_VIP:443/ | grep -q backend:32400"
pass "vip:443 is the plain mapping again"
start_terminator
wait_for "TLS back on :443" 60 sh -c "podman run --rm --network container:$CLIENT -v $WORK:/work:ro,Z $DEBUG_IMG curl -s --max-time 3 --cacert /work/pebble-root.pem --resolve plex.$DOMAIN:443:$PLEX_VIP https://plex.$DOMAIN/ | grep -q backend:32400"
pass "and TLS again once it is back"

log "9/9: local routes go with the daemon, and a crash's are swept"
in_netns "$HOME_AGENT" ip -4 route show table local proto 247 | grep -q "$PLEX_VIP" \
    || fail "no local route for $PLEX_VIP while terminated"
signal "$HOME_AGENT" TERM 'wireserve daemon'
sleep 4
in_netns "$HOME_AGENT" ip -4 route show table local proto 247 | grep -q . \
    && fail "a stopped daemon left its local route"
pass "a clean stop removes the local route"
podman exec -d "$HOME_AGENT" sh -c 'wireserve daemon --poll-interval-secs 3 >/var/log/agent.log 2>&1'
wait_for "the route to come back" 60 sh -c "podman run --rm --network container:$HOME_AGENT --cap-add=NET_ADMIN $DEBUG_IMG ip -4 route show table local proto 247 | grep -q $PLEX_VIP"
signal "$HOME_AGENT" KILL 'wireserve daemon'
sleep 1
in_netns "$HOME_AGENT" ip -4 route show table local proto 247 | grep -q "$PLEX_VIP" \
    || fail "the route should have outlived a kill -9 (nothing left to test otherwise)"
podman exec -d "$HOME_AGENT" sh -c 'wireserve daemon --poll-interval-secs 3 >/var/log/agent2.log 2>&1'
wait_for "the sweep" 20 podman exec "$HOME_AGENT" grep -q 'left behind' /var/log/agent2.log
pass "the leftover route was swept at start"
[ -n "$HOME_IP" ] || true

echo
echo "=== TLS TERMINATION TEST COMPLETE ==="

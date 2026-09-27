#!/usr/bin/env bash
# WireServe reverse-proxy test.
#
# Spec §7 requires that every external path to the coordinator is TLS
# terminated at the operator's own reverse proxy, and that the
# coordinator's plain-HTTP listener is never directly reachable. Every
# other test in this directory talks plain HTTP straight to the
# coordinator, so the topology the spec actually mandates was the one
# thing never exercised.
#
#   [agent1]─┐                     ┌───────────────┐
#            ├── https ──▶ [nginx] │ coordinator   │
#   [agent2]─┘   (TLS)     plain──▶│ 47820 only    │
#                                  └───────────────┘
#
# The coordinator sits on an internal-only segment that agents cannot
# reach at all; the proxy is the sole path in. That is checked, not
# assumed. A private CA is generated here and installed into each agent's
# trust store, so certificate validation is real rather than disabled.
#
# It also covers what the proxy changes about the coordinator's own
# behaviour: with WIRESERVE_TRUST_PROXY_HEADERS on, the client address is
# read from X-Forwarded-For rather than being the proxy's for everybody.
#
# Usage: ./deploy/e2e/run-proxy-test.sh

set -euo pipefail
cd "$(dirname "$0")/../.."

FRONT=wireserve-proxy-front
BACK=wireserve-proxy-back
COORD=wireserve-proxy-coord
PROXY=wireserve-proxy-nginx
AGENT1=wireserve-proxy-agent1
AGENT2=wireserve-proxy-agent2
ADMIN_TOKEN=proxy-test-admin-token
HOSTNAME_FQDN=wireserve.test

log()  { echo; echo "=== $* ==="; }
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
note() { echo "NOTE: $*"; }

cleanup() {
    podman rm -f "$COORD" "$PROXY" "$AGENT1" "$AGENT2" >/dev/null 2>&1 || true
    podman network rm "$FRONT" "$BACK" >/dev/null 2>&1 || true
    # ${WORK:-} because the trap is armed before the directory exists, so
    # an early failure must not expand to `rm -rf ""`.
    [ -n "${WORK:-}" ] && rm -rf "$WORK"
    return 0
}
trap cleanup EXIT
# Clear anything a killed earlier run left behind, and only then create
# the scratch directory — doing it the other way round deletes the
# directory this run is about to write its keys into.
cleanup 2>/dev/null || true
WORK=$(mktemp -d)

log "checking prerequisites"
command -v podman >/dev/null || fail "podman not found on PATH"
command -v openssl >/dev/null || fail "openssl not found on PATH"
modinfo wireguard >/dev/null 2>&1 || fail "WireGuard kernel module not available"
pass "podman, openssl and the WireGuard kernel module are present"

log "building images"
podman build -q -f deploy/docker/coordinator.Dockerfile -t wireserve-coordinator:proxy-test . >/dev/null
podman build -q -f deploy/docker/agent.Dockerfile -t wireserve-agent:proxy-test . >/dev/null
pass "images built"

log "generating a private CA and a server certificate"
# A real chain, validated for real. Disabling verification would remove
# the only thing this part of the test is here to check.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout "$WORK/ca.key" -out "$WORK/ca.crt" \
    -subj "/CN=WireServe Test CA" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
    -keyout "$WORK/server.key" -out "$WORK/server.csr" \
    -subj "/CN=$HOSTNAME_FQDN" >/dev/null 2>&1
printf 'subjectAltName=DNS:%s\n' "$HOSTNAME_FQDN" > "$WORK/ext.cnf"
openssl x509 -req -in "$WORK/server.csr" -CA "$WORK/ca.crt" -CAkey "$WORK/ca.key" \
    -CAcreateserial -out "$WORK/server.crt" -days 1 -extfile "$WORK/ext.cnf" >/dev/null 2>&1
pass "CA and server certificate for $HOSTNAME_FQDN"

log "creating the front and back segments"
podman network create "$FRONT" >/dev/null
# The coordinator's own segment is internal: agents are not on it and have
# no route to it, so "the plain-HTTP listener is not directly reachable"
# is a property of the topology rather than a promise.
podman network create --internal "$BACK" >/dev/null
pass "agents on the front segment, coordinator on an internal back segment"

log "starting the coordinator on the back segment only"
podman run -d --name "$COORD" --network "$BACK" \
    -e WIRESERVE_ADMIN_TOKEN="$ADMIN_TOKEN" \
    -e WIRESERVE_TRUST_PROXY_HEADERS=true \
    wireserve-coordinator:proxy-test >/dev/null
sleep 2
COORD_IP=$(podman inspect "$COORD" --format "{{(index .NetworkSettings.Networks \"$BACK\").IPAddress}}")
echo "coordinator (back segment only): $COORD_IP"

log "starting nginx as the TLS-terminating reverse proxy"
cat > "$WORK/nginx.conf" <<NGINX
events {}
http {
    access_log /dev/stdout;
    server {
        listen 443 ssl;
        server_name $HOSTNAME_FQDN;
        ssl_certificate     /etc/nginx/certs/server.crt;
        ssl_certificate_key /etc/nginx/certs/server.key;
        location / {
            proxy_pass http://$COORD_IP:47820;
            proxy_set_header Host \$host;
            # The header the coordinator reads the real client address
            # from when WIRESERVE_TRUST_PROXY_HEADERS is set. nginx
            # appends the connecting peer to any inbound value, so the
            # right-most entry is the one it observed itself, which is
            # exactly the one the coordinator trusts.
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        }
    }
}
NGINX
podman run -d --name "$PROXY" --network "$FRONT" --network "$BACK" \
    -v "$WORK/nginx.conf:/etc/nginx/nginx.conf:ro,Z" \
    -v "$WORK/server.crt:/etc/nginx/certs/server.crt:ro,Z" \
    -v "$WORK/server.key:/etc/nginx/certs/server.key:ro,Z" \
    docker.io/library/nginx:stable >/dev/null
sleep 3
PROXY_IP=$(podman inspect "$PROXY" --format "{{(index .NetworkSettings.Networks \"$FRONT\").IPAddress}}")
echo "proxy (front segment): $PROXY_IP"
podman logs "$PROXY" 2>&1 | grep -qi "emerg" && fail "nginx failed to start: $(podman logs "$PROXY" 2>&1 | tail -3)"
pass "nginx is terminating TLS in front of the coordinator"

start_agent() {
    podman run -d --name "$1" --network "$FRONT" \
        --cap-add=NET_ADMIN --device /dev/net/tun \
        --add-host "$HOSTNAME_FQDN:$PROXY_IP" \
        -v "$WORK/ca.crt:/usr/local/share/ca-certificates/wireserve-test-ca.crt:ro,Z" \
        --entrypoint sleep wireserve-agent:proxy-test infinity >/dev/null
    sleep 1
    # Install the private CA properly rather than turning verification
    # off: the point is to prove the agent's HTTPS client validates a
    # real chain, which a disabled check would not show.
    podman exec "$1" update-ca-certificates >/dev/null 2>&1
}

log "starting two agents on the front segment"
start_agent "$AGENT1"
start_agent "$AGENT2"
pass "both agents have the test CA installed"

log "the coordinator must NOT be reachable except through the proxy"
if podman exec "$AGENT1" timeout 5 bash -c "exec 3<>/dev/tcp/$COORD_IP/47820" 2>/dev/null; then
    fail "an agent reached the coordinator's plain-HTTP listener directly — spec §7 requires the proxy to be the only path in"
fi
pass "the coordinator's plain-HTTP port is unreachable from the agents' segment"

log "the admin listener must not be reachable either"
if podman exec "$AGENT1" timeout 5 bash -c "exec 3<>/dev/tcp/$PROXY_IP/47821" 2>/dev/null; then
    fail "the admin port was reachable through the proxy segment"
fi
pass "the admin port is not exposed"

create_node() {
    podman exec "$COORD" wireserve-admin create-node "$1" | grep -oE 'jtk_[a-f0-9]+'
}

log "joining both nodes over HTTPS through the proxy"
JT1=$(create_node node1)
JT2=$(create_node node2)
URL="https://$HOSTNAME_FQDN"
podman exec "$AGENT1" wireserve join "$URL" "$JT1" --listen-port 51820 \
    || fail "agent1 could not register over HTTPS through the proxy"
podman exec "$AGENT2" wireserve join "$URL" "$JT2" --listen-port 51821 \
    || fail "agent2 could not register over HTTPS through the proxy"
pass "both nodes registered over TLS with a validated certificate"

log "checking no plaintext warning was printed for an https:// URL"
OUT=$(podman exec "$AGENT1" wireserve join "$URL" "jtk_bogus" --listen-port 51820 2>&1 || true)
if echo "$OUT" | grep -qi "over plain HTTP"; then
    fail "the plaintext-HTTP warning fired for an https:// URL"
fi
pass "no spurious plaintext warning on an https:// URL"

log "checking the coordinator resolved each agent's real address, not the proxy's"
# With trust_proxy_headers on, /register's endpoint fallback should record
# each agent's own front-segment address. If the header were being ignored
# the two would be identical and equal to the proxy's.
podman exec "$COORD" wireserve-admin list-peers | awk '{ for (i = 1; i <= NF; i++) if (index($i, "endpoint=") == 1) printf "  %-7s %s\n", $1, $i }'
EP1=$(podman exec "$COORD" wireserve-admin list-peers | awk '$1=="node1" { for (i = 1; i <= NF; i++) if (index($i, "endpoint=") == 1) print $i }')
EP2=$(podman exec "$COORD" wireserve-admin list-peers | awk '$1=="node2" { for (i = 1; i <= NF; i++) if (index($i, "endpoint=") == 1) print $i }')
[ "$EP1" != "$EP2" ] \
    || fail "both nodes were recorded at the same endpoint ($EP1) — X-Forwarded-For is not being honoured"
echo "$EP1" | grep -q "$PROXY_IP" \
    && fail "node1 was recorded at the proxy's own address — X-Forwarded-For is not being honoured"
pass "each node was recorded at its own address, resolved from X-Forwarded-For"

log "checking the two agents get separate rate-limit budgets behind one proxy"
# Sharing the proxy's address as a rate-limit key is what made one bad
# actor able to take the whole mesh offline. With the header trusted they
# are keyed separately; agent1 burning its budget must not affect agent2.
# Burn agent1's budget with bad bearer tokens, then confirm agent2 is
# unaffected. Keyed on the proxy's address these would share one bucket.
for _ in $(seq 1 12); do
    podman exec "$AGENT1" wireserve join "$URL" "jtk_deliberately_wrong" \
        --listen-port 51820 >/dev/null 2>&1 || true
done
JT3=$(create_node node3)
podman exec "$AGENT2" wireserve join "$URL" "$JT3" --listen-port 51822 \
    || fail "agent2 was rate-limited by agent1's failures — the budget is being shared"
pass "one agent burning its budget does not block the other behind the same proxy"

log "both agents poll successfully through the proxy"
podman exec -d "$AGENT1" sh -c "wireserve daemon --poll-interval-secs 5 >/tmp/daemon.log 2>&1"
podman exec -d "$AGENT2" sh -c "wireserve daemon --poll-interval-secs 5 >/tmp/daemon.log 2>&1"
sleep 15
for a in node1 node2; do
    podman exec "$COORD" wireserve-admin list-peers | grep -q "^$a" \
        || fail "$a vanished from the directory"
done
# Declaring a service only reaches the coordinator via a poll, so a new
# service_declared audit event is evidence of polling rather than of the
# earlier registration.
#
# Matched on the bare event name: tracing writes ANSI escapes between the
# field name and its `=`, so a literal 'event="..."' never matches a log
# that was not stripped first.
coord_events() { podman logs "$COORD" 2>&1 | grep -c "service_declared" || true; }
POLLED=$(coord_events)
podman exec "$AGENT1" wireserve serve proxysvc 9999 \
    || fail "could not declare a service on agent1"
sleep 8
POLLED_AFTER=$(coord_events)
[ "$POLLED_AFTER" -gt "$POLLED" ] \
    || fail "no poll reached the coordinator through the proxy after a serve"
pass "polls reach the coordinator through the proxy"

log "confirming traffic really went through nginx"
REQS=$(podman logs "$PROXY" 2>&1 | grep -cE '"(POST|GET) /(register|poll)' || true)
[ "$REQS" -gt 0 ] || fail "nginx never logged a /register or /poll request — traffic bypassed the proxy"
echo "nginx handled $REQS coordinator requests"
pass "every coordinator request went through the reverse proxy"

echo
echo "=== PROXY TEST COMPLETE ==="

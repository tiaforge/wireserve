#!/usr/bin/env bash
# WireServe sign-in test (PLAN.md M29), and the first end-to-end run of the
# M25 service proxy it sits on.
#
# A service marked for sign-in must be reachable through the proxy's
# forward_auth and nowhere else. What this proves, against a real Caddy and
# real WireGuard:
#
#   1. the agent generates the sign-in import for the marked service, and the
#      cookie-stripping import for every service, and Caddy takes it;
#   2. without a session the proxy sends the browser to the login URL;
#   3. with one, the backend is reached with the identity header set, and
#      without the sign-in cookie (other cookies untouched);
#   4. an unmarked service through the same proxy needs no sign-in, but is
#      stripped of the cookie as well;
#   5. dialling the marked service's own address directly — the way round the
#      sign-in — leads nowhere, while the unmarked one's direct address works
#      (so the refusal is the mark, not the topology);
#   6. `service-auth off` gives the direct path back.
#
#     ( inet )──┬────────────┬───────────────┬──────────────┐
#          [coordinator]  [proxy agent     [home agent]   [client agent]
#                          + caddy          jellyfin (marked)
#                          + stub auth]     grafana (unmarked)
#
# The sign-in provider is a stub inside the proxy's own Caddy, standing in for
# authward's /verify: 200 with X-Auth-User for a request carrying
# `authward_session=ok`, otherwise 401 with X-Login-Url. WireServe never talks
# to the provider — it only emits the snippet imports — so the stub exercises
# every part of the path that is WireServe's.
#
# Rootful Podman, like the other harnesses that rewrite packets.
#
# Usage: sudo ./deploy/e2e/run-service-auth-test.sh
# Exit code 0 = every check passed.

set -euo pipefail
cd "$(dirname "$0")/../.."

INET=wireserve-sa-inet
COORD=wireserve-sa-coord
PROXY=wireserve-sa-proxy
HOME_AGENT=wireserve-sa-home
CLIENT=wireserve-sa-client
DEBUG_IMG=wireserve-e2e-debug-tools
PROXY_IMG=wireserve-agent-caddy:sa-test
ADMIN_TOKEN=service-auth-test-admin-token
DOMAIN=int.test
WG_PORT=51820

log()  { echo; echo "=== $* ==="; }
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
note() { echo "NOTE: $*"; }

cleanup() {
    podman rm -f "$COORD" "$PROXY" "$HOME_AGENT" "$CLIENT" >/dev/null 2>&1 || true
    for c in $(podman ps -aq --filter "name=wireserve-sa-helper" 2>/dev/null); do
        podman rm -f "$c" >/dev/null 2>&1 || true
    done
    podman network rm "$INET" >/dev/null 2>&1 || true
    [ -n "${WORK:-}" ] && rm -rf "$WORK"
    return 0
}
trap cleanup EXIT
cleanup
WORK=$(mktemp -d)

in_netns() {
    local target=$1; shift
    podman run --rm --name "wireserve-sa-helper-$$-$RANDOM" \
        --network "container:$target" --cap-add=NET_ADMIN --cap-add=NET_RAW "$DEBUG_IMG" "$@"
}
in_netns_bg() {
    local target=$1; shift
    podman run -d --name "wireserve-sa-helper-$$-$RANDOM" \
        --network "container:$target" "$DEBUG_IMG" "$@" >/dev/null
}
ip_on() {
    podman inspect "$1" --format "{{(index .NetworkSettings.Networks \"$2\").IPAddress}}"
}
admin() { podman exec "$COORD" wireserve-admin "$@"; }
svc_addr() {
    podman exec "$1" wireserve-agent list --json \
        | python3 -c "import json,sys; d=json.load(sys.stdin); print(next((s.get('vip4') or '' for s in d['services'] if s['name']=='$2'), ''))"
}
# HTTPS through the proxy, by name, from the client: status, then the body.
via_proxy() {
    local host=$1; shift
    in_netns "$CLIENT" curl -sk -o /dev/stdout -w '\nSTATUS %{http_code} %{redirect_url}\n' --max-time 10 \
        --resolve "$host.$DOMAIN:443:$WEB_VIP" "$@" "https://$host.$DOMAIN/"
}

log "checking prerequisites"
command -v podman >/dev/null || fail "podman not found on PATH"
command -v python3 >/dev/null || fail "python3 not found on PATH"
modinfo wireguard >/dev/null 2>&1 || fail "WireGuard kernel module not available"
[ "$(podman info --format '{{.Host.Security.Rootless}}')" = false ] \
    || fail "needs rootful podman (service-address rewrites are refused in a user namespace): sudo $0"
pass "podman, python3 and the WireGuard kernel module are present"

log "building images"
podman build -q -f deploy/docker/coordinator.Dockerfile -t wireserve-coordinator:sa-test . >/dev/null
podman build -q -f deploy/docker/agent.Dockerfile -t wireserve-agent:sa-test . >/dev/null
podman build -q -f deploy/e2e/debug-tools.Dockerfile -t "$DEBUG_IMG" deploy/e2e >/dev/null
# The proxy node: the agent plus Caddy, 2.11.2 or newer as authward requires.
podman build -q -t "$PROXY_IMG" -f - . >/dev/null <<'EOF'
FROM docker.io/library/caddy:2 AS caddy
FROM wireserve-agent:sa-test
COPY --from=caddy /usr/bin/caddy /usr/bin/caddy
EOF
pass "images built"

log "one segment, the coordinator naming services under $DOMAIN with 'web' as the proxy"
podman network create --internal "$INET" >/dev/null
podman run -d --name "$COORD" --network "$INET" \
    -e WIRESERVE_ADMIN_TOKEN="$ADMIN_TOKEN" \
    -e WIRESERVE_SERVICE_DOMAIN="$DOMAIN" -e WIRESERVE_SERVICE_PROXY=web \
    wireserve-coordinator:sa-test >/dev/null
sleep 2
COORD_IP=$(ip_on "$COORD" "$INET")

for c in "$PROXY" "$HOME_AGENT" "$CLIENT"; do
    img=wireserve-agent:sa-test
    [ "$c" = "$PROXY" ] && img=$PROXY_IMG
    podman run -d --name "$c" --network "$INET" \
        --cap-add=NET_ADMIN --security-opt unmask=/proc/sys --device /dev/net/tun \
        --entrypoint sleep "$img" infinity >/dev/null
done
sleep 1

log "the proxy's Caddyfile: the shipped example's snippets, a stub sign-in, internal TLS"
# The snippets are the example's own, verbatim, so what is tested is what is
# shipped. Only the site block differs: internal TLS instead of DNS-01, and a
# stub on 127.0.0.1:8080 where authward would listen.
python3 - "$WORK/Caddyfile" "$DOMAIN" <<'PY'
import re, sys
out, domain = sys.argv[1], sys.argv[2]
example = open("deploy/proxy/Caddyfile.services.example").read()
snippets = "".join(re.findall(r"^\((?:wireserve_auth|wireserve_upstream)\) \{\n.*?^\}\n", example, re.M | re.S))
assert snippets.count("wireserve_") == 2, "the example's snippets were not found"
# forward_auth keeps the original Host, so the stub listens on the port with
# no host of its own, bound to loopback like authward's default.
open(out, "w").write(f"""{{
	https_port 8443
	auto_https disable_redirects
}}

{snippets}
http://:8080 {{
	bind 127.0.0.1
	@ok header Cookie *authward_session=ok*
	handle @ok {{
		header X-Auth-User alice
		respond 200
	}}
	handle {{
		header X-Login-Url "https://auth.{domain}/login?rd=x"
		respond 401
	}}
}}

jellyfin.{domain}, grafana.{domain}, auth.{domain} {{
	tls internal
	import /etc/caddy/conf.d/wireserve.caddy
	handle {{
		respond "not a published service" 404
	}}
}}
""")
PY
podman exec "$PROXY" mkdir -p /etc/caddy/conf.d
podman cp "$WORK/Caddyfile" "$PROXY:/etc/caddy/Caddyfile"
podman exec "$PROXY" sh -c ': > /etc/caddy/conf.d/wireserve.caddy'
podman exec "$PROXY" caddy start --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1 \
    || fail "caddy would not start with the example's snippets"
pass "Caddy runs the example's snippets"

create_node() { admin create-node "$1" | grep -oE 'jtk_[a-f0-9]+'; }

log "joining the three agents"
for pair in "$PROXY:node-proxy" "$HOME_AGENT:node-home" "$CLIENT:node-client"; do
    c=${pair%%:*}; n=${pair#*:}
    jt=$(create_node "$n")
    podman exec "$c" wireserve-agent join "http://$COORD_IP:47820" --allow-plaintext-http "$jt" \
        --listen-port "$WG_PORT" --endpoint-addr "$(ip_on "$c" "$INET"):$WG_PORT" 2>/dev/null
done
podman exec -d "$PROXY" wireserve-agent daemon --poll-interval-secs 5 --proxy caddy
podman exec -d "$HOME_AGENT" wireserve-agent daemon --poll-interval-secs 5
podman exec -d "$CLIENT" wireserve-agent daemon --poll-interval-secs 5
sleep 12
pass "all three polling"

log "publishing the proxy, and two services on the home node"
podman exec "$PROXY" wireserve-agent serve web 443:8443
podman exec "$HOME_AGENT" wireserve-agent serve jellyfin 443:8096
podman exec "$HOME_AGENT" wireserve-agent serve grafana 443:3000
# Backends that answer with the request headers they were sent.
for port in 8096 3000; do
    in_netns_bg "$HOME_AGENT" socat "TCP-LISTEN:$port,fork,reuseaddr" \
        SYSTEM:'H=$(sed -u "/^\r$/q"); printf "HTTP/1.0 200 OK\r\n\r\nbackend:%s\n%s\n" '"$port"' "$H"'
done
sleep 12
admin approve-service node-proxy web >/dev/null 2>&1 || true
admin approve-service node-home grafana >/dev/null 2>&1 || true

log "1/6: marking jellyfin, and what the proxy generates for it"
admin approve-service node-home jellyfin --auth || fail "approve-service --auth was refused"
admin list-services | grep '^jellyfin' | grep -q 'sign-in=yes' || fail "list-services does not show the mark"
sleep 15
GEN=$(podman exec "$PROXY" cat /etc/caddy/conf.d/wireserve.caddy)
echo "$GEN" | sed 's/^/  /'
echo "$GEN" | grep -A1 '^handle @jellyfin' | grep -q 'import wireserve_auth' \
    || fail "the marked service does not import the sign-in"
echo "$GEN" | grep -A1 '^handle @grafana' | grep -q 'import wireserve_auth' \
    && fail "the unmarked service imports the sign-in"
[ "$(echo "$GEN" | grep -c 'import wireserve_upstream')" = 2 ] \
    || fail "every service's upstream must strip the sign-in cookie"
WEB_VIP=$(svc_addr "$CLIENT" web)
JF_VIP=$(svc_addr "$CLIENT" jellyfin)
GF_VIP=$(svc_addr "$CLIENT" grafana)
[ -n "$WEB_VIP" ] && [ -n "$JF_VIP" ] && [ -n "$GF_VIP" ] || fail "a service has no address (web=$WEB_VIP jellyfin=$JF_VIP grafana=$GF_VIP)"
pass "sign-in on jellyfin only; the cookie strip on both"

log "2/6: no session, sent to sign in"
OUT=$(via_proxy jellyfin) || true
echo "$OUT" | tail -1
echo "$OUT" | grep -q '^STATUS 302 https://auth.int.test/login' || fail "expected a redirect to the login URL"
echo "$OUT" | grep -q 'backend:' && fail "the backend was reached without a session"
pass "redirected to the login URL; the backend never saw the request"

log "3/6: with a session, the backend sees who, and not the cookie"
OUT=$(via_proxy jellyfin -H 'Cookie: theme=dark; authward_session=ok; lang=de') || true
echo "$OUT" | grep -q '^STATUS 200' || { echo "$OUT"; fail "a signed-in request did not reach the backend"; }
echo "$OUT" | grep -qi '^X-Auth-User: alice' || { echo "$OUT"; fail "the backend did not get the identity header"; }
echo "$OUT" | grep -q 'authward_session' && { echo "$OUT"; fail "the sign-in cookie reached the backend"; }
echo "$OUT" | grep -qi '^Cookie: .*theme=dark' || { echo "$OUT"; fail "other cookies were lost"; }
pass "X-Auth-User: alice reached the backend; authward_session did not, theme did"

log "4/6: an unmarked service needs no sign-in, and loses the cookie too"
OUT=$(via_proxy grafana -H 'Cookie: authward_session=ok') || true
echo "$OUT" | grep -q '^STATUS 200' || { echo "$OUT"; fail "the unmarked service asked for a sign-in"; }
echo "$OUT" | grep -q 'authward_session' && { echo "$OUT"; fail "the sign-in cookie reached an unmarked backend"; }
pass "grafana served without a sign-in, without the cookie"

log "5/6: the way round the sign-in leads nowhere"
in_netns "$CLIENT" curl -s --max-time 6 "http://$GF_VIP:443/" | grep -q 'backend:3000' \
    || fail "the unmarked service's own address is unreachable — the next check would prove nothing"
if in_netns "$CLIENT" curl -s --max-time 6 "http://$JF_VIP:443/" | grep -q 'backend:'; then
    fail "the marked service was reached directly, around the sign-in"
fi
pass "grafana's own address answers; jellyfin's does not"

log "6/6: service-auth off gives the direct path back"
admin service-auth jellyfin off
sleep 15
in_netns "$CLIENT" curl -s --max-time 6 "http://$JF_VIP:443/" | grep -q 'backend:8096' \
    || fail "jellyfin's own address is still closed after the mark was removed"
OUT=$(via_proxy jellyfin) || true
echo "$OUT" | grep -q '^STATUS 200' || { echo "$OUT"; fail "the proxy still asks for a sign-in"; }
pass "unmarked again: reachable directly and through the proxy without a sign-in"

echo
echo "=== SERVICE AUTH TEST COMPLETE ==="

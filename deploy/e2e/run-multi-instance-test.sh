#!/usr/bin/env bash
# Several agents on one host, end to end, with the real binaries — and no
# root, no containers: everything runs inside a throwaway unprivileged
# user + network namespace (`unshare -rn`), so nothing touches the
# machine's own interfaces, firewall or /etc/hosts.
#
# Topology, all inside that namespace:
#
#   "host" netns (the namespace the script runs in)        "peer" netns
#   ├─ coordinator A (mesh A, 10.201.0.0/24)                ├─ agent, instance default → mesh A
#   ├─ coordinator B (mesh B, 10.202.0.0/24)                └─ agent, instance work    → mesh B
#   ├─ agent, instance default → mesh A
#   ├─ agent, instance work    → mesh B          veth 10.99.0.1 <-> 10.99.0.2
#   ├─ a foreign WireGuard tunnel called wireserve0 (someone else's)
#   └─ a host firewall that drops INPUT (iptables-nft, ufw-style, and a
#      native nftables `inet filter` table)
#
# Checks that the two host instances pick separate interfaces around the
# foreign one, keep separate ports, tables, hosts blocks and firewall
# rules, carry real traffic only for what each declared, don't fight over
# the host firewall, clean up after each other only once one is dead, and
# that the default instance clears up after a pre-instances (wg0) agent.
#
# Prerequisites: unprivileged user namespaces, the WireGuard kernel
# module, nft, iptables-nft, wg, python3. Usage:
#   cargo build --workspace && ./deploy/e2e/run-multi-instance-test.sh
# Exit code 0 = every check passed.

set -euo pipefail
cd "$(dirname "$0")/../.."   # repo root
BIN=${BIN:-$PWD/target/debug}

if [ -z "${WIRESERVE_IN_TEST_NETNS:-}" ]; then
    for tool in unshare nsenter ip nft iptables-nft wg python3; do
        command -v "$tool" >/dev/null || { echo "FAIL: $tool not found" >&2; exit 1; }
    done
    for b in wireserve-agent wireserve-coordinator wireserve-admin; do
        [ -x "$BIN/$b" ] || { echo "FAIL: $BIN/$b missing — run cargo build --workspace" >&2; exit 1; }
    done
    WIRESERVE_IN_TEST_NETNS=1 exec unshare -rn "$0" "$@"
fi

WORK=$(mktemp -d)
PIDS=()
log() { echo; echo "=== $* ==="; }
pass() { echo "PASS: $*"; }
fail() {
    echo "FAIL: $*" >&2
    for f in "$WORK"/*.log; do echo "--- $f"; tail -20 "$f"; done >&2
    exit 1
}
cleanup() {
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
    wait 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

ADMIN_TOKEN=multi-instance-test-token
POLL=2

# ---------------------------------------------------------------------
log "network: loopback, a peer namespace, a veth between them"
ip link set lo up
unshare -n sleep infinity &
PEER_NS=$!
PIDS+=("$PEER_NS")
sleep 0.2
in_peer() { nsenter -t "$PEER_NS" -n "$@"; }
ip link add vh type veth peer name vp
ip link set vp netns "$PEER_NS"
ip addr add 10.99.0.1/24 dev vh && ip link set vh up
in_peer ip link set lo up
in_peer ip addr add 10.99.0.2/24 dev vp
in_peer ip link set vp up
# Default routes, as real hosts have: without one, defguard's
# `configure_peer_routing` blackholes every peer endpoint (see the
# README's known issues).
ip route add default via 10.99.0.2
in_peer ip route add default via 10.99.0.1

log "a host firewall that drops everything not explicitly allowed"
iptables-nft -P INPUT DROP
iptables-nft -A INPUT -i lo -j ACCEPT
iptables-nft -A INPUT -i vh -j ACCEPT
nft -f - <<'EOF'
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    iifname "vh" accept
  }
}
EOF

log "someone else's WireGuard tunnel already called wireserve0"
FOREIGN_KEY=$(wg genkey)
echo "$FOREIGN_KEY" > "$WORK/foreign.key"
ip link add wireserve0 type wireguard
wg set wireserve0 private-key "$WORK/foreign.key" listen-port 51900
ip addr add 192.0.2.77/32 dev wireserve0
ip link set wireserve0 up
FOREIGN_PUB=$(wg show wireserve0 public-key)

# ---------------------------------------------------------------------
log "two coordinators, one per mesh"
start_coordinator() {
    local name=$1 port=$2 v4=$3 v6=$4
    WIRESERVE_ADMIN_TOKEN=$ADMIN_TOKEN WIRESERVE_DB_PATH="$WORK/$name/db.sqlite" \
    WIRESERVE_LISTEN_ADDR="0.0.0.0:$port" WIRESERVE_ADMIN_LISTEN_ADDR="127.0.0.1:$((port + 1))" \
    WIRESERVE_NET_V4_CIDR=$v4 WIRESERVE_NET_V6_PREFIX=$v6 WIRESERVE_REQUIRE_SERVICE_APPROVAL=false \
        "$BIN/wireserve-coordinator" >"$WORK/coord-$name.log" 2>&1 &
    PIDS+=("$!")
}
start_coordinator a 47820 10.201.0.0/24 fd00:201::/64
start_coordinator b 47830 10.202.0.0/24 fd00:202::/64
sleep 1

token() {
    WIRESERVE_ADMIN_TOKEN=$ADMIN_TOKEN WIRESERVE_COORDINATOR_URL="http://127.0.0.1:$(($1 + 1))" \
        "$BIN/wireserve-admin" create-node "$2" | grep -oE 'jtk_[a-f0-9]+'
}

# Each side has its own state, sockets and hosts file; each command runs
# in its side's network namespace.
host_env=(env WIRESERVE_STATE_ROOT="$WORK/host/lib" WIRESERVE_RUN_ROOT="$WORK/host/run" WIRESERVE_HOSTS_PATH="$WORK/host/hosts")
peer_env=(env WIRESERVE_STATE_ROOT="$WORK/peer/lib" WIRESERVE_RUN_ROOT="$WORK/peer/run" WIRESERVE_HOSTS_PATH="$WORK/peer/hosts")
mkdir -p "$WORK/host" "$WORK/peer"
printf '127.0.0.1 localhost\n' | tee "$WORK/host/hosts" > "$WORK/peer/hosts"
# Plain commands, not functions, so a backgrounded daemon's $! is the
# agent itself (env and nsenter exec it) and signals reach it.
host_cmd=("${host_env[@]}" "$BIN/wireserve-agent")
peer_cmd=(nsenter -t "$PEER_NS" -n "${peer_env[@]}" "$BIN/wireserve-agent")
host() { "${host_cmd[@]}" "$@"; }
peer() { "${peer_cmd[@]}" "$@"; }
daemon() {  # side instance [args…]
    local side=$1 inst=$2
    shift 2
    local -n cmd="${side}_cmd"
    "${cmd[@]}" --instance "$inst" daemon --poll-interval-secs "$POLL" "$@" >>"$WORK/$side-$inst.log" 2>&1 &
    PIDS+=("$!")
    LAST_PID=$!
}
state() { python3 -c "import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])" "$1" "$2"; }
list() { "$1" --instance "$2" list; }
field() { python3 -c "import json,sys; print(json.load(sys.stdin)[sys.argv[1]])" "$1"; }
peer_ip() { python3 -c "
import json, sys
print(next(p['ip4'] for p in json.load(sys.stdin)['peers'] if p['name'] == sys.argv[1]))" "$1"; }

# ---------------------------------------------------------------------
log "joining: host default + work, peer default + work"
host --instance default join http://10.99.0.1:47820 "$(token 47820 host-a)" --endpoint-addr 10.99.0.1:51820 >/dev/null
host --instance work join http://10.99.0.1:47830 "$(token 47830 host-b)" --endpoint-addr 10.99.0.1:51821 >/dev/null
peer --instance default join http://10.99.0.1:47820 "$(token 47820 peer-a)" --listen-port 51820 --endpoint-addr 10.99.0.2:51820 >/dev/null
peer --instance work join http://10.99.0.1:47830 "$(token 47830 peer-b)" --listen-port 51821 --endpoint-addr 10.99.0.2:51821 >/dev/null

[ "$(state "$WORK/host/lib/agent-state.json" listen_port)" = 51820 ] || fail "default instance did not get port 51820"
[ "$(state "$WORK/host/lib/instances/work/agent-state.json" listen_port)" = 51821 ] \
    || fail "the second instance did not get the next free port"
pass "join picked separate listen ports (51820, 51821) without being told"

log "starting all four daemons"
# One after the other on the host, so which gets which name is fixed.
# Generous wait: removing an interface (a leftover, at start) includes a
# systemd-resolved cache flush over D-Bus inside defguard, which times
# out after 25s in a namespace that can't reach the host's bus.
# (Started together they'd split the names either way round, which is
# fine, but the checks below want to know.)
up() { for _ in $(seq 600); do "$1" --instance "$2" list >/dev/null 2>&1 && return; sleep 0.1; done; fail "$1/$2 did not come up"; }
daemon host default; HOST_DEFAULT=$LAST_PID; up host default
daemon host work; HOST_WORK=$LAST_PID; up host work
daemon peer default
daemon peer work
sleep $((POLL * 3))

[ "$(list host default | field ifname)" = wireserve1 ] || fail "default instance is not on wireserve1"
[ "$(list host work | field ifname)" = wireserve2 ] || fail "work instance is not on wireserve2"
pass "the instances picked wireserve1 and wireserve2, around the foreign wireserve0"
[ "$(wg show wireserve0 public-key)" = "$FOREIGN_PUB" ] && ip addr show wireserve0 | grep -q 192.0.2.77 \
    || fail "the foreign wireserve0 was modified"
pass "the foreign wireserve0 kept its key and address"

nft list tables | grep -qx 'table inet wireserve.wireserve1' && nft list tables | grep -qx 'table inet wireserve.wireserve2' \
    || fail "missing per-interface tables: $(nft list tables)"
pass "each instance has its own nftables table"

if host --instance default daemon 2>"$WORK/second.err"; then fail "a second daemon for the same instance started"; fi
grep -q "already using instance 'default'" "$WORK/second.err" || fail "unexpected error: $(cat "$WORK/second.err")"
pass "a second daemon for the same instance is refused"

# ---------------------------------------------------------------------
log "services: each instance opens only what it declared, only on its own interface"
host --instance default serve alpha 7001 >/dev/null
host --instance work serve beta 7002 >/dev/null
for port in 7001 7002 7003; do
    python3 -c "
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', int(sys.argv[1]))); s.listen()
while True: s.accept()[0].close()" "$port" &
    PIDS+=("$!")
done
sleep $((POLL * 3))

HOST_A=$(list peer default | peer_ip host-a)
HOST_B=$(list peer work | peer_ip host-b)
echo "host's mesh addresses: $HOST_A (mesh A), $HOST_B (mesh B)"
reach() { in_peer timeout 3 python3 -c "import socket,sys; socket.create_connection((sys.argv[1], int(sys.argv[2])), 2)" "$1" "$2" 2>/dev/null; }
reach "$HOST_A" 7001 || fail "mesh A: declared port 7001 unreachable"
reach "$HOST_B" 7002 || fail "mesh B: declared port 7002 unreachable"
pass "each mesh reaches the port its own instance declared (through the host firewall)"
if reach "$HOST_A" 7002; then fail "mesh A reached 7002, which only the other instance declared"; fi
if reach "$HOST_B" 7001; then fail "mesh B reached 7001, which only the other instance declared"; fi
if reach "$HOST_A" 7003 || reach "$HOST_B" 7003; then fail "an undeclared port was reachable"; fi
pass "nothing else is reachable: not the other instance's port, not an undeclared one"

grep -qx '# BEGIN WIRESERVE' "$WORK/peer/hosts" && grep -q 'alpha.wg' "$WORK/peer/hosts" \
    || fail "peer default block missing alpha: $(cat "$WORK/peer/hosts")"
grep -qx '# BEGIN WIRESERVE work' "$WORK/peer/hosts" && grep -q 'beta.wg' "$WORK/peer/hosts" \
    || fail "peer work block missing beta: $(cat "$WORK/peer/hosts")"
pass "each instance keeps its own hosts-file block"

# ---------------------------------------------------------------------
log "the host firewall: one accept per instance, and nobody keeps rewriting them"
tags() { { nft list table inet filter; iptables-nft -S INPUT; } | grep -c "wireserve:$1\"" || true; }
[ "$(tags wireserve1)" = 2 ] && [ "$(tags wireserve2)" = 2 ] \
    || fail "expected 2+2 tagged accepts, got $(tags wireserve1)+$(tags wireserve2)"
BEFORE=$(nft -a list table inet filter; iptables-nft -S INPUT)
sleep $((POLL * 3))
[ "$BEFORE" = "$(nft -a list table inet filter; iptables-nft -S INPUT)" ] \
    || fail "the host firewall rules keep changing: the instances are fighting"
pass "both instances' rules sit side by side, stable across poll cycles"

# ---------------------------------------------------------------------
log "a crashed instance: the other one cleans up its rules; a restart gets its name back"
kill -9 "$HOST_WORK"
wait "$HOST_WORK" 2>/dev/null || true
sleep $((POLL * 2))
[ "$(tags wireserve2)" = 0 ] || fail "the dead instance's accepts are still there"
[ "$(tags wireserve1)" = 2 ] || fail "the live instance lost its own accepts"
pass "the running instance removed the dead one's leftover accepts, and only those"

daemon host work; HOST_WORK=$LAST_PID; up host work
sleep $((POLL * 2))
[ "$(list host work | field ifname)" = wireserve2 ] || fail "restarted instance moved off wireserve2"
[ "$(tags wireserve2)" = 2 ] || fail "restarted instance's accepts not back"
reach "$HOST_B" 7002 || fail "mesh B unreachable after the restart"
pass "the restarted instance is back on wireserve2 with its rules"

# ---------------------------------------------------------------------
log "stopping one instance leaves the other untouched"
kill -TERM "$HOST_DEFAULT"
wait "$HOST_DEFAULT" 2>/dev/null || true
ip link show wireserve1 >/dev/null 2>&1 && fail "wireserve1 still exists after stop"
[ "$(tags wireserve1)" = 0 ] || fail "stopped instance left its accepts"
[ "$(tags wireserve2)" = 2 ] || fail "the other instance's accepts went too"
nft list tables | grep -q 'wireserve.wireserve1' && fail "stopped instance left its table"
grep -qx '# BEGIN WIRESERVE' "$WORK/host/hosts" && fail "stopped instance left its hosts block"
grep -qx '# BEGIN WIRESERVE work' "$WORK/host/hosts" || fail "the other instance's hosts block went too"
reach "$HOST_B" 7002 || fail "mesh B stopped working when the other instance stopped"
pass "interface, table, accepts and hosts block of the stopped instance are gone; the other still serves"

# ---------------------------------------------------------------------
log "upgrade from a pre-instances agent: its wg0, table, guard and accepts are cleared up"
# What a crashed old agent leaves: wg0 carrying this node's key, the
# fixed-name `inet wireserve` table, a fixed-name guard table, and
# accepts tagged wireserve:wg0. Put there by hand, with the default
# instance's own key.
KEY=$(state "$WORK/host/lib/agent-state.json" private_key)
echo "$KEY" > "$WORK/own.key"
ip link add wg0 type wireguard
wg set wg0 private-key "$WORK/own.key"
nft add table inet wireserve
nft add table inet wireserve-interop
iptables-nft -I INPUT 1 -i wg0 -m comment --comment wireserve:wg0 -j ACCEPT
nft insert rule inet filter input iifname wg0 counter accept comment '"wireserve:wg0"'
daemon host default; HOST_DEFAULT=$LAST_PID; up host default
sleep $((POLL * 2))
ip link show wg0 >/dev/null 2>&1 && fail "the old agent's wg0 is still there"
nft list tables | grep -Eqx 'table inet (wireserve|wireserve-interop)' && fail "legacy tables still there: $(nft list tables)"
[ "$(tags wg0)" = 0 ] || fail "legacy wireserve:wg0 accepts still there"
[ "$(list host default | field ifname)" = wireserve1 ] || fail "default instance not back on wireserve1"
reach "$HOST_A" 7001 || fail "mesh A unreachable after the upgrade cleanup"
pass "legacy wg0, tables and accepts removed; the instance came back on its own interface"

# ---------------------------------------------------------------------
log "leave takes everything of that instance, nothing else"
host --instance work leave >/dev/null
wait "$HOST_WORK" 2>/dev/null || true   # leave answers first, then tears down
ip link show wireserve2 >/dev/null 2>&1 && fail "wireserve2 still exists after leave"
[ "$(tags wireserve2)" = 0 ] || fail "leave left the accepts"
[ "$(tags wireserve1)" = 2 ] || fail "leave took the other instance's accepts"
pass "leave removed only its own instance"
[ "$(wg show wireserve0 public-key)" = "$FOREIGN_PUB" ] || fail "the foreign wireserve0 was modified"
pass "the foreign wireserve0 survived all of it"

echo
echo "=== ALL CHECKS PASSED ==="

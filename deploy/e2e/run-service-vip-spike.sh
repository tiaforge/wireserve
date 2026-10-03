#!/usr/bin/env bash
# Service VIP data-path spike (PLAN.md M20, phase 0). No wireserve code
# runs here: a hand-written nft ruleset in three network namespaces
# proves the kernel mechanism the agent will generate, before any product
# code depends on it.
#
#   client ──wg0── owner ──veth── app
#
# owner publishes, per service, a VIP routed to it by the client's
# AllowedIPs, and rewrites VIP:PUB → nodeIP:TGT statelessly BEFORE
# conntrack (raw priority), marking the packet. Replies are rewritten
# back after every NAT hook. Nothing here is a NAT of ours, so the app
# namespace's netavark-style DNAT (what rootful Podman and Docker with
# userland-proxy=false rely on) still applies as the connection's only
# NAT.
#
# Asserts: native and containerised targets over TCP and UDP, the server
# seeing the client's real mesh IP, two services on one node both on :80,
# a target bound to the node's mesh IP only, access from the owner itself,
# refusal of every non-published port, and correct L4 checksums after the
# rewrite.
#
# Needs podman and the WireGuard kernel module. Runs in one privileged
# container, and that container must be ROOTFUL: since the "netfilter:
# disable payload mangling in userns" hardening (in 7.x kernels), nft
# refuses every header write (`ip daddr set`, `tcp dport set`) with EPERM
# in any network namespace owned by a non-init user namespace, and rootless
# podman is exactly that. A real agent runs as root in the host's own
# namespace and is unaffected.
#
# Usage: sudo ./deploy/e2e/run-service-vip-spike.sh

set -euo pipefail
cd "$(dirname "$0")/../.."   # repo root

CTR=wireserve-vip-spike
DEBUG_IMG=wireserve-e2e-debug-tools

log() { echo; echo "=== $* ==="; }
fail() { echo "FAIL: $*" >&2; exit 1; }

cleanup() { podman rm -fv -t 0 "$CTR" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

command -v podman >/dev/null || fail "podman not found on PATH"
modinfo wireguard >/dev/null 2>&1 || fail "WireGuard kernel module not available"
[ "$(podman info --format '{{.Host.Security.Rootless}}')" = false ] \
    || fail "needs rootful podman (nft refuses payload rewrites in user namespaces): sudo $0"

log "building debug image"
podman build -q -f deploy/e2e/debug-tools.Dockerfile -t "$DEBUG_IMG" deploy/e2e >/dev/null

podman run -d --name "$CTR" --privileged --network none "$DEBUG_IMG" >/dev/null

podman exec -i "$CTR" bash -s <<'SPIKE'
set -euo pipefail
PASSES=0
pass() { echo "PASS: $*"; PASSES=$((PASSES + 1)); }
fail() { echo "FAIL: $*" >&2; exit 1; }
nsx() { local ns=$1; shift; nsenter --net=/run/netns/"$ns" "$@"; }

MARK=0x01000000   # SERVICE_MARK in firewall/nftables.rs
CLIENT=10.99.0.1 NODE=10.99.0.2 VIP1=10.99.0.50 VIP2=10.99.0.51 APP=172.30.0.2

# ---- topology ----
for ns in client owner app; do ip netns add $ns; nsx $ns ip link set lo up; done
ip link add u0 type veth peer name u1
ip link set u0 netns client; ip link set u1 netns owner
nsx client ip addr add 192.168.77.1/24 dev u0; nsx client ip link set u0 up
nsx owner  ip addr add 192.168.77.2/24 dev u1; nsx owner  ip link set u1 up

ip link add a0 type veth peer name a1
ip link set a0 netns owner; ip link set a1 netns app
nsx owner ip addr add 172.30.0.1/24 dev a0; nsx owner ip link set a0 up
nsx app   ip addr add $APP/24 dev a1; nsx app ip link set a1 up
nsx app   ip route add default via 172.30.0.1
nsx owner sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"

umask 077
wg genkey > /tmp/ck; wg pubkey < /tmp/ck > /tmp/cp
wg genkey > /tmp/ok; wg pubkey < /tmp/ok > /tmp/op
nsx client ip link add wg0 type wireguard
nsx owner  ip link add wg0 type wireguard
nsx client wg set wg0 private-key /tmp/ck listen-port 51820 \
    peer "$(cat /tmp/op)" endpoint 192.168.77.2:51820 allowed-ips $NODE/32,$VIP1/32,$VIP2/32
nsx owner  wg set wg0 private-key /tmp/ok listen-port 51820 \
    peer "$(cat /tmp/cp)" endpoint 192.168.77.1:51820 allowed-ips $CLIENT/32
nsx client ip addr add $CLIENT/32 dev wg0; nsx client ip link set wg0 up
nsx owner  ip addr add $NODE/32 dev wg0;   nsx owner  ip link set wg0 up
for ip in $NODE $VIP1 $VIP2; do nsx client ip route add $ip/32 dev wg0; done
nsx owner ip route add $CLIENT/32 dev wg0
# The owner routes its own VIPs to wg0 too, so a local client's initial
# route lookup succeeds (and picks the mesh source address) even on a host
# with no default route; the output rewrite then re-routes it locally.
for ip in $VIP1 $VIP2; do nsx owner ip route add $ip/32 dev wg0; done

# ---- servers: each prints the address it saw the client connect from ----
srv() { # ns proto bind port tag
    local lopt=""; [ "$3" != any ] && lopt=",bind=$3"
    if [ "$2" = tcp ]; then
        nsx "$1" socat TCP-LISTEN:"$4",fork,reuseaddr"$lopt" SYSTEM:"echo $5 peer=\$SOCAT_PEERADDR" &
    else
        nsx "$1" socat UDP-RECVFROM:"$4",fork"$lopt" SYSTEM:"echo $5 peer=\$SOCAT_PEERADDR" &
    fi
}
srv owner tcp any 5080 native-tcp
srv owner udp any 5080 native-udp
srv owner tcp $NODE 5081 node-bound-tcp
srv app   tcp any 6080 ctr-tcp
srv app   udp any 6080 ctr-udp
sleep 1

# ---- container runtime stand-in: netavark's shape, DNAT only ----
nsx owner nft -f - <<EOF
table ip fake-netavark {
  chain pre { type nat hook prerouting priority dstnat;
    fib daddr type local tcp dport 6080 dnat to $APP:6080
    fib daddr type local udp dport 6080 dnat to $APP:6080
  }
  chain out { type nat hook output priority -100;
    fib daddr type local tcp dport 6080 dnat to $APP:6080
    fib daddr type local udp dport 6080 dnat to $APP:6080
  }
  chain post { type nat hook postrouting priority srcnat;
    oifname "a0" ip saddr $NODE masquerade
  }
}
EOF

# ---- the ruleset the agent will generate ----
# svc(vip, proto, pub, tgt) -> the forward rewrite, used in two chains.
fwd_rw() { echo "ip daddr $1 $2 dport $3 ip daddr set $NODE $2 dport set $4 meta mark set meta mark | $MARK"; }
rev_rw() { echo "ct direction reply ct mark & $MARK == $MARK ip saddr $NODE $2 sport $4 ip saddr set $1 $2 sport set $3"; }
MAPS="$VIP1 tcp 80 5080
$VIP1 udp 53 5080
$VIP1 tcp 81 5081
$VIP2 tcp 80 6080
$VIP2 udp 80 6080"
PRE="" OUT="" REV=""
while read -r v p pub tgt; do
    PRE+="    iifname \"wg0\" $(fwd_rw $v $p $pub $tgt)"$'\n'
    OUT+="    $(fwd_rw $v $p $pub $tgt)"$'\n'
    REV+="    $(rev_rw $v $p $pub $tgt)"$'\n'
done <<< "$MAPS"

nsx owner nft -f - <<EOF
table inet wireserve.wg0 {
  chain svc-pre { type filter hook prerouting priority raw;
$PRE  }
  chain svc-out { type route hook output priority raw;
$OUT  }
  chain svc-mark-pre { type filter hook prerouting priority mangle;
    meta mark & $MARK == $MARK ct mark set ct mark | $MARK
  }
  chain svc-mark-out { type route hook output priority mangle;
    meta mark & $MARK == $MARK ct mark set ct mark | $MARK
  }
  chain wireserve-in { type filter hook input priority filter; policy accept;
    iifname "wg0" ct state established,related accept
    iifname "wg0" ct mark & $MARK == $MARK accept
    iifname "wg0" drop
  }
  chain wireserve-fwd { type filter hook forward priority filter; policy accept;
    iifname "wg0" ct mark & $MARK == $MARK accept
    iifname "wg0" drop
  }
  chain svc-rev-post { type filter hook postrouting priority 300;
$REV  }
  chain svc-rev-in { type filter hook input priority 300;
$REV  }
}
EOF
echo "--- owner ruleset ---"; nsx owner nft list table inet wireserve.wg0

# ---- checksum capture: only packets the rewrite produced — replies as
# the client receives them, requests as the container receives them.
# Never a host's own outgoing packets: with checksum offload those are
# captured before the checksum is filled in, and always look wrong. ----
nsx client tcpdump -nn -vv -i wg0 -l "(tcp or udp) and dst host $CLIENT" > /tmp/cap-client 2>/dev/null &
CAP1=$!
nsx owner  tcpdump -nn -vv -i a0 -l "src host $CLIENT and dst host $APP" > /tmp/cap-app 2>/dev/null &
CAP2=$!
sleep 1

ask() { # ns proto addr port
    local t=TCP; [ "$2" = udp ] && t=UDP
    echo hi | nsx "$1" timeout 4 socat -t2 - "$t:$3:$4" 2>/dev/null || true
}
expect() { # ns proto addr port tag peer
    local out; out=$(ask "$1" "$2" "$3" "$4")
    [ "$out" = "$5 peer=$6" ] || fail "$1 -> $3:$4/$2: expected '$5 peer=$6', got '$out'"
    pass "$1 -> $3:$4/$2 reached $5, which saw $6"
}
refused() { # ns proto addr port
    local out; out=$(ask "$1" "$2" "$3" "$4")
    [ -z "$out" ] || fail "$1 -> $3:$4/$2 should be unreachable, got '$out'"
    pass "$1 -> $3:$4/$2 unreachable"
}

expect client tcp $VIP1 80 native-tcp $CLIENT
expect client udp $VIP1 53 native-udp $CLIENT
expect client tcp $VIP1 81 node-bound-tcp $CLIENT
expect client tcp $VIP2 80 ctr-tcp $CLIENT
expect client udp $VIP2 80 ctr-udp $CLIENT

# Only published ports: the target port on either address, and ports the
# VIP doesn't publish, must all be closed to the mesh.
refused client tcp $NODE 5080
refused client udp $NODE 5080
refused client tcp $VIP1 5080
refused client tcp $NODE 6080
refused client tcp $VIP2 6080
refused client udp $VIP1 80

# From the owner itself.
expect owner tcp $VIP1 80 native-tcp $NODE
expect owner udp $VIP1 53 native-udp $NODE
# A container sees host-originated traffic from its bridge gateway: the
# runtime masquerades it (fake-netavark's `post` chain, as netavark and
# Docker do). That's the runtime's doing, not ours; for a local client the
# host itself is the client, so there is no remote IP to preserve.
expect owner tcp $VIP2 80 ctr-tcp 172.30.0.1
expect owner udp $VIP2 80 ctr-udp 172.30.0.1
# The owner's own direct access to its target port is untouched: its reply
# must NOT be rewritten to the VIP (no mark on this flow).
expect owner tcp $NODE 5080 native-tcp $NODE

# Several flows at once and a larger payload, to exercise more than one
# segment per connection through the rewrite.
big=$(head -c 200000 /dev/urandom | base64 -w0)
nsx owner socat TCP-LISTEN:5090,reuseaddr SYSTEM:'wc -c' &
sleep 0.5
nsx owner nft add rule inet wireserve.wg0 svc-pre iifname wg0 "$(fwd_rw $VIP1 tcp 90 5090)"
nsx owner nft add rule inet wireserve.wg0 svc-rev-post "$(rev_rw $VIP1 tcp 90 5090)"
got=$(echo "$big" | nsx client timeout 10 socat -t5 - TCP:$VIP1:90 | tr -d ' ')
[ "$got" = "$(( ${#big} + 1 ))" ] || fail "bulk transfer through the rewrite: got '$got' bytes, expected $(( ${#big} + 1 ))"
pass "200 KB transfer through the rewrite arrived intact"

sleep 1
kill "$CAP1" "$CAP2" 2>/dev/null || true; sleep 0.5
for f in /tmp/cap-client /tmp/cap-app; do
    if grep -qiE 'incorrect|bad (tcp|udp) cksum' "$f"; then
        grep -iE 'incorrect|bad (tcp|udp) cksum' "$f" | head
        fail "bad checksum in $f"
    fi
    grep -qE '\(correct\)|udp sum ok' "$f" || fail "no verified checksums captured in $f"
done
pass "every captured TCP/UDP checksum verified correct"

echo; echo "ALL $PASSES CHECKS PASSED"
SPIKE

# Ports, firewalls and host setup

## Coordinator host

| Port | Direction | Who connects | Notes |
| --- | --- | --- | --- |
| 443/tcp | inbound | every agent | your reverse proxy, terminating TLS |
| 47820/tcp | none | the proxy only | plain HTTP, must not be reachable from an untrusted network |
| 47821/tcp | none | nobody | admin listener, loopback only; the coordinator refuses to start if it is not |

The coordinator is not a WireGuard peer and needs no UDP port, no
`NET_ADMIN`, and no access to `/dev/net/tun`. Admin commands run inside the
host or container (`podman exec <container> wireserve-admin ...`), because
the admin port is deliberately unreachable from anywhere else.

## Agent nodes

| Port | Direction | Who connects | Notes |
| --- | --- | --- | --- |
| 51820/udp | inbound | other agent nodes, phones | the WireGuard listen port, on the node's real interface |
| relay ports/udp | inbound | phones | **carriers only, and only the ports `wireserve-admin transit ports` lists** — see below |
| 443/tcp | outbound | the coordinator | the poll loop |
| 443/tcp | outbound | your ACME CA | the TLS terminator, for certificates (Let's Encrypt by default) |

Inbound UDP 51820 has to reach the node for other peers to open a tunnel to
it, which usually means a port-forward on the router plus an
`--endpoint` the other nodes can resolve. A node behind NAT with no
port-forward can still reach nodes that do have one, and they can reach
back into it, because `PersistentKeepalive` holds its side of the mapping
open. Two nodes that both lack a forward cannot reach each other at all.
Unless a third node relays them, that is: see
[relaying](#6-route-through-another-node-when-nat-blocks-a-direct-path), which
needs nothing opened, since relayed sessions travel inside the carrier's own
tunnels. `deploy/e2e/run-nat-test.sh` builds this topology and checks all of
it.

**What a carrier needs open, and when.** Nothing, for relaying between
agents. For phones: one UDP port per node a phone reaches
through it — that node's relay port, `41000` plus its number — on its public
IPv4 address. Its own firewall (ufw, firewalld, nftables) is wireserve's to
handle; a firewall **outside** the machine is yours: a cloud provider's
security group, or the router's port forward for a carrier at home.
`device create` checks each port from outside before writing a config that
needs it, and stops with the exact port and address if it is closed;
`wireserve-admin transit ports` lists them all afterwards, including those no
device uses any more. A port stays the same for the node's life, so it is
opened once. The whole relay range (`41000`–`42999` by default, moved with
`WIRESERVE_RELAY_PORT_BASE`) is closed to anything not relayed on a
carrier's other interfaces, so keep other services off it there.

**Two machines behind the same router is the case to watch.** They learn
each other's address as their shared router's external one, so reaching it
from inside means sending a packet out to your own NAT and expecting it
back, which is NAT hairpinning. Many routers do not do it, and where it
fails those two nodes cannot reach each other even though both reach
everything else on the mesh normally. Giving at least one of them a
port-forward avoids it.

A related wrinkle if you skip `--endpoint`: the coordinator falls back
to the source address it observed plus the port the node reported for
itself, and behind NAT the port a router maps for WireGuard's UDP is not
that one. The recorded endpoint is then wrong, and two nodes behind one
router get recorded identically. It self-corrects, because WireGuard
replaces a peer's endpoint with the real source of the first packet it
receives, so any node that speaks within its keepalive (10 seconds between
agents, 25 for a phone) is found.
Set `--endpoint` on nodes that have a stable reachable address rather
than relying on the guess.

The agent needs `CAP_NET_ADMIN` and `/dev/net/tun`, and in a container it
needs host networking, or the mesh exists only inside that container. The
systemd unit also grants `CAP_CHOWN`, which it uses for one thing: handing
its socket to the `wireserve` group.

## Two conflicts worth checking before the first start

**The interface name.** The agent picks the first free name of
`wireserve0` … `wireserve15` and keeps it across restarts (it's stored in
the instance's state). It never takes over an interface it did not create:
a name held by another tunnel is simply skipped. `--ifname <name>` pins an
exact name instead — then a conflict makes the daemon refuse to start
rather than pick another, since you presumably refer to that name
elsewhere — and `--ifname auto` removes the pin.

**The mesh address ranges.** If you left `WIRESERVE_NET_V4_CIDR` and
`WIRESERVE_NET_V6_PREFIX` unset, the coordinator already generated a safe
pair for you on first start (see [Running the coordinator](coordinator.md)) and there is
nothing to do here. This section is for anyone who set one or both
explicitly — the compiled-in defaults are poor choices, for unrelated
reasons, and changing them requires care: addresses are
allocated once and kept for the life of the node record, so a later change
leaves the mesh addressed out of two ranges. Each node also pins the ranges
it joined with and ignores any peer or service address outside them (so a
compromised coordinator can't route arbitrary addresses into its tunnel).
After a change, nodes joined under the new ranges therefore don't see
peers still addressed from the old ones until those are re-joined.

The compiled-in IPv4 default `100.90.0.0/24` sits inside `100.64.0.0/10`,
the carrier-grade-NAT block Tailscale allocates all of its addresses from
and some ISPs use on WAN links. A host running such an overlay routes that
whole `/10` to the overlay's interface, covering these mesh addresses too.

The compiled-in IPv6 default `fd00:90::/64` is not a Tailscale problem at
all, since Tailscale uses `fd7a:115c:a1e0::/48`. It is an RFC 4193
problem: a unique local address is `fd` followed by 40
**pseudo-randomly generated** bits, and that randomness is the entire
mechanism that lets two networks built by strangers be merged without
renumbering. `fd00:90::` throws it away, and round-numbered `fd00::`
prefixes are the most commonly hand-picked there are, so it collides with
exactly the neighbours it should coexist with. Generate your own the same
way the coordinator does internally:

```sh
python3 -c "import secrets; h=secrets.token_bytes(5).hex(); print(f'fd{h[0:2]}:{h[2:6]}:{h[6:10]}::/64')"
```

The coordinator warns at startup if either configured range still matches
one of these compiled-in defaults.

## Other firewalls on the host

A host firewall filters the mesh interface on its own, next to the agent's
table: ufw's default deny, firewalld's default zone, or a hand-written
`nftables.conf` with `policy drop` all block a declared service even though
the agent allows it (netfilter lets every table drop a packet; an accept in
one doesn't override a drop in another). So the agent makes them let the
mesh interface through, the same way NetBird does, and its own table then
decides what is actually reachable:

- **nftables tables** (native configs, crowdsec, geoip-shell, …): a rule
  `iifname "wireserve0" counter accept comment "wireserve:wireserve0"` at the
  top of every other table's input filter chain.
- **iptables** (ufw, Docker hosts, scripts; both nft-backed and legacy):
  `-A INPUT -i wireserve0 -m comment --comment "wireserve:wireserve0" -j ACCEPT`
  at the top of `INPUT`.
- **firewalld**: the interface goes into the `trusted` zone for the current
  boot only (never `--permanent`), plus a small table
  `inet wireserve-interop.wireserve0` that drops traffic *forwarded* from the mesh
  interface, because a trusted zone would otherwise let mesh peers route
  through this host. A zone you bound the interface to yourself is left
  alone (the agent logs that it did).

The carry interface (`wireserve0-t`, see
[relaying](#6-route-through-another-node-when-nat-blocks-a-direct-path)) gets
the same openings under its own name, with its own table, and never any for
forwarded traffic.

All of it is scoped to exactly the mesh interface, and only to traffic
addressed to this host: nothing is opened on any other interface, and
nothing is opened for outgoing traffic. Forwarded traffic is opened in two
narrow cases only. A transit-capable node gets
`iifname "wireserve0" oifname "wireserve0"` (mesh back into the mesh). A
node serving a device on its network gets `iifname "wireserve0"` and
`oifname "wireserve0"`, each with `ct mark & 0x01000000 == 0x01000000`
(iptables: `-m connmark --mark 0x1000000/0x1000000`), which matches only
connections the agent's own table rewrote to a declared target. The
firewalld guard gets the same exceptions ahead of its drop. The agent keeps it in
place when another tool reloads (`ufw reload`, `firewall-cmd --reload`,
`nft -f`), usually within a second, and removes all of it on stop or
`leave`. To see what it added:

```sh
sudo nft list ruleset | grep wireserve:
sudo iptables -S INPUT | grep wireserve:
firewall-cmd --get-zone-of-interface=wireserve0
```

`sudo ufw allow in on wireserve0` or similar manual exceptions are not
needed and can be removed.

A carrier (`transit on`) also gets one input accept that is not tied to
the mesh interface: `ct mark & 0x8000000 == 0x8000000` (iptables:
`-m connmark --mark 0x8000000/0x8000000`). Only the agent's own table sets
that bit, and only on the public relay port a `wireserve-admin
device create` is checking at that moment, so the coordinator's probe gets
through the host's own firewall and the check measures the firewalls
outside the host — the cloud firewall or router — which are the only ones
to open by hand. firewalld is not covered: on a firewalld host, open the
port being checked with `firewall-cmd --add-port=<port>/udp` for the
duration, or pass `--allow-unverified`.

In a container (Docker/Podman with host networking) the same happens on
the host, except for firewalld, which the container can't reach; the agent
logs the command to run on the host instead.

# Publishing services

On the node hosting it.

**By default a declaration needs an admin to approve it** before any other
node sees it. Service names are globally unique and first-come-first-served,
so without that gate any node holding a valid bearer token could claim an
unclaimed name — or re-claim one freed a moment earlier when its owner was
revoked — and every other node's `/etc/hosts` would point `<name>.wg` at it.
One compromised node is enough. Set
`WIRESERVE_REQUIRE_SERVICE_APPROVAL=false` on the coordinator for a
single-operator mesh where every node is already trusted and the round trip
is pure ceremony.

A node may have at most 16 services waiting for approval or denied at a time;
a declaration past that is not taken and `wireserve status` says why, until an
admin has decided some of the others. A denied service holds its name but not
an address of the mesh's range. (A poll rate limit and the address range's
size are the coordinator's other bounds on one node; see
`deploy/env/coordinator.env.example`.)

So the flow is two steps:

```sh
# on the node: plex.wg:80 reaches this node's port 32400
wireserve plex 80:32400

# on the coordinator — see what is waiting, then approve it
wireserve-admin service list --pending
wireserve-admin service approve plex --node homeserver
```

Until it is approved, `wireserve status` shows the service as
`pending approval`, which is how you tell "waiting on an admin" from "this
node has not polled yet". The node's own firewall is ready immediately
either way — it is only firewalling itself, and nothing routes to the
service's address or resolves `<name>.wg` for it yet.

`wireserve-admin service deny <service> --node <node> --reason '...'` refuses one,
and the declaring node withdraws it and closes the hole on its next poll.
Denying an already-approved service pulls it back out of the directory,
which is the way to re-review a name on a mesh where approval was switched
on after the fact — enabling it grandfathers everything already declared,
rather than blanking every hosts file at upgrade time.

**Deny is for mistakes; `revoke` is for compromise.** A denied service still
holds its globally-unique name until the declaring node withdraws it, and a
node you do not trust will not withdraw anything. `revoke` deletes all of
its declarations and kills its token.

Once approved, the declaration takes effect on the next poll: the service's
address is routed to its node and its name appears in every other node's
hosts file.

```sh
wireserve openobserve 80:5080          # openobserve.wg:80 -> :5080
wireserve mydns 53/udp 53/tcp 8080:8000 # several ports, TCP and UDP
wireserve plex 32400                    # a bare port maps to itself
wireserve myrouter 443:192.168.178.1:80 # a device on this node's LAN, see below
wireserve status                    # what this node sees right now (--json for scripts)
wireserve plex off
```

Each `PORT` is `[PUBLIC:][ADDRESS:]TARGET[/tcp|/udp]` (TCP unless given;
without an address, the target is on this node). Names are unique across the
whole mesh, first come first served.

`status` reads the daemon's cache of the last poll, no network call:

```
lego2, instance default on wireserve0

SERVICE         ADDRESS       PORTS                        NODE               STATE             ACCESS
mydns.wg        10.1.0.4      53/udp 53/tcp 8080:8000/tcp  lego2 (this node)  pending approval  yes
openobserve.wg  10.1.0.3      80:5080/tcp                  strato             online            yes
plex.wg         (no address)  32400/tcp                    strato             offline           no

PEER    ADDRESS   ENDPOINT              HANDSHAKE
lego2   10.1.0.1  -                     this node
strato  10.1.0.2  85.215.231.166:51820  1m ago
```

A peer's endpoint and handshake are read from the WireGuard interface
itself: the address it really talks to, which can differ from the one the
coordinator has on record (an IPv6 candidate this node can't use, say, or
a peer that roamed).

`(no address)` marks a service the coordinator had no address left for; it
is reachable nowhere until one frees up. ACCESS is what this node's grants
get it there, see [Who can reach what](access-control.md).

## Service addresses

Every service gets **its own mesh address** from the coordinator, and
`<name>.wg` resolves to it, so any number of services on one node can each
answer on `:80`. Peers route that address to the owning node, whose
firewall rewrites `address:PUBLIC` to `node:TARGET` in the kernel:

- **Only the published ports answer.** The target port is closed to the
  mesh, on the node's own address and on the service's: after
  `wireserve openobserve 80:5080`, `openobserve.wg:80` works and
  `openobserve.wg:5080` does not.
- **The service sees the real client.** Nothing is proxied; any TCP or UDP
  protocol works, and logs, rate limits and allowlists see the peer's own
  mesh address. (A connection from the owning node itself shows up as that
  node, as local connections do.)
- **Containers work**, published ports included, whatever the runtime —
  the rewrite happens before connection tracking, so a published port's
  own NAT still applies (rootful Podman, Docker with or without its
  userland proxy). The target must listen somewhere the mesh can reach:
  `0.0.0.0`, or the node's mesh address. A service bound to `127.0.0.1`
  is not reachable, by design.
- A target port can back one mapping per node (per protocol); `serve`
  refuses a second.
- Addresses come from the mesh range, shared with the nodes (a `/24`
  holds 253 nodes and services together), and stay with a service until
  it is withdrawn.

Rewriting packets needs the agent to run as root in the host's own
namespaces, as the shipped systemd unit and quadlets do. The kernel refuses
it inside an unprivileged container (LXC, rootless podman); the agent says
so in its log, and the services on that node stay unreachable.

## Devices on the node's network

A mapping can name an IPv4 address the node reaches, such as a router,
NAS or printer that can't run an agent itself:

```sh
wireserve myrouter 443:192.168.178.1:80   # myrouter.wg:443 -> the router's :80
```

The node forwards `myrouter.wg:443` to `192.168.178.1:80`, and the device
sees every connection come from the node's own LAN address. It has no route
back into the mesh, so unlike a service on the node, **the client's address
is not preserved**. Everything else works the same: approval, the name, only
the published port answering, and (on 443) HTTPS from the node's
terminator. What an admin approves includes the address:
`wireserve-admin service list` shows `443:192.168.178.1:80/tcp`. The rest
of the mesh only ever sees `443:80/tcp`.

- **IPv4 only**, and a literal address, not a hostname. A service's own
  address is IPv4, and the kernel can't forward an IPv4 connection to an
  IPv6 one.
- Not loopback, and nothing inside the mesh range. A service on this node
  is the form without an address; one on another node is that node's to
  serve.
- **Forwarding.** Replies arrive on the interface facing the device, and
  Linux only forwards what arrives on an interface with forwarding on. If
  that interface's `net.ipv4.conf.<if>.forwarding` is off and the host
  doesn't forward globally, the agent turns it on. While it does, its own
  table drops anything else forwarded from that interface, so the host
  doesn't become a router for its LAN. It turns forwarding off again on
  stop. A host that already forwards (a router, or a Docker or Podman host)
  is left as it is.
- **Routers that check the Host header.** Many (a FRITZ!Box among them)
  answer only to their own name, as a defence against DNS rebinding, and
  refuse `myrouter.<domain>`, which the terminator passes through. Publish
  such a device on another port than 443 and reach it by address.
